#![forbid(unsafe_code)]

//! Atomic generation storage for encrypted canonical wallet state.

use dom_wallet_crypto::{decode, encode, open, seal, CryptoError, KdfParameters};
use dom_wallet_domain::{
    NetworkIdentity, NodeConfiguration, RescanPlan, WalletState, MODEL_VERSION,
    SECRET_PROFILE_VERSION,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

const METADATA_FILE: &str = "metadata.json";
const ACTIVE_FILE: &str = "active-generation";
const GENERATIONS_DIR: &str = "generations";
const STATE_FILE: &str = "state.envelope";
const RESCAN_PLAN_FILE: &str = "rescan-plan.envelope";
const WRITER_LOCK_FILE: &str = ".wallet.lock";
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const BACKUP_MAGIC: [u8; 8] = *b"DOMWBK01";
pub const BACKUP_FORMAT_VERSION: u16 = 1;
pub const MAX_BACKUP_BYTES: usize = 20 * 1024 * 1024;
pub const RETAIN_SUPERSEDED_GENERATIONS: usize = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletMetadata {
    pub metadata_version: u16,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub schema_version: u16,
    pub secret_profile_version: u16,
    pub active_generation: u64,
}

/// The outer, non-secret backup header is authenticated as AEAD associated
/// data.  The encrypted payload carries the complete active V3 state and the
/// durable rescan plan; it is never an archive of filesystem paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupContainer {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub created_unix_seconds: u64,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub envelope: dom_wallet_crypto::EncryptedEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    payload_version: u16,
    state: WalletState,
    rescan_plan: Option<RescanPlan>,
}

impl WalletMetadata {
    fn from_state(state: &WalletState) -> Self {
        Self {
            metadata_version: 1,
            wallet_id: state.wallet_id,
            identity: state.identity.clone(),
            schema_version: MODEL_VERSION,
            secret_profile_version: SECRET_PROFILE_VERSION,
            active_generation: state.generation,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WalletDirectory {
    root: PathBuf,
    _writer_lock: Arc<File>,
}

impl WalletDirectory {
    pub fn create(
        root: impl AsRef<Path>,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        if root.exists() {
            return Err(StorageError::AlreadyExists);
        }
        state.validate().map_err(StorageError::Domain)?;
        fs::create_dir_all(root.join(GENERATIONS_DIR)).map_err(StorageError::Io)?;
        let wallet = Self {
            _writer_lock: acquire_writer_lock(&root)?,
            root,
        };
        wallet.publish_initial(state, password, kdf)?;
        Ok(wallet)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(StorageError::NotFound);
        }
        Ok(Self {
            _writer_lock: acquire_writer_lock(&root)?,
            root,
        })
    }

    pub fn metadata(&self) -> Result<WalletMetadata, StorageError> {
        let bytes = read_bounded(&self.root.join(METADATA_FILE))?;
        let metadata: WalletMetadata =
            serde_json::from_slice(&bytes).map_err(|_| StorageError::InvalidMetadata)?;
        if metadata.metadata_version != 1
            || metadata.schema_version != MODEL_VERSION
            || metadata.secret_profile_version != SECRET_PROFILE_VERSION
        {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(metadata)
    }

    pub fn load(&self, password: &str) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let active = self.active_generation()?;
        let interrupted_publication = metadata
            .active_generation
            .checked_add(1)
            .is_some_and(|next| next == active);
        if active != metadata.active_generation && !interrupted_publication {
            return Err(StorageError::GenerationConflict);
        }
        let state = self.load_generation(active, password, &metadata)?;
        if state.generation != active
            || state.wallet_id != metadata.wallet_id
            || state.identity != metadata.identity
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        if interrupted_publication {
            let repaired = serde_json::to_vec(&WalletMetadata::from_state(&state))
                .map_err(|_| StorageError::CanonicalEncoding)?;
            atomic_write(&self.root.join(METADATA_FILE), &repaired)?;
            sync_directory(&self.root)?;
        }
        Ok(state)
    }

    pub fn commit(
        &self,
        expected_generation: u64,
        state: WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<WalletState, StorageError> {
        let state = self.stage_generation(expected_generation, state, password, kdf)?;
        self.publish_staged_generation(expected_generation, &state)?;
        Ok(state)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes a complete encrypted generation without changing the sole active
    /// pointer. This is the first half of the existing commit protocol.
    pub fn stage_generation(
        &self,
        expected_generation: u64,
        mut state: WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let active = self.active_generation()?;
        if active != expected_generation || metadata.active_generation != expected_generation {
            return Err(StorageError::ExpectedGenerationConflict { current: active });
        }
        if state.wallet_id != metadata.wallet_id || state.identity != metadata.identity {
            return Err(StorageError::IdentityMismatch);
        }
        state.generation = expected_generation
            .checked_add(1)
            .ok_or(StorageError::GenerationOverflow)?;
        state.validate().map_err(StorageError::Domain)?;
        self.write_generation(&state, password, kdf)?;
        Ok(state)
    }

    /// Publishes only a previously complete generation through the existing
    /// pointer+metadata atomic publication path.
    pub fn publish_staged_generation(
        &self,
        expected_generation: u64,
        state: &WalletState,
    ) -> Result<(), StorageError> {
        let active = self.active_generation()?;
        if active != expected_generation {
            return Err(StorageError::ExpectedGenerationConflict { current: active });
        }
        if state.generation
            != expected_generation
                .checked_add(1)
                .ok_or(StorageError::GenerationOverflow)?
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        self.publish_pointer_and_metadata(state)
    }

    pub fn load_generation_for_recovery(
        &self,
        generation: u64,
        password: &str,
    ) -> Result<WalletState, StorageError> {
        let metadata = self.metadata()?;
        let state = self.load_generation(generation, password, &metadata)?;
        if state.generation != generation
            || state.wallet_id != metadata.wallet_id
            || state.identity != metadata.identity
        {
            return Err(StorageError::GenerationConflict);
        }
        state.validate().map_err(StorageError::Domain)?;
        Ok(state)
    }

    /// Durable staging is deliberately outside the active-generation pointer:
    /// a failed or interrupted rescan cannot publish partial canonical state.
    pub fn save_rescan_plan(
        &self,
        state: &WalletState,
        plan: &RescanPlan,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        let plaintext = serde_json::to_vec(plan).map_err(|_| StorageError::CanonicalEncoding)?;
        let context = rescan_context(state.wallet_id, &state.identity);
        let encoded =
            encode(&seal(&plaintext, password, &context, kdf).map_err(StorageError::Crypto)?)
                .map_err(StorageError::Crypto)?;
        atomic_write(&self.root.join(RESCAN_PLAN_FILE), &encoded)
    }

    pub fn load_rescan_plan(
        &self,
        state: &WalletState,
        password: &str,
    ) -> Result<Option<RescanPlan>, StorageError> {
        let path = self.root.join(RESCAN_PLAN_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let envelope = decode(&read_bounded(&path)?).map_err(StorageError::Crypto)?;
        let context = rescan_context(state.wallet_id, &state.identity);
        let plaintext = open(&envelope, password, &context).map_err(StorageError::Crypto)?;
        let plan =
            serde_json::from_slice(&plaintext).map_err(|_| StorageError::CanonicalEncoding)?;
        Ok(Some(plan))
    }

    pub fn clear_rescan_plan(&self) -> Result<(), StorageError> {
        let path = self.root.join(RESCAN_PLAN_FILE);
        if path.exists() {
            fs::remove_file(path).map_err(StorageError::Io)?;
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    /// Exports one coherent committed generation, rather than a collection of
    /// mutable wallet files. The outer envelope uses the same Argon2id and
    /// authenticated-encryption profile as storage, with independent salt and
    /// nonce under the explicitly supplied backup password.
    pub fn export_backup(
        &self,
        wallet_password: &str,
        backup_password: &str,
        kdf: KdfParameters,
        destination: impl AsRef<Path>,
    ) -> Result<(), StorageError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StorageError::BackupDestinationExists);
        }
        let state = self.load(wallet_password)?;
        let plan = self.load_rescan_plan(&state, wallet_password)?;
        let created_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StorageError::Clock)?
            .as_secs();
        let payload = BackupPayload {
            payload_version: BACKUP_FORMAT_VERSION,
            state: state.clone(),
            rescan_plan: plan,
        };
        let plaintext =
            serde_json::to_vec(&payload).map_err(|_| StorageError::CanonicalEncoding)?;
        if plaintext.is_empty() || plaintext.len() > MAX_STATE_BYTES {
            return Err(StorageError::FileSizeOutOfBounds);
        }
        let context = backup_context(created_unix_seconds, state.wallet_id, &state.identity);
        let envelope =
            seal(&plaintext, backup_password, &context, kdf).map_err(StorageError::Crypto)?;
        let container = BackupContainer {
            magic: BACKUP_MAGIC,
            format_version: BACKUP_FORMAT_VERSION,
            created_unix_seconds,
            wallet_id: state.wallet_id,
            identity: state.identity,
            envelope,
        };
        let encoded =
            serde_json::to_vec(&container).map_err(|_| StorageError::CanonicalEncoding)?;
        atomic_write_private(destination, &encoded, MAX_BACKUP_BYTES)
    }

    /// Authenticates and validates the complete backup before creating any
    /// destination state. Installation happens through a sibling staging
    /// directory and a single rename; an existing wallet is never replaced.
    pub fn import_backup(
        destination: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        backup_password: &str,
        wallet_password: &str,
        expected_identity: &NetworkIdentity,
        kdf: KdfParameters,
    ) -> Result<Self, StorageError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(StorageError::AlreadyExists);
        }
        let encoded = read_bounded_with_limit(backup_path.as_ref(), MAX_BACKUP_BYTES)?;
        let container: BackupContainer =
            serde_json::from_slice(&encoded).map_err(|_| StorageError::InvalidBackup)?;
        if container.magic != BACKUP_MAGIC || container.format_version != BACKUP_FORMAT_VERSION {
            return Err(StorageError::UnsupportedBackupVersion);
        }
        if &container.identity != expected_identity {
            return Err(StorageError::IdentityMismatch);
        }
        let context = backup_context(
            container.created_unix_seconds,
            container.wallet_id,
            &container.identity,
        );
        let plaintext =
            open(&container.envelope, backup_password, &context).map_err(StorageError::Crypto)?;
        let payload: BackupPayload =
            serde_json::from_slice(&plaintext).map_err(|_| StorageError::InvalidBackup)?;
        if payload.payload_version != BACKUP_FORMAT_VERSION
            || payload.state.wallet_id != container.wallet_id
            || payload.state.identity != container.identity
            || payload.state.identity != *expected_identity
        {
            return Err(StorageError::IdentityMismatch);
        }
        payload.state.validate().map_err(StorageError::Domain)?;
        if let Some(plan) = &payload.rescan_plan {
            if plan.wallet_id != payload.state.wallet_id || plan.identity != payload.state.identity
            {
                return Err(StorageError::InvalidBackup);
            }
        }
        let file_name = destination.file_name().ok_or(StorageError::InvalidBackup)?;
        let parent = destination.parent().ok_or(StorageError::InvalidBackup)?;
        let staging = parent.join(format!(".{}.backup-import", file_name.to_string_lossy()));
        if staging.exists() {
            return Err(StorageError::IncompleteGeneration);
        }
        let staged = match WalletDirectory::create(&staging, &payload.state, wallet_password, kdf) {
            Ok(staged) => staged,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        let result = (|| {
            if let Some(plan) = &payload.rescan_plan {
                staged.save_rescan_plan(&payload.state, plan, wallet_password, kdf)?;
            }
            fs::rename(&staging, destination).map_err(StorageError::Io)?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        drop(staged);
        WalletDirectory::open(destination)
    }

    /// Conservative, idempotent cleanup. It only considers complete named
    /// generations after reading the authoritative active pointer; callers
    /// provide generations referenced by a durable nonterminal plan.
    pub fn cleanup_superseded_generations(&self, protected: &[u64]) -> Result<(), StorageError> {
        let active = self.active_generation()?;
        let mut generations = Vec::new();
        for entry in fs::read_dir(self.root.join(GENERATIONS_DIR)).map_err(StorageError::Io)? {
            let entry = entry.map_err(StorageError::Io)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(StorageError::InvalidActiveGeneration)?;
            if name.starts_with('.') {
                continue;
            }
            generations.push(parse_generation(name)?);
        }
        generations.sort_unstable();
        if !generations.contains(&active) {
            return Err(StorageError::GenerationConflict);
        }
        let mut retained = std::collections::BTreeSet::from([active]);
        retained.extend(protected.iter().copied());
        retained.extend(
            generations
                .iter()
                .copied()
                .filter(|generation| *generation < active)
                .rev()
                .take(RETAIN_SUPERSEDED_GENERATIONS),
        );
        for generation in generations {
            if !retained.contains(&generation) {
                let path = self
                    .root
                    .join(GENERATIONS_DIR)
                    .join(generation_name(generation));
                if path.exists() {
                    fs::remove_dir_all(path).map_err(StorageError::Io)?;
                    sync_directory(&self.root.join(GENERATIONS_DIR))?;
                }
            }
        }
        Ok(())
    }

    fn publish_initial(
        &self,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        self.write_generation(state, password, kdf)?;
        self.publish_pointer_and_metadata(state)
    }

    fn write_generation(
        &self,
        state: &WalletState,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<(), StorageError> {
        let generation = generation_name(state.generation);
        let final_dir = self.root.join(GENERATIONS_DIR).join(&generation);
        if final_dir.exists() {
            return Err(StorageError::GenerationAlreadyExists);
        }
        let temporary_dir = self
            .root
            .join(GENERATIONS_DIR)
            .join(format!(".{generation}.staging"));
        if temporary_dir.exists() {
            return Err(StorageError::IncompleteGeneration);
        }
        fs::create_dir(&temporary_dir).map_err(StorageError::Io)?;
        let result = (|| {
            let plaintext =
                serde_json::to_vec(state).map_err(|_| StorageError::CanonicalEncoding)?;
            let context = state_context(state.wallet_id, &state.identity, state.generation);
            let envelope =
                seal(&plaintext, password, &context, kdf).map_err(StorageError::Crypto)?;
            let encoded = encode(&envelope).map_err(StorageError::Crypto)?;
            atomic_write(&temporary_dir.join(STATE_FILE), &encoded)?;
            sync_directory(&temporary_dir)?;
            fs::rename(&temporary_dir, &final_dir).map_err(StorageError::Io)?;
            sync_directory(&self.root.join(GENERATIONS_DIR))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temporary_dir);
        }
        result
    }

    fn publish_pointer_and_metadata(&self, state: &WalletState) -> Result<(), StorageError> {
        let generation = generation_name(state.generation);
        atomic_write(&self.root.join(ACTIVE_FILE), generation.as_bytes())?;
        let metadata = serde_json::to_vec(&WalletMetadata::from_state(state))
            .map_err(|_| StorageError::CanonicalEncoding)?;
        atomic_write(&self.root.join(METADATA_FILE), &metadata)?;
        sync_directory(&self.root)
    }

    fn active_generation(&self) -> Result<u64, StorageError> {
        let bytes = read_bounded(&self.root.join(ACTIVE_FILE))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| StorageError::InvalidActiveGeneration)?;
        parse_generation(text)
    }

    fn load_generation(
        &self,
        generation: u64,
        password: &str,
        metadata: &WalletMetadata,
    ) -> Result<WalletState, StorageError> {
        let encoded = read_bounded(
            &self
                .root
                .join(GENERATIONS_DIR)
                .join(generation_name(generation))
                .join(STATE_FILE),
        )?;
        let envelope = decode(&encoded).map_err(StorageError::Crypto)?;
        let context = state_context(metadata.wallet_id, &metadata.identity, generation);
        let plaintext = open(&envelope, password, &context).map_err(StorageError::Crypto)?;
        serde_json::from_slice(&plaintext).map_err(|_| StorageError::CanonicalEncoding)
    }
}

pub fn default_node_configuration(identity: NetworkIdentity) -> NodeConfiguration {
    NodeConfiguration {
        endpoint_url: "https://example.invalid/dom-rpc".into(),
        expected_identity: identity,
        source_identity: "configured-dom-node".into(),
        api_compatibility_version: 1,
        connect_timeout_ms: 5_000,
        request_timeout_ms: 10_000,
        poll_interval_ms: 5_000,
        retry_ceiling: 6,
        max_backoff_ms: 60_000,
        stable_success_threshold: 3,
        tls_required: true,
        credential_reference: None,
    }
}

fn generation_name(generation: u64) -> String {
    format!("generation-{generation:020}")
}

fn parse_generation(value: &str) -> Result<u64, StorageError> {
    value
        .strip_prefix("generation-")
        .ok_or(StorageError::InvalidActiveGeneration)?
        .parse()
        .map_err(|_| StorageError::InvalidActiveGeneration)
}

fn state_context(wallet_id: Uuid, identity: &NetworkIdentity, generation: u64) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 + 32 + 32 + 8 + 24);
    context.extend_from_slice(b"DOM-WALLET-V3-STATE-V1");
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context.extend_from_slice(&generation.to_le_bytes());
    context
}

fn rescan_context(wallet_id: Uuid, identity: &NetworkIdentity) -> Vec<u8> {
    let mut context = Vec::with_capacity(16 + 32 + 32 + 24);
    context.extend_from_slice(b"DOM-WALLET-V3-RESCAN-V1");
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context
}

fn backup_context(
    created_unix_seconds: u64,
    wallet_id: Uuid,
    identity: &NetworkIdentity,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(8 + 2 + 8 + 16 + 32 + 32);
    context.extend_from_slice(&BACKUP_MAGIC);
    context.extend_from_slice(&BACKUP_FORMAT_VERSION.to_le_bytes());
    context.extend_from_slice(&created_unix_seconds.to_le_bytes());
    context.extend_from_slice(wallet_id.as_bytes());
    context.extend_from_slice(&identity.chain_id);
    context.extend_from_slice(&identity.genesis_id);
    context
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StorageError> {
    read_bounded_with_limit(path, MAX_STATE_BYTES)
}

fn acquire_writer_lock(root: &Path) -> Result<Arc<File>, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(root.join(WRITER_LOCK_FILE))
        .map_err(StorageError::Io)?;
    match FileExt::try_lock_exclusive(&lock) {
        Ok(()) => Ok(Arc::new(lock)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Err(StorageError::WriterActive)
        }
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn read_bounded_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>, StorageError> {
    let metadata = fs::metadata(path).map_err(StorageError::Io)?;
    if metadata.len() == 0 || metadata.len() as usize > max_bytes {
        return Err(StorageError::FileSizeOutOfBounds);
    }
    fs::read(path).map_err(StorageError::Io)
}

fn atomic_write_private(path: &Path, bytes: &[u8], max_bytes: usize) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(StorageError::FileSizeOutOfBounds);
    }
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(StorageError::Io)?;
    let result = (|| {
        file.write_all(bytes).map_err(StorageError::Io)?;
        file.sync_all().map_err(StorageError::Io)?;
        drop(file);
        fs::rename(&temporary, path).map_err(StorageError::Io)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err(StorageError::FileSizeOutOfBounds);
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(StorageError::Io)?;
    file.write_all(bytes).map_err(StorageError::Io)?;
    file.sync_all().map_err(StorageError::Io)?;
    drop(file);
    fs::rename(&temporary, path).map_err(StorageError::Io)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(StorageError::Io)?
            .sync_all()
            .map_err(StorageError::Io)?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("wallet directory already exists")]
    AlreadyExists,
    #[error("wallet directory was not found")]
    NotFound,
    #[error("wallet is already open by another writer")]
    WriterActive,
    #[error("invalid wallet metadata")]
    InvalidMetadata,
    #[error("unsupported wallet version")]
    UnsupportedVersion,
    #[error("invalid active generation pointer")]
    InvalidActiveGeneration,
    #[error("generation conflict")]
    GenerationConflict,
    #[error("expected generation conflict; current generation is {current}")]
    ExpectedGenerationConflict { current: u64 },
    #[error("wallet identity or network identity mismatch")]
    IdentityMismatch,
    #[error("generation already exists")]
    GenerationAlreadyExists,
    #[error("incomplete generation is present")]
    IncompleteGeneration,
    #[error("generation overflow")]
    GenerationOverflow,
    #[error("bounded file size validation failed")]
    FileSizeOutOfBounds,
    #[error("backup destination already exists")]
    BackupDestinationExists,
    #[error("backup data is invalid")]
    InvalidBackup,
    #[error("backup format is unsupported")]
    UnsupportedBackupVersion,
    #[error("system clock is unavailable")]
    Clock,
    #[error("canonical state encoding failed")]
    CanonicalEncoding,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Domain(#[from] dom_wallet_domain::DomainError),
    #[error("filesystem error: {0}")]
    Io(std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_domain::{Network, NetworkIdentity, WalletState};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HistoricalSchemaFixture {
        fixture_version: u16,
        releases: Vec<String>,
        metadata_version: u16,
        schema_version: u16,
        secret_profile_version: u16,
        migration_required: bool,
    }

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [4; 32],
            genesis_id: [5; 32],
        }
    }

    #[test]
    fn create_reopen_and_wrong_password_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let reopened = wallet.load("correct").unwrap();
        assert_eq!(reopened.wallet_id, state.wallet_id);
        assert!(matches!(
            wallet.load("wrong"),
            Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
        ));
    }

    #[test]
    fn commits_are_old_or_new_and_generation_checked() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let mut changed = wallet.load("correct").unwrap();
        changed.allocate().unwrap();
        let committed = wallet
            .commit(0, changed, "correct", KdfParameters::TEST)
            .unwrap();
        assert_eq!(committed.generation, 1);
        assert_eq!(wallet.load("correct").unwrap().generation, 1);
        assert!(matches!(
            wallet.commit(0, committed, "correct", KdfParameters::TEST),
            Err(StorageError::ExpectedGenerationConflict { current: 1 })
        ));
    }

    #[test]
    fn process_lock_rejects_an_active_writer_and_reuses_a_stale_lock_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let shared_owner = wallet.clone();

        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::WriterActive)
        ));
        drop(wallet);
        assert!(matches!(
            WalletDirectory::open(&root),
            Err(StorageError::WriterActive)
        ));
        drop(shared_owner);

        let reopened = WalletDirectory::open(&root).unwrap();
        assert_eq!(reopened.load("correct").unwrap().wallet_id, state.wallet_id);
        assert!(root.join(WRITER_LOCK_FILE).is_file());
    }

    #[test]
    fn v01_schema_fixture_opens_without_mutating_wallet_data() {
        let fixture: HistoricalSchemaFixture =
            serde_json::from_str(include_str!("../fixtures/v0.1.x-schema-v1.json")).unwrap();
        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(
            fixture
                .releases
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5"]
        );
        assert_eq!(fixture.metadata_version, 1);
        assert_eq!(fixture.schema_version, MODEL_VERSION);
        assert_eq!(fixture.secret_profile_version, SECRET_PROFILE_VERSION);
        assert!(!fixture.migration_required);

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("v0.1.x-wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let metadata_before = fs::read(root.join(METADATA_FILE)).unwrap();
        let generation_path = root
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .join(STATE_FILE);
        let generation_before = fs::read(&generation_path).unwrap();
        drop(wallet);

        let reopened = WalletDirectory::open(&root).unwrap();
        let loaded = reopened.load("correct").unwrap();
        assert_eq!(loaded, state);
        drop(reopened);
        assert_eq!(fs::read(root.join(METADATA_FILE)).unwrap(), metadata_before);
        assert_eq!(fs::read(generation_path).unwrap(), generation_before);
    }

    #[test]
    fn unknown_schema_fails_without_overwriting_original_data() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("unknown-schema-wallet");
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet =
            WalletDirectory::create(&root, &state, "correct", KdfParameters::TEST).unwrap();
        let mut metadata: WalletMetadata =
            serde_json::from_slice(&fs::read(root.join(METADATA_FILE)).unwrap()).unwrap();
        metadata.schema_version = u16::MAX;
        let unsupported = serde_json::to_vec(&metadata).unwrap();
        atomic_write(&root.join(METADATA_FILE), &unsupported).unwrap();
        let generation_path = root
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .join(STATE_FILE);
        let generation_before = fs::read(&generation_path).unwrap();
        drop(wallet);

        let reopened = WalletDirectory::open(&root).unwrap();
        assert!(matches!(
            reopened.metadata(),
            Err(StorageError::UnsupportedVersion)
        ));
        assert!(matches!(
            reopened.load("correct"),
            Err(StorageError::UnsupportedVersion)
        ));
        drop(reopened);
        assert_eq!(fs::read(root.join(METADATA_FILE)).unwrap(), unsupported);
        assert_eq!(fs::read(generation_path).unwrap(), generation_before);
    }

    #[test]
    fn mixed_generation_pointer_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let state = WalletState::new(identity(), [6; 32], default_node_configuration(identity()));
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &state,
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        fs::write(
            wallet.root().join(ACTIVE_FILE),
            b"generation-00000000000000000009",
        )
        .unwrap();
        assert!(wallet.load("correct").is_err());
    }

    #[test]
    fn authenticated_adjacent_generation_repairs_interrupted_publication() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let mut changed = wallet.load("correct").unwrap();
        changed.allocate().unwrap();
        let staged = wallet
            .stage_generation(0, changed, "correct", KdfParameters::TEST)
            .unwrap();
        atomic_write(
            &wallet.root().join(ACTIVE_FILE),
            generation_name(staged.generation).as_bytes(),
        )
        .unwrap();

        assert!(matches!(
            wallet.load("wrong"),
            Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
        ));
        assert_eq!(wallet.metadata().unwrap().active_generation, 0);

        let reopened = wallet.load("correct").unwrap();
        assert_eq!(reopened.generation, 1);
        assert_eq!(wallet.metadata().unwrap().active_generation, 1);
        assert_eq!(wallet.load("correct").unwrap(), reopened);
    }

    #[test]
    fn cleanup_retains_active_and_one_predecessor_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let first = wallet.load("correct").unwrap();
        let second = wallet
            .commit(0, first, "correct", KdfParameters::TEST)
            .unwrap();
        let _third = wallet
            .commit(1, second, "correct", KdfParameters::TEST)
            .unwrap();
        wallet.cleanup_superseded_generations(&[]).unwrap();
        wallet.cleanup_superseded_generations(&[]).unwrap();
        assert!(!wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(0))
            .exists());
        assert!(wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(1))
            .exists());
        assert!(wallet
            .root()
            .join(GENERATIONS_DIR)
            .join(generation_name(2))
            .exists());
        assert_eq!(wallet.load("correct").unwrap().generation, 2);
    }

    #[test]
    fn cleanup_ambiguous_metadata_fails_closed_without_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "correct",
            KdfParameters::TEST,
        )
        .unwrap();
        let active = wallet.root().join(GENERATIONS_DIR).join(generation_name(0));
        fs::create_dir(
            wallet
                .root()
                .join(GENERATIONS_DIR)
                .join("generation-not-a-number"),
        )
        .unwrap();
        assert!(wallet.cleanup_superseded_generations(&[]).is_err());
        assert!(active.exists());
        assert_eq!(wallet.load("correct").unwrap().generation, 0);
    }

    #[test]
    fn backup_round_trip_authenticates_header_ciphertext_and_identity_before_install() {
        let temp = tempfile::tempdir().unwrap();
        let wallet = WalletDirectory::create(
            temp.path().join("wallet"),
            &WalletState::new(identity(), [6; 32], default_node_configuration(identity())),
            "wallet-password",
            KdfParameters::TEST,
        )
        .unwrap();
        let backup = temp.path().join("wallet.dombackup");
        wallet
            .export_backup(
                "wallet-password",
                "backup-password",
                KdfParameters::TEST,
                &backup,
            )
            .unwrap();
        let imported = WalletDirectory::import_backup(
            temp.path().join("restored"),
            &backup,
            "backup-password",
            "new-wallet-password",
            &identity(),
            KdfParameters::TEST,
        )
        .unwrap();
        assert_eq!(
            imported.load("new-wallet-password").unwrap().wallet_id,
            wallet.load("wallet-password").unwrap().wallet_id
        );

        assert!(matches!(
            WalletDirectory::import_backup(
                temp.path().join("wrong-password"),
                &backup,
                "wrong-password",
                "new-wallet-password",
                &identity(),
                KdfParameters::TEST,
            ),
            Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
        ));
        let mut wrong = identity();
        wrong.genesis_id[0] ^= 1;
        assert!(matches!(
            WalletDirectory::import_backup(
                temp.path().join("wrong-identity"),
                &backup,
                "backup-password",
                "new-wallet-password",
                &wrong,
                KdfParameters::TEST,
            ),
            Err(StorageError::IdentityMismatch)
        ));
        let mut corrupted = fs::read(&backup).unwrap();
        let last = corrupted.len() - 2;
        corrupted[last] ^= 1;
        let damaged = temp.path().join("damaged.dombackup");
        fs::write(&damaged, corrupted).unwrap();
        assert!(WalletDirectory::import_backup(
            temp.path().join("damaged"),
            &damaged,
            "backup-password",
            "new-wallet-password",
            &identity(),
            KdfParameters::TEST,
        )
        .is_err());
        assert!(!temp.path().join("damaged").exists());
    }
}
