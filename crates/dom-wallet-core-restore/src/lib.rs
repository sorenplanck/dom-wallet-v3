//! Wallet-owned orchestration for BIP-39 seed plus canonical-chain restoration.

#![forbid(unsafe_code)]

use dom_crypto::recovery::{OutputRecoveryDomain, RecoveryChainContext};
use dom_tx::InputSource;
use dom_wallet_core_api::{
    CoinbaseScanMetadata, CoreNetwork, ScanBlock, ScanInput, ScanKernel, ScanOutput, WalletCoreApi,
};
use dom_wallet_core_recovery::CanonicalWalletSeed;
use dom_wallet_core_sync::{
    CoreBlockReference, CoreChainAdapter, CoreChainIdentity, CoreCursorBytes, CoreReconcileResult,
    CoreScanBatch, CoreScanError, CoreScanTransactionSink, PersistedCoreCursorState,
};
use dom_wallet_crypto::KdfParameters;
use dom_wallet_domain::{
    BalanceProjection, Network, NetworkIdentity, OutputRecord, OutputState,
    RecoveredAccountMapping, RecoveredOutputDomain, RecoveredOutputMetadata,
    RecoveryAllocationFloors, RecoveryCanonicalBlock, RecoveryMetadata, SeedRestoreStatus,
    SyncStatus, WalletState, MAX_ACCOUNTS, RECOVERY_SCHEME_BIP39_256_V1,
};
use dom_wallet_recovery::RestoreError;
use dom_wallet_storage::{default_node_configuration, StorageError, WalletDirectory};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Default number of canonical blocks committed in one encrypted generation.
pub const DEFAULT_RESTORE_BATCH_BLOCKS: u64 = 256;
/// Default bounded canonical reorganization search.
pub const DEFAULT_RESTORE_REORG_DEPTH: u64 = 1_024;

/// Safe completion classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedRestoreCompletion {
    OwnedOutputsRecovered,
    NoOwnedOutputs,
}

/// Stable redacted recovery warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedRestoreWarning {
    LegacyBackupRequired,
    OffChainMetadataNotRecoverableWithSeed,
}

/// Public per-account balance projection keyed only by capsule account number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredAccountBalance {
    pub recovery_account: u32,
    pub balance: BalanceProjection,
}

/// Structured result containing no phrase, seed, root, blinding, or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedRestoreResult {
    pub completion: SeedRestoreCompletion,
    pub network: CoreNetwork,
    pub chain_id: [u8; 32],
    pub scanned_blocks: u64,
    pub scanned_outputs: u64,
    pub owned_outputs: u64,
    pub spent_outputs: u64,
    pub unspent_outputs: u64,
    pub coinbase_outputs: u64,
    pub legacy_outputs: u64,
    pub balance: BalanceProjection,
    pub accounts: Vec<RecoveredAccountBalance>,
    pub floors: RecoveryAllocationFloors,
    pub final_cursor_anchor: CoreBlockReference,
    pub warnings: Vec<SeedRestoreWarning>,
}

/// Redacted progress from one atomic canonical recovery step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedRestoreProgress {
    BatchCommitted {
        anchor: CoreBlockReference,
    },
    ReorgCommitted {
        safe_anchor: CoreBlockReference,
        new_anchor: CoreBlockReference,
    },
    ReadyToPublish,
}

/// Typed restore failures expose stable categories only.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SeedRestoreError {
    #[error("BIP-39 recovery phrase is invalid")]
    InvalidMnemonic,
    #[error("Wallet encryption password is invalid")]
    InvalidPassword,
    #[error("restore destination is invalid or already exists")]
    InvalidDestination,
    #[error("Core chain identity does not match the requested restore")]
    ChainIdentityMismatch,
    #[error("canonical scan contract failed")]
    CanonicalScan,
    #[error("canonical recovery data is malformed")]
    MalformedRecovery,
    #[error("restored output metadata conflicts")]
    ConflictingOutput,
    #[error("restored recovery coordinate overflow")]
    CoordinateOverflow,
    #[error("encrypted restore state could not be committed")]
    Storage,
    #[error("restore staging state is incompatible")]
    IncompatibleCheckpoint,
    #[error("restore is not complete")]
    Incomplete,
}

/// Wallet-owned recovery service over the frozen scanner and recovery APIs.
pub struct SeedRestoreService {
    api: Arc<dyn WalletCoreApi + Send + Sync>,
    expected_identity: CoreChainIdentity,
    batch_blocks: u64,
    reorg_depth: u64,
    kdf: KdfParameters,
}

impl fmt::Debug for SeedRestoreService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeedRestoreService")
            .field("network", &self.expected_identity.network)
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .field("batch_blocks", &self.batch_blocks)
            .field("reorg_depth", &self.reorg_depth)
            .finish_non_exhaustive()
    }
}

impl SeedRestoreService {
    pub fn new(
        api: Arc<dyn WalletCoreApi + Send + Sync>,
        expected_identity: CoreChainIdentity,
        kdf: KdfParameters,
    ) -> Self {
        Self {
            api,
            expected_identity,
            batch_blocks: DEFAULT_RESTORE_BATCH_BLOCKS,
            reorg_depth: DEFAULT_RESTORE_REORG_DEPTH,
            kdf,
        }
    }

    pub fn with_limits(mut self, batch_blocks: u64, reorg_depth: u64) -> Self {
        self.batch_blocks = batch_blocks;
        self.reorg_depth = reorg_depth;
        self
    }

    /// Begin or resume a restore without publishing the destination.
    pub fn begin(
        &self,
        mnemonic: &str,
        password: &str,
        destination: impl AsRef<Path>,
    ) -> Result<SeedRestoreSession, SeedRestoreError> {
        validate_password(password)?;
        let seed =
            CanonicalWalletSeed::parse(mnemonic).map_err(|_| SeedRestoreError::InvalidMnemonic)?;
        let adapter = CoreChainAdapter::connect(
            Arc::clone(&self.api),
            Some(&self.expected_identity),
            self.batch_blocks,
            self.reorg_depth,
        )
        .map_err(map_scan_error)?;
        let destination = destination.as_ref().to_path_buf();
        if destination.exists() {
            return Err(SeedRestoreError::InvalidDestination);
        }
        let staging = staging_path(&destination)?;
        let chain = RecoveryChainContext {
            network_magic: self.expected_identity.network_magic,
            chain_id: self.expected_identity.chain_id,
        };
        let password = Zeroizing::new(password.to_owned());
        let (directory, state) = if staging.exists() {
            let directory =
                WalletDirectory::open(&staging).map_err(|_| SeedRestoreError::Storage)?;
            let state = directory
                .load(password.as_str())
                .map_err(|_| SeedRestoreError::IncompatibleCheckpoint)?;
            validate_checkpoint(&state, &seed, &self.expected_identity)?;
            (directory, state)
        } else {
            let state = initial_restore_state(&seed, &self.expected_identity)?;
            let directory = WalletDirectory::create(&staging, &state, password.as_str(), self.kdf)
                .map_err(|_| SeedRestoreError::Storage)?;
            restrict_directory(&staging)?;
            (directory, state)
        };
        Ok(SeedRestoreSession {
            adapter,
            seed,
            chain,
            identity: self.expected_identity.clone(),
            directory,
            state: Some(state),
            password,
            kdf: self.kdf,
            destination,
            staging,
            ready_to_publish: false,
        })
    }

    /// Restore every canonical page and atomically publish the completed wallet.
    pub fn restore(
        &self,
        mnemonic: &str,
        password: &str,
        destination: impl AsRef<Path>,
    ) -> Result<SeedRestoreResult, SeedRestoreError> {
        let mut session = self.begin(mnemonic, password, destination)?;
        loop {
            if session.advance_once()? == SeedRestoreProgress::ReadyToPublish {
                return session.publish();
            }
        }
    }
}

/// Resumable encrypted restore session. Debug output contains no paths or secrets.
pub struct SeedRestoreSession {
    adapter: CoreChainAdapter,
    seed: CanonicalWalletSeed,
    chain: RecoveryChainContext,
    identity: CoreChainIdentity,
    directory: WalletDirectory,
    state: Option<WalletState>,
    password: Zeroizing<String>,
    kdf: KdfParameters,
    destination: PathBuf,
    staging: PathBuf,
    ready_to_publish: bool,
}

impl fmt::Debug for SeedRestoreSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeedRestoreSession")
            .field("network", &self.identity.network)
            .field("destination", &"[REDACTED]")
            .field("staging", &"[REDACTED]")
            .field("seed", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SeedRestoreSession {
    /// Commit exactly one validated page or one bounded reorg transaction.
    pub fn advance_once(&mut self) -> Result<SeedRestoreProgress, SeedRestoreError> {
        if self.ready_to_publish {
            return Ok(SeedRestoreProgress::ReadyToPublish);
        }
        let mut sink = RestoreSink {
            seed: &self.seed,
            chain: self.chain,
            identity: &self.identity,
            directory: &self.directory,
            state: &mut self.state,
            password: self.password.as_str(),
            kdf: self.kdf,
            last_error: None,
        };
        let reconciliation = self.adapter.reconcile_once(&mut sink);
        if let Err(error) = reconciliation {
            return Err(sink.last_error.unwrap_or_else(|| map_scan_error(error)));
        }
        match reconciliation.expect("checked above") {
            CoreReconcileResult::NoChanges => {
                self.ready_to_publish = true;
                Ok(SeedRestoreProgress::ReadyToPublish)
            }
            CoreReconcileResult::Committed(cursor) => Ok(SeedRestoreProgress::BatchCommitted {
                anchor: cursor_anchor(cursor)?,
            }),
            CoreReconcileResult::ReorgCommitted {
                safe_anchor,
                cursor,
            } => Ok(SeedRestoreProgress::ReorgCommitted {
                safe_anchor,
                new_anchor: cursor_anchor(cursor)?,
            }),
        }
    }

    /// Mark the encrypted generation complete and atomically publish it.
    pub fn publish(mut self) -> Result<SeedRestoreResult, SeedRestoreError> {
        if !self.ready_to_publish {
            return Err(SeedRestoreError::Incomplete);
        }
        let mut state = self.state.take().ok_or(SeedRestoreError::Storage)?;
        if state.core_scan_cursor.is_none() {
            return Err(SeedRestoreError::Incomplete);
        }
        state.seed_restore_status = Some(SeedRestoreStatus::Complete);
        state.sync_status = SyncStatus::Synced;
        let expected_generation = state.generation;
        let state = self
            .directory
            .commit(expected_generation, state, self.password.as_str(), self.kdf)
            .map_err(|_| SeedRestoreError::Storage)?;
        let result = result_from_state(&state, &self.identity)?;
        if self.destination.exists() {
            return Err(SeedRestoreError::InvalidDestination);
        }
        fs::rename(&self.staging, &self.destination).map_err(|_| SeedRestoreError::Storage)?;
        sync_parent(&self.destination)?;
        Ok(result)
    }
}

struct RestoreSink<'a> {
    seed: &'a CanonicalWalletSeed,
    chain: RecoveryChainContext,
    identity: &'a CoreChainIdentity,
    directory: &'a WalletDirectory,
    state: &'a mut Option<WalletState>,
    password: &'a str,
    kdf: KdfParameters,
    last_error: Option<SeedRestoreError>,
}

impl CoreScanTransactionSink for RestoreSink<'_> {
    type Error = SeedRestoreError;

    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error> {
        let state = self.state.as_ref().ok_or(SeedRestoreError::Storage)?;
        match state.core_scan_cursor.as_deref() {
            None => Ok(PersistedCoreCursorState::Absent),
            Some(bytes) => CoreCursorBytes::parse(bytes, self.identity)
                .map(PersistedCoreCursorState::Valid)
                .map_err(|_| SeedRestoreError::IncompatibleCheckpoint),
        }
    }

    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self
            .state
            .as_ref()
            .ok_or(SeedRestoreError::Storage)?
            .recovery_canonical_blocks
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.block_hash))
    }

    fn commit_core_batch(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        self.commit(batch, cursor, None)
    }

    fn commit_core_reorg(
        &mut self,
        safe_anchor: CoreBlockReference,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        self.commit(batch, cursor, Some(safe_anchor))
    }
}

impl RestoreSink<'_> {
    fn commit(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
        reorg_anchor: Option<CoreBlockReference>,
    ) -> Result<(), SeedRestoreError> {
        let mut state = self.state.take().ok_or(SeedRestoreError::Storage)?;
        let expected_generation = state.generation;
        let result = (|| {
            if let Some(anchor) = reorg_anchor {
                rewind_recovery_state(&mut state, anchor.height, batch.observed_tip.height);
            }
            apply_recovery_batch(self.seed, self.chain, self.identity, &mut state, batch)?;
            state.core_scan_cursor = Some(cursor.as_bytes().to_vec());
            state.seed_restore_status = Some(SeedRestoreStatus::InProgress);
            state.sync_status = SyncStatus::Synchronizing;
            state
                .validate()
                .map_err(|_| SeedRestoreError::MalformedRecovery)?;
            self.directory
                .commit(expected_generation, state, self.password, self.kdf)
                .map_err(|_| SeedRestoreError::Storage)
        })();
        match result {
            Ok(committed) => {
                *self.state = Some(committed);
                Ok(())
            }
            Err(error) => {
                *self.state = self.directory.load(self.password).ok();
                self.last_error = Some(error);
                Err(error)
            }
        }
    }
}

/// Apply one already validated canonical Core batch to encrypted Wallet state.
pub fn apply_recovery_batch(
    seed: &CanonicalWalletSeed,
    chain: RecoveryChainContext,
    identity: &CoreChainIdentity,
    state: &mut WalletState,
    batch: &CoreScanBatch,
) -> Result<(), SeedRestoreError> {
    let blocks = batch.blocks.iter().map(to_core_block).collect::<Vec<_>>();
    let restored = seed
        .restore_canonical_scan(chain, &blocks)
        .map_err(|error| match error {
            RestoreError::Continuity(_) => SeedRestoreError::ConflictingOutput,
            RestoreError::Malformed(_) | RestoreError::Crypto(_) => {
                SeedRestoreError::MalformedRecovery
            }
        })?;
    let positions = batch
        .blocks
        .iter()
        .flat_map(|block| block.outputs.iter())
        .map(|output| (output.commitment, output.output_position))
        .collect::<BTreeMap<_, _>>();

    for restored_output in restored.outputs() {
        merge_restored_output(
            state,
            restored_output,
            *positions
                .get(&restored_output.commitment)
                .ok_or(SeedRestoreError::MalformedRecovery)?,
            batch.observed_tip.height,
            identity.coinbase_maturity,
        )?;
    }

    let mut page_inputs = BTreeSet::new();
    for block in &batch.blocks {
        let legacy_count = block
            .outputs
            .iter()
            .filter(|output| output.recovery_version == 0 && output.recovery_capsule.is_empty())
            .count()
            .try_into()
            .map_err(|_| SeedRestoreError::MalformedRecovery)?;
        if let Some(existing) = state
            .recovery_canonical_blocks
            .iter()
            .find(|existing| existing.height == block.height)
        {
            if existing.block_hash != block.block_hash {
                return Err(SeedRestoreError::ConflictingOutput);
            }
        } else {
            state
                .recovery_canonical_blocks
                .push(RecoveryCanonicalBlock {
                    height: block.height,
                    block_hash: block.block_hash,
                    previous_block_hash: block.previous_block_hash,
                    output_count: block
                        .outputs
                        .len()
                        .try_into()
                        .map_err(|_| SeedRestoreError::MalformedRecovery)?,
                    legacy_proof_only_outputs: legacy_count,
                });
        }
        for input in &block.inputs {
            if !page_inputs.insert(input.spent_commitment) {
                return Err(SeedRestoreError::ConflictingOutput);
            }
            if let Some(output) = state
                .outputs
                .iter_mut()
                .find(|output| output.commitment == Some(input.spent_commitment))
            {
                match output.state {
                    OutputState::Spent { spent_height } if spent_height != block.height => {
                        return Err(SeedRestoreError::ConflictingOutput)
                    }
                    _ => {
                        output.state = OutputState::Spent {
                            spent_height: block.height,
                        };
                        output.reserved_by = None;
                    }
                }
            }
        }
    }
    state
        .recovery_canonical_blocks
        .sort_by_key(|block| block.height);
    state.legacy_proof_only_outputs = state
        .recovery_canonical_blocks
        .iter()
        .map(|block| u64::from(block.legacy_proof_only_outputs))
        .try_fold(0u64, u64::checked_add)
        .ok_or(SeedRestoreError::CoordinateOverflow)?;
    refresh_maturity(state, batch.observed_tip.height, identity.coinbase_maturity)?;
    Ok(())
}

fn merge_restored_output(
    state: &mut WalletState,
    restored: &dom_wallet_recovery::RestoredOutput,
    output_position: u32,
    tip_height: u64,
    coinbase_maturity: u64,
) -> Result<(), SeedRestoreError> {
    let domain = map_domain(restored.domain);
    update_floor(
        &mut state.recovery_allocation_floors,
        domain,
        restored.derivation_index,
    );
    state.non_reuse_floor = state.non_reuse_floor.max(restored.derivation_index);
    if let Some(existing) = state
        .outputs
        .iter()
        .find(|output| output.commitment == Some(restored.commitment))
    {
        let metadata = state
            .recovered_output_metadata
            .iter()
            .find(|metadata| metadata.output_id == existing.id)
            .ok_or(SeedRestoreError::ConflictingOutput)?;
        let blinding = state
            .output_blinding(existing.id)
            .ok_or(SeedRestoreError::ConflictingOutput)?;
        if existing.value != restored.value
            || existing.discovered_height != restored.block_height
            || metadata.recovery_account != restored.account
            || metadata.derivation_index != restored.derivation_index
            || metadata.domain != domain
            || metadata.block_hash != restored.block_hash
            || metadata.output_position != output_position
            || blinding != restored.blinding
        {
            return Err(SeedRestoreError::ConflictingOutput);
        }
        return Ok(());
    }
    let account_id = account_id_for(state, restored.account)?;
    let output_id = Uuid::new_v4();
    let state_value = recovered_output_state(restored, tip_height, coinbase_maturity)?;
    state.outputs.push(OutputRecord {
        id: output_id,
        account_id,
        commitment: Some(restored.commitment),
        value: restored.value,
        state: state_value,
        discovered_height: restored.block_height,
        reserved_by: None,
    });
    state.remember_output_blinding(output_id, restored.blinding);
    state
        .recovered_output_metadata
        .push(RecoveredOutputMetadata {
            output_id,
            recovery_account: restored.account,
            derivation_index: restored.derivation_index,
            domain,
            is_coinbase: restored.is_coinbase,
            block_hash: restored.block_hash,
            output_position,
        });
    Ok(())
}

fn recovered_output_state(
    restored: &dom_wallet_recovery::RestoredOutput,
    tip_height: u64,
    coinbase_maturity: u64,
) -> Result<OutputState, SeedRestoreError> {
    if let Some(spent_height) = restored.spent_at_height {
        return Ok(OutputState::Spent { spent_height });
    }
    if restored.is_coinbase {
        let required_height = restored
            .block_height
            .checked_add(coinbase_maturity)
            .ok_or(SeedRestoreError::CoordinateOverflow)?;
        if tip_height < required_height {
            return Ok(OutputState::Immature { required_height });
        }
    }
    Ok(OutputState::Confirmed)
}

fn refresh_maturity(
    state: &mut WalletState,
    tip_height: u64,
    coinbase_maturity: u64,
) -> Result<(), SeedRestoreError> {
    for output in &mut state.outputs {
        if matches!(output.state, OutputState::Spent { .. }) {
            continue;
        }
        let Some(metadata) = state
            .recovered_output_metadata
            .iter()
            .find(|metadata| metadata.output_id == output.id)
        else {
            continue;
        };
        if metadata.is_coinbase {
            let required_height = output
                .discovered_height
                .checked_add(coinbase_maturity)
                .ok_or(SeedRestoreError::CoordinateOverflow)?;
            output.state = if tip_height < required_height {
                OutputState::Immature { required_height }
            } else {
                OutputState::Confirmed
            };
        } else {
            output.state = OutputState::Confirmed;
        }
    }
    Ok(())
}

/// Rewind canonical recovery evidence while preserving allocation non-reuse floors.
pub fn rewind_recovery_state(state: &mut WalletState, safe_height: u64, tip_height: u64) {
    let removed_ids = state
        .outputs
        .iter()
        .filter(|output| output.discovered_height > safe_height)
        .map(|output| output.id)
        .collect::<BTreeSet<_>>();
    state
        .outputs
        .retain(|output| output.discovered_height <= safe_height);
    state
        .private_output_blindings
        .retain(|secret| !removed_ids.contains(&secret.output_id));
    state
        .recovered_output_metadata
        .retain(|metadata| !removed_ids.contains(&metadata.output_id));
    state
        .recovery_canonical_blocks
        .retain(|block| block.height <= safe_height);
    for output in &mut state.outputs {
        if matches!(output.state, OutputState::Spent { spent_height } if spent_height > safe_height)
        {
            output.state = OutputState::Confirmed;
        }
    }
    let _ = refresh_maturity(state, tip_height, 0);
}

fn account_id_for(
    state: &mut WalletState,
    recovery_account: u32,
) -> Result<Uuid, SeedRestoreError> {
    if recovery_account == 0 {
        return Ok(state.default_account.id);
    }
    if let Some(account) = state
        .recovered_accounts
        .iter()
        .find(|account| account.recovery_account == recovery_account)
    {
        return Ok(account.account_id);
    }
    if state.recovered_accounts.len() >= MAX_ACCOUNTS.saturating_sub(1) {
        return Err(SeedRestoreError::MalformedRecovery);
    }
    let account_id = Uuid::new_v4();
    state.recovered_accounts.push(RecoveredAccountMapping {
        recovery_account,
        account_id,
    });
    Ok(account_id)
}

fn update_floor(
    floors: &mut RecoveryAllocationFloors,
    domain: RecoveredOutputDomain,
    recovered_index: u64,
) {
    let floor = match domain {
        RecoveredOutputDomain::Received => &mut floors.received,
        RecoveredOutputDomain::Change => &mut floors.change,
        RecoveredOutputDomain::SelfTransfer => &mut floors.self_transfer,
        RecoveredOutputDomain::Coinbase => &mut floors.coinbase,
    };
    *floor = (*floor).max(recovered_index);
}

fn map_domain(domain: OutputRecoveryDomain) -> RecoveredOutputDomain {
    match domain {
        OutputRecoveryDomain::Received => RecoveredOutputDomain::Received,
        OutputRecoveryDomain::Change => RecoveredOutputDomain::Change,
        OutputRecoveryDomain::SelfTransfer => RecoveredOutputDomain::SelfTransfer,
        OutputRecoveryDomain::Coinbase => RecoveredOutputDomain::Coinbase,
    }
}

fn to_core_block(block: &dom_wallet_core_sync::CoreScanBlock) -> ScanBlock {
    ScanBlock {
        height: block.height,
        block_hash: block.block_hash,
        previous_block_hash: block.previous_block_hash,
        timestamp: block.timestamp,
        canonical_marker: block.canonical_marker,
        outputs: block
            .outputs
            .iter()
            .map(|output| ScanOutput {
                commitment: output.commitment,
                range_proof: output.range_proof.clone(),
                recovery_capsule: output.recovery_capsule.clone(),
                recovery_version: output.recovery_version,
                is_coinbase: output.is_coinbase,
                block_height: output.block_height,
                block_hash: output.block_hash,
                output_position: output.output_position,
            })
            .collect(),
        inputs: block
            .inputs
            .iter()
            .map(|input| ScanInput {
                spent_commitment: input.spent_commitment,
            })
            .collect(),
        kernels: block
            .kernels
            .iter()
            .map(|kernel| ScanKernel {
                excess: kernel.excess,
                features: kernel.features,
                fee: kernel.fee,
                lock_height: kernel.lock_height,
            })
            .collect(),
        coinbase: CoinbaseScanMetadata {
            output_commitment: block.coinbase.output_commitment,
            explicit_value: block.coinbase.explicit_value,
            kernel_excess: block.coinbase.kernel_excess,
        },
        total_fees_noms: block.total_fees_noms,
        protocol_version: block.protocol_version,
        range_proof_serialization_version: block.range_proof_serialization_version,
    }
}

fn initial_restore_state(
    seed: &CanonicalWalletSeed,
    identity: &CoreChainIdentity,
) -> Result<WalletState, SeedRestoreError> {
    let domain_identity = domain_identity(identity);
    let mut entropy = Zeroizing::new([0u8; 32]);
    seed.copy_entropy_to(&mut entropy);
    let mut state = WalletState::new(
        domain_identity.clone(),
        *entropy,
        default_node_configuration(domain_identity),
    );
    state.recovery = Some(RecoveryMetadata {
        scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
        phrase_confirmed: true,
    });
    state.seed_restore_status = Some(SeedRestoreStatus::InProgress);
    state.sync_status = SyncStatus::Synchronizing;
    Ok(state)
}

fn validate_checkpoint(
    state: &WalletState,
    seed: &CanonicalWalletSeed,
    identity: &CoreChainIdentity,
) -> Result<(), SeedRestoreError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    seed.copy_entropy_to(&mut entropy);
    if state.root_material != *entropy
        || state.identity != domain_identity(identity)
        || state.seed_restore_status != Some(SeedRestoreStatus::InProgress)
        || state
            .recovery
            .as_ref()
            .is_none_or(|recovery| recovery.scheme != RECOVERY_SCHEME_BIP39_256_V1)
    {
        return Err(SeedRestoreError::IncompatibleCheckpoint);
    }
    Ok(())
}

fn domain_identity(identity: &CoreChainIdentity) -> NetworkIdentity {
    NetworkIdentity {
        network: match identity.network {
            CoreNetwork::Mainnet => Network::Mainnet,
            CoreNetwork::Testnet => Network::PublicTestnet,
            CoreNetwork::Regtest => Network::PrivateTestnet,
        },
        chain_id: identity.chain_id,
        genesis_id: identity.genesis_hash,
    }
}

fn result_from_state(
    state: &WalletState,
    identity: &CoreChainIdentity,
) -> Result<SeedRestoreResult, SeedRestoreError> {
    let cursor = CoreCursorBytes::parse(
        state
            .core_scan_cursor
            .as_deref()
            .ok_or(SeedRestoreError::Incomplete)?,
        identity,
    )?;
    let final_cursor_anchor = cursor_anchor(cursor)?;
    let mut account_outputs = BTreeMap::<u32, Vec<OutputRecord>>::new();
    let metadata_by_id = state
        .recovered_output_metadata
        .iter()
        .map(|metadata| (metadata.output_id, metadata))
        .collect::<BTreeMap<_, _>>();
    for output in &state.outputs {
        let account = metadata_by_id
            .get(&output.id)
            .ok_or(SeedRestoreError::MalformedRecovery)?
            .recovery_account;
        account_outputs
            .entry(account)
            .or_default()
            .push(output.clone());
    }
    let accounts = account_outputs
        .into_iter()
        .map(|(recovery_account, outputs)| RecoveredAccountBalance {
            recovery_account,
            balance: BalanceProjection::from_outputs(&outputs),
        })
        .collect();
    let spent_outputs = state
        .outputs
        .iter()
        .filter(|output| matches!(output.state, OutputState::Spent { .. }))
        .count() as u64;
    let unspent_outputs = state.outputs.len() as u64 - spent_outputs;
    let coinbase_outputs = state
        .recovered_output_metadata
        .iter()
        .filter(|metadata| metadata.is_coinbase)
        .count() as u64;
    let scanned_outputs = state
        .recovery_canonical_blocks
        .iter()
        .try_fold(0u64, |total, block| {
            total.checked_add(u64::from(block.output_count))
        })
        .ok_or(SeedRestoreError::CoordinateOverflow)?;
    let mut warnings = vec![SeedRestoreWarning::OffChainMetadataNotRecoverableWithSeed];
    if state.legacy_proof_only_outputs != 0 {
        warnings.push(SeedRestoreWarning::LegacyBackupRequired);
    }
    Ok(SeedRestoreResult {
        completion: if state.outputs.is_empty() {
            SeedRestoreCompletion::NoOwnedOutputs
        } else {
            SeedRestoreCompletion::OwnedOutputsRecovered
        },
        network: identity.network,
        chain_id: identity.chain_id,
        scanned_blocks: state.recovery_canonical_blocks.len() as u64,
        scanned_outputs,
        owned_outputs: state.outputs.len() as u64,
        spent_outputs,
        unspent_outputs,
        coinbase_outputs,
        legacy_outputs: state.legacy_proof_only_outputs,
        balance: state.balance(),
        accounts,
        floors: state.recovery_allocation_floors,
        final_cursor_anchor,
        warnings,
    })
}

fn cursor_anchor(cursor: CoreCursorBytes) -> Result<CoreBlockReference, SeedRestoreError> {
    let cursor = cursor.decode().map_err(map_scan_error)?;
    Ok(CoreBlockReference {
        height: cursor.anchor_height,
        hash: cursor.anchor_hash,
    })
}

fn map_scan_error(error: CoreScanError) -> SeedRestoreError {
    match error {
        CoreScanError::InvalidIdentity { .. }
        | CoreScanError::IdentityMismatch { .. }
        | CoreScanError::CursorIdentityMismatch => SeedRestoreError::ChainIdentityMismatch,
        CoreScanError::Persistence => SeedRestoreError::Storage,
        _ => SeedRestoreError::CanonicalScan,
    }
}

fn validate_password(password: &str) -> Result<(), SeedRestoreError> {
    if (8..=1024).contains(&password.len()) {
        Ok(())
    } else {
        Err(SeedRestoreError::InvalidPassword)
    }
}

fn staging_path(destination: &Path) -> Result<PathBuf, SeedRestoreError> {
    let parent = destination
        .parent()
        .ok_or(SeedRestoreError::InvalidDestination)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or(SeedRestoreError::InvalidDestination)?;
    if !parent.is_dir() {
        return Err(SeedRestoreError::InvalidDestination);
    }
    Ok(parent.join(format!(".{name}.seed-restore")))
}

fn restrict_directory(path: &Path) -> Result<(), SeedRestoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| SeedRestoreError::Storage)?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), SeedRestoreError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(SeedRestoreError::InvalidDestination)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| SeedRestoreError::Storage)?;
    }
    Ok(())
}

/// Decrypted spending authority loaded only from encrypted Wallet state.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RestoredSpendSource {
    commitment: [u8; 33],
    value: u64,
    blinding: [u8; 32],
    block_height: u64,
    is_coinbase: bool,
}

impl fmt::Debug for RestoredSpendSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestoredSpendSource([REDACTED])")
    }
}

impl RestoredSpendSource {
    pub fn load(state: &WalletState, commitment: &[u8; 33]) -> Result<Self, SeedRestoreError> {
        let output = state
            .outputs
            .iter()
            .find(|output| output.commitment.as_ref() == Some(commitment))
            .filter(|output| matches!(output.state, OutputState::Confirmed))
            .ok_or(SeedRestoreError::MalformedRecovery)?;
        let metadata = state
            .recovered_output_metadata
            .iter()
            .find(|metadata| metadata.output_id == output.id)
            .ok_or(SeedRestoreError::MalformedRecovery)?;
        let blinding = state
            .output_blinding(output.id)
            .ok_or(SeedRestoreError::MalformedRecovery)?;
        Ok(Self {
            commitment: *commitment,
            value: output.value,
            blinding,
            block_height: output.discovered_height,
            is_coinbase: metadata.is_coinbase,
        })
    }
}

impl InputSource for RestoredSpendSource {
    fn commitment(&self) -> [u8; 33] {
        self.commitment
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn blinding(&self) -> [u8; 32] {
        self.blinding
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }
}

impl From<StorageError> for SeedRestoreError {
    fn from(_: StorageError) -> Self {
        Self::Storage
    }
}

impl From<CoreScanError> for SeedRestoreError {
    fn from(error: CoreScanError) -> Self {
        map_scan_error(error)
    }
}
