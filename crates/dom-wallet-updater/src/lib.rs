//! Signed update policy and managed node runtime primitives.

#![forbid(unsafe_code)]

use minisign_verify::{PublicKey, Signature};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

/// Nominal interval between automatic update checks.
pub const UPDATE_INTERVAL_SECONDS: u64 = 60 * 60;
/// Maximum startup jitter.
pub const MAX_INITIAL_JITTER_SECONDS: u64 = 5 * 60;
/// Stable software update feed.
pub const WALLET_UPDATE_ENDPOINT: &str =
    "https://github.com/sorenplanck/dom-wallet-v3/releases/latest/download/latest.json";
/// Stable node-only update feed.
pub const NODE_UPDATE_ENDPOINT: &str =
    "https://github.com/sorenplanck/dom-protocol/releases/latest/download/node-latest.json";
/// Signed operational Mainnet peer feed.
pub const PEER_UPDATE_ENDPOINT: &str =
    "https://github.com/sorenplanck/dom-wallet-v3/releases/latest/download/mainnet-peers.json";
/// Pinned DOM Protocol revision compiled into this Wallet.
pub const EMBEDDED_NODE_REVISION: &str = "28ba3cefc9fbc913f126336482662528c68a7d8c";
/// First immutable DOM Protocol revision with authenticated build-info and shutdown.
pub const MANAGED_NODE_CONTROL_REVISION: &str = "28ba3cefc9fbc913f126336482662528c68a7d8c";
/// Stable update channel.
pub const UPDATE_CHANNEL: &str = "stable";

const ALLOWED_DOWNLOAD_HOSTS: [&str; 4] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "dom-protocol.org",
];
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stable failures exposed to the UI without remote response bodies or secrets.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum UpdateError {
    #[error("UPDATE_CHECK_FAILED")]
    CheckFailed,
    #[error("UPDATE_MANIFEST_INVALID")]
    ManifestInvalid,
    #[error("UPDATE_SIGNATURE_INVALID")]
    SignatureInvalid,
    #[error("UPDATE_HASH_MISMATCH")]
    HashMismatch,
    #[error("UPDATE_SIZE_MISMATCH")]
    SizeMismatch,
    #[error("UPDATE_UNSUPPORTED_PLATFORM")]
    UnsupportedPlatform,
    #[error("UPDATE_DOWNGRADE_REJECTED")]
    DowngradeRejected,
    #[error("UPDATE_CHANNEL_INVALID")]
    ChannelInvalid,
    #[error("UPDATE_EXPIRED")]
    Expired,
    #[error("UPDATE_ORIGIN_REJECTED")]
    OriginRejected,
    #[error("UPDATE_BUSY_CRITICAL_OPERATION")]
    BusyCriticalOperation,
    #[error("UPDATE_MINER_STOP_FAILED")]
    MinerStopFailed,
    #[error("UPDATE_NODE_STOP_FAILED")]
    NodeStopFailed,
    #[error("UPDATE_WALLET_PERSIST_FAILED")]
    WalletPersistFailed,
    #[error("UPDATE_INSTALL_FAILED")]
    InstallFailed,
    #[error("UPDATE_RESTART_FAILED")]
    RestartFailed,
    #[error("NODE_IDENTITY_MISMATCH")]
    NodeIdentityMismatch,
    #[error("NODE_INCOMPATIBLE")]
    NodeIncompatible,
    #[error("PEER_MANIFEST_INVALID")]
    PeerManifestInvalid,
    #[error("PEER_MANIFEST_EXPIRED")]
    PeerManifestExpired,
    #[error("PEER_MANIFEST_IDENTITY_MISMATCH")]
    PeerManifestIdentityMismatch,
    #[error("UPDATE_CONCURRENT_CHECK")]
    ConcurrentCheck,
    #[error("UPDATE_STATE_IO")]
    StateIo,
    #[error("UPDATE_UNSAFE_PATH")]
    UnsafePath,
}

/// Signed artifact metadata for one platform.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub target: String,
    pub architecture: String,
    pub url: Url,
    pub sha256: String,
    pub size: u64,
    pub signature: String,
}

/// DOM metadata carried alongside the official Tauri updater schema.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletManifest {
    pub schema_version: u32,
    pub channel: String,
    pub version: String,
    pub published_at: String,
    pub expires_at: String,
    pub minimum_supported_version: String,
    pub critical_update: bool,
    pub draft: bool,
    pub prerelease: bool,
    pub release_url: Url,
    pub release_notes: String,
    pub wallet_revision: String,
    pub embedded_node_version: String,
    pub embedded_node_revision: String,
    pub network: String,
    pub minimum_wallet_schema: u32,
    pub artifact: ArtifactDescriptor,
    pub manifest_signature: String,
}

/// Installed Wallet constraints used to validate a remote manifest.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalletPolicy<'a> {
    pub installed_version: &'a str,
    pub update_channel: &'a str,
    pub target: &'a str,
    pub architecture: &'a str,
    pub network: &'a str,
    pub wallet_schema: u32,
}

/// Result of evaluating a Wallet update without downloading it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WalletDecision {
    UpToDate,
    Available(Version),
}

/// Validate all policy fields layered on top of Tauri's mandatory artifact signature.
pub fn validate_wallet_manifest(
    manifest: &WalletManifest,
    policy: &WalletPolicy<'_>,
    now: OffsetDateTime,
) -> Result<WalletDecision, UpdateError> {
    validate_schema_channel_time(
        manifest.schema_version,
        &manifest.channel,
        policy.update_channel,
        &manifest.published_at,
        &manifest.expires_at,
        now,
    )?;
    if manifest.draft || (policy.update_channel == UPDATE_CHANNEL && manifest.prerelease) {
        return Err(UpdateError::ManifestInvalid);
    }
    if manifest.network != policy.network
        || manifest.minimum_wallet_schema > policy.wallet_schema
        || manifest.wallet_revision.is_empty()
        || manifest.embedded_node_revision.is_empty()
        || manifest.manifest_signature.is_empty()
    {
        return Err(UpdateError::ManifestInvalid);
    }
    validate_release_url(&manifest.release_url)?;
    validate_artifact(&manifest.artifact, policy.target, policy.architecture)?;
    let installed =
        Version::parse(policy.installed_version).map_err(|_| UpdateError::ManifestInvalid)?;
    let available = Version::parse(&manifest.version).map_err(|_| UpdateError::ManifestInvalid)?;
    let minimum = Version::parse(&manifest.minimum_supported_version)
        .map_err(|_| UpdateError::ManifestInvalid)?;
    if available <= installed {
        return if available == installed {
            Ok(WalletDecision::UpToDate)
        } else {
            Err(UpdateError::DowngradeRejected)
        };
    }
    if installed < minimum {
        return Err(UpdateError::ManifestInvalid);
    }
    Ok(WalletDecision::Available(available))
}

/// Verify the complete Wallet metadata envelope before evaluating its policy.
pub fn verify_wallet_manifest_signature(
    manifest: &WalletManifest,
    verifier: &dyn SignatureVerifier,
) -> Result<(), UpdateError> {
    let mut signed = manifest.clone();
    signed.manifest_signature.clear();
    let canonical = serde_json::to_vec(&signed).map_err(|_| UpdateError::ManifestInvalid)?;
    verifier
        .verify(&canonical, &manifest.manifest_signature)
        .then_some(())
        .ok_or(UpdateError::SignatureInvalid)
}

/// Signed node-only feed.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeManifest {
    pub schema_version: u32,
    pub channel: String,
    pub node_version: String,
    pub node_revision: String,
    pub sequence: u64,
    pub published_at: String,
    pub expires_at: String,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
    pub storage_schema_version: u32,
    pub compatible_wallet_versions: String,
    pub requires_wallet_update: bool,
    pub node_only_compatible: bool,
    pub critical_update: bool,
    pub artifact: ArtifactDescriptor,
    pub manifest_signature: String,
}

/// Runtime compatibility contract expected by the installed Wallet.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeCompatibility {
    pub wallet_version: String,
    pub active_node_version: String,
    pub active_node_revision: String,
    pub update_sequence: u64,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
    pub storage_schema_version: u32,
    pub target: String,
    pub architecture: String,
}

/// Node feed decision.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NodeDecision {
    UpToDate,
    Available(Version),
    WalletUpdateRequired,
}

/// Validate node identity, monotonic sequence and explicit compatibility.
pub fn validate_node_manifest(
    manifest: &NodeManifest,
    compatibility: &NodeCompatibility,
    now: OffsetDateTime,
) -> Result<NodeDecision, UpdateError> {
    validate_schema_channel_time(
        manifest.schema_version,
        &manifest.channel,
        UPDATE_CHANNEL,
        &manifest.published_at,
        &manifest.expires_at,
        now,
    )?;
    if manifest.node_revision.is_empty()
        || manifest.manifest_signature.is_empty()
        || manifest.sequence <= compatibility.update_sequence
    {
        return Err(UpdateError::DowngradeRejected);
    }
    validate_artifact(
        &manifest.artifact,
        &compatibility.target,
        &compatibility.architecture,
    )?;
    let installed = Version::parse(&compatibility.active_node_version)
        .map_err(|_| UpdateError::ManifestInvalid)?;
    let available =
        Version::parse(&manifest.node_version).map_err(|_| UpdateError::ManifestInvalid)?;
    if available < installed {
        return Err(UpdateError::DowngradeRejected);
    }
    if available == installed && manifest.node_revision == compatibility.active_node_revision {
        return Ok(NodeDecision::UpToDate);
    }
    let wallet =
        Version::parse(&compatibility.wallet_version).map_err(|_| UpdateError::ManifestInvalid)?;
    let wallet_range = VersionReq::parse(&manifest.compatible_wallet_versions)
        .map_err(|_| UpdateError::ManifestInvalid)?;
    let incompatible = manifest.requires_wallet_update
        || !manifest.node_only_compatible
        || !wallet_range.matches(&wallet)
        || manifest.network != compatibility.network
        || manifest.chain_id != compatibility.chain_id
        || manifest.genesis_hash != compatibility.genesis_hash
        || manifest.rpc_protocol_version != compatibility.rpc_protocol_version
        || manifest.p2p_protocol_version != compatibility.p2p_protocol_version
        || manifest.storage_schema_version != compatibility.storage_schema_version;
    if incompatible {
        return Ok(NodeDecision::WalletUpdateRequired);
    }
    Ok(NodeDecision::Available(available))
}

/// Verify the complete node-only metadata envelope before compatibility checks.
pub fn verify_node_manifest_signature(
    manifest: &NodeManifest,
    verifier: &dyn SignatureVerifier,
) -> Result<(), UpdateError> {
    let mut signed = manifest.clone();
    signed.manifest_signature.clear();
    let canonical = serde_json::to_vec(&signed).map_err(|_| UpdateError::ManifestInvalid)?;
    verifier
        .verify(&canonical, &manifest.manifest_signature)
        .then_some(())
        .ok_or(UpdateError::SignatureInvalid)
}

/// Runtime identity returned by the authenticated local node RPC.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_version: String,
    pub node_revision: String,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
    pub storage_schema_version: u32,
}

/// Response currently provided by authenticated `GET /build-info`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBuildInfoResponse {
    pub commit: String,
}

/// Capabilities required before node-only promotion can be enabled.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NodeRpcIdentityCapabilities {
    pub build_revision: bool,
    pub network: bool,
    pub chain_id: bool,
    pub genesis_hash: bool,
    pub rpc_protocol_version: bool,
    pub p2p_protocol_version: bool,
    pub storage_schema_version: bool,
    pub graceful_shutdown: bool,
}

impl NodeRpcIdentityCapabilities {
    pub fn permits_node_only_update(self) -> bool {
        self.build_revision
            && self.network
            && self.chain_id
            && self.genesis_hash
            && self.rpc_protocol_version
            && self.p2p_protocol_version
            && self.storage_schema_version
            && self.graceful_shutdown
    }
}

/// Validate the revision returned by the authenticated control plane.
pub fn validate_node_build_info(
    response: &NodeBuildInfoResponse,
    expected_revision: &str,
) -> Result<(), UpdateError> {
    if response.commit.len() != 40
        || !response.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !response.commit.eq_ignore_ascii_case(expected_revision)
    {
        return Err(UpdateError::NodeIdentityMismatch);
    }
    Ok(())
}

/// Validate the process-reported identity rather than trusting its path or manifest.
pub fn validate_node_identity(
    actual: &NodeIdentity,
    manifest: &NodeManifest,
) -> Result<(), UpdateError> {
    if actual.node_version != manifest.node_version
        || actual.node_revision != manifest.node_revision
        || actual.network != manifest.network
        || actual.chain_id != manifest.chain_id
        || actual.genesis_hash != manifest.genesis_hash
        || actual.rpc_protocol_version != manifest.rpc_protocol_version
        || actual.p2p_protocol_version != manifest.p2p_protocol_version
        || actual.storage_schema_version != manifest.storage_schema_version
    {
        return Err(UpdateError::NodeIdentityMismatch);
    }
    Ok(())
}

/// Signed peer payload; it cannot carry commands or binaries.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerManifestPayload {
    pub schema_version: u32,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub generated_at: String,
    pub expires_at: String,
    pub sequence: u64,
    pub peers: Vec<String>,
}

/// Detached signed peer envelope.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPeerManifest {
    pub payload: PeerManifestPayload,
    pub signature: String,
}

/// Minimal signature abstraction for deterministic tests.
pub trait SignatureVerifier {
    fn verify(&self, payload: &[u8], signature: &str) -> bool;
}

/// Production Minisign verifier shared with the official Tauri updater format.
#[derive(Debug, Clone)]
pub struct MinisignVerifier {
    public_key: PublicKey,
}

impl MinisignVerifier {
    pub fn from_base64(public_key: &str) -> Result<Self, UpdateError> {
        PublicKey::from_base64(public_key)
            .map(|public_key| Self { public_key })
            .map_err(|_| UpdateError::SignatureInvalid)
    }
}

impl SignatureVerifier for MinisignVerifier {
    fn verify(&self, payload: &[u8], signature: &str) -> bool {
        Signature::decode(signature)
            .and_then(|signature| self.public_key.verify(payload, &signature, false))
            .is_ok()
    }
}

/// Validate signature, identity, expiry, sequence and routability, preserving order.
pub fn validate_peer_manifest(
    manifest: &SignedPeerManifest,
    verifier: &dyn SignatureVerifier,
    expected_chain_id: &str,
    expected_genesis_hash: &str,
    previous_sequence: u64,
    now: OffsetDateTime,
) -> Result<Vec<SocketAddr>, UpdateError> {
    let canonical =
        serde_json::to_vec(&manifest.payload).map_err(|_| UpdateError::PeerManifestInvalid)?;
    if !verifier.verify(&canonical, &manifest.signature) {
        return Err(UpdateError::SignatureInvalid);
    }
    if manifest.payload.schema_version != 1
        || manifest.payload.network != "mainnet"
        || manifest.payload.chain_id != expected_chain_id
        || manifest.payload.genesis_hash != expected_genesis_hash
    {
        return Err(UpdateError::PeerManifestIdentityMismatch);
    }
    validate_time_window(
        &manifest.payload.generated_at,
        &manifest.payload.expires_at,
        now,
    )
    .map_err(|error| match error {
        UpdateError::Expired => UpdateError::PeerManifestExpired,
        _ => UpdateError::PeerManifestInvalid,
    })?;
    if manifest.payload.sequence <= previous_sequence {
        return Err(UpdateError::DowngradeRejected);
    }
    let mut seen = HashSet::new();
    let peers = manifest
        .payload
        .peers
        .iter()
        .map(|peer| {
            peer.parse::<SocketAddr>()
                .map_err(|_| UpdateError::PeerManifestInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|peer| is_public_routable_peer(*peer))
        .filter(|peer| seen.insert(*peer))
        .collect::<Vec<_>>();
    if peers.is_empty() {
        return Err(UpdateError::PeerManifestInvalid);
    }
    Ok(prioritize_mainnet_relay(peers))
}

pub fn persist_peer_manifest_cache(
    path: &Path,
    manifest: &SignedPeerManifest,
) -> Result<(), UpdateError> {
    let parent = path.parent().ok_or(UpdateError::StateIo)?;
    fs::create_dir_all(parent).map_err(|_| UpdateError::StateIo)?;
    let bytes = serde_json::to_vec(manifest).map_err(|_| UpdateError::PeerManifestInvalid)?;
    let temporary = parent.join(format!(
        ".peer-manifest.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| UpdateError::StateIo)?;
    let result = (|| {
        file.write_all(&bytes).map_err(|_| UpdateError::StateIo)?;
        file.sync_all().map_err(|_| UpdateError::StateIo)?;
        fs::rename(&temporary, path).map_err(|_| UpdateError::StateIo)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn load_valid_peer_manifest_cache(
    path: &Path,
    verifier: &dyn SignatureVerifier,
    expected_chain_id: &str,
    expected_genesis_hash: &str,
    previous_sequence: u64,
    now: OffsetDateTime,
) -> Result<(u64, Vec<SocketAddr>), UpdateError> {
    let bytes = fs::read(path).map_err(|_| UpdateError::StateIo)?;
    let manifest: SignedPeerManifest =
        serde_json::from_slice(&bytes).map_err(|_| UpdateError::PeerManifestInvalid)?;
    let peers = validate_peer_manifest(
        &manifest,
        verifier,
        expected_chain_id,
        expected_genesis_hash,
        previous_sequence,
        now,
    )?;
    Ok((manifest.payload.sequence, peers))
}

fn prioritize_mainnet_relay(mut peers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    const PRIORITY: [&str; 2] = ["168.100.9.70:8443", "168.100.9.70:33369"];
    peers.sort_by_key(|peer| {
        PRIORITY
            .iter()
            .position(|priority| peer.to_string() == *priority)
            .unwrap_or(PRIORITY.len())
    });
    peers
}

fn validate_schema_channel_time(
    schema_version: u32,
    channel: &str,
    expected_channel: &str,
    published_at: &str,
    expires_at: &str,
    now: OffsetDateTime,
) -> Result<(), UpdateError> {
    if schema_version != 1 {
        return Err(UpdateError::ManifestInvalid);
    }
    if channel != expected_channel {
        return Err(UpdateError::ChannelInvalid);
    }
    validate_time_window(published_at, expires_at, now)
}

fn validate_time_window(
    published_at: &str,
    expires_at: &str,
    now: OffsetDateTime,
) -> Result<(), UpdateError> {
    let published =
        OffsetDateTime::parse(published_at, &time::format_description::well_known::Rfc3339)
            .map_err(|_| UpdateError::ManifestInvalid)?;
    let expires = OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
        .map_err(|_| UpdateError::ManifestInvalid)?;
    if expires <= published || expires <= now || published > now + time::Duration::minutes(5) {
        return Err(UpdateError::Expired);
    }
    Ok(())
}

/// Restrict update endpoints and every redirect to approved HTTPS origins on port 443.
pub fn validate_release_url(url: &Url) -> Result<(), UpdateError> {
    let approved = url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .is_some_and(|host| ALLOWED_DOWNLOAD_HOSTS.contains(&host));
    approved.then_some(()).ok_or(UpdateError::OriginRejected)
}

fn validate_artifact(
    artifact: &ArtifactDescriptor,
    target: &str,
    architecture: &str,
) -> Result<(), UpdateError> {
    if artifact.target != target || artifact.architecture != architecture {
        return Err(UpdateError::UnsupportedPlatform);
    }
    validate_release_url(&artifact.url)?;
    if artifact.size == 0
        || artifact.signature.trim().is_empty()
        || artifact.sha256.len() != 64
        || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(UpdateError::ManifestInvalid);
    }
    Ok(())
}

/// Verify size and digest in addition to the mandatory Minisign verification.
pub fn validate_download(bytes: &[u8], artifact: &ArtifactDescriptor) -> Result<(), UpdateError> {
    if bytes.len() as u64 != artifact.size {
        return Err(UpdateError::SizeMismatch);
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    if !digest.eq_ignore_ascii_case(&artifact.sha256) {
        return Err(UpdateError::HashMismatch);
    }
    Ok(())
}

/// Persisted non-secret updater metadata.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMetadataState {
    pub schema_version: u32,
    pub last_check_at: Option<String>,
    pub last_successful_check_at: Option<String>,
    pub installed_version: String,
    pub installed_wallet_revision: String,
    pub installed_node_revision: String,
    pub latest_seen_version: Option<String>,
    pub pending_version: Option<String>,
    pub channel: String,
    pub wallet_state: WalletUpdaterState,
    pub node_state: NodeUpdaterState,
    pub last_sanitized_error: Option<String>,
    pub etag: Option<String>,
    pub successful_update_at: Option<String>,
}

/// Wallet updater lifecycle.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletUpdaterState {
    Idle,
    Checking,
    UpToDate,
    WalletUpdateAvailable,
    Downloading,
    Verifying,
    WaitingForSafePoint,
    Installing,
    Restarting,
    Failed,
}

/// Independent node updater lifecycle.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeUpdaterState {
    Idle,
    Checking,
    UpToDate,
    NodeUpdateAvailable,
    Downloading,
    Verifying,
    WaitingForSafePoint,
    StoppingMiner,
    StoppingNode,
    Promoting,
    StartingNode,
    HealthCheck,
    Succeeded,
    RollingBack,
    RolledBack,
    WalletUpdateRequired,
    Failed,
}

/// Crash-safe metadata write using a same-directory temporary file and atomic rename.
pub fn persist_update_state(path: &Path, state: &UpdateMetadataState) -> Result<(), UpdateError> {
    let parent = path.parent().ok_or(UpdateError::StateIo)?;
    fs::create_dir_all(parent).map_err(|_| UpdateError::StateIo)?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(UpdateError::StateIo)?,
        std::process::id(),
        TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = serde_json::to_vec(state).map_err(|_| UpdateError::StateIo)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| UpdateError::StateIo)?;
    let result = (|| {
        file.write_all(&bytes).map_err(|_| UpdateError::StateIo)?;
        file.sync_all().map_err(|_| UpdateError::StateIo)?;
        fs::rename(&temporary, path).map_err(|_| UpdateError::StateIo)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), UpdateError> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| UpdateError::StateIo)?;
    }
    Ok(())
}

/// Monotonic hourly schedule with bounded initial jitter and concurrency guard.
#[derive(Debug)]
pub struct UpdateSchedule {
    next_check_seconds: u64,
    check_in_progress: AtomicBool,
}

impl UpdateSchedule {
    pub fn new(now_seconds: u64, initial_jitter_seconds: u64) -> Self {
        Self {
            next_check_seconds: now_seconds
                + initial_jitter_seconds.min(MAX_INITIAL_JITTER_SECONDS),
            check_in_progress: AtomicBool::new(false),
        }
    }

    pub fn is_due(&self, now_seconds: u64) -> bool {
        now_seconds >= self.next_check_seconds
    }

    pub fn begin_check(&self) -> Result<(), UpdateError> {
        self.check_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| UpdateError::ConcurrentCheck)
    }

    pub fn finish_check(&mut self, now_seconds: u64) {
        self.next_check_seconds = now_seconds + UPDATE_INTERVAL_SECONDS;
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn on_resume(&mut self, now_seconds: u64) {
        self.next_check_seconds = now_seconds;
    }

    pub fn next_check_seconds(&self) -> u64 {
        self.next_check_seconds
    }
}

/// Sidecar runtime state authenticated by its state file and binary digest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeState {
    pub schema_version: u32,
    pub active_version: String,
    pub active_revision: String,
    pub previous_version: Option<String>,
    pub previous_revision: Option<String>,
    pub installed_at: String,
    pub binary_sha256: String,
    pub signature_identity: String,
    pub compatibility: NodeCompatibility,
    pub update_sequence: u64,
    pub temporarily_denied_revision: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NodeRuntimeLayout {
    root: PathBuf,
}

impl NodeRuntimeLayout {
    pub fn initialize(root: &Path) -> Result<Self, UpdateError> {
        if root
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(UpdateError::UnsafePath);
        }
        fs::create_dir_all(root.join("staging")).map_err(|_| UpdateError::StateIo)?;
        fs::create_dir_all(root.join("nodes")).map_err(|_| UpdateError::StateIo)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::StateIo)?;
            fs::set_permissions(root.join("staging"), fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::StateIo)?;
            fs::set_permissions(root.join("nodes"), fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::StateIo)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn stage_verified_node(
        &self,
        version: &str,
        revision: &str,
        bytes: &[u8],
        artifact: &ArtifactDescriptor,
    ) -> Result<PathBuf, UpdateError> {
        validate_download(bytes, artifact)?;
        let directory_name = validated_node_directory_name(version, revision)?;
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stage = self.root.join("staging").join(format!(
            "{directory_name}.{}.{}",
            std::process::id(),
            sequence
        ));
        validate_runtime_destination(
            &self.root,
            stage
                .strip_prefix(&self.root)
                .map_err(|_| UpdateError::UnsafePath)?,
        )?;
        fs::create_dir(&stage).map_err(|_| UpdateError::StateIo)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))
                .map_err(|_| UpdateError::StateIo)?;
        }
        let binary = stage.join(node_binary_name());
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut file = options.open(&binary).map_err(|_| UpdateError::StateIo)?;
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| UpdateError::StateIo)
        {
            let _ = fs::remove_file(&binary);
            let _ = fs::remove_dir(&stage);
            return Err(error);
        }
        sync_directory(&stage)?;
        Ok(stage)
    }

    pub fn promote_staged_node(
        &self,
        stage: &Path,
        version: &str,
        revision: &str,
    ) -> Result<PathBuf, UpdateError> {
        let directory_name = validated_node_directory_name(version, revision)?;
        let staging_root = self.root.join("staging");
        if stage.parent() != Some(staging_root.as_path())
            || stage
                .symlink_metadata()
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(true)
            || !stage.join(node_binary_name()).is_file()
        {
            return Err(UpdateError::UnsafePath);
        }
        let destination = self.root.join("nodes").join(directory_name);
        if destination.exists() {
            return Err(UpdateError::UnsafePath);
        }
        fs::rename(stage, &destination).map_err(|_| UpdateError::StateIo)?;
        sync_directory(&self.root.join("nodes"))?;
        Ok(destination)
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("node-state.json")
    }
}

fn validated_node_directory_name(version: &str, revision: &str) -> Result<String, UpdateError> {
    Version::parse(version).map_err(|_| UpdateError::ManifestInvalid)?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UpdateError::ManifestInvalid);
    }
    Ok(format!("{version}-{}", revision.to_ascii_lowercase()))
}

fn node_binary_name() -> &'static str {
    if cfg!(windows) {
        "dom-node.exe"
    } else {
        "dom-node"
    }
}

pub fn persist_node_runtime_state(
    layout: &NodeRuntimeLayout,
    state: &NodeRuntimeState,
) -> Result<(), UpdateError> {
    let state_path = layout.state_path();
    let metadata = serde_json::to_vec(state).map_err(|_| UpdateError::StateIo)?;
    let parent = state_path.parent().ok_or(UpdateError::StateIo)?;
    let temporary = parent.join(format!(
        ".node-state.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| UpdateError::StateIo)?;
    let result = (|| {
        file.write_all(&metadata)
            .map_err(|_| UpdateError::StateIo)?;
        file.sync_all().map_err(|_| UpdateError::StateIo)?;
        fs::rename(&temporary, &state_path).map_err(|_| UpdateError::StateIo)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Reject traversal and existing symlink/reparse-like paths before promotion.
pub fn validate_runtime_destination(root: &Path, relative: &Path) -> Result<(), UpdateError> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(UpdateError::UnsafePath);
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(component) = component {
            current.push(component);
            if current
                .symlink_metadata()
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(UpdateError::UnsafePath);
            }
        }
    }
    Ok(())
}

/// Backend boundary used by the production sidecar manager and deterministic tests.
pub trait NodeUpdateBackend {
    fn critical_operation_active(&self) -> bool;
    fn stop_miner(&mut self) -> Result<(), UpdateError>;
    fn persist_wallet_cursor_and_journal(&mut self) -> Result<(), UpdateError>;
    fn stop_node(&mut self) -> Result<u32, UpdateError>;
    fn process_is_stopped(&self, pid: u32) -> bool;
    fn local_ports_released(&self) -> bool;
    fn promote_staged_node(&mut self) -> Result<(), UpdateError>;
    fn start_node(&mut self) -> Result<u32, UpdateError>;
    fn handshake(&self) -> Result<NodeIdentity, UpdateError>;
    fn ready(&self) -> bool;
    fn cursor_is_canonical(&self) -> bool;
    fn connected_peers(&self) -> usize;
    fn rollback(&mut self) -> Result<(), UpdateError>;
    fn expected_previous_identity(&self) -> NodeIdentity;
}

/// Apply a node-only update. Success is impossible before restart, handshake and READY.
pub fn apply_node_update(
    backend: &mut dyn NodeUpdateBackend,
    manifest: &NodeManifest,
) -> Result<NodeUpdaterState, UpdateError> {
    if backend.critical_operation_active() {
        return Ok(NodeUpdaterState::WaitingForSafePoint);
    }
    backend.stop_miner()?;
    backend.persist_wallet_cursor_and_journal()?;
    let previous_pid = backend.stop_node()?;
    if !backend.process_is_stopped(previous_pid) || !backend.local_ports_released() {
        return Err(UpdateError::NodeStopFailed);
    }
    backend.promote_staged_node()?;
    let new_pid = match backend.start_node() {
        Ok(pid) if pid != previous_pid => pid,
        _ => return rollback_node(backend, UpdateError::RestartFailed),
    };
    let identity = match backend.handshake() {
        Ok(identity) => identity,
        Err(error) => return rollback_node(backend, error),
    };
    if let Err(error) = validate_node_identity(&identity, manifest) {
        return rollback_node(backend, error);
    }
    if !backend.ready() || !backend.cursor_is_canonical() || backend.connected_peers() == 0 {
        return rollback_node(backend, UpdateError::NodeIncompatible);
    }
    let _ = new_pid;
    Ok(NodeUpdaterState::Succeeded)
}

fn rollback_node(
    backend: &mut dyn NodeUpdateBackend,
    cause: UpdateError,
) -> Result<NodeUpdaterState, UpdateError> {
    backend.rollback().map_err(|_| cause)?;
    let _rollback_pid = backend.start_node().map_err(|_| cause)?;
    let expected = backend.expected_previous_identity();
    if backend.handshake().as_ref() != Ok(&expected) || !backend.ready() {
        return Err(cause);
    }
    Ok(NodeUpdaterState::RolledBack)
}

fn is_public_routable_peer(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    if a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return false;
    }
    !(a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.to_ipv4().is_some()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
    {
        return false;
    }
    let discard_only = segments[0] == 0x0100 && segments[1..].iter().all(|segment| *segment == 0);
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let benchmark = segments[0] == 0x2001 && segments[1] == 0x0002;
    !(discard_only || documentation || benchmark)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NOW: &str = "2026-07-23T12:00:00Z";

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(NOW, &time::format_description::well_known::Rfc3339)
            .expect("test timestamp")
    }

    fn artifact() -> ArtifactDescriptor {
        let bytes = b"signed update";
        ArtifactDescriptor {
            target: "linux".into(),
            architecture: "x86_64".into(),
            url: Url::parse(
                "https://github.com/sorenplanck/dom-wallet-v3/releases/download/v1/app",
            )
            .expect("URL"),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
            signature: "trusted-test-signature".into(),
        }
    }

    fn wallet_manifest(version: &str) -> WalletManifest {
        WalletManifest {
            schema_version: 1,
            channel: "stable".into(),
            version: version.into(),
            published_at: "2026-07-23T11:00:00Z".into(),
            expires_at: "2026-08-23T12:00:00Z".into(),
            minimum_supported_version: "0.2.0".into(),
            critical_update: false,
            draft: false,
            prerelease: false,
            release_url: Url::parse(
                "https://github.com/sorenplanck/dom-wallet-v3/releases/tag/wallet-v0.2.1",
            )
            .expect("URL"),
            release_notes: "Security and reliability update.".into(),
            wallet_revision: "a".repeat(40),
            embedded_node_version: "0.1.0".into(),
            embedded_node_revision: "b".repeat(40),
            network: "mainnet".into(),
            minimum_wallet_schema: 2,
            artifact: artifact(),
            manifest_signature: "manifest-signature".into(),
        }
    }

    fn wallet_policy() -> WalletPolicy<'static> {
        WalletPolicy {
            installed_version: "0.2.0",
            update_channel: "stable",
            target: "linux",
            architecture: "x86_64",
            network: "mainnet",
            wallet_schema: 2,
        }
    }

    fn node_manifest() -> NodeManifest {
        NodeManifest {
            schema_version: 1,
            channel: "stable".into(),
            node_version: "0.1.1".into(),
            node_revision: "c".repeat(40),
            sequence: 2,
            published_at: "2026-07-23T11:00:00Z".into(),
            expires_at: "2026-08-23T12:00:00Z".into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version: 1,
            compatible_wallet_versions: ">=0.2.0, <0.3.0".into(),
            requires_wallet_update: false,
            node_only_compatible: true,
            critical_update: false,
            artifact: artifact(),
            manifest_signature: "manifest-signature".into(),
        }
    }

    fn compatibility() -> NodeCompatibility {
        NodeCompatibility {
            wallet_version: "0.2.0".into(),
            active_node_version: "0.1.0".into(),
            active_node_revision: "b".repeat(40),
            update_sequence: 1,
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version: 1,
            target: "linux".into(),
            architecture: "x86_64".into(),
        }
    }

    #[test]
    fn wallet_policy_accepts_only_newer_stable_signed_metadata() {
        assert_eq!(
            validate_wallet_manifest(&wallet_manifest("0.2.1"), &wallet_policy(), now()),
            Ok(WalletDecision::Available(
                Version::parse("0.2.1").expect("version")
            ))
        );
        assert_eq!(
            validate_wallet_manifest(&wallet_manifest("0.2.0"), &wallet_policy(), now()),
            Ok(WalletDecision::UpToDate)
        );
        assert_eq!(
            validate_wallet_manifest(&wallet_manifest("0.1.9"), &wallet_policy(), now()),
            Err(UpdateError::DowngradeRejected)
        );
    }

    #[test]
    fn wallet_policy_rejects_invalid_semver_expiry_channel_and_release_class() {
        let mut manifest = wallet_manifest("invalid");
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::ManifestInvalid)
        );
        manifest = wallet_manifest("0.2.1");
        manifest.expires_at = "2026-07-23T11:30:00Z".into();
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::Expired)
        );
        manifest = wallet_manifest("0.2.1");
        manifest.channel = "beta".into();
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::ChannelInvalid)
        );
        manifest = wallet_manifest("0.2.1");
        manifest.draft = true;
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::ManifestInvalid)
        );
        manifest.draft = false;
        manifest.prerelease = true;
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::ManifestInvalid)
        );
    }

    #[test]
    fn wallet_and_node_metadata_require_valid_detached_signatures() {
        struct RejectSignature;
        impl SignatureVerifier for RejectSignature {
            fn verify(&self, _payload: &[u8], _signature: &str) -> bool {
                false
            }
        }

        let mut wallet = wallet_manifest("0.2.1");
        wallet.manifest_signature = "valid".into();
        let mut node = node_manifest();
        node.manifest_signature = "valid".into();
        assert_eq!(
            verify_wallet_manifest_signature(&wallet, &AcceptSignature),
            Ok(())
        );
        assert_eq!(
            verify_node_manifest_signature(&node, &AcceptSignature),
            Ok(())
        );
        assert_eq!(
            verify_wallet_manifest_signature(&wallet_manifest("0.2.1"), &RejectSignature),
            Err(UpdateError::SignatureInvalid)
        );
        assert_eq!(
            verify_node_manifest_signature(&node_manifest(), &RejectSignature),
            Err(UpdateError::SignatureInvalid)
        );
    }

    #[test]
    fn origins_platform_hash_and_size_fail_closed() {
        let mut manifest = wallet_manifest("0.2.1");
        manifest.artifact.url = Url::parse("http://github.com/file").expect("URL");
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::OriginRejected)
        );
        manifest.artifact.url = Url::parse("https://evil.example/file").expect("URL");
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::OriginRejected)
        );
        manifest = wallet_manifest("0.2.1");
        manifest.artifact.target = "windows".into();
        assert_eq!(
            validate_wallet_manifest(&manifest, &wallet_policy(), now()),
            Err(UpdateError::UnsupportedPlatform)
        );
        let valid = artifact();
        assert_eq!(validate_download(b"signed update", &valid), Ok(()));
        assert_eq!(
            validate_download(b"truncated", &valid),
            Err(UpdateError::SizeMismatch)
        );
        let mut wrong_hash = valid;
        wrong_hash.sha256 = "0".repeat(64);
        assert_eq!(
            validate_download(b"signed update", &wrong_hash),
            Err(UpdateError::HashMismatch)
        );
    }

    #[test]
    fn compatible_node_only_update_is_independent_from_wallet_update() {
        assert_eq!(
            validate_node_manifest(&node_manifest(), &compatibility(), now()),
            Ok(NodeDecision::Available(
                Version::parse("0.1.1").expect("version")
            ))
        );
    }

    #[test]
    fn incompatible_node_requires_wallet_update() {
        for mutate in 0..5 {
            let mut manifest = node_manifest();
            match mutate {
                0 => manifest.requires_wallet_update = true,
                1 => manifest.rpc_protocol_version = 2,
                2 => manifest.p2p_protocol_version = 2,
                3 => manifest.storage_schema_version = 2,
                _ => manifest.network = "testnet".into(),
            }
            assert_eq!(
                validate_node_manifest(&manifest, &compatibility(), now()),
                Ok(NodeDecision::WalletUpdateRequired)
            );
        }
    }

    #[test]
    fn node_sequence_and_version_never_downgrade() {
        let mut manifest = node_manifest();
        manifest.sequence = 1;
        assert_eq!(
            validate_node_manifest(&manifest, &compatibility(), now()),
            Err(UpdateError::DowngradeRejected)
        );
        manifest.sequence = 2;
        manifest.node_version = "0.0.9".into();
        assert_eq!(
            validate_node_manifest(&manifest, &compatibility(), now()),
            Err(UpdateError::DowngradeRejected)
        );
    }

    struct AcceptSignature;
    impl SignatureVerifier for AcceptSignature {
        fn verify(&self, _payload: &[u8], signature: &str) -> bool {
            signature == "valid"
        }
    }

    fn peers() -> SignedPeerManifest {
        SignedPeerManifest {
            payload: PeerManifestPayload {
                schema_version: 1,
                network: "mainnet".into(),
                chain_id: "chain".into(),
                genesis_hash: "genesis".into(),
                generated_at: "2026-07-23T11:00:00Z".into(),
                expires_at: "2026-08-23T12:00:00Z".into(),
                sequence: 2,
                peers: vec![
                    "168.100.9.70:33369".into(),
                    "168.100.9.70:8443".into(),
                    "168.100.9.70:8443".into(),
                    "168.100.8.144:33369".into(),
                ],
            },
            signature: "valid".into(),
        }
    }

    #[test]
    fn peer_manifest_is_signed_ordered_and_deduplicated() {
        let result =
            validate_peer_manifest(&peers(), &AcceptSignature, "chain", "genesis", 1, now())
                .expect("valid peer manifest");
        assert_eq!(
            result,
            vec![
                "168.100.9.70:8443".parse().expect("address"),
                "168.100.9.70:33369".parse().expect("address"),
                "168.100.8.144:33369".parse().expect("address"),
            ]
        );
    }

    #[test]
    fn peer_manifest_rejects_signature_identity_sequence_expiry_and_unroutable_only() {
        let mut manifest = peers();
        manifest.signature = "invalid".into();
        assert_eq!(
            validate_peer_manifest(&manifest, &AcceptSignature, "chain", "genesis", 1, now()),
            Err(UpdateError::SignatureInvalid)
        );
        manifest = peers();
        manifest.payload.chain_id = "wrong".into();
        assert_eq!(
            validate_peer_manifest(&manifest, &AcceptSignature, "chain", "genesis", 1, now()),
            Err(UpdateError::PeerManifestIdentityMismatch)
        );
        manifest = peers();
        assert_eq!(
            validate_peer_manifest(&manifest, &AcceptSignature, "chain", "genesis", 2, now()),
            Err(UpdateError::DowngradeRejected)
        );
        manifest.payload.sequence = 3;
        manifest.payload.expires_at = "2026-07-23T11:30:00Z".into();
        assert_eq!(
            validate_peer_manifest(&manifest, &AcceptSignature, "chain", "genesis", 2, now()),
            Err(UpdateError::PeerManifestExpired)
        );
        manifest = peers();
        manifest.payload.peers = vec!["127.0.0.1:8443".into(), "10.0.0.1:33369".into()];
        assert_eq!(
            validate_peer_manifest(&manifest, &AcceptSignature, "chain", "genesis", 1, now()),
            Err(UpdateError::PeerManifestInvalid)
        );
    }

    #[test]
    fn authenticated_peer_cache_works_offline_and_rejects_tampering() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("mainnet-peers.json");
        let manifest = peers();
        persist_peer_manifest_cache(&path, &manifest).expect("cache signed manifest");
        let (sequence, loaded) =
            load_valid_peer_manifest_cache(&path, &AcceptSignature, "chain", "genesis", 1, now())
                .expect("load authenticated cache");
        assert_eq!(sequence, 2);
        assert_eq!(
            loaded.first().map(ToString::to_string).as_deref(),
            Some("168.100.9.70:8443")
        );

        let mut tampered = manifest;
        tampered.payload.chain_id = "other-chain".into();
        persist_peer_manifest_cache(&path, &tampered).expect("write tampered envelope");
        assert_eq!(
            load_valid_peer_manifest_cache(&path, &AcceptSignature, "chain", "genesis", 1, now()),
            Err(UpdateError::PeerManifestIdentityMismatch)
        );
    }

    #[test]
    fn minisign_verifier_matches_official_test_vector() {
        let verifier = MinisignVerifier::from_base64(
            "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3",
        )
        .expect("public key");
        let signature = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1633700835\tfile:test\tprehashed\nwLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";
        assert!(verifier.verify(b"test", signature));
        assert!(!verifier.verify(b"tampered", signature));
    }

    #[test]
    fn scheduler_is_hourly_resume_aware_and_single_flight() {
        let mut schedule = UpdateSchedule::new(100, 999);
        assert_eq!(schedule.next_check_seconds(), 400);
        assert!(!schedule.is_due(399));
        assert!(schedule.is_due(400));
        assert_eq!(schedule.begin_check(), Ok(()));
        assert_eq!(schedule.begin_check(), Err(UpdateError::ConcurrentCheck));
        schedule.finish_check(500);
        assert_eq!(schedule.next_check_seconds(), 4_100);
        schedule.on_resume(600);
        assert!(schedule.is_due(600));
    }

    #[test]
    fn updater_state_is_written_atomically_without_secrets() {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("updater-state.json");
        let state = UpdateMetadataState {
            schema_version: 1,
            last_check_at: None,
            last_successful_check_at: None,
            installed_version: "0.2.0".into(),
            installed_wallet_revision: "a".repeat(40),
            installed_node_revision: "b".repeat(40),
            latest_seen_version: None,
            pending_version: None,
            channel: "stable".into(),
            wallet_state: WalletUpdaterState::Idle,
            node_state: NodeUpdaterState::Idle,
            last_sanitized_error: None,
            etag: Some("etag".into()),
            successful_update_at: None,
        };
        persist_update_state(&path, &state).expect("persist");
        let encoded = fs::read_to_string(path).expect("read state");
        assert_eq!(
            serde_json::from_str::<UpdateMetadataState>(&encoded).expect("parse state"),
            state
        );
        for forbidden in ["seed", "password", "private_key", "bearer", "blinding"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn runtime_destination_rejects_traversal() {
        let directory = TempDir::new().expect("tempdir");
        assert_eq!(
            validate_runtime_destination(directory.path(), Path::new("../node")),
            Err(UpdateError::UnsafePath)
        );
        assert_eq!(
            validate_runtime_destination(directory.path(), Path::new("nodes/0.1.1/node")),
            Ok(())
        );
    }

    #[test]
    fn managed_runtime_stages_and_promotes_without_overwriting() {
        let directory = TempDir::new().expect("tempdir");
        let layout = NodeRuntimeLayout::initialize(directory.path()).expect("runtime layout");
        let bytes = b"signed node";
        let mut descriptor = artifact();
        descriptor.size = bytes.len() as u64;
        descriptor.sha256 = format!("{:x}", Sha256::digest(bytes));
        let revision = "d".repeat(40);
        let stage = layout
            .stage_verified_node("0.1.2", &revision, bytes, &descriptor)
            .expect("stage");
        assert!(stage.join(node_binary_name()).is_file());
        let active = layout
            .promote_staged_node(&stage, "0.1.2", &revision)
            .expect("promote");
        assert!(active.join(node_binary_name()).is_file());
        assert_eq!(
            layout.promote_staged_node(&active, "0.1.2", &revision),
            Err(UpdateError::UnsafePath)
        );
    }

    #[test]
    fn runtime_rejects_invalid_revision_and_binary_digest() {
        let directory = TempDir::new().expect("tempdir");
        let layout = NodeRuntimeLayout::initialize(directory.path()).expect("runtime layout");
        assert_eq!(
            layout.stage_verified_node("0.1.2", "../bad", b"signed update", &artifact()),
            Err(UpdateError::ManifestInvalid)
        );
        assert_eq!(
            layout.stage_verified_node("0.1.2", &"a".repeat(40), b"tampered", &artifact()),
            Err(UpdateError::SizeMismatch)
        );
    }

    #[derive(Clone)]
    struct FakeNodeBackend {
        critical: bool,
        old_pid: u32,
        new_pid: u32,
        stopped: bool,
        ports_released: bool,
        start_fails: bool,
        ready: bool,
        cursor: bool,
        peers: usize,
        identity: NodeIdentity,
        previous_identity: NodeIdentity,
        rolled_back: bool,
        calls: Vec<&'static str>,
    }

    impl FakeNodeBackend {
        fn healthy() -> Self {
            let manifest = node_manifest();
            Self {
                critical: false,
                old_pid: 10,
                new_pid: 11,
                stopped: true,
                ports_released: true,
                start_fails: false,
                ready: true,
                cursor: true,
                peers: 1,
                identity: NodeIdentity {
                    node_version: manifest.node_version,
                    node_revision: manifest.node_revision,
                    network: manifest.network,
                    chain_id: manifest.chain_id,
                    genesis_hash: manifest.genesis_hash,
                    rpc_protocol_version: manifest.rpc_protocol_version,
                    p2p_protocol_version: manifest.p2p_protocol_version,
                    storage_schema_version: manifest.storage_schema_version,
                },
                previous_identity: NodeIdentity {
                    node_version: "0.1.0".into(),
                    node_revision: "previous".into(),
                    network: "mainnet".into(),
                    chain_id: "chain".into(),
                    genesis_hash: "genesis".into(),
                    rpc_protocol_version: 1,
                    p2p_protocol_version: 1,
                    storage_schema_version: 1,
                },
                rolled_back: false,
                calls: Vec::new(),
            }
        }
    }

    impl NodeUpdateBackend for FakeNodeBackend {
        fn critical_operation_active(&self) -> bool {
            self.critical
        }
        fn stop_miner(&mut self) -> Result<(), UpdateError> {
            self.calls.push("stop_miner");
            Ok(())
        }
        fn persist_wallet_cursor_and_journal(&mut self) -> Result<(), UpdateError> {
            self.calls.push("persist");
            Ok(())
        }
        fn stop_node(&mut self) -> Result<u32, UpdateError> {
            self.calls.push("stop_node");
            Ok(self.old_pid)
        }
        fn process_is_stopped(&self, _pid: u32) -> bool {
            self.stopped
        }
        fn local_ports_released(&self) -> bool {
            self.ports_released
        }
        fn promote_staged_node(&mut self) -> Result<(), UpdateError> {
            self.calls.push("promote");
            Ok(())
        }
        fn start_node(&mut self) -> Result<u32, UpdateError> {
            self.calls.push("start_node");
            if self.start_fails {
                Err(UpdateError::RestartFailed)
            } else {
                Ok(if self.rolled_back {
                    self.old_pid + 100
                } else {
                    self.new_pid
                })
            }
        }
        fn handshake(&self) -> Result<NodeIdentity, UpdateError> {
            Ok(if self.rolled_back {
                self.previous_identity.clone()
            } else {
                self.identity.clone()
            })
        }
        fn ready(&self) -> bool {
            self.ready
        }
        fn cursor_is_canonical(&self) -> bool {
            self.cursor
        }
        fn connected_peers(&self) -> usize {
            self.peers
        }
        fn rollback(&mut self) -> Result<(), UpdateError> {
            self.calls.push("rollback");
            self.rolled_back = true;
            self.start_fails = false;
            self.ready = true;
            Ok(())
        }
        fn expected_previous_identity(&self) -> NodeIdentity {
            self.previous_identity.clone()
        }
    }

    #[test]
    fn node_update_succeeds_only_after_restart_handshake_ready_cursor_and_peers() {
        let mut backend = FakeNodeBackend::healthy();
        assert_eq!(
            apply_node_update(&mut backend, &node_manifest()),
            Ok(NodeUpdaterState::Succeeded)
        );
        assert_ne!(backend.old_pid, backend.new_pid);
        assert_eq!(
            backend.calls,
            vec![
                "stop_miner",
                "persist",
                "stop_node",
                "promote",
                "start_node"
            ]
        );
    }

    #[test]
    fn critical_slate_defers_node_update_without_stopping_anything() {
        let mut backend = FakeNodeBackend::healthy();
        backend.critical = true;
        assert_eq!(
            apply_node_update(&mut backend, &node_manifest()),
            Ok(NodeUpdaterState::WaitingForSafePoint)
        );
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn node_start_or_health_failure_rolls_back_and_restarts_previous_node() {
        let mut start_failure = FakeNodeBackend::healthy();
        start_failure.start_fails = true;
        assert_eq!(
            apply_node_update(&mut start_failure, &node_manifest()),
            Ok(NodeUpdaterState::RolledBack)
        );
        assert!(start_failure.rolled_back);

        let mut health_failure = FakeNodeBackend::healthy();
        health_failure.ready = false;
        assert_eq!(
            apply_node_update(&mut health_failure, &node_manifest()),
            Ok(NodeUpdaterState::RolledBack)
        );
        assert!(health_failure.rolled_back);
    }

    #[test]
    fn identity_mismatch_never_marks_node_update_succeeded() {
        let mut backend = FakeNodeBackend::healthy();
        backend.identity.node_revision = "wrong".into();
        assert_eq!(
            apply_node_update(&mut backend, &node_manifest()),
            Ok(NodeUpdaterState::RolledBack)
        );
    }

    #[test]
    fn authenticated_build_info_matches_embedded_pin_but_partial_identity_fails_closed() {
        let response = NodeBuildInfoResponse {
            commit: MANAGED_NODE_CONTROL_REVISION.into(),
        };
        assert_eq!(
            validate_node_build_info(&response, MANAGED_NODE_CONTROL_REVISION),
            Ok(())
        );
        assert_eq!(
            validate_node_build_info(&response, EMBEDDED_NODE_REVISION),
            Ok(())
        );
        assert_eq!(
            validate_node_build_info(&response, "0000000000000000000000000000000000000000"),
            Err(UpdateError::NodeIdentityMismatch)
        );
        let current_rpc = NodeRpcIdentityCapabilities {
            build_revision: true,
            network: true,
            chain_id: false,
            genesis_hash: false,
            rpc_protocol_version: false,
            p2p_protocol_version: false,
            storage_schema_version: false,
            graceful_shutdown: true,
        };
        assert!(!current_rpc.permits_node_only_update());
    }
}
