#![forbid(unsafe_code)]

//! Tauri-ready command boundary.
//!
//! The commands are framework-neutral Rust functions so they can be tested in
//! a headless environment. A production Tauri `invoke_handler` binds these
//! names without moving domain, storage, cryptographic, or sync logic here.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dom_wallet_core::{
    BackupStatus, CoreError, DiagnosticSnapshot, FeeEstimate, RecoveryCreateResult,
    RecoveryRestoreResult, SlateExport, TransactionSummary, WalletService, WalletSummary,
    MAINNET_CHAIN_ID_HEX, MAINNET_GENESIS_HASH_HEX,
};
use dom_wallet_core_api::CoreNetwork;
use dom_wallet_core_restore::SeedRestoreError;
use dom_wallet_domain::{BalanceProjection, Network, NetworkIdentity};
use dom_wallet_embedded_core::{
    mine_wallet_block, EmbeddedCoreConfiguration, WalletMiningOutcome, MAINNET_DNS_SEEDS,
    MAINNET_P2P_PORT,
};
use dom_wallet_node_manager::{
    ManagedNodeConfig, NodeManager, NodeReleaseMetadata, SidecarStatus,
    EXPERIMENTAL_ENABLE_CONFIRMATION,
};
use dom_wallet_storage::WalletDirectory;
use dom_wallet_updater::{
    WalletUpdaterState, EMBEDDED_NODE_REVISION, UPDATE_CHANNEL, UPDATE_INTERVAL_SECONDS,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    thread::JoinHandle,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct DesktopApplication {
    service: Arc<Mutex<WalletService>>,
    qr_reassembler: Mutex<SlateQrReassembler>,
    node_started: AtomicBool,
    last_successful_node_status_at: AtomicU64,
    last_peer_connected_unix_seconds: AtomicU64,
    synchronization_paused: AtomicBool,
    synchronization: Mutex<SynchronizationRuntime>,
    mining: Mutex<MiningRuntime>,
    sidecar: Mutex<NodeManager>,
    shutdown: AtomicBool,
    recovery_required: AtomicBool,
    activities: Arc<ActivityCoordinator>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ActivityKind {
    WalletLifecycle,
    NodeLifecycle,
    Mining,
    Synchronization,
    CriticalTransaction,
    Backup,
    Restore,
    Updater,
    Shutdown,
}

#[derive(Default)]
struct ActivityCoordinator {
    active: Mutex<BTreeSet<ActivityKind>>,
}

pub struct ActivityLease {
    coordinator: Arc<ActivityCoordinator>,
    kind: ActivityKind,
}

impl Drop for ActivityLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active.lock() {
            active.remove(&self.kind);
        }
    }
}

impl ActivityCoordinator {
    fn try_begin(self: &Arc<Self>, kind: ActivityKind) -> Result<ActivityLease, CommandError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| CommandError::RecoveryRequired)?;
        let exclusive = matches!(kind, ActivityKind::Updater | ActivityKind::Shutdown);
        if (exclusive && !active.is_empty())
            || (!exclusive
                && active
                    .iter()
                    .any(|value| matches!(value, ActivityKind::Updater | ActivityKind::Shutdown)))
            || active.contains(&kind)
        {
            return Err(CommandError::ActivityBusy);
        }
        active.insert(kind);
        Ok(ActivityLease {
            coordinator: Arc::clone(self),
            kind,
        })
    }
}

/// Authoritative command registry consumed by the Tauri handler and tests.
#[macro_export]
macro_rules! wallet_command_registry {
    ($consumer:ident) => {
        $consumer! {
            native_bridge_status,
            get_build_info,
            update_status,
            automatic_updates_set,
            check_updates_now,
            download_update_now,
            apply_update_now,
            application_status,
            wallet_create_recoverable,
            wallet_create_resume,
            wallet_create_abort,
            wallet_restore_from_mnemonic,
            wallet_restore_staging_list,
            wallet_restore_abort,
            wallet_backup_export,
            wallet_backup_import,
            wallet_recovery_phrase_resume,
            wallet_recovery_phrase_confirm,
            wallet_open_named,
            wallet_recover_from_disk,
            wallet_list,
            wallet_unlock,
            wallet_lock,
            wallet_close,
            wallet_summary,
            account_list,
            account_summary,
            embedded_node_start,
            embedded_node_stop,
            embedded_node_status,
            experimental_sidecar_status,
            experimental_sidecar_enable,
            experimental_sidecar_disable,
            experimental_sidecar_start,
            experimental_sidecar_stop,
            experimental_sidecar_evaluate_release,
            node_network_status,
            node_peer_status,
            wallet_sync_status,
            wallet_sync_start,
            wallet_sync_pause,
            wallet_sync_resume,
            wallet_sync_retry,
            wallet_rescan,
            mining_status,
            mining_config_get,
            mining_config_set,
            mining_start,
            mining_stop,
            synchronization_start,
            synchronization_pause,
            synchronization_resume,
            synchronization_retry,
            synchronization_rescan,
            diagnostics_redacted,
            application_shutdown,
            transaction_fee_estimate,
            wallet_address_validate,
            transaction_send_create,
            slate_request_export,
            slate_request_import,
            slate_response_create,
            slate_response_export,
            slate_response_import,
            slate_summary_redacted,
            transaction_finalize,
            transaction_submit,
            transaction_retry_submission,
            transaction_reconcile_submission,
            transaction_cancel,
            transaction_list,
            transaction_detail_redacted,
            slate_qr_encode,
            slate_qr_decode_frame,
            slate_qr_reassembly_status,
            slate_qr_reassembly_clear,
        }
    };
}

macro_rules! define_command_names {
    ($($command:ident),+ $(,)?) => {
        pub const COMMAND_NAMES: &[&str] = &[$(stringify!($command)),+];
    };
}

wallet_command_registry!(define_command_names);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInfoDto {
    pub wallet_version: &'static str,
    pub wallet_revision: &'static str,
    pub embedded_node_version: &'static str,
    pub embedded_node_revision: &'static str,
    pub update_channel: &'static str,
}

pub fn get_build_info() -> BuildInfoDto {
    BuildInfoDto {
        wallet_version: env!("CARGO_PKG_VERSION"),
        wallet_revision: option_env!("DOM_WALLET_REVISION").unwrap_or("UNAVAILABLE"),
        embedded_node_version: option_env!("DOM_NODE_VERSION").unwrap_or("0.1.0"),
        embedded_node_revision: EMBEDDED_NODE_REVISION,
        update_channel: UPDATE_CHANNEL,
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateStatusDto {
    pub automatic_updates: bool,
    pub signature_key_configured: bool,
    pub channel: &'static str,
    pub wallet: WalletUpdaterStatusDto,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletUpdaterStatusDto {
    pub installed_version: &'static str,
    pub installed_revision: &'static str,
    pub available_version: Option<String>,
    pub state: WalletUpdaterState,
    pub last_check_unix_seconds: Option<u64>,
    pub next_check_unix_seconds: Option<u64>,
    pub progress_percent: Option<u8>,
    pub sanitized_error: Option<String>,
}

pub struct UpdateControl {
    status: Mutex<UpdateStatusDto>,
    check_in_progress: AtomicBool,
}

impl UpdateControl {
    pub fn new(signature_key_configured: bool) -> Self {
        let build = get_build_info();
        Self {
            status: Mutex::new(UpdateStatusDto {
                automatic_updates: true,
                signature_key_configured,
                channel: UPDATE_CHANNEL,
                wallet: WalletUpdaterStatusDto {
                    installed_version: build.wallet_version,
                    installed_revision: build.wallet_revision,
                    available_version: None,
                    state: WalletUpdaterState::Idle,
                    last_check_unix_seconds: None,
                    next_check_unix_seconds: None,
                    progress_percent: None,
                    sanitized_error: None,
                },
            }),
            check_in_progress: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> UpdateStatusDto {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| UpdateStatusDto {
                automatic_updates: true,
                signature_key_configured: false,
                channel: UPDATE_CHANNEL,
                wallet: WalletUpdaterStatusDto {
                    installed_version: env!("CARGO_PKG_VERSION"),
                    installed_revision: "UNAVAILABLE",
                    available_version: None,
                    state: WalletUpdaterState::Failed,
                    last_check_unix_seconds: None,
                    next_check_unix_seconds: None,
                    progress_percent: None,
                    sanitized_error: Some("UPDATE_STATE_UNAVAILABLE".into()),
                },
            })
    }

    pub fn set_automatic_updates(&self, enabled: bool) {
        if let Ok(mut status) = self.status.lock() {
            status.automatic_updates = enabled;
        }
    }

    pub fn begin_check(&self, now: u64) -> bool {
        if self
            .check_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = WalletUpdaterState::Checking;
            status.wallet.last_check_unix_seconds = Some(now);
            status.wallet.next_check_unix_seconds = Some(now + UPDATE_INTERVAL_SECONDS);
            status.wallet.sanitized_error = None;
        }
        true
    }

    pub fn finish_check_without_key(&self) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = WalletUpdaterState::Failed;
            status.wallet.sanitized_error = Some("UPDATE_SIGNATURE_KEY_UNAVAILABLE".into());
        }
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn finish_network_check(
        &self,
        wallet_available: Option<String>,
        wallet_error: Option<&'static str>,
    ) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.available_version = wallet_available;
            status.wallet.state = if status.wallet.available_version.is_some() {
                WalletUpdaterState::WalletUpdateAvailable
            } else if wallet_error.is_some() {
                WalletUpdaterState::Failed
            } else {
                WalletUpdaterState::UpToDate
            };
            status.wallet.sanitized_error = wallet_error.map(str::to_owned);
        }
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn set_wallet_download_state(&self, state: WalletUpdaterState, progress: Option<u8>) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = state;
            status.wallet.progress_percent = progress;
        }
    }

    pub fn finish_verified_download(&self, version: String) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.available_version = Some(version);
            status.wallet.state = WalletUpdaterState::ReadyToApply;
            status.wallet.progress_percent = Some(100);
            status.wallet.sanitized_error = None;
        }
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn fail_wallet_check(&self, error: &'static str) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = WalletUpdaterState::Failed;
            status.wallet.sanitized_error = Some(error.into());
        }
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn defer_wallet_install(&self, version: String) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.available_version = Some(version);
            status.wallet.state = WalletUpdaterState::WaitingForSafePoint;
            status.wallet.sanitized_error = Some("UPDATE_BUSY_CRITICAL_OPERATION".into());
        }
        self.check_in_progress.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBridgeStatusDto {
    pub bridge: &'static str,
    pub app_version: &'static str,
    pub command_names: &'static [&'static str],
}

pub fn native_bridge_status() -> NativeBridgeStatusDto {
    NativeBridgeStatusDto {
        bridge: "ready",
        app_version: env!("CARGO_PKG_VERSION"),
        command_names: COMMAND_NAMES,
    }
}

impl Default for DesktopApplication {
    fn default() -> Self {
        Self {
            service: Arc::new(Mutex::new(WalletService::default())),
            qr_reassembler: Mutex::new(SlateQrReassembler::default()),
            node_started: AtomicBool::new(false),
            last_successful_node_status_at: AtomicU64::new(0),
            last_peer_connected_unix_seconds: AtomicU64::new(0),
            synchronization_paused: AtomicBool::new(false),
            synchronization: Mutex::new(SynchronizationRuntime::default()),
            mining: Mutex::new(MiningRuntime::default()),
            sidecar: Mutex::new(NodeManager::default()),
            shutdown: AtomicBool::new(false),
            recovery_required: AtomicBool::new(false),
            activities: Arc::new(ActivityCoordinator::default()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationStatusDto {
    pub state: String,
    pub experimental: bool,
    pub unaudited: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletReadinessDto {
    Stopped,
    Starting,
    WaitingForPeers,
    UnknownPeerHeight,
    ConnectedAtGenesis,
    Synchronizing,
    Ready,
    Stale,
    NotReady,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeReadinessSnapshot {
    pub process_running: bool,
    pub canonical_identity_verified: bool,
    pub local_height: u64,
    pub local_tip_hash: Option<[u8; 32]>,
    pub connected_peers: u64,
    pub highest_known_peer_height: Option<u64>,
    pub ibd_progress_percent: Option<u8>,
    pub critical_task_failed: bool,
    pub last_successful_status_at: Option<u64>,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeReadiness {
    Stopped,
    Starting,
    WaitingForPeers,
    UnknownPeerHeight,
    ConnectedAtGenesis,
    Synchronizing { local_height: u64, peer_height: u64 },
    Ready,
    Stale,
    Failed,
}

pub const NODE_STATUS_STALE_AFTER_SECONDS: u64 = 30;

pub fn derive_node_readiness(snapshot: NodeReadinessSnapshot) -> NodeReadiness {
    if !snapshot.process_running {
        return NodeReadiness::Stopped;
    }
    if snapshot.critical_task_failed {
        return NodeReadiness::Failed;
    }
    if snapshot.last_successful_status_at.is_some_and(|observed| {
        snapshot.now.saturating_sub(observed) > NODE_STATUS_STALE_AFTER_SECONDS
    }) {
        return NodeReadiness::Stale;
    }
    if !snapshot.canonical_identity_verified || snapshot.local_tip_hash.is_none() {
        return NodeReadiness::Starting;
    }
    if snapshot.connected_peers == 0 {
        return NodeReadiness::WaitingForPeers;
    }
    let Some(peer_height) = snapshot.highest_known_peer_height else {
        return NodeReadiness::UnknownPeerHeight;
    };
    if snapshot.local_height == 0 && peer_height == 0 {
        return NodeReadiness::ConnectedAtGenesis;
    }
    if peer_height > snapshot.local_height {
        return NodeReadiness::Synchronizing {
            local_height: snapshot.local_height,
            peer_height,
        };
    }
    if peer_height == snapshot.local_height {
        return NodeReadiness::Ready;
    }
    NodeReadiness::UnknownPeerHeight
}

fn readiness_allows_mining(readiness: NodeReadiness) -> bool {
    matches!(
        readiness,
        NodeReadiness::Ready | NodeReadiness::ConnectedAtGenesis
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedNodeStatusDto {
    pub lifecycle: WalletReadinessDto,
    pub network: Option<String>,
    pub chain_id: Option<String>,
    pub genesis_hash: Option<String>,
    pub canonical_tip_height: Option<u64>,
    pub canonical_tip_hash: Option<String>,
    pub protocol_version: Option<u32>,
    pub range_proof_version: Option<u8>,
    pub ready: bool,
    pub error_code: Option<String>,
    pub connected_peers: u64,
    pub bootstrap_phase: String,
    pub highest_known_peer_height: Option<u64>,
    pub synchronization_progress_percent: Option<u64>,
    pub status_message: String,
    pub last_successful_status_at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeedResolutionDto {
    pub seed: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodePeerStatusDto {
    pub connected_inbound: u64,
    pub connected_outbound: u64,
    pub total_connected_peers: u64,
    pub known_peer_count: u64,
    pub bootstrap_phase: String,
    pub last_successful_connection_time: Option<u64>,
    pub last_connection_error_code: Option<String>,
    pub seed_resolution_summary: Vec<SeedResolutionDto>,
    pub canonical_height: u64,
    pub highest_known_peer_height: Option<u64>,
    pub peer_addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeNetworkStatusDto {
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub canonical_height: u64,
    pub ready: bool,
    pub data_directory: String,
    pub bootstrap_fallback: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSyncStatusDto {
    pub state: String,
    pub cursor_height: Option<u64>,
    pub cursor_hash: Option<String>,
    pub canonical_height: Option<u64>,
    pub canonical_hash: Option<String>,
    pub synchronized: bool,
    pub paused: bool,
    pub last_result: String,
    pub last_error: Option<String>,
}

const MINING_DISABLED: u64 = 0;
const MINING_READY: u64 = 1;
const MINING_STARTING: u64 = 2;
const MINING_RUNNING: u64 = 3;
const MINING_STOPPING: u64 = 4;
const MINING_ERROR: u64 = 5;

struct MiningRuntime {
    state: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    hash_attempts: Arc<AtomicU64>,
    accepted_blocks: Arc<AtomicU64>,
    rejected_work: Arc<AtomicU64>,
    template_refreshes: Arc<AtomicU64>,
    last_candidate_time: Arc<AtomicU64>,
    last_accepted_height: Arc<AtomicU64>,
    started_at: Arc<AtomicU64>,
    cached_current_height: AtomicU64,
    cached_connected_peers: AtomicU64,
    error_code: Arc<Mutex<Option<String>>>,
    cached_config: Mutex<Option<MiningConfigDto>>,
    worker: Option<JoinHandle<()>>,
}

impl Default for MiningRuntime {
    fn default() -> Self {
        let available_logical_cpus = available_logical_cpus();
        Self {
            state: Arc::new(AtomicU64::new(MINING_DISABLED)),
            stop: Arc::new(AtomicBool::new(false)),
            hash_attempts: Arc::new(AtomicU64::new(0)),
            accepted_blocks: Arc::new(AtomicU64::new(0)),
            rejected_work: Arc::new(AtomicU64::new(0)),
            template_refreshes: Arc::new(AtomicU64::new(0)),
            last_candidate_time: Arc::new(AtomicU64::new(0)),
            last_accepted_height: Arc::new(AtomicU64::new(u64::MAX)),
            started_at: Arc::new(AtomicU64::new(0)),
            cached_current_height: AtomicU64::new(0),
            cached_connected_peers: AtomicU64::new(0),
            error_code: Arc::new(Mutex::new(None)),
            cached_config: Mutex::new(Some(MiningConfigDto {
                enabled: false,
                cpu_threads: (available_logical_cpus / 2).max(1),
                available_logical_cpus,
                recommended_cpu_threads: (available_logical_cpus / 2).max(1),
                mining_address: String::new(),
            })),
            worker: None,
        }
    }
}

const SYNC_IDLE: u64 = 0;
const SYNC_RUNNING: u64 = 1;
const SYNC_STOPPING: u64 = 2;
const SYNC_ERROR: u64 = 3;
const SYNC_CATCH_UP_RETRY_MILLIS: u64 = 10;
const SYNC_FOLLOW_POLL_MILLIS: u64 = 1_000;
const SYNC_NOT_READY_INITIAL_BACKOFF_MILLIS: u64 = 100;
const SYNC_NOT_READY_MAX_BACKOFF_MILLIS: u64 = 2_000;

fn transient_synchronization_error(error: &CommandError) -> bool {
    matches!(
        error,
        CommandError::NodeNotReady | CommandError::ActivityBusy
    )
}

fn synchronization_retry_backoff(consecutive_failures: u32) -> std::time::Duration {
    let shift = consecutive_failures.min(4);
    std::time::Duration::from_millis(
        SYNC_NOT_READY_INITIAL_BACKOFF_MILLIS
            .saturating_mul(1_u64 << shift)
            .min(SYNC_NOT_READY_MAX_BACKOFF_MILLIS),
    )
}

fn run_synchronization_follow_loop<Synchronize, Wait>(
    stop: &AtomicBool,
    mut synchronize_once: Synchronize,
    mut wait: Wait,
) -> Result<(), CommandError>
where
    Synchronize: FnMut() -> Result<bool, CommandError>,
    Wait: FnMut(std::time::Duration),
{
    let mut consecutive_transient_failures = 0_u32;
    while !stop.load(Ordering::Acquire) {
        let delay = match synchronize_once() {
            Ok(synchronized) => {
                consecutive_transient_failures = 0;
                std::time::Duration::from_millis(if synchronized {
                    SYNC_FOLLOW_POLL_MILLIS
                } else {
                    SYNC_CATCH_UP_RETRY_MILLIS
                })
            }
            Err(error) if transient_synchronization_error(&error) => {
                let delay = synchronization_retry_backoff(consecutive_transient_failures);
                consecutive_transient_failures = consecutive_transient_failures.saturating_add(1);
                delay
            }
            Err(error) => return Err(error),
        };
        if !stop.load(Ordering::Acquire) {
            wait(delay);
        }
    }
    Ok(())
}

struct SynchronizationRuntime {
    state: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    error_code: Arc<Mutex<Option<String>>>,
    cached_status: Arc<Mutex<Option<WalletSyncStatusDto>>>,
    worker: Option<JoinHandle<()>>,
}

impl Default for SynchronizationRuntime {
    fn default() -> Self {
        Self {
            state: Arc::new(AtomicU64::new(SYNC_IDLE)),
            stop: Arc::new(AtomicBool::new(false)),
            error_code: Arc::new(Mutex::new(None)),
            cached_status: Arc::new(Mutex::new(None)),
            worker: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiningConfigDto {
    pub enabled: bool,
    pub cpu_threads: usize,
    pub available_logical_cpus: usize,
    pub recommended_cpu_threads: usize,
    pub mining_address: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiningStatusDto {
    pub status: String,
    pub enabled: bool,
    pub running: bool,
    pub cpu_threads: usize,
    pub mining_address: String,
    pub hash_attempts: u64,
    pub hashrate_hps: f64,
    pub current_height: u64,
    pub connected_peers: u64,
    pub accepted_blocks: u64,
    pub rejected_work: u64,
    pub template_refreshes: u64,
    pub last_block_candidate_time: Option<u64>,
    pub last_accepted_block_height: Option<u64>,
    pub uptime_seconds: u64,
    pub error_code: Option<String>,
}

#[derive(Debug)]
pub struct RecoveryCreateDto {
    pub wallet: WalletSummary,
    pub mnemonic: Zeroizing<String>,
}

impl Serialize for RecoveryCreateDto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RecoveryCreateDto", 2)?;
        state.serialize_field("wallet", &self.wallet)?;
        state.serialize_field("mnemonic", self.mnemonic.as_str())?;
        state.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryCompletionDto {
    OwnedOutputsRecovered,
    NoOwnedOutputs,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResultDto {
    pub wallet: WalletSummary,
    pub completion: RecoveryCompletionDto,
    pub scanned_blocks: u64,
    pub scanned_outputs: u64,
    pub owned_outputs: u64,
    pub spent_outputs: u64,
    pub unspent_outputs: u64,
    pub coinbase_outputs: u64,
    pub legacy_outputs: u64,
    pub balance: BalanceProjection,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubmissionOutcomeDto {
    Accepted,
    AcceptedNotRelayed,
    AlreadyKnown,
    RejectedInvalid,
    RejectedFee,
    RejectedDoubleSpend,
    RejectedImmatureCoinbase,
    RejectedExpired,
    RejectedPolicy,
    NodeNotReady,
    TemporaryFailure,
    InternalFailure,
    Confirmed,
    Reorged,
    Cancelled,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionResultDto {
    pub transaction: TransactionSummary,
    pub outcome: SubmissionOutcomeDto,
    pub retryable: bool,
    pub accepted: bool,
    pub relayed: Option<bool>,
    pub diagnostic_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlateQrExportDto {
    pub frames: Vec<String>,
    pub multipart: bool,
    pub content_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlateQrReassemblyDto {
    pub message_id: Option<String>,
    pub received_frames: u16,
    pub total_frames: u16,
    pub response: Option<bool>,
    pub complete_text: Option<String>,
}

const SLATE_QR_VERSION: u8 = 1;
const SLATE_QR_FRAME_PREFIX: &str = "DOMQR5";
const SLATE_QR_PAYLOAD_BYTES: usize = 768;
const MAX_SLATE_QR_TEXT_BYTES: usize = 2_097_280;
const MAX_SLATE_QR_FRAMES: usize = MAX_SLATE_QR_TEXT_BYTES.div_ceil(SLATE_QR_PAYLOAD_BYTES);

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlateQrFrameV1 {
    version: u8,
    message_id: Uuid,
    response: bool,
    part_index: u16,
    part_count: u16,
    total_length: u32,
    content_sha256: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Default)]
struct SlateQrReassembler {
    active: Option<SlateQrAssembly>,
    completed: BTreeSet<[u8; 32]>,
}

struct SlateQrAssembly {
    message_id: Uuid,
    response: bool,
    part_count: u16,
    total_length: u32,
    content_sha256: [u8; 32],
    parts: BTreeMap<u16, Vec<u8>>,
    complete_text: Option<String>,
}

impl DesktopApplication {
    pub fn configure_sidecar_runtime(
        &self,
        runtime_root: impl Into<std::path::PathBuf>,
    ) -> Result<(), CommandError> {
        self.sidecar
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .configure_runtime(runtime_root)
            .map_err(|_| CommandError::Unavailable)?;
        Ok(())
    }

    pub fn experimental_sidecar_status(&self) -> Result<SidecarStatus, CommandError> {
        self.sidecar
            .lock()
            .map_err(|_| CommandError::Unavailable)
            .map(|mut manager| manager.status())
    }

    pub fn experimental_sidecar_enable(
        &self,
        confirmation: &str,
    ) -> Result<SidecarStatus, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        let unlocked = self
            .service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .summary()
            .is_ok();
        let mut manager = self.sidecar.lock().map_err(|_| CommandError::Unavailable)?;
        manager
            .enable_for_session(confirmation, unlocked)
            .map_err(|_| {
                CommandError::InvalidInput(format!(
                    "sidecar activation requires an unlocked wallet and exact confirmation: {EXPERIMENTAL_ENABLE_CONFIRMATION}"
                ))
            })?;
        Ok(manager.status())
    }

    pub fn experimental_sidecar_disable(&self) -> Result<SidecarStatus, CommandError> {
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        let mut manager = self.sidecar.lock().map_err(|_| CommandError::Unavailable)?;
        manager
            .disable_for_session()
            .map_err(|_| CommandError::Unavailable)?;
        Ok(manager.status())
    }

    pub fn experimental_sidecar_start(
        &self,
        configuration: ManagedNodeConfig,
    ) -> Result<SidecarStatus, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        let mut manager = self.sidecar.lock().map_err(|_| CommandError::Unavailable)?;
        manager
            .start_active(configuration)
            .map_err(|_| CommandError::NodeNotReady)?;
        Ok(manager.status())
    }

    pub fn experimental_sidecar_stop(&self) -> Result<SidecarStatus, CommandError> {
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        let mut manager = self.sidecar.lock().map_err(|_| CommandError::Unavailable)?;
        manager.shutdown().map_err(|_| CommandError::Unavailable)?;
        Ok(manager.status())
    }

    pub fn experimental_sidecar_evaluate_release(
        &self,
        node_feed_json: Option<&str>,
        sidecar_manifest_json: Option<&str>,
        sidecar_manifest_signature: Option<&str>,
        platform: &str,
    ) -> Result<NodeReleaseMetadata, CommandError> {
        self.ensure_running()?;
        self.sidecar
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .evaluate_running_signed_release_metadata(
                node_feed_json.map(str::as_bytes),
                sidecar_manifest_json.map(str::as_bytes),
                sidecar_manifest_signature,
                platform,
            )
            .map_err(|error| CommandError::InvalidInput(error.to_string()))
    }

    pub fn update_safe_point_available(&self) -> Result<bool, CommandError> {
        match self.acquire_update_apply_lease() {
            Ok(lease) => {
                drop(lease);
                Ok(true)
            }
            Err(CommandError::ActivityBusy) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn acquire_update_apply_lease(&self) -> Result<ActivityLease, CommandError> {
        let lease = self.activities.try_begin(ActivityKind::Updater)?;
        let service = self.lock_service()?;
        let transactions = service.transaction_list().map_err(|error| match error {
            CoreError::WalletNotOpen | CoreError::Locked => CommandError::ActivityBusy,
            other => CommandError::from(other),
        })?;
        const CRITICAL_STATES: [&str; 8] = [
            "INPUTS_RESERVED",
            "REQUEST_EXPORTED",
            "REQUEST_IMPORTED",
            "RESPONSE_PREPARED",
            "RESPONSE_EXPORTED",
            "RESPONSE_IMPORTED",
            "FINALIZED",
            "SUBMITTING",
        ];
        if transactions
            .iter()
            .any(|transaction| CRITICAL_STATES.contains(&transaction.state.as_str()))
        {
            return Err(CommandError::ActivityBusy);
        }
        Ok(lease)
    }

    /// Persist and close local runtime state while an already-acquired updater
    /// lease prevents any new protected activity from starting.
    pub fn prepare_for_update(&self, _lease: &ActivityLease) -> Result<(), CommandError> {
        self.sidecar
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .shutdown()
            .map_err(|_| CommandError::Unavailable)?;
        self.clear_qr_buffers()?;
        let mut service = self.lock_service()?;
        service.close().map_err(CommandError::from)?;
        self.node_started.store(false, Ordering::Release);
        Ok(())
    }

    pub fn application_status(&self) -> ApplicationStatusDto {
        match self.service.lock() {
            Ok(service) => {
                let diagnostic = service.diagnostics();
                ApplicationStatusDto {
                    state: diagnostic.application_state,
                    experimental: true,
                    unaudited: true,
                }
            }
            Err(_) => ApplicationStatusDto {
                state: {
                    self.recovery_required.store(true, Ordering::Release);
                    "RECOVERY_REQUIRED".into()
                },
                experimental: true,
                unaudited: true,
            },
        }
    }

    pub fn wallet_create_recoverable(
        &self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<RecoveryCreateDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Restore)?;
        checked_password(password)?;
        let result: RecoveryCreateResult = self
            .lock_service()?
            .create_recoverable_for_embedded(path, password)
            .map_err(CommandError::from)?;
        Ok(RecoveryCreateDto {
            wallet: result.wallet,
            mnemonic: result.mnemonic,
        })
    }

    pub fn wallet_create_resume(
        &self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<RecoveryCreateDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Restore)?;
        checked_password(password)?;
        let result = self
            .lock_service()?
            .resume_recoverable_creation(path, password)
            .map_err(CommandError::from)?;
        Ok(RecoveryCreateDto {
            wallet: result.wallet,
            mnemonic: result.mnemonic,
        })
    }

    pub fn wallet_create_abort(
        &self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<(), CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Restore)?;
        checked_password(password)?;
        self.lock_service()?
            .abort_recoverable_creation(path, password)
            .map_err(CommandError::from)
    }

    pub fn wallet_restore_from_mnemonic(
        &self,
        path: impl AsRef<Path>,
        password: &str,
        mnemonic: &str,
    ) -> Result<RecoveryResultDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Restore)?;
        checked_password(password)?;
        if mnemonic.len() > 4096 {
            return Err(CommandError::InvalidInput(
                "recovery phrase is invalid".into(),
            ));
        }
        let path = path.as_ref();
        if path.exists() {
            return Err(CommandError::RestoreDestinationExists);
        }
        let node_status = self.embedded_node_status()?;
        ensure_seed_restore_node_ready(&node_status)?;
        let result: RecoveryRestoreResult = self
            .lock_service()?
            .restore_from_mnemonic(path, password, mnemonic)
            .map_err(CommandError::from)?;
        let completion = match result.recovery.completion {
            dom_wallet_core_restore::SeedRestoreCompletion::OwnedOutputsRecovered => {
                RecoveryCompletionDto::OwnedOutputsRecovered
            }
            dom_wallet_core_restore::SeedRestoreCompletion::NoOwnedOutputs => {
                RecoveryCompletionDto::NoOwnedOutputs
            }
        };
        Ok(RecoveryResultDto {
            wallet: result.wallet,
            completion,
            scanned_blocks: result.recovery.scanned_blocks,
            scanned_outputs: result.recovery.scanned_outputs,
            owned_outputs: result.recovery.owned_outputs,
            spent_outputs: result.recovery.spent_outputs,
            unspent_outputs: result.recovery.unspent_outputs,
            coinbase_outputs: result.recovery.coinbase_outputs,
            legacy_outputs: result.recovery.legacy_outputs,
            balance: result.recovery.balance,
            warnings: result
                .recovery
                .warnings
                .into_iter()
                .map(|warning| match warning {
                    dom_wallet_core_restore::SeedRestoreWarning::LegacyBackupRequired => {
                        "LEGACY_BACKUP_REQUIRED".into()
                    }
                    dom_wallet_core_restore::SeedRestoreWarning::OffChainMetadataNotRecoverableWithSeed => {
                        "OFF_CHAIN_METADATA_NOT_RECOVERABLE_WITH_SEED".into()
                    }
                })
                .collect(),
        })
    }

    pub fn wallet_backup_export(
        &self,
        destination: impl AsRef<Path>,
        backup_password: &str,
    ) -> Result<BackupStatus, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Backup)?;
        checked_password(backup_password)?;
        self.lock_service()?
            .backup_export(destination, backup_password)
            .map_err(CommandError::from)
    }

    pub fn wallet_backup_import(
        &self,
        destination: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        backup_password: &str,
        password: &str,
    ) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Backup)?;
        checked_password(backup_password)?;
        checked_password(password)?;
        let mut service = self.lock_service()?;
        let identity = domain_identity(
            &service
                .embedded_core_identity()
                .map_err(CommandError::from)?,
        );
        service
            .backup_import(
                destination,
                backup_path,
                backup_password,
                password,
                identity,
            )
            .map_err(CommandError::from)
    }

    pub fn wallet_recovery_phrase_confirm(&self, password: &str) -> Result<(), CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        checked_password(password)?;
        self.lock_service()?
            .recovery_phrase_confirmed(password)
            .map_err(CommandError::from)
    }

    pub fn wallet_recovery_phrase_resume(
        &self,
        password: &str,
    ) -> Result<RecoveryCreateDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        checked_password(password)?;
        let result = self
            .lock_service()?
            .recovery_phrase_resume(password)
            .map_err(CommandError::from)?;
        Ok(RecoveryCreateDto {
            wallet: result.wallet,
            mnemonic: result.mnemonic,
        })
    }

    fn wallet_open_path(&self, path: impl AsRef<Path>) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        self.lock_service()?.open(path).map_err(CommandError::from)
    }

    pub fn wallet_open_managed(
        &self,
        wallets_root: &Path,
        name: &str,
    ) -> Result<WalletSummary, CommandError> {
        let path = resolve_existing_managed_wallet(wallets_root, name)?;
        self.wallet_open_path(path)
    }

    pub fn wallet_unlock(&self, password: &str) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        checked_password(password)?;
        self.lock_service()?
            .unlock(password)
            .map_err(CommandError::from)
    }

    pub fn wallet_lock(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        self.stop_mining_worker()?;
        self.stop_synchronization_worker()?;
        self.clear_qr_buffers()?;
        self.lock_service()?.lock().map_err(CommandError::from)
    }
    pub fn wallet_close(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        self.stop_mining_worker()?;
        self.stop_synchronization_worker()?;
        self.clear_qr_buffers()?;
        self.lock_service()?.close().map_err(CommandError::from)?;
        self.node_started.store(false, Ordering::Release);
        Ok(())
    }
    pub fn wallet_summary(&self) -> Result<WalletSummary, CommandError> {
        self.lock_service()?.summary().map_err(CommandError::from)
    }
    pub fn account_list(&self) -> Result<Vec<(uuid::Uuid, String)>, CommandError> {
        self.lock_service()?.accounts().map_err(CommandError::from)
    }
    pub fn account_summary(&self) -> Result<WalletSummary, CommandError> {
        self.wallet_summary()
    }
    pub fn embedded_node_start_mainnet(
        &self,
        data_directory: impl AsRef<Path>,
        listen_address: SocketAddr,
    ) -> Result<EmbeddedNodeStatusDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        if self.node_started.load(Ordering::Acquire) {
            let status = self.embedded_node_status_inner()?;
            if !matches!(
                status.lifecycle,
                WalletReadinessDto::Failed | WalletReadinessDto::Stale
            ) {
                return Ok(status);
            }
        }
        if !listen_address.ip().is_loopback() || listen_address.port() == 0 {
            return Err(CommandError::InvalidInput(
                "automatic local node listener is invalid".into(),
            ));
        }
        let configuration =
            EmbeddedCoreConfiguration::mainnet(data_directory.as_ref(), listen_address);
        self.lock_service()?
            .start_embedded_core(configuration)
            .map_err(CommandError::from)?;
        self.node_started.store(true, Ordering::Release);
        self.embedded_node_status_inner()
    }

    pub fn embedded_node_status(&self) -> Result<EmbeddedNodeStatusDto, CommandError> {
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        self.embedded_node_status_inner()
    }

    fn embedded_node_status_inner(&self) -> Result<EmbeddedNodeStatusDto, CommandError> {
        if !self.node_started.load(Ordering::Acquire) {
            return Ok(stopped_node_status());
        }
        let mut service = self.lock_service()?;
        let running = service.embedded_core_running().unwrap_or(false);
        if !running {
            let _ = service.stop_embedded_core();
            drop(service);
            self.node_started.store(false, Ordering::Release);
            let last = self.last_successful_node_status_at.load(Ordering::Acquire);
            return Ok(unavailable_node_status((last > 0).then_some(last)));
        }
        let peers = match service.embedded_peer_status() {
            Ok(peers) => peers,
            Err(_) => {
                let _ = service.stop_embedded_core();
                drop(service);
                self.node_started.store(false, Ordering::Release);
                let last = self.last_successful_node_status_at.load(Ordering::Acquire);
                return Ok(unavailable_node_status((last > 0).then_some(last)));
            }
        };
        let wallet_api_ready = service.embedded_core_ready().unwrap_or(false);
        let identity = match service.embedded_core_identity() {
            Ok(identity) => identity,
            Err(_) => {
                let cached = service
                    .embedded_core_cached_identity()
                    .map_err(CommandError::from)?;
                if cached.current_tip.height == 0 && peers.canonical_height == 0 {
                    cached
                } else {
                    let last = self.last_successful_node_status_at.load(Ordering::Acquire);
                    return Ok(synchronizing_node_status_without_tip(
                        cached,
                        peers,
                        (last > 0).then_some(last),
                    ));
                }
            }
        };
        let now = unix_seconds();
        self.last_successful_node_status_at
            .store(now, Ordering::Release);
        let canonical_identity_verified = identity.network == CoreNetwork::Mainnet
            && hex::encode(identity.chain_id) == MAINNET_CHAIN_ID_HEX
            && hex::encode(identity.genesis_hash) == MAINNET_GENESIS_HASH_HEX;
        let highest_known_peer_height = if peers.connected_total == 0
            || (peers.highest_known_peer_height == 0 && identity.current_tip.height > 0)
        {
            None
        } else {
            Some(peers.highest_known_peer_height)
        };
        let snapshot = NodeReadinessSnapshot {
            process_running: true,
            canonical_identity_verified,
            local_height: identity.current_tip.height,
            local_tip_hash: Some(identity.current_tip.hash),
            connected_peers: peers.connected_total,
            highest_known_peer_height,
            ibd_progress_percent: None,
            critical_task_failed: false,
            last_successful_status_at: Some(now),
            now,
        };
        let readiness = derive_node_readiness(snapshot);
        let synchronization = node_synchronization_status(snapshot);
        let ready = wallet_api_ready && readiness_allows_mining(readiness);
        Ok(EmbeddedNodeStatusDto {
            lifecycle: synchronization.lifecycle,
            network: Some(core_network_name(identity.network).into()),
            chain_id: Some(hex::encode(identity.chain_id)),
            genesis_hash: Some(hex::encode(identity.genesis_hash)),
            canonical_tip_height: Some(identity.current_tip.height),
            canonical_tip_hash: Some(hex::encode(identity.current_tip.hash)),
            protocol_version: Some(identity.protocol_version),
            range_proof_version: Some(identity.range_proof_serialization_version),
            ready,
            error_code: (!canonical_identity_verified)
                .then(|| "CANONICAL_IDENTITY_UNVERIFIED".into()),
            connected_peers: peers.connected_total,
            bootstrap_phase: peers.bootstrap_phase.into(),
            highest_known_peer_height: synchronization.highest_known_peer_height,
            synchronization_progress_percent: synchronization.progress_percent,
            status_message: synchronization.message,
            last_successful_status_at: Some(now),
        })
    }

    pub fn embedded_node_stop(&self) -> Result<EmbeddedNodeStatusDto, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::NodeLifecycle)?;
        self.stop_mining_worker()?;
        self.stop_synchronization_worker()?;
        self.lock_service()?
            .stop_embedded_core()
            .map_err(CommandError::from)?;
        self.node_started.store(false, Ordering::Release);
        self.last_peer_connected_unix_seconds
            .store(0, Ordering::Release);
        Ok(stopped_node_status())
    }

    pub fn node_network_status(&self) -> Result<NodeNetworkStatusDto, CommandError> {
        let status = self.embedded_node_status()?;
        Ok(NodeNetworkStatusDto {
            network: status.network.ok_or(CommandError::Unavailable)?,
            chain_id: status.chain_id.ok_or(CommandError::Unavailable)?,
            genesis_hash: status.genesis_hash.ok_or(CommandError::Unavailable)?,
            canonical_height: status
                .canonical_tip_height
                .ok_or(CommandError::Unavailable)?,
            ready: status.ready,
            data_directory: "…/DOM Wallet V3/mainnet/node".into(),
            bootstrap_fallback: format!("{}:{MAINNET_P2P_PORT}", MAINNET_DNS_SEEDS[0]),
        })
    }

    pub fn node_peer_status(&self) -> Result<NodePeerStatusDto, CommandError> {
        let service = self.lock_service()?;
        let status = service.embedded_peer_status().map_err(CommandError::from)?;
        let observed = if status.connected_total > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let _ = self.last_peer_connected_unix_seconds.compare_exchange(
                0,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            Some(
                self.last_peer_connected_unix_seconds
                    .load(Ordering::Acquire),
            )
        } else {
            None
        };
        Ok(NodePeerStatusDto {
            connected_inbound: status.connected_inbound,
            connected_outbound: status.connected_outbound,
            total_connected_peers: status.connected_total,
            known_peer_count: status.known_peers,
            bootstrap_phase: status.bootstrap_phase.into(),
            last_successful_connection_time: observed,
            last_connection_error_code: None,
            seed_resolution_summary: MAINNET_DNS_SEEDS
                .iter()
                .zip(status.seed_resolution_states)
                .map(|(seed, state)| SeedResolutionDto {
                    seed: (*seed).into(),
                    state: state.into(),
                })
                .collect(),
            canonical_height: status.canonical_height,
            highest_known_peer_height: (status.connected_total > 0)
                .then_some(status.highest_known_peer_height),
            peer_addresses: status.peer_addresses,
        })
    }

    pub fn wallet_sync_status(&self) -> Result<WalletSyncStatusDto, CommandError> {
        self.reap_finished_sync_worker()?;
        match self.service.try_lock() {
            Ok(service) => {
                let status = sync_status_from_service(
                    &service,
                    self.synchronization_paused.load(Ordering::Acquire),
                );
                if let Ok(runtime) = self.synchronization.lock() {
                    if let Ok(mut cached) = runtime.cached_status.lock() {
                        *cached = Some(status.clone());
                    }
                }
                Ok(status)
            }
            Err(std::sync::TryLockError::WouldBlock) => self
                .synchronization
                .lock()
                .ok()
                .and_then(|runtime| runtime.cached_status.lock().ok()?.clone())
                .map(|mut status| {
                    status.state = "SYNCHRONIZING".into();
                    status.paused = self.synchronization_paused.load(Ordering::Acquire);
                    status
                })
                .ok_or(CommandError::Unavailable),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.recovery_required.store(true, Ordering::Release);
                Err(CommandError::RecoveryRequired)
            }
        }
    }

    pub fn mining_config_get(&self) -> Result<MiningConfigDto, CommandError> {
        let service = match self.service.try_lock() {
            Ok(service) => service,
            Err(std::sync::TryLockError::WouldBlock) => {
                return self
                    .mining
                    .lock()
                    .map_err(|_| CommandError::Unavailable)?
                    .cached_config
                    .lock()
                    .map_err(|_| CommandError::Unavailable)?
                    .clone()
                    .ok_or(CommandError::Unavailable);
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.recovery_required.store(true, Ordering::Release);
                return Err(CommandError::RecoveryRequired);
            }
        };
        let preferences = service.mining_preferences().map_err(CommandError::from)?;
        let available = available_logical_cpus();
        let recommended = (available / 2).max(1);
        let config = MiningConfigDto {
            enabled: preferences.enabled,
            cpu_threads: if preferences.cpu_threads == 0 {
                recommended
            } else {
                preferences.cpu_threads.min(available).max(1)
            },
            available_logical_cpus: available,
            recommended_cpu_threads: recommended,
            mining_address: service
                .mining_reward_destination()
                .map_err(CommandError::from)?,
        };
        drop(service);
        if let Ok(mining) = self.mining.lock() {
            if let Ok(mut cached) = mining.cached_config.lock() {
                *cached = Some(config.clone());
            }
        }
        Ok(config)
    }

    pub fn mining_config_set(
        &self,
        enabled: bool,
        cpu_threads: usize,
    ) -> Result<MiningConfigDto, CommandError> {
        self.ensure_running()?;
        let state = self
            .mining
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .state
            .load(Ordering::Acquire);
        if matches!(state, MINING_STARTING | MINING_RUNNING | MINING_STOPPING) {
            return Err(CommandError::MiningRunning);
        }
        let _activity = self.activities.try_begin(ActivityKind::Mining)?;
        let available = available_logical_cpus();
        if cpu_threads == 0 || cpu_threads > available {
            return Err(CommandError::InvalidInput(
                "CPU thread count is invalid".into(),
            ));
        }
        self.lock_service()?
            .set_mining_preferences(enabled, cpu_threads)
            .map_err(CommandError::from)?;
        let mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
        mining.state.store(
            if enabled {
                MINING_READY
            } else {
                MINING_DISABLED
            },
            Ordering::Release,
        );
        drop(mining);
        self.mining_config_get()
    }

    pub fn mining_status(&self) -> Result<MiningStatusDto, CommandError> {
        self.reap_finished_mining_worker()?;
        let config = self.mining_config_get()?;
        let mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
        let raw_state = mining.state.load(Ordering::Acquire);
        let attempts = mining.hash_attempts.load(Ordering::Relaxed);
        let started_at = mining.started_at.load(Ordering::Acquire);
        let uptime = if matches!(
            raw_state,
            MINING_STARTING | MINING_RUNNING | MINING_STOPPING
        ) && started_at > 0
        {
            unix_seconds().saturating_sub(started_at)
        } else {
            0
        };
        let (current_height, connected_peers) = match self.service.try_lock() {
            Ok(service) => {
                let peer_status = service.embedded_peer_status().map_err(CommandError::from)?;
                mining
                    .cached_current_height
                    .store(peer_status.canonical_height, Ordering::Release);
                mining
                    .cached_connected_peers
                    .store(peer_status.connected_total, Ordering::Release);
                (peer_status.canonical_height, peer_status.connected_total)
            }
            Err(std::sync::TryLockError::WouldBlock) => (
                mining.cached_current_height.load(Ordering::Acquire),
                mining.cached_connected_peers.load(Ordering::Acquire),
            ),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.recovery_required.store(true, Ordering::Release);
                return Err(CommandError::RecoveryRequired);
            }
        };
        let last_candidate = mining.last_candidate_time.load(Ordering::Acquire);
        let last_height = mining.last_accepted_height.load(Ordering::Acquire);
        Ok(MiningStatusDto {
            status: mining_state_name(raw_state, config.enabled).into(),
            enabled: config.enabled,
            running: raw_state == MINING_RUNNING,
            cpu_threads: config.cpu_threads,
            mining_address: config.mining_address,
            hash_attempts: attempts,
            hashrate_hps: if uptime > 0 {
                attempts as f64 / uptime as f64
            } else {
                0.0
            },
            current_height,
            connected_peers,
            accepted_blocks: mining.accepted_blocks.load(Ordering::Relaxed),
            rejected_work: mining.rejected_work.load(Ordering::Relaxed),
            template_refreshes: mining.template_refreshes.load(Ordering::Relaxed),
            last_block_candidate_time: (last_candidate > 0).then_some(last_candidate),
            last_accepted_block_height: (last_height != u64::MAX).then_some(last_height),
            uptime_seconds: uptime,
            error_code: mining
                .error_code
                .lock()
                .ok()
                .and_then(|error| error.clone()),
        })
    }

    pub fn mining_start(&self, confirmed: bool) -> Result<MiningStatusDto, CommandError> {
        self.reap_finished_mining_worker()?;
        if !confirmed {
            return Err(CommandError::MiningConfirmationRequired);
        }
        let config = self.mining_config_get()?;
        if !config.enabled {
            return Err(CommandError::MiningDisabled);
        }
        let sync = self.wallet_sync_status()?;
        let peers = self.node_peer_status()?;
        require_mining_cursor_gate(
            sync.cursor_height,
            sync.cursor_hash.as_deref(),
            sync.canonical_height,
            sync.canonical_hash.as_deref(),
            sync.last_error.as_deref(),
            peers.total_connected_peers,
        )?;
        let node_status = self.embedded_node_status()?;
        if !matches!(
            node_status.lifecycle,
            WalletReadinessDto::Ready | WalletReadinessDto::ConnectedAtGenesis
        ) || !node_status.ready
        {
            return Err(CommandError::NodeNotReady);
        }
        let service = Arc::clone(&self.service);
        let node = service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .embedded_node_handle()
            .map_err(CommandError::from)?;
        let mut mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
        mining
            .cached_current_height
            .store(peers.canonical_height, Ordering::Release);
        mining
            .cached_connected_peers
            .store(peers.total_connected_peers, Ordering::Release);
        if mining.worker.is_some()
            || matches!(
                mining.state.load(Ordering::Acquire),
                MINING_STARTING | MINING_RUNNING | MINING_STOPPING
            )
        {
            return Err(CommandError::MiningRunning);
        }
        let activity = self.activities.try_begin(ActivityKind::Mining)?;
        mining.stop.store(false, Ordering::Release);
        mining.hash_attempts.store(0, Ordering::Release);
        mining.accepted_blocks.store(0, Ordering::Release);
        mining.rejected_work.store(0, Ordering::Release);
        mining.template_refreshes.store(0, Ordering::Release);
        mining.last_candidate_time.store(0, Ordering::Release);
        mining
            .last_accepted_height
            .store(u64::MAX, Ordering::Release);
        mining.started_at.store(unix_seconds(), Ordering::Release);
        if let Ok(mut error) = mining.error_code.lock() {
            *error = None;
        }
        mining.state.store(MINING_STARTING, Ordering::Release);
        let stop = Arc::clone(&mining.stop);
        let attempts = Arc::clone(&mining.hash_attempts);
        let accepted = Arc::clone(&mining.accepted_blocks);
        let rejected = Arc::clone(&mining.rejected_work);
        let refreshes = Arc::clone(&mining.template_refreshes);
        let candidate_time = Arc::clone(&mining.last_candidate_time);
        let accepted_height = Arc::clone(&mining.last_accepted_height);
        let state = Arc::clone(&mining.state);
        let error_code = Arc::clone(&mining.error_code);
        let threads = config.cpu_threads;
        let worker = std::thread::Builder::new()
            .name("dom-wallet-cpu-miner".into())
            .spawn(move || {
                let _activity = activity;
                let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    let Ok(runtime) = runtime else {
                        state.store(MINING_ERROR, Ordering::Release);
                        if let Ok(mut error) = error_code.lock() {
                            *error = Some("MINER_RUNTIME_START_FAILED".into());
                        }
                        return;
                    };
                    node.metrics.mining_active.store(1, Ordering::Release);
                    state.store(MINING_RUNNING, Ordering::Release);
                    let mut coinbase_candidate = None;
                    while !stop.load(Ordering::Acquire) {
                        let height = node
                            .metrics
                            .chain_height
                            .load(Ordering::Acquire)
                            .saturating_add(1);
                        candidate_time.store(unix_seconds(), Ordering::Release);
                        if coinbase_candidate
                            .as_ref()
                            .is_none_or(|(candidate_height, _)| *candidate_height != height)
                        {
                            let coinbase = service.lock().map_err(|_| ()).and_then(|mut wallet| {
                                wallet.mining_coinbase_candidate(height).map_err(|_| ())
                            });
                            let Ok(coinbase) = coinbase else {
                                state.store(MINING_ERROR, Ordering::Release);
                                if let Ok(mut error) = error_code.lock() {
                                    *error = Some("MINING_COINBASE_PREPARATION_FAILED".into());
                                }
                                break;
                            };
                            coinbase_candidate = Some((height, coinbase));
                        }
                        let Some((_, coinbase)) = coinbase_candidate.as_ref() else {
                            state.store(MINING_ERROR, Ordering::Release);
                            if let Ok(mut error) = error_code.lock() {
                                *error = Some("MINING_COINBASE_PREPARATION_FAILED".into());
                            }
                            break;
                        };
                        match runtime.block_on(mine_wallet_block(
                            Arc::clone(&node),
                            coinbase,
                            threads,
                            Arc::clone(&stop),
                            Arc::clone(&attempts),
                        )) {
                            Ok(WalletMiningOutcome::Accepted { height }) => {
                                accepted.fetch_add(1, Ordering::Relaxed);
                                accepted_height.store(height, Ordering::Release);
                                coinbase_candidate = None;
                            }
                            Ok(WalletMiningOutcome::Rejected { .. }) => {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                coinbase_candidate = None;
                            }
                            Ok(WalletMiningOutcome::Stale { .. }) => {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                coinbase_candidate = None;
                            }
                            Ok(WalletMiningOutcome::TemplateExpired { .. }) => {
                                refreshes.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(WalletMiningOutcome::Stopped) => break,
                            Err(_) => {
                                rejected.fetch_add(1, Ordering::Relaxed);
                                state.store(MINING_ERROR, Ordering::Release);
                                if let Ok(mut error) = error_code.lock() {
                                    *error = Some("MINING_WORK_FAILED".into());
                                }
                                break;
                            }
                        }
                    }
                }));
                node.metrics.mining_active.store(0, Ordering::Release);
                if worker_result.is_err() {
                    state.store(MINING_ERROR, Ordering::Release);
                    if let Ok(mut error) = error_code.lock() {
                        *error = Some("MINING_WORKER_PANIC".into());
                    }
                }
                if state.load(Ordering::Acquire) != MINING_ERROR {
                    state.store(MINING_READY, Ordering::Release);
                }
            });
        match worker {
            Ok(worker) => mining.worker = Some(worker),
            Err(_) => {
                mining.state.store(MINING_ERROR, Ordering::Release);
                if let Ok(mut error) = mining.error_code.lock() {
                    *error = Some("MINING_WORKER_START_FAILED".into());
                }
                return Err(CommandError::Unavailable);
            }
        }
        drop(mining);
        self.mining_status()
    }

    pub fn mining_stop(&self) -> Result<MiningStatusDto, CommandError> {
        self.stop_mining_worker()?;
        self.mining_status()
    }

    fn stop_mining_worker(&self) -> Result<(), CommandError> {
        let worker = {
            let mut mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
            if mining.worker.is_some() {
                mining.state.store(MINING_STOPPING, Ordering::Release);
                mining.stop.store(true, Ordering::Release);
            }
            mining.worker.take()
        };
        if let Some(worker) = worker {
            if worker.join().is_err() {
                if let Ok(mining) = self.mining.lock() {
                    mining.state.store(MINING_ERROR, Ordering::Release);
                    if let Ok(mut error) = mining.error_code.lock() {
                        *error = Some("MINING_WORKER_PANIC".into());
                    }
                }
                return Err(CommandError::WorkerPanicked);
            }
        }
        let mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
        mining.state.store(MINING_READY, Ordering::Release);
        Ok(())
    }

    fn reap_finished_mining_worker(&self) -> Result<(), CommandError> {
        let worker = {
            let mut mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
            if mining.worker.as_ref().is_some_and(JoinHandle::is_finished) {
                mining.worker.take()
            } else {
                None
            }
        };
        if worker.is_some_and(|worker| worker.join().is_err()) {
            if let Ok(mining) = self.mining.lock() {
                mining.state.store(MINING_ERROR, Ordering::Release);
                if let Ok(mut error) = mining.error_code.lock() {
                    *error = Some("MINING_WORKER_PANIC".into());
                }
            }
            return Err(CommandError::WorkerPanicked);
        }
        Ok(())
    }
    pub fn diagnostics_redacted(&self) -> DiagnosticSnapshot {
        match self.service.lock() {
            Ok(service) => service.diagnostics(),
            Err(_) => {
                self.recovery_required.store(true, Ordering::Release);
                DiagnosticSnapshot {
                    application_state: "RECOVERY_REQUIRED".into(),
                    connection_state: "UNAVAILABLE".into(),
                    generation: None,
                    cursor_height: None,
                    cursor_hash: None,
                    last_error: Some("APPLICATION_STATE_UNAVAILABLE".into()),
                }
            }
        }
    }
    pub fn application_shutdown(&self) -> Result<(), CommandError> {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = (|| {
            let _activity = self.activities.try_begin(ActivityKind::Shutdown)?;
            self.stop_mining_worker()?;
            self.stop_synchronization_worker()?;
            self.sidecar
                .lock()
                .map_err(|_| CommandError::Unavailable)?
                .shutdown()
                .map_err(|_| CommandError::Unavailable)?;
            self.clear_qr_buffers()?;
            let mut service = self.lock_service()?;
            service.close().map_err(CommandError::from)?;
            self.node_started.store(false, Ordering::Release);
            Ok(())
        })();
        if result.is_err() {
            self.shutdown.store(false, Ordering::Release);
        }
        result
    }
    pub fn synchronization_pause(&self) -> Result<(), CommandError> {
        self.synchronization_paused.store(true, Ordering::Release);
        self.stop_synchronization_worker()
    }
    pub fn synchronization_resume_live(&self) -> Result<WalletSyncStatusDto, CommandError> {
        self.synchronization_paused.store(false, Ordering::Release);
        self.synchronization_start_live()
    }
    pub fn synchronization_rescan(&self) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self.activities.try_begin(ActivityKind::Synchronization)?;
        self.synchronization_paused.store(false, Ordering::Release);
        self.lock_service()?
            .rescan_from_genesis()
            .map_err(CommandError::from)
    }

    pub fn synchronization_start_live(&self) -> Result<WalletSyncStatusDto, CommandError> {
        self.ensure_running()?;
        if self.synchronization_paused.load(Ordering::Acquire) {
            return Err(CommandError::SynchronizationPaused);
        }
        self.reap_finished_sync_worker()?;
        let mut initial = self.wallet_sync_status()?;
        let mut runtime = self
            .synchronization
            .lock()
            .map_err(|_| CommandError::Unavailable)?;
        if runtime.worker.is_some() || runtime.state.load(Ordering::Acquire) == SYNC_RUNNING {
            initial.state = "SYNCHRONIZING".into();
            return Ok(initial);
        }
        let activity = self.activities.try_begin(ActivityKind::Synchronization)?;
        runtime.stop.store(false, Ordering::Release);
        runtime.state.store(SYNC_RUNNING, Ordering::Release);
        if let Ok(mut error) = runtime.error_code.lock() {
            *error = None;
        }
        initial.state = "SYNCHRONIZING".into();
        if let Ok(mut cached) = runtime.cached_status.lock() {
            *cached = Some(initial.clone());
        }
        let service = Arc::clone(&self.service);
        let stop = Arc::clone(&runtime.stop);
        let state = Arc::clone(&runtime.state);
        let error_code = Arc::clone(&runtime.error_code);
        let cached = Arc::clone(&runtime.cached_status);
        let activities = Arc::clone(&self.activities);
        let worker = std::thread::Builder::new()
            .name("dom-wallet-sync".into())
            .spawn(move || {
                let mut initial_activity = Some(activity);
                let worker_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_synchronization_follow_loop(
                        &stop,
                        || {
                            let _activity = match initial_activity.take() {
                                Some(activity) => activity,
                                None => activities.try_begin(ActivityKind::Synchronization)?,
                            };
                            let mut wallet =
                                service.lock().map_err(|_| CommandError::RecoveryRequired)?;
                            let result = wallet.synchronize_live().map_err(CommandError::from);
                            let snapshot = sync_status_from_service(&wallet, false);
                            let synchronized = snapshot.synchronized;
                            if let Ok(mut cached) = cached.lock() {
                                *cached = Some(snapshot);
                            }
                            result.map(|_| synchronized)
                        },
                        std::thread::park_timeout,
                    )
                }));
                match worker_result {
                    Ok(Ok(())) => {
                        if state.load(Ordering::Acquire) != SYNC_ERROR {
                            state.store(SYNC_IDLE, Ordering::Release);
                        }
                    }
                    Ok(Err(error)) => {
                        state.store(SYNC_ERROR, Ordering::Release);
                        if let Ok(mut slot) = error_code.lock() {
                            *slot = Some(match error {
                                CommandError::RecoveryRequired => "SYNC_RECOVERY_REQUIRED".into(),
                                _ => "SYNC_WORK_FAILED".into(),
                            });
                        }
                    }
                    Err(_) => {
                        state.store(SYNC_ERROR, Ordering::Release);
                        if let Ok(mut slot) = error_code.lock() {
                            *slot = Some("SYNC_WORKER_PANIC".into());
                        }
                    }
                }
            });
        match worker {
            Ok(worker) => runtime.worker = Some(worker),
            Err(_) => {
                runtime.state.store(SYNC_ERROR, Ordering::Release);
                if let Ok(mut error) = runtime.error_code.lock() {
                    *error = Some("SYNC_WORKER_START_FAILED".into());
                }
                return Err(CommandError::Unavailable);
            }
        }
        Ok(initial)
    }

    fn stop_synchronization_worker(&self) -> Result<(), CommandError> {
        let worker = {
            let mut runtime = self
                .synchronization
                .lock()
                .map_err(|_| CommandError::Unavailable)?;
            runtime.stop.store(true, Ordering::Release);
            if runtime.worker.is_some() {
                runtime.state.store(SYNC_STOPPING, Ordering::Release);
            }
            let worker = runtime.worker.take();
            if let Some(worker) = worker.as_ref() {
                worker.thread().unpark();
            }
            worker
        };
        if worker.is_some_and(|worker| worker.join().is_err()) {
            if let Ok(runtime) = self.synchronization.lock() {
                runtime.state.store(SYNC_ERROR, Ordering::Release);
                if let Ok(mut error) = runtime.error_code.lock() {
                    *error = Some("SYNC_WORKER_PANIC".into());
                }
            }
            return Err(CommandError::WorkerPanicked);
        }
        let runtime = self
            .synchronization
            .lock()
            .map_err(|_| CommandError::Unavailable)?;
        runtime.state.store(SYNC_IDLE, Ordering::Release);
        Ok(())
    }

    fn reap_finished_sync_worker(&self) -> Result<(), CommandError> {
        let worker = {
            let mut runtime = self
                .synchronization
                .lock()
                .map_err(|_| CommandError::Unavailable)?;
            if runtime.worker.as_ref().is_some_and(JoinHandle::is_finished) {
                runtime.worker.take()
            } else {
                None
            }
        };
        if worker.is_some_and(|worker| worker.join().is_err()) {
            if let Ok(runtime) = self.synchronization.lock() {
                runtime.state.store(SYNC_ERROR, Ordering::Release);
                if let Ok(mut error) = runtime.error_code.lock() {
                    *error = Some("SYNC_WORKER_PANIC".into());
                }
            }
            return Err(CommandError::WorkerPanicked);
        }
        Ok(())
    }

    pub fn transaction_fee_estimate(
        &self,
        amount: u64,
        selected_input_count: u32,
        change_output: bool,
    ) -> Result<FeeEstimate, CommandError> {
        self.ensure_running()?;
        self.lock_service()?
            .transaction_fee_estimate(amount, selected_input_count, change_output)
            .map_err(CommandError::from)
    }

    pub fn transaction_send_create(
        &self,
        amount: u64,
        requested_fee: Option<u64>,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        if amount == 0 {
            return Err(CommandError::InvalidInput("amount must be positive".into()));
        }
        self.lock_service()?
            .transaction_send_create(amount, requested_fee, expires_at_height)
            .map_err(CommandError::from)
    }

    pub fn wallet_address_validate(&self, address: &str) -> Result<String, CommandError> {
        self.ensure_running()?;
        self.lock_service()?
            .validate_wallet_address(address)
            .map_err(CommandError::from)
    }

    pub fn slate_request_export(&self, slate_id: uuid::Uuid) -> Result<SlateExport, CommandError> {
        self.ensure_running()?;
        self.lock_service()?
            .slate_request_export(slate_id)
            .map_err(CommandError::from)
    }

    /// Encodes exactly the existing canonical text envelope. It creates no
    /// alternative slate format and carries no private wallet material.
    pub fn slate_qr_encode(
        &self,
        slate_id: uuid::Uuid,
        response: bool,
    ) -> Result<SlateQrExportDto, CommandError> {
        self.ensure_running()?;
        let exported = if response {
            self.slate_response_export(slate_id)?
        } else {
            self.slate_request_export(slate_id)?
        };
        if exported.text.len() > MAX_SLATE_QR_TEXT_BYTES {
            return Err(CommandError::InvalidInput("QR payload is too large".into()));
        }
        let content_hash: [u8; 32] = Sha256::digest(exported.text.as_bytes()).into();
        let mut message_id_bytes = [0u8; 16];
        message_id_bytes.copy_from_slice(&content_hash[..16]);
        let message_id = Uuid::from_bytes(message_id_bytes);
        let count = exported.text.len().div_ceil(SLATE_QR_PAYLOAD_BYTES);
        if count == 0 || count > MAX_SLATE_QR_FRAMES {
            return Err(CommandError::InvalidInput("QR payload is invalid".into()));
        }
        let part_count = u16::try_from(count)
            .map_err(|_| CommandError::InvalidInput("QR payload is too large".into()))?;
        let total_length = u32::try_from(exported.text.len())
            .map_err(|_| CommandError::InvalidInput("QR payload is too large".into()))?;
        let frames = exported
            .text
            .as_bytes()
            .chunks(SLATE_QR_PAYLOAD_BYTES)
            .enumerate()
            .map(|(index, payload)| {
                encode_slate_qr_frame(&SlateQrFrameV1 {
                    version: SLATE_QR_VERSION,
                    message_id,
                    response,
                    part_index: u16::try_from(index).map_err(|_| {
                        CommandError::InvalidInput("QR payload is too large".into())
                    })?,
                    part_count,
                    total_length,
                    content_sha256: content_hash,
                    payload: payload.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, CommandError>>()?;
        Ok(SlateQrExportDto {
            multipart: frames.len() > 1,
            frames,
            content_hash: hex::encode(content_hash),
        })
    }

    /// Reassembles public QR transport frames only. A completed text envelope
    /// must still pass the normal role-bound core import path.
    pub fn slate_qr_decode_frame(&self, frame: &str) -> Result<SlateQrReassemblyDto, CommandError> {
        self.ensure_running()?;
        let frame = parse_slate_qr_frame(frame)?;
        let mut runtime = self
            .qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)?;
        if runtime.completed.contains(&frame.content_sha256) {
            return Err(CommandError::InvalidInput("QR replay rejected".into()));
        }
        let assembly = runtime.active.get_or_insert_with(|| SlateQrAssembly {
            message_id: frame.message_id,
            response: frame.response,
            part_count: frame.part_count,
            total_length: frame.total_length,
            content_sha256: frame.content_sha256,
            parts: BTreeMap::new(),
            complete_text: None,
        });
        if assembly.message_id != frame.message_id
            || assembly.response != frame.response
            || assembly.part_count != frame.part_count
            || assembly.total_length != frame.total_length
            || assembly.content_sha256 != frame.content_sha256
        {
            return Err(CommandError::InvalidInput(
                "QR frame conflicts with active message".into(),
            ));
        }
        if let Some(existing) = assembly.parts.get(&frame.part_index) {
            if existing != &frame.payload {
                return Err(CommandError::InvalidInput(
                    "QR duplicate frame conflicts".into(),
                ));
            }
        } else {
            assembly.parts.insert(frame.part_index, frame.payload);
        }
        if assembly.parts.len() == usize::from(assembly.part_count) {
            let mut bytes = Vec::with_capacity(assembly.total_length as usize);
            for index in 0..assembly.part_count {
                bytes.extend_from_slice(
                    assembly
                        .parts
                        .get(&index)
                        .ok_or_else(|| CommandError::InvalidInput("QR frame is missing".into()))?,
                );
            }
            if bytes.len() != assembly.total_length as usize
                || bytes.len() > MAX_SLATE_QR_TEXT_BYTES
                || <Sha256 as Digest>::digest(&bytes).as_slice() != assembly.content_sha256
            {
                return Err(CommandError::InvalidInput(
                    "QR message integrity failed".into(),
                ));
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| CommandError::InvalidInput("QR message is invalid".into()))?;
            checked_slate_text(&text)?;
            if !text.starts_with("DOMSLATE4.") {
                return Err(CommandError::InvalidInput(
                    "QR message role is invalid".into(),
                ));
            }
            assembly.complete_text = Some(text);
            runtime.completed.insert(frame.content_sha256);
        }
        Ok(qr_reassembly_dto(runtime.active.as_ref()))
    }

    pub fn slate_qr_reassembly_status(&self) -> Result<SlateQrReassemblyDto, CommandError> {
        let runtime = self
            .qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)?;
        Ok(qr_reassembly_dto(runtime.active.as_ref()))
    }

    pub fn slate_qr_reassembly_clear(&self) -> Result<(), CommandError> {
        self.clear_qr_buffers()
    }

    pub fn slate_request_import(&self, text: &str) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        checked_slate_text(text)?;
        self.lock_service()?
            .slate_request_import(text)
            .map_err(CommandError::from)
    }

    pub fn slate_response_create(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .slate_response_create(slate_id)
            .map_err(CommandError::from)
    }

    pub fn slate_response_export(&self, slate_id: uuid::Uuid) -> Result<SlateExport, CommandError> {
        self.ensure_running()?;
        self.lock_service()?
            .slate_response_export(slate_id)
            .map_err(CommandError::from)
    }

    pub fn slate_response_import(&self, text: &str) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        checked_slate_text(text)?;
        self.lock_service()?
            .slate_response_import(text)
            .map_err(CommandError::from)
    }

    pub fn slate_summary_redacted(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_detail_redacted(slate_id)
            .map_err(CommandError::from)
    }

    pub fn transaction_finalize(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_finalize(slate_id)
            .map_err(CommandError::from)
    }

    pub fn transaction_submit(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_submit(slate_id)
            .map(submission_result)
            .map_err(CommandError::from)
    }

    pub fn transaction_retry_submission(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_retry_submission(slate_id)
            .map(submission_result)
            .map_err(CommandError::from)
    }

    pub fn transaction_reconcile_submission(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_reconcile_submission(slate_id)
            .map(submission_result)
            .map_err(CommandError::from)
    }

    pub fn transaction_cancel(
        &self,
        slate_id: uuid::Uuid,
        confirm_exported: bool,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        let _activity = self
            .activities
            .try_begin(ActivityKind::CriticalTransaction)?;
        self.lock_service()?
            .transaction_cancel(slate_id, confirm_exported)
            .map_err(CommandError::from)
    }

    pub fn transaction_list(&self) -> Result<Vec<TransactionSummary>, CommandError> {
        self.ensure_running()?;
        self.lock_service()?
            .transaction_list()
            .map_err(CommandError::from)
    }

    fn ensure_running(&self) -> Result<(), CommandError> {
        if self.recovery_required.load(Ordering::Acquire) {
            Err(CommandError::RecoveryRequired)
        } else if self.shutdown.load(Ordering::Acquire) {
            Err(CommandError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn lock_service(&self) -> Result<MutexGuard<'_, WalletService>, CommandError> {
        if self.recovery_required.load(Ordering::Acquire) {
            return Err(CommandError::RecoveryRequired);
        }
        match self.service.lock() {
            Ok(service) => Ok(service),
            Err(_) => {
                self.recovery_required.store(true, Ordering::Release);
                Err(CommandError::RecoveryRequired)
            }
        }
    }

    /// Discard poisoned in-memory state and reconstruct a locked wallet from
    /// its already validated managed directory.
    pub fn recover_managed_wallet_from_disk(
        &self,
        wallets_root: &Path,
        name: &str,
    ) -> Result<WalletSummary, CommandError> {
        let _activity = self.activities.try_begin(ActivityKind::WalletLifecycle)?;
        let path = resolve_existing_managed_wallet(wallets_root, name)?;
        self.stop_mining_worker()?;
        self.stop_synchronization_worker()?;
        self.clear_qr_buffers()?;
        self.sidecar
            .lock()
            .map_err(|_| CommandError::RecoveryRequired)?
            .shutdown()
            .map_err(|_| CommandError::RecoveryRequired)?;
        let replacement = WalletService::default();
        let mut guard = match self.service.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = replacement;
        let summary = guard.open(path).map_err(CommandError::from)?;
        drop(guard);
        self.service.clear_poison();
        self.node_started.store(false, Ordering::Release);
        self.last_successful_node_status_at
            .store(0, Ordering::Release);
        self.last_peer_connected_unix_seconds
            .store(0, Ordering::Release);
        self.synchronization_paused.store(false, Ordering::Release);
        self.recovery_required.store(false, Ordering::Release);
        Ok(summary)
    }

    fn clear_qr_buffers(&self) -> Result<(), CommandError> {
        self.qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .active = None;
        Ok(())
    }
}

fn encode_slate_qr_frame(frame: &SlateQrFrameV1) -> Result<String, CommandError> {
    if frame.version != SLATE_QR_VERSION
        || frame.part_count == 0
        || usize::from(frame.part_count) > MAX_SLATE_QR_FRAMES
        || frame.part_index >= frame.part_count
        || frame.payload.len() > SLATE_QR_PAYLOAD_BYTES
        || frame.total_length == 0
        || frame.total_length as usize > MAX_SLATE_QR_TEXT_BYTES
    {
        return Err(CommandError::InvalidInput("QR frame is invalid".into()));
    }
    Ok(format!(
        "{SLATE_QR_FRAME_PREFIX}.{}.{}.{}.{}.{}.{}.{}.{}",
        frame.version,
        frame.message_id.simple(),
        u8::from(frame.response),
        frame.part_index,
        frame.part_count,
        frame.total_length,
        hex::encode(frame.content_sha256),
        URL_SAFE_NO_PAD.encode(&frame.payload),
    ))
}

fn parse_slate_qr_frame(value: &str) -> Result<SlateQrFrameV1, CommandError> {
    if value.is_empty()
        || value.len() > SLATE_QR_PAYLOAD_BYTES.saturating_mul(2).saturating_add(256)
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(CommandError::InvalidInput("QR frame is invalid".into()));
    }
    let mut fields = value.split('.');
    if fields.next() != Some(SLATE_QR_FRAME_PREFIX) {
        return Err(CommandError::InvalidInput("QR frame is invalid".into()));
    }
    let version = fields
        .next()
        .and_then(|field| field.parse::<u8>().ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let message_id = fields
        .next()
        .and_then(|field| Uuid::parse_str(field).ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let response = match fields.next() {
        Some("0") => false,
        Some("1") => true,
        _ => return Err(CommandError::InvalidInput("QR frame is invalid".into())),
    };
    let part_index = fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let part_count = fields
        .next()
        .and_then(|field| field.parse::<u16>().ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let total_length = fields
        .next()
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let hash = fields
        .next()
        .and_then(|field| hex::decode(field).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    let payload = fields
        .next()
        .and_then(|field| URL_SAFE_NO_PAD.decode(field).ok())
        .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
    if fields.next().is_some() {
        return Err(CommandError::InvalidInput("QR frame is invalid".into()));
    }
    let frame = SlateQrFrameV1 {
        version,
        message_id,
        response,
        part_index,
        part_count,
        total_length,
        content_sha256: hash,
        payload,
    };
    if encode_slate_qr_frame(&frame)? != value {
        return Err(CommandError::InvalidInput(
            "QR frame encoding is noncanonical".into(),
        ));
    }
    Ok(frame)
}

fn qr_reassembly_dto(assembly: Option<&SlateQrAssembly>) -> SlateQrReassemblyDto {
    SlateQrReassemblyDto {
        message_id: assembly.map(|value| value.message_id.to_string()),
        received_frames: assembly
            .and_then(|value| u16::try_from(value.parts.len()).ok())
            .unwrap_or(0),
        total_frames: assembly.map(|value| value.part_count).unwrap_or(0),
        response: assembly.map(|value| value.response),
        complete_text: assembly.and_then(|value| value.complete_text.clone()),
    }
}

fn sync_status_from_service(service: &WalletService, paused: bool) -> WalletSyncStatusDto {
    let diagnostic = service.diagnostics();
    let identity = service.embedded_core_identity().ok();
    let peers = service.embedded_peer_status().ok();
    let canonical_height = identity.as_ref().map(|value| value.current_tip.height);
    let canonical_hash = identity
        .as_ref()
        .map(|value| hex::encode(value.current_tip.hash));
    let synchronized = cursor_is_authoritatively_synchronized(
        diagnostic.cursor_height,
        diagnostic.cursor_hash.as_deref(),
        canonical_height,
        canonical_hash.as_deref(),
        peers.as_ref().map_or(0, |status| status.connected_total),
        peers
            .as_ref()
            .filter(|status| status.connected_total > 0)
            .map(|status| status.highest_known_peer_height),
        diagnostic.last_error.as_deref(),
    );
    WalletSyncStatusDto {
        state: diagnostic.application_state,
        cursor_height: diagnostic.cursor_height,
        cursor_hash: diagnostic.cursor_hash,
        canonical_height,
        canonical_hash,
        synchronized,
        paused,
        last_result: if synchronized {
            "SUCCESS"
        } else {
            "NOT_SYNCHRONIZED"
        }
        .into(),
        last_error: diagnostic.last_error,
    }
}

fn cursor_is_authoritatively_synchronized(
    cursor_height: Option<u64>,
    cursor_hash: Option<&str>,
    canonical_height: Option<u64>,
    canonical_hash: Option<&str>,
    connected_peers: u64,
    highest_known_peer_height: Option<u64>,
    last_error: Option<&str>,
) -> bool {
    connected_peers > 0
        && cursor_height.is_some()
        && cursor_height == canonical_height
        && cursor_height == highest_known_peer_height
        && cursor_hash.is_some()
        && cursor_hash == canonical_hash
        && last_error.is_none()
}

fn stopped_node_status() -> EmbeddedNodeStatusDto {
    EmbeddedNodeStatusDto {
        lifecycle: WalletReadinessDto::Stopped,
        network: None,
        chain_id: None,
        genesis_hash: None,
        canonical_tip_height: None,
        canonical_tip_hash: None,
        protocol_version: None,
        range_proof_version: None,
        ready: false,
        error_code: None,
        connected_peers: 0,
        bootstrap_phase: "STOPPED".into(),
        highest_known_peer_height: None,
        synchronization_progress_percent: None,
        status_message: "Node stopped".into(),
        last_successful_status_at: None,
    }
}

fn unavailable_node_status(last_successful_status_at: Option<u64>) -> EmbeddedNodeStatusDto {
    EmbeddedNodeStatusDto {
        lifecycle: if last_successful_status_at.is_some() {
            WalletReadinessDto::Stale
        } else {
            WalletReadinessDto::Failed
        },
        network: None,
        chain_id: None,
        genesis_hash: None,
        canonical_tip_height: None,
        canonical_tip_hash: None,
        protocol_version: None,
        range_proof_version: None,
        ready: false,
        error_code: Some("NODE_STATUS_UNAVAILABLE".into()),
        connected_peers: 0,
        bootstrap_phase: "FAILED".into(),
        highest_known_peer_height: None,
        synchronization_progress_percent: None,
        status_message: "Node status is unavailable; restart is required".into(),
        last_successful_status_at,
    }
}

fn synchronizing_node_status_without_tip(
    identity: dom_wallet_core_sync::CoreChainIdentity,
    peers: dom_wallet_embedded_core::EmbeddedPeerStatus,
    last_successful_status_at: Option<u64>,
) -> EmbeddedNodeStatusDto {
    let highest_known_peer_height = (peers.connected_total > 0
        && peers.highest_known_peer_height > 0)
        .then_some(peers.highest_known_peer_height);
    EmbeddedNodeStatusDto {
        lifecycle: WalletReadinessDto::Synchronizing,
        network: Some(core_network_name(identity.network).into()),
        chain_id: Some(hex::encode(identity.chain_id)),
        genesis_hash: Some(hex::encode(identity.genesis_hash)),
        canonical_tip_height: Some(peers.canonical_height),
        canonical_tip_hash: None,
        protocol_version: Some(identity.protocol_version),
        range_proof_version: Some(identity.range_proof_serialization_version),
        ready: false,
        error_code: Some("CANONICAL_TIP_TEMPORARILY_UNAVAILABLE".into()),
        connected_peers: peers.connected_total,
        bootstrap_phase: peers.bootstrap_phase.into(),
        highest_known_peer_height,
        synchronization_progress_percent: highest_known_peer_height.map(|peer_height| {
            if peer_height == 0 {
                0
            } else {
                ((u128::from(peers.canonical_height) * 100) / u128::from(peer_height)) as u64
            }
        }),
        status_message: "Synchronizing; canonical tip details are temporarily unavailable".into(),
        last_successful_status_at,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NodeSynchronizationStatus {
    lifecycle: WalletReadinessDto,
    highest_known_peer_height: Option<u64>,
    progress_percent: Option<u64>,
    message: String,
}

fn node_synchronization_status(snapshot: NodeReadinessSnapshot) -> NodeSynchronizationStatus {
    let readiness = derive_node_readiness(snapshot);
    let (lifecycle, progress_percent, message) = match readiness {
        NodeReadiness::Stopped => (WalletReadinessDto::Stopped, None, "Node stopped".into()),
        NodeReadiness::Starting => (
            WalletReadinessDto::Starting,
            None,
            "Starting and verifying canonical identity".into(),
        ),
        NodeReadiness::WaitingForPeers => (
            WalletReadinessDto::WaitingForPeers,
            None,
            format!("Waiting for peers at height {}", snapshot.local_height),
        ),
        NodeReadiness::UnknownPeerHeight => (
            WalletReadinessDto::UnknownPeerHeight,
            None,
            format!(
                "Connected; waiting for an authoritative peer height at {}",
                snapshot.local_height
            ),
        ),
        NodeReadiness::ConnectedAtGenesis => (
            WalletReadinessDto::ConnectedAtGenesis,
            Some(100),
            "Connected to canonical peers at genesis".into(),
        ),
        NodeReadiness::Synchronizing {
            local_height,
            peer_height,
        } => {
            let progress = if peer_height == 0 {
                0
            } else {
                ((u128::from(local_height) * 100) / u128::from(peer_height)) as u64
            };
            (
                WalletReadinessDto::Synchronizing,
                Some(progress),
                format!("Synchronizing {local_height} / {peer_height} ({progress}%)"),
            )
        }
        NodeReadiness::Ready => (
            WalletReadinessDto::Ready,
            Some(100),
            format!("Ready at height {}", snapshot.local_height),
        ),
        NodeReadiness::Stale => (
            WalletReadinessDto::Stale,
            None,
            "Node status is stale".into(),
        ),
        NodeReadiness::Failed => (
            WalletReadinessDto::Failed,
            None,
            "A critical node task failed".into(),
        ),
    };
    NodeSynchronizationStatus {
        lifecycle,
        highest_known_peer_height: snapshot.highest_known_peer_height,
        progress_percent,
        message,
    }
}

fn ensure_seed_restore_node_ready(status: &EmbeddedNodeStatusDto) -> Result<(), CommandError> {
    let local_height = status.canonical_tip_height.unwrap_or(0);
    let peer_height = status.highest_known_peer_height.unwrap_or(0);
    let mainnet = status.network.as_deref() == Some("MAINNET");
    let synchronized = status.lifecycle == WalletReadinessDto::Ready
        && status.ready
        && status.connected_peers > 0
        && peer_height > 0
        && local_height >= peer_height;
    if mainnet && synchronized {
        Ok(())
    } else {
        Err(CommandError::RestoreNodeSynchronizing)
    }
}

fn core_network_name(network: CoreNetwork) -> &'static str {
    match network {
        CoreNetwork::Mainnet => "MAINNET",
        CoreNetwork::Testnet => "TESTNET",
        CoreNetwork::Regtest => "REGTEST",
    }
}

fn available_logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn mining_state_name(state: u64, enabled: bool) -> &'static str {
    match state {
        MINING_STARTING => "STARTING",
        MINING_RUNNING => "RUNNING",
        MINING_STOPPING => "STOPPING",
        MINING_ERROR => "ERROR",
        MINING_READY if enabled => "READY",
        _ => "DISABLED",
    }
}

fn require_mining_cursor_gate(
    cursor_height: Option<u64>,
    cursor_hash: Option<&str>,
    canonical_height: Option<u64>,
    canonical_hash: Option<&str>,
    last_error: Option<&str>,
    connected_peers: u64,
) -> Result<(), CommandError> {
    if cursor_height.is_none()
        || cursor_height != canonical_height
        || cursor_hash.is_none()
        || cursor_hash != canonical_hash
        || last_error.is_some()
    {
        return Err(CommandError::CursorInitializationFailed);
    }
    if connected_peers == 0 {
        return Err(CommandError::NoPeers);
    }
    Ok(())
}

fn domain_identity(identity: &dom_wallet_core_sync::CoreChainIdentity) -> NetworkIdentity {
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

fn submission_result(transaction: TransactionSummary) -> SubmissionResultDto {
    let (outcome, retryable, accepted, relayed) = match transaction.state.as_str() {
        "SUBMITTED" => (SubmissionOutcomeDto::Accepted, false, true, Some(true)),
        "ACCEPTED_NOT_RELAYED" => (
            SubmissionOutcomeDto::AcceptedNotRelayed,
            true,
            true,
            Some(false),
        ),
        "IN_MEMPOOL" => (SubmissionOutcomeDto::AlreadyKnown, false, true, None),
        "RETRANSMIT_REQUIRED" | "RECONCILIATION_REQUIRED" => {
            (SubmissionOutcomeDto::TemporaryFailure, true, false, None)
        }
        "CONFIRMED" => (SubmissionOutcomeDto::Confirmed, false, true, None),
        "REORGED" => (SubmissionOutcomeDto::Reorged, true, false, None),
        "CANCELLED" => (SubmissionOutcomeDto::Cancelled, false, false, None),
        "FAILED" => (SubmissionOutcomeDto::InternalFailure, false, false, None),
        _ => (SubmissionOutcomeDto::Other, false, false, None),
    };
    SubmissionResultDto {
        transaction,
        outcome,
        retryable,
        accepted,
        relayed,
        diagnostic_code: None,
    }
}

fn checked_password(value: &str) -> Result<(), CommandError> {
    if value.len() < 8 || value.len() > 1024 {
        Err(CommandError::InvalidInput(
            "password length is invalid".into(),
        ))
    } else {
        Ok(())
    }
}

fn checked_slate_text(value: &str) -> Result<(), CommandError> {
    if value.is_empty() || value.len() > 2_097_280 || !value.is_ascii() {
        Err(CommandError::InvalidInput(
            "manual slate text is invalid".into(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("invalid command input: {0}")]
    InvalidInput(String),
    #[error("application is unavailable")]
    Unavailable,
    #[error("wallet and Mainnet identities differ")]
    IdentityMismatch,
    #[error("embedded node is not ready")]
    NodeNotReady,
    #[error("seed restore requires a synchronized Mainnet node")]
    RestoreNodeSynchronizing,
    #[error("restore destination already exists")]
    RestoreDestinationExists,
    #[error("restore staging state is incompatible")]
    RestoreStagingIncompatible,
    #[error("wallet name is invalid")]
    InvalidWalletName,
    #[error("managed wallet catalog rejected the requested entry")]
    ManagedWalletRejected,
    #[error("wallet synchronization is paused")]
    SynchronizationPaused,
    #[error("wallet cursor initialization failed")]
    CursorInitializationFailed,
    #[error("mining is already running")]
    MiningRunning,
    #[error("mining is disabled")]
    MiningDisabled,
    #[error("mining confirmation is required")]
    MiningConfirmationRequired,
    #[error("no remote peers are connected")]
    NoPeers,
    #[error("background worker terminated unexpectedly")]
    WorkerPanicked,
    #[error("application recovery from disk is required")]
    RecoveryRequired,
    #[error("another protected wallet activity is active")]
    ActivityBusy,
    #[error("wallet operation rejected ({code})")]
    Wallet {
        code: &'static str,
        message: &'static str,
        retryable: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandErrorDto {
    pub code: String,
    pub category: String,
    pub message: String,
    pub retryable: bool,
}

impl From<CommandError> for CommandErrorDto {
    fn from(value: CommandError) -> Self {
        match value {
            CommandError::InvalidInput(_) => Self {
                code: "INVALID_INPUT".into(),
                category: "VALIDATION".into(),
                message: "The provided value is invalid.".into(),
                retryable: false,
            },
            CommandError::Unavailable => Self {
                code: "APPLICATION_UNAVAILABLE".into(),
                category: "TEMPORARY".into(),
                message: "The embedded wallet service is unavailable.".into(),
                retryable: true,
            },
            CommandError::IdentityMismatch => Self {
                code: "CHAIN_IDENTITY_MISMATCH".into(),
                category: "NETWORK_IDENTITY".into(),
                message: "This wallet does not belong to DOM Mainnet and was not opened.".into(),
                retryable: false,
            },
            CommandError::NodeNotReady => Self {
                code: "EMBEDDED_NODE_NOT_READY".into(),
                category: "NODE".into(),
                message: "The embedded Mainnet node is still starting.".into(),
                retryable: true,
            },
            CommandError::RestoreNodeSynchronizing => Self {
                code: "RESTORE_NODE_SYNCHRONIZING".into(),
                category: "SYNCHRONIZATION".into(),
                message:
                    "Wait for the embedded Mainnet node to finish synchronizing, then retry restore."
                        .into(),
                retryable: true,
            },
            CommandError::RestoreDestinationExists => Self {
                code: "RESTORE_DESTINATION_EXISTS".into(),
                category: "STORAGE".into(),
                message: "A wallet with this name already exists. Choose another name or remove \
                          the existing wallet folder."
                    .into(),
                retryable: false,
            },
            CommandError::RestoreStagingIncompatible => Self {
                code: "RESTORE_STAGING_INCOMPATIBLE".into(),
                category: "STORAGE".into(),
                message: "An interrupted restore left staging data for this destination. Retry \
                          with the same password used before, or remove the hidden restore \
                          staging folder next to the destination."
                    .into(),
                retryable: false,
            },
            CommandError::InvalidWalletName => Self {
                code: "WALLET_NAME_INVALID".into(),
                category: "VALIDATION".into(),
                message: "Use a simple wallet name without separators, special characters, or \
                          reserved Windows names."
                    .into(),
                retryable: false,
            },
            CommandError::ManagedWalletRejected => Self {
                code: "MANAGED_WALLET_REJECTED".into(),
                category: "STORAGE".into(),
                message: "Only a complete wallet inside the managed catalog can be opened."
                    .into(),
                retryable: false,
            },
            CommandError::SynchronizationPaused => Self {
                code: "WALLET_SYNC_PAUSED".into(),
                category: "SYNCHRONIZATION".into(),
                message: "Wallet synchronization is paused.".into(),
                retryable: true,
            },
            CommandError::CursorInitializationFailed => Self {
                code: "CURSOR_INITIALIZATION_FAILED".into(),
                category: "CURSOR".into(),
                message: "The wallet cursor could not be initialized from the canonical chain."
                    .into(),
                retryable: true,
            },
            CommandError::MiningRunning => Self {
                code: "MINING_ALREADY_RUNNING".into(),
                category: "MINING".into(),
                message: "Stop the active miner before changing its configuration.".into(),
                retryable: false,
            },
            CommandError::MiningDisabled => Self {
                code: "MINING_DISABLED".into(),
                category: "MINING".into(),
                message: "Enable mining controls before starting the miner.".into(),
                retryable: false,
            },
            CommandError::MiningConfirmationRequired => Self {
                code: "MINING_CONFIRMATION_REQUIRED".into(),
                category: "MINING".into(),
                message: "Explicit confirmation is required before mining starts.".into(),
                retryable: false,
            },
            CommandError::NoPeers => Self {
                code: "NO_REMOTE_PEERS".into(),
                category: "P2P".into(),
                message: "Connect to at least one Mainnet peer before starting mining.".into(),
                retryable: true,
            },
            CommandError::WorkerPanicked => Self {
                code: "WORKER_PANIC_RECOVERY_REQUIRED".into(),
                category: "WORKER".into(),
                message: "A background worker stopped unexpectedly and was reaped safely."
                    .into(),
                retryable: true,
            },
            CommandError::RecoveryRequired => Self {
                code: "APPLICATION_RECOVERY_REQUIRED".into(),
                category: "FATAL".into(),
                message: "The in-memory wallet service stopped unexpectedly. Close and reopen the managed wallet from disk.".into(),
                retryable: false,
            },
            CommandError::ActivityBusy => Self {
                code: "ACTIVITY_COORDINATOR_BUSY".into(),
                category: "COORDINATION".into(),
                message: "Finish the active wallet operation before continuing.".into(),
                retryable: true,
            },
            CommandError::Wallet {
                code,
                message,
                retryable,
            } => Self {
                code: code.into(),
                category: match code {
                    "INVALID_PASSWORD" | "WALLET_AUTH_DATA_CORRUPT" => "AUTHENTICATION",
                    "WALLET_METADATA_CORRUPT"
                    | "WALLET_PAYLOAD_CORRUPT"
                    | "WALLET_WRITER_ACTIVE"
                    | "WALLET_NOT_FOUND"
                    | "WALLET_STORAGE_FAILED" => "STORAGE",
                    "INVALID_WALLET_STATE"
                    | "TRANSACTION_STATE_INVALID"
                    | "TRANSACTION_CANNOT_CANCEL" => "LIFECYCLE",
                    "EMBEDDED_NODE_OPERATION_FAILED" | "EMBEDDED_NODE_REQUIRED" => "NODE",
                    "TRANSACTION_SUBMISSION_FAILED" => "SUBMISSION",
                    _ => "WALLET",
                }
                .into(),
                message: message.into(),
                retryable,
            },
        }
    }
}

impl From<CoreError> for CommandError {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::IdentityMismatch => Self::IdentityMismatch,
            CoreError::NodeNotReady | CoreError::EmbeddedCoreRequired => Self::NodeNotReady,
            CoreError::InvalidCoreCursor => Self::CursorInitializationFailed,
            CoreError::Restore(error) => command_error_from_restore(error),
            CoreError::WalletNotOpen => Self::Wallet {
                code: "WALLET_NOT_OPEN",
                message: "Open a Mainnet wallet before using this operation.",
                retryable: false,
            },
            CoreError::Locked => Self::Wallet {
                code: "WALLET_LOCKED",
                message: "Unlock the wallet before using this operation.",
                retryable: false,
            },
            CoreError::InsufficientFunds => Self::Wallet {
                code: "INSUFFICIENT_FUNDS",
                message: "The wallet does not have enough spendable funds for this payment.",
                retryable: false,
            },
            CoreError::InvalidSlateTransport => Self::Wallet {
                code: "SLATE_V4_TRANSPORT_INVALID",
                message: "The imported Slate v4 data is invalid or has been altered.",
                retryable: false,
            },
            CoreError::MissingPrivateContext => Self::Wallet {
                code: "SLATE_PRIVATE_CONTEXT_MISSING",
                message: "The private context required to continue this Slate is unavailable.",
                retryable: false,
            },
            CoreError::FeeTooLow => Self::Wallet {
                code: "FEE_TOO_LOW",
                message: "The fee is below the embedded node policy minimum.",
                retryable: false,
            },
            CoreError::Backend(error) if error.is_transient_sync_unavailability() => {
                Self::NodeNotReady
            }
            CoreError::Backend(_) => Self::Wallet {
                code: "EMBEDDED_NODE_OPERATION_FAILED",
                message: "The embedded Mainnet node could not complete the requested operation.",
                retryable: true,
            },
            other => {
                let code = other.redacted_code();
                let (message, retryable) = match code {
                    "WALLET_WRITER_ACTIVE" => (
                        "Close the other running wallet process before opening this wallet.",
                        true,
                    ),
                    "INVALID_PASSWORD" => ("The local wallet password is invalid.", false),
                    "WALLET_AUTH_DATA_CORRUPT" => (
                        "The wallet authentication record is corrupt and cannot be trusted.",
                        false,
                    ),
                    "WALLET_METADATA_CORRUPT" => {
                        ("The wallet metadata is corrupt and was not opened.", false)
                    }
                    "WALLET_PAYLOAD_CORRUPT" => (
                        "The authenticated wallet payload is corrupt and was not opened.",
                        false,
                    ),
                    "WALLET_NOT_FOUND" => ("The managed wallet was not found.", false),
                    _ => (
                        "The wallet rejected the requested operation. Review its typed error code.",
                        false,
                    ),
                };
                Self::Wallet {
                    code,
                    message,
                    retryable,
                }
            }
        }
    }
}

/// Windows device names that can never be wallet names on any platform, so a
/// managed wallet directory always round-trips across operating systems.
const RESERVED_WALLET_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validate a user-facing wallet name for the managed wallets directory.
///
/// Fail closed: a name is a single path component with no traversal, no
/// leading dot (hidden and restore-staging namespace), no trailing dot or
/// space (silently stripped by Windows), no control or Windows-forbidden
/// characters, and no reserved Windows device name as its stem.
pub fn validate_wallet_name(name: &str) -> Result<(), CommandError> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('.')
        || name.ends_with('.')
        || name.starts_with(' ')
        || name.ends_with(' ')
    {
        return Err(CommandError::InvalidWalletName);
    }
    if name.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
    }) {
        return Err(CommandError::InvalidWalletName);
    }
    let stem = name.split('.').next().unwrap_or_default();
    if RESERVED_WALLET_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return Err(CommandError::InvalidWalletName);
    }
    Ok(())
}

/// Resolve a validated wallet name inside the managed wallets root.
pub fn resolve_wallet_directory(wallets_root: &Path, name: &str) -> Result<PathBuf, CommandError> {
    validate_wallet_name(name)?;
    if wallets_root.exists()
        && wallets_root
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink() || !metadata.is_dir())
            .unwrap_or(true)
    {
        return Err(CommandError::ManagedWalletRejected);
    }
    Ok(wallets_root.join(name))
}

pub fn resolve_existing_managed_wallet(
    wallets_root: &Path,
    name: &str,
) -> Result<PathBuf, CommandError> {
    let candidate = resolve_wallet_directory(wallets_root, name)?;
    let root = wallets_root
        .canonicalize()
        .map_err(|_| CommandError::ManagedWalletRejected)?;
    let metadata = candidate
        .symlink_metadata()
        .map_err(|_| CommandError::ManagedWalletRejected)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CommandError::ManagedWalletRejected);
    }
    WalletDirectory::inspect_structure(&candidate)
        .map_err(|_| CommandError::ManagedWalletRejected)?;
    let canonical = candidate
        .canonicalize()
        .map_err(|_| CommandError::ManagedWalletRejected)?;
    if canonical.parent() != Some(root.as_path()) {
        return Err(CommandError::ManagedWalletRejected);
    }
    Ok(canonical)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCatalogDiagnostic {
    pub entry: String,
    pub code: String,
}

pub fn inspect_wallet_catalog(wallets_root: &Path) -> (Vec<String>, Vec<WalletCatalogDiagnostic>) {
    let Ok(root_metadata) = wallets_root.symlink_metadata() else {
        return (Vec::new(), Vec::new());
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return (
            Vec::new(),
            vec![WalletCatalogDiagnostic {
                entry: "[ROOT]".into(),
                code: "MANAGED_ROOT_UNSAFE".into(),
            }],
        );
    }
    let Ok(entries) = std::fs::read_dir(wallets_root) else {
        return (Vec::new(), Vec::new());
    };
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            invalid.push(WalletCatalogDiagnostic {
                entry: "[NON_UTF8]".into(),
                code: "ENTRY_NAME_INVALID".into(),
            });
            continue;
        };
        let code = if name.starts_with('.') {
            Some("STAGING_OR_HIDDEN")
        } else if validate_wallet_name(&name).is_err() {
            Some("ENTRY_NAME_INVALID")
        } else if entry
            .file_type()
            .map(|kind| kind.is_symlink() || !kind.is_dir())
            .unwrap_or(true)
        {
            Some("ENTRY_TYPE_INVALID")
        } else if WalletDirectory::inspect_structure(entry.path()).is_err() {
            Some("WALLET_STRUCTURE_INVALID")
        } else {
            valid.push(name.clone());
            None
        };
        if let Some(code) = code {
            invalid.push(WalletCatalogDiagnostic {
                entry: name,
                code: code.into(),
            });
        }
    }
    valid.sort();
    invalid.sort_by(|left, right| left.entry.cmp(&right.entry));
    (valid, invalid)
}

/// List valid wallet names inside the managed wallets root, sorted.
///
/// A missing root simply yields no wallets; files, hidden restore-staging
/// directories and foreign entries are never listed.
pub fn list_wallet_names(wallets_root: &Path) -> Vec<String> {
    inspect_wallet_catalog(wallets_root).0
}

fn command_error_from_restore(error: SeedRestoreError) -> CommandError {
    match error {
        SeedRestoreError::InvalidDestination => CommandError::RestoreDestinationExists,
        SeedRestoreError::CoreBusy => CommandError::RestoreNodeSynchronizing,
        SeedRestoreError::InvalidMnemonic => CommandError::Wallet {
            code: "RECOVERY_PHRASE_INVALID",
            message: "The recovery phrase is invalid.",
            retryable: false,
        },
        SeedRestoreError::InvalidPassword => CommandError::Wallet {
            code: "INVALID_PASSWORD",
            message: "The local wallet password is invalid.",
            retryable: false,
        },
        SeedRestoreError::ChainIdentityMismatch => CommandError::IdentityMismatch,
        SeedRestoreError::IncompatibleCheckpoint => CommandError::RestoreStagingIncompatible,
        SeedRestoreError::Storage => CommandError::Wallet {
            code: "RESTORE_STORAGE_FAILED",
            message: "The encrypted restore state could not be resumed safely.",
            retryable: true,
        },
        SeedRestoreError::CanonicalScan => CommandError::Wallet {
            code: "RESTORE_CANONICAL_SCAN_FAILED",
            message: "The canonical chain scan failed. Check node synchronization and retry.",
            retryable: true,
        },
        SeedRestoreError::MalformedRecovery
        | SeedRestoreError::ConflictingOutput
        | SeedRestoreError::CoordinateOverflow
        | SeedRestoreError::Incomplete => CommandError::Wallet {
            code: "RESTORE_VALIDATION_FAILED",
            message: "The restored wallet state failed canonical validation.",
            retryable: false,
        },
    }
}

impl From<SeedRestoreError> for CommandError {
    fn from(error: SeedRestoreError) -> Self {
        command_error_from_restore(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_errors_and_status_do_not_expose_passwords() {
        let app = DesktopApplication::default();
        let error = app.wallet_unlock("password-1").unwrap_err();
        assert!(!format!("{error}").contains("password-1"));
        assert!(app.application_status().experimental);
    }

    #[test]
    fn command_manifest_is_complete_unique_and_unprivileged() {
        let unique = COMMAND_NAMES
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), COMMAND_NAMES.len());
        for required in [
            "native_bridge_status",
            "application_status",
            "wallet_create_recoverable",
            "wallet_restore_from_mnemonic",
            "wallet_backup_export",
            "wallet_backup_import",
            "wallet_recovery_phrase_resume",
            "wallet_recovery_phrase_confirm",
            "embedded_node_start",
            "embedded_node_stop",
            "embedded_node_status",
            "wallet_address_validate",
            "application_shutdown",
            "transaction_send_create",
            "transaction_submit",
            "slate_qr_encode",
            "slate_qr_decode_frame",
        ] {
            assert!(COMMAND_NAMES.contains(&required));
        }
        for forbidden in ["shell", "process", "filesystem", "http", "sql", "exec"] {
            assert!(!COMMAND_NAMES
                .iter()
                .any(|command| command.contains(forbidden)));
        }
    }

    #[test]
    fn native_bridge_probe_is_static_redacted_and_versioned() {
        let status = native_bridge_status();
        assert_eq!(status.bridge, "ready");
        assert_eq!(status.app_version, "0.2.9");
        fn assert_serializable<T: serde::Serialize>(_: &T) {}
        assert_serializable(&status);
    }

    #[test]
    fn build_and_update_status_are_separate_redacted_channels() {
        let build = get_build_info();
        assert_eq!(build.wallet_version, "0.2.9");
        assert_eq!(build.embedded_node_revision, EMBEDDED_NODE_REVISION);
        assert_eq!(build.update_channel, "stable");

        let updates = UpdateControl::new(false);
        assert!(updates.begin_check(100));
        assert!(!updates.begin_check(100));
        updates.finish_check_without_key();
        let status = updates.snapshot();
        assert_eq!(status.wallet.state, WalletUpdaterState::Failed);
        assert_eq!(
            status.wallet.sanitized_error.as_deref(),
            Some("UPDATE_SIGNATURE_KEY_UNAVAILABLE")
        );
        let encoded = serde_json::to_string(&status).expect("serialize update status");
        for forbidden in ["seed", "mnemonic", "password", "private_key", "rpc_token"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn closed_wallet_alone_is_not_a_safe_update_point() {
        assert!(!DesktopApplication::default()
            .update_safe_point_available()
            .expect("closed Wallet is conservatively unsafe"));
    }

    #[test]
    fn regression_m1_registry_is_exact_unique_and_served_to_the_frontend() {
        let unique = COMMAND_NAMES.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), COMMAND_NAMES.len());
        assert_eq!(native_bridge_status().command_names, COMMAND_NAMES);
        for removed in ["wallet_open", "check_node_now"] {
            assert!(!COMMAND_NAMES.contains(&removed));
        }
        for required in [
            "wallet_open_named",
            "download_update_now",
            "apply_update_now",
            "automatic_updates_set",
        ] {
            assert!(COMMAND_NAMES.contains(&required));
        }
    }

    #[test]
    fn regression_m2_product_contract_exposes_only_the_signed_wallet_update_feed() {
        let status = serde_json::to_value(UpdateControl::new(true).snapshot())
            .expect("serialize update product contract");
        assert!(status.get("wallet").is_some());
        assert!(status.get("node").is_none());
        assert!(status.get("peers").is_none());
        assert!(!COMMAND_NAMES.contains(&"check_node_now"));
        assert!(dom_wallet_updater::WALLET_UPDATE_ENDPOINT.starts_with("https://"));
    }

    #[test]
    fn sidecar_cannot_be_enabled_without_an_unlocked_wallet_session() {
        let runtime = tempfile::tempdir().expect("temporary runtime");
        let app = DesktopApplication::default();
        app.configure_sidecar_runtime(runtime.path())
            .expect("configure isolated runtime");
        assert!(matches!(
            app.experimental_sidecar_enable(EXPERIMENTAL_ENABLE_CONFIRMATION),
            Err(CommandError::InvalidInput(_))
        ));
        assert!(
            !app.experimental_sidecar_status()
                .expect("sidecar status")
                .enabled_for_session
        );
    }

    #[test]
    fn app_runtime_rejects_equal_and_lower_node_sequences_and_missing_manifest() {
        use dom_wallet_node_manager::NodeIdentity;
        use dom_wallet_updater::{ArtifactDescriptor, NodeManifest, UpdateError};

        let runtime = tempfile::tempdir().expect("temporary runtime");
        let app = DesktopApplication::default();
        app.configure_sidecar_runtime(runtime.path().join("managed"))
            .expect("configure isolated runtime");
        let artifact = b"app-level node fixture";
        let identity = |version: &str, revision: &str| NodeIdentity {
            node_version: version.into(),
            node_revision: revision.into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 1,
            storage_schema_version_supported: 1,
            storage_schema_version_on_disk: 1,
            height: 1,
        };
        let feed = |sequence: u64, version: &str, revision: &str| {
            NodeManifest {
            schema_version: 1,
            channel: "stable".into(),
            node_version: version.into(),
            node_revision: revision.into(),
            sequence,
            published_at: "2026-07-23T12:00:00Z".into(),
            expires_at: "2099-08-23T12:00:00Z".into(),
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
            artifact: ArtifactDescriptor {
                target: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                url: "https://github.com/sorenplanck/dom-protocol/releases/download/node-test/dom-node"
                    .parse()
                    .unwrap(),
                sha256: format!("{:x}", Sha256::digest(artifact)),
                size: artifact.len() as u64,
                signature: "test-only-detached-signature".into(),
            },
            manifest_signature: "test-only-feed-signature".into(),
        }
        };
        let installed_at = time::OffsetDateTime::parse(
            "2026-07-23T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let now = time::OffsetDateTime::parse(
            "2026-07-23T13:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let old = identity("0.1.0", &"b".repeat(40));
        let active = identity("0.1.1", &"c".repeat(40));
        let manager = app.sidecar.lock().unwrap();
        manager
            .app_test_persist_state(&feed(8, "0.1.1", &"c".repeat(40)), &old, installed_at)
            .unwrap();
        for sequence in [8, 7] {
            assert!(matches!(
                manager.app_test_evaluate_verified_feed(
                    feed(sequence, "0.1.2", &"d".repeat(40)),
                    &active,
                    now
                ),
                Err(dom_wallet_node_manager::NodeManagerError::Update(
                    UpdateError::DowngradeRejected
                ))
            ));
        }
        assert_eq!(
            manager
                .app_test_evaluate_verified_feed(feed(9, "0.1.2", &"d".repeat(40)), &active, now)
                .unwrap()
                .sequence,
            9
        );
        drop(manager);
        assert!(matches!(
            app.experimental_sidecar_evaluate_release(None, None, None, std::env::consts::OS),
            Err(CommandError::InvalidInput(_))
        ));
    }

    #[test]
    fn mining_gate_accepts_synchronized_height_one_cursor() {
        let hash = "11".repeat(32);
        assert!(
            require_mining_cursor_gate(Some(1), Some(&hash), Some(1), Some(&hash), None, 1).is_ok()
        );
        assert!(matches!(
            require_mining_cursor_gate(None, None, Some(1), Some(&hash), None, 1),
            Err(CommandError::CursorInitializationFailed)
        ));
        assert!(matches!(
            require_mining_cursor_gate(
                Some(1),
                Some(&hash),
                Some(1),
                Some(&"22".repeat(32)),
                None,
                1
            ),
            Err(CommandError::CursorInitializationFailed)
        ));
    }

    #[test]
    fn shutdown_is_idempotent_and_rejects_new_work() {
        let app = DesktopApplication::default();
        app.application_shutdown().unwrap();
        app.application_shutdown().unwrap();
        assert!(matches!(
            app.wallet_open_path("/tmp/not-used"),
            Err(CommandError::Unavailable)
        ));
        assert!(!format!("{:?}", app.diagnostics_redacted()).contains("password"));
    }

    #[test]
    fn regression_m3_poisoned_service_requires_typed_disk_reconstruction() {
        let root = tempfile::tempdir().unwrap();
        create_catalog_wallet(root.path(), "recoverable");
        let app = DesktopApplication::default();
        app.node_started.store(true, Ordering::Release);
        app.last_successful_node_status_at
            .store(999, Ordering::Release);
        app.synchronization_paused.store(true, Ordering::Release);
        let service = Arc::clone(&app.service);
        let _ = std::thread::spawn(move || {
            let mut guard = service.lock().expect("test acquires service");
            *guard = WalletService::default();
            panic!("poison test mutex");
        })
        .join();

        assert_eq!(app.application_status().state, "RECOVERY_REQUIRED");
        let diagnostic = app.diagnostics_redacted();
        assert_eq!(diagnostic.application_state, "RECOVERY_REQUIRED");
        assert_eq!(
            diagnostic.last_error.as_deref(),
            Some("APPLICATION_STATE_UNAVAILABLE")
        );
        assert!(matches!(
            app.wallet_open_path(root.path().join("recoverable")),
            Err(CommandError::RecoveryRequired)
        ));
        let recovered = app
            .recover_managed_wallet_from_disk(root.path(), "recoverable")
            .unwrap();
        assert_eq!(recovered.network, Network::PrivateTestnet);
        assert_eq!(app.application_status().state, "LOCKED");
        assert!(!app.node_started.load(Ordering::Acquire));
        assert_eq!(
            app.last_successful_node_status_at.load(Ordering::Acquire),
            0
        );
        assert!(!app.synchronization_paused.load(Ordering::Acquire));
    }

    #[test]
    fn poisoned_application_state_is_reported_without_panicking() {
        let app = DesktopApplication::default();
        let service = Arc::clone(&app.service);
        let _ = std::thread::spawn(move || {
            let _guard = service.lock().expect("test acquires service");
            panic!("poison test mutex");
        })
        .join();

        assert_eq!(app.application_status().state, "RECOVERY_REQUIRED");
        let diagnostic = app.diagnostics_redacted();
        assert_eq!(diagnostic.application_state, "RECOVERY_REQUIRED");
        assert_eq!(
            diagnostic.last_error.as_deref(),
            Some("APPLICATION_STATE_UNAVAILABLE")
        );
    }

    #[test]
    fn redacted_configuration_and_errors_never_serialize_credentials() {
        let app = DesktopApplication::default();
        let error = app.wallet_unlock("password-contains-secret").unwrap_err();
        let rendered = error.to_string();
        assert!(!rendered.contains("password-contains-secret"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn node_status_reports_live_initial_block_download_progress() {
        let status = node_synchronization_status(readiness_snapshot(1_008, Some(6_622), 1));

        assert_eq!(status.lifecycle, WalletReadinessDto::Synchronizing);
        assert_eq!(status.highest_known_peer_height, Some(6_622));
        assert_eq!(status.progress_percent, Some(15));
        assert_eq!(status.message, "Synchronizing 1008 / 6622 (15%)");
    }

    #[test]
    fn node_status_never_claims_ready_while_peer_tip_is_ahead() {
        let status = node_synchronization_status(readiness_snapshot(50, Some(100), 1));

        assert_eq!(status.lifecycle, WalletReadinessDto::Synchronizing);
        assert_eq!(status.progress_percent, Some(50));
    }

    #[test]
    fn node_status_is_readable_while_discovering_peers() {
        let status = node_synchronization_status(readiness_snapshot(0, None, 0));

        assert_eq!(status.lifecycle, WalletReadinessDto::WaitingForPeers);
        assert_eq!(status.highest_known_peer_height, None);
        assert_eq!(status.progress_percent, None);
        assert_eq!(status.message, "Waiting for peers at height 0");
    }

    fn readiness_snapshot(
        local_height: u64,
        peer_height: Option<u64>,
        peers: u64,
    ) -> NodeReadinessSnapshot {
        NodeReadinessSnapshot {
            process_running: true,
            canonical_identity_verified: true,
            local_height,
            local_tip_hash: Some([1; 32]),
            connected_peers: peers,
            highest_known_peer_height: peer_height,
            ibd_progress_percent: None,
            critical_task_failed: false,
            last_successful_status_at: Some(1_000),
            now: 1_000,
        }
    }

    #[test]
    fn regression_c5_authoritative_node_readiness_table_covers_every_state() {
        let mut snapshot = readiness_snapshot(0, None, 0);
        snapshot.process_running = false;
        assert_eq!(derive_node_readiness(snapshot), NodeReadiness::Stopped);

        snapshot = readiness_snapshot(0, None, 0);
        snapshot.canonical_identity_verified = false;
        assert_eq!(derive_node_readiness(snapshot), NodeReadiness::Starting);

        snapshot = readiness_snapshot(9, None, 0);
        assert_eq!(
            derive_node_readiness(snapshot),
            NodeReadiness::WaitingForPeers
        );

        snapshot = readiness_snapshot(9, None, 1);
        assert_eq!(
            derive_node_readiness(snapshot),
            NodeReadiness::UnknownPeerHeight
        );

        snapshot = readiness_snapshot(0, Some(0), 1);
        assert_eq!(
            derive_node_readiness(snapshot),
            NodeReadiness::ConnectedAtGenesis
        );

        snapshot = readiness_snapshot(9, Some(10), 1);
        assert_eq!(
            derive_node_readiness(snapshot),
            NodeReadiness::Synchronizing {
                local_height: 9,
                peer_height: 10
            }
        );

        snapshot = readiness_snapshot(10, Some(10), 1);
        assert_eq!(derive_node_readiness(snapshot), NodeReadiness::Ready);

        snapshot.last_successful_status_at = Some(900);
        assert_eq!(derive_node_readiness(snapshot), NodeReadiness::Stale);

        snapshot = readiness_snapshot(10, Some(10), 1);
        snapshot.critical_task_failed = true;
        assert_eq!(derive_node_readiness(snapshot), NodeReadiness::Failed);

        let hash = "11".repeat(32);
        assert!(!cursor_is_authoritatively_synchronized(
            Some(0),
            Some(&hash),
            Some(0),
            Some(&hash),
            0,
            None,
            None,
        ));
        assert!(cursor_is_authoritatively_synchronized(
            Some(0),
            Some(&hash),
            Some(0),
            Some(&hash),
            1,
            Some(0),
            None,
        ));
        assert!(!cursor_is_authoritatively_synchronized(
            Some(9),
            Some(&hash),
            Some(9),
            Some(&hash),
            1,
            Some(10),
            None,
        ));
    }

    #[test]
    fn regression_a6_dead_node_clears_started_state_and_never_reuses_ready_status() {
        let app = DesktopApplication::default();
        app.node_started.store(true, Ordering::Release);
        app.last_successful_node_status_at
            .store(500, Ordering::Release);
        let stale = app.embedded_node_status().unwrap();
        assert_eq!(stale.lifecycle, WalletReadinessDto::Stale);
        assert!(!stale.ready);
        assert_eq!(stale.last_successful_status_at, Some(500));
        assert!(!app.node_started.load(Ordering::Acquire));

        let stopped = app.embedded_node_status().unwrap();
        assert_eq!(stopped.lifecycle, WalletReadinessDto::Stopped);
        assert!(!stopped.ready);
        app.node_started.store(true, Ordering::Release);
        let stale_again = app.embedded_node_status().unwrap();
        assert_eq!(stale_again.lifecycle, WalletReadinessDto::Stale);
        assert!(!app.node_started.load(Ordering::Acquire));
    }

    #[test]
    fn regression_c1_mining_policy_allows_connected_genesis_but_never_zero_peers_or_peer_ahead() {
        assert!(readiness_allows_mining(derive_node_readiness(
            readiness_snapshot(0, Some(0), 1)
        )));
        assert!(!readiness_allows_mining(derive_node_readiness(
            readiness_snapshot(0, None, 0)
        )));
        assert!(!readiness_allows_mining(derive_node_readiness(
            readiness_snapshot(4, Some(5), 1)
        )));
        assert!(readiness_allows_mining(derive_node_readiness(
            readiness_snapshot(5, Some(5), 1)
        )));
    }

    #[test]
    fn regression_a3_mining_worker_reaps_recovers_and_restarts_for_100_cycles() {
        let app = DesktopApplication::default();
        for _ in 0..100 {
            let (finished_tx, finished_rx) = std::sync::mpsc::channel();
            {
                let mut mining = app.mining.lock().unwrap();
                mining.state.store(MINING_RUNNING, Ordering::Release);
                mining.worker = Some(std::thread::spawn(move || {
                    let _ = finished_tx.send(());
                }));
            }
            finished_rx.recv().unwrap();
            app.stop_mining_worker().unwrap();
            let mining = app.mining.lock().unwrap();
            assert!(mining.worker.is_none());
            assert_eq!(mining.state.load(Ordering::Acquire), MINING_READY);
        }

        {
            let mut mining = app.mining.lock().unwrap();
            let state = Arc::clone(&mining.state);
            mining.worker = Some(std::thread::spawn(move || {
                state.store(MINING_ERROR, Ordering::Release);
            }));
        }
        app.stop_mining_worker().unwrap();
        assert_eq!(
            app.mining.lock().unwrap().state.load(Ordering::Acquire),
            MINING_READY
        );

        {
            let mut mining = app.mining.lock().unwrap();
            mining.worker = Some(std::thread::spawn(|| panic!("injected worker panic")));
        }
        assert!(matches!(
            app.stop_mining_worker(),
            Err(CommandError::WorkerPanicked)
        ));
        assert!(app.mining.lock().unwrap().worker.is_none());
        app.stop_mining_worker().unwrap();
        assert_eq!(
            app.mining.lock().unwrap().state.load(Ordering::Acquire),
            MINING_READY
        );
    }

    #[test]
    fn regression_cursor_follow_survives_tip_matches_and_transient_core_not_ready() {
        let stop = AtomicBool::new(false);
        let canonical_height = std::cell::Cell::new(10_007_u64);
        let cursor_height = std::cell::Cell::new(10_006_u64);
        let calls = std::cell::Cell::new(0_u64);
        let observed_not_ready = std::cell::Cell::new(false);
        let waits = std::cell::RefCell::new(Vec::new());

        let result = run_synchronization_follow_loop(
            &stop,
            || {
                let call = calls.get() + 1;
                calls.set(call);
                if call == 3 {
                    observed_not_ready.set(true);
                    return Err(CommandError::NodeNotReady);
                }
                if cursor_height.get() < canonical_height.get() {
                    cursor_height.set(cursor_height.get() + 1);
                }
                Ok(cursor_height.get() == canonical_height.get())
            },
            |delay| {
                let mut waits = waits.borrow_mut();
                waits.push(delay);
                if waits.len() <= 3 {
                    canonical_height.set(canonical_height.get() + 1);
                }
                if canonical_height.get() == 10_010 && cursor_height.get() == canonical_height.get()
                {
                    stop.store(true, Ordering::Release);
                }
            },
        );

        assert!(result.is_ok());
        assert!(observed_not_ready.get());
        assert_eq!(cursor_height.get(), canonical_height.get());
        assert_eq!(cursor_height.get(), 10_010);
        assert_eq!(calls.get(), 5);
        assert_eq!(
            waits.borrow()[2],
            std::time::Duration::from_millis(SYNC_NOT_READY_INITIAL_BACKOFF_MILLIS)
        );
    }

    #[test]
    fn cursor_follow_still_stops_on_non_transient_failures() {
        let stop = AtomicBool::new(false);
        let waits = std::cell::Cell::new(0_u64);
        let result = run_synchronization_follow_loop(
            &stop,
            || Err(CommandError::IdentityMismatch),
            |_| waits.set(waits.get() + 1),
        );

        assert!(matches!(result, Err(CommandError::IdentityMismatch)));
        assert_eq!(waits.get(), 0);
    }

    #[test]
    fn regression_a4_background_sync_keeps_status_and_mining_stop_responsive_without_timing() {
        let app = DesktopApplication::default();
        {
            let runtime = app.synchronization.lock().unwrap();
            *runtime.cached_status.lock().unwrap() = Some(WalletSyncStatusDto {
                state: "SYNCHRONIZING".into(),
                cursor_height: Some(4),
                cursor_hash: Some("11".repeat(32)),
                canonical_height: Some(5),
                canonical_hash: Some("22".repeat(32)),
                synchronized: false,
                paused: false,
                last_result: "NOT_SYNCHRONIZED".into(),
                last_error: None,
            });
        }
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let service = Arc::clone(&app.service);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let holder = std::thread::spawn(move || {
            let _guard = service.lock().unwrap();
            worker_entered.wait();
            worker_release.wait();
        });
        entered.wait();

        let status = app.wallet_sync_status().unwrap();
        assert_eq!(status.state, "SYNCHRONIZING");
        assert_eq!(status.cursor_height, Some(4));
        let stopped = app
            .mining_stop()
            .expect("mining stop uses responsive caches");
        assert!(!stopped.running);

        release.wait();
        holder.join().unwrap();

        let (worker_started_tx, worker_started_rx) = std::sync::mpsc::channel();
        let (worker_stopped_tx, worker_stopped_rx) = std::sync::mpsc::channel();
        {
            let mut runtime = app.synchronization.lock().unwrap();
            runtime.stop.store(false, Ordering::Release);
            runtime.state.store(SYNC_RUNNING, Ordering::Release);
            let stop = Arc::clone(&runtime.stop);
            runtime.worker = Some(std::thread::spawn(move || {
                worker_started_tx.send(()).unwrap();
                while !stop.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                worker_stopped_tx.send(()).unwrap();
            }));
        }
        worker_started_rx.recv().unwrap();
        assert!(app.synchronization_pause().is_ok());
        worker_stopped_rx.recv().unwrap();
        assert_eq!(
            app.synchronization
                .lock()
                .unwrap()
                .state
                .load(Ordering::Acquire),
            SYNC_IDLE
        );
        app.synchronization_paused.store(false, Ordering::Release);
        assert!(!app.synchronization_paused.load(Ordering::Acquire));

        {
            let mut runtime = app.synchronization.lock().unwrap();
            runtime.state.store(SYNC_RUNNING, Ordering::Release);
            runtime.worker = Some(std::thread::spawn(|| panic!("injected sync panic")));
        }
        assert!(matches!(
            app.stop_synchronization_worker(),
            Err(CommandError::WorkerPanicked)
        ));
        assert_eq!(
            app.synchronization
                .lock()
                .unwrap()
                .state
                .load(Ordering::Acquire),
            SYNC_ERROR
        );
        app.stop_synchronization_worker().unwrap();
        assert_eq!(
            app.synchronization
                .lock()
                .unwrap()
                .state
                .load(Ordering::Acquire),
            SYNC_IDLE
        );
    }

    #[test]
    fn regression_m4_activity_coordinator_atomically_excludes_update_races() {
        let coordinator = Arc::new(ActivityCoordinator::default());
        for kind in [
            ActivityKind::WalletLifecycle,
            ActivityKind::NodeLifecycle,
            ActivityKind::Mining,
            ActivityKind::Synchronization,
            ActivityKind::CriticalTransaction,
            ActivityKind::Backup,
            ActivityKind::Restore,
        ] {
            let active = coordinator.try_begin(kind).unwrap();
            assert!(matches!(
                coordinator.try_begin(ActivityKind::Updater),
                Err(CommandError::ActivityBusy)
            ));
            drop(active);
        }

        let update = coordinator.try_begin(ActivityKind::Updater).unwrap();
        for kind in [
            ActivityKind::WalletLifecycle,
            ActivityKind::NodeLifecycle,
            ActivityKind::Mining,
            ActivityKind::Synchronization,
            ActivityKind::CriticalTransaction,
            ActivityKind::Backup,
            ActivityKind::Restore,
            ActivityKind::Shutdown,
        ] {
            assert!(matches!(
                coordinator.try_begin(kind),
                Err(CommandError::ActivityBusy)
            ));
        }
        drop(update);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut workers = Vec::new();
        for kind in [ActivityKind::Updater, ActivityKind::CriticalTransaction] {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            let results = Arc::clone(&results);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let lease = coordinator.try_begin(kind).ok();
                let acquired = lease.is_some();
                results.lock().unwrap().push(acquired);
                barrier.wait();
                drop(lease);
            }));
        }
        barrier.wait();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            results
                .lock()
                .unwrap()
                .iter()
                .filter(|result| **result)
                .count(),
            1
        );

        let app = DesktopApplication::default();
        let update = app.activities.try_begin(ActivityKind::Updater).unwrap();
        assert!(matches!(
            app.wallet_unlock("password-1"),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.wallet_recovery_phrase_resume("password-1"),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.mining_config_set(true, 1),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.embedded_node_start_mainnet("/tmp/not-used", "127.0.0.1:3414".parse().unwrap()),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.experimental_sidecar_disable(),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.transaction_finalize(Uuid::nil()),
            Err(CommandError::ActivityBusy)
        ));
        assert!(matches!(
            app.synchronization_rescan(),
            Err(CommandError::ActivityBusy)
        ));
        drop(update);
    }

    #[test]
    fn closed_wallet_is_a_safe_update_point() {
        assert!(matches!(
            DesktopApplication::default().acquire_update_apply_lease(),
            Err(CommandError::ActivityBusy)
        ));
    }

    fn restore_node_status(
        lifecycle: WalletReadinessDto,
        local_height: u64,
        peer_height: Option<u64>,
        connected_peers: u64,
        ready: bool,
    ) -> EmbeddedNodeStatusDto {
        EmbeddedNodeStatusDto {
            lifecycle,
            network: Some("MAINNET".into()),
            chain_id: Some("11".repeat(32)),
            genesis_hash: Some("22".repeat(32)),
            canonical_tip_height: Some(local_height),
            canonical_tip_hash: Some("33".repeat(32)),
            protocol_version: Some(1),
            range_proof_version: Some(1),
            ready,
            error_code: None,
            connected_peers,
            bootstrap_phase: "CONNECTED".into(),
            highest_known_peer_height: peer_height,
            synchronization_progress_percent: None,
            status_message: "test-only".into(),
            last_successful_status_at: Some(1),
        }
    }

    #[test]
    fn seed_restore_app_gate_requires_a_confirmed_synchronized_peer_tip() {
        let discovering = restore_node_status(WalletReadinessDto::Ready, 5_241, None, 0, true);
        assert!(matches!(
            ensure_seed_restore_node_ready(&discovering),
            Err(CommandError::RestoreNodeSynchronizing)
        ));

        let behind = restore_node_status(
            WalletReadinessDto::Synchronizing,
            5_241,
            Some(8_009),
            2,
            false,
        );
        assert!(matches!(
            ensure_seed_restore_node_ready(&behind),
            Err(CommandError::RestoreNodeSynchronizing)
        ));

        let synchronized =
            restore_node_status(WalletReadinessDto::Ready, 8_009, Some(8_009), 2, true);
        assert!(ensure_seed_restore_node_ready(&synchronized).is_ok());
    }

    #[test]
    fn wallet_name_validation_fails_closed() {
        for valid in [
            "main",
            "savings-2026",
            "Leo_wallet",
            "a",
            "COM10",
            "COM",
            "LPT",
            "LPT10",
            "console",
            "aux-backup",
        ] {
            assert!(
                validate_wallet_name(valid).is_ok(),
                "expected valid: {valid:?}"
            );
        }
        let oversized = "x".repeat(65);
        for invalid in [
            "",
            ".",
            "..",
            ".hidden",
            ".main.seed-restore",
            "a/b",
            "a\\b",
            "../up",
            "..\\up",
            "name.",
            "name ",
            " name",
            "CON",
            "con",
            "Con.wallet",
            "com7",
            "LPT9",
            "lpt1.old",
            "nul",
            "a:b",
            "a*b",
            "a?b",
            "a|b",
            "a<b",
            "a>b",
            "a\"b",
            "tab\tname",
            oversized.as_str(),
        ] {
            assert!(
                matches!(
                    validate_wallet_name(invalid),
                    Err(CommandError::InvalidWalletName)
                ),
                "expected invalid: {invalid:?}"
            );
        }
    }

    #[test]
    fn wallet_directory_resolution_and_listing_use_validated_names() {
        let root = tempfile::tempdir().unwrap();
        let resolved = resolve_wallet_directory(root.path(), "primary").unwrap();
        assert_eq!(resolved, root.path().join("primary"));
        assert!(matches!(
            resolve_wallet_directory(root.path(), "../escape"),
            Err(CommandError::InvalidWalletName)
        ));

        create_catalog_wallet(root.path(), "beta");
        create_catalog_wallet(root.path(), "alpha");
        std::fs::create_dir_all(root.path().join(".alpha.seed-restore")).unwrap();
        std::fs::write(root.path().join("stray-file"), b"x").unwrap();
        assert_eq!(
            list_wallet_names(root.path()),
            vec!["alpha".to_string(), "beta".to_string()]
        );
        assert!(list_wallet_names(&root.path().join("missing")).is_empty());
    }

    fn create_catalog_wallet(root: &Path, name: &str) {
        let identity = NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [4; 32],
            genesis_id: [5; 32],
        };
        let state = dom_wallet_domain::WalletState::new(
            identity.clone(),
            [6; 32],
            dom_wallet_storage::default_node_configuration(identity),
        );
        dom_wallet_storage::WalletDirectory::create(
            root.join(name),
            &state,
            "password-1",
            dom_wallet_crypto::KdfParameters::TEST,
        )
        .unwrap();
    }

    #[test]
    fn regression_m9_catalog_lists_only_complete_structurally_valid_wallets() {
        let root = tempfile::tempdir().unwrap();
        create_catalog_wallet(root.path(), "valid");
        std::fs::create_dir(root.path().join("random")).unwrap();
        std::fs::create_dir(root.path().join(".pending.create-staging")).unwrap();
        std::fs::create_dir(root.path().join("corrupt")).unwrap();
        std::fs::write(root.path().join("corrupt").join("metadata.json"), b"{").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join("valid"), root.path().join("escape")).unwrap();

        let (valid, invalid) = inspect_wallet_catalog(root.path());
        assert_eq!(valid, vec!["valid"]);
        assert!(invalid.iter().any(|entry| entry.entry == "random"));
        assert!(invalid.iter().any(|entry| entry.entry == "corrupt"));
        assert!(invalid
            .iter()
            .any(|entry| entry.entry == ".pending.create-staging"));
        #[cfg(unix)]
        assert!(invalid.iter().any(|entry| entry.entry == "escape"));
    }

    #[test]
    fn regression_a7_managed_open_rejects_traversal_staging_symlink_and_outside_paths() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        create_catalog_wallet(root.path(), "valid");
        create_catalog_wallet(outside.path(), "outside");
        std::fs::create_dir(root.path().join(".valid.seed-restore")).unwrap();

        assert!(resolve_existing_managed_wallet(root.path(), "valid").is_ok());
        for rejected in ["../outside", ".valid.seed-restore", "missing"] {
            assert!(matches!(
                resolve_existing_managed_wallet(root.path(), rejected),
                Err(CommandError::InvalidWalletName | CommandError::ManagedWalletRejected)
            ));
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path().join("outside"), root.path().join("linked"))
                .unwrap();
            assert!(matches!(
                resolve_existing_managed_wallet(root.path(), "linked"),
                Err(CommandError::ManagedWalletRejected)
            ));
        }
    }

    #[test]
    fn incompatible_restore_staging_maps_to_guided_error() {
        let staging: CommandErrorDto =
            CommandError::from(CoreError::Restore(SeedRestoreError::IncompatibleCheckpoint)).into();
        assert_eq!(staging.code, "RESTORE_STAGING_INCOMPATIBLE");
        assert_eq!(staging.category, "STORAGE");
        assert!(!staging.retryable);
        assert!(staging.message.contains("same password"));
    }

    #[test]
    fn seed_restore_app_reports_destination_and_sync_errors_without_node_mislabeling() {
        let app = DesktopApplication::default();
        let parent = tempfile::tempdir().unwrap();
        let existing = parent.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        assert!(matches!(
            app.wallet_restore_from_mnemonic(&existing, "correct-horse", "test-only"),
            Err(CommandError::RestoreDestinationExists)
        ));

        let not_yet_created = parent.path().join("new-wallet");
        assert!(matches!(
            app.wallet_restore_from_mnemonic(&not_yet_created, "correct-horse", "test-only"),
            Err(CommandError::RestoreNodeSynchronizing)
        ));

        let destination: CommandErrorDto =
            CommandError::from(CoreError::Restore(SeedRestoreError::InvalidDestination)).into();
        assert_eq!(destination.code, "RESTORE_DESTINATION_EXISTS");
        assert_eq!(destination.category, "STORAGE");
        assert!(destination.message.contains("already exists"));
        assert!(destination.message.contains("another name"));

        let busy: CommandErrorDto =
            CommandError::from(CoreError::Restore(SeedRestoreError::CoreBusy)).into();
        assert_eq!(busy.code, "RESTORE_NODE_SYNCHRONIZING");
        assert!(busy.retryable);
    }

    #[test]
    fn transaction_commands_are_registered_locked_and_redacted() {
        let app = DesktopApplication::default();
        for command in [
            "transaction_fee_estimate",
            "transaction_send_create",
            "slate_request_export",
            "slate_request_import",
            "slate_response_create",
            "slate_response_export",
            "slate_response_import",
            "slate_summary_redacted",
            "transaction_finalize",
            "transaction_submit",
            "transaction_retry_submission",
            "transaction_cancel",
            "transaction_list",
            "transaction_detail_redacted",
        ] {
            assert!(COMMAND_NAMES.contains(&command));
        }
        let error = app.transaction_send_create(42, None, 100).unwrap_err();
        assert!(matches!(
            &error,
            CommandError::Wallet {
                code: "WALLET_LOCKED",
                ..
            }
        ));
        assert!(app.slate_request_import("invalid=not-a-slate").is_err());
        assert!(!format!("{error:?}").contains("password"));
    }

    fn test_qr_frames(text: &str, response: bool) -> Vec<String> {
        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash[..16]);
        let chunks = text.as_bytes().chunks(7).collect::<Vec<_>>();
        chunks
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                encode_slate_qr_frame(&SlateQrFrameV1 {
                    version: 1,
                    message_id: Uuid::from_bytes(id),
                    response,
                    part_index: index as u16,
                    part_count: chunks.len() as u16,
                    total_length: text.len() as u32,
                    content_sha256: hash,
                    payload: payload.to_vec(),
                })
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn regression_m8_qr_multipart_bounds_order_duplicates_conflicts_roles_and_replay() {
        let text = format!("DOMSLATE4.{}", "a".repeat(40));
        let frames = test_qr_frames(&text, false);
        assert!(frames.len() > 2);
        let app = DesktopApplication::default();

        let first = app.slate_qr_decode_frame(&frames[1]).unwrap();
        assert_eq!(first.received_frames, 1);
        assert!(first.complete_text.is_none());
        let duplicate = app.slate_qr_decode_frame(&frames[1]).unwrap();
        assert_eq!(duplicate.received_frames, 1);

        let duplicate_conflict_app = DesktopApplication::default();
        duplicate_conflict_app
            .slate_qr_decode_frame(&frames[0])
            .unwrap();
        let mut duplicate_conflict = parse_slate_qr_frame(&frames[0]).unwrap();
        duplicate_conflict.payload[0] ^= 1;
        assert!(duplicate_conflict_app
            .slate_qr_decode_frame(&encode_slate_qr_frame(&duplicate_conflict).unwrap())
            .is_err());

        let mut conflicting = parse_slate_qr_frame(&frames[0]).unwrap();
        conflicting.response = true;
        assert!(app
            .slate_qr_decode_frame(&encode_slate_qr_frame(&conflicting).unwrap())
            .is_err());

        let mut completed = None;
        for frame in frames.iter().rev() {
            if frame == &frames[1] {
                continue;
            }
            completed = app
                .slate_qr_decode_frame(frame)
                .unwrap()
                .complete_text
                .or(completed);
        }
        assert_eq!(completed.as_deref(), Some(text.as_str()));
        assert!(app.slate_qr_decode_frame(&frames[0]).is_err());

        let missing_app = DesktopApplication::default();
        for (index, frame) in frames.iter().enumerate() {
            if index != 2 {
                missing_app.slate_qr_decode_frame(frame).unwrap();
            }
        }
        let missing = missing_app.slate_qr_reassembly_status().unwrap();
        assert_eq!(usize::from(missing.received_frames), frames.len() - 1);
        assert!(missing.complete_text.is_none());

        let bad_hash_app = DesktopApplication::default();
        let bad_hash_frames = frames
            .iter()
            .map(|frame| {
                let mut frame = parse_slate_qr_frame(frame).unwrap();
                frame.content_sha256 = [9; 32];
                encode_slate_qr_frame(&frame).unwrap()
            })
            .collect::<Vec<_>>();
        for frame in &bad_hash_frames[..bad_hash_frames.len() - 1] {
            bad_hash_app.slate_qr_decode_frame(frame).unwrap();
        }
        assert!(bad_hash_app
            .slate_qr_decode_frame(bad_hash_frames.last().unwrap())
            .is_err());

        let mut oversized = parse_slate_qr_frame(&frames[0]).unwrap();
        oversized.total_length = (MAX_SLATE_QR_TEXT_BYTES as u32) + 1;
        assert!(encode_slate_qr_frame(&oversized).is_err());

        let mut too_many_parts = parse_slate_qr_frame(&frames[0]).unwrap();
        too_many_parts.part_count = (MAX_SLATE_QR_FRAMES + 1) as u16;
        assert!(encode_slate_qr_frame(&too_many_parts).is_err());

        app.slate_qr_reassembly_clear().unwrap();
        let cleared = app.slate_qr_reassembly_status().unwrap();
        assert_eq!(cleared.received_frames, 0);
        assert!(cleared.complete_text.is_none());
    }

    #[test]
    #[ignore = "live packaged-equivalent Mainnet acceptance gate"]
    fn live_mainnet_genesis_wallet_syncs_at_zero_without_mining() {
        let node_directory = tempfile::tempdir().expect("temporary node directory");
        let wallet_directory = tempfile::tempdir().expect("temporary wallet parent");
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral embedded-node listener");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        let app = DesktopApplication::default();
        let node = app
            .embedded_node_start_mainnet(node_directory.path(), address)
            .expect("Mainnet node starts");
        assert_eq!(node.network.as_deref(), Some("MAINNET"));
        assert_eq!(node.canonical_tip_height, Some(0));
        let destination = wallet_directory.path().join("wallet");
        let created = app
            .wallet_create_recoverable(&destination, "correct-horse-battery")
            .expect("Mainnet wallet created");
        assert_eq!(created.wallet.network, Network::Mainnet);
        app.wallet_recovery_phrase_confirm("correct-horse-battery")
            .expect("phrase confirmation");
        app.wallet_unlock("correct-horse-battery")
            .expect("wallet unlock");
        let node = app.embedded_node_status().expect("live node status");
        assert_eq!(node.canonical_tip_height, Some(0));
        assert!(!node.ready);
        assert!(app.node_started.load(Ordering::Acquire));
        assert!(
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1),)
                .is_ok()
        );
        if node.connected_peers == 0 {
            assert_eq!(node.lifecycle, WalletReadinessDto::WaitingForPeers);
            assert_eq!(node.highest_known_peer_height, None);
        } else {
            assert_eq!(node.lifecycle, WalletReadinessDto::Synchronizing);
            assert!(node
                .highest_known_peer_height
                .is_some_and(|height| height > 0));
        }
        let mining = app.mining_status().expect("mining status");
        assert_eq!(mining.status, "DISABLED");
        assert!(!mining.running);
        assert_eq!(mining.hash_attempts, 0);
        app.mining_config_set(true, 1)
            .expect("enable mining controls");
        assert!(matches!(
            app.mining_start(true),
            Err(CommandError::CursorInitializationFailed
                | CommandError::NoPeers
                | CommandError::NodeNotReady)
        ));
        app.application_shutdown().expect("shutdown");
    }
}
