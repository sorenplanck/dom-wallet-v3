#![forbid(unsafe_code)]

//! Tauri-ready command boundary.
//!
//! The commands are framework-neutral Rust functions so they can be tested in
//! a headless environment. A production Tauri `invoke_handler` binds these
//! names without moving domain, storage, cryptographic, or sync logic here.

use dom_wallet_core::{
    BackupStatus, CoreError, DiagnosticSnapshot, FeeEstimate, RecoveryCreateResult,
    RecoveryRestoreResult, SlateExport, TransactionSummary, WalletService, WalletSummary,
};
use dom_wallet_core_api::CoreNetwork;
use dom_wallet_domain::{BalanceProjection, Network, NetworkIdentity};
use dom_wallet_embedded_core::{
    mine_wallet_block, EmbeddedCoreConfiguration, WalletMiningOutcome, MAINNET_BOOTSTRAP_FALLBACK,
    MAINNET_BOOTSTRAP_PEERS, MAINNET_DNS_SEEDS,
};
use dom_wallet_node_manager::{
    ManagedNodeConfig, NodeManager, NodeReleaseMetadata, SidecarStatus,
    EXPERIMENTAL_ENABLE_CONFIRMATION,
};
use dom_wallet_updater::{
    NodeUpdaterState, WalletUpdaterState, EMBEDDED_NODE_REVISION, UPDATE_CHANNEL,
    UPDATE_INTERVAL_SECONDS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::{net::SocketAddr, path::Path, thread::JoinHandle};
use thiserror::Error;

pub struct DesktopApplication {
    service: Arc<Mutex<WalletService>>,
    qr_reassembler: Mutex<Option<String>>,
    node_started: AtomicBool,
    last_peer_connected_unix_seconds: AtomicU64,
    synchronization_paused: AtomicBool,
    mining: Mutex<MiningRuntime>,
    sidecar: Mutex<NodeManager>,
    shutdown: AtomicBool,
}

pub const COMMAND_NAMES: [&str; 67] = [
    "native_bridge_status",
    "get_build_info",
    "update_status",
    "check_updates_now",
    "check_node_now",
    "application_status",
    "wallet_create_recoverable",
    "wallet_restore_from_mnemonic",
    "wallet_backup_export",
    "wallet_backup_import",
    "wallet_recovery_phrase_confirm",
    "wallet_open",
    "wallet_unlock",
    "wallet_lock",
    "wallet_close",
    "wallet_summary",
    "account_list",
    "account_summary",
    "embedded_node_start",
    "embedded_node_stop",
    "embedded_node_status",
    "experimental_sidecar_status",
    "experimental_sidecar_enable",
    "experimental_sidecar_disable",
    "experimental_sidecar_start",
    "experimental_sidecar_stop",
    "experimental_sidecar_evaluate_release",
    "node_network_status",
    "node_peer_status",
    "wallet_sync_status",
    "wallet_sync_start",
    "wallet_sync_pause",
    "wallet_sync_resume",
    "wallet_rescan",
    "wallet_sync_retry",
    "mining_status",
    "mining_config_get",
    "mining_config_set",
    "mining_start",
    "mining_stop",
    "synchronization_start",
    "synchronization_pause",
    "synchronization_resume",
    "synchronization_retry",
    "synchronization_rescan",
    "diagnostics_redacted",
    "application_shutdown",
    "transaction_fee_estimate",
    "wallet_address_validate",
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
    "transaction_reconcile_submission",
    "transaction_cancel",
    "transaction_list",
    "transaction_detail_redacted",
    "slate_qr_encode",
    "slate_qr_decode_frame",
    "slate_qr_reassembly_status",
    "slate_qr_reassembly_clear",
];

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
    pub node: NodeUpdaterStatusDto,
    pub peers: PeerUpdaterStatusDto,
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

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeUpdaterStatusDto {
    pub active_version: &'static str,
    pub active_revision: &'static str,
    pub previous_version: Option<String>,
    pub previous_revision: Option<String>,
    pub available_version: Option<String>,
    pub available_revision: Option<String>,
    pub compatibility: String,
    pub state: NodeUpdaterState,
    pub last_check_unix_seconds: Option<u64>,
    pub progress_percent: Option<u8>,
    pub sanitized_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerUpdaterStatusDto {
    pub state: String,
    pub sequence: u64,
    pub last_check_unix_seconds: Option<u64>,
    pub active_peers: Vec<String>,
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
                node: NodeUpdaterStatusDto {
                    active_version: build.embedded_node_version,
                    active_revision: build.embedded_node_revision,
                    previous_version: None,
                    previous_revision: None,
                    available_version: None,
                    available_revision: None,
                    compatibility: "RPC_BUILD_INFO_PENDING".into(),
                    state: NodeUpdaterState::Idle,
                    last_check_unix_seconds: None,
                    progress_percent: None,
                    sanitized_error: None,
                },
                peers: PeerUpdaterStatusDto {
                    state: "IDLE".into(),
                    sequence: 0,
                    last_check_unix_seconds: None,
                    active_peers: MAINNET_BOOTSTRAP_PEERS
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
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
                node: NodeUpdaterStatusDto {
                    active_version: "UNAVAILABLE",
                    active_revision: "UNAVAILABLE",
                    previous_version: None,
                    previous_revision: None,
                    available_version: None,
                    available_revision: None,
                    compatibility: "UNKNOWN".into(),
                    state: NodeUpdaterState::Failed,
                    last_check_unix_seconds: None,
                    progress_percent: None,
                    sanitized_error: Some("UPDATE_STATE_UNAVAILABLE".into()),
                },
                peers: PeerUpdaterStatusDto {
                    state: "FAILED".into(),
                    sequence: 0,
                    last_check_unix_seconds: None,
                    active_peers: Vec::new(),
                    sanitized_error: Some("UPDATE_STATE_UNAVAILABLE".into()),
                },
            })
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
            status.node.state = NodeUpdaterState::Checking;
            status.peers.state = "CHECKING".into();
            status.wallet.last_check_unix_seconds = Some(now);
            status.wallet.next_check_unix_seconds = Some(now + UPDATE_INTERVAL_SECONDS);
            status.node.last_check_unix_seconds = Some(now);
            status.peers.last_check_unix_seconds = Some(now);
            status.wallet.sanitized_error = None;
            status.node.sanitized_error = None;
            status.peers.sanitized_error = None;
        }
        true
    }

    pub fn finish_check_without_key(&self) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = WalletUpdaterState::Failed;
            status.wallet.sanitized_error = Some("UPDATE_SIGNATURE_KEY_UNAVAILABLE".into());
            status.node.state = NodeUpdaterState::Failed;
            status.node.sanitized_error = Some("UPDATE_SIGNATURE_KEY_UNAVAILABLE".into());
            status.peers.state = "FAILED".into();
            status.peers.sanitized_error = Some("PEER_SIGNATURE_KEY_UNAVAILABLE".into());
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
            status.node.state = NodeUpdaterState::Failed;
            status.node.sanitized_error = Some("NODE_RPC_BUILD_INFO_PENDING".into());
            status.peers.state = "FALLBACK_ACTIVE".into();
            status.peers.sanitized_error = Some("PEER_MANIFEST_NOT_ACTIVATED".into());
        }
        self.check_in_progress.store(false, Ordering::Release);
    }

    pub fn set_wallet_download_state(&self, state: WalletUpdaterState, progress: Option<u8>) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = state;
            status.wallet.progress_percent = progress;
        }
    }

    pub fn fail_wallet_check(&self, error: &'static str) {
        if let Ok(mut status) = self.status.lock() {
            status.wallet.state = WalletUpdaterState::Failed;
            status.wallet.sanitized_error = Some(error.into());
            status.node.state = NodeUpdaterState::Failed;
            status.node.sanitized_error = Some("NODE_RPC_BUILD_INFO_PENDING".into());
            status.peers.state = "FALLBACK_ACTIVE".into();
            status.peers.sanitized_error = Some("PEER_MANIFEST_NOT_ACTIVATED".into());
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
}

pub fn native_bridge_status() -> NativeBridgeStatusDto {
    NativeBridgeStatusDto {
        bridge: "ready",
        app_version: env!("CARGO_PKG_VERSION"),
    }
}

impl Default for DesktopApplication {
    fn default() -> Self {
        Self {
            service: Arc::new(Mutex::new(WalletService::default())),
            qr_reassembler: Mutex::new(None),
            node_started: AtomicBool::new(false),
            last_peer_connected_unix_seconds: AtomicU64::new(0),
            synchronization_paused: AtomicBool::new(false),
            mining: Mutex::new(MiningRuntime::default()),
            sidecar: Mutex::new(NodeManager::default()),
            shutdown: AtomicBool::new(false),
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
    Synchronizing,
    Ready,
    NotReady,
    Failed,
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
    error_code: Arc<Mutex<Option<String>>>,
    worker: Option<JoinHandle<()>>,
}

impl Default for MiningRuntime {
    fn default() -> Self {
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
            error_code: Arc::new(Mutex::new(None)),
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCreateDto {
    pub wallet: WalletSummary,
    pub mnemonic: String,
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
    pub complete_text: Option<String>,
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
        let mut manager = self.sidecar.lock().map_err(|_| CommandError::Unavailable)?;
        manager
            .start_active(configuration)
            .map_err(|_| CommandError::NodeNotReady)?;
        Ok(manager.status())
    }

    pub fn experimental_sidecar_stop(&self) -> Result<SidecarStatus, CommandError> {
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
        let service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let transactions = match service.transaction_list() {
            Ok(transactions) => transactions,
            Err(CoreError::WalletNotOpen) | Err(CoreError::Locked) => return Ok(true),
            Err(error) => return Err(CommandError::from(error)),
        };
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
        Ok(!transactions
            .iter()
            .any(|transaction| CRITICAL_STATES.contains(&transaction.state.as_str())))
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
                state: "ERROR".into(),
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
        checked_password(password)?;
        let result: RecoveryCreateResult = self
            .service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .create_recoverable_for_embedded(path, password)
            .map_err(CommandError::from)?;
        Ok(RecoveryCreateDto {
            wallet: result.wallet,
            mnemonic: result.mnemonic.to_string(),
        })
    }

    pub fn wallet_restore_from_mnemonic(
        &self,
        path: impl AsRef<Path>,
        password: &str,
        mnemonic: &str,
    ) -> Result<RecoveryResultDto, CommandError> {
        self.ensure_running()?;
        checked_password(password)?;
        if mnemonic.len() > 4096 {
            return Err(CommandError::InvalidInput(
                "recovery phrase is invalid".into(),
            ));
        }
        let result: RecoveryRestoreResult = self
            .service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        checked_password(backup_password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        checked_password(backup_password)?;
        checked_password(password)?;
        let mut service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
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
        checked_password(password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .recovery_phrase_confirmed(password)
            .map_err(CommandError::from)
    }

    pub fn wallet_open(&self, path: impl AsRef<Path>) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .open(path)
            .map_err(CommandError::from)
    }

    pub fn wallet_unlock(&self, password: &str) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        checked_password(password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .unlock(password)
            .map_err(CommandError::from)
    }

    pub fn wallet_lock(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        self.stop_mining_worker()?;
        self.clear_qr_buffers()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .lock()
            .map_err(CommandError::from)
    }
    pub fn wallet_close(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        self.stop_mining_worker()?;
        self.clear_qr_buffers()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .close()
            .map_err(CommandError::from)?;
        self.node_started.store(false, Ordering::Release);
        Ok(())
    }
    pub fn wallet_summary(&self) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .summary()
            .map_err(CommandError::from)
    }
    pub fn account_list(&self) -> Result<Vec<(uuid::Uuid, String)>, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .accounts()
            .map_err(CommandError::from)
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
        if self.node_started.load(Ordering::Acquire) {
            return self.embedded_node_status();
        }
        if !listen_address.ip().is_loopback() || listen_address.port() == 0 {
            return Err(CommandError::InvalidInput(
                "automatic local node listener is invalid".into(),
            ));
        }
        let configuration =
            EmbeddedCoreConfiguration::mainnet(data_directory.as_ref(), listen_address);
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .start_embedded_core(configuration)
            .map_err(CommandError::from)?;
        self.node_started.store(true, Ordering::Release);
        self.embedded_node_status()
    }

    pub fn embedded_node_status(&self) -> Result<EmbeddedNodeStatusDto, CommandError> {
        if !self.node_started.load(Ordering::Acquire) {
            return Ok(stopped_node_status());
        }
        let service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let identity = service
            .embedded_core_identity()
            .map_err(CommandError::from)?;
        let ready = service.embedded_core_ready().unwrap_or(false);
        let diagnostic = service.diagnostics();
        let peers = service.embedded_peer_status().map_err(CommandError::from)?;
        let synchronization = node_synchronization_status(
            identity.current_tip.height,
            peers.highest_known_peer_height,
            peers.connected_total,
            ready,
        );
        let expected_initial_sync = synchronization.lifecycle == WalletReadinessDto::Synchronizing;
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
            error_code: (!ready && !expected_initial_sync)
                .then(|| diagnostic.last_error.map(|_| "CORE_NOT_READY".into()))
                .flatten(),
            connected_peers: peers.connected_total,
            bootstrap_phase: peers.bootstrap_phase.into(),
            highest_known_peer_height: synchronization.highest_known_peer_height,
            synchronization_progress_percent: synchronization.progress_percent,
            status_message: synchronization.message,
        })
    }

    pub fn embedded_node_stop(&self) -> Result<EmbeddedNodeStatusDto, CommandError> {
        self.ensure_running()?;
        self.stop_mining_worker()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
            bootstrap_fallback: MAINNET_BOOTSTRAP_FALLBACK.into(),
        })
    }

    pub fn node_peer_status(&self) -> Result<NodePeerStatusDto, CommandError> {
        let service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
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
        let service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let diagnostic = service.diagnostics();
        let canonical_height = service
            .embedded_core_identity()
            .ok()
            .map(|identity| identity.current_tip.height);
        let canonical_hash = service
            .embedded_core_identity()
            .ok()
            .map(|identity| hex::encode(identity.current_tip.hash));
        let synchronized = diagnostic.cursor_height.is_some()
            && diagnostic.cursor_height == canonical_height
            && diagnostic.cursor_hash.is_some()
            && diagnostic.cursor_hash == canonical_hash
            && diagnostic.last_error.is_none();
        Ok(WalletSyncStatusDto {
            state: diagnostic.application_state,
            cursor_height: diagnostic.cursor_height,
            cursor_hash: diagnostic.cursor_hash,
            canonical_height,
            canonical_hash,
            synchronized,
            paused: self.synchronization_paused.load(Ordering::Acquire),
            last_result: if synchronized {
                "SUCCESS"
            } else {
                "NOT_SYNCHRONIZED"
            }
            .into(),
            last_error: diagnostic.last_error,
        })
    }

    pub fn mining_config_get(&self) -> Result<MiningConfigDto, CommandError> {
        let service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let preferences = service.mining_preferences().map_err(CommandError::from)?;
        let available = available_logical_cpus();
        let recommended = (available / 2).max(1);
        Ok(MiningConfigDto {
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
        })
    }

    pub fn mining_config_set(
        &self,
        enabled: bool,
        cpu_threads: usize,
    ) -> Result<MiningConfigDto, CommandError> {
        let state = self
            .mining
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .state
            .load(Ordering::Acquire);
        if matches!(state, MINING_STARTING | MINING_RUNNING | MINING_STOPPING) {
            return Err(CommandError::MiningRunning);
        }
        let available = available_logical_cpus();
        if cpu_threads == 0 || cpu_threads > available {
            return Err(CommandError::InvalidInput(
                "CPU thread count is invalid".into(),
            ));
        }
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        let peer_status = self
            .service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .embedded_peer_status()
            .map_err(CommandError::from)?;
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
            current_height: peer_status.canonical_height,
            connected_peers: peer_status.connected_total,
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
        let service = Arc::clone(&self.service);
        let node = service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .embedded_node_handle()
            .map_err(CommandError::from)?;
        if node.metrics.peer_count.load(Ordering::Acquire) == 0
            || node.metrics.ibd_progress_percent.load(Ordering::Acquire) < 100
        {
            return Err(CommandError::NodeNotReady);
        }
        let mut mining = self.mining.lock().map_err(|_| CommandError::Unavailable)?;
        if mining.worker.is_some()
            || matches!(
                mining.state.load(Ordering::Acquire),
                MINING_STARTING | MINING_RUNNING | MINING_STOPPING
            )
        {
            return Err(CommandError::MiningRunning);
        }
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
        mining.worker = Some(
            std::thread::Builder::new()
                .name("dom-wallet-cpu-miner".into())
                .spawn(move || {
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
                    node.metrics.mining_active.store(0, Ordering::Release);
                    if state.load(Ordering::Acquire) != MINING_ERROR {
                        state.store(MINING_READY, Ordering::Release);
                    }
                })
                .map_err(|_| CommandError::Unavailable)?,
        );
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
            worker.join().map_err(|_| CommandError::Unavailable)?;
        }
        Ok(())
    }
    pub fn diagnostics_redacted(&self) -> DiagnosticSnapshot {
        match self.service.lock() {
            Ok(service) => service.diagnostics(),
            Err(_) => DiagnosticSnapshot {
                application_state: "ERROR".into(),
                connection_state: "UNAVAILABLE".into(),
                generation: None,
                cursor_height: None,
                cursor_hash: None,
                last_error: Some("APPLICATION_STATE_UNAVAILABLE".into()),
            },
        }
    }
    pub fn application_shutdown(&self) -> Result<(), CommandError> {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = (|| {
            self.stop_mining_worker()?;
            self.sidecar
                .lock()
                .map_err(|_| CommandError::Unavailable)?
                .shutdown()
                .map_err(|_| CommandError::Unavailable)?;
            self.clear_qr_buffers()?;
            let mut service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
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
        Ok(())
    }
    pub fn synchronization_resume_live(&self) -> Result<WalletSummary, CommandError> {
        self.synchronization_paused.store(false, Ordering::Release);
        self.synchronization_start_live()
    }
    pub fn synchronization_rescan(&self) -> Result<WalletSummary, CommandError> {
        self.synchronization_paused.store(false, Ordering::Release);
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .rescan_from_genesis()
            .map_err(CommandError::from)
    }

    pub fn synchronization_start_live(&self) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        if self.synchronization_paused.load(Ordering::Acquire) {
            return Err(CommandError::SynchronizationPaused);
        }
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .synchronize_live()
            .map_err(CommandError::from)
    }

    pub fn transaction_fee_estimate(
        &self,
        amount: u64,
        selected_input_count: u32,
        change_output: bool,
    ) -> Result<FeeEstimate, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        if amount == 0 {
            return Err(CommandError::InvalidInput("amount must be positive".into()));
        }
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_send_create(amount, requested_fee, expires_at_height)
            .map_err(CommandError::from)
    }

    pub fn wallet_address_validate(&self, address: &str) -> Result<String, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .validate_wallet_address(address)
            .map_err(CommandError::from)
    }

    pub fn slate_request_export(&self, slate_id: uuid::Uuid) -> Result<SlateExport, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        let content_hash = Sha256::digest(exported.text.as_bytes());
        Ok(SlateQrExportDto {
            frames: vec![format!("DOMQR4.{}", exported.text)],
            multipart: false,
            content_hash: hex::encode(content_hash),
        })
    }

    /// Reassembles public QR transport frames only. A completed text envelope
    /// must still pass the normal role-bound core import path.
    pub fn slate_qr_decode_frame(&self, frame: &str) -> Result<SlateQrReassemblyDto, CommandError> {
        self.ensure_running()?;
        if frame.is_empty() || frame.len() > 2_097_280 || !frame.is_ascii() {
            return Err(CommandError::InvalidInput("QR frame is invalid".into()));
        }
        let text = frame
            .strip_prefix("DOMQR4.")
            .ok_or_else(|| CommandError::InvalidInput("QR frame is invalid".into()))?;
        checked_slate_text(text)?;
        *self
            .qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)? = Some(text.to_owned());
        Ok(SlateQrReassemblyDto {
            message_id: Some(hex::encode(Sha256::digest(text.as_bytes()))),
            received_frames: 1,
            total_frames: 1,
            complete_text: Some(text.to_owned()),
        })
    }

    pub fn slate_qr_reassembly_status(&self) -> Result<SlateQrReassemblyDto, CommandError> {
        let text = self
            .qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .clone();
        Ok(SlateQrReassemblyDto {
            message_id: text
                .as_ref()
                .map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            received_frames: u16::from(text.is_some()),
            total_frames: u16::from(text.is_some()),
            complete_text: text,
        })
    }

    pub fn slate_qr_reassembly_clear(&self) -> Result<(), CommandError> {
        self.clear_qr_buffers()
    }

    pub fn slate_request_import(&self, text: &str) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        checked_slate_text(text)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .slate_request_import(text)
            .map_err(CommandError::from)
    }

    pub fn slate_response_create(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .slate_response_create(slate_id)
            .map_err(CommandError::from)
    }

    pub fn slate_response_export(&self, slate_id: uuid::Uuid) -> Result<SlateExport, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .slate_response_export(slate_id)
            .map_err(CommandError::from)
    }

    pub fn slate_response_import(&self, text: &str) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        checked_slate_text(text)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .slate_response_import(text)
            .map_err(CommandError::from)
    }

    pub fn slate_summary_redacted(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_detail_redacted(slate_id)
            .map_err(CommandError::from)
    }

    pub fn transaction_finalize(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_finalize(slate_id)
            .map_err(CommandError::from)
    }

    pub fn transaction_submit(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_submit(slate_id)
            .map(submission_result)
            .map_err(CommandError::from)
    }

    pub fn transaction_retry_submission(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_retry_submission(slate_id)
            .map(submission_result)
            .map_err(CommandError::from)
    }

    pub fn transaction_reconcile_submission(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<SubmissionResultDto, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
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
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_cancel(slate_id, confirm_exported)
            .map_err(CommandError::from)
    }

    pub fn transaction_list(&self) -> Result<Vec<TransactionSummary>, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_list()
            .map_err(CommandError::from)
    }

    fn ensure_running(&self) -> Result<(), CommandError> {
        if self.shutdown.load(Ordering::Acquire) {
            Err(CommandError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn clear_qr_buffers(&self) -> Result<(), CommandError> {
        self.qr_reassembler
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .take();
        Ok(())
    }
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
    }
}

#[derive(Debug, Eq, PartialEq)]
struct NodeSynchronizationStatus {
    lifecycle: WalletReadinessDto,
    highest_known_peer_height: Option<u64>,
    progress_percent: Option<u64>,
    message: String,
}

fn node_synchronization_status(
    local_height: u64,
    peer_height: u64,
    connected_peers: u64,
    ready: bool,
) -> NodeSynchronizationStatus {
    let observed_peer_height = (connected_peers > 0).then_some(peer_height);
    if connected_peers > 0 && peer_height > local_height {
        let progress_percent = ((u128::from(local_height) * 100) / u128::from(peer_height)) as u64;
        return NodeSynchronizationStatus {
            lifecycle: WalletReadinessDto::Synchronizing,
            highest_known_peer_height: observed_peer_height,
            progress_percent: Some(progress_percent),
            message: format!("Synchronizing {local_height} / {peer_height} ({progress_percent}%)"),
        };
    }
    if ready {
        return NodeSynchronizationStatus {
            lifecycle: WalletReadinessDto::Ready,
            highest_known_peer_height: observed_peer_height,
            progress_percent: observed_peer_height.map(|_| 100),
            message: format!("Ready at height {local_height}"),
        };
    }
    let message = if connected_peers > 0 {
        format!("Connected; waiting for synchronization status at height {local_height}")
    } else {
        "Discovering peers".into()
    };
    NodeSynchronizationStatus {
        lifecycle: WalletReadinessDto::Starting,
        highest_known_peer_height: observed_peer_height,
        progress_percent: None,
        message,
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
            CommandError::Wallet {
                code,
                message,
                retryable,
            } => Self {
                code: code.into(),
                category: "WALLET".into(),
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
            CoreError::Backend(_) => Self::Wallet {
                code: "EMBEDDED_NODE_OPERATION_FAILED",
                message: "The embedded Mainnet node could not complete the requested operation.",
                retryable: true,
            },
            other => {
                let code = other.redacted_code();
                let (message, retryable) = if code == "WALLET_WRITER_ACTIVE" {
                    (
                        "Close the other running wallet process before opening this wallet.",
                        true,
                    )
                } else {
                    (
                        "The wallet rejected the requested operation. Review its typed error code.",
                        false,
                    )
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
        assert_eq!(status.app_version, "0.2.2");
        fn assert_serializable<T: serde::Serialize>(_: &T) {}
        assert_serializable(&status);
    }

    #[test]
    fn build_and_update_status_are_separate_redacted_channels() {
        let build = get_build_info();
        assert_eq!(build.wallet_version, "0.2.2");
        assert_eq!(build.embedded_node_revision, EMBEDDED_NODE_REVISION);
        assert_eq!(build.update_channel, "stable");

        let updates = UpdateControl::new(false);
        assert!(updates.begin_check(100));
        assert!(!updates.begin_check(100));
        updates.finish_check_without_key();
        let status = updates.snapshot();
        assert_eq!(status.wallet.state, WalletUpdaterState::Failed);
        assert_eq!(status.node.state, NodeUpdaterState::Failed);
        assert_eq!(status.peers.state, "FAILED");
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
    fn closed_wallet_is_a_safe_update_point() {
        assert!(DesktopApplication::default()
            .update_safe_point_available()
            .expect("closed Wallet is safe"));
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
            app.wallet_open("/tmp/not-used"),
            Err(CommandError::Unavailable)
        ));
        assert!(!format!("{:?}", app.diagnostics_redacted()).contains("password"));
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

        assert_eq!(app.application_status().state, "ERROR");
        let diagnostic = app.diagnostics_redacted();
        assert_eq!(diagnostic.application_state, "ERROR");
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
        let status = node_synchronization_status(1_008, 6_622, 1, false);

        assert_eq!(status.lifecycle, WalletReadinessDto::Synchronizing);
        assert_eq!(status.highest_known_peer_height, Some(6_622));
        assert_eq!(status.progress_percent, Some(15));
        assert_eq!(status.message, "Synchronizing 1008 / 6622 (15%)");
    }

    #[test]
    fn node_status_never_claims_ready_while_peer_tip_is_ahead() {
        let status = node_synchronization_status(50, 100, 1, true);

        assert_eq!(status.lifecycle, WalletReadinessDto::Synchronizing);
        assert_eq!(status.progress_percent, Some(50));
    }

    #[test]
    fn node_status_is_readable_while_discovering_peers() {
        let status = node_synchronization_status(0, 0, 0, false);

        assert_eq!(status.lifecycle, WalletReadinessDto::Starting);
        assert_eq!(status.highest_known_peer_height, None);
        assert_eq!(status.progress_percent, None);
        assert_eq!(status.message, "Discovering peers");
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
        assert_eq!(error.to_string(), "embedded node is not ready");
        assert!(app.slate_request_import("invalid=not-a-slate").is_err());
        assert!(!format!("{error:?}").contains("password"));
    }

    #[test]
    #[ignore = "live packaged-equivalent Mainnet acceptance gate"]
    fn live_mainnet_genesis_wallet_syncs_at_zero_without_mining() {
        let node_directory = tempfile::tempdir().expect("temporary node directory");
        let wallet_directory = tempfile::tempdir().expect("temporary wallet parent");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
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
        let synchronized = app.synchronization_start_live().unwrap_or_else(|error| {
            panic!(
                "genesis-only synchronization: {error:?}; diagnostics={:?}",
                app.diagnostics_redacted()
            )
        });
        assert_eq!(synchronized.cursor_height, Some(0));
        let status = app.wallet_sync_status().expect("sync status");
        assert!(status.synchronized);
        assert_eq!(status.canonical_height, Some(0));
        assert_eq!(status.cursor_height, Some(0));
        let mining = app.mining_status().expect("mining status");
        assert_eq!(mining.status, "DISABLED");
        assert!(!mining.running);
        assert_eq!(mining.hash_attempts, 0);
        app.application_shutdown().expect("shutdown");
    }
}
