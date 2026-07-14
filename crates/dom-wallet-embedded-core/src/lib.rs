//! Wallet-owned lifecycle boundary for the embedded DOM node.

#![forbid(unsafe_code)]

use dom_config::{Network, NodeConfig};
use dom_node::{node::DomNode, wallet_core_api::EmbeddedWalletCoreApi};
use dom_wallet_core_api::{
    BlockSelector, BlockSummary, ChainIdentity, CursorValidation, FeeBreakdown, FeeEstimate,
    FeeEstimateRequest, FeePolicySnapshot, FeeValidation, KernelQueryResult, MempoolPolicySnapshot,
    ScanRequest, ScanResult, SubmissionResult, SubmitTransactionRequest, SyncStatus,
    TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use std::{
    fmt,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STATE_UNINITIALIZED: u8 = 0;
const STATE_STARTING: u8 = 1;
const STATE_RUNNING: u8 = 2;
const STATE_STOPPING: u8 = 3;
const STATE_STOPPED: u8 = 4;
const STATE_FAILED: u8 = 5;

/// Network selected for the embedded node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedCoreNetwork {
    /// Production network.
    Mainnet,
    /// Public test network.
    Testnet,
    /// Isolated development network.
    Regtest,
}

impl EmbeddedCoreNetwork {
    fn node_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }
}

/// Validated Wallet-side configuration for the embedded node boundary.
#[derive(Clone)]
pub struct EmbeddedCoreConfiguration {
    network: EmbeddedCoreNetwork,
    data_directory: PathBuf,
    p2p_listen_address: SocketAddr,
    maximum_inbound_peers: usize,
    seed_peers: Vec<SocketAddr>,
}

impl EmbeddedCoreConfiguration {
    /// Create a configuration. Validation occurs before node initialization.
    pub fn new(
        network: EmbeddedCoreNetwork,
        data_directory: impl Into<PathBuf>,
        p2p_listen_address: SocketAddr,
    ) -> Self {
        Self {
            network,
            data_directory: data_directory.into(),
            p2p_listen_address,
            maximum_inbound_peers: 32,
            seed_peers: Vec::new(),
        }
    }

    /// Set the maximum inbound peer count.
    pub fn with_maximum_inbound_peers(mut self, maximum: usize) -> Self {
        self.maximum_inbound_peers = maximum;
        self
    }

    /// Set explicit bootstrap peers. DNS discovery remains disabled.
    pub fn with_seed_peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.seed_peers = peers;
        self
    }

    fn validate(&self) -> Result<(), EmbeddedCoreAdapterError> {
        if self.data_directory.as_os_str().is_empty() {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "EMPTY_DATA_DIRECTORY",
            });
        }
        if self.p2p_listen_address.port() == 0 {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_P2P_PORT",
            });
        }
        if self.maximum_inbound_peers == 0 {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_INBOUND_LIMIT",
            });
        }
        Ok(())
    }

    fn node_config(&self) -> NodeConfig {
        let mut config = match self.network.node_network() {
            Network::Mainnet => NodeConfig::mainnet(),
            Network::Testnet => NodeConfig::testnet(),
            Network::Regtest => NodeConfig::regtest(),
        };
        config.data_dir = self.data_directory.to_string_lossy().into_owned();
        config.p2p_listen_addr = self.p2p_listen_address.to_string();
        config.max_inbound = self.maximum_inbound_peers;
        config.min_outbound = 0;
        config.dns_seeds.clear();
        config.disable_dns_seeds = true;
        config.seed_peers = self.seed_peers.iter().map(ToString::to_string).collect();
        config.mine = false;
        config.miner_address = None;
        config.wallet_path = None;
        config.wallet_password = None;
        config.rpc_listen_addr = None;
        config.rpc_bearer_token = None;
        config.metrics_listen_addr = None;
        config
    }
}

impl fmt::Debug for EmbeddedCoreConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedCoreConfiguration")
            .field("network", &self.network)
            .field("data_directory", &"<redacted>")
            .field("p2p_listen_address", &self.p2p_listen_address)
            .field("maximum_inbound_peers", &self.maximum_inbound_peers)
            .field("seed_peer_count", &self.seed_peers.len())
            .finish()
    }
}

/// Observable lifecycle state of the embedded Core owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedCoreLifecycleState {
    /// Configuration exists but Core has not been initialized.
    Uninitialized,
    /// Core is initializing and binding its local services.
    Starting,
    /// Core completed startup and its Wallet API may be used.
    Running,
    /// Shutdown has been requested.
    Stopping,
    /// Core shut down cleanly.
    Stopped,
    /// Initialization, startup, or shutdown failed.
    Failed,
}

impl EmbeddedCoreLifecycleState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            STATE_STARTING => Self::Starting,
            STATE_RUNNING => Self::Running,
            STATE_STOPPING => Self::Stopping,
            STATE_STOPPED => Self::Stopped,
            STATE_FAILED => Self::Failed,
            _ => Self::Uninitialized,
        }
    }
}

/// Stable adapter failures. Diagnostic codes contain no Core error text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmbeddedCoreAdapterError {
    /// Wallet configuration was rejected before node initialization.
    #[error("invalid embedded Core configuration ({code})")]
    InvalidConfiguration { code: &'static str },
    /// The node could not be initialized.
    #[error("embedded Core initialization failed ({code})")]
    InitializationFailed { code: &'static str },
    /// The node task could not reach the running state.
    #[error("embedded Core startup failed ({code})")]
    StartupFailed { code: &'static str },
    /// The requested operation requires a running node.
    #[error("embedded Core is not running")]
    NotRunning,
    /// Shutdown or task joining failed.
    #[error("embedded Core shutdown failed ({code})")]
    ShutdownFailed { code: &'static str },
    /// An internal adapter invariant failed.
    #[error("embedded Core adapter failure ({code})")]
    Internal { code: &'static str },
}

enum LifecycleCommand {
    Shutdown,
}

/// Lifecycle-gated implementation of the frozen Wallet-facing Core contract.
pub struct EmbeddedWalletApiHandle {
    inner: EmbeddedWalletCoreApi,
    lifecycle: Arc<AtomicU8>,
}

impl EmbeddedWalletApiHandle {
    fn ensure_running(&self) -> Result<(), WalletCoreError> {
        if self.lifecycle.load(Ordering::Acquire) == STATE_RUNNING {
            Ok(())
        } else {
            Err(WalletCoreError::NodeNotReady(
                "embedded Core lifecycle is not running".to_owned(),
            ))
        }
    }
}

macro_rules! delegate_wallet_api {
    ($name:ident ( $($argument:ident : $argument_type:ty),* ) -> $result:ty) => {
        fn $name(&self, $($argument: $argument_type),*) -> Result<$result, WalletCoreError> {
            self.ensure_running()?;
            self.inner.$name($($argument),*)
        }
    };
}

impl WalletCoreApi for EmbeddedWalletApiHandle {
    delegate_wallet_api!(chain_identity() -> ChainIdentity);
    delegate_wallet_api!(scan_range(request: ScanRequest) -> ScanResult);
    delegate_wallet_api!(validate_cursor(cursor: WalletScanCursor) -> CursorValidation);
    delegate_wallet_api!(canonical_hash_at_height(height: u64) -> Option<[u8; 32]>);
    delegate_wallet_api!(get_utxo(commitment: &[u8; 33]) -> Option<UtxoQueryResult>);
    delegate_wallet_api!(get_kernel(excess: &[u8; 33]) -> Option<KernelQueryResult>);
    delegate_wallet_api!(get_block_summary(selector: BlockSelector) -> Option<BlockSummary>);
    delegate_wallet_api!(transaction_status(id: TransactionIdentifier) -> TransactionStatus);
    delegate_wallet_api!(submit_transaction(request: SubmitTransactionRequest) -> SubmissionResult);
    delegate_wallet_api!(rebroadcast_transaction(id: TransactionIdentifier) -> SubmissionResult);
    delegate_wallet_api!(query_submission(id: TransactionIdentifier) -> SubmissionResult);
    delegate_wallet_api!(sync_status() -> SyncStatus);
    delegate_wallet_api!(is_ready_for_wallet_operations() -> bool);
    delegate_wallet_api!(mempool_policy_snapshot() -> MempoolPolicySnapshot);
    delegate_wallet_api!(fee_policy_snapshot() -> FeePolicySnapshot);
    delegate_wallet_api!(transaction_weight(shape: TransactionShape) -> TransactionWeight);
    delegate_wallet_api!(minimum_fee(shape: TransactionShape) -> FeeBreakdown);
    delegate_wallet_api!(estimate_fee(request: FeeEstimateRequest) -> FeeEstimate);

    fn validate_fee(
        &self,
        transaction: &dom_consensus::Transaction,
    ) -> Result<FeeValidation, WalletCoreError> {
        self.ensure_running()?;
        self.inner.validate_fee(transaction)
    }
}

/// Exclusive owner of the embedded DOM node runtime and Wallet API adapter.
pub struct EmbeddedCoreLifecycle {
    configuration: EmbeddedCoreConfiguration,
    lifecycle: Arc<AtomicU8>,
    node: Option<Arc<DomNode>>,
    wallet_api: Option<Arc<EmbeddedWalletApiHandle>>,
    command_sender: Option<tokio::sync::mpsc::UnboundedSender<LifecycleCommand>>,
    runtime_thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for EmbeddedCoreLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedCoreLifecycle")
            .field("configuration", &self.configuration)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl EmbeddedCoreLifecycle {
    /// Create an uninitialized owner. No node process or task starts here.
    pub fn new(configuration: EmbeddedCoreConfiguration) -> Self {
        Self {
            configuration,
            lifecycle: Arc::new(AtomicU8::new(STATE_UNINITIALIZED)),
            node: None,
            wallet_api: None,
            command_sender: None,
            runtime_thread: None,
        }
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> EmbeddedCoreLifecycleState {
        EmbeddedCoreLifecycleState::from_raw(self.lifecycle.load(Ordering::Acquire))
    }

    /// Initialize Core and start its services on an owned runtime thread.
    pub fn start(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Uninitialized {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LIFECYCLE_ALREADY_STARTED",
            });
        }
        self.configuration.validate()?;
        self.lifecycle.store(STATE_STARTING, Ordering::Release);

        let node = Arc::new(
            DomNode::init(self.configuration.node_config()).map_err(|_| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::InitializationFailed {
                    code: "DOM_NODE_INIT",
                }
            })?,
        );
        let wallet_api = Arc::new(EmbeddedWalletApiHandle {
            inner: EmbeddedWalletCoreApi::new(node.clone()),
            lifecycle: self.lifecycle.clone(),
        });
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let lifecycle = self.lifecycle.clone();
        let listen_address = self.configuration.p2p_listen_address;
        let runtime_node = node.clone();

        let runtime_thread = thread::Builder::new()
            .name("dom-wallet-embedded-core".to_owned())
            .spawn(move || {
                run_node_thread(
                    runtime_node,
                    listen_address,
                    lifecycle,
                    command_receiver,
                    startup_sender,
                );
            })
            .map_err(|_| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::StartupFailed {
                    code: "RUNTIME_THREAD_SPAWN",
                }
            })?;

        match startup_receiver.recv_timeout(STARTUP_TIMEOUT + Duration::from_secs(2)) {
            Ok(Ok(())) => {
                self.node = Some(node);
                self.wallet_api = Some(wallet_api);
                self.command_sender = Some(command_sender);
                self.runtime_thread = Some(runtime_thread);
                Ok(())
            }
            Ok(Err(())) => {
                let _ = runtime_thread.join();
                Err(EmbeddedCoreAdapterError::StartupFailed {
                    code: "DOM_NODE_RUN",
                })
            }
            Err(_) => {
                let _ = command_sender.send(LifecycleCommand::Shutdown);
                let _ = runtime_thread.join();
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                Err(EmbeddedCoreAdapterError::StartupFailed {
                    code: "STARTUP_TIMEOUT",
                })
            }
        }
    }

    /// Obtain a lifecycle-gated handle to the frozen Wallet Core API.
    pub fn wallet_api(
        &self,
    ) -> Result<Arc<dyn WalletCoreApi + Send + Sync>, EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Running {
            return Err(EmbeddedCoreAdapterError::NotRunning);
        }
        self.wallet_api
            .as_ref()
            .map(|api| api.clone() as Arc<dyn WalletCoreApi + Send + Sync>)
            .ok_or(EmbeddedCoreAdapterError::Internal {
                code: "MISSING_WALLET_API",
            })
    }

    /// Query readiness through the frozen Wallet Core API.
    pub fn is_ready_for_wallet_operations(&self) -> Result<bool, EmbeddedCoreAdapterError> {
        self.wallet_api()?
            .is_ready_for_wallet_operations()
            .map_err(|_| EmbeddedCoreAdapterError::Internal {
                code: "READINESS_QUERY",
            })
    }

    /// Query synchronization status through the frozen Wallet Core API.
    pub fn sync_status(&self) -> Result<SyncStatus, EmbeddedCoreAdapterError> {
        self.wallet_api()?
            .sync_status()
            .map_err(|_| EmbeddedCoreAdapterError::Internal {
                code: "SYNC_STATUS_QUERY",
            })
    }

    /// Request shutdown. Repeated requests are safe.
    pub fn request_shutdown(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        match self.state() {
            EmbeddedCoreLifecycleState::Uninitialized => {
                self.lifecycle.store(STATE_STOPPED, Ordering::Release);
                Ok(())
            }
            EmbeddedCoreLifecycleState::Starting | EmbeddedCoreLifecycleState::Running => {
                self.lifecycle.store(STATE_STOPPING, Ordering::Release);
                if let Some(sender) = &self.command_sender {
                    sender.send(LifecycleCommand::Shutdown).map_err(|_| {
                        EmbeddedCoreAdapterError::ShutdownFailed {
                            code: "SHUTDOWN_CHANNEL_CLOSED",
                        }
                    })?;
                }
                Ok(())
            }
            EmbeddedCoreLifecycleState::Stopping
            | EmbeddedCoreLifecycleState::Stopped
            | EmbeddedCoreLifecycleState::Failed => Ok(()),
        }
    }

    /// Wait for the owned node runtime to stop.
    pub fn wait_for_shutdown(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        if let Some(runtime_thread) = self.runtime_thread.take() {
            runtime_thread.join().map_err(|_| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::ShutdownFailed {
                    code: "RUNTIME_THREAD_PANIC",
                }
            })?;
        }
        self.command_sender = None;
        self.wallet_api = None;
        self.node = None;
        if self.state() == EmbeddedCoreLifecycleState::Failed {
            Err(EmbeddedCoreAdapterError::ShutdownFailed {
                code: "DOM_NODE_RUN",
            })
        } else {
            self.lifecycle.store(STATE_STOPPED, Ordering::Release);
            Ok(())
        }
    }
}

impl Drop for EmbeddedCoreLifecycle {
    fn drop(&mut self) {
        let _ = self.request_shutdown();
        let _ = self.wait_for_shutdown();
    }
}

fn run_node_thread(
    node: Arc<DomNode>,
    listen_address: SocketAddr,
    lifecycle: Arc<AtomicU8>,
    mut command_receiver: tokio::sync::mpsc::UnboundedReceiver<LifecycleCommand>,
    startup_sender: mpsc::SyncSender<Result<(), ()>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            lifecycle.store(STATE_FAILED, Ordering::Release);
            let _ = startup_sender.send(Err(()));
            return;
        }
    };

    runtime.block_on(async move {
        let mut node_task = tokio::spawn(node.clone().run());
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if node_task.is_finished() || Instant::now() >= deadline {
                node.request_shutdown().await;
                let _ = node_task.await;
                lifecycle.store(STATE_FAILED, Ordering::Release);
                let _ = startup_sender.send(Err(()));
                return;
            }
            if listener_is_bound(listen_address) {
                break;
            }
            tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
        }

        lifecycle.store(STATE_RUNNING, Ordering::Release);
        if startup_sender.send(Ok(())).is_err() {
            node.request_shutdown().await;
        }

        tokio::select! {
            command = command_receiver.recv() => {
                if matches!(command, Some(LifecycleCommand::Shutdown)) {
                    lifecycle.store(STATE_STOPPING, Ordering::Release);
                }
                node.request_shutdown().await;
                match node_task.await {
                    Ok(Ok(())) => lifecycle.store(STATE_STOPPED, Ordering::Release),
                    _ => lifecycle.store(STATE_FAILED, Ordering::Release),
                }
            }
            _ = &mut node_task => {
                lifecycle.store(STATE_FAILED, Ordering::Release);
            }
        }
    });
}

fn listener_is_bound(address: SocketAddr) -> bool {
    match TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(error) => error.kind() == std::io::ErrorKind::AddrInUse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn unused_loopback_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
        let address = listener.local_addr().expect("read ephemeral test port");
        drop(listener);
        address
    }

    fn regtest_configuration(directory: &Path) -> EmbeddedCoreConfiguration {
        EmbeddedCoreConfiguration::new(
            EmbeddedCoreNetwork::Regtest,
            directory,
            unused_loopback_address(),
        )
        .with_maximum_inbound_peers(2)
    }

    #[test]
    fn configuration_fails_before_node_startup() {
        let directory = TempDir::new().expect("temporary directory");
        let configuration = EmbeddedCoreConfiguration::new(
            EmbeddedCoreNetwork::Regtest,
            directory.path(),
            "127.0.0.1:0".parse().expect("socket address"),
        );
        let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);

        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Uninitialized);
        assert!(matches!(
            lifecycle.wallet_api(),
            Err(EmbeddedCoreAdapterError::NotRunning)
        ));
        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_P2P_PORT"
            })
        ));
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Uninitialized);
    }

    #[test]
    fn initialization_failure_does_not_publish_an_api() {
        let directory = TempDir::new().expect("temporary directory");
        let invalid_path = directory.path().join("not-a-directory");
        fs::write(&invalid_path, b"file").expect("write invalid data path fixture");
        let mut lifecycle = EmbeddedCoreLifecycle::new(regtest_configuration(&invalid_path));

        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InitializationFailed { .. })
        ));
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Failed);
        assert!(matches!(
            lifecycle.wallet_api(),
            Err(EmbeddedCoreAdapterError::NotRunning)
        ));
    }

    #[test]
    fn lifecycle_gates_wallet_api_and_shutdown_is_idempotent() {
        let directory = TempDir::new().expect("temporary directory");
        let mut lifecycle = EmbeddedCoreLifecycle::new(regtest_configuration(directory.path()));

        lifecycle.start().expect("start embedded Core");
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Running);
        let api = lifecycle.wallet_api().expect("running Wallet Core API");
        let identity = api.chain_identity().expect("chain identity");
        assert_eq!(identity.network, dom_wallet_core_api::CoreNetwork::Regtest);
        assert!(lifecycle.sync_status().is_ok());
        assert!(lifecycle.is_ready_for_wallet_operations().is_ok());
        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LIFECYCLE_ALREADY_STARTED"
            })
        ));

        lifecycle.request_shutdown().expect("request shutdown");
        lifecycle.request_shutdown().expect("repeat shutdown");
        assert!(matches!(
            api.chain_identity(),
            Err(WalletCoreError::NodeNotReady(_))
        ));
        lifecycle.wait_for_shutdown().expect("join node runtime");
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Stopped);
        lifecycle.request_shutdown().expect("shutdown after stop");
    }

    #[test]
    fn dropping_running_owner_releases_listener() {
        let directory = TempDir::new().expect("temporary directory");
        let address = unused_loopback_address();
        let configuration =
            EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory.path(), address);
        let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);
        lifecycle.start().expect("start embedded Core");

        drop(lifecycle);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpListener::bind(address) {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("listener was not released: {error}"),
            }
        }
    }

    #[test]
    fn public_source_uses_only_the_frozen_node_boundary() {
        let source = include_str!("lib.rs");
        for forbidden in [
            concat!("req", "west"),
            concat!("http", "://"),
            concat!("https", "://"),
            concat!("rpc", " route"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden API reference: {forbidden}"
            );
        }
    }
}
