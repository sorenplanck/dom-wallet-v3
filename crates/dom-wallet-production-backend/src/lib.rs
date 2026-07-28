//! Sole default production backend for DOM Wallet V3.

#![forbid(unsafe_code)]

use dom_wallet_core_api::WalletCoreApi;
use dom_wallet_core_protocol::{
    CoreFeePolicyService, ProtocolAdapterError, WalletFeeEstimate, WalletTransactionShape,
};
use dom_wallet_core_recovery::{CanonicalWalletSeed, RecoverableOutputBuilder};
use dom_wallet_core_restore::{SeedRestoreError, SeedRestoreResult, SeedRestoreService};
use dom_wallet_core_submit::{
    CanonicalTransactionSubmission, CoreSubmissionService, WalletSubmissionError,
    WalletSubmissionOutcome, WalletSubmissionQuery, WalletTransactionIdentifier,
    WalletTransactionStatus,
};
use dom_wallet_core_sync::{
    CoreChainAdapter, CoreChainIdentity, CoreReconcileResult, CoreScanError,
    CoreScanTransactionSink,
};
use dom_wallet_crypto::KdfParameters;
use dom_wallet_embedded_core::{
    EmbeddedCoreAdapterError, EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedPeerStatus,
};
use std::{fmt, path::Path, sync::Arc};
use thiserror::Error;

pub const PRODUCTION_BACKEND_KIND: &str = "EMBEDDED_WALLET_CORE_API_ONLY";
pub const DEFAULT_SCAN_BATCH_BLOCKS: u64 = 256;
pub const DEFAULT_REORG_DEPTH: u64 = 1_024;

#[derive(Debug, Error)]
pub enum ProductionBackendError {
    #[error("embedded Core lifecycle failed")]
    Lifecycle(#[from] EmbeddedCoreAdapterError),
    #[error("embedded Core identity or scanner failed")]
    Scan(#[from] CoreScanError),
    #[error("embedded Core submission failed")]
    Submission(#[from] WalletSubmissionError),
    #[error("embedded Core fee policy failed")]
    Fee(#[from] ProtocolAdapterError),
    #[error("output recovery material failed")]
    Recovery,
    #[error("seed-only restore failed")]
    Restore(#[from] SeedRestoreError),
}

impl ProductionBackendError {
    /// Whether a live Wallet scan was rejected only because Core is
    /// temporarily unable to serve a canonical view.
    pub fn is_transient_sync_unavailability(&self) -> bool {
        matches!(self, Self::Scan(CoreScanError::CoreNotReady))
    }
}

/// Explicit owner of the embedded node and every Wallet-facing frozen adapter.
pub struct ProductionWalletBackend {
    lifecycle: EmbeddedCoreLifecycle,
    chain: CoreChainAdapter,
    submission: CoreSubmissionService,
    fees: CoreFeePolicyService,
    identity: CoreChainIdentity,
    api: Arc<dyn WalletCoreApi + Send + Sync>,
}

impl fmt::Debug for ProductionWalletBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionWalletBackend")
            .field("kind", &PRODUCTION_BACKEND_KIND)
            .field("network", &self.identity.network)
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .finish_non_exhaustive()
    }
}

impl ProductionWalletBackend {
    pub fn start(
        configuration: EmbeddedCoreConfiguration,
        expected_identity: Option<&CoreChainIdentity>,
    ) -> Result<Self, ProductionBackendError> {
        let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);
        lifecycle.start()?;
        let api = lifecycle.wallet_api()?;
        let chain = CoreChainAdapter::connect(
            Arc::clone(&api),
            expected_identity,
            DEFAULT_SCAN_BATCH_BLOCKS,
            DEFAULT_REORG_DEPTH,
        )?;
        let identity = chain.identity().clone();
        let submission = CoreSubmissionService::connect(Arc::clone(&api), identity.clone())?;
        let fees = CoreFeePolicyService::connect(Arc::clone(&api), identity.clone())?;
        Ok(Self {
            lifecycle,
            chain,
            submission,
            fees,
            identity,
            api,
        })
    }

    pub fn identity(&self) -> &CoreChainIdentity {
        &self.identity
    }

    pub fn is_running(&self) -> bool {
        self.lifecycle.state() == dom_wallet_embedded_core::EmbeddedCoreLifecycleState::Running
    }

    /// Refresh the canonical tip while requiring every immutable chain identity
    /// field to remain equal to the identity validated at startup.
    pub fn current_identity(&self) -> Result<CoreChainIdentity, ProductionBackendError> {
        Ok(self.chain.current_identity()?)
    }

    pub fn is_ready(&self) -> Result<bool, ProductionBackendError> {
        Ok(self.lifecycle.is_ready_for_wallet_operations()?)
    }

    pub fn peer_status(&self) -> Result<EmbeddedPeerStatus, ProductionBackendError> {
        Ok(self.lifecycle.peer_status()?)
    }

    pub fn node_handle(&self) -> Result<Arc<dom_node::node::DomNode>, ProductionBackendError> {
        Ok(self.lifecycle.node_handle()?)
    }

    pub fn reconcile_once<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, ProductionBackendError> {
        Ok(self.chain.reconcile_to_tip(sink)?)
    }

    /// Reconcile at most one bounded canonical page.
    ///
    /// Desktop background synchronization uses this boundary so pause,
    /// shutdown, status, and mining-stop requests are never held behind an
    /// unbounded scan-to-tip loop.
    pub fn reconcile_page<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, ProductionBackendError> {
        Ok(self.chain.reconcile_wallet_once(sink)?)
    }

    pub fn minimum_fee(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletFeeEstimate, ProductionBackendError> {
        Ok(self.fees.minimum_fee(shape)?)
    }

    pub fn recommended_fee(
        &self,
        shape: WalletTransactionShape,
    ) -> Result<WalletFeeEstimate, ProductionBackendError> {
        Ok(self.fees.recommended_fee(shape)?)
    }

    pub fn output_builder(
        &self,
        seed: &CanonicalWalletSeed,
    ) -> Result<RecoverableOutputBuilder, ProductionBackendError> {
        RecoverableOutputBuilder::new(seed, &self.identity)
            .map_err(|_| ProductionBackendError::Recovery)
    }

    pub fn submit(
        &self,
        transaction: &CanonicalTransactionSubmission,
    ) -> Result<WalletSubmissionOutcome, ProductionBackendError> {
        Ok(self.submission.submit_transaction(transaction)?)
    }

    pub fn rebroadcast(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletSubmissionOutcome, ProductionBackendError> {
        Ok(self.submission.rebroadcast_transaction(identifier)?)
    }

    pub fn query_submission(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletSubmissionQuery, ProductionBackendError> {
        Ok(self.submission.query_submission(identifier)?)
    }

    pub fn transaction_status(
        &self,
        identifier: WalletTransactionIdentifier,
    ) -> Result<WalletTransactionStatus, ProductionBackendError> {
        Ok(self.submission.transaction_status(identifier)?)
    }

    pub fn restore(
        &self,
        mnemonic: &str,
        password: &str,
        destination: impl AsRef<Path>,
        kdf: KdfParameters,
    ) -> Result<SeedRestoreResult, ProductionBackendError> {
        Ok(
            SeedRestoreService::new(Arc::clone(&self.api), self.identity.clone(), kdf).restore(
                mnemonic,
                password,
                destination,
            )?,
        )
    }

    pub fn shutdown(&mut self) -> Result<(), ProductionBackendError> {
        self.lifecycle.request_shutdown()?;
        self.lifecycle.wait_for_shutdown()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_embedded_core::{EmbeddedCoreConfiguration, EmbeddedCoreNetwork};
    use std::net::TcpListener;

    fn unused_loopback_address() -> std::net::SocketAddr {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("ephemeral production-backend listener");
        let address = listener.local_addr().expect("loopback address");
        drop(listener);
        address
    }

    #[test]
    fn production_core_backend_cutover_e2e() {
        let directory = tempfile::tempdir().expect("temporary node directory");
        let address = unused_loopback_address();
        let configuration =
            EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory.path(), address)
                .with_maximum_inbound_peers(2);
        let mut backend = ProductionWalletBackend::start(configuration, None)
            .expect("embedded production backend starts");
        assert_eq!(
            backend.identity().network,
            dom_wallet_core_api::CoreNetwork::Regtest
        );
        assert!(backend.is_ready().is_ok());
        backend.shutdown().expect("idempotent shutdown");
        backend.shutdown().expect("repeated shutdown");
    }

    #[test]
    fn seed_restore_round_trip_uses_the_real_embedded_core() {
        let node_directory = tempfile::tempdir().expect("temporary node directory");
        let wallet_parent = tempfile::tempdir().expect("temporary wallet parent");
        let address = unused_loopback_address();
        let configuration = EmbeddedCoreConfiguration::new(
            EmbeddedCoreNetwork::Regtest,
            node_directory.path(),
            address,
        )
        .with_maximum_inbound_peers(2);
        let mut backend = ProductionWalletBackend::start(configuration, None)
            .expect("embedded production backend starts");
        let seed =
            CanonicalWalletSeed::from_entropy(&[0x73; 32]).expect("test-only recovery material");
        let phrase = seed.mnemonic_text();
        let destination = wallet_parent.path().join("restored-wallet");

        let restored = backend
            .restore(
                phrase.as_str(),
                "test-only-restore-password",
                &destination,
                KdfParameters::TEST,
            )
            .expect("seed restore through real embedded Core");

        assert_eq!(
            restored.completion,
            dom_wallet_core_restore::SeedRestoreCompletion::NoOwnedOutputs
        );
        assert!(destination.join("active-generation").is_file());
        assert!(!wallet_parent
            .path()
            .join(".restored-wallet.seed-restore")
            .exists());
        backend.shutdown().expect("ordered shutdown");
    }
}
