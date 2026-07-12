#![forbid(unsafe_code)]

//! Tauri-ready command boundary.
//!
//! The commands are framework-neutral Rust functions so they can be tested in
//! a headless environment. A production Tauri `invoke_handler` binds these
//! names without moving domain, storage, cryptographic, or sync logic here.

use dom_wallet_chain::{ChainSource, LiveNodeProbe, MockChainSource};
use dom_wallet_core::{
    CoreError, DiagnosticSnapshot, FeeEstimate, ProbeResult, SlateExport, TransactionSummary,
    WalletService, WalletSummary,
};
use dom_wallet_domain::{
    NetworkIdentity, NodeConfiguration, RedactedNodeConfiguration, ScanBounds,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use thiserror::Error;

pub struct DesktopApplication {
    service: Mutex<WalletService>,
    shutdown: AtomicBool,
}

pub const COMMAND_NAMES: [&str; 33] = [
    "application_status",
    "wallet_create",
    "wallet_open",
    "wallet_unlock",
    "wallet_lock",
    "wallet_close",
    "wallet_summary",
    "account_list",
    "account_summary",
    "node_configuration_get_redacted",
    "node_configuration_set",
    "node_probe",
    "synchronization_start",
    "synchronization_pause",
    "synchronization_resume",
    "synchronization_retry",
    "synchronization_rescan",
    "diagnostics_redacted",
    "application_shutdown",
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
];

impl Default for DesktopApplication {
    fn default() -> Self {
        Self {
            service: Mutex::new(WalletService::default()),
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

impl DesktopApplication {
    pub fn application_status(&self) -> ApplicationStatusDto {
        let diagnostic = self
            .service
            .lock()
            .expect("application mutex poisoned")
            .diagnostics();
        ApplicationStatusDto {
            state: diagnostic.application_state,
            experimental: true,
            unaudited: true,
        }
    }

    pub fn wallet_create(
        &self,
        path: impl AsRef<Path>,
        password: &str,
        identity: NetworkIdentity,
    ) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
        checked_password(password)?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .create(path, password, identity)
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
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .lock()
            .map_err(CommandError::from)
    }
    pub fn wallet_close(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .close()
            .map_err(CommandError::from)
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
    pub fn node_configuration_get_redacted(
        &self,
    ) -> Result<RedactedNodeConfiguration, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .node_configuration()
            .map_err(CommandError::from)
    }
    pub fn node_configuration_set(
        &self,
        configuration: NodeConfiguration,
    ) -> Result<(), CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .set_node_configuration(configuration)
            .map_err(CommandError::from)
    }
    pub fn diagnostics_redacted(&self) -> DiagnosticSnapshot {
        self.service
            .lock()
            .expect("application mutex poisoned")
            .diagnostics()
    }
    pub fn application_shutdown(&self) -> Result<(), CommandError> {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let _ = service.close();
        Ok(())
    }

    pub fn node_probe<S: ChainSource>(&self, source: &mut S) -> Result<ProbeResult, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .probe(source)
            .map_err(CommandError::from)
    }
    pub fn node_probe_unlocked_free<S: ChainSource>(
        &self,
        source: &mut S,
        expected: &NetworkIdentity,
    ) -> Result<ProbeResult, CommandError> {
        WalletService::probe_node(source, expected).map_err(CommandError::from)
    }
    /// Delegates to the core's node-only probe; it never opens, unlocks, or
    /// persists a wallet and the returned projection has no credential value.
    pub fn node_probe_live(
        &self,
        configuration: NodeConfiguration,
    ) -> Result<LiveNodeProbe, CommandError> {
        WalletService::probe_live_configuration(&configuration).map_err(CommandError::from)
    }
    pub fn synchronization_start<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .synchronize(source, bounds, 256)
            .map_err(CommandError::from)
    }
    pub fn synchronization_pause(&self) -> Result<(), CommandError> {
        Ok(())
    }
    pub fn synchronization_resume<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.synchronization_start(source, bounds)
    }
    pub fn synchronization_retry<S: ChainSource>(
        &self,
        source: &mut S,
        bounds: ScanBounds,
    ) -> Result<WalletSummary, CommandError> {
        self.synchronization_start(source, bounds)
    }
    pub fn synchronization_rescan(&self) -> Result<(), CommandError> {
        Ok(())
    }

    pub fn synchronization_start_live(&self) -> Result<WalletSummary, CommandError> {
        self.ensure_running()?;
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
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        if amount == 0 {
            return Err(CommandError::InvalidInput("amount must be positive".into()));
        }
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_send_create(amount, requested_fee)
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
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_submit(slate_id)
            .map_err(CommandError::from)
    }

    pub fn transaction_retry_submission(
        &self,
        slate_id: uuid::Uuid,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_retry_submission(slate_id)
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

    pub fn probe_mock(&self, source: &mut MockChainSource) -> Result<ProbeResult, CommandError> {
        self.node_probe(source)
    }

    fn ensure_running(&self) -> Result<(), CommandError> {
        if self.shutdown.load(Ordering::Acquire) {
            Err(CommandError::Unavailable)
        } else {
            Ok(())
        }
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
    #[error("wallet operation failed")]
    Wallet,
}

impl From<CoreError> for CommandError {
    fn from(_: CoreError) -> Self {
        Self::Wallet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_domain::{Network, NetworkIdentity};

    #[test]
    fn command_errors_and_status_do_not_expose_passwords() {
        let app = DesktopApplication::default();
        let error = app.wallet_unlock("password-1").unwrap_err();
        assert!(!format!("{error}").contains("password-1"));
        assert!(app.application_status().experimental);
    }

    #[test]
    fn mock_probe_uses_redacted_dto() {
        let app = DesktopApplication::default();
        let identity = NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        };
        let temp = tempfile::tempdir().unwrap();
        app.wallet_create(temp.path().join("wallet"), "password-1", identity.clone())
            .unwrap();
        app.wallet_unlock("password-1").unwrap();
        let mut source = MockChainSource::new(identity);
        assert!(app.probe_mock(&mut source).unwrap().connected);
    }

    #[test]
    fn command_manifest_is_complete_unique_and_unprivileged() {
        let unique = COMMAND_NAMES
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), 33);
        for required in [
            "application_status",
            "wallet_create",
            "node_probe",
            "application_shutdown",
            "transaction_send_create",
            "transaction_submit",
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
    fn redacted_configuration_and_errors_never_serialize_credentials() {
        let app = DesktopApplication::default();
        let error = app.wallet_unlock("password-contains-secret").unwrap_err();
        let rendered = error.to_string();
        assert!(!rendered.contains("password-contains-secret"));
        assert!(!rendered.contains("secret"));
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
        let error = app.transaction_send_create(42, None).unwrap_err();
        assert_eq!(error.to_string(), "wallet operation failed");
        assert!(app.slate_request_import("invalid=not-a-slate").is_err());
        assert!(!format!("{error:?}").contains("password"));
    }
}
