#![forbid(unsafe_code)]

//! Tauri-ready command boundary.
//!
//! The commands are framework-neutral Rust functions so they can be tested in
//! a headless environment. A production Tauri `invoke_handler` binds these
//! names without moving domain, storage, cryptographic, or sync logic here.

use dom_wallet_core::{
    CoreError, DiagnosticSnapshot, FeeEstimate, ProbeResult, SlateExport, TransactionSummary,
    WalletService, WalletSummary,
};
use dom_wallet_domain::{NetworkIdentity, NodeConfiguration, RedactedNodeConfiguration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use thiserror::Error;

pub struct DesktopApplication {
    service: Mutex<WalletService>,
    qr_reassembler: Mutex<Option<String>>,
    shutdown: AtomicBool,
}

pub const COMMAND_NAMES: [&str; 37] = [
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
    "slate_qr_encode",
    "slate_qr_decode_frame",
    "slate_qr_reassembly_status",
    "slate_qr_reassembly_clear",
];

impl Default for DesktopApplication {
    fn default() -> Self {
        Self {
            service: Mutex::new(WalletService::default()),
            qr_reassembler: Mutex::new(None),
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
        self.clear_qr_buffers()?;
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .lock()
            .map_err(CommandError::from)
    }
    pub fn wallet_close(&self) -> Result<(), CommandError> {
        self.ensure_running()?;
        self.clear_qr_buffers()?;
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
        self.clear_qr_buffers()?;
        let mut service = self.service.lock().map_err(|_| CommandError::Unavailable)?;
        let _ = service.close();
        Ok(())
    }

    /// Legacy endpoint configuration has no authority after the embedded cutover.
    pub fn node_probe_live(
        &self,
        _configuration: NodeConfiguration,
    ) -> Result<ProbeResult, CommandError> {
        Err(CommandError::Unavailable)
    }
    pub fn synchronization_pause(&self) -> Result<(), CommandError> {
        Ok(())
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
        assert_eq!(unique.len(), 37);
        for required in [
            "application_status",
            "wallet_create",
            "node_probe",
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
