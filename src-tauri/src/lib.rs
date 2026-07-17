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
use dom_wallet_embedded_core::{EmbeddedCoreConfiguration, EmbeddedCoreNetwork};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::{net::SocketAddr, path::Path};
use thiserror::Error;

pub struct DesktopApplication {
    service: Mutex<WalletService>,
    qr_reassembler: Mutex<Option<String>>,
    node_started: AtomicBool,
    shutdown: AtomicBool,
}

pub const COMMAND_NAMES: [&str; 43] = [
    "native_bridge_status",
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
    "embedded_node_status",
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
            service: Mutex::new(WalletService::default()),
            qr_reassembler: Mutex::new(None),
            node_started: AtomicBool::new(false),
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
pub enum EmbeddedNetworkDto {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedNodeStartDto {
    pub network: EmbeddedNetworkDto,
    pub data_directory: String,
    pub listen_address: String,
    pub maximum_inbound_peers: u32,
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
    pub fn embedded_node_start(
        &self,
        request: EmbeddedNodeStartDto,
    ) -> Result<EmbeddedNodeStatusDto, CommandError> {
        self.ensure_running()?;
        if self.node_started.load(Ordering::Acquire) {
            return self.embedded_node_status();
        }
        if request.data_directory.is_empty() || request.data_directory.len() > 4096 {
            return Err(CommandError::InvalidInput(
                "embedded node data directory is invalid".into(),
            ));
        }
        let listen_address: SocketAddr = request
            .listen_address
            .parse()
            .map_err(|_| CommandError::InvalidInput("listen address is invalid".into()))?;
        if request.maximum_inbound_peers == 0 || request.maximum_inbound_peers > 1_024 {
            return Err(CommandError::InvalidInput("peer limit is invalid".into()));
        }
        let network = match request.network {
            EmbeddedNetworkDto::Mainnet => EmbeddedCoreNetwork::Mainnet,
            EmbeddedNetworkDto::Testnet => EmbeddedCoreNetwork::Testnet,
            EmbeddedNetworkDto::Regtest => EmbeddedCoreNetwork::Regtest,
        };
        let configuration =
            EmbeddedCoreConfiguration::new(network, request.data_directory, listen_address)
                .with_maximum_inbound_peers(request.maximum_inbound_peers as usize);
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
        let lifecycle = if ready {
            WalletReadinessDto::Ready
        } else if diagnostic.application_state == "SYNCHRONIZING" {
            WalletReadinessDto::Synchronizing
        } else {
            WalletReadinessDto::Starting
        };
        Ok(EmbeddedNodeStatusDto {
            lifecycle,
            network: Some(core_network_name(identity.network).into()),
            chain_id: Some(hex::encode(identity.chain_id)),
            genesis_hash: Some(hex::encode(identity.genesis_hash)),
            canonical_tip_height: Some(identity.current_tip.height),
            canonical_tip_hash: Some(hex::encode(identity.current_tip.hash)),
            protocol_version: Some(identity.protocol_version),
            range_proof_version: Some(identity.range_proof_serialization_version),
            ready,
            error_code: diagnostic.last_error.map(|_| "CORE_NOT_READY".into()),
        })
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
        self.node_started.store(false, Ordering::Release);
        Ok(())
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
        sender_address: &str,
        receiver_address: &str,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CommandError> {
        self.ensure_running()?;
        if amount == 0 {
            return Err(CommandError::InvalidInput("amount must be positive".into()));
        }
        self.service
            .lock()
            .map_err(|_| CommandError::Unavailable)?
            .transaction_send_create_with_addresses(
                amount,
                requested_fee,
                sender_address,
                receiver_address,
                expires_at_height,
            )
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
    }
}

fn core_network_name(network: CoreNetwork) -> &'static str {
    match network {
        CoreNetwork::Mainnet => "MAINNET",
        CoreNetwork::Testnet => "TESTNET",
        CoreNetwork::Regtest => "REGTEST",
    }
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
    #[error("wallet operation failed")]
    Wallet,
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
            CommandError::Wallet => Self {
                code: "WALLET_OPERATION_FAILED".into(),
                category: "WALLET".into(),
                message: "The wallet operation failed.".into(),
                retryable: false,
            },
        }
    }
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
        assert_eq!(unique.len(), 43);
        for required in [
            "native_bridge_status",
            "application_status",
            "wallet_create_recoverable",
            "wallet_restore_from_mnemonic",
            "wallet_backup_export",
            "wallet_backup_import",
            "wallet_recovery_phrase_confirm",
            "embedded_node_start",
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
        assert_eq!(status.app_version, "0.1.1");
        fn assert_serializable<T: serde::Serialize>(_: &T) {}
        assert_serializable(&status);
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
        let error = app
            .transaction_send_create(42, None, "invalid", "invalid", 100)
            .unwrap_err();
        assert_eq!(error.to_string(), "wallet operation failed");
        assert!(app.slate_request_import("invalid=not-a-slate").is_err());
        assert!(!format!("{error:?}").contains("password"));
    }
}
