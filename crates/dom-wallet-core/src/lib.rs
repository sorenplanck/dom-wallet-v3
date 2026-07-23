#![forbid(unsafe_code)]

//! Production Wallet orchestration over the frozen embedded DOM Core boundary.

use dom_consensus::Transaction;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet_core_api::WalletScanCursor;
use dom_wallet_core_protocol::{
    AddressIdentityPurpose, CanonicalSlate, ProtocolAdapterError, SlatePhase, WalletAddress,
    WalletTransactionShape,
};
use dom_wallet_core_recovery::{
    finalize_recoverable_transaction, CanonicalWalletSeed, RecoverableOutputBuilder,
    RecoverableSenderParts, WalletSlateInput, CANONICAL_TRANSACTION_OUTPUT_SIZE,
};
use dom_wallet_core_restore::{apply_recovery_batch, rewind_recovery_state, SeedRestoreResult};
use dom_wallet_core_submit::{
    CanonicalTransactionSubmission, WalletSubmissionOutcome, WalletSubmissionQuery,
    WalletTransactionIdentifier, WalletTransactionStatus,
};
use dom_wallet_core_sync::{
    CoreBlockReference, CoreChainIdentity, CoreCursorBytes, CoreScanBatch, CoreScanTransactionSink,
    PersistedCoreCursorState,
};
use dom_wallet_crypto::{KdfParameters, SecretBytes};
use dom_wallet_domain::{
    BalanceProjection, LocalTransactionIntent, MiningPreferences, Network, NetworkIdentity,
    NodeConfiguration, OutputRecord, OutputState, PrivateTransactionContext, RecoveryMetadata,
    RecoveryOutputClass, RedactedNodeConfiguration, TransactionLifecycle, TransactionRole,
    WalletState, RECOVERY_SCHEME_BIP39_256_V1,
};
use dom_wallet_embedded_core::{EmbeddedCoreConfiguration, EmbeddedPeerStatus};
use dom_wallet_production_backend::{
    ProductionBackendError, ProductionWalletBackend, PRODUCTION_BACKEND_KIND,
};
use dom_wallet_storage::{
    default_node_configuration, StorageError, WalletDirectory, WalletMetadata,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAINNET_CHAIN_ID_HEX: &str =
    "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b";
pub const MAINNET_GENESIS_HASH_HEX: &str =
    "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationState {
    Closed,
    Locked,
    Unlocking,
    Unlocked,
    Synchronizing,
    Degraded { reason: String },
    Error { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSummary {
    pub wallet_id: Uuid,
    pub network: Network,
    pub generation: u64,
    pub cursor_height: Option<u64>,
    pub balance: BalanceProjection,
    pub state: String,
    pub experimental: bool,
    pub unaudited: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSnapshot {
    pub application_state: String,
    pub connection_state: String,
    pub generation: Option<u64>,
    pub cursor_height: Option<u64>,
    pub cursor_hash: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub source_identity: String,
    pub network: Network,
    pub tip_height: u64,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionSummary {
    pub id: Uuid,
    pub slate_id: Option<Uuid>,
    pub role: Option<String>,
    pub state: String,
    pub amount: u64,
    pub fee: u64,
    pub kernel_excess: Option<String>,
    pub transaction_hash: Option<String>,
    pub attempt_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeeEstimate {
    pub amount: u64,
    pub selected_input_count: u32,
    pub expected_output_count: u32,
    pub weight: u32,
    pub minimum_fee: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FundingPreflight {
    pub amount: u64,
    pub spendable: u64,
    pub selected_input_count: u32,
    pub estimated_fee: u64,
    pub fundable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlateExport {
    pub transaction_id: Uuid,
    pub slate_id: Uuid,
    pub text: String,
}

pub struct RecoveryCreateResult {
    pub wallet: WalletSummary,
    pub mnemonic: Zeroizing<String>,
}

pub struct RecoveryRestoreResult {
    pub wallet: WalletSummary,
    pub recovery: SeedRestoreResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupStatus {
    pub format_version: u16,
    pub destination_name: String,
}

pub struct WalletService {
    location: Option<WalletDirectory>,
    metadata: Option<WalletMetadata>,
    state: ApplicationState,
    unlocked: Option<WalletState>,
    password: Option<SecretBytes>,
    kdf: KdfParameters,
    backend: Option<ProductionWalletBackend>,
    sender_secrets: Option<(Uuid, RecoverableSenderParts)>,
    last_error: Option<String>,
}

impl fmt::Debug for WalletService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletService")
            .field("state", &self.state)
            .field(
                "backend",
                &self.backend.as_ref().map(|_| PRODUCTION_BACKEND_KIND),
            )
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Default for WalletService {
    fn default() -> Self {
        Self {
            location: None,
            metadata: None,
            state: ApplicationState::Closed,
            unlocked: None,
            password: None,
            kdf: KdfParameters::DOM_CONTINUITY,
            backend: None,
            sender_secrets: None,
            last_error: None,
        }
    }
}

impl WalletService {
    /// Legacy creation is deliberately disabled: every new Wallet must expose its BIP-39 ceremony.
    pub fn create(
        &mut self,
        _path: impl AsRef<Path>,
        _password: &str,
        _identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        Err(CoreError::RecoveryCeremonyRequired)
    }

    pub fn create_recoverable(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        identity: NetworkIdentity,
    ) -> Result<RecoveryCreateResult, CoreError> {
        self.ensure_closed()?;
        validate_password(password)?;
        let seed = CanonicalWalletSeed::generate().map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let mut root_material = Zeroizing::new([0u8; 32]);
        seed.copy_entropy_to(&mut root_material);
        let mut state = WalletState::new(
            identity.clone(),
            *root_material,
            default_node_configuration(identity),
        );
        state.recovery = Some(RecoveryMetadata {
            scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
            phrase_confirmed: false,
        });
        let directory = WalletDirectory::create(path, &state, password, self.kdf)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        Ok(RecoveryCreateResult {
            wallet: self.summary_locked()?,
            mnemonic: seed.mnemonic_text(),
        })
    }

    pub fn create_recoverable_for_embedded(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<RecoveryCreateResult, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        self.create_recoverable(
            path,
            password,
            NetworkIdentity {
                network: map_network(identity.network),
                chain_id: identity.chain_id,
                genesis_id: identity.genesis_hash,
            },
        )
    }

    pub fn open(&mut self, path: impl AsRef<Path>) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        let directory = WalletDirectory::open(path)?;
        let metadata = directory.metadata()?;
        if let Some(backend) = &self.backend {
            require_mainnet_identity(&metadata.identity)?;
            require_domain_identity(&metadata.identity, backend.identity())?;
        }
        self.metadata = Some(metadata);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        self.summary_locked()
    }

    pub fn unlock(&mut self, password: &str) -> Result<WalletSummary, CoreError> {
        if self.state != ApplicationState::Locked {
            return Err(CoreError::InvalidLifecycleState);
        }
        self.state = ApplicationState::Unlocking;
        let result = (|| {
            let password_secret = SecretBytes::from_bytes(password.as_bytes().to_vec())
                .map_err(|_| CoreError::InvalidPassword)?;
            let state = self
                .location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .load(password)?;
            if let Some(backend) = &self.backend {
                require_mainnet_identity(&state.identity)?;
                require_domain_identity(&state.identity, backend.identity())?;
            }
            self.password = Some(password_secret);
            self.unlocked = Some(state);
            self.state = ApplicationState::Unlocked;
            self.summary()
        })();
        if let Err(error) = &result {
            self.state = ApplicationState::Locked;
            self.last_error = Some(error.redacted_message());
        }
        result
    }

    /// Start the sole production backend. No remote endpoint is consulted.
    pub fn start_embedded_core(
        &mut self,
        configuration: EmbeddedCoreConfiguration,
    ) -> Result<ProbeResult, CoreError> {
        if self.backend.is_some() {
            return Err(CoreError::InvalidLifecycleState);
        }
        let expected = self.unlocked.as_ref().map(|state| &state.identity);
        let backend = ProductionWalletBackend::start(configuration, None)?;
        if let Some(expected) = expected {
            require_domain_identity(expected, backend.identity())?;
        }
        let identity = backend.identity().clone();
        let result = ProbeResult {
            source_identity: PRODUCTION_BACKEND_KIND.into(),
            network: map_network(identity.network),
            tip_height: identity.current_tip.height,
            connected: true,
        };
        self.backend = Some(backend);
        Ok(result)
    }

    pub fn embedded_core_identity(&self) -> Result<CoreChainIdentity, CoreError> {
        self.backend
            .as_ref()
            .map(|backend| backend.identity().clone())
            .ok_or(CoreError::EmbeddedCoreRequired)
    }

    pub fn embedded_core_ready(&self) -> Result<bool, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .is_ready()
            .map_err(CoreError::from)
    }

    pub fn embedded_peer_status(&self) -> Result<EmbeddedPeerStatus, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .peer_status()
            .map_err(CoreError::from)
    }

    pub fn embedded_node_handle(
        &self,
    ) -> Result<std::sync::Arc<dom_node::node::DomNode>, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .node_handle()
            .map_err(CoreError::from)
    }

    /// Stop the embedded node without changing the open or unlocked wallet state.
    pub fn stop_embedded_core(&mut self) -> Result<(), CoreError> {
        if let Some(mut backend) = self.backend.take() {
            backend.shutdown()?;
        }
        Ok(())
    }

    /// Reserve a Coinbase recovery coordinate before creating public mining
    /// material. Seed and blinding data never cross into the embedded node.
    pub fn mining_coinbase_candidate(
        &mut self,
        height: u64,
    ) -> Result<dom_consensus::CoinbaseTransaction, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        require_mainnet_identity(&self.unlocked.as_ref().ok_or(CoreError::Locked)?.identity)?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)?;
        self.commit(state)?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        builder
            .build_coinbase(dom_core::BlockHeight(height), 0, coordinate)
            .map_err(CoreError::from)
    }

    pub fn mining_preferences(&self) -> Result<MiningPreferences, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .mining_preferences
            .clone())
    }

    pub fn set_mining_preferences(
        &mut self,
        enabled: bool,
        cpu_threads: usize,
    ) -> Result<MiningPreferences, CoreError> {
        if cpu_threads == 0 || cpu_threads > 4_096 {
            return Err(CoreError::InvalidTransactionInput);
        }
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        state.mining_preferences = MiningPreferences {
            enabled,
            cpu_threads,
        };
        self.commit(state)?;
        self.mining_preferences()
    }

    pub fn mining_reward_destination(&self) -> Result<String, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(format!("DOM-MAINNET-RECOVERY:{}", state.wallet_id))
    }

    pub fn validate_wallet_address(&self, address: &str) -> Result<String, CoreError> {
        let network = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .network;
        WalletAddress::parse(
            address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )
        .map(|value| value.encode())
        .map_err(CoreError::from)
    }

    pub fn restore_from_mnemonic(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        phrase: &str,
    ) -> Result<RecoveryRestoreResult, CoreError> {
        self.ensure_closed()?;
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        let recovery = backend.restore(phrase, password, &path, self.kdf)?;
        let directory = WalletDirectory::open(path)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        Ok(RecoveryRestoreResult {
            wallet: self.summary_locked()?,
            recovery,
        })
    }

    pub fn recovery_phrase_confirmed(&mut self, password: &str) -> Result<(), CoreError> {
        if self.state != ApplicationState::Locked {
            return Err(CoreError::InvalidLifecycleState);
        }
        validate_password(password)?;
        let location = self.location.as_ref().ok_or(CoreError::WalletNotOpen)?;
        let mut state = location.load(password)?;
        let recovery = state
            .recovery
            .as_mut()
            .ok_or(CoreError::RecoveryUnavailable)?;
        recovery.phrase_confirmed = true;
        let expected = state.generation;
        let committed = location.commit(expected, state, password, self.kdf)?;
        self.metadata = Some(location.metadata()?);
        debug_assert!(committed.recovery.is_some());
        Ok(())
    }

    pub fn backup_export(
        &self,
        destination: impl AsRef<Path>,
        backup_password: &str,
    ) -> Result<BackupStatus, CoreError> {
        validate_password(backup_password)?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let wallet_password = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        let name = destination
            .as_ref()
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or(CoreError::InvalidBackupDestination)?
            .to_owned();
        self.location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .export_backup(wallet_password, backup_password, self.kdf, destination)?;
        let _ = state.wallet_id;
        Ok(BackupStatus {
            format_version: dom_wallet_storage::BACKUP_FORMAT_VERSION,
            destination_name: name,
        })
    }

    pub fn backup_import(
        &mut self,
        destination: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        backup_password: &str,
        wallet_password: &str,
        expected_identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        validate_password(backup_password)?;
        validate_password(wallet_password)?;
        let directory = WalletDirectory::import_backup(
            destination,
            backup_path,
            backup_password,
            wallet_password,
            &expected_identity,
            self.kdf,
        )?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        self.summary_locked()
    }

    pub fn lock(&mut self) -> Result<(), CoreError> {
        if self.location.is_none() {
            return Err(CoreError::WalletNotOpen);
        }
        self.sender_secrets = None;
        self.unlocked = None;
        self.password = None;
        self.state = ApplicationState::Locked;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), CoreError> {
        if self.location.is_some() {
            self.lock()?;
        }
        if let Some(mut backend) = self.backend.take() {
            backend.shutdown()?;
        }
        self.location = None;
        self.metadata = None;
        self.state = ApplicationState::Closed;
        Ok(())
    }

    pub fn summary(&self) -> Result<WalletSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(summary_from_state(
            state,
            application_state_name(&self.state),
        ))
    }

    pub fn summary_locked(&self) -> Result<WalletSummary, CoreError> {
        let metadata = self.metadata.as_ref().ok_or(CoreError::WalletNotOpen)?;
        Ok(WalletSummary {
            wallet_id: metadata.wallet_id,
            network: metadata.identity.network,
            generation: metadata.active_generation,
            cursor_height: None,
            balance: BalanceProjection::default(),
            state: application_state_name(&self.state).into(),
            experimental: true,
            unaudited: true,
        })
    }

    pub fn accounts(&self) -> Result<Vec<(Uuid, String)>, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(vec![(
            state.default_account.id,
            state.default_account.label.clone(),
        )])
    }

    /// Deprecated endpoint fields remain readable only as schema compatibility data.
    pub fn node_configuration(&self) -> Result<RedactedNodeConfiguration, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .node_configuration
            .redacted())
    }

    pub fn set_node_configuration(
        &mut self,
        configuration: NodeConfiguration,
    ) -> Result<(), CoreError> {
        configuration.validate()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if configuration.expected_identity != state.identity {
            return Err(CoreError::IdentityMismatch);
        }
        state.node_configuration = configuration;
        self.commit(state)
    }

    pub fn synchronize(&mut self) -> Result<WalletSummary, CoreError> {
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        if !backend.is_ready()? {
            return Err(CoreError::NodeNotReady);
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let identity = backend.identity().clone();
        require_domain_identity(&state.identity, &identity)?;
        let location = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .clone();
        let password = self.password_text()?.to_owned();

        let backend = self.backend.take().ok_or(CoreError::EmbeddedCoreRequired)?;
        let state = self.unlocked.take().ok_or(CoreError::Locked)?;
        let mut sink = WalletRecoverySink::new(location, state, password, self.kdf, seed, identity);
        self.state = ApplicationState::Synchronizing;
        let result = backend.reconcile_once(&mut sink);
        self.backend = Some(backend);
        self.unlocked = Some(sink.state);
        match result {
            Ok(_) => {
                self.last_error = None;
                self.metadata = Some(
                    self.location
                        .as_ref()
                        .ok_or(CoreError::WalletNotOpen)?
                        .metadata()?,
                );
                self.state = ApplicationState::Unlocked;
                self.summary()
            }
            Err(error) => {
                self.record_sync_failure(&error);
                Err(error.into())
            }
        }
    }

    fn record_sync_failure(&mut self, error: &ProductionBackendError) {
        self.last_error = Some(match error {
            ProductionBackendError::Scan(scan) => {
                format!("CURSOR_SYNCHRONIZATION_FAILED:{scan}")
            }
            _ => "CURSOR_SYNCHRONIZATION_FAILED".into(),
        });
        self.state = ApplicationState::Unlocked;
    }

    pub fn synchronize_live(&mut self) -> Result<WalletSummary, CoreError> {
        self.synchronize()
    }

    pub fn rescan_from_genesis(&mut self) -> Result<WalletSummary, CoreError> {
        let tip = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .current_tip
            .height;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        rewind_recovery_state(&mut state, 0, tip);
        state.core_scan_cursor = None;
        state.recovery_canonical_blocks.clear();
        self.commit(state)?;
        self.synchronize()
    }

    pub fn transaction_fee_estimate(
        &self,
        amount: u64,
        selected_input_count: u32,
        change_output: bool,
    ) -> Result<FeeEstimate, CoreError> {
        if amount == 0 || selected_input_count == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let estimate = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .minimum_fee(WalletTransactionShape {
                input_count: selected_input_count,
                output_count: if change_output { 2 } else { 1 },
                kernel_count: 1,
            })?;
        Ok(FeeEstimate {
            amount,
            selected_input_count,
            expected_output_count: estimate.shape.output_count,
            weight: u32::try_from(estimate.weight.total_weight)
                .map_err(|_| CoreError::ArithmeticOverflow)?,
            minimum_fee: estimate.minimum_fee_noms,
        })
    }

    pub fn preflight_funding(&self, amount: u64) -> Result<FundingPreflight, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let mut total = 0u64;
        let mut selected = 0u32;
        let mut fee = 0u64;
        for output in spendable_outputs(state) {
            selected = selected
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow)?;
            fee = self
                .transaction_fee_estimate(amount, selected, true)?
                .minimum_fee;
            total = total
                .checked_add(output.value)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if total
                >= amount
                    .checked_add(fee)
                    .ok_or(CoreError::ArithmeticOverflow)?
            {
                break;
            }
        }
        Ok(FundingPreflight {
            amount,
            spendable: state.balance().spendable,
            selected_input_count: selected,
            estimated_fee: fee,
            fundable: selected > 0
                && total
                    >= amount
                        .checked_add(fee)
                        .ok_or(CoreError::ArithmeticOverflow)?,
        })
    }

    /// Create a manual interactive Slate v4 request. Address v1 interaction
    /// identities are derived from public one-time Slate participant keys.
    pub fn transaction_send_create(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        self.transaction_send_create_with_identities(
            amount,
            requested_fee,
            None,
            None,
            expires_at_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_send_create_recoverable(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender: &WalletAddress,
        receiver: &WalletAddress,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        self.transaction_send_create_with_identities(
            amount,
            requested_fee,
            Some(sender),
            Some(receiver),
            expires_at_height,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transaction_send_create_with_identities(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender: Option<&WalletAddress>,
        receiver: Option<&WalletAddress>,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        if amount == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let mut selected = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for output in spendable_outputs(&state) {
            selected.push(output.clone());
            let minimum = self
                .backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .minimum_fee(WalletTransactionShape {
                    input_count: u32::try_from(selected.len())
                        .map_err(|_| CoreError::ArithmeticOverflow)?,
                    output_count: 2,
                    kernel_count: 1,
                })?;
            fee = requested_fee.unwrap_or(minimum.minimum_fee_noms);
            if fee < minimum.minimum_fee_noms {
                return Err(CoreError::FeeTooLow);
            }
            total = total
                .checked_add(output.value)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if total
                >= amount
                    .checked_add(fee)
                    .ok_or(CoreError::ArithmeticOverflow)?
            {
                break;
            }
        }
        let required = amount
            .checked_add(fee)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if total < required {
            return Err(CoreError::InsufficientFunds);
        }
        let change_value = total - required;
        let transaction_id = Uuid::new_v4();
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::Change)?;
        let reserved_output_ids = selected.iter().map(|output| output.id).collect::<Vec<_>>();
        for output in &mut state.outputs {
            if reserved_output_ids.contains(&output.id) {
                if output.reserved_by.is_some() {
                    return Err(CoreError::ReservationConflict);
                }
                output.reserved_by = Some(transaction_id);
                output.state = OutputState::PendingOutgoing;
            }
        }
        let mut slate_id = [0u8; 32];
        let mut replay_id = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut slate_id)
            .map_err(|_| CoreError::RandomnessUnavailable)?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut replay_id)
            .map_err(|_| CoreError::RandomnessUnavailable)?;
        let public_slate_id = uuid_from_protocol_id(slate_id);
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            slate_id: Some(public_slate_id),
            role: Some(TransactionRole::Sender),
            amount,
            fee,
            reserved_output_ids,
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
        });
        self.commit(state)?; // Coordinate and reservations are durable before construction.

        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        let inputs = selected
            .iter()
            .map(|output| {
                Ok(WalletSlateInput::new(
                    output
                        .commitment
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                    state
                        .output_blinding(output.id)
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                ))
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let sender_parts = builder
            .build_sender_offer(&inputs, change_value, amount, fee, coordinate)?
            .into_sender_parts()?;
        let (automatic_sender, automatic_receiver);
        let (sender, receiver) = match (sender, receiver) {
            (Some(sender), Some(receiver)) => (sender, receiver),
            (None, None) => {
                let (sender_key, receiver_key) = sender_parts.body.manual_interaction_public_keys();
                automatic_sender = WalletAddress::from_public_key(
                    sender_key,
                    identity.network,
                    AddressIdentityPurpose::TransactionInteraction,
                )?;
                automatic_receiver = WalletAddress::from_public_key(
                    receiver_key,
                    identity.network,
                    AddressIdentityPurpose::TransactionInteraction,
                )?;
                (&automatic_sender, &automatic_receiver)
            }
            _ => return Err(CoreError::AddressIdentityRequired),
        };
        let envelope = CanonicalSlate::new_recoverable(
            &identity,
            slate_id,
            replay_id,
            SlatePhase::SenderOffer,
            expires_at_height,
            sender,
            receiver,
            sender_parts.body.clone(),
        )?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, public_slate_id, TransactionRole::Sender)?;
        if let Some(change) = &sender_parts.change {
            let output_id = Uuid::new_v4();
            let mut blinding = Zeroizing::new([0u8; 32]);
            change.copy_blinding_to(&mut blinding);
            state.outputs.push(OutputRecord {
                id: output_id,
                account_id: state.default_account.id,
                commitment: Some(change.commitment),
                value: change.value,
                state: OutputState::PendingIncoming,
                discovered_height: 0,
                reserved_by: None,
            });
            state.remember_output_blinding(output_id, *blinding);
            state.transactions[index].change_output_id = Some(output_id);
        }
        let mut excess = Zeroizing::new([0u8; 32]);
        let mut nonce = Zeroizing::new([0u8; 32]);
        sender_parts.copy_signing_secrets_to(&mut excess, &mut nonce);
        state.transactions[index].private_context = Some(PrivateTransactionContext {
            sender_excess_blinding: Some(*excess),
            sender_nonce: Some(*nonce),
            recipient_output_blinding: None,
        });
        state.transactions[index].request_bytes = envelope.canonical_bytes().to_vec();
        self.commit(state)?;
        self.sender_secrets = Some((public_slate_id, sender_parts));
        self.transaction_summary(transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_send_create_with_addresses(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender_address: &str,
        receiver_address: &str,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        let network = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .network;
        let sender = WalletAddress::parse(
            sender_address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )?;
        let receiver = WalletAddress::parse(
            receiver_address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )?;
        self.transaction_send_create_recoverable(
            amount,
            requested_fee,
            &sender,
            &receiver,
            expires_at_height,
        )
    }

    pub fn slate_request_export(&mut self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Sender)?;
        let slate = CanonicalSlate::from_recovery_bytes(
            &transaction.request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        transaction.lifecycle = TransactionLifecycle::RequestExported;
        let export = SlateExport {
            transaction_id: transaction.id,
            slate_id,
            text: slate.to_text(),
        };
        self.commit(state)?;
        Ok(export)
    }

    pub fn slate_request_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let slate = CanonicalSlate::from_text(text, &identity, identity.current_tip.height)?;
        if slate.phase()? != SlatePhase::SenderOffer {
            return Err(CoreError::InvalidSlateTransport);
        }
        let replay = slate.replay_key();
        let slate_id = uuid_from_protocol_id(replay.slate_id);
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if state
            .transactions
            .iter()
            .any(|tx| tx.slate_id == Some(slate_id))
        {
            return Err(CoreError::SlateReplayConflict);
        }
        let id = Uuid::new_v4();
        state.transactions.push(LocalTransactionIntent {
            id,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::RequestImported,
            submitted: false,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Recipient),
            amount: slate.recovery_body()?.amount_noms(),
            fee: slate.fee_noms(),
            reserved_output_ids: Vec::new(),
            request_bytes: slate.canonical_bytes().to_vec(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
        });
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn slate_response_create(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Recipient)?;
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)?;
        self.commit(state)?; // Burn the recipient coordinate before response construction.
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let request = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = RecoverableOutputBuilder::new(&seed, &identity)?;
        let recipient = builder
            .build_recipient_response(&request.recovery_body()?, coordinate)?
            .into_recipient_parts()?;
        let response = request.with_recovery_body(
            SlatePhase::ReceiverResponse,
            recipient.body,
            &identity,
            identity.current_tip.height,
        )?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let output_id = Uuid::new_v4();
        let mut blinding = Zeroizing::new([0u8; 32]);
        recipient.output.copy_blinding_to(&mut blinding);
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some(recipient.output.commitment),
            value: recipient.output.value,
            state: OutputState::PendingIncoming,
            discovered_height: 0,
            reserved_by: None,
        });
        state.remember_output_blinding(output_id, *blinding);
        state.transactions[index].recipient_output_id = Some(output_id);
        state.transactions[index].private_context = Some(PrivateTransactionContext {
            sender_excess_blinding: None,
            sender_nonce: None,
            recipient_output_blinding: Some(*blinding),
        });
        state.transactions[index].response_bytes = response.canonical_bytes().to_vec();
        state.transactions[index].lifecycle = TransactionLifecycle::ResponsePrepared;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn slate_response_export(&mut self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Recipient)?;
        let slate = CanonicalSlate::from_recovery_bytes(
            &transaction.response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        transaction.lifecycle = TransactionLifecycle::ResponseExported;
        let export = SlateExport {
            transaction_id: transaction.id,
            slate_id,
            text: slate.to_text(),
        };
        self.commit(state)?;
        Ok(export)
    }

    pub fn slate_response_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let response = CanonicalSlate::from_text(text, &identity, identity.current_tip.height)?;
        if response.phase()? != SlatePhase::ReceiverResponse {
            return Err(CoreError::InvalidSlateTransport);
        }
        let slate_id = uuid_from_protocol_id(response.replay_key().slate_id);
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Sender)?;
        let request = CanonicalSlate::from_recovery_bytes(
            &transaction.request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        if request.replay_key() != response.replay_key() {
            return Err(CoreError::SlateReplayConflict);
        }
        transaction.response_bytes = response.canonical_bytes().to_vec();
        transaction.lifecycle = TransactionLifecycle::ResponseImported;
        let id = transaction.id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_finalize(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        if state.transactions[index].lifecycle == TransactionLifecycle::Finalized {
            return Ok(transaction_summary_from(&state.transactions[index]));
        }
        let request = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let response = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let persisted_sender;
        let sender = if let Some((_, sender)) = self
            .sender_secrets
            .as_ref()
            .filter(|(id, _)| *id == slate_id)
        {
            sender
        } else {
            let context = state.transactions[index]
                .private_context
                .as_ref()
                .ok_or(CoreError::MissingPrivateContext)?;
            persisted_sender = RecoverableSenderParts::from_encrypted_context(
                request.recovery_body()?,
                context
                    .sender_excess_blinding
                    .ok_or(CoreError::MissingPrivateContext)?,
                context
                    .sender_nonce
                    .ok_or(CoreError::MissingPrivateContext)?,
            )?;
            &persisted_sender
        };
        let finalized = finalize_recoverable_transaction(
            &response.recovery_body()?,
            &request.recovery_body()?,
            sender,
            identity.chain_id,
        )?;
        let transaction = Transaction::from_bytes(&finalized.canonical_bytes)
            .map_err(|_| CoreError::ProtocolRejected)?;
        if transaction.outputs.iter().any(|output| {
            output.to_bytes().map_or(true, |bytes| {
                bytes.len() != CANONICAL_TRANSACTION_OUTPUT_SIZE
            }) || output.recovery_capsule().ok().flatten().is_none()
        }) {
            return Err(CoreError::MixedOutputRegime);
        }
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        state.transactions[index].finalized_transaction_bytes = finalized.canonical_bytes;
        state.transactions[index].transaction_hash = Some(finalized.transaction_hash);
        state.transactions[index].kernel_excess = finalized.kernel_excess.to_vec();
        state.transactions[index].lifecycle = TransactionLifecycle::Finalized;
        self.commit(state)?;
        self.transaction_summary(state_transaction_id(self.unlocked.as_ref(), index)?)
    }

    pub fn transaction_submit(&mut self, slate_id: Uuid) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, false)
    }

    pub fn transaction_retry_submission(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, true)
    }

    pub fn transaction_reconcile_submission(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        let hash = state.transactions[index]
            .transaction_hash
            .ok_or(CoreError::ProtocolRejected)?;
        let identifier = WalletTransactionIdentifier::TransactionHash(hash);
        let query = backend.query_submission(identifier)?;
        let status = if matches!(query, WalletSubmissionQuery::Unknown) {
            Some(backend.transaction_status(identifier)?)
        } else {
            None
        };

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        apply_submission_query(&mut state.transactions[index], query, status);
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    fn submit_transaction(
        &mut self,
        slate_id: Uuid,
        retry: bool,
    ) -> Result<TransactionSummary, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        let tx = &state.transactions[index];
        if tx.lifecycle != TransactionLifecycle::Finalized
            && !(retry
                && matches!(
                    tx.lifecycle,
                    TransactionLifecycle::Submitting | TransactionLifecycle::RetransmitRequired
                ))
        {
            return Err(CoreError::InvalidTransactionTransition);
        }
        let transaction = Transaction::from_bytes(&tx.finalized_transaction_bytes)
            .map_err(|_| CoreError::ProtocolRejected)?;
        let hash = tx.transaction_hash.ok_or(CoreError::ProtocolRejected)?;
        let kernel = (tx.kernel_excess.len() == 33)
            .then(|| tx.kernel_excess.clone().try_into().ok())
            .flatten();
        let submission = CanonicalTransactionSubmission::new(transaction, hash, kernel)?;
        state.transactions[index].lifecycle = TransactionLifecycle::Submitting;
        state.transactions[index].attempt_count = state.transactions[index]
            .attempt_count
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow)?;
        self.commit(state)?;
        let outcome = if retry {
            self.backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .rebroadcast(WalletTransactionIdentifier::TransactionHash(hash))?
        } else {
            self.backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .submit(&submission)?
        };
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        apply_submission_outcome(&mut state.transactions[index], outcome);
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_cancel(
        &mut self,
        slate_id: Uuid,
        confirm_exported: bool,
    ) -> Result<TransactionSummary, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = state
            .transactions
            .iter()
            .position(|transaction| transaction.slate_id == Some(slate_id))
            .ok_or(CoreError::TransactionNotFound)?;
        if matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::Submitting
                | TransactionLifecycle::Submitted
                | TransactionLifecycle::AcceptedNotRelayed
                | TransactionLifecycle::InMempool
                | TransactionLifecycle::Confirmed { .. }
        ) {
            return Err(CoreError::CannotCancelTransaction);
        }
        if matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::RequestExported | TransactionLifecycle::ResponseExported
        ) && !confirm_exported
        {
            return Err(CoreError::ConfirmationRequired);
        }
        let reserved = state.transactions[index].reserved_output_ids.clone();
        for output in &mut state.outputs {
            if reserved.contains(&output.id) {
                output.reserved_by = None;
                if matches!(output.state, OutputState::PendingOutgoing) {
                    output.state = OutputState::Confirmed;
                }
            }
        }
        state.transactions[index].lifecycle = TransactionLifecycle::Cancelled;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_list(&self) -> Result<Vec<TransactionSummary>, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .transactions
            .iter()
            .map(transaction_summary_from)
            .collect())
    }

    pub fn transaction_detail_redacted(
        &self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        state
            .transactions
            .iter()
            .find(|transaction| transaction.slate_id == Some(slate_id))
            .map(transaction_summary_from)
            .ok_or(CoreError::TransactionNotFound)
    }

    pub fn diagnostics(&self) -> DiagnosticSnapshot {
        let cursor = self
            .unlocked
            .as_ref()
            .and_then(|state| state.core_scan_cursor.as_deref())
            .and_then(|bytes| WalletScanCursor::from_bytes(bytes).ok());
        DiagnosticSnapshot {
            application_state: application_state_name(&self.state).into(),
            connection_state: if self.backend.is_some() {
                PRODUCTION_BACKEND_KIND.into()
            } else {
                "EMBEDDED_CORE_STOPPED".into()
            },
            generation: self.unlocked.as_ref().map(|state| state.generation),
            cursor_height: cursor.as_ref().map(|cursor| cursor.anchor_height),
            cursor_hash: cursor.map(|cursor| hex::encode(cursor.anchor_hash)),
            last_error: self.last_error.clone(),
        }
    }

    fn transaction_summary(&self, id: Uuid) -> Result<TransactionSummary, CoreError> {
        self.unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .transactions
            .iter()
            .find(|transaction| transaction.id == id)
            .map(transaction_summary_from)
            .ok_or(CoreError::TransactionNotFound)
    }

    fn password_text(&self) -> Result<&str, CoreError> {
        std::str::from_utf8(
            self.password
                .as_ref()
                .ok_or(CoreError::Locked)?
                .expose_for_crypto(),
        )
        .map_err(|_| CoreError::InvalidPassword)
    }

    fn commit(&mut self, state: WalletState) -> Result<(), CoreError> {
        let expected = self.unlocked.as_ref().ok_or(CoreError::Locked)?.generation;
        let committed = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .commit(expected, state, self.password_text()?, self.kdf)?;
        self.metadata = Some(
            self.location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .metadata()?,
        );
        self.unlocked = Some(committed);
        Ok(())
    }

    fn ensure_closed(&self) -> Result<(), CoreError> {
        if self.state == ApplicationState::Closed {
            Ok(())
        } else {
            Err(CoreError::InvalidLifecycleState)
        }
    }
}

impl Drop for WalletService {
    fn drop(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            let _ = backend.shutdown();
        }
    }
}

struct WalletRecoverySink {
    directory: WalletDirectory,
    state: WalletState,
    password: Zeroizing<String>,
    kdf: KdfParameters,
    seed: CanonicalWalletSeed,
    identity: CoreChainIdentity,
}

impl WalletRecoverySink {
    fn new(
        directory: WalletDirectory,
        state: WalletState,
        password: String,
        kdf: KdfParameters,
        seed: CanonicalWalletSeed,
        identity: CoreChainIdentity,
    ) -> Self {
        Self {
            directory,
            state,
            password: Zeroizing::new(password),
            kdf,
            seed,
            identity,
        }
    }

    fn commit(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
        reorg: Option<CoreBlockReference>,
    ) -> Result<(), CoreError> {
        let mut next = self.state.clone();
        if let Some(anchor) = reorg {
            rewind_recovery_state(&mut next, anchor.height, batch.observed_tip.height);
        }
        apply_recovery_batch(
            &self.seed,
            dom_crypto::recovery::RecoveryChainContext {
                network_magic: self.identity.network_magic,
                chain_id: self.identity.chain_id,
            },
            &self.identity,
            &mut next,
            batch,
        )?;
        next.core_scan_cursor = Some(cursor.as_bytes().to_vec());
        self.state = self.directory.commit(
            self.state.generation,
            next,
            self.password.as_str(),
            self.kdf,
        )?;
        Ok(())
    }
}

impl CoreScanTransactionSink for WalletRecoverySink {
    type Error = CoreError;

    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error> {
        match self.state.core_scan_cursor.as_deref() {
            None => Ok(PersistedCoreCursorState::Absent),
            Some(bytes) => CoreCursorBytes::parse(bytes, &self.identity)
                .map(PersistedCoreCursorState::Valid)
                .map_err(|_| CoreError::InvalidCoreCursor),
        }
    }

    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self
            .state
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

fn validate_password(password: &str) -> Result<(), CoreError> {
    if (8..=1024).contains(&password.len()) {
        Ok(())
    } else {
        Err(CoreError::InvalidPassword)
    }
}

fn require_domain_identity(
    expected: &NetworkIdentity,
    core: &CoreChainIdentity,
) -> Result<(), CoreError> {
    if expected.network != map_network(core.network)
        || expected.chain_id != core.chain_id
        || expected.genesis_id != core.genesis_hash
    {
        Err(CoreError::IdentityMismatch)
    } else {
        Ok(())
    }
}

fn require_mainnet_identity(identity: &NetworkIdentity) -> Result<(), CoreError> {
    if identity.network != Network::Mainnet
        || hex::encode(identity.chain_id) != MAINNET_CHAIN_ID_HEX
        || hex::encode(identity.genesis_id) != MAINNET_GENESIS_HASH_HEX
    {
        Err(CoreError::IdentityMismatch)
    } else {
        Ok(())
    }
}

fn map_network(network: dom_wallet_core_api::CoreNetwork) -> Network {
    match network {
        dom_wallet_core_api::CoreNetwork::Mainnet => Network::Mainnet,
        dom_wallet_core_api::CoreNetwork::Testnet => Network::PublicTestnet,
        dom_wallet_core_api::CoreNetwork::Regtest => Network::PrivateTestnet,
    }
}

fn spendable_outputs(state: &WalletState) -> Vec<&OutputRecord> {
    let mut outputs = state
        .outputs
        .iter()
        .filter(|output| {
            matches!(output.state, OutputState::Confirmed)
                && output.reserved_by.is_none()
                && output.commitment.is_some()
                && state.output_blinding(output.id).is_some()
        })
        .collect::<Vec<_>>();
    outputs.sort_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then_with(|| left.commitment.cmp(&right.commitment))
            .then_with(|| left.id.cmp(&right.id))
    });
    outputs
}

fn find_transaction_index(
    state: &WalletState,
    slate_id: Uuid,
    role: TransactionRole,
) -> Result<usize, CoreError> {
    state
        .transactions
        .iter()
        .position(|transaction| {
            transaction.slate_id == Some(slate_id) && transaction.role == Some(role.clone())
        })
        .ok_or(CoreError::TransactionNotFound)
}

fn find_transaction_mut(
    state: &mut WalletState,
    slate_id: Uuid,
    role: TransactionRole,
) -> Result<&mut LocalTransactionIntent, CoreError> {
    let index = find_transaction_index(state, slate_id, role)?;
    state
        .transactions
        .get_mut(index)
        .ok_or(CoreError::TransactionNotFound)
}

fn uuid_from_protocol_id(id: [u8; 32]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&id[..16]);
    Uuid::from_bytes(bytes)
}

fn state_transaction_id(state: Option<&WalletState>, index: usize) -> Result<Uuid, CoreError> {
    state
        .and_then(|state| state.transactions.get(index))
        .map(|transaction| transaction.id)
        .ok_or(CoreError::TransactionNotFound)
}

fn apply_submission_outcome(
    transaction: &mut LocalTransactionIntent,
    outcome: WalletSubmissionOutcome,
) {
    transaction.lifecycle = match outcome {
        WalletSubmissionOutcome::Accepted(evidence) if evidence.relayed => {
            transaction.submitted = true;
            TransactionLifecycle::Submitted
        }
        WalletSubmissionOutcome::Accepted(_) => {
            transaction.submitted = true;
            TransactionLifecycle::AcceptedNotRelayed
        }
        WalletSubmissionOutcome::AlreadyKnown(_) => {
            transaction.submitted = true;
            TransactionLifecycle::InMempool
        }
        WalletSubmissionOutcome::NodeNotReady(_)
        | WalletSubmissionOutcome::TemporaryFailure(_)
        | WalletSubmissionOutcome::InternalFailure(_) => TransactionLifecycle::RetransmitRequired,
        WalletSubmissionOutcome::RejectedInvalid(_)
        | WalletSubmissionOutcome::RejectedFee(_)
        | WalletSubmissionOutcome::RejectedDoubleSpend(_)
        | WalletSubmissionOutcome::RejectedImmatureCoinbase(_)
        | WalletSubmissionOutcome::RejectedExpired(_)
        | WalletSubmissionOutcome::RejectedPolicy(_) => TransactionLifecycle::Failed,
    };
}

fn apply_submission_query(
    transaction: &mut LocalTransactionIntent,
    query: WalletSubmissionQuery,
    status: Option<WalletTransactionStatus>,
) {
    match query {
        WalletSubmissionQuery::InMempool(outcome) => {
            apply_submission_outcome(transaction, outcome);
            transaction.submitted = true;
            transaction.lifecycle = TransactionLifecycle::InMempool;
        }
        WalletSubmissionQuery::Confirmed {
            height, block_hash, ..
        } => {
            transaction.submitted = true;
            transaction.lifecycle = TransactionLifecycle::Confirmed { height, block_hash };
        }
        WalletSubmissionQuery::Rejected(outcome)
        | WalletSubmissionQuery::TemporarilyUnavailable(outcome) => {
            apply_submission_outcome(transaction, outcome);
        }
        WalletSubmissionQuery::Unknown => match status {
            Some(WalletTransactionStatus::Confirmed { height, block_hash }) => {
                transaction.submitted = true;
                transaction.lifecycle = TransactionLifecycle::Confirmed { height, block_hash };
            }
            Some(WalletTransactionStatus::InMempool) => {
                transaction.submitted = true;
                transaction.lifecycle = TransactionLifecycle::InMempool;
            }
            Some(WalletTransactionStatus::Unknown)
                if matches!(
                    transaction.lifecycle,
                    TransactionLifecycle::Confirmed { .. }
                ) =>
            {
                transaction.lifecycle = TransactionLifecycle::Reorged;
            }
            Some(WalletTransactionStatus::Unknown) | None => {
                transaction.lifecycle = TransactionLifecycle::ReconciliationRequired;
            }
        },
    }
}

fn summary_from_state(state: &WalletState, application_state: &str) -> WalletSummary {
    WalletSummary {
        wallet_id: state.wallet_id,
        network: state.identity.network,
        generation: state.generation,
        cursor_height: state
            .core_scan_cursor
            .as_deref()
            .and_then(|bytes| WalletScanCursor::from_bytes(bytes).ok())
            .map(|cursor| cursor.anchor_height),
        balance: state.balance(),
        state: application_state.into(),
        experimental: true,
        unaudited: true,
    }
}

fn transaction_summary_from(transaction: &LocalTransactionIntent) -> TransactionSummary {
    TransactionSummary {
        id: transaction.id,
        slate_id: transaction.slate_id,
        role: transaction.role.as_ref().map(|role| match role {
            TransactionRole::Sender => "SENDER".into(),
            TransactionRole::Recipient => "RECIPIENT".into(),
        }),
        state: transaction_state_name(&transaction.lifecycle).into(),
        amount: transaction.amount,
        fee: transaction.fee,
        kernel_excess: (transaction.kernel_excess.len() == 33)
            .then(|| hex::encode(&transaction.kernel_excess)),
        transaction_hash: transaction.transaction_hash.map(hex::encode),
        attempt_count: transaction.attempt_count,
    }
}

fn transaction_state_name(state: &TransactionLifecycle) -> &'static str {
    match state {
        TransactionLifecycle::Draft => "DRAFT",
        TransactionLifecycle::InputsReserved => "INPUTS_RESERVED",
        TransactionLifecycle::RequestExported => "REQUEST_EXPORTED",
        TransactionLifecycle::RequestImported => "REQUEST_IMPORTED",
        TransactionLifecycle::ResponsePrepared => "RESPONSE_PREPARED",
        TransactionLifecycle::ResponseExported => "RESPONSE_EXPORTED",
        TransactionLifecycle::ResponseImported => "RESPONSE_IMPORTED",
        TransactionLifecycle::Finalized => "FINALIZED",
        TransactionLifecycle::Submitting => "SUBMITTING",
        TransactionLifecycle::Submitted => "SUBMITTED",
        TransactionLifecycle::AcceptedNotRelayed => "ACCEPTED_NOT_RELAYED",
        TransactionLifecycle::InMempool => "IN_MEMPOOL",
        TransactionLifecycle::Confirmed { .. } => "CONFIRMED",
        TransactionLifecycle::Reorged => "REORGED",
        TransactionLifecycle::RetransmitRequired => "RETRANSMIT_REQUIRED",
        TransactionLifecycle::Cancelled => "CANCELLED",
        TransactionLifecycle::Failed => "FAILED",
        TransactionLifecycle::ReconciliationRequired => "RECONCILIATION_REQUIRED",
    }
}

fn application_state_name(state: &ApplicationState) -> &'static str {
    match state {
        ApplicationState::Closed => "CLOSED",
        ApplicationState::Locked => "LOCKED",
        ApplicationState::Unlocking => "UNLOCKING",
        ApplicationState::Unlocked => "READY",
        ApplicationState::Synchronizing => "SYNCHRONIZING",
        ApplicationState::Degraded { .. } => "DEGRADED",
        ApplicationState::Error { .. } => "ERROR",
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("wallet is not open")]
    WalletNotOpen,
    #[error("wallet is locked")]
    Locked,
    #[error("wallet lifecycle state does not permit this operation")]
    InvalidLifecycleState,
    #[error("password does not meet local requirements")]
    InvalidPassword,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("BIP-39 recovery ceremony is required")]
    RecoveryCeremonyRequired,
    #[error("recovery phrase is invalid")]
    RecoveryPhraseInvalid,
    #[error("wallet is not eligible for mnemonic recovery")]
    RecoveryUnavailable,
    #[error("backup destination is invalid")]
    InvalidBackupDestination,
    #[error("embedded DOM Core must be running")]
    EmbeddedCoreRequired,
    #[error("embedded DOM Core is not ready")]
    NodeNotReady,
    #[error("wallet and Core identities differ")]
    IdentityMismatch,
    #[error("canonical Address v1 identities are required")]
    AddressIdentityRequired,
    #[error("transaction input is invalid")]
    InvalidTransactionInput,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("selected outputs have no encrypted spending evidence")]
    UnsupportedSpendingEvidence,
    #[error("transaction fee is below the Core policy floor")]
    FeeTooLow,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("input is already reserved")]
    ReservationConflict,
    #[error("canonical Slate transport is invalid")]
    InvalidSlateTransport,
    #[error("canonical Slate replay conflicts with durable state")]
    SlateReplayConflict,
    #[error("transaction transition is invalid")]
    InvalidTransactionTransition,
    #[error("private transaction context is unavailable")]
    MissingPrivateContext,
    #[error("DOM protocol transaction validation failed")]
    ProtocolRejected,
    #[error("mixed recoverable and proof-only output regime")]
    MixedOutputRegime,
    #[error("transaction cannot be cancelled after submission evidence")]
    CannotCancelTransaction,
    #[error("explicit confirmation is required")]
    ConfirmationRequired,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("persisted Core cursor is invalid")]
    InvalidCoreCursor,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Domain(#[from] dom_wallet_domain::DomainError),
    #[error(transparent)]
    Backend(#[from] ProductionBackendError),
    #[error(transparent)]
    Protocol(#[from] ProtocolAdapterError),
    #[error(transparent)]
    Recovery(#[from] dom_wallet_core_recovery::RecoveryMaterialError),
    #[error(transparent)]
    Restore(#[from] dom_wallet_core_restore::SeedRestoreError),
    #[error(transparent)]
    Submission(#[from] dom_wallet_core_submit::WalletSubmissionError),
}

impl CoreError {
    pub fn redacted_code(&self) -> &'static str {
        match self {
            Self::WalletNotOpen => "WALLET_NOT_OPEN",
            Self::Locked => "WALLET_LOCKED",
            Self::InvalidLifecycleState => "INVALID_WALLET_STATE",
            Self::InvalidPassword => "INVALID_PASSWORD",
            Self::RandomnessUnavailable => "RANDOMNESS_UNAVAILABLE",
            Self::RecoveryCeremonyRequired => "RECOVERY_CONFIRMATION_REQUIRED",
            Self::RecoveryPhraseInvalid => "RECOVERY_PHRASE_INVALID",
            Self::RecoveryUnavailable => "RECOVERY_UNAVAILABLE",
            Self::InvalidBackupDestination => "BACKUP_DESTINATION_INVALID",
            Self::EmbeddedCoreRequired => "EMBEDDED_NODE_REQUIRED",
            Self::NodeNotReady => "EMBEDDED_NODE_NOT_READY",
            Self::IdentityMismatch => "CHAIN_IDENTITY_MISMATCH",
            Self::AddressIdentityRequired => "ADDRESS_IDENTITY_REQUIRED",
            Self::InvalidTransactionInput => "TRANSACTION_INPUT_INVALID",
            Self::InsufficientFunds => "INSUFFICIENT_FUNDS",
            Self::UnsupportedSpendingEvidence => "SPENDING_EVIDENCE_UNSUPPORTED",
            Self::FeeTooLow => "FEE_TOO_LOW",
            Self::ArithmeticOverflow => "ARITHMETIC_OVERFLOW",
            Self::ReservationConflict => "OUTPUT_RESERVATION_CONFLICT",
            Self::InvalidSlateTransport => "SLATE_V4_TRANSPORT_INVALID",
            Self::SlateReplayConflict => "SLATE_REPLAY_CONFLICT",
            Self::InvalidTransactionTransition => "TRANSACTION_STATE_INVALID",
            Self::MissingPrivateContext => "SLATE_PRIVATE_CONTEXT_MISSING",
            Self::ProtocolRejected => "PROTOCOL_REJECTED",
            Self::MixedOutputRegime => "MIXED_OUTPUT_REGIME",
            Self::CannotCancelTransaction => "TRANSACTION_CANNOT_CANCEL",
            Self::ConfirmationRequired => "CONFIRMATION_REQUIRED",
            Self::TransactionNotFound => "TRANSACTION_NOT_FOUND",
            Self::InvalidCoreCursor => "CURSOR_INVALID",
            Self::Storage(StorageError::WriterActive) => "WALLET_WRITER_ACTIVE",
            Self::Storage(_) => "WALLET_STORAGE_FAILED",
            Self::Domain(_) => "WALLET_STATE_VALIDATION_FAILED",
            Self::Backend(_) => "EMBEDDED_NODE_OPERATION_FAILED",
            Self::Protocol(_) => "PROTOCOL_VALIDATION_FAILED",
            Self::Recovery(_) => "RECOVERY_MATERIAL_FAILED",
            Self::Restore(_) => "RESTORE_FAILED",
            Self::Submission(_) => "TRANSACTION_SUBMISSION_FAILED",
        }
    }

    pub fn redacted_message(&self) -> String {
        let description: &str = match self {
            Self::Locked => "wallet is locked",
            Self::IdentityMismatch => "embedded Core identity does not match wallet",
            Self::InsufficientFunds => "insufficient spendable funds",
            Self::FeeTooLow => "transaction fee is below the required Core policy floor",
            Self::NodeNotReady => "embedded Core is not ready",
            Self::InvalidCoreCursor => "wallet cursor is invalid",
            Self::InvalidSlateTransport => "Slate v4 transport is invalid",
            Self::MissingPrivateContext => "private Slate context is unavailable",
            Self::Storage(StorageError::WriterActive) => "wallet is already open by another writer",
            _ => "the requested wallet operation was rejected",
        };
        format!("{}:{description}", self.redacted_code())
    }
}

/// Default production graph contains no legacy HTTP, custom scanner, or proof-only constructor.
pub const PRODUCTION_REACHABILITY: &[(&str, &str)] = &[
    ("node", "EmbeddedCoreLifecycle"),
    ("scanner", "CoreChainAdapter"),
    ("cursor", "WalletScanCursorV1"),
    ("submission", "CoreSubmissionService"),
    ("fees", "CoreFeePolicyService"),
    ("address", "WalletAddressV1"),
    ("slate", "RecoverySlateV4"),
    ("outputs", "RecoveryCapsuleV1Only"),
    ("restore", "SeedRestoreService"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }

    fn canonical_mainnet_identity() -> NetworkIdentity {
        let mut chain_id = [0u8; 32];
        let mut genesis_id = [0u8; 32];
        hex::decode_to_slice(MAINNET_CHAIN_ID_HEX, &mut chain_id).unwrap();
        hex::decode_to_slice(MAINNET_GENESIS_HASH_HEX, &mut genesis_id).unwrap();
        NetworkIdentity {
            network: Network::Mainnet,
            chain_id,
            genesis_id,
        }
    }

    fn test_service() -> WalletService {
        let mut service = WalletService::default();
        service.kdf = KdfParameters::TEST;
        service
    }

    #[test]
    fn backup_round_trip_preserves_existing_state_and_rejects_wrong_identity() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("wallet");
        let backup_path = temp.path().join("wallet.dombackup");
        let mut service = test_service();
        let created = service
            .create_recoverable(&wallet_path, "password-1", backup_identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        service
            .backup_export(&backup_path, "backup-password")
            .unwrap();
        service.close().unwrap();

        let mut imported = test_service();
        let summary = imported
            .backup_import(
                temp.path().join("imported"),
                &backup_path,
                "backup-password",
                "password-2",
                backup_identity(),
            )
            .unwrap();
        assert_eq!(summary.wallet_id, created.wallet.wallet_id);
        imported.close().unwrap();

        let mut wrong_identity = backup_identity();
        wrong_identity.chain_id[0] ^= 1;
        let mut rejected = test_service();
        assert!(matches!(
            rejected.backup_import(
                temp.path().join("wrong-identity"),
                &backup_path,
                "backup-password",
                "password-3",
                wrong_identity,
            ),
            Err(CoreError::Storage(StorageError::IdentityMismatch))
        ));
    }

    #[test]
    fn desktop_mainnet_identity_is_exact_and_every_mismatch_fails_closed() {
        assert_eq!(
            MAINNET_CHAIN_ID_HEX,
            "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b"
        );
        assert_eq!(
            MAINNET_GENESIS_HASH_HEX,
            "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce"
        );
        let identity = canonical_mainnet_identity();
        require_mainnet_identity(&identity).unwrap();

        let mut wrong_network = identity.clone();
        wrong_network.network = Network::PublicTestnet;
        assert!(matches!(
            require_mainnet_identity(&wrong_network),
            Err(CoreError::IdentityMismatch)
        ));
        let mut wrong_chain = identity.clone();
        wrong_chain.chain_id[0] ^= 1;
        assert!(matches!(
            require_mainnet_identity(&wrong_chain),
            Err(CoreError::IdentityMismatch)
        ));
        let mut wrong_genesis = identity;
        wrong_genesis.genesis_id[0] ^= 1;
        assert!(matches!(
            require_mainnet_identity(&wrong_genesis),
            Err(CoreError::IdentityMismatch)
        ));
    }

    #[test]
    fn cursor_failure_does_not_close_unlocked_wallet() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = test_service();
        service
            .create_recoverable(temp.path().join("wallet"), "password-1", backup_identity())
            .unwrap();
        service.unlock("password-1").unwrap();

        service.record_sync_failure(&ProductionBackendError::Scan(
            dom_wallet_core_sync::CoreScanError::CoreContract {
                code: "CORE_INTERNAL_FAILURE",
            },
        ));

        let diagnostics = service.diagnostics();
        assert_eq!(diagnostics.application_state, "READY");
        assert_eq!(
            diagnostics.last_error.as_deref(),
            Some("CURSOR_SYNCHRONIZATION_FAILED:Core scan contract failed (CORE_INTERNAL_FAILURE)")
        );
        assert!(service.summary().is_ok());
    }

    #[test]
    fn active_writer_has_a_distinct_redacted_error_code() {
        let error = CoreError::Storage(StorageError::WriterActive);
        assert_eq!(error.redacted_code(), "WALLET_WRITER_ACTIVE");
        assert_eq!(
            error.redacted_message(),
            "WALLET_WRITER_ACTIVE:wallet is already open by another writer"
        );
    }

    #[test]
    fn no_legacy_production_reachability() {
        let values = PRODUCTION_REACHABILITY
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        assert!(!values.iter().any(|value| value.contains("Http")));
        assert!(!values.iter().any(|value| value.contains("ProofOnly")));
    }

    #[test]
    fn no_mixed_output_regime() {
        assert_eq!(CANONICAL_TRANSACTION_OUTPUT_SIZE, 872);
        assert_eq!(dom_wallet_core_recovery::PRODUCTION_OUTPUT_PATHS.len(), 5);
        assert!(dom_wallet_core_recovery::PRODUCTION_OUTPUT_PATHS
            .iter()
            .all(|path| path.recovery_required));
    }

    #[test]
    fn embedded_core_can_stop_and_restart_without_closing_the_service() {
        let directory = tempfile::tempdir().unwrap();
        let first_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_address = first_listener.local_addr().unwrap();
        drop(first_listener);
        let second_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second_address = second_listener.local_addr().unwrap();
        drop(second_listener);
        let mut service = test_service();

        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                directory.path(),
                first_address,
            ))
            .unwrap();
        assert!(service.embedded_core_identity().is_ok());
        service.stop_embedded_core().unwrap();
        assert!(matches!(
            service.embedded_core_identity(),
            Err(CoreError::EmbeddedCoreRequired)
        ));
        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                directory.path(),
                second_address,
            ))
            .unwrap();
        assert!(service.embedded_core_identity().is_ok());
        service.stop_embedded_core().unwrap();
    }
}
