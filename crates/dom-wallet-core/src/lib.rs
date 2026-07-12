#![forbid(unsafe_code)]

//! Application orchestration. Tauri and CLI code delegate here.

use dom_wallet_chain::{
    acquire_target, collect_provisional_pages, validate_target, ChainError, ChainSource,
    ConnectionState, DomHttpChainSource, LiveNodeProbe, ReconnectController,
};
use dom_wallet_crypto::{KdfParameters, SecretBytes};
use dom_wallet_domain::{
    BalanceProjection, LocalTransactionIntent, NetworkIdentity, NodeConfiguration, OutputRecord,
    OutputState, PrivateTransactionContext, RedactedNodeConfiguration, ScanBounds,
    TransactionLifecycle, TransactionRole, WalletState,
};
use dom_wallet_protocol::{self as protocol, InputMaterial, SenderSecrets};
use dom_wallet_storage::{
    default_node_configuration, StorageError, WalletDirectory, WalletMetadata,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

pub mod live_e2e;

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
    pub network: dom_wallet_domain::Network,
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
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub source_identity: String,
    pub network: dom_wallet_domain::Network,
    pub tip_height: u64,
    pub connected: bool,
}

/// Redacted transaction projection. The public slate identifier, kernel and
/// state are safe to show; encrypted signing contexts never leave core.
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
pub struct SlateExport {
    pub transaction_id: Uuid,
    pub slate_id: Uuid,
    pub text: String,
}

pub struct WalletService {
    location: Option<WalletDirectory>,
    metadata: Option<WalletMetadata>,
    state: ApplicationState,
    unlocked: Option<WalletState>,
    password: Option<SecretBytes>,
    kdf: KdfParameters,
    connection: ConnectionState,
    reconnect: ReconnectController,
    last_error: Option<String>,
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
            connection: ConnectionState::Disconnected,
            reconnect: ReconnectController::new(6, 60_000, 3),
            last_error: None,
        }
    }
}

impl WalletService {
    pub fn create(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        if password.len() < 8 || password.len() > 1024 {
            return Err(CoreError::InvalidPassword);
        }
        let mut root = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut root)
            .map_err(|_| CoreError::RandomnessUnavailable)?;
        let node = default_node_configuration(identity.clone());
        let state = WalletState::new(identity, root, node);
        let directory = WalletDirectory::create(path, &state, password, self.kdf)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        self.summary_locked()
    }

    pub fn open(&mut self, path: impl AsRef<Path>) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        let directory = WalletDirectory::open(path)?;
        self.metadata = Some(directory.metadata()?);
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
            let mut state = self
                .location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .load(password)?;
            state.rescan_plan = self
                .location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .load_rescan_plan(&state, password)?;
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

    pub fn lock(&mut self) -> Result<(), CoreError> {
        if self.location.is_none() {
            return Err(CoreError::WalletNotOpen);
        }
        self.unlocked = None;
        self.password = None;
        self.state = ApplicationState::Locked;
        self.connection = ConnectionState::Disconnected;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), CoreError> {
        self.lock()?;
        self.location = None;
        self.metadata = None;
        self.state = ApplicationState::Closed;
        Ok(())
    }

    pub fn summary(&self) -> Result<WalletSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(WalletSummary {
            wallet_id: state.wallet_id,
            network: state.identity.network,
            generation: state.generation,
            cursor_height: state.cursor.as_ref().map(|cursor| cursor.height),
            balance: state.balance(),
            state: application_state_name(&self.state).into(),
            experimental: true,
            unaudited: true,
        })
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
        configuration.validate().map_err(CoreError::Domain)?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if configuration.expected_identity != state.identity {
            return Err(CoreError::IdentityMismatch);
        }
        state.node_configuration = configuration;
        self.commit(state)
    }

    pub fn probe<S: ChainSource>(&mut self, source: &mut S) -> Result<ProbeResult, CoreError> {
        self.connection = ConnectionState::Connecting;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        self.connection = ConnectionState::VerifyingIdentity;
        let handshake = source.handshake()?;
        if handshake.identity != state.identity {
            self.connection = ConnectionState::WrongNetwork;
            return Err(CoreError::IdentityMismatch);
        }
        if handshake.api_compatibility_version != state.node_configuration.api_compatibility_version
        {
            self.connection = ConnectionState::IncompatibleProtocol;
            return Err(CoreError::Chain(ChainError::IncompatibleProtocol));
        }
        self.connection = ConnectionState::Connected;
        self.reconnect.on_success();
        Ok(ProbeResult {
            source_identity: handshake.source_identity,
            network: handshake.identity.network,
            tip_height: handshake.tip_height,
            connected: true,
        })
    }

    /// Read-only, unlock-free node evidence probe.  The caller supplies the
    /// expected identity because encrypted wallet configuration is deliberately
    /// unavailable while locked; this method never reads or changes wallet state.
    pub fn probe_node<S: ChainSource>(
        source: &mut S,
        expected: &NetworkIdentity,
    ) -> Result<ProbeResult, CoreError> {
        let handshake = source.handshake()?;
        if &handshake.identity != expected {
            return Err(CoreError::IdentityMismatch);
        }
        Ok(ProbeResult {
            source_identity: handshake.source_identity,
            network: handshake.identity.network,
            tip_height: handshake.tip_height,
            connected: true,
        })
    }

    /// Node-only probe for closed and locked applications. Configuration is
    /// caller supplied; no wallet directory is opened and no service field is
    /// read or modified.
    pub fn probe_live_configuration(
        configuration: &NodeConfiguration,
    ) -> Result<LiveNodeProbe, CoreError> {
        configuration.validate().map_err(CoreError::Domain)?;
        let source = DomHttpChainSource::new(
            &configuration.endpoint_url,
            configuration.expected_identity.clone(),
            configuration.source_identity.clone(),
            configuration.api_compatibility_version,
            configuration.connect_timeout_ms,
            configuration.request_timeout_ms,
            None,
        )?;
        source.live_probe().map_err(CoreError::Chain)
    }

    pub fn synchronize<S: ChainSource>(
        &mut self,
        source: &mut S,
        bounds: ScanBounds,
        ancestry_limit: u32,
    ) -> Result<WalletSummary, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        self.connection = ConnectionState::Synchronizing;
        self.state = ApplicationState::Synchronizing;
        let result = (|| {
            let (_, target) = acquire_target(source, &state.identity, bounds)?;
            state
                .begin_scan(target.clone())
                .map_err(CoreError::Domain)?;
            let pages = collect_provisional_pages(source, &target)?;
            // HTTP scan pages contain public commitments, not wallet-owned
            // output records. Preserve existing encrypted descriptors and
            // merge only explicit test/source observations that are not
            // already known locally.
            let mut provisional = state.outputs.clone();
            for output in pages.iter().flat_map(|page| page.outputs.iter()).cloned() {
                let already_known = provisional.iter().any(|known| {
                    known.id == output.id
                        || (known.commitment.is_some() && known.commitment == output.commitment)
                });
                if !already_known {
                    provisional.push(output);
                }
            }
            state.outputs = provisional;
            for page in &pages {
                for block in &page.blocks {
                    state
                        .mark_known_outputs_confirmed(
                            &block.output_commitments,
                            block.height,
                            block.hash,
                        )
                        .map_err(CoreError::Domain)?;
                    state
                        .apply_kernel_evidence(block.height, block.hash, &block.kernel_excesses)
                        .map_err(CoreError::Domain)?;
                    for input in &block.input_commitments {
                        state.mark_known_output_spent(input, block.height);
                    }
                }
            }
            validate_target(source, &state.identity, &target, ancestry_limit)?;
            let reconciled_outputs = state.outputs.clone();
            state
                .activate_scan(&target, reconciled_outputs)
                .map_err(CoreError::Domain)?;
            self.commit(state.clone())?;
            self.connection = ConnectionState::Synced;
            self.reconnect.on_success();
            self.state = ApplicationState::Unlocked;
            self.summary()
        })();
        if let Err(error) = &result {
            let reason = error.redacted_message();
            state.invalidate_scan(reason.clone());
            self.unlocked = Some(state);
            self.connection = ConnectionState::Degraded {
                error: chain_error_for(error),
            };
            self.state = ApplicationState::Degraded {
                reason: reason.clone(),
            };
            self.last_error = Some(reason);
            let _ = self.reconnect.on_failure();
        }
        result
    }

    /// Reconstruct canonical observations from the configured recovery start.
    /// The existing generation remains active until `synchronize` publishes the
    /// replacement generation; allocation and non-reuse floors are retained.
    pub fn full_rescan<S: ChainSource>(
        &mut self,
        source: &mut S,
        mut bounds: ScanBounds,
        ancestry_limit: u32,
    ) -> Result<WalletSummary, CoreError> {
        if self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .rescan_plan
            .as_ref()
            .is_some_and(|plan| plan.phase == dom_wallet_domain::RescanPhase::Complete)
        {
            return self.summary();
        }
        if self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .rescan_plan
            .is_some()
        {
            self.revalidate_staged_rescan(source, ancestry_limit)?;
            return Err(CoreError::Domain(
                dom_wallet_domain::DomainError::RescanAlreadyActive,
            ));
        }
        bounds.start_height = 0;
        let mut staged = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let floors = (staged.allocation_floor, staged.non_reuse_floor);
        let (_, target) = acquire_target(source, &staged.identity, bounds)?;
        staged
            .prepare_rescan(target.clone())
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&staged)?; // durable PREPARED plan before the first page request
        self.unlocked = Some(staged);

        let mut staged = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        staged
            .transition_rescan(dom_wallet_domain::RescanPhase::Scanning)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&staged)?;
        self.unlocked = Some(staged);

        let pages = collect_provisional_pages(source, &target)?;
        let mut staged = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        for page in &pages {
            let mut transactions = staged
                .rescan_plan_mut()
                .map_err(CoreError::Domain)?
                .provisional_transactions
                .clone();
            for block in &page.blocks {
                let mut candidate = staged.clone();
                candidate.transactions = transactions;
                candidate
                    .apply_kernel_evidence(block.height, block.hash, &block.kernel_excesses)
                    .map_err(CoreError::Domain)?;
                transactions = candidate.transactions;
                let plan = staged.rescan_plan_mut().map_err(CoreError::Domain)?;
                for input in &block.input_commitments {
                    if let Some(output) = plan
                        .provisional_outputs
                        .iter_mut()
                        .find(|output| output.commitment.as_ref() == Some(input))
                    {
                        output.state = dom_wallet_domain::OutputState::Spent {
                            spent_height: block.height,
                        };
                    }
                }
            }
            staged
                .rescan_plan_mut()
                .map_err(CoreError::Domain)?
                .provisional_transactions = transactions;
            staged
                .apply_rescan_page_cursor(page.page_number, page.start_height, page.end_height)
                .map_err(CoreError::Domain)?;
        }
        if staged
            .rescan_plan
            .as_ref()
            .ok_or(CoreError::Domain(
                dom_wallet_domain::DomainError::InvalidRescanPlan,
            ))?
            .phase
            != dom_wallet_domain::RescanPhase::ValidatingTarget
        {
            return Err(CoreError::Domain(
                dom_wallet_domain::DomainError::InvalidRescanPage,
            ));
        }
        self.save_rescan_plan(&staged)?; // page progress becomes restartable only after complete pages
        self.unlocked = Some(staged);

        validate_target(
            source,
            &self.unlocked.as_ref().ok_or(CoreError::Locked)?.identity,
            &target,
            ancestry_limit,
        )?;
        let mut ready = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        ready
            .transition_rescan(dom_wallet_domain::RescanPhase::ReadyToActivate)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&ready)?;
        self.unlocked = Some(ready);
        let mut activation = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        activation
            .transition_rescan(dom_wallet_domain::RescanPhase::Activating)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&activation)?;
        let completed_plan = activation.rescan_plan.clone().ok_or(CoreError::Domain(
            dom_wallet_domain::DomainError::InvalidRescanPlan,
        ))?;
        self.unlocked = Some(activation);
        let mut activation = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        activation.activate_rescan().map_err(CoreError::Domain)?;
        if activation.allocation_floor < floors.0 || activation.non_reuse_floor < floors.1 {
            return Err(CoreError::Domain(
                dom_wallet_domain::DomainError::NonReuseFloorRegression,
            ));
        }
        let staged_generation = self.stage_activation_generation(activation)?;
        self.publish_activation_generation(&staged_generation)?;
        self.unlocked = Some(staged_generation);
        let mut complete = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        complete.rescan_plan = Some(completed_plan);
        complete
            .transition_rescan(dom_wallet_domain::RescanPhase::Complete)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&complete)?;
        self.unlocked = Some(complete);
        self.state = ApplicationState::Unlocked;
        self.summary()
    }

    /// Reopening code calls this before any attempt to continue a staged
    /// rescan. Invalid evidence only changes the sidecar's terminal phase;
    /// it never changes the active canonical generation.
    pub fn revalidate_staged_rescan<S: ChainSource>(
        &mut self,
        source: &mut S,
        ancestry_limit: u32,
    ) -> Result<dom_wallet_domain::RescanPhase, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let plan = state.rescan_plan.clone().ok_or(CoreError::Domain(
            dom_wallet_domain::DomainError::InvalidRescanPlan,
        ))?;
        if matches!(
            plan.phase,
            dom_wallet_domain::RescanPhase::Complete
                | dom_wallet_domain::RescanPhase::Invalidated
                | dom_wallet_domain::RescanPhase::Failed
        ) {
            return Err(CoreError::Domain(
                dom_wallet_domain::DomainError::InvalidRescanPlan,
            ));
        }
        let validation = validate_target(source, &state.identity, &plan.target, ancestry_limit);
        if let Err(error) = validation {
            let mut invalidated = state;
            invalidated
                .transition_rescan(dom_wallet_domain::RescanPhase::Invalidated)
                .map_err(CoreError::Domain)?;
            self.save_rescan_plan(&invalidated)?;
            self.unlocked = Some(invalidated);
            return Err(CoreError::Chain(error));
        }
        Ok(plan.phase)
    }

    /// Deterministic crash recovery for the only split publication point. It
    /// reads the active pointer and a complete encrypted candidate generation;
    /// it never infers success from directory presence alone.
    pub fn recover_activating_rescan(&mut self) -> Result<WalletSummary, CoreError> {
        let active = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let plan = active.rescan_plan.clone().ok_or(CoreError::Domain(
            dom_wallet_domain::DomainError::InvalidRescanPlan,
        ))?;
        if plan.phase == dom_wallet_domain::RescanPhase::Complete {
            return self.summary();
        }
        if plan.phase != dom_wallet_domain::RescanPhase::Activating {
            return Err(CoreError::Domain(
                dom_wallet_domain::DomainError::InvalidRescanPlan,
            ));
        }
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let password_text = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        let location = self.location.as_ref().ok_or(CoreError::WalletNotOpen)?;
        let candidate =
            location.load_generation_for_recovery(plan.provisional_generation_id, password_text);
        let candidate = match candidate {
            Ok(state)
                if state.cursor == Some(plan.target.cursor())
                    && state.wallet_id == plan.wallet_id
                    && state.identity == plan.identity =>
            {
                state
            }
            _ => return self.fail_activating(active),
        };
        if active.generation == plan.retained_canonical_generation_id {
            location
                .publish_staged_generation(plan.retained_canonical_generation_id, &candidate)?;
            self.metadata = Some(location.metadata()?);
        } else if active.generation != plan.provisional_generation_id {
            return self.fail_activating(active);
        }
        let mut complete = candidate;
        complete.rescan_plan = Some(plan);
        complete
            .transition_rescan(dom_wallet_domain::RescanPhase::Complete)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&complete)?;
        self.unlocked = Some(complete);
        self.summary()
    }

    pub fn synchronize_live(&mut self) -> Result<WalletSummary, CoreError> {
        let config = self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .node_configuration
            .clone();
        let mut source = DomHttpChainSource::new(
            &config.endpoint_url,
            config.expected_identity,
            config.source_identity,
            config.api_compatibility_version,
            config.connect_timeout_ms,
            config.request_timeout_ms,
            None,
        )?;
        let tip = source.handshake()?;
        let start_height = self
            .unlocked
            .as_ref()
            .and_then(|state| {
                state
                    .cursor
                    .as_ref()
                    // Re-read the cursor block when already at the tip. This
                    // makes a reopen/resynchronize cycle validate durable
                    // canonical evidence instead of producing an empty range.
                    .map(|cursor| cursor.height.saturating_add(1).min(tip.tip_height))
            })
            .unwrap_or(0);
        let span = tip
            .tip_height
            .checked_sub(start_height)
            .ok_or(CoreError::Chain(ChainError::ChangedBounds))?;
        let max_pages = u32::try_from((span / 1_000).saturating_add(1))
            .map_err(|_| CoreError::Chain(ChainError::PageLimitExceeded))?;
        self.synchronize(
            &mut source,
            ScanBounds {
                start_height,
                end_height: tip.tip_height,
                max_pages,
                max_records_per_page: 100_000,
            },
            256,
        )
    }

    /// Exact protocol fee floor for a proposed interactive DOM send. Frontends
    /// may display it but never supply an authoritative fee calculation.
    pub fn transaction_fee_estimate(
        &self,
        amount: u64,
        selected_input_count: u32,
        change_output: bool,
    ) -> Result<FeeEstimate, CoreError> {
        self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        if amount == 0 || selected_input_count == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        let count = usize::try_from(selected_input_count)
            .map_err(|_| CoreError::InvalidTransactionInput)?;
        let weight = protocol::expected_weight(count, change_output)
            .map_err(|_| CoreError::InvalidTransactionInput)?;
        let minimum_fee = protocol::minimum_fee(count, change_output)
            .map_err(|_| CoreError::InvalidTransactionInput)?;
        Ok(FeeEstimate {
            amount,
            selected_input_count,
            expected_output_count: if change_output { 2 } else { 1 },
            weight,
            minimum_fee,
        })
    }

    /// Creates and durably reserves a sender slate before any public request
    /// text can be exported. Outputs without their encrypted local blinding
    /// are deliberately not selectable; Phase 1A scan evidence alone is not
    /// sufficient to spend an output.
    pub fn transaction_send_create(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
    ) -> Result<TransactionSummary, CoreError> {
        if amount == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let mut candidates = state
            .outputs
            .iter()
            .filter(|output| {
                matches!(output.state, OutputState::Confirmed)
                    && output.reserved_by.is_none()
                    && output.commitment.is_some()
                    && state.output_blinding(output.id).is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.value
                .cmp(&right.value)
                .then_with(|| left.commitment.cmp(&right.commitment))
                .then_with(|| left.id.cmp(&right.id))
        });
        if candidates.is_empty() {
            return Err(CoreError::UnsupportedSpendingEvidence);
        }

        let mut selected = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for output in candidates {
            if selected.len() >= protocol::MAX_INPUTS {
                return Err(CoreError::InvalidTransactionInput);
            }
            selected.push(output);
            fee = requested_fee
                .unwrap_or_else(|| protocol::minimum_fee(selected.len(), true).unwrap_or(u64::MAX));
            let minimum = protocol::minimum_fee(selected.len(), true)
                .map_err(|_| CoreError::InvalidTransactionInput)?;
            if fee < minimum {
                return Err(CoreError::FeeTooLow);
            }
            total = total
                .checked_add(
                    selected
                        .last()
                        .ok_or(CoreError::InvalidTransactionInput)?
                        .value,
                )
                .ok_or(CoreError::ArithmeticOverflow)?;
            let required = amount
                .checked_add(fee)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if total >= required {
                break;
            }
        }
        let required = amount
            .checked_add(fee)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if total < required {
            return Err(CoreError::InsufficientFunds);
        }
        let transaction_id = Uuid::new_v4();
        let slate_id = Uuid::new_v4();
        let input_material = selected
            .iter()
            .map(|output| {
                Ok(InputMaterial {
                    commitment: output
                        .commitment
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                    blinding: state
                        .output_blinding(output.id)
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                    value: output.value,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let built = protocol::build_sender(&input_material, amount, fee, state.identity.chain_id)
            .map_err(|_| CoreError::ProtocolRejected)?;
        let mut change_output_id = None;
        if let Some(change) = built.change.as_ref() {
            let id = Uuid::new_v4();
            state.outputs.push(OutputRecord {
                id,
                account_id: state.default_account.id,
                commitment: Some(change.commitment),
                value: change.value,
                state: OutputState::PendingIncoming,
                discovered_height: state.cursor.as_ref().map_or(0, |cursor| cursor.height),
                reserved_by: None,
            });
            state.remember_output_blinding(id, change.blinding);
            change_output_id = Some(id);
        }
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
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Sender),
            amount,
            fee,
            reserved_output_ids,
            request_bytes: built.slate_bytes,
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: Some(PrivateTransactionContext {
                sender_excess_blinding: Some(built.secrets.excess_blinding),
                sender_nonce: Some(built.secrets.nonce),
                recipient_output_blinding: None,
            }),
            recipient_output_id: None,
            change_output_id,
        });
        self.commit(state)?;
        self.transaction_summary(transaction_id)
    }

    pub fn slate_request_export(&mut self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let network = state.identity.network.to_string();
        let chain_id = state.identity.chain_id;
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Sender)?;
        match transaction.lifecycle {
            TransactionLifecycle::InputsReserved => {
                transaction.lifecycle = TransactionLifecycle::RequestExported
            }
            TransactionLifecycle::RequestExported => {}
            _ => return Err(CoreError::InvalidTransactionTransition),
        }
        let text = protocol::export_transport(
            &network,
            chain_id,
            slate_id,
            false,
            &transaction.request_bytes,
        )
        .map_err(|_| CoreError::ProtocolRejected)?;
        let id = transaction.id;
        self.commit(state)?;
        Ok(SlateExport {
            transaction_id: id,
            slate_id,
            text,
        })
    }

    pub fn slate_request_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let envelope =
            protocol::import_transport(text).map_err(|_| CoreError::InvalidSlateTransport)?;
        if envelope.response {
            return Err(CoreError::InvalidSlateTransport);
        }
        let slate_id = envelope.slate_id;
        let bytes = envelope.payload;
        let details =
            protocol::slate_public_details(&bytes).map_err(|_| CoreError::InvalidSlateTransport)?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if envelope.network != state.identity.network.to_string()
            || envelope.chain_id != state.identity.chain_id
            || details.chain_id != state.identity.chain_id
            || details.amount == 0
            || details.has_recipient_response
            || details.fee
                < protocol::minimum_fee(details.input_count, details.has_sender_change)
                    .map_err(|_| CoreError::InvalidSlateTransport)?
        {
            return Err(CoreError::IdentityMismatch);
        }
        if let Some(existing) = state
            .transactions
            .iter()
            .find(|intent| intent.slate_id == Some(slate_id))
        {
            if existing.role == Some(TransactionRole::Recipient) && existing.request_bytes == bytes
            {
                return Ok(transaction_summary_from(existing));
            }
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
            amount: details.amount,
            fee: details.fee,
            reserved_output_ids: Vec::new(),
            request_bytes: bytes,
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
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Recipient)?;
        if matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::ResponsePrepared | TransactionLifecycle::ResponseExported
        ) {
            return Ok(transaction_summary_from(&state.transactions[index]));
        }
        if state.transactions[index].lifecycle != TransactionLifecycle::RequestImported {
            return Err(CoreError::InvalidTransactionTransition);
        }
        let request = state.transactions[index].request_bytes.clone();
        let amount = state.transactions[index].amount;
        let response = protocol::create_recipient_response(&request, state.identity.chain_id)
            .map_err(|_| CoreError::ProtocolRejected)?;
        // The receive coordinate and non-reuse floor advance before response
        // export. The authoritative protocol creates the output commitment.
        state.allocate().map_err(CoreError::Domain)?;
        let output_id = Uuid::new_v4();
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some(response.recipient_commitment),
            value: amount,
            state: OutputState::PendingIncoming,
            discovered_height: state.cursor.as_ref().map_or(0, |cursor| cursor.height),
            reserved_by: None,
        });
        state.remember_output_blinding(output_id, response.secrets.output_blinding);
        let transaction = &mut state.transactions[index];
        transaction.response_bytes = response.slate_bytes;
        transaction.private_context = Some(PrivateTransactionContext {
            sender_excess_blinding: None,
            sender_nonce: None,
            recipient_output_blinding: Some(response.secrets.output_blinding),
        });
        transaction.recipient_output_id = Some(output_id);
        transaction.lifecycle = TransactionLifecycle::ResponsePrepared;
        let id = transaction.id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn slate_response_export(&mut self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let network = state.identity.network.to_string();
        let chain_id = state.identity.chain_id;
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Recipient)?;
        match transaction.lifecycle {
            TransactionLifecycle::ResponsePrepared => {
                transaction.lifecycle = TransactionLifecycle::ResponseExported
            }
            TransactionLifecycle::ResponseExported => {}
            _ => return Err(CoreError::InvalidTransactionTransition),
        }
        let id = transaction.id;
        let text = protocol::export_transport(
            &network,
            chain_id,
            slate_id,
            true,
            &transaction.response_bytes,
        )
        .map_err(|_| CoreError::ProtocolRejected)?;
        self.commit(state)?;
        Ok(SlateExport {
            transaction_id: id,
            slate_id,
            text,
        })
    }

    pub fn slate_response_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let envelope =
            protocol::import_transport(text).map_err(|_| CoreError::InvalidSlateTransport)?;
        if !envelope.response {
            return Err(CoreError::InvalidSlateTransport);
        }
        let slate_id = envelope.slate_id;
        let bytes = envelope.payload;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        let details =
            protocol::slate_public_details(&bytes).map_err(|_| CoreError::InvalidSlateTransport)?;
        let transaction = &mut state.transactions[index];
        if envelope.network != state.identity.network.to_string()
            || envelope.chain_id != state.identity.chain_id
            || details.chain_id != state.identity.chain_id
            || !details.has_recipient_response
            || details.amount != transaction.amount
            || details.fee != transaction.fee
            || details.fee
                < protocol::minimum_fee(details.input_count, details.has_sender_change)
                    .map_err(|_| CoreError::InvalidSlateTransport)?
        {
            return Err(CoreError::SlateReplayConflict);
        }
        if matches!(
            transaction.lifecycle,
            TransactionLifecycle::ResponseImported
                | TransactionLifecycle::Finalized
                | TransactionLifecycle::Submitting
                | TransactionLifecycle::Submitted
                | TransactionLifecycle::AcceptedNotRelayed
        ) {
            if transaction.response_bytes == bytes {
                return Ok(transaction_summary_from(transaction));
            }
            return Err(CoreError::SlateReplayConflict);
        }
        if transaction.lifecycle != TransactionLifecycle::RequestExported {
            return Err(CoreError::InvalidTransactionTransition);
        }
        transaction.response_bytes = bytes;
        transaction.lifecycle = TransactionLifecycle::ResponseImported;
        let id = transaction.id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_finalize(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        if matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::Finalized
                | TransactionLifecycle::Submitting
                | TransactionLifecycle::Submitted
                | TransactionLifecycle::AcceptedNotRelayed
        ) {
            return Ok(transaction_summary_from(&state.transactions[index]));
        }
        if state.transactions[index].lifecycle != TransactionLifecycle::ResponseImported {
            return Err(CoreError::InvalidTransactionTransition);
        }
        let transaction = &mut state.transactions[index];
        let context = transaction
            .private_context
            .as_ref()
            .ok_or(CoreError::MissingPrivateContext)?;
        let sender_secrets = SenderSecrets {
            excess_blinding: context
                .sender_excess_blinding
                .ok_or(CoreError::MissingPrivateContext)?,
            nonce: context
                .sender_nonce
                .ok_or(CoreError::MissingPrivateContext)?,
        };
        let finalized = protocol::finalize_sender(
            &transaction.response_bytes,
            &transaction.request_bytes,
            &sender_secrets,
            state.identity.chain_id,
        )
        .map_err(|_| CoreError::ProtocolRejected)?;
        transaction.finalized_transaction_bytes = finalized.bytes;
        transaction.kernel_excess = finalized.kernel_excess.to_vec();
        transaction.transaction_hash = Some(finalized.transaction_hash);
        transaction.private_context = None; // consume sender nonce after exactly one finalization.
        transaction.lifecycle = TransactionLifecycle::Finalized;
        let id = transaction.id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    /// Submit immutable finalized bytes only through the existing wallet-safe
    /// POST /tx/submit adapter. Timeouts deliberately remain SUBMITTING because
    /// the node may have admitted the exact bytes before its reply was lost.
    pub fn transaction_submit(&mut self, slate_id: Uuid) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, false)
    }

    pub fn transaction_retry_submission(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, true)
    }

    /// Records only positive node mempool evidence.  A missing `/tx/{hash}`
    /// result is intentionally a no-op: it can mean mining, eviction, or a
    /// reorganization and is never a local rejection decision.
    pub fn transaction_observe_mempool(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        let transaction = &state.transactions[index];
        if !matches!(
            transaction.lifecycle,
            TransactionLifecycle::Submitting
                | TransactionLifecycle::Submitted
                | TransactionLifecycle::AcceptedNotRelayed
                | TransactionLifecycle::RetransmitRequired
                | TransactionLifecycle::InMempool
        ) {
            return Err(CoreError::InvalidTransactionTransition);
        }
        let transaction_hash = transaction
            .transaction_hash
            .ok_or(CoreError::InvalidTransactionTransition)?;
        let configuration = state.node_configuration.clone();
        let source = DomHttpChainSource::new(
            &configuration.endpoint_url,
            configuration.expected_identity,
            configuration.source_identity,
            configuration.api_compatibility_version,
            configuration.connect_timeout_ms,
            configuration.request_timeout_ms,
            None,
        )?;
        let observed = source.lookup_transaction(transaction_hash)?;
        if !observed.in_mempool {
            return self.transaction_summary(transaction.id);
        }
        let mut state = state.clone();
        state.transactions[index].lifecycle = TransactionLifecycle::InMempool;
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
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        let transaction_id = state.transactions[index].id;
        match state.transactions[index].lifecycle {
            TransactionLifecycle::InputsReserved => {}
            TransactionLifecycle::RequestExported if confirm_exported => {}
            TransactionLifecycle::RequestExported => return Err(CoreError::ConfirmationRequired),
            _ => return Err(CoreError::CannotCancelTransaction),
        }
        for output in &mut state.outputs {
            if output.reserved_by == Some(transaction_id) {
                output.reserved_by = None;
                output.state = OutputState::Confirmed;
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
        let transaction = state
            .transactions
            .iter()
            .find(|transaction| transaction.slate_id == Some(slate_id))
            .ok_or(CoreError::TransactionNotFound)?;
        Ok(transaction_summary_from(transaction))
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

    fn submit_transaction(
        &mut self,
        slate_id: Uuid,
        retry: bool,
    ) -> Result<TransactionSummary, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        let allowed = matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::Finalized
        ) || (retry
            && matches!(
                state.transactions[index].lifecycle,
                TransactionLifecycle::AcceptedNotRelayed
                    | TransactionLifecycle::RetransmitRequired
                    | TransactionLifecycle::Submitting
            ));
        if !allowed {
            return Err(CoreError::InvalidTransactionTransition);
        }
        if state.transactions[index]
            .finalized_transaction_bytes
            .is_empty()
        {
            return Err(CoreError::InvalidTransactionTransition);
        }
        protocol::validate_finalized_bytes(&state.transactions[index].finalized_transaction_bytes)
            .map_err(|_| CoreError::ProtocolRejected)?;
        state.transactions[index].lifecycle = TransactionLifecycle::Submitting;
        state.transactions[index].attempt_count =
            state.transactions[index].attempt_count.saturating_add(1);
        let bytes = state.transactions[index]
            .finalized_transaction_bytes
            .clone();
        let id = state.transactions[index].id;
        let configuration = state.node_configuration.clone();
        self.commit(state)?; // durable uncertain state before network I/O
        let source = DomHttpChainSource::new(
            &configuration.endpoint_url,
            configuration.expected_identity,
            configuration.source_identity,
            configuration.api_compatibility_version,
            configuration.connect_timeout_ms,
            configuration.request_timeout_ms,
            None,
        )?;
        let outcome = source.submit_finalized(&bytes);
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = state
            .transactions
            .iter()
            .position(|transaction| transaction.id == id)
            .ok_or(CoreError::TransactionNotFound)?;
        match outcome {
            Ok(outcome) if outcome.accepted && outcome.relayed => {
                if outcome.tx_hash != state.transactions[index].transaction_hash {
                    self.last_error =
                        Some("node submission hash did not match persisted transaction".into());
                    return Err(CoreError::SubmissionUncertain);
                }
                state.transactions[index].lifecycle = TransactionLifecycle::Submitted;
                state.transactions[index].submitted = true;
                self.commit(state)?;
                self.transaction_summary(id)
            }
            Ok(outcome) if outcome.accepted => {
                if outcome.tx_hash != state.transactions[index].transaction_hash {
                    self.last_error =
                        Some("node submission hash did not match persisted transaction".into());
                    return Err(CoreError::SubmissionUncertain);
                }
                state.transactions[index].lifecycle = TransactionLifecycle::AcceptedNotRelayed;
                state.transactions[index].submitted = true;
                self.commit(state)?;
                self.transaction_summary(id)
            }
            Ok(_) => {
                state.transactions[index].lifecycle = TransactionLifecycle::Failed;
                self.commit(state)?;
                Err(CoreError::SubmissionRejected)
            }
            Err(error) => {
                // Leave the durably committed SUBMITTING state untouched. A
                // later retry reuses these same canonical bytes.
                self.last_error = Some(CoreError::Chain(error).redacted_message());
                Err(CoreError::SubmissionUncertain)
            }
        }
    }

    pub fn diagnostics(&self) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            application_state: application_state_name(&self.state).into(),
            connection_state: format!("{:?}", self.connection),
            generation: self
                .unlocked
                .as_ref()
                .map(|state| state.generation)
                .or_else(|| {
                    self.metadata
                        .as_ref()
                        .map(|metadata| metadata.active_generation)
                }),
            cursor_height: self
                .unlocked
                .as_ref()
                .and_then(|state| state.cursor.as_ref().map(|cursor| cursor.height)),
            last_error: self.last_error.clone(),
        }
    }

    fn commit(&mut self, state: WalletState) -> Result<(), CoreError> {
        let expected = self.unlocked.as_ref().ok_or(CoreError::Locked)?.generation;
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let password_text = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        let committed = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .commit(expected, state, password_text, self.kdf)?;
        self.metadata = Some(
            self.location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .metadata()?,
        );
        self.unlocked = Some(committed);
        Ok(())
    }

    fn save_rescan_plan(&self, state: &WalletState) -> Result<(), CoreError> {
        let plan = state.rescan_plan.as_ref().ok_or(CoreError::Domain(
            dom_wallet_domain::DomainError::InvalidRescanPlan,
        ))?;
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let password_text = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        self.location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .save_rescan_plan(state, plan, password_text, self.kdf)?;
        Ok(())
    }

    fn stage_activation_generation(&self, state: WalletState) -> Result<WalletState, CoreError> {
        let expected = self.unlocked.as_ref().ok_or(CoreError::Locked)?.generation;
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let password_text = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        self.location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .stage_generation(expected, state, password_text, self.kdf)
            .map_err(CoreError::Storage)
    }

    fn publish_activation_generation(&mut self, state: &WalletState) -> Result<(), CoreError> {
        let expected = self.unlocked.as_ref().ok_or(CoreError::Locked)?.generation;
        let location = self.location.as_ref().ok_or(CoreError::WalletNotOpen)?;
        location.publish_staged_generation(expected, state)?;
        self.metadata = Some(location.metadata()?);
        Ok(())
    }

    fn fail_activating<T>(&mut self, mut active: WalletState) -> Result<T, CoreError> {
        active
            .transition_rescan(dom_wallet_domain::RescanPhase::Failed)
            .map_err(CoreError::Domain)?;
        self.save_rescan_plan(&active)?;
        self.unlocked = Some(active);
        Err(CoreError::Domain(
            dom_wallet_domain::DomainError::InvalidRescanPlan,
        ))
    }

    fn ensure_closed(&self) -> Result<(), CoreError> {
        if self.state == ApplicationState::Closed {
            Ok(())
        } else {
            Err(CoreError::InvalidLifecycleState)
        }
    }
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
        ApplicationState::Unlocked => "UNLOCKED",
        ApplicationState::Synchronizing => "SYNCHRONIZING",
        ApplicationState::Degraded { .. } => "DEGRADED",
        ApplicationState::Error { .. } => "ERROR",
    }
}

fn chain_error_for(error: &CoreError) -> ChainError {
    match error {
        CoreError::Chain(error) => error.clone(),
        _ => ChainError::Transport,
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
    #[error("wallet and node identities differ")]
    IdentityMismatch,
    #[error("transaction input is invalid")]
    InvalidTransactionInput,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("selected outputs have no encrypted spending evidence")]
    UnsupportedSpendingEvidence,
    #[error("transaction fee is below the DOM relay floor")]
    FeeTooLow,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("input is already reserved")]
    ReservationConflict,
    #[error("manual slate transport is invalid")]
    InvalidSlateTransport,
    #[error("manual slate replay conflicts with durable state")]
    SlateReplayConflict,
    #[error("transaction transition is invalid")]
    InvalidTransactionTransition,
    #[error("private transaction context is unavailable")]
    MissingPrivateContext,
    #[error("DOM protocol transaction validation failed")]
    ProtocolRejected,
    #[error("transaction cannot be cancelled after submission evidence")]
    CannotCancelTransaction,
    #[error("explicit confirmation is required")]
    ConfirmationRequired,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("transaction submission was rejected")]
    SubmissionRejected,
    #[error("transaction submission outcome is uncertain")]
    SubmissionUncertain,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Domain(#[from] dom_wallet_domain::DomainError),
}

impl CoreError {
    pub fn redacted_message(&self) -> String {
        match self {
            Self::Locked => "wallet is locked".into(),
            Self::IdentityMismatch => "configured node identity does not match wallet".into(),
            Self::Chain(ChainError::AuthenticationFailed) => "node authentication failed".into(),
            Self::Chain(ChainError::Timeout) => "node request timed out".into(),
            Self::Chain(ChainError::IncompatibleProtocol) => "node protocol is incompatible".into(),
            Self::Storage(_) => "wallet storage operation failed".into(),
            Self::InsufficientFunds => "insufficient spendable funds".into(),
            Self::FeeTooLow => "transaction fee is below the required relay floor".into(),
            Self::SubmissionRejected => "node rejected the finalized transaction".into(),
            Self::SubmissionUncertain => {
                "submission outcome is uncertain; retry the same finalized transaction".into()
            }
            _ => "wallet operation failed".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_chain::MockChainSource;
    use dom_wallet_domain::Network;

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }

    #[test]
    fn create_open_unlock_lock_and_redaction_work() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service
            .create(temp.path().join("wallet"), "password-1", identity())
            .unwrap();
        assert!(matches!(service.summary(), Err(CoreError::Locked)));
        service.unlock("password-1").unwrap();
        assert_eq!(service.summary().unwrap().state, "UNLOCKED");
        service.lock().unwrap();
        assert!(matches!(service.accounts(), Err(CoreError::Locked)));
        assert!(!format!("{:?}", service.diagnostics()).contains("password-1"));
    }

    #[test]
    fn mock_scan_persists_cursor_across_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet");
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service.create(&path, "password-1", identity()).unwrap();
        service.unlock("password-1").unwrap();
        let mut source = MockChainSource::new(identity());
        service
            .synchronize(
                &mut source,
                ScanBounds {
                    start_height: 0,
                    end_height: 0,
                    max_pages: 2,
                    max_records_per_page: 10,
                },
                10,
            )
            .unwrap();
        service.close().unwrap();
        service.open(&path).unwrap();
        service.unlock("password-1").unwrap();
        assert_eq!(service.summary().unwrap().cursor_height, Some(0));
    }

    #[test]
    fn wrong_network_rejected_before_state_activation() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service
            .create(temp.path().join("wallet"), "password-1", identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        let wrong = NetworkIdentity {
            network: Network::Mainnet,
            chain_id: [3; 32],
            genesis_id: [4; 32],
        };
        let mut source = MockChainSource::new(wrong);
        assert!(matches!(
            service.probe(&mut source),
            Err(CoreError::IdentityMismatch)
        ));
    }

    #[test]
    fn full_rescan_preserves_floors_and_old_generation_on_failure() {
        let mut service = WalletService::default();
        let temp = tempfile::tempdir().unwrap();
        service
            .create(temp.path().join("wallet"), "password-1", identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        service.unlocked.as_mut().unwrap().allocate().unwrap();
        let before = service.unlocked.as_ref().unwrap().generation;
        let floors = (
            service.unlocked.as_ref().unwrap().allocation_floor,
            service.unlocked.as_ref().unwrap().non_reuse_floor,
        );
        let mut source = MockChainSource::new(identity());
        source.handshake.tip_height = 1;
        assert!(service
            .full_rescan(
                &mut source,
                ScanBounds {
                    start_height: 0,
                    end_height: 1,
                    max_pages: 2,
                    max_records_per_page: 10
                },
                16
            )
            .is_err());
        assert_eq!(service.unlocked.as_ref().unwrap().generation, before);
        assert_eq!(
            (
                service.unlocked.as_ref().unwrap().allocation_floor,
                service.unlocked.as_ref().unwrap().non_reuse_floor
            ),
            floors
        );
    }

    #[test]
    fn full_rescan_persists_plan_then_atomically_activates() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service
            .create(temp.path().join("wallet"), "password-1", identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        let mut source = MockChainSource::new(identity());
        service
            .full_rescan(
                &mut source,
                ScanBounds {
                    start_height: 0,
                    end_height: 0,
                    max_pages: 1,
                    max_records_per_page: 10,
                },
                16,
            )
            .unwrap();
        let state = service.unlocked.as_ref().unwrap();
        assert_eq!(state.cursor.as_ref().map(|cursor| cursor.height), Some(0));
        assert!(matches!(
            state.rescan_plan.as_ref().map(|plan| &plan.phase),
            Some(dom_wallet_domain::RescanPhase::Complete)
        ));
    }

    fn activating_fixture(service: &mut WalletService, path: &std::path::Path) {
        service.create(path, "password-1", identity()).unwrap();
        service.unlock("password-1").unwrap();
        let mut active = service.unlocked.as_ref().unwrap().clone();
        let target = dom_wallet_domain::ScanTarget {
            target_height: 0,
            target_block_hash: [9; 32],
            source_identity: "mock-dom-node".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 0,
                max_pages: 1,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        active.prepare_rescan(target).unwrap();
        active
            .transition_rescan(dom_wallet_domain::RescanPhase::Scanning)
            .unwrap();
        active
            .transition_rescan(dom_wallet_domain::RescanPhase::ValidatingTarget)
            .unwrap();
        active
            .transition_rescan(dom_wallet_domain::RescanPhase::ReadyToActivate)
            .unwrap();
        active
            .transition_rescan(dom_wallet_domain::RescanPhase::Activating)
            .unwrap();
        service.save_rescan_plan(&active).unwrap();
        service.unlocked = Some(active);
        let mut candidate = service.unlocked.as_ref().unwrap().clone();
        candidate.activate_rescan().unwrap();
        let _ = service.stage_activation_generation(candidate).unwrap();
    }

    #[test]
    fn activating_recovery_publishes_once_then_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet");
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        activating_fixture(&mut service, &path);
        service.recover_activating_rescan().unwrap();
        let first = service.summary().unwrap();
        service.recover_activating_rescan().unwrap();
        assert_eq!(service.summary().unwrap(), first);
        service.close().unwrap();
        service.open(&path).unwrap();
        service.unlock("password-1").unwrap();
        service.recover_activating_rescan().unwrap();
        assert_eq!(service.summary().unwrap(), first);
    }

    #[test]
    fn activating_recovery_fails_closed_when_candidate_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet");
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service.create(&path, "password-1", identity()).unwrap();
        service.unlock("password-1").unwrap();
        let mut active = service.unlocked.as_ref().unwrap().clone();
        let target = dom_wallet_domain::ScanTarget {
            target_height: 0,
            target_block_hash: [9; 32],
            source_identity: "mock-dom-node".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 0,
                max_pages: 1,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        active.prepare_rescan(target).unwrap();
        for phase in [
            dom_wallet_domain::RescanPhase::Scanning,
            dom_wallet_domain::RescanPhase::ValidatingTarget,
            dom_wallet_domain::RescanPhase::ReadyToActivate,
            dom_wallet_domain::RescanPhase::Activating,
        ] {
            active.transition_rescan(phase).unwrap();
        }
        let old_generation = active.generation;
        service.save_rescan_plan(&active).unwrap();
        service.unlocked = Some(active);
        assert!(service.recover_activating_rescan().is_err());
        assert_eq!(
            service.unlocked.as_ref().unwrap().generation,
            old_generation
        );
    }

    #[test]
    fn activating_recovery_after_pointer_publication_is_reopen_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet");
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        activating_fixture(&mut service, &path);
        let plan = service
            .unlocked
            .as_ref()
            .unwrap()
            .rescan_plan
            .clone()
            .unwrap();
        let candidate = service
            .location
            .as_ref()
            .unwrap()
            .load_generation_for_recovery(plan.provisional_generation_id, "password-1")
            .unwrap();
        service
            .location
            .as_ref()
            .unwrap()
            .publish_staged_generation(plan.retained_canonical_generation_id, &candidate)
            .unwrap();
        service.close().unwrap();
        service.open(&path).unwrap();
        service.unlock("password-1").unwrap();
        let before = service.summary().unwrap();
        service.recover_activating_rescan().unwrap();
        assert_eq!(service.summary().unwrap(), before);
        service.recover_activating_rescan().unwrap();
        assert_eq!(service.summary().unwrap(), before);
    }

    #[test]
    fn manual_slate_round_trip_persists_contexts_and_finalizes_authoritatively() {
        use dom_crypto::{bp2_prove, BlindingFactor};

        let temp = tempfile::tempdir().unwrap();
        let sender_path = temp.path().join("sender");
        let recipient_path = temp.path().join("recipient");
        let mut sender = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        let mut recipient = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        sender
            .create(&sender_path, "password-1", identity())
            .unwrap();
        recipient
            .create(&recipient_path, "password-1", identity())
            .unwrap();
        sender.unlock("password-1").unwrap();
        recipient.unlock("password-1").unwrap();

        let blinding = BlindingFactor::from_bytes([7; 32]).unwrap();
        let (_, commitment) = bp2_prove(900_000, &blinding).unwrap();
        let mut funded = sender.unlocked.as_ref().unwrap().clone();
        let output_id = Uuid::new_v4();
        funded.outputs.push(OutputRecord {
            id: output_id,
            account_id: funded.default_account.id,
            commitment: Some(commitment),
            value: 900_000,
            state: OutputState::Confirmed,
            discovered_height: 0,
            reserved_by: None,
        });
        funded.remember_output_blinding(output_id, [7; 32]);
        sender.commit(funded).unwrap();

        let created = sender.transaction_send_create(600_000, None).unwrap();
        let slate_id = created.slate_id.unwrap();
        assert_eq!(created.state, "INPUTS_RESERVED");
        sender.close().unwrap();
        sender.open(&sender_path).unwrap();
        sender.unlock("password-1").unwrap();
        let request = sender.slate_request_export(slate_id).unwrap();
        let imported = recipient.slate_request_import(&request.text).unwrap();
        assert_eq!(imported.state, "REQUEST_IMPORTED");
        recipient.slate_response_create(slate_id).unwrap();
        let response = recipient.slate_response_export(slate_id).unwrap();
        sender.slate_response_import(&response.text).unwrap();
        let finalized = sender.transaction_finalize(slate_id).unwrap();
        assert_eq!(finalized.state, "FINALIZED");
        assert!(finalized.kernel_excess.is_some());
        // The sender's nonce has been consumed and cannot be accidentally
        // reused; a repeat finalize returns the persisted canonical result.
        assert_eq!(sender.transaction_finalize(slate_id).unwrap(), finalized);
        assert!(recipient
            .transaction_detail_redacted(slate_id)
            .unwrap()
            .kernel_excess
            .is_none());
    }

    #[test]
    fn cancellation_releases_only_pre_submission_reservations() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wallet");
        let mut service = WalletService {
            kdf: KdfParameters::TEST,
            ..Default::default()
        };
        service.create(&path, "password-1", identity()).unwrap();
        service.unlock("password-1").unwrap();
        let state = service.unlocked.as_ref().unwrap();
        let slate_id = Uuid::new_v4();
        let transaction_id = Uuid::new_v4();
        let output_id = Uuid::new_v4();
        let mut prepared = state.clone();
        prepared.outputs.push(OutputRecord {
            id: output_id,
            account_id: prepared.default_account.id,
            commitment: Some([3; 33]),
            value: 100,
            state: OutputState::PendingOutgoing,
            discovered_height: 0,
            reserved_by: Some(transaction_id),
        });
        prepared.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Sender),
            amount: 1,
            fee: 1,
            reserved_output_ids: vec![output_id],
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
        });
        service.commit(prepared).unwrap();
        service.transaction_cancel(slate_id, false).unwrap();
        assert!(matches!(
            service
                .unlocked
                .as_ref()
                .unwrap()
                .outputs
                .last()
                .unwrap()
                .state,
            OutputState::Confirmed
        ));
    }
}
