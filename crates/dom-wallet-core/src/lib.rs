#![forbid(unsafe_code)]

//! Application orchestration. Tauri and CLI code delegate here.

use dom_wallet_chain::{
    acquire_target, collect_provisional_pages, validate_target, ChainError, ChainSource,
    ConnectionState, DomHttpChainSource, LiveNodeProbe, ReconnectController,
};
use dom_wallet_crypto::{KdfParameters, SecretBytes};
use dom_wallet_domain::{
    BalanceProjection, NetworkIdentity, NodeConfiguration, RedactedNodeConfiguration, ScanBounds,
    WalletState,
};
use dom_wallet_storage::{
    default_node_configuration, StorageError, WalletDirectory, WalletMetadata,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

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
            let provisional = pages.iter().flat_map(|page| page.outputs.clone()).collect();
            for page in &pages {
                for block in &page.blocks {
                    state
                        .apply_kernel_evidence(block.height, block.hash, &block.kernel_excesses)
                        .map_err(CoreError::Domain)?;
                    for input in &block.input_commitments {
                        state.mark_known_output_spent(input, block.height);
                    }
                }
            }
            validate_target(source, &state.identity, &target, ancestry_limit)?;
            state
                .activate_scan(&target, provisional)
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
                    .map(|cursor| cursor.height.saturating_add(1))
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
}
