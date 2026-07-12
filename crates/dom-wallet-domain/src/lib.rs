#![forbid(unsafe_code)]

//! Canonical DOM Wallet V3 domain state.
//!
//! This crate intentionally contains no filesystem, network, Tauri, or raw
//! cryptographic implementation. It owns the typed state and invariants that
//! those adapters must preserve.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub const MODEL_VERSION: u16 = 1;
pub const SECRET_PROFILE_VERSION: u16 = 1;
pub const MAX_ACCOUNTS: usize = 64;
pub const MAX_OUTPUTS: usize = 100_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Network {
    PrivateTestnet,
    PublicTestnet,
    Mainnet,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrivateTestnet => "PRIVATE_TESTNET",
            Self::PublicTestnet => "PUBLIC_TESTNET",
            Self::Mainnet => "MAINNET",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub network: Network,
    pub chain_id: [u8; 32],
    pub genesis_id: [u8; 32],
}

impl NetworkIdentity {
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCursor {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanBounds {
    pub start_height: u64,
    pub end_height: u64,
    pub max_pages: u32,
    pub max_records_per_page: u32,
}

impl ScanBounds {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.start_height > self.end_height
            || self.max_pages == 0
            || self.max_records_per_page == 0
        {
            return Err(DomainError::InvalidScanBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanTarget {
    pub target_height: u64,
    pub target_block_hash: [u8; 32],
    pub source_identity: String,
    pub scan_bounds: ScanBounds,
    pub evidence_version: u16,
}

impl ScanTarget {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source_identity.is_empty()
            || self.source_identity.len() > 128
            || self.evidence_version == 0
        {
            return Err(DomainError::InvalidScanTarget);
        }
        if self.target_height != self.scan_bounds.end_height {
            return Err(DomainError::InvalidScanTarget);
        }
        self.scan_bounds.validate()
    }

    pub fn cursor(&self) -> CanonicalCursor {
        CanonicalCursor {
            height: self.target_height,
            block_hash: self.target_block_hash,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Idle,
    Synchronizing,
    Synced,
    Degraded { reason: String },
    RecoveryRequired { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: Uuid,
    pub label: String,
    pub created_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputState {
    Confirmed,
    Immature { required_height: u64 },
    PendingIncoming,
    PendingOutgoing,
    Locked,
    Spent { spent_height: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRecord {
    pub id: Uuid,
    pub account_id: Uuid,
    /// The authoritative local descriptor used for scan ownership matching.
    /// Older encrypted generations did not contain descriptors and therefore
    /// fail closed as unprovable rather than becoming heuristic matches.
    #[serde(default, with = "serde_option_bytes_33")]
    pub commitment: Option<[u8; 33]>,
    pub value: u64,
    pub state: OutputState,
    pub discovered_height: u64,
    /// A reservation is durable wallet evidence, never a chain observation.
    /// It prevents two locally-created slates selecting one canonical output.
    #[serde(default)]
    pub reserved_by: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputOwnership {
    KnownLocalOutput(OutputRecord),
    DeterministicallyRecoverableOutput(OutputRecord),
    NotOwnedOrUnprovable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionLifecycle {
    Draft,
    InputsReserved,
    RequestExported,
    RequestImported,
    ResponsePrepared,
    ResponseExported,
    ResponseImported,
    Finalized,
    Submitting,
    Submitted,
    AcceptedNotRelayed,
    InMempool,
    Confirmed { height: u64, block_hash: [u8; 32] },
    Reorged,
    RetransmitRequired,
    Cancelled,
    Failed,
    ReconciliationRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionRole {
    Sender,
    Recipient,
}

/// Secrets required to continue an interactive DOM slate. This object is
/// encrypted as part of `WalletState`; it is deliberately redacted from Debug
/// so it cannot reach command errors or application logs.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTransactionContext {
    #[serde(default, with = "serde_option_bytes_32")]
    pub sender_excess_blinding: Option<[u8; 32]>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub sender_nonce: Option<[u8; 32]>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub recipient_output_blinding: Option<[u8; 32]>,
}

impl std::fmt::Debug for PrivateTransactionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateTransactionContext(REDACTED)")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOutputBlinding {
    pub output_id: Uuid,
    #[serde(with = "serde_bytes_32")]
    pub blinding: [u8; 32],
}

impl std::fmt::Debug for PrivateOutputBlinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateOutputBlinding(REDACTED)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTransactionIntent {
    pub id: Uuid,
    /// Exactly 33 canonical commitment bytes. This is persisted before an
    /// external submission and is the only kernel-to-wallet association.
    pub kernel_excess: Vec<u8>,
    pub lifecycle: TransactionLifecycle,
    pub submitted: bool,
    /// A protocol-independent identifier carried by the manual transport
    /// envelope. It is not a replacement for the DOM canonical slate bytes.
    #[serde(default)]
    pub slate_id: Option<Uuid>,
    #[serde(default)]
    pub role: Option<TransactionRole>,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub reserved_output_ids: Vec<Uuid>,
    #[serde(default)]
    pub request_bytes: Vec<u8>,
    #[serde(default)]
    pub response_bytes: Vec<u8>,
    #[serde(default)]
    pub finalized_transaction_bytes: Vec<u8>,
    #[serde(default)]
    pub transaction_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub attempt_count: u32,
    #[serde(default)]
    pub private_context: Option<PrivateTransactionContext>,
    #[serde(default)]
    pub recipient_output_id: Option<Uuid>,
    #[serde(default)]
    pub change_output_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RescanPhase {
    Prepared,
    Scanning,
    ValidatingTarget,
    ReadyToActivate,
    Activating,
    Complete,
    Invalidated,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RescanPlan {
    pub version: u16,
    pub plan_id: Uuid,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub source_identity: String,
    pub target: ScanTarget,
    pub recovery_start_height: u64,
    pub next_page: u32,
    pub next_page_height: u64,
    pub provisional_generation_id: u64,
    pub retained_canonical_generation_id: u64,
    pub phase: RescanPhase,
    pub provisional_outputs: Vec<OutputRecord>,
    pub provisional_transactions: Vec<LocalTransactionIntent>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceProjection {
    pub confirmed: u64,
    pub immature: u64,
    pub pending_incoming: u64,
    pub pending_outgoing: u64,
    pub locked: u64,
    pub spendable: u64,
    pub total: u64,
}

impl BalanceProjection {
    pub fn from_outputs(outputs: &[OutputRecord]) -> Self {
        let mut balance = Self::default();
        for output in outputs {
            balance.total = balance.total.saturating_add(output.value);
            match output.state {
                OutputState::Confirmed => {
                    balance.confirmed = balance.confirmed.saturating_add(output.value);
                    balance.spendable = balance.spendable.saturating_add(output.value);
                }
                OutputState::Immature { .. } => {
                    balance.immature = balance.immature.saturating_add(output.value)
                }
                OutputState::PendingIncoming => {
                    balance.pending_incoming = balance.pending_incoming.saturating_add(output.value)
                }
                OutputState::PendingOutgoing => {
                    balance.pending_outgoing = balance.pending_outgoing.saturating_add(output.value)
                }
                OutputState::Locked => balance.locked = balance.locked.saturating_add(output.value),
                OutputState::Spent { .. } => {}
            }
        }
        balance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfiguration {
    pub endpoint_url: String,
    pub expected_identity: NetworkIdentity,
    pub source_identity: String,
    pub api_compatibility_version: u16,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub retry_ceiling: u32,
    pub max_backoff_ms: u64,
    pub stable_success_threshold: u32,
    pub tls_required: bool,
    pub credential_reference: Option<String>,
}

impl NodeConfiguration {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.endpoint_url.is_empty()
            || self.endpoint_url.len() > 2048
            || self.source_identity.is_empty()
            || self.source_identity.len() > 128
            || self.api_compatibility_version == 0
            || self.connect_timeout_ms == 0
            || self.request_timeout_ms == 0
            || self.poll_interval_ms == 0
            || self.retry_ceiling == 0
            || self.max_backoff_ms < self.poll_interval_ms
            || self.stable_success_threshold == 0
        {
            return Err(DomainError::InvalidNodeConfiguration);
        }
        if self.tls_required && !self.endpoint_url.starts_with("https://") {
            return Err(DomainError::TlsRequired);
        }
        if self
            .credential_reference
            .as_ref()
            .is_some_and(|value| value.len() > 256)
        {
            return Err(DomainError::InvalidNodeConfiguration);
        }
        Ok(())
    }

    pub fn redacted(&self) -> RedactedNodeConfiguration {
        RedactedNodeConfiguration {
            endpoint_url: self.endpoint_url.clone(),
            expected_network: self.expected_identity.network,
            source_identity: self.source_identity.clone(),
            api_compatibility_version: self.api_compatibility_version,
            tls_required: self.tls_required,
            has_credential_reference: self.credential_reference.is_some(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedNodeConfiguration {
    pub endpoint_url: String,
    pub expected_network: Network,
    pub source_identity: String,
    pub api_compatibility_version: u16,
    pub tls_required: bool,
    pub has_credential_reference: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletState {
    pub model_version: u16,
    pub secret_profile_version: u16,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub generation: u64,
    pub default_account: Account,
    pub allocation_floor: u64,
    pub non_reuse_floor: u64,
    pub cursor: Option<CanonicalCursor>,
    pub outputs: Vec<OutputRecord>,
    /// Per-output secrets are encrypted in the canonical wallet generation and
    /// are never part of scan, summary, slate transport, or Tauri DTOs.
    #[serde(default)]
    pub private_output_blindings: Vec<PrivateOutputBlinding>,
    #[serde(default)]
    pub transactions: Vec<LocalTransactionIntent>,
    pub sync_status: SyncStatus,
    pub provisional_target: Option<ScanTarget>,
    #[serde(default)]
    pub rescan_plan: Option<RescanPlan>,
    pub node_configuration: NodeConfiguration,
    #[serde(with = "serde_bytes_32")]
    pub root_material: [u8; 32],
}

impl WalletState {
    pub fn new(
        identity: NetworkIdentity,
        root_material: [u8; 32],
        node_configuration: NodeConfiguration,
    ) -> Self {
        let wallet_id = Uuid::new_v4();
        Self {
            model_version: MODEL_VERSION,
            secret_profile_version: SECRET_PROFILE_VERSION,
            wallet_id,
            identity,
            generation: 0,
            default_account: Account {
                id: Uuid::new_v4(),
                label: "Default account".into(),
                created_generation: 0,
            },
            allocation_floor: 0,
            non_reuse_floor: 0,
            cursor: None,
            outputs: Vec::new(),
            private_output_blindings: Vec::new(),
            transactions: Vec::new(),
            sync_status: SyncStatus::Idle,
            provisional_target: None,
            rescan_plan: None,
            node_configuration,
            root_material,
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.model_version != MODEL_VERSION
            || self.secret_profile_version != SECRET_PROFILE_VERSION
        {
            return Err(DomainError::UnsupportedVersion);
        }
        if self.outputs.len() > MAX_OUTPUTS
            || self.default_account.label.is_empty()
            || self.default_account.label.len() > 128
        {
            return Err(DomainError::InvalidState);
        }
        self.node_configuration.validate()?;
        if !self
            .identity
            .matches(&self.node_configuration.expected_identity)
        {
            return Err(DomainError::IdentityMismatch);
        }
        if self.non_reuse_floor < self.allocation_floor {
            return Err(DomainError::NonReuseFloorRegression);
        }
        if let Some(target) = &self.provisional_target {
            target.validate()?;
        }
        for transaction in &self.transactions {
            if (!transaction.kernel_excess.is_empty() && transaction.kernel_excess.len() != 33)
                || (transaction.submitted && transaction.kernel_excess.len() != 33)
            {
                return Err(DomainError::InvalidTransactionIntent);
            }
        }
        if let Some(plan) = &self.rescan_plan {
            if plan.wallet_id != self.wallet_id
                || plan.identity != self.identity
                || plan.target.source_identity != plan.source_identity
                || plan.version != 1
                || plan.next_page_height < plan.recovery_start_height
                || plan.next_page_height > plan.target.scan_bounds.end_height.saturating_add(1)
            {
                return Err(DomainError::InvalidRescanPlan);
            }
        }
        if self
            .outputs
            .iter()
            .any(|output| output.account_id != self.default_account.id)
        {
            return Err(DomainError::InvalidState);
        }
        if self.private_output_blindings.iter().any(|secret| {
            !self
                .outputs
                .iter()
                .any(|output| output.id == secret.output_id)
        }) {
            return Err(DomainError::InvalidState);
        }
        Ok(())
    }

    pub fn allocate(&mut self) -> Result<u64, DomainError> {
        let position = self
            .allocation_floor
            .checked_add(1)
            .ok_or(DomainError::AllocationOverflow)?;
        self.allocation_floor = position;
        self.non_reuse_floor = self.non_reuse_floor.max(position);
        Ok(position)
    }

    pub fn begin_scan(&mut self, target: ScanTarget) -> Result<(), DomainError> {
        target.validate()?;
        self.provisional_target = Some(target);
        self.sync_status = SyncStatus::Synchronizing;
        Ok(())
    }

    pub fn activate_scan(
        &mut self,
        target: &ScanTarget,
        observations: Vec<OutputRecord>,
    ) -> Result<(), DomainError> {
        if self.provisional_target.as_ref() != Some(target) {
            return Err(DomainError::ProvisionalTargetMismatch);
        }
        if observations.len() > MAX_OUTPUTS
            || observations
                .iter()
                .any(|output| output.account_id != self.default_account.id)
        {
            return Err(DomainError::InvalidState);
        }
        self.outputs = observations;
        self.cursor = Some(target.cursor());
        self.provisional_target = None;
        self.sync_status = SyncStatus::Synced;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(DomainError::GenerationOverflow)?;
        self.validate()
    }

    pub fn invalidate_scan(&mut self, reason: impl Into<String>) {
        self.provisional_target = None;
        self.sync_status = SyncStatus::RecoveryRequired {
            reason: reason.into(),
        };
    }

    pub fn balance(&self) -> BalanceProjection {
        BalanceProjection::from_outputs(&self.outputs)
    }

    /// The sole ownership classifier. There is no approved DOM derivation and
    /// value-recovery interface in this foundation, so descriptor equality is
    /// the only positive evidence. Callers that require recovery must treat
    /// `NotOwnedOrUnprovable` as `UnsupportedRecoveryEvidence`.
    pub fn classify_commitment(&self, commitment: &[u8; 33]) -> OutputOwnership {
        self.outputs
            .iter()
            .find(|output| output.commitment.as_ref() == Some(commitment))
            .cloned()
            .map(OutputOwnership::KnownLocalOutput)
            .unwrap_or(OutputOwnership::NotOwnedOrUnprovable)
    }

    pub fn mark_known_output_spent(&mut self, commitment: &[u8; 33], height: u64) -> bool {
        if let Some(output) = self
            .outputs
            .iter_mut()
            .find(|output| output.commitment.as_ref() == Some(commitment))
        {
            output.state = OutputState::Spent {
                spent_height: height,
            };
            return true;
        }
        false
    }

    pub fn output_blinding(&self, output_id: Uuid) -> Option<[u8; 32]> {
        self.private_output_blindings
            .iter()
            .find(|secret| secret.output_id == output_id)
            .map(|secret| secret.blinding)
    }

    pub fn remember_output_blinding(&mut self, output_id: Uuid, blinding: [u8; 32]) {
        if let Some(existing) = self
            .private_output_blindings
            .iter_mut()
            .find(|secret| secret.output_id == output_id)
        {
            existing.blinding = blinding;
        } else {
            self.private_output_blindings.push(PrivateOutputBlinding {
                output_id,
                blinding,
            });
        }
    }

    pub fn apply_kernel_evidence(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        kernels: &[[u8; 33]],
    ) -> Result<(), DomainError> {
        let mut seen = std::collections::BTreeSet::new();
        for kernel in kernels {
            if !seen.insert(*kernel) {
                return Err(DomainError::DuplicateKernelEvidence);
            }
            let matches = self
                .transactions
                .iter()
                .enumerate()
                .filter(|(_, transaction)| {
                    transaction.kernel_excess.as_slice() == kernel.as_slice()
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() > 1 {
                return Err(DomainError::AmbiguousKernelEvidence);
            }
            if let Some(index) = matches.first() {
                let transaction = &mut self.transactions[*index];
                match transaction.lifecycle {
                    TransactionLifecycle::Submitted
                    | TransactionLifecycle::AcceptedNotRelayed
                    | TransactionLifecycle::InMempool
                    | TransactionLifecycle::RetransmitRequired
                    | TransactionLifecycle::Reorged => {
                        transaction.lifecycle =
                            TransactionLifecycle::Confirmed { height, block_hash }
                    }
                    TransactionLifecycle::Confirmed {
                        height: known_height,
                        block_hash: known_hash,
                    } if known_height == height && known_hash == block_hash => {}
                    TransactionLifecycle::Confirmed { .. } => {
                        transaction.lifecycle = TransactionLifecycle::ReconciliationRequired
                    }
                    TransactionLifecycle::ReconciliationRequired
                    | TransactionLifecycle::Draft
                    | TransactionLifecycle::InputsReserved
                    | TransactionLifecycle::RequestExported
                    | TransactionLifecycle::RequestImported
                    | TransactionLifecycle::ResponsePrepared
                    | TransactionLifecycle::ResponseExported
                    | TransactionLifecycle::ResponseImported
                    | TransactionLifecycle::Finalized
                    | TransactionLifecycle::Submitting
                    | TransactionLifecycle::Cancelled
                    | TransactionLifecycle::Failed => {}
                }
            }
        }
        Ok(())
    }

    pub fn rollback_confirmations_for_rescan(&mut self) {
        for transaction in &mut self.transactions {
            if matches!(
                transaction.lifecycle,
                TransactionLifecycle::Confirmed { .. }
            ) {
                transaction.lifecycle = if transaction.submitted {
                    TransactionLifecycle::Submitted
                } else {
                    TransactionLifecycle::Finalized
                };
            }
        }
    }

    pub fn prepare_rescan(&mut self, target: ScanTarget) -> Result<(), DomainError> {
        if self.rescan_plan.is_some() {
            return Err(DomainError::RescanAlreadyActive);
        }
        target.validate()?;
        let mut transactions = self.transactions.clone();
        for transaction in &mut transactions {
            if matches!(
                transaction.lifecycle,
                TransactionLifecycle::Confirmed { .. }
            ) {
                transaction.lifecycle = TransactionLifecycle::Submitted;
            }
        }
        self.rescan_plan = Some(RescanPlan {
            version: 1,
            plan_id: Uuid::new_v4(),
            wallet_id: self.wallet_id,
            identity: self.identity.clone(),
            source_identity: target.source_identity.clone(),
            recovery_start_height: target.scan_bounds.start_height,
            next_page: 0,
            next_page_height: target.scan_bounds.start_height,
            provisional_generation_id: self
                .generation
                .checked_add(1)
                .ok_or(DomainError::GenerationOverflow)?,
            retained_canonical_generation_id: self.generation,
            phase: RescanPhase::Prepared,
            provisional_outputs: self.outputs.clone(),
            provisional_transactions: transactions,
            target,
        });
        Ok(())
    }

    pub fn rescan_plan_mut(&mut self) -> Result<&mut RescanPlan, DomainError> {
        self.rescan_plan
            .as_mut()
            .ok_or(DomainError::InvalidRescanPlan)
    }

    pub fn transition_rescan(&mut self, next: RescanPhase) -> Result<(), DomainError> {
        let plan = self.rescan_plan_mut()?;
        let allowed = matches!(
            (&plan.phase, &next),
            (RescanPhase::Prepared, RescanPhase::Scanning)
                | (RescanPhase::Scanning, RescanPhase::ValidatingTarget)
                | (RescanPhase::ValidatingTarget, RescanPhase::ReadyToActivate)
                | (RescanPhase::ReadyToActivate, RescanPhase::Activating)
                | (RescanPhase::Activating, RescanPhase::Complete)
                | (
                    RescanPhase::Prepared
                        | RescanPhase::Scanning
                        | RescanPhase::ValidatingTarget
                        | RescanPhase::ReadyToActivate
                        | RescanPhase::Activating,
                    RescanPhase::Invalidated | RescanPhase::Failed
                )
        );
        if !allowed {
            return Err(DomainError::InvalidRescanTransition);
        }
        plan.phase = next;
        Ok(())
    }

    /// Advances the durable cursor only after a complete page has been applied
    /// to the provisional state. `next_page_height` is always the first height
    /// not represented by a durable page effect.
    pub fn apply_rescan_page_cursor(
        &mut self,
        page_number: u32,
        start: u64,
        end: u64,
    ) -> Result<(), DomainError> {
        let plan = self.rescan_plan_mut()?;
        if plan.phase != RescanPhase::Scanning
            || page_number != plan.next_page
            || start != plan.next_page_height
            || end < start
            || end > plan.target.target_height
        {
            return Err(DomainError::InvalidRescanPage);
        }
        let next = end.checked_add(1).ok_or(DomainError::InvalidRescanPage)?;
        if next > plan.target.target_height.saturating_add(1) {
            return Err(DomainError::InvalidRescanPage);
        }
        plan.next_page = plan
            .next_page
            .checked_add(1)
            .ok_or(DomainError::InvalidRescanPage)?;
        plan.next_page_height = next;
        if next == plan.target.target_height.saturating_add(1) {
            plan.phase = RescanPhase::ValidatingTarget;
        }
        Ok(())
    }

    pub fn activate_rescan(&mut self) -> Result<(), DomainError> {
        let plan = self
            .rescan_plan
            .take()
            .ok_or(DomainError::InvalidRescanPlan)?;
        if plan.phase != RescanPhase::Activating {
            return Err(DomainError::InvalidRescanPlan);
        }
        self.outputs = plan.provisional_outputs;
        self.transactions = plan.provisional_transactions;
        self.cursor = Some(plan.target.cursor());
        self.sync_status = SyncStatus::Synced;
        Ok(())
    }
}

pub mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
    }
}

pub mod serde_option_bytes_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)?.map_or(Ok(None), |bytes| {
            bytes
                .try_into()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
        })
    }
}

pub mod serde_option_bytes_33 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 33]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)?.map_or(Ok(None), |bytes| {
            bytes
                .try_into()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("expected exactly 33 bytes"))
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("unsupported schema or profile version")]
    UnsupportedVersion,
    #[error("invalid canonical wallet state")]
    InvalidState,
    #[error("invalid node configuration")]
    InvalidNodeConfiguration,
    #[error("TLS is required for the configured endpoint")]
    TlsRequired,
    #[error("wallet and node identity differ")]
    IdentityMismatch,
    #[error("invalid ScanTarget")]
    InvalidScanTarget,
    #[error("invalid scan bounds")]
    InvalidScanBounds,
    #[error("provisional ScanTarget differs from the activation target")]
    ProvisionalTargetMismatch,
    #[error("allocation floor overflow")]
    AllocationOverflow,
    #[error("generation overflow")]
    GenerationOverflow,
    #[error("non-reuse floor regressed")]
    NonReuseFloorRegression,
    #[error("invalid local transaction intent")]
    InvalidTransactionIntent,
    #[error("duplicate kernel evidence")]
    DuplicateKernelEvidence,
    #[error("kernel evidence maps to multiple local transactions")]
    AmbiguousKernelEvidence,
    #[error("invalid rescan plan")]
    InvalidRescanPlan,
    #[error("a rescan is already active")]
    RescanAlreadyActive,
    #[error("invalid rescan phase transition")]
    InvalidRescanTransition,
    #[error("invalid rescan page cursor")]
    InvalidRescanPage,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }

    fn configuration() -> NodeConfiguration {
        NodeConfiguration {
            endpoint_url: "https://node.invalid".into(),
            expected_identity: identity(),
            source_identity: "mock-a".into(),
            api_compatibility_version: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            poll_interval_ms: 10,
            retry_ceiling: 3,
            max_backoff_ms: 100,
            stable_success_threshold: 2,
            tls_required: true,
            credential_reference: Some("environment:DOM_NODE_TOKEN".into()),
        }
    }

    #[test]
    fn allocation_and_non_reuse_floors_are_monotonic() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        assert_eq!(state.allocate().unwrap(), 1);
        assert_eq!(state.allocate().unwrap(), 2);
        assert_eq!(state.non_reuse_floor, 2);
        assert!(state.validate().is_ok());
    }

    #[test]
    fn scan_activation_needs_the_same_provisional_target() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 4,
            target_block_hash: [4; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 4,
                max_pages: 2,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.begin_scan(target.clone()).unwrap();
        let wrong = ScanTarget {
            target_block_hash: [5; 32],
            ..target.clone()
        };
        assert_eq!(
            state.activate_scan(&wrong, Vec::new()),
            Err(DomainError::ProvisionalTargetMismatch)
        );
        state.activate_scan(&target, Vec::new()).unwrap();
        assert_eq!(state.cursor, Some(target.cursor()));
    }

    #[test]
    fn descriptor_ownership_and_spend_are_exact_and_fail_closed() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let commitment = [9; 33];
        state.outputs.push(OutputRecord {
            id: Uuid::new_v4(),
            account_id: state.default_account.id,
            commitment: Some(commitment),
            value: 42,
            state: OutputState::Confirmed,
            discovered_height: 3,
            reserved_by: None,
        });
        assert!(matches!(
            state.classify_commitment(&commitment),
            OutputOwnership::KnownLocalOutput(_)
        ));
        assert_eq!(
            state.classify_commitment(&[8; 33]),
            OutputOwnership::NotOwnedOrUnprovable
        );
        assert!(state.mark_known_output_spent(&commitment, 4));
        assert!(matches!(
            state.outputs[0].state,
            OutputState::Spent { spent_height: 4 }
        ));
    }

    #[test]
    fn kernel_evidence_confirms_only_existing_intent_and_conflicts_reconcile() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        state.transactions.push(LocalTransactionIntent {
            id: Uuid::new_v4(),
            kernel_excess: vec![3; 33],
            lifecycle: TransactionLifecycle::Submitted,
            submitted: true,
            slate_id: None,
            role: None,
            amount: 0,
            fee: 0,
            reserved_output_ids: Vec::new(),
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
        });
        state
            .apply_kernel_evidence(8, [8; 32], &[[3; 33], [4; 33]])
            .unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Confirmed {
                height: 8,
                block_hash: [8; 32]
            }
        );
        state.apply_kernel_evidence(8, [8; 32], &[[3; 33]]).unwrap();
        state.apply_kernel_evidence(9, [9; 32], &[[3; 33]]).unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::ReconciliationRequired
        );
    }

    #[test]
    fn rescan_plan_is_durable_state_until_ready_activation() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 0,
            target_block_hash: [9; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 0,
                max_pages: 1,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.prepare_rescan(target).unwrap();
        assert_eq!(
            state.rescan_plan.as_ref().unwrap().phase,
            RescanPhase::Prepared
        );
        state.transition_rescan(RescanPhase::Scanning).unwrap();
        state
            .transition_rescan(RescanPhase::ValidatingTarget)
            .unwrap();
        state
            .transition_rescan(RescanPhase::ReadyToActivate)
            .unwrap();
        state.transition_rescan(RescanPhase::Activating).unwrap();
        state.activate_rescan().unwrap();
        assert!(state.rescan_plan.is_none());
    }

    #[test]
    fn page_cursor_accepts_only_the_next_complete_page() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 1,
            target_block_hash: [9; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 1,
                max_pages: 2,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.prepare_rescan(target).unwrap();
        state.transition_rescan(RescanPhase::Scanning).unwrap();
        assert!(state.apply_rescan_page_cursor(0, 1, 1).is_err());
        state.apply_rescan_page_cursor(0, 0, 0).unwrap();
        state.apply_rescan_page_cursor(1, 1, 1).unwrap();
        assert_eq!(
            state.rescan_plan.as_ref().unwrap().phase,
            RescanPhase::ValidatingTarget
        );
    }
}
