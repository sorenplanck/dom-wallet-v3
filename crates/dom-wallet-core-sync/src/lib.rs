//! Wallet-owned validation and persistence boundary for canonical Core scans.

#![forbid(unsafe_code)]

use dom_wallet_core_api::{
    BlockRef, ChainIdentity, CoinbaseScanMetadata, CoreNetwork, CursorValidation, ScanBlock,
    ScanRequest, ScanResult, ScanStart, WalletCoreApi, WalletCoreError, WalletScanCursor,
    WALLET_SCAN_CURSOR_LEN, WALLET_SCAN_CURSOR_VERSION,
};
use std::{fmt, sync::Arc};
use thiserror::Error;

/// Conservative maximum number of blocks accepted in one Wallet-side batch.
pub const MAX_CORE_SCAN_BATCH_BLOCKS: u64 = 1_024;

/// Wallet-owned chain identity copied from the frozen Core contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreChainIdentity {
    /// Core network.
    pub network: CoreNetwork,
    /// Network magic.
    pub network_magic: u32,
    /// Consensus chain identifier.
    pub chain_id: [u8; 32],
    /// Genesis block hash.
    pub genesis_hash: [u8; 32],
    /// Consensus protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
    /// Coinbase maturity.
    pub coinbase_maturity: u64,
    /// Current canonical tip.
    pub current_tip: CoreBlockReference,
}

/// Wallet-owned canonical block reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreBlockReference {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: [u8; 32],
}

impl From<BlockRef> for CoreBlockReference {
    fn from(value: BlockRef) -> Self {
        Self {
            height: value.height,
            hash: value.hash,
        }
    }
}

/// Exact canonical bytes of a frozen WalletScanCursor v1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoreCursorBytes([u8; WALLET_SCAN_CURSOR_LEN]);

impl CoreCursorBytes {
    /// Parse bytes with the frozen Core decoder and bind them to an identity.
    pub fn parse(bytes: &[u8], identity: &CoreChainIdentity) -> Result<Self, CoreScanError> {
        let cursor = WalletScanCursor::from_bytes(bytes).map_err(CoreScanError::from_core)?;
        validate_cursor_identity(&cursor, identity)?;
        let canonical = cursor.to_bytes();
        Ok(Self(canonical))
    }

    fn from_cursor(
        cursor: WalletScanCursor,
        identity: &CoreChainIdentity,
    ) -> Result<Self, CoreScanError> {
        cursor.validate_shape().map_err(CoreScanError::from_core)?;
        validate_cursor_identity(&cursor, identity)?;
        Ok(Self(cursor.to_bytes()))
    }

    /// Return the exact 86 persisted bytes.
    pub fn as_bytes(&self) -> &[u8; WALLET_SCAN_CURSOR_LEN] {
        &self.0
    }

    /// Decode with the frozen Core decoder.
    pub fn decode(&self) -> Result<WalletScanCursor, CoreScanError> {
        WalletScanCursor::from_bytes(&self.0).map_err(CoreScanError::from_core)
    }
}

impl fmt::Debug for CoreCursorBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreCursorBytes")
            .field("length", &WALLET_SCAN_CURSOR_LEN)
            .finish_non_exhaustive()
    }
}

/// Durable Core cursor state. Legacy custom cursors remain outside this field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PersistedCoreCursorState {
    /// No Core scan has committed yet.
    #[default]
    Absent,
    /// Exact frozen Core cursor bytes.
    Valid(CoreCursorBytes),
    /// Persisted bytes failed canonical decoding or identity validation.
    Invalid,
    /// A previously valid cursor was invalidated by a canonical reorganization.
    ReorgInvalidated(CoreCursorBytes),
}

/// Wallet-owned output projection. Proof and capsule bytes remain public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanOutput {
    /// Output commitment.
    pub commitment: [u8; 33],
    /// Exact 739-byte range proof.
    pub range_proof: Vec<u8>,
    /// Exact public recovery capsule bytes.
    pub recovery_capsule: Vec<u8>,
    /// Recovery capsule version.
    pub recovery_version: u16,
    /// Coinbase marker.
    pub is_coinbase: bool,
    /// Containing block height.
    pub block_height: u64,
    /// Containing block hash.
    pub block_hash: [u8; 32],
    /// Canonical output position in the block projection.
    pub output_position: u32,
}

/// Wallet-owned input projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreScanInput {
    /// Spent commitment.
    pub spent_commitment: [u8; 33],
}

/// Wallet-owned kernel projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanKernel {
    /// Kernel excess.
    pub excess: [u8; 33],
    /// Kernel feature byte.
    pub features: u8,
    /// Fee in noms.
    pub fee: u64,
    /// Absolute lock height.
    pub lock_height: u64,
}

/// Wallet-owned coinbase metadata projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreCoinbaseMetadata {
    /// Coinbase output commitment.
    pub output_commitment: [u8; 33],
    /// Explicit coinbase value.
    pub explicit_value: u64,
    /// Coinbase kernel excess.
    pub kernel_excess: [u8; 33],
}

impl From<CoinbaseScanMetadata> for CoreCoinbaseMetadata {
    fn from(value: CoinbaseScanMetadata) -> Self {
        Self {
            output_commitment: value.output_commitment,
            explicit_value: value.explicit_value,
            kernel_excess: value.kernel_excess,
        }
    }
}

/// Fully validated canonical block projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanBlock {
    /// Height.
    pub height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// Previous block hash.
    pub previous_block_hash: [u8; 32],
    /// Timestamp.
    pub timestamp: u64,
    /// Canonical marker supplied by Core.
    pub canonical_marker: [u8; 32],
    /// Outputs.
    pub outputs: Vec<CoreScanOutput>,
    /// Inputs.
    pub inputs: Vec<CoreScanInput>,
    /// Kernels.
    pub kernels: Vec<CoreScanKernel>,
    /// Coinbase metadata.
    pub coinbase: CoreCoinbaseMetadata,
    /// Total fees.
    pub total_fees_noms: u64,
    /// Protocol version.
    pub protocol_version: u32,
    /// Range-proof serialization version.
    pub range_proof_serialization_version: u8,
}

/// One validated scan page and the cursor that may be committed with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreScanBatch {
    /// Core tip observed for this scan.
    pub observed_tip: CoreBlockReference,
    /// Ascending contiguous canonical blocks.
    pub blocks: Vec<CoreScanBlock>,
    /// Exact cursor bytes. Present whenever at least one block was returned.
    pub commit_cursor: Option<CoreCursorBytes>,
}

/// Result of one atomic reconciliation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreReconcileResult {
    /// No canonical blocks were available to commit.
    NoChanges,
    /// A normal page and cursor committed atomically.
    Committed(CoreCursorBytes),
    /// A reorg rewind, replacement page, and cursor committed atomically.
    ReorgCommitted {
        /// Last locally known anchor that still matches Core.
        safe_anchor: CoreBlockReference,
        /// Replacement cursor.
        cursor: CoreCursorBytes,
    },
}

/// Durable transaction boundary implemented by Wallet state/storage integration.
///
/// Implementations must apply all effects represented by a batch and publish
/// the supplied cursor in one atomic durable transaction. The legacy custom
/// cursor must not be synthesized into or deleted by this interface.
pub trait CoreScanTransactionSink {
    /// Storage-specific error.
    type Error;

    /// Load the separately versioned Core cursor state.
    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error>;

    /// Return a previously committed canonical hash for bounded reorg search.
    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error>;

    /// Atomically apply a normal batch and publish its exact cursor bytes.
    fn commit_core_batch(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error>;

    /// Atomically rewind to `safe_anchor`, apply replacement blocks, and publish
    /// the replacement cursor.
    fn commit_core_reorg(
        &mut self,
        safe_anchor: CoreBlockReference,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error>;
}

/// Typed failures at the Wallet/Core identity and canonical-scan boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreScanError {
    /// Core identity is malformed or unsupported.
    #[error("invalid Core chain identity ({code})")]
    InvalidIdentity { code: &'static str },
    /// Persisted identity conflicts with Core.
    #[error("Core chain identity mismatch ({code})")]
    IdentityMismatch { code: &'static str },
    /// Cursor bytes or shape are invalid.
    #[error("invalid Core cursor ({code})")]
    InvalidCursor { code: &'static str },
    /// Cursor belongs to another network or chain.
    #[error("Core cursor identity mismatch")]
    CursorIdentityMismatch,
    /// Cursor anchor is no longer canonical.
    #[error("Core cursor was invalidated by a reorganization")]
    ReorgDetected,
    /// A scan page violates canonical ordering or continuity.
    #[error("invalid canonical scan page ({code})")]
    InvalidScan { code: &'static str },
    /// Scan request exceeds the Wallet-side bound.
    #[error("invalid scan limit")]
    InvalidScanLimit,
    /// No matching local/Core anchor was found inside the configured bound.
    #[error("reorganization exceeds the configured reconciliation bound")]
    ReorgBeyondBound,
    /// Core is temporarily unavailable.
    #[error("Core is not ready")]
    CoreNotReady,
    /// Core returned a stable contract failure.
    #[error("Core scan contract failed ({code})")]
    CoreContract { code: &'static str },
    /// Wallet persistence failed. No storage text crosses this boundary.
    #[error("Wallet scan transaction failed")]
    Persistence,
}

impl CoreScanError {
    fn from_core(error: WalletCoreError) -> Self {
        match error {
            WalletCoreError::MalformedCursor(_) => Self::InvalidCursor {
                code: "MALFORMED_CURSOR",
            },
            WalletCoreError::CursorChainMismatch(_) => Self::CursorIdentityMismatch,
            WalletCoreError::CursorReorg(_) => Self::ReorgDetected,
            WalletCoreError::CanonicalGap(_) => Self::InvalidScan {
                code: "CANONICAL_GAP",
            },
            WalletCoreError::InvalidScanRequest(_) => Self::InvalidScan {
                code: "REQUEST_REJECTED",
            },
            WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_) => {
                Self::CoreNotReady
            }
            WalletCoreError::InternalFailure(_) => Self::CoreContract {
                code: "CORE_INTERNAL_FAILURE",
            },
            WalletCoreError::SubmissionRejected(_) => Self::CoreContract {
                code: "UNEXPECTED_SUBMISSION_FAILURE",
            },
        }
    }
}

/// Wallet-owned orchestrator over the frozen WalletCoreApi scanner contract.
pub struct CoreChainAdapter {
    api: Arc<dyn WalletCoreApi + Send + Sync>,
    identity: CoreChainIdentity,
    maximum_batch_blocks: u64,
    maximum_reorg_depth: u64,
}

impl fmt::Debug for CoreChainAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreChainAdapter")
            .field("identity", &self.identity)
            .field("maximum_batch_blocks", &self.maximum_batch_blocks)
            .field("maximum_reorg_depth", &self.maximum_reorg_depth)
            .finish_non_exhaustive()
    }
}

impl CoreChainAdapter {
    /// Bind a Wallet scan session to Core identity and optional persisted identity.
    pub fn connect(
        api: Arc<dyn WalletCoreApi + Send + Sync>,
        persisted_identity: Option<&CoreChainIdentity>,
        maximum_batch_blocks: u64,
        maximum_reorg_depth: u64,
    ) -> Result<Self, CoreScanError> {
        validate_scan_limit(maximum_batch_blocks)?;
        let identity = map_identity(api.chain_identity().map_err(CoreScanError::from_core)?)?;
        if let Some(expected) = persisted_identity {
            validate_same_chain(expected, &identity)?;
        }
        Ok(Self {
            api,
            identity,
            maximum_batch_blocks,
            maximum_reorg_depth,
        })
    }

    /// Return the identity that binds this session.
    pub fn identity(&self) -> &CoreChainIdentity {
        &self.identity
    }

    /// Refresh current tip while requiring all immutable identity fields to match.
    pub fn current_identity(&self) -> Result<CoreChainIdentity, CoreScanError> {
        let current = map_identity(
            self.api
                .chain_identity()
                .map_err(CoreScanError::from_core)?,
        )?;
        validate_same_chain(&self.identity, &current)?;
        Ok(current)
    }

    /// Return the current canonical tip through Core identity.
    pub fn current_tip(&self) -> Result<CoreBlockReference, CoreScanError> {
        Ok(self.current_identity()?.current_tip)
    }

    /// Start an unfiltered canonical scan at an explicit height.
    pub fn scan_from_height(
        &self,
        start_height: u64,
        limit: u64,
    ) -> Result<CoreScanBatch, CoreScanError> {
        self.check_limit(limit)?;
        let identity = self.current_identity()?;
        let result = self
            .api
            .scan_range(ScanRequest {
                network: identity.network,
                chain_id: identity.chain_id,
                start: ScanStart::Height(start_height),
                max_blocks: limit,
                stop_height: None,
                commitment_filters: Vec::new(),
            })
            .map_err(CoreScanError::from_core)?;
        self.validate_and_map(result, start_height, None, &identity)
    }

    /// Continue an unfiltered scan from exact persisted cursor bytes.
    pub fn scan_next(
        &self,
        cursor_bytes: CoreCursorBytes,
        limit: u64,
    ) -> Result<CoreScanBatch, CoreScanError> {
        self.check_limit(limit)?;
        let identity = self.current_identity()?;
        let cursor = cursor_bytes.decode()?;
        validate_cursor_identity(&cursor, &identity)?;
        self.validate_cursor(cursor_bytes)?;
        let result = self
            .api
            .scan_next(cursor, limit)
            .map_err(CoreScanError::from_core)?;
        self.validate_and_map(
            result,
            cursor.next_height,
            Some(CoreBlockReference {
                height: cursor.anchor_height,
                hash: cursor.anchor_hash,
            }),
            &identity,
        )
    }

    /// Validate exact cursor bytes against current canonical Core state.
    pub fn validate_cursor(
        &self,
        cursor_bytes: CoreCursorBytes,
    ) -> Result<CoreBlockReference, CoreScanError> {
        let cursor = cursor_bytes.decode()?;
        validate_cursor_identity(&cursor, &self.identity)?;
        let validation = self
            .api
            .validate_cursor(cursor)
            .map_err(CoreScanError::from_core)?;
        validate_cursor_result(cursor, validation)
    }

    /// Look up the canonical hash at a height through Core.
    pub fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, CoreScanError> {
        self.api
            .canonical_hash_at_height(height)
            .map_err(CoreScanError::from_core)
    }

    /// Validate, scan, and atomically commit one normal or reorg page.
    pub fn reconcile_once<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        match sink
            .core_cursor_state()
            .map_err(|_| CoreScanError::Persistence)?
        {
            PersistedCoreCursorState::Absent => {
                let identity = self.current_identity()?;
                let genesis_hash =
                    self.canonical_hash_at_height(0)?
                        .ok_or(CoreScanError::InvalidScan {
                            code: "MISSING_CANONICAL_GENESIS",
                        })?;
                if genesis_hash != identity.genesis_hash {
                    return Err(CoreScanError::InvalidScan {
                        code: "GENESIS_HASH_DISAGREEMENT",
                    });
                }
                let batch = if identity.current_tip.height == 0 {
                    if genesis_hash != identity.current_tip.hash {
                        return Err(CoreScanError::InvalidScan {
                            code: "TIP_GENESIS_DISAGREEMENT",
                        });
                    }
                    let cursor = WalletScanCursor::new(
                        identity.network,
                        identity.chain_id,
                        1,
                        BlockRef {
                            height: 0,
                            hash: identity.current_tip.hash,
                        },
                    );
                    let cursor = CoreCursorBytes::from_cursor(cursor, &identity)?;
                    self.validate_cursor(cursor)?;
                    CoreScanBatch {
                        observed_tip: identity.current_tip,
                        blocks: Vec::new(),
                        commit_cursor: Some(cursor),
                    }
                } else {
                    self.scan_from_height(1, self.maximum_batch_blocks)?
                };
                self.commit_normal(sink, batch)
            }
            PersistedCoreCursorState::Valid(cursor) => match self.validate_cursor(cursor) {
                Ok(_) => {
                    let batch = self.scan_next(cursor, self.maximum_batch_blocks)?;
                    self.commit_normal(sink, batch)
                }
                Err(CoreScanError::ReorgDetected) => self.reconcile_reorg(sink, cursor),
                Err(error) => Err(error),
            },
            PersistedCoreCursorState::ReorgInvalidated(cursor) => {
                self.reconcile_reorg(sink, cursor)
            }
            PersistedCoreCursorState::Invalid => Err(CoreScanError::InvalidCursor {
                code: "PERSISTED_CURSOR_INVALID",
            }),
        }
    }

    /// Reconcile canonical pages until the committed cursor reaches the observed tip.
    pub fn reconcile_to_tip<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        let target_height = self.current_tip()?.height;
        loop {
            let result = self.reconcile_once(sink)?;
            let cursor = match result {
                CoreReconcileResult::Committed(cursor)
                | CoreReconcileResult::ReorgCommitted { cursor, .. } => cursor,
                CoreReconcileResult::NoChanges => {
                    return Err(CoreScanError::InvalidScan {
                        code: "SCAN_STALLED_BEFORE_TARGET",
                    });
                }
            };
            if cursor.decode()?.anchor_height >= target_height {
                return Ok(result);
            }
        }
    }

    fn commit_normal<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
        batch: CoreScanBatch,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        let Some(cursor) = batch.commit_cursor else {
            return Ok(CoreReconcileResult::NoChanges);
        };
        sink.commit_core_batch(&batch, cursor)
            .map_err(|_| CoreScanError::Persistence)?;
        Ok(CoreReconcileResult::Committed(cursor))
    }

    fn reconcile_reorg<S: CoreScanTransactionSink>(
        &self,
        sink: &mut S,
        invalid_cursor: CoreCursorBytes,
    ) -> Result<CoreReconcileResult, CoreScanError> {
        let cursor = invalid_cursor.decode()?;
        let safe_anchor = self.find_safe_anchor(sink, cursor.anchor_height)?;
        let start_height =
            safe_anchor
                .height
                .checked_add(1)
                .ok_or(CoreScanError::InvalidCursor {
                    code: "ANCHOR_HEIGHT_OVERFLOW",
                })?;
        let batch = self.scan_from_height(start_height, self.maximum_batch_blocks)?;
        let Some(replacement) = batch.commit_cursor else {
            return Err(CoreScanError::InvalidScan {
                code: "REORG_REPLACEMENT_EMPTY",
            });
        };
        sink.commit_core_reorg(safe_anchor, &batch, replacement)
            .map_err(|_| CoreScanError::Persistence)?;
        Ok(CoreReconcileResult::ReorgCommitted {
            safe_anchor,
            cursor: replacement,
        })
    }

    fn find_safe_anchor<S: CoreScanTransactionSink>(
        &self,
        sink: &S,
        invalid_height: u64,
    ) -> Result<CoreBlockReference, CoreScanError> {
        let lowest = invalid_height.saturating_sub(self.maximum_reorg_depth);
        for height in (lowest..invalid_height).rev() {
            let local = sink
                .committed_canonical_hash(height)
                .map_err(|_| CoreScanError::Persistence)?;
            let core = self.canonical_hash_at_height(height)?;
            if let (Some(local_hash), Some(core_hash)) = (local, core) {
                if local_hash == core_hash && core_hash != [0u8; 32] {
                    return Ok(CoreBlockReference {
                        height,
                        hash: core_hash,
                    });
                }
            }
        }
        Err(CoreScanError::ReorgBeyondBound)
    }

    fn check_limit(&self, limit: u64) -> Result<(), CoreScanError> {
        validate_scan_limit(limit)?;
        if limit > self.maximum_batch_blocks {
            return Err(CoreScanError::InvalidScanLimit);
        }
        Ok(())
    }

    fn validate_and_map(
        &self,
        result: ScanResult,
        expected_start: u64,
        previous_anchor: Option<CoreBlockReference>,
        identity: &CoreChainIdentity,
    ) -> Result<CoreScanBatch, CoreScanError> {
        if result.blocks.len() as u64 > self.maximum_batch_blocks {
            return Err(CoreScanError::InvalidScan {
                code: "BATCH_TOO_LARGE",
            });
        }
        if result.tip.hash == [0u8; 32] {
            return Err(CoreScanError::InvalidScan {
                code: "ZERO_TIP_HASH",
            });
        }
        let canonical_tip = self.canonical_hash_at_height(result.tip.height)?;
        if canonical_tip != Some(result.tip.hash) {
            return Err(CoreScanError::InvalidScan {
                code: "TIP_HASH_DISAGREEMENT",
            });
        }

        let expected_previous = if expected_start == 0 {
            [0u8; 32]
        } else if let Some(anchor) = previous_anchor {
            if anchor.height.checked_add(1) != Some(expected_start) {
                return Err(CoreScanError::InvalidScan {
                    code: "START_ANCHOR_GAP",
                });
            }
            anchor.hash
        } else {
            self.canonical_hash_at_height(expected_start - 1)?.ok_or(
                CoreScanError::InvalidScan {
                    code: "MISSING_PREVIOUS_HASH",
                },
            )?
        };

        let mut mapped = Vec::with_capacity(result.blocks.len());
        let mut next_height = expected_start;
        let mut previous_hash = expected_previous;
        for block in result.blocks {
            if block.height != next_height {
                return Err(CoreScanError::InvalidScan {
                    code: "NONCONTIGUOUS_HEIGHT",
                });
            }
            if block.previous_block_hash != previous_hash {
                return Err(CoreScanError::InvalidScan {
                    code: "PREVIOUS_HASH_MISMATCH",
                });
            }
            let mapped_block = map_block(block, identity)?;
            previous_hash = mapped_block.block_hash;
            next_height = next_height
                .checked_add(1)
                .ok_or(CoreScanError::InvalidScan {
                    code: "HEIGHT_OVERFLOW",
                })?;
            mapped.push(mapped_block);
        }

        let commit_cursor = match mapped.last() {
            None => {
                if result.continuation.is_some() {
                    return Err(CoreScanError::InvalidScan {
                        code: "CURSOR_WITHOUT_BLOCKS",
                    });
                }
                if expected_start == 0 && result.tip.height == 0 {
                    let cursor = WalletScanCursor::new(
                        identity.network,
                        identity.chain_id,
                        1,
                        BlockRef {
                            height: 0,
                            hash: result.tip.hash,
                        },
                    );
                    let bytes = CoreCursorBytes::from_cursor(cursor, identity)?;
                    self.validate_cursor(bytes)?;
                    Some(bytes)
                } else {
                    None
                }
            }
            Some(last) => {
                let cursor = if let Some(cursor) = result.continuation {
                    if last.height >= result.tip.height {
                        return Err(CoreScanError::InvalidScan {
                            code: "CURSOR_PAST_TIP",
                        });
                    }
                    cursor
                } else {
                    if last.height < result.tip.height {
                        return Err(CoreScanError::InvalidScan {
                            code: "MISSING_CONTINUATION",
                        });
                    }
                    WalletScanCursor::new(
                        identity.network,
                        identity.chain_id,
                        last.height
                            .checked_add(1)
                            .ok_or(CoreScanError::InvalidScan {
                                code: "HEIGHT_OVERFLOW",
                            })?,
                        BlockRef {
                            height: last.height,
                            hash: last.block_hash,
                        },
                    )
                };
                if cursor.next_height != last.height.saturating_add(1)
                    || cursor.anchor_height != last.height
                    || cursor.anchor_hash != last.block_hash
                {
                    return Err(CoreScanError::InvalidScan {
                        code: "CONTINUATION_REGRESSION",
                    });
                }
                let bytes = CoreCursorBytes::from_cursor(cursor, identity)?;
                self.validate_cursor(bytes)?;
                Some(bytes)
            }
        };

        Ok(CoreScanBatch {
            observed_tip: result.tip.into(),
            blocks: mapped,
            commit_cursor,
        })
    }
}

fn validate_scan_limit(limit: u64) -> Result<(), CoreScanError> {
    if limit == 0 || limit > MAX_CORE_SCAN_BATCH_BLOCKS {
        Err(CoreScanError::InvalidScanLimit)
    } else {
        Ok(())
    }
}

fn map_identity(identity: ChainIdentity) -> Result<CoreChainIdentity, CoreScanError> {
    if identity.network.magic() != identity.network_magic {
        return Err(CoreScanError::InvalidIdentity {
            code: "NETWORK_MAGIC_MISMATCH",
        });
    }
    if identity.chain_id == [0u8; 32] {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_CHAIN_ID",
        });
    }
    // Frozen pre-launch Core intentionally retains the configured zero genesis
    // constant on regtest so chain-ID and kernel-signature derivation agree.
    // The live canonical genesis is still bound below through the nonzero tip
    // and canonical-hash checks. Real networks must never accept a zero value.
    if identity.genesis_hash == [0u8; 32] && identity.network != CoreNetwork::Regtest {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_GENESIS_HASH",
        });
    }
    if identity.protocol_version != dom_core::PROTOCOL_VERSION {
        return Err(CoreScanError::InvalidIdentity {
            code: "UNSUPPORTED_PROTOCOL_VERSION",
        });
    }
    if identity.range_proof_serialization_version != dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION {
        return Err(CoreScanError::InvalidIdentity {
            code: "UNSUPPORTED_RANGE_PROOF_VERSION",
        });
    }
    if identity.current_tip.hash == [0u8; 32] {
        return Err(CoreScanError::InvalidIdentity {
            code: "ZERO_TIP_HASH",
        });
    }
    Ok(CoreChainIdentity {
        network: identity.network,
        network_magic: identity.network_magic,
        chain_id: identity.chain_id,
        genesis_hash: identity.genesis_hash,
        protocol_version: identity.protocol_version,
        range_proof_serialization_version: identity.range_proof_serialization_version,
        coinbase_maturity: identity.coinbase_maturity,
        current_tip: identity.current_tip.into(),
    })
}

fn validate_same_chain(
    expected: &CoreChainIdentity,
    actual: &CoreChainIdentity,
) -> Result<(), CoreScanError> {
    if expected.network != actual.network {
        return Err(CoreScanError::IdentityMismatch { code: "NETWORK" });
    }
    if expected.network_magic != actual.network_magic {
        return Err(CoreScanError::IdentityMismatch {
            code: "NETWORK_MAGIC",
        });
    }
    if expected.chain_id != actual.chain_id {
        return Err(CoreScanError::IdentityMismatch { code: "CHAIN_ID" });
    }
    if expected.genesis_hash != actual.genesis_hash {
        return Err(CoreScanError::IdentityMismatch {
            code: "GENESIS_HASH",
        });
    }
    if expected.protocol_version != actual.protocol_version {
        return Err(CoreScanError::IdentityMismatch {
            code: "PROTOCOL_VERSION",
        });
    }
    if expected.range_proof_serialization_version != actual.range_proof_serialization_version {
        return Err(CoreScanError::IdentityMismatch {
            code: "RANGE_PROOF_VERSION",
        });
    }
    if expected.coinbase_maturity != actual.coinbase_maturity {
        return Err(CoreScanError::IdentityMismatch {
            code: "COINBASE_MATURITY",
        });
    }
    Ok(())
}

fn validate_cursor_identity(
    cursor: &WalletScanCursor,
    identity: &CoreChainIdentity,
) -> Result<(), CoreScanError> {
    if cursor.version != WALLET_SCAN_CURSOR_VERSION {
        return Err(CoreScanError::InvalidCursor {
            code: "UNSUPPORTED_VERSION",
        });
    }
    if cursor.network_magic != identity.network_magic || cursor.chain_id != identity.chain_id {
        return Err(CoreScanError::CursorIdentityMismatch);
    }
    if cursor.anchor_hash == [0u8; 32] {
        return Err(CoreScanError::InvalidCursor {
            code: "ZERO_ANCHOR_HASH",
        });
    }
    Ok(())
}

fn validate_cursor_result(
    cursor: WalletScanCursor,
    validation: CursorValidation,
) -> Result<CoreBlockReference, CoreScanError> {
    if !validation.valid
        || validation.safe_rescan_anchor.height != cursor.anchor_height
        || validation.safe_rescan_anchor.hash != cursor.anchor_hash
    {
        return Err(CoreScanError::ReorgDetected);
    }
    Ok(validation.safe_rescan_anchor.into())
}

fn map_block(
    block: ScanBlock,
    identity: &CoreChainIdentity,
) -> Result<CoreScanBlock, CoreScanError> {
    if block.block_hash == [0u8; 32] || block.canonical_marker != block.block_hash {
        return Err(CoreScanError::InvalidScan {
            code: "NONCANONICAL_BLOCK",
        });
    }
    if block.protocol_version != identity.protocol_version {
        return Err(CoreScanError::InvalidScan {
            code: "PROTOCOL_VERSION",
        });
    }
    if block.range_proof_serialization_version != identity.range_proof_serialization_version {
        return Err(CoreScanError::InvalidScan {
            code: "RANGE_PROOF_VERSION",
        });
    }
    let mut outputs = Vec::with_capacity(block.outputs.len());
    for output in block.outputs {
        if output.block_height != block.height || output.block_hash != block.block_hash {
            return Err(CoreScanError::InvalidScan {
                code: "OUTPUT_BLOCK_CONTEXT",
            });
        }
        if output.range_proof.len() != dom_crypto::RANGE_PROOF_SIZE {
            return Err(CoreScanError::InvalidScan {
                code: "RANGE_PROOF_LENGTH",
            });
        }
        match (output.recovery_version, output.recovery_capsule.len()) {
            (0, 0) => {}
            (
                dom_crypto::recovery::RECOVERY_VERSION,
                dom_crypto::recovery::RECOVERY_CAPSULE_SIZE,
            ) => {}
            _ => {
                return Err(CoreScanError::InvalidScan {
                    code: "RECOVERY_CAPSULE_FORMAT",
                })
            }
        }
        outputs.push(CoreScanOutput {
            commitment: output.commitment,
            range_proof: output.range_proof,
            recovery_capsule: output.recovery_capsule,
            recovery_version: output.recovery_version,
            is_coinbase: output.is_coinbase,
            block_height: output.block_height,
            block_hash: output.block_hash,
            output_position: output.output_position,
        });
    }
    Ok(CoreScanBlock {
        height: block.height,
        block_hash: block.block_hash,
        previous_block_hash: block.previous_block_hash,
        timestamp: block.timestamp,
        canonical_marker: block.canonical_marker,
        outputs,
        inputs: block
            .inputs
            .into_iter()
            .map(|input| CoreScanInput {
                spent_commitment: input.spent_commitment,
            })
            .collect(),
        kernels: block
            .kernels
            .into_iter()
            .map(|kernel| CoreScanKernel {
                excess: kernel.excess,
                features: kernel.features,
                fee: kernel.fee,
                lock_height: kernel.lock_height,
            })
            .collect(),
        coinbase: block.coinbase.into(),
        total_fees_noms: block.total_fees_noms,
        protocol_version: block.protocol_version,
        range_proof_serialization_version: block.range_proof_serialization_version,
    })
}
