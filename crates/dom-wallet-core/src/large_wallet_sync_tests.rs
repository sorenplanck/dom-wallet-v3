//! End-to-end regression for the Mainnet report "canonical height 51795,
//! wallet cursor 43264": the real `WalletService::synchronize_live` path
//! (full-fidelity scanner, `WalletRecoverySink`, `apply_recovery_batch`,
//! `WalletDirectory`) over a fake Core that serves valid canonical blocks.
//!
//! Cursor 43264 is a 256-block page boundary, so the next page is exactly
//! 43265..=43520. The page carries 256 coinbase outputs genuinely owned by the
//! wallet seed; the wallet already holds enough outputs that, in the legacy
//! envelope, this page can never be committed.

use super::*;
use dom_consensus::{Block, CoinbaseTransaction};
use dom_core::{BlockHeight, Hash256, Timestamp};
use dom_serialization::DomSerialize;
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeePolicySnapshot,
    FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock, ScanKernel, ScanOutput,
    ScanRequest, ScanResult, ScanStart, SubmissionResult, SubmitTransactionRequest, SyncStatus,
    TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError,
};
use dom_wallet_core_recovery::RecoverableOutputBuilder;
use dom_wallet_crypto::LEGACY_V1_MAX_ENVELOPE_BYTES;
use dom_wallet_domain::{
    OutputState, PrivateOutputBlinding, RecoveredOutputDomain, RecoveredOutputMetadata,
    RecoveryCanonicalBlock, RecoveryOutputClass,
};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

const PASSWORD: &str = "large-wallet-regression-password";
const CHAIN_ID: [u8; 32] = [8; 32];
const CURSOR: u64 = 43_264;
const FIRST_PAGE_END: u64 = 43_520;
const TIP: u64 = 43_776;
const WINDOW: u64 = 2_048;

fn network_magic() -> u32 {
    CoreNetwork::Regtest.magic()
}

fn genesis_template() -> &'static Block {
    static GENESIS: OnceLock<Block> = OnceLock::new();
    GENESIS.get_or_init(|| {
        dom_chain::build_canonical_genesis(network_magic(), &CHAIN_ID)
            .expect("regtest genesis")
            .block
            .expect("regtest genesis block")
    })
}

/// Deterministic synthetic hash for the unscanned prefix of the chain.
fn prefix_hash(height: u64) -> [u8; 32] {
    let mut hash = [0x5a; 32];
    hash[..8].copy_from_slice(&height.to_le_bytes());
    hash[31] = 0x01;
    hash
}

fn scan_output(
    output: &dom_consensus::TransactionOutput,
    height: u64,
    hash: [u8; 32],
) -> ScanOutput {
    let capsule = output.recovery_capsule().expect("capsule envelope");
    ScanOutput {
        commitment: *output.commitment.as_bytes(),
        range_proof: output.range_proof_bytes().expect("range proof").to_vec(),
        recovery_capsule: capsule
            .as_ref()
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default(),
        recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
        is_coinbase: true,
        block_height: height,
        block_hash: hash,
        output_position: 0,
    }
}

const SPEND_HEIGHT: u64 = 43_600;

fn transaction_output_projection(
    output: &dom_consensus::TransactionOutput,
    height: u64,
    hash: [u8; 32],
    position: u32,
) -> ScanOutput {
    ScanOutput {
        is_coinbase: false,
        output_position: position,
        ..scan_output(output, height, hash)
    }
}

/// A valid canonical block (coinbase plus optional transactions) projected
/// exactly like Core's full-fidelity scanner does.
fn canonical_block(
    height: u64,
    previous_hash: [u8; 32],
    coinbase: CoinbaseTransaction,
    transactions: Vec<dom_consensus::Transaction>,
) -> ScanBlock {
    let mut block = genesis_template().clone();
    block.coinbase = coinbase;
    block.transactions = transactions;
    block.header.version = dom_core::required_block_version_for_network(network_magic(), height);
    block.header.height = BlockHeight(height);
    block.header.prev_hash = Hash256::from_bytes(previous_hash);
    block.header.timestamp = Timestamp(1_700_000_000 + height * 120);
    block.header.total_kernel_offset = block
        .transactions
        .first()
        .map_or([0u8; 32], |transaction| transaction.offset);
    let (output_root, kernel_root, rangeproof_root) = dom_consensus::compute_block_pmmr_roots(
        BlockHeight(height),
        &block.coinbase,
        &block.transactions,
    )
    .expect("block roots");
    block.header.output_root = output_root;
    block.header.kernel_root = kernel_root;
    block.header.rangeproof_root = rangeproof_root;
    let header_bytes = block.header.to_bytes().expect("header bytes");
    let hash = *dom_chain::canonical_header_identifier(network_magic(), &header_bytes)
        .expect("header id")
        .as_bytes();
    let coinbase_kernel = ScanKernel {
        excess: *block.coinbase.kernel.excess.as_bytes(),
        features: block.coinbase.kernel.features,
        fee: 0,
        lock_height: 0,
        excess_signature: block.coinbase.kernel.excess_signature,
    };
    let mut outputs = vec![scan_output(&block.coinbase.output, height, hash)];
    let mut inputs = Vec::new();
    let mut kernels = vec![coinbase_kernel];
    let mut projected = Vec::new();
    let mut position = 1u32;
    for (index, transaction) in block.transactions.iter().enumerate() {
        let bytes = transaction.to_bytes().expect("transaction bytes");
        let tx_inputs: Vec<_> = transaction
            .inputs
            .iter()
            .map(|input| dom_wallet_core_api::ScanInput {
                spent_commitment: *input.commitment.as_bytes(),
            })
            .collect();
        let tx_outputs: Vec<_> = transaction
            .outputs
            .iter()
            .map(|output| {
                let projection = transaction_output_projection(output, height, hash, position);
                position += 1;
                projection
            })
            .collect();
        let tx_kernels: Vec<_> = transaction
            .kernels
            .iter()
            .map(|kernel| ScanKernel {
                excess: *kernel.excess.as_bytes(),
                features: kernel.features,
                fee: kernel.fee.noms(),
                lock_height: kernel.lock_height,
                excess_signature: kernel.excess_signature,
            })
            .collect();
        inputs.extend(tx_inputs.clone());
        outputs.extend(tx_outputs.clone());
        kernels.extend(tx_kernels.clone());
        projected.push(dom_wallet_core_api::ScanTransaction {
            location: dom_wallet_core_api::TransactionLocation {
                block_height: height,
                block_hash: hash,
                transaction_index: index as u32,
            },
            tx_hash: *dom_crypto::blake2b_256(&bytes).as_bytes(),
            canonical_bytes: bytes,
            inputs: tx_inputs,
            outputs: tx_outputs,
            kernels: tx_kernels,
            offset: transaction.offset,
        });
    }
    ScanBlock {
        height,
        block_hash: hash,
        previous_block_hash: previous_hash,
        canonical_header_bytes: header_bytes,
        timestamp: block.header.timestamp.0,
        canonical_marker: hash,
        outputs,
        inputs,
        kernels,
        transactions: projected,
        coinbase: CoinbaseScanMetadata {
            output_commitment: *block.coinbase.output.commitment.as_bytes(),
            explicit_value: block.coinbase.kernel.explicit_value,
            kernel_excess: *block.coinbase.kernel.excess.as_bytes(),
            kernel_features: block.coinbase.kernel.features,
            kernel_excess_signature: block.coinbase.kernel.excess_signature,
            offset: block.coinbase.offset,
            output_proof_envelope: block.coinbase.output.proof.clone(),
        },
        total_fees_noms: block.total_fees().expect("fees"),
        protocol_version: block.header.version,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
    }
}

/// A recoverable output owned by an unrelated seed (never ours).
fn foreign_output() -> dom_consensus::TransactionOutput {
    let identity = CoreChainIdentity {
        network: CoreNetwork::Regtest,
        network_magic: network_magic(),
        chain_id: CHAIN_ID,
        genesis_hash: [0x11; 32],
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 1,
        current_tip: dom_wallet_core_sync::CoreBlockReference {
            height: 0,
            hash: [0x11; 32],
        },
    };
    let seed = CanonicalWalletSeed::from_entropy(&[0x33; 32]).expect("foreign seed");
    let builder = RecoverableOutputBuilder::new(&seed, &identity).expect("builder");
    let mut state = WalletState::new(
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: CHAIN_ID,
            genesis_id: [0x11; 32],
        },
        [0x33; 32],
        default_node_configuration(NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: CHAIN_ID,
            genesis_id: [0x11; 32],
        }),
    );
    let coordinate = state
        .reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)
        .expect("coordinate");
    builder
        .build_coinbase(BlockHeight(SPEND_HEIGHT), 0, coordinate)
        .expect("foreign output")
        .output
}

/// A transaction spending `spent` (validity of signatures and balance is
/// Core's job; the wallet scanner checks projection fidelity and roots).
fn spend_transaction(spent: &dom_consensus::TransactionOutput) -> dom_consensus::Transaction {
    let mut offset = [0u8; 32];
    offset[31] = 7;
    dom_consensus::Transaction {
        inputs: vec![dom_consensus::TransactionInput {
            commitment: spent.commitment.clone(),
        }],
        outputs: vec![foreign_output()],
        kernels: vec![dom_consensus::TransactionKernel {
            features: dom_core::KERNEL_FEAT_PLAIN,
            fee: dom_core::Amount::from_noms(1_000).expect("fee"),
            lock_height: 0,
            excess: genesis_template().coinbase.kernel.excess.clone(),
            excess_signature: [0x42; 65],
        }],
        offset,
    }
}

struct FakeChainState {
    identity: ChainIdentity,
    /// Canonical hash of every height 0..=TIP.
    hashes: Vec<[u8; 32]>,
    /// Full blocks for the heights the wallet will scan.
    blocks: BTreeMap<u64, ScanBlock>,
    scan_calls: u64,
}

#[derive(Clone)]
struct FakeChain(Arc<Mutex<FakeChainState>>);

impl FakeChain {
    /// `owned_first_page` supplies the coinbases of 43265..=43520; the second
    /// page 43521..=43776 carries unowned coinbases.
    fn new(owned_first_page: Vec<CoinbaseTransaction>) -> Self {
        let mut hashes: Vec<[u8; 32]> = (0..=CURSOR).map(prefix_hash).collect();
        let mut blocks = BTreeMap::new();
        // The second page spends the first owned coinbase of the first page.
        let spent_source = owned_first_page
            .first()
            .map(|coinbase| coinbase.output.clone());
        let mut owned = owned_first_page.into_iter();
        for height in CURSOR + 1..=TIP {
            let coinbase = if height <= FIRST_PAGE_END {
                owned
                    .next()
                    .unwrap_or_else(|| genesis_template().coinbase.clone())
            } else {
                genesis_template().coinbase.clone()
            };
            let transactions = if height == SPEND_HEIGHT {
                spent_source
                    .as_ref()
                    .map(|output| vec![spend_transaction(output)])
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let block = canonical_block(
                height,
                hashes[(height - 1) as usize],
                coinbase,
                transactions,
            );
            hashes.push(block.block_hash);
            blocks.insert(height, block);
        }
        let identity = ChainIdentity {
            network: CoreNetwork::Regtest,
            network_magic: network_magic(),
            chain_id: CHAIN_ID,
            genesis_hash: hashes[0],
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
            coinbase_maturity: 1,
            current_tip: BlockRef {
                height: TIP,
                hash: hashes[TIP as usize],
            },
        };
        Self(Arc::new(Mutex::new(FakeChainState {
            identity,
            hashes,
            blocks,
            scan_calls: 0,
        })))
    }

    fn hash(&self, height: u64) -> [u8; 32] {
        self.0.lock().expect("fake chain").hashes[height as usize]
    }

    fn scan_calls(&self) -> u64 {
        self.0.lock().expect("fake chain").scan_calls
    }
}

fn check_anchor(state: &FakeChainState, cursor: &WalletScanCursor) -> Result<(), WalletCoreError> {
    cursor.validate_shape()?;
    if state.hashes.get(cursor.anchor_height as usize) != Some(&cursor.anchor_hash) {
        return Err(WalletCoreError::CursorReorg("anchor".into()));
    }
    Ok(())
}

impl WalletCoreApi for FakeChain {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        Ok(self.0.lock().expect("fake chain").identity.clone())
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        let mut state = self.0.lock().expect("fake chain");
        state.scan_calls += 1;
        let start = match request.start {
            ScanStart::Height(height) => height,
            ScanStart::Cursor(cursor) => {
                check_anchor(&state, &cursor)?;
                cursor.next_height
            }
        };
        let tip = state.identity.current_tip;
        let end = start
            .saturating_add(request.max_blocks.saturating_sub(1))
            .min(tip.height);
        let blocks: Vec<ScanBlock> = (start..=end)
            .map(|height| {
                state
                    .blocks
                    .get(&height)
                    .cloned()
                    .ok_or_else(|| WalletCoreError::CanonicalGap(format!("{height}")))
            })
            .collect::<Result<_, _>>()?;
        let continuation = blocks.last().and_then(|block| {
            (block.height < tip.height).then(|| {
                WalletScanCursor::new(
                    state.identity.network,
                    state.identity.chain_id,
                    block.height + 1,
                    BlockRef {
                        height: block.height,
                        hash: block.block_hash,
                    },
                )
            })
        });
        Ok(ScanResult {
            tip,
            blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        let state = self.0.lock().expect("fake chain");
        check_anchor(&state, &cursor)?;
        Ok(CursorValidation {
            valid: true,
            safe_rescan_anchor: BlockRef {
                height: cursor.anchor_height,
                hash: cursor.anchor_hash,
            },
        })
    }

    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        Ok(self
            .0
            .lock()
            .expect("fake chain")
            .hashes
            .get(height as usize)
            .copied())
    }

    fn get_utxo(&self, _: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        Ok(None)
    }
    fn get_kernel(&self, _: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        Ok(None)
    }
    fn get_block_summary(&self, _: BlockSelector) -> Result<Option<BlockSummary>, WalletCoreError> {
        Ok(None)
    }
    fn transaction_status(
        &self,
        _: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        Ok(TransactionStatus::Unknown)
    }
    fn submit_transaction(
        &self,
        _: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn rebroadcast_transaction(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn query_submission(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        Ok(SyncStatus::Ready)
    }
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        Ok(true)
    }
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        Ok(FeePolicySnapshot {
            policy_version: 1,
            network: CoreNetwork::Regtest,
            min_relay_fee_rate: 1_000,
            min_mempool_fee_rate: 1_000,
            recommended_fee_rate: 2_000,
            dust_threshold_noms: 0,
            max_tx_weight: 40_000,
            validity_horizon: None,
        })
    }
    fn transaction_weight(
        &self,
        _: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn minimum_fee(&self, _: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn estimate_fee(&self, _: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
    fn validate_fee(
        &self,
        _: &dom_consensus::Transaction,
    ) -> Result<FeeValidation, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("unused".into()))
    }
}

fn attach(chain: &FakeChain) -> WalletService {
    let mut service = WalletService::default();
    service.kdf = KdfParameters::TEST;
    service
        .start_remote_source(Arc::new(chain.clone()))
        .expect("attach fake Core");
    service
}

fn create_wallet(chain: &FakeChain, path: &Path) -> WalletService {
    let mut service = attach(chain);
    service
        .create_recoverable_for_embedded(path, PASSWORD)
        .expect("create wallet");
    service
        .recovery_phrase_confirmed(PASSWORD)
        .expect("confirm phrase");
    service.unlock(PASSWORD).expect("unlock");
    service
}

fn reopen(chain: &FakeChain, path: &Path) -> WalletService {
    let mut service = attach(chain);
    service.open(path).expect("open after restart");
    service.unlock(PASSWORD).expect("unlock after restart");
    service
}

fn cursor_height(service: &WalletService) -> Option<u64> {
    service.diagnostics().cursor_height
}

/// Place the wallet on cursor 43264 with a consistent 2048-block window.
fn position_at_cursor(state: &mut WalletState, chain: &FakeChain) {
    let cursor = WalletScanCursor::new(
        CoreNetwork::Regtest,
        CHAIN_ID,
        CURSOR + 1,
        BlockRef {
            height: CURSOR,
            hash: chain.hash(CURSOR),
        },
    );
    state.core_scan_cursor = Some(cursor.to_bytes().to_vec());
    state.recovery_canonical_blocks = (CURSOR + 1 - WINDOW..=CURSOR)
        .map(|height| RecoveryCanonicalBlock {
            height,
            block_hash: chain.hash(height),
            previous_block_hash: chain.hash(height - 1),
            output_count: 1,
            legacy_proof_only_outputs: 0,
        })
        .collect();
    state.recovery_scanned_blocks = CURSOR + 1;
    state.recovery_scanned_outputs = CURSOR + 1;
}

fn filled<const N: usize>(seed: u64) -> [u8; N] {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut bytes = [0u8; N];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    bytes
}

/// Synthetic historical coinbase records (a heavy miner's past rewards).
fn add_history(state: &mut WalletState, count: u64) {
    let account = state.default_account.id;
    let first = state.outputs.len() as u64;
    for offset in 0..count {
        let index = first + offset;
        let id = Uuid::from_u128(0x00C0_FFEE_0000_0000 + u128::from(index));
        // Full-entropy bytes: realistic widths in the legacy numeric encoding.
        let commitment: [u8; 33] = filled(index * 3 + 1);
        let blinding: [u8; 32] = filled(index * 3 + 2);
        let hash: [u8; 32] = filled(index * 3 + 3);
        state.outputs.push(OutputRecord {
            id,
            account_id: account,
            commitment: Some(commitment),
            value: 3_300_000_000,
            state: OutputState::Confirmed,
            discovered_height: 1 + index % (CURSOR - 1),
            reserved_by: None,
        });
        state.private_output_blindings.push(PrivateOutputBlinding {
            output_id: id,
            blinding,
        });
        state
            .recovered_output_metadata
            .push(RecoveredOutputMetadata {
                output_id: id,
                recovery_account: 0,
                derivation_index: index + 1,
                domain: RecoveredOutputDomain::Coinbase,
                is_coinbase: true,
                block_hash: hash,
                output_position: 0,
            });
    }
    let floor = first + count;
    state.recovery_allocation_floors.coinbase =
        state.recovery_allocation_floors.coinbase.max(floor);
    state.non_reuse_floor = state.non_reuse_floor.max(floor);
}

fn active_state_file_len(path: &Path) -> u64 {
    let active = std::fs::read_to_string(path.join("active-generation")).expect("pointer");
    std::fs::metadata(path.join("generations").join(active).join("state.envelope"))
        .expect("state file")
        .len()
}

/// Real recoverable coinbases for 43265..=43520, owned by the wallet seed.
fn owned_coinbases(state: &WalletState, identity: &CoreChainIdentity) -> Vec<CoinbaseTransaction> {
    let seed = CanonicalWalletSeed::from_entropy(&state.root_material).expect("seed");
    let builder = RecoverableOutputBuilder::new(&seed, identity).expect("output builder");
    let mut floors = state.clone();
    (CURSOR + 1..=FIRST_PAGE_END)
        .map(|height| {
            let coordinate = floors
                .reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)
                .expect("coordinate");
            builder
                .build_coinbase(BlockHeight(height), 0, coordinate)
                .expect("owned coinbase")
        })
        .collect()
}

fn unspent_total(state: &WalletState) -> u64 {
    state
        .outputs
        .iter()
        .filter(|output| !matches!(output.state, OutputState::Spent { .. }))
        .map(|output| output.value)
        .sum()
}

/// Exactly the inputs `require_mining_cursor_gate` (shell) consumes: cursor on
/// the canonical tip with the canonical hash and no synchronization error.
fn mining_gate_inputs_open(service: &WalletService, chain: &FakeChain) -> bool {
    let diagnostics = service.diagnostics();
    diagnostics.cursor_height == Some(TIP)
        && diagnostics.cursor_hash == Some(hex::encode(chain.hash(TIP)))
        && diagnostics.last_error.is_none()
}

/// I + H (old behaviour) + J: the exact Mainnet boundary through the real
/// WalletService -> scanner -> WalletRecoverySink -> WalletDirectory path:
/// 43264 -> (legacy: refused) -> 43520 -> backup/restore + full restart ->
/// 43776 with a real spend of an owned output.
#[test]
fn regression_cursor_43264_page_crosses_the_old_limit_and_now_advances_to_43520() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("heavy-miner-wallet");

    // Build the wallet first (the seed decides which coinbases it owns).
    let bootstrap = FakeChain::new(Vec::new());
    let service = create_wallet(&bootstrap, &path);
    let base = service.unlocked.clone().expect("state");
    let identity = service.embedded_core_identity().expect("identity");
    let owned = owned_coinbases(&base, &identity);
    assert_eq!(owned.len(), 256);
    let first_owned_commitment = *owned[0].output.commitment.as_bytes();
    drop(service);
    let chain = FakeChain::new(owned);
    let mut service = reopen(&chain, &path);

    // A legacy wallet at cursor 43264 sitting just below the old 16 MiB bound.
    service.state_encoding = StateEncoding::LegacyV1;
    let mut state = service.unlocked.clone().expect("state");
    position_at_cursor(&mut state, &chain);
    add_history(&mut state, 4_600);
    service.commit(state).expect("legacy wallet fits");
    while active_state_file_len(&path) < (LEGACY_V1_MAX_ENVELOPE_BYTES - 450 * 1024) as u64 {
        let mut state = service.unlocked.clone().expect("state");
        add_history(&mut state, 100);
        service.commit(state).expect("legacy wallet still fits");
    }
    let legacy_file_len = active_state_file_len(&path);
    assert!(legacy_file_len <= LEGACY_V1_MAX_ENVELOPE_BYTES as u64);
    let before_page = service.unlocked.clone().unwrap();
    let historical_outputs = before_page.outputs.len();
    assert_eq!(
        service
            .location
            .as_ref()
            .unwrap()
            .active_state_encoding()
            .unwrap(),
        StateEncoding::LegacyV1
    );
    assert_eq!(cursor_height(&service), Some(CURSOR));
    assert!(
        !mining_gate_inputs_open(&service, &chain),
        "gate closed while behind"
    );

    // OLD BEHAVIOUR: page 43265..=43520 is scanned, applied and refused at
    // commit, deterministically, with a typed non-retryable error whose sizes
    // prove the state really crosses the legacy bound.
    let scans_before = chain.scan_calls();
    for attempt in 1..=2 {
        let error = service
            .synchronize_live()
            .expect_err("legacy page cannot commit");
        match &error {
            CoreError::Storage(StorageError::StateTooLarge {
                encoding: StateEncoding::LegacyV1,
                plaintext_bytes,
                envelope_bytes: Some(envelope_bytes),
                envelope_limit_bytes,
                ..
            }) => {
                assert_eq!(*envelope_limit_bytes, LEGACY_V1_MAX_ENVELOPE_BYTES as u64);
                assert!(*envelope_bytes > *envelope_limit_bytes, "{envelope_bytes}");
                assert!(*plaintext_bytes < *envelope_limit_bytes);
                assert!(
                    *envelope_bytes > legacy_file_len,
                    "the page itself crossed it"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(error.redacted_code(), WALLET_STATE_STORAGE_LIMIT_EXCEEDED);
        assert_eq!(
            service.diagnostics().last_error.as_deref(),
            Some(WALLET_STATE_STORAGE_LIMIT_EXCEEDED)
        );
        assert_eq!(
            cursor_height(&service),
            Some(CURSOR),
            "cursor frozen at 43264"
        );
        assert_eq!(
            service.unlocked.as_ref().unwrap(),
            &before_page,
            "state untouched"
        );
        // One scan per attempt: the service itself never loops.
        assert_eq!(chain.scan_calls() - scans_before, attempt);
    }

    // NEW BEHAVIOUR: the same page commits in the compact format.
    service.state_encoding = StateEncoding::CompactV2;
    service.synchronize_live().expect("compact page commits");
    assert_eq!(cursor_height(&service), Some(FIRST_PAGE_END));
    assert!(service.diagnostics().last_error.is_none());
    let after_first_page = service.unlocked.clone().unwrap();
    after_first_page.validate().expect("invariants");
    assert_eq!(after_first_page.wallet_id, before_page.wallet_id);
    assert_eq!(after_first_page.identity, before_page.identity);
    assert_eq!(after_first_page.outputs.len(), historical_outputs + 256);
    let discovered: Vec<_> = after_first_page
        .outputs
        .iter()
        .filter(|output| (CURSOR + 1..=FIRST_PAGE_END).contains(&output.discovered_height))
        .collect();
    assert_eq!(
        discovered.len(),
        256,
        "every owned coinbase of the page was recovered"
    );
    assert!(discovered.iter().all(|output| output.value
        == dom_core::block_reward(BlockHeight(output.discovered_height)).noms()
        && !matches!(output.state, OutputState::Spent { .. })));
    assert_eq!(
        after_first_page.private_output_blindings.len(),
        after_first_page.outputs.len()
    );
    let balance_after_first_page = service.summary().unwrap().balance.total;
    assert_eq!(balance_after_first_page, unspent_total(&after_first_page));
    // The committed state could never have been written by the old format.
    let location = service.location.clone().unwrap();
    assert!(matches!(
        location.commit_with_encoding(
            after_first_page.generation,
            after_first_page.clone(),
            PASSWORD,
            KdfParameters::TEST,
            StateEncoding::LegacyV1,
        ),
        Err(StorageError::StateTooLarge { .. })
    ));
    assert_eq!(
        location.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    assert_eq!(
        location.pre_migration_snapshot_generation().unwrap(),
        Some(before_page.generation),
        "the pre-migration legacy generation is retained"
    );
    drop(location);

    // Backup at 43520, restored into another directory by a fresh service.
    let backup = directory.path().join("at-43520.backup");
    service
        .backup_export(&backup, "backup-password-43520")
        .expect("export backup");
    let restored_path = directory.path().join("restored-wallet");
    let mut restored = attach(&chain);
    restored
        .backup_import(
            &restored_path,
            &backup,
            "backup-password-43520",
            PASSWORD,
            after_first_page.identity.clone(),
        )
        .expect("import backup");
    restored.unlock(PASSWORD).expect("unlock restored");
    assert_eq!(
        restored.unlocked.as_ref().unwrap().outputs,
        after_first_page.outputs
    );
    assert_eq!(cursor_height(&restored), Some(FIRST_PAGE_END));

    // J: full restart of the primary wallet, then the next page with a spend.
    drop(service);
    let mut service = reopen(&chain, &path);
    let reloaded = service.unlocked.clone().unwrap();
    reloaded.validate().expect("invariants after restart");
    assert_eq!(reloaded.outputs, after_first_page.outputs);
    assert_eq!(reloaded.core_scan_cursor, after_first_page.core_scan_cursor);
    assert!(service.diagnostics().last_error.is_none());
    service.synchronize_live().expect("second page");
    restored
        .synchronize_live()
        .expect("restored copy follows too");

    for wallet in [&service, &restored] {
        assert_eq!(cursor_height(wallet), Some(TIP));
        assert_eq!(
            wallet.diagnostics().cursor_hash,
            Some(hex::encode(chain.hash(TIP)))
        );
        let state = wallet.unlocked.as_ref().unwrap();
        state.validate().expect("invariants at the tip");
        let spent = state
            .outputs
            .iter()
            .find(|output| output.commitment == Some(first_owned_commitment))
            .expect("owned output");
        assert_eq!(
            spent.state,
            OutputState::Spent {
                spent_height: SPEND_HEIGHT
            }
        );
        assert_eq!(
            state.outputs.len(),
            historical_outputs + 256,
            "no output lost"
        );
        assert_eq!(
            wallet.summary().unwrap().balance.total,
            unspent_total(state)
        );
        assert_eq!(
            unspent_total(state),
            balance_after_first_page - spent.value,
            "the spend is the only balance change"
        );
        assert!(
            mining_gate_inputs_open(wallet, &chain),
            "gate opens once synchronized"
        );
    }
    assert_eq!(
        service.unlocked.as_ref().unwrap().outputs,
        restored.unlocked.as_ref().unwrap().outputs,
        "primary and restored copies agree"
    );
}

/// H: at least 6000 outputs; the legacy writer refuses the state, the compact
/// one commits it, and synchronization keeps advancing across a restart.
#[test]
fn regression_six_thousand_output_wallet_keeps_synchronizing_across_restart() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("six-thousand");
    let chain = FakeChain::new(Vec::new());
    let mut service = create_wallet(&chain, &path);
    let mut state = service.unlocked.clone().unwrap();
    position_at_cursor(&mut state, &chain);
    add_history(&mut state, 6_000);

    service.state_encoding = StateEncoding::LegacyV1;
    assert!(matches!(
        service.commit(state.clone()),
        Err(CoreError::Storage(StorageError::StateTooLarge { .. }))
    ));
    service.state_encoding = StateEncoding::CompactV2;
    service.commit(state).expect("compact commit");
    assert_eq!(cursor_height(&service), Some(CURSOR));

    drop(service);
    let mut service = reopen(&chain, &path);
    assert_eq!(service.unlocked.as_ref().unwrap().outputs.len(), 6_000);
    assert_eq!(cursor_height(&service), Some(CURSOR));
    let scans_before = chain.scan_calls();
    service.synchronize_live().expect("page 43265..=43520");
    assert_eq!(cursor_height(&service), Some(FIRST_PAGE_END));
    drop(service);
    let mut service = reopen(&chain, &path);
    assert_eq!(cursor_height(&service), Some(FIRST_PAGE_END));
    service.synchronize_live().expect("page 43521..=43776");
    assert_eq!(cursor_height(&service), Some(TIP));
    assert_eq!(
        chain.scan_calls() - scans_before,
        2,
        "one scan per page, no replay"
    );
    assert_eq!(service.unlocked.as_ref().unwrap().outputs.len(), 6_000);
}

#[test]
fn storage_failures_are_classified_transient_or_terminal_explicitly() {
    use std::io::ErrorKind;
    let transient = [
        StorageError::ExpectedGenerationConflict { current: 3 },
        StorageError::WriterActive,
        StorageError::Io(std::io::Error::from(ErrorKind::Interrupted)),
        StorageError::Io(std::io::Error::from(ErrorKind::TimedOut)),
    ];
    for error in &transient {
        assert!(
            StorageFailure::classify(error).terminal_error().is_none(),
            "{error:?} must stay transient"
        );
    }
    let terminal = [
        (
            StorageError::StateTooLarge {
                encoding: StateEncoding::CompactV2,
                plaintext_bytes: 1,
                envelope_bytes: None,
                plaintext_limit_bytes: 0,
                envelope_limit_bytes: 0,
            },
            "WALLET_STATE_STORAGE_LIMIT_EXCEEDED",
            WALLET_STATE_STORAGE_LIMIT_EXCEEDED,
        ),
        (
            StorageError::Io(std::io::Error::from(ErrorKind::StorageFull)),
            "WALLET_STORAGE_IO_FAILED:StorageFull",
            WALLET_STORAGE_IO_FAILED,
        ),
        (
            StorageError::Io(std::io::Error::from(ErrorKind::PermissionDenied)),
            "WALLET_STORAGE_IO_FAILED:PermissionDenied",
            WALLET_STORAGE_IO_FAILED,
        ),
        (
            StorageError::Domain(DomainError::InvalidState),
            "WALLET_STATE_VALIDATION_FAILED",
            "WALLET_STATE_VALIDATION_FAILED",
        ),
        (
            StorageError::UnsafePath,
            "WALLET_STORAGE_FAILED",
            "WALLET_STORAGE_FAILED",
        ),
    ];
    for (error, last_error, code) in &terminal {
        let (reported, typed) = StorageFailure::classify(error)
            .terminal_error()
            .unwrap_or_else(|| panic!("{error:?} must be terminal"));
        assert_eq!(&reported, last_error);
        assert_eq!(typed.redacted_code(), *code);
    }
}

/// A failure of one pass never leaks into the next: the sink (and its side
/// record) is per pass, and a successful commit clears the service error.
#[test]
fn a_storage_failure_never_leaks_into_a_later_pass_or_session() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("isolation");
    let chain = FakeChain::new(Vec::new());
    let mut service = create_wallet(&chain, &path);
    let mut state = service.unlocked.clone().unwrap();
    position_at_cursor(&mut state, &chain);
    add_history(&mut state, 6_000);
    service.commit(state).expect("compact state");
    service.state_encoding = StateEncoding::LegacyV1;
    assert!(service.synchronize_live().is_err());
    assert_eq!(
        service.diagnostics().last_error.as_deref(),
        Some(WALLET_STATE_STORAGE_LIMIT_EXCEEDED)
    );
    // New session: the error is not persisted state.
    drop(service);
    let mut service = reopen(&chain, &path);
    assert!(service.diagnostics().last_error.is_none());
    assert_eq!(cursor_height(&service), Some(CURSOR));
    // Next pass in the compact format succeeds and reports no stale error.
    service.synchronize_live().expect("compact pass");
    assert!(service.diagnostics().last_error.is_none());
    assert_eq!(cursor_height(&service), Some(FIRST_PAGE_END));
}
