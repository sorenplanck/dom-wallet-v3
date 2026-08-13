use dom_consensus::{Transaction, TransactionInput};
use dom_crypto::{
    pedersen::BlindingFactor,
    range_proof_prove_bytes,
    recovery::{RecoveryChainContext, RECOVERY_VERSION},
    RANGE_PROOF_SERIALIZATION_VERSION,
};
use dom_tx::{InputSource, SpendBuilder};
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeePolicySnapshot,
    FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock, ScanInput, ScanKernel,
    ScanOutput, ScanRequest, ScanResult, ScanStart, SubmissionResult, SubmitTransactionRequest,
    SyncStatus, TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight,
    UtxoQueryResult, WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use dom_wallet_core_recovery::{CanonicalWalletSeed, RecoverableOutputBuilder};
use dom_wallet_core_restore::{
    abort_restore_stage, apply_recovery_batch, discover_restore_stages, offline_restore_state,
    rewind_recovery_state, RestoredSpendSource, SeedRestoreCompletion, SeedRestoreError,
    SeedRestoreProgress, SeedRestoreService, SeedRestoreWarning, RECOVERY_CANONICAL_WINDOW_BLOCKS,
};
use dom_wallet_core_sync::{
    CoreBlockReference, CoreChainAdapter, CoreChainIdentity, CoreCoinbaseMetadata, CoreCursorBytes,
    CoreReconcileResult, CoreScanBatch, CoreScanBlock, CoreScanTransactionSink,
    PersistedCoreCursorState,
};
use dom_wallet_crypto::KdfParameters;
use dom_wallet_domain::{
    Network, NetworkIdentity, OutputState, RecoveryCanonicalBlock, RecoveryOutputClass,
    SeedRestoreStatus, SyncStatus as WalletSyncStatus, WalletState,
};
use dom_wallet_storage::{default_node_configuration, WalletDirectory};
use std::{
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

#[derive(Clone)]
struct FakeCore {
    state: Arc<Mutex<FakeState>>,
}

struct FakeState {
    identity: ChainIdentity,
    blocks: Vec<ScanBlock>,
    scan_busy_remaining: u32,
}

impl FakeCore {
    fn new(blocks: Vec<ScanBlock>, identity: CoreChainIdentity) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                identity: ChainIdentity {
                    network: identity.network,
                    network_magic: identity.network_magic,
                    chain_id: identity.chain_id,
                    genesis_hash: identity.genesis_hash,
                    protocol_version: identity.protocol_version,
                    range_proof_serialization_version: identity.range_proof_serialization_version,
                    coinbase_maturity: identity.coinbase_maturity,
                    current_tip: BlockRef {
                        height: identity.current_tip.height,
                        hash: identity.current_tip.hash,
                    },
                },
                blocks,
                scan_busy_remaining: 0,
            })),
        }
    }

    fn fail_next_scan_attempts(&self, attempts: u32) {
        self.state.lock().unwrap().scan_busy_remaining = attempts;
    }

    fn replace_from(&self, height: u64, marker: u8, clear_inputs: bool) {
        let mut state = self.state.lock().unwrap();
        let mut previous = if height == 0 {
            [0; 32]
        } else {
            state.blocks[(height - 1) as usize].block_hash
        };
        for block in state.blocks.iter_mut().skip(height as usize) {
            block.block_hash = [marker.wrapping_add(block.height as u8); 32];
            block.previous_block_hash = previous;
            block.canonical_marker = block.block_hash;
            if clear_inputs {
                block.inputs.clear();
            }
            for output in &mut block.outputs {
                output.block_hash = block.block_hash;
            }
            previous = block.block_hash;
        }
        let tip = state.blocks.last().unwrap();
        state.identity.current_tip = BlockRef {
            height: tip.height,
            hash: tip.block_hash,
        };
    }

    fn clear_outputs_at(&self, height: u64) {
        self.state.lock().unwrap().blocks[height as usize]
            .outputs
            .clear();
    }
}

impl WalletCoreApi for FakeCore {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        Ok(self.state.lock().unwrap().identity.clone())
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        let mut state = self.state.lock().unwrap();
        if state.scan_busy_remaining > 0 {
            state.scan_busy_remaining -= 1;
            return Err(WalletCoreError::NodeNotReady(
                "test-only transient chain lock".into(),
            ));
        }
        if request.network != state.identity.network
            || request.chain_id != state.identity.chain_id
            || !request.commitment_filters.is_empty()
        {
            return Err(WalletCoreError::CursorChainMismatch("identity".into()));
        }
        let start = match request.start {
            ScanStart::Height(height) => height,
            ScanStart::Cursor(cursor) => {
                validate_cursor_against(&state, cursor)?;
                cursor.next_height
            }
        };
        let end = start
            .saturating_add(request.max_blocks.saturating_sub(1))
            .min(state.identity.current_tip.height);
        let blocks = if start > state.identity.current_tip.height {
            Vec::new()
        } else {
            state.blocks[start as usize..=end as usize].to_vec()
        };
        let continuation = blocks.last().and_then(|block| {
            (block.height < state.identity.current_tip.height).then(|| {
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
            tip: state.identity.current_tip,
            blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        let state = self.state.lock().unwrap();
        validate_cursor_against(&state, cursor)?;
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
            .state
            .lock()
            .unwrap()
            .blocks
            .get(height as usize)
            .map(|block| block.block_hash))
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
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn rebroadcast_transaction(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn query_submission(
        &self,
        _: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        Ok(SyncStatus::Ready)
    }
    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        Ok(true)
    }
    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn transaction_weight(
        &self,
        _: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn minimum_fee(&self, _: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn estimate_fee(&self, _: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
    fn validate_fee(&self, _: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        Err(WalletCoreError::NodeNotReady("test-only".into()))
    }
}

fn validate_cursor_against(
    state: &FakeState,
    cursor: WalletScanCursor,
) -> Result<(), WalletCoreError> {
    cursor.validate_shape()?;
    if cursor.network_magic != state.identity.network_magic
        || cursor.chain_id != state.identity.chain_id
    {
        return Err(WalletCoreError::CursorChainMismatch("identity".into()));
    }
    if state
        .blocks
        .get(cursor.anchor_height as usize)
        .map(|block| block.block_hash)
        != Some(cursor.anchor_hash)
    {
        return Err(WalletCoreError::CursorReorg("anchor".into()));
    }
    Ok(())
}

struct Fixture {
    phrase: Zeroizing<String>,
    identity: CoreChainIdentity,
    blocks: Vec<ScanBlock>,
    owned: Vec<(
        RecoveryOutputClass,
        u64,
        dom_wallet_core_recovery::RecoverableOutputResult,
    )>,
}

fn fixture() -> Fixture {
    let seed = CanonicalWalletSeed::from_entropy(&[0x41; 32]).unwrap();
    let unrelated = CanonicalWalletSeed::from_entropy(&[0x52; 32]).unwrap();
    let identity = identity();
    let domain_identity = NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: identity.chain_id,
        genesis_id: identity.genesis_hash,
    };
    let mut allocation = WalletState::new(
        domain_identity.clone(),
        [0; 32],
        default_node_configuration(domain_identity.clone()),
    );
    let builder = RecoverableOutputBuilder::new(&seed, &identity).unwrap();
    let unrelated_builder = RecoverableOutputBuilder::new(&unrelated, &identity).unwrap();
    let definitions = [
        (RecoveryOutputClass::ReceiveRequest, 100, 0),
        (RecoveryOutputClass::ReceiveSlate, 200, 1),
        (RecoveryOutputClass::Change, 300, 0),
        (RecoveryOutputClass::SelfTransfer, 400, 2),
        (RecoveryOutputClass::Coinbase, 500, 0),
    ];
    let built = definitions
        .into_iter()
        .map(|(class, value, account)| {
            let coordinate = allocation
                .reserve_recovery_coordinate(account, class)
                .unwrap();
            let output = builder.build(value, coordinate).unwrap();
            (class, value, output)
        })
        .collect::<Vec<_>>();
    let unrelated_coordinate = allocation
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)
        .unwrap();
    let unrelated_output = unrelated_builder.build(700, unrelated_coordinate).unwrap();
    let legacy_blinding = BlindingFactor::from_bytes([7; 32]).unwrap();
    let (legacy_proof, legacy_commitment) = range_proof_prove_bytes(800, &legacy_blinding).unwrap();

    let mut blocks = (0..5).map(empty_block).collect::<Vec<_>>();
    blocks[0].outputs.push(scan_output(&built[0].2, 0, 0));
    blocks[1].outputs.push(scan_output(&built[1].2, 1, 0));
    blocks[1].outputs.push(scan_output(&unrelated_output, 1, 1));
    blocks[2].outputs.push(scan_output(&built[2].2, 2, 0));
    blocks[2].outputs.push(scan_output(&built[3].2, 2, 1));
    let block_two_hash = blocks[2].block_hash;
    blocks[2].outputs.push(ScanOutput {
        commitment: legacy_commitment,
        range_proof: legacy_proof,
        recovery_capsule: Vec::new(),
        recovery_version: 0,
        is_coinbase: false,
        block_height: 2,
        block_hash: block_two_hash,
        output_position: 2,
    });
    blocks[3].outputs.push(scan_output(&built[4].2, 3, 0));
    blocks[3].coinbase.output_commitment = built[4].2.commitment;
    blocks[3].coinbase.explicit_value = 500;
    blocks[4].inputs = vec![
        ScanInput {
            spent_commitment: built[0].2.commitment,
        },
        ScanInput {
            spent_commitment: built[2].2.commitment,
        },
    ];
    Fixture {
        phrase: seed.mnemonic_text(),
        identity,
        blocks,
        owned: built,
    }
}

fn identity() -> CoreChainIdentity {
    CoreChainIdentity {
        network: CoreNetwork::Regtest,
        network_magic: CoreNetwork::Regtest.magic(),
        chain_id: [0x31; 32],
        genesis_hash: [0x32; 32],
        protocol_version: dom_core::PROTOCOL_VERSION,
        range_proof_serialization_version: RANGE_PROOF_SERIALIZATION_VERSION,
        coinbase_maturity: 3,
        current_tip: CoreBlockReference {
            height: 4,
            hash: [5; 32],
        },
    }
}

fn empty_block(height: u64) -> ScanBlock {
    let marker = height as u8 + 1;
    ScanBlock {
        height,
        block_hash: [marker; 32],
        previous_block_hash: if height == 0 {
            [0; 32]
        } else {
            [marker - 1; 32]
        },
        timestamp: 1_800_000_000 + height,
        canonical_marker: [marker; 32],
        outputs: Vec::new(),
        inputs: Vec::new(),
        kernels: vec![ScanKernel {
            excess: public_commitment(marker.wrapping_add(40)),
            features: 0,
            fee: 0,
            lock_height: 0,
        }],
        coinbase: CoinbaseScanMetadata {
            output_commitment: public_commitment(marker.wrapping_add(20)),
            explicit_value: 0,
            kernel_excess: public_commitment(marker.wrapping_add(40)),
        },
        total_fees_noms: 0,
        protocol_version: dom_core::required_block_version_for_network(
            CoreNetwork::Regtest.magic(),
            height,
        ),
        range_proof_serialization_version: RANGE_PROOF_SERIALIZATION_VERSION,
    }
}

fn scan_output(
    output: &dom_wallet_core_recovery::RecoverableOutputResult,
    height: u64,
    position: u32,
) -> ScanOutput {
    ScanOutput {
        commitment: output.commitment,
        range_proof: output.range_proof.to_vec(),
        recovery_capsule: output.recovery_capsule.to_vec(),
        recovery_version: RECOVERY_VERSION,
        is_coinbase: output.class == RecoveryOutputClass::Coinbase,
        block_height: height,
        block_hash: [height as u8 + 1; 32],
        output_position: position,
    }
}

fn public_commitment(marker: u8) -> [u8; 33] {
    let mut commitment = [marker; 33];
    commitment[0] = 2;
    commitment
}

fn service(fake: &FakeCore, identity: &CoreChainIdentity) -> SeedRestoreService {
    SeedRestoreService::new(
        Arc::new(fake.clone()),
        identity.clone(),
        KdfParameters::TEST,
    )
    .with_limits(2, 8)
}

fn password() -> String {
    ["test", "only", "restore", "credential"].join("-")
}

#[test]
fn seed_only_restore_decisive_e2e() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("new-encrypted-wallet");
    let password = password();
    assert!(!destination.exists());
    assert!(!temp.path().join("wallet.dombackup").exists());

    let result = service(&fake, &fixture.identity)
        .restore(&fixture.phrase, &password, &destination)
        .unwrap();
    assert_eq!(
        result.completion,
        SeedRestoreCompletion::OwnedOutputsRecovered
    );
    assert_eq!(result.owned_outputs, 5);
    assert_eq!(result.spent_outputs, 2);
    assert_eq!(result.unspent_outputs, 3);
    assert_eq!(result.coinbase_outputs, 1);
    assert_eq!(result.legacy_outputs, 1);
    assert_eq!(result.scanned_outputs, 7);
    assert_eq!(result.balance.total, 1_100);
    assert_eq!(result.balance.spendable, 600);
    assert_eq!(result.balance.confirmed, 600);
    assert_eq!(result.balance.immature, 500);
    assert_eq!(result.accounts.len(), 3);
    assert_eq!(result.floors.received, 2);
    assert_eq!(result.floors.change, 1);
    assert_eq!(result.floors.self_transfer, 1);
    assert_eq!(result.floors.coinbase, 1);
    assert!(result
        .warnings
        .contains(&SeedRestoreWarning::LegacyBackupRequired));

    let wallet = WalletDirectory::open(&destination).unwrap();
    let state = wallet.load(&password).unwrap();
    assert_eq!(state.seed_restore_status, Some(SeedRestoreStatus::Complete));
    assert_eq!(state.core_scan_cursor.as_ref().unwrap().len(), 86);
    assert_eq!(state.outputs.len(), 5);
    assert_eq!(state.private_output_blindings.len(), 5);
    assert!(state.transactions.is_empty());
    assert!(state.rescan_plan.is_none());
    let coinbase_output_id = state
        .recovered_output_metadata
        .iter()
        .find(|metadata| metadata.is_coinbase)
        .unwrap()
        .output_id;
    let coinbase_output = state
        .outputs
        .iter()
        .find(|output| output.id == coinbase_output_id)
        .unwrap();
    assert!(matches!(
        coinbase_output.state,
        OutputState::Immature { .. }
    ));

    for (_, value, original) in &fixture.owned {
        let output = state
            .outputs
            .iter()
            .find(|output| output.commitment == Some(original.commitment))
            .unwrap();
        assert_eq!(output.value, *value);
        assert!(original.matches_spend_blinding(&state.output_blinding(output.id).unwrap()));
    }

    let domains = state
        .recovered_output_metadata
        .iter()
        .map(|metadata| metadata.domain)
        .collect::<Vec<_>>();
    assert_eq!(
        domains
            .iter()
            .filter(|domain| **domain == dom_wallet_domain::RecoveredOutputDomain::Received)
            .count(),
        2
    );
    assert!(domains.contains(&dom_wallet_domain::RecoveredOutputDomain::Change));
    assert!(domains.contains(&dom_wallet_domain::RecoveredOutputDomain::SelfTransfer));
    assert!(domains.contains(&dom_wallet_domain::RecoveredOutputDomain::Coinbase));

    let spend_commitment = fixture.owned[1].2.commitment;
    assert_restored_spend(&state, &fixture.identity, spend_commitment);

    let phrase_bytes = fixture.phrase.as_bytes();
    for entry in walk_files(&destination) {
        let bytes = fs::read(entry).unwrap();
        assert!(!bytes
            .windows(phrase_bytes.len())
            .any(|window| window == phrase_bytes));
        for secret in &state.private_output_blindings {
            assert!(!bytes
                .windows(secret.blinding.len())
                .any(|window| window == secret.blinding));
        }
    }
    assert!(!format!("{result:?}").contains(fixture.phrase.as_str()));
    let mut overflow = state.clone();
    overflow.recovery_allocation_floors.received = u64::MAX;
    assert!(overflow
        .reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveRequest)
        .is_err());
}

#[test]
fn restored_spend_decisive_uses_only_reopened_encrypted_authority() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("spendable-restored-wallet");
    let password = password();
    service(&fake, &fixture.identity)
        .restore(&fixture.phrase, &password, &destination)
        .unwrap();
    let state = WalletDirectory::open(destination)
        .unwrap()
        .load(&password)
        .unwrap();
    assert_restored_spend(&state, &fixture.identity, fixture.owned[1].2.commitment);
}

#[test]
fn malformed_wrong_seed_chain_and_tampering_fail_closed() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let password = password();
    let malformed = temp.path().join("malformed");
    assert!(matches!(
        service(&fake, &fixture.identity).restore(
            "not a valid canonical mnemonic",
            &password,
            &malformed
        ),
        Err(SeedRestoreError::InvalidMnemonic)
    ));
    assert!(!malformed.exists());

    let wrong = CanonicalWalletSeed::from_entropy(&[0x63; 32]).unwrap();
    let wrong_result = service(&fake, &fixture.identity)
        .restore(
            &wrong.mnemonic_text(),
            &password,
            temp.path().join("wrong-seed"),
        )
        .unwrap();
    assert_eq!(
        wrong_result.completion,
        SeedRestoreCompletion::NoOwnedOutputs
    );
    assert_eq!(wrong_result.owned_outputs, 0);

    let mut wrong_identity = fixture.identity.clone();
    wrong_identity.chain_id[0] ^= 1;
    assert!(matches!(
        service(&fake, &wrong_identity).restore(
            &fixture.phrase,
            &password,
            temp.path().join("wrong-chain")
        ),
        Err(SeedRestoreError::ChainIdentityMismatch)
    ));

    let mut wrong_network = fixture.identity.clone();
    wrong_network.network = CoreNetwork::Testnet;
    wrong_network.network_magic = CoreNetwork::Testnet.magic();
    assert!(matches!(
        service(&fake, &wrong_network).restore(
            &fixture.phrase,
            &password,
            temp.path().join("wrong-network")
        ),
        Err(SeedRestoreError::ChainIdentityMismatch)
    ));

    let mut capsule_blocks = fixture.blocks.clone();
    capsule_blocks[0].outputs[0].recovery_capsule[20] ^= 1;
    let capsule_fake = FakeCore::new(capsule_blocks, fixture.identity.clone());
    let capsule_result = service(&capsule_fake, &fixture.identity)
        .restore(
            &fixture.phrase,
            &password,
            temp.path().join("tampered-capsule"),
        )
        .unwrap();
    assert_eq!(capsule_result.owned_outputs, 4);

    let mut proof_blocks = fixture.blocks.clone();
    proof_blocks[0].outputs[0].range_proof[20] ^= 1;
    let proof_fake = FakeCore::new(proof_blocks, fixture.identity.clone());
    assert!(matches!(
        service(&proof_fake, &fixture.identity).restore(
            &fixture.phrase,
            &password,
            temp.path().join("tampered-proof")
        ),
        Err(SeedRestoreError::CanonicalScan | SeedRestoreError::MalformedRecovery)
    ));
    assert!(!temp.path().join("tampered-proof").exists());

    let mut commitment_blocks = fixture.blocks.clone();
    commitment_blocks[0].outputs[0].commitment[10] ^= 1;
    let commitment_fake = FakeCore::new(commitment_blocks, fixture.identity.clone());
    let commitment_result = service(&commitment_fake, &fixture.identity)
        .restore(
            &fixture.phrase,
            &password,
            temp.path().join("tampered-commitment"),
        )
        .unwrap();
    assert_eq!(commitment_result.owned_outputs, 4);
}

#[test]
fn canonical_gaps_noncanonical_blocks_and_conflicting_duplicates_fail_closed() {
    let fixture = fixture();
    let temp = TempDir::new().unwrap();
    let password = password();

    let mut gap = fixture.blocks.clone();
    gap[2].height += 1;
    let gap_fake = FakeCore::new(gap, fixture.identity.clone());
    assert!(service(&gap_fake, &fixture.identity)
        .restore(&fixture.phrase, &password, temp.path().join("gap"))
        .is_err());

    let mut noncanonical = fixture.blocks.clone();
    noncanonical[1].canonical_marker[0] ^= 1;
    let noncanonical_fake = FakeCore::new(noncanonical, fixture.identity.clone());
    assert!(service(&noncanonical_fake, &fixture.identity)
        .restore(&fixture.phrase, &password, temp.path().join("noncanonical"))
        .is_err());

    let mut duplicate = fixture.blocks.clone();
    let mut moved = duplicate[0].outputs[0].clone();
    moved.block_height = 1;
    moved.block_hash = duplicate[1].block_hash;
    moved.output_position = 2;
    duplicate[1].outputs.push(moved);
    let duplicate_fake = FakeCore::new(duplicate, fixture.identity.clone());
    assert!(matches!(
        service(&duplicate_fake, &fixture.identity).restore(
            &fixture.phrase,
            &password,
            temp.path().join("conflicting-duplicate")
        ),
        Err(SeedRestoreError::ConflictingOutput)
    ));

    let mut duplicate_input = fixture.blocks.clone();
    let repeated_input = duplicate_input[4].inputs[0];
    duplicate_input[4].inputs.push(repeated_input);
    let duplicate_input_fake = FakeCore::new(duplicate_input, fixture.identity.clone());
    assert!(matches!(
        service(&duplicate_input_fake, &fixture.identity).restore(
            &fixture.phrase,
            &password,
            temp.path().join("duplicate-input")
        ),
        Err(SeedRestoreError::ConflictingOutput)
    ));

    let mut exact_duplicate = fixture.blocks.clone();
    let repeated_output = exact_duplicate[0].outputs[0].clone();
    exact_duplicate[0].outputs.push(repeated_output);
    let exact_duplicate_fake = FakeCore::new(exact_duplicate, fixture.identity.clone());
    let exact = service(&exact_duplicate_fake, &fixture.identity)
        .restore(
            &fixture.phrase,
            &password,
            temp.path().join("exact-duplicate"),
        )
        .unwrap();
    assert_eq!(exact.owned_outputs, 5);
}

#[test]
fn interrupted_restore_resumes_exact_cursor_without_false_completion() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("resumed");
    let password = password();
    let service = service(&fake, &fixture.identity);
    let mut first = service
        .begin(&fixture.phrase, &password, &destination)
        .unwrap();
    assert!(matches!(
        first.advance_once().unwrap(),
        SeedRestoreProgress::BatchCommitted { .. }
    ));
    drop(first);
    assert!(!destination.exists());
    let staging = temp.path().join(".resumed.seed-restore");
    let staged = WalletDirectory::open(&staging)
        .unwrap()
        .load(&password)
        .unwrap();
    assert_eq!(
        staged.seed_restore_status,
        Some(SeedRestoreStatus::InProgress)
    );
    assert_eq!(staged.core_scan_cursor.as_ref().unwrap().len(), 86);
    assert_eq!(staged.outputs.len(), 2);

    let result = service
        .restore(&fixture.phrase, &password, &destination)
        .unwrap();
    assert_eq!(result.owned_outputs, 5);
    assert!(!staging.exists());
    assert_eq!(
        WalletDirectory::open(&destination)
            .unwrap()
            .load(&password)
            .unwrap()
            .seed_restore_status,
        Some(SeedRestoreStatus::Complete)
    );
    assert!(matches!(
        service.restore(&fixture.phrase, &password, &destination),
        Err(SeedRestoreError::InvalidDestination)
    ));
}

#[test]
fn regression_a8_abandoned_restore_is_private_discoverable_resumable_and_authenticated_abortable() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("crash-restart");
    let password = password();
    let service = service(&fake, &fixture.identity);
    let mut interrupted = service
        .begin(&fixture.phrase, &password, &destination)
        .unwrap();
    interrupted.advance_once().unwrap();
    drop(interrupted);

    let staging = temp.path().join(".crash-restart.seed-restore");
    assert!(staging.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert_eq!(discover_restore_stages(temp.path()), vec!["crash-restart"]);
    assert!(matches!(
        abort_restore_stage(&destination, "wrong-password"),
        Err(SeedRestoreError::InvalidPassword)
    ));
    assert!(staging.exists());

    let resumed = service
        .begin(&fixture.phrase, &password, &destination)
        .unwrap();
    drop(resumed);
    abort_restore_stage(&destination, &password).unwrap();
    assert!(!staging.exists());
    assert!(discover_restore_stages(temp.path()).is_empty());
    assert!(!destination.exists());

    let completed_destination = temp.path().join("completed-before-rename");
    let mut completed = service
        .begin(&fixture.phrase, &password, &completed_destination)
        .unwrap();
    loop {
        if completed.advance_once().unwrap() == SeedRestoreProgress::ReadyToPublish {
            break;
        }
    }
    drop(completed);
    let completed_staging = temp.path().join(".completed-before-rename.seed-restore");
    let directory = WalletDirectory::open(&completed_staging).unwrap();
    let mut state = directory.load(&password).unwrap();
    let expected_generation = state.generation;
    state.seed_restore_status = Some(SeedRestoreStatus::Complete);
    state.sync_status = dom_wallet_domain::SyncStatus::Synced;
    directory
        .commit(expected_generation, state, &password, KdfParameters::TEST)
        .unwrap();
    drop(directory);

    let published = service
        .restore(&fixture.phrase, &password, &completed_destination)
        .unwrap();
    assert_eq!(published.owned_outputs, 5);
    assert!(completed_destination.is_dir());
    assert!(!completed_staging.exists());
}

#[test]
fn transient_core_busy_is_bounded_and_restore_remains_resumable() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("busy-resume");
    let password = password();
    fake.fail_next_scan_attempts(3);
    let bounded =
        service(&fake, &fixture.identity).with_busy_retry_policy(2, Duration::ZERO, Duration::ZERO);

    assert!(matches!(
        bounded.restore(&fixture.phrase, &password, &destination),
        Err(SeedRestoreError::CoreBusy)
    ));
    assert!(!destination.exists());
    assert!(temp.path().join(".busy-resume.seed-restore").exists());

    let restored = service(&fake, &fixture.identity)
        .restore(&fixture.phrase, &password, &destination)
        .unwrap();
    assert_eq!(restored.owned_outputs, 5);
    assert!(!temp.path().join(".busy-resume.seed-restore").exists());
}

#[test]
fn shallow_and_deeper_reorgs_rewind_replay_and_never_lower_floors() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("shallow");
    let password = password();
    let restore_service = service(&fake, &fixture.identity);
    let mut session = restore_service
        .begin(&fixture.phrase, &password, &destination)
        .unwrap();
    session.advance_once().unwrap();
    session.advance_once().unwrap();
    session.advance_once().unwrap();
    fake.replace_from(4, 0x70, true);
    assert!(matches!(
        session.advance_once().unwrap(),
        SeedRestoreProgress::ReorgCommitted { .. }
    ));
    assert_eq!(
        session.advance_once().unwrap(),
        SeedRestoreProgress::ReadyToPublish
    );
    let shallow = session.publish().unwrap();
    assert_eq!(shallow.spent_outputs, 0);
    assert_eq!(shallow.floors.received, 2);
    assert_eq!(shallow.floors.change, 1);

    let deep_destination = temp.path().join("deep");
    let deep_fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let deep_service = service(&deep_fake, &fixture.identity);
    let mut interrupted = deep_service
        .begin(&fixture.phrase, &password, &deep_destination)
        .unwrap();
    interrupted.advance_once().unwrap();
    drop(interrupted);
    deep_fake.clear_outputs_at(1);
    deep_fake.replace_from(1, 0x50, false);
    let deep = deep_service
        .restore(&fixture.phrase, &password, &deep_destination)
        .unwrap();
    assert_eq!(deep.owned_outputs, 4);
    assert_eq!(deep.floors.received, 2);
}

/// Minimal durable sink mirroring the production Wallet synchronization sink:
/// recovery is applied per page and the cursor is committed atomically with
/// the state inside the same encrypted generation.
struct PageSink<'a> {
    seed: &'a CanonicalWalletSeed,
    chain: RecoveryChainContext,
    identity: &'a CoreChainIdentity,
    directory: &'a WalletDirectory,
    state: WalletState,
    password: &'a str,
}

impl PageSink<'_> {
    fn commit(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
        reorg_anchor: Option<CoreBlockReference>,
    ) -> Result<(), SeedRestoreError> {
        let mut next = self.state.clone();
        if let Some(anchor) = reorg_anchor {
            rewind_recovery_state(&mut next, anchor.height, batch.observed_tip.height)?;
        }
        apply_recovery_batch(self.seed, self.chain, self.identity, &mut next, batch)?;
        next.core_scan_cursor = Some(cursor.as_bytes().to_vec());
        next.validate()
            .map_err(|_| SeedRestoreError::MalformedRecovery)?;
        self.state = self
            .directory
            .commit(
                self.state.generation,
                next,
                self.password,
                KdfParameters::TEST,
            )
            .map_err(|_| SeedRestoreError::Storage)?;
        Ok(())
    }
}

impl CoreScanTransactionSink for PageSink<'_> {
    type Error = SeedRestoreError;

    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error> {
        match self.state.core_scan_cursor.as_deref() {
            None => Ok(PersistedCoreCursorState::Absent),
            Some(bytes) => CoreCursorBytes::parse(bytes, self.identity)
                .map(PersistedCoreCursorState::Valid)
                .map_err(|_| SeedRestoreError::IncompatibleCheckpoint),
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

#[test]
fn regression_offline_restore_wallet_syncs_outputs_via_normal_page_path() {
    let fixture = fixture();
    let fake = FakeCore::new(fixture.blocks.clone(), fixture.identity.clone());
    let temp = TempDir::new().unwrap();
    let destination = temp.path().join("offline-restored");
    let password = password();
    let seed = CanonicalWalletSeed::parse(fixture.phrase.as_str()).unwrap();
    let domain_identity = NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: fixture.identity.chain_id,
        genesis_id: fixture.identity.genesis_hash,
    };

    // Immediate offline creation: no backend, no staging, no cursor, and the
    // wallet is recovery-eligible with the phrase already confirmed.
    let state = offline_restore_state(&seed, domain_identity);
    assert_eq!(
        state.seed_restore_status,
        Some(SeedRestoreStatus::InProgress)
    );
    assert_eq!(state.sync_status, WalletSyncStatus::Synchronizing);
    assert!(state.core_scan_cursor.is_none());
    assert!(state
        .recovery
        .as_ref()
        .is_some_and(|recovery| recovery.phrase_confirmed));
    let directory =
        WalletDirectory::create(&destination, &state, &password, KdfParameters::TEST).unwrap();

    // The recovery scan then happens on the normal per-page sync path.
    let adapter =
        CoreChainAdapter::connect(Arc::new(fake.clone()), Some(&fixture.identity), 2, 8).unwrap();
    let mut sink = PageSink {
        seed: &seed,
        chain: RecoveryChainContext {
            network_magic: fixture.identity.network_magic,
            chain_id: fixture.identity.chain_id,
        },
        identity: &fixture.identity,
        directory: &directory,
        state,
        password: &password,
    };
    let mut pages = 0;
    loop {
        let before_generation = sink.state.generation;
        match adapter.reconcile_once(&mut sink).unwrap() {
            CoreReconcileResult::NoChanges => break,
            CoreReconcileResult::Committed(_) | CoreReconcileResult::ReorgCommitted { .. } => {
                pages += 1;
                let durable = directory.load(&password).unwrap();
                assert!(durable.generation > before_generation);
                assert_eq!(durable.generation, sink.state.generation);
                assert_eq!(
                    durable.core_scan_cursor, sink.state.core_scan_cursor,
                    "cursor must be committed atomically with the state"
                );
            }
        }
    }
    assert!(pages >= 2, "fixture must span multiple pages");

    let synced = directory.load(&password).unwrap();
    assert_eq!(synced.outputs.len(), 5);
    assert_eq!(synced.recovery_scanned_blocks, 5);
    assert_eq!(synced.recovery_scanned_outputs, 7);
    assert_eq!(synced.legacy_proof_only_outputs, 1);
    assert_eq!(synced.balance().total, 1_100);
    assert_eq!(synced.core_scan_cursor.as_ref().unwrap().len(), 86);
    assert_eq!(
        synced
            .outputs
            .iter()
            .filter(|output| matches!(output.state, OutputState::Spent { .. }))
            .count(),
        2
    );
}

fn window_hash(height: u64, tag: u8) -> [u8; 32] {
    let mut hash = [tag; 32];
    hash[..8].copy_from_slice(&height.to_le_bytes());
    hash
}

#[test]
fn regression_known_phrase_mines_legacy_coinbase_then_v3_restore_has_balance() {
    use dom_wallet::{Bip39Seed, SeedAcceptance, Wallet};
    use dom_wallet_embedded_core::{
        mine_wallet_block, EmbeddedCoreConfiguration, EmbeddedCoreLifecycle, EmbeddedCoreNetwork,
        WalletMiningOutcome,
    };
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, AtomicU64},
            Arc,
        },
    };

    let temp = TempDir::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::new(
        EmbeddedCoreNetwork::Regtest,
        temp.path().join("core"),
        address,
    ));
    lifecycle.start().unwrap();

    let adapter = CoreChainAdapter::connect(lifecycle.wallet_api().unwrap(), None, 8, 8).unwrap();
    let identity = adapter.identity().clone();
    let v3_seed = CanonicalWalletSeed::from_entropy(&[0x2b; 32]).unwrap();
    let phrase = v3_seed.mnemonic_text();
    let legacy_seed = Bip39Seed::from_phrase(&phrase, SeedAcceptance::NewWallet).unwrap();
    let genesis = dom_crypto::Hash256::from_bytes(identity.genesis_hash);
    let mut legacy_wallet = Wallet::create_from_seed(
        &temp.path().join("legacy-wallet.dat"),
        "test-password",
        dom_wallet::Network::Regtest,
        &genesis,
        &legacy_seed,
    )
    .unwrap();
    let coinbase = legacy_wallet
        .build_coinbase(dom_core::BlockHeight(1), 0)
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mined = runtime
        .block_on(mine_wallet_block(
            lifecycle.node_handle().unwrap(),
            &coinbase,
            1,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        ))
        .unwrap();
    assert_eq!(mined, WalletMiningOutcome::Accepted { height: 1 });

    let batch = adapter.scan_from_height(0, 8).unwrap();
    assert_eq!(batch.observed_tip.height, 1);
    let chain = RecoveryChainContext {
        network_magic: identity.network_magic,
        chain_id: identity.chain_id,
    };
    let mut restored = offline_restore_state(
        &v3_seed,
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: identity.chain_id,
            genesis_id: identity.genesis_hash,
        },
    );
    apply_recovery_batch(&v3_seed, chain, &identity, &mut restored, &batch).unwrap();

    let reward = dom_core::block_reward(dom_core::BlockHeight(1)).noms();
    assert_eq!(restored.balance().total, reward);
    assert_eq!(restored.outputs.len(), 1);
    assert_eq!(
        restored.outputs[0].commitment,
        Some(*coinbase.output.commitment.as_bytes())
    );

    lifecycle.request_shutdown().unwrap();
    lifecycle.wait_for_shutdown().unwrap();
}

fn window_block(height: u64, tag: u8, previous_block_hash: [u8; 32]) -> CoreScanBlock {
    let block_hash = window_hash(height, tag);
    CoreScanBlock {
        height,
        block_hash,
        previous_block_hash,
        canonical_header_bytes: Vec::new(),
        timestamp: 1_800_000_000 + height,
        canonical_marker: block_hash,
        outputs: Vec::new(),
        inputs: Vec::new(),
        kernels: Vec::new(),
        transactions: Vec::new(),
        coinbase: CoreCoinbaseMetadata {
            output_commitment: public_commitment(2),
            explicit_value: 0,
            kernel_excess: public_commitment(2),
            kernel_features: 1,
            kernel_excess_signature: [0; 65],
            offset: [0; 32],
            output_proof_envelope: Vec::new(),
        },
        total_fees_noms: 0,
        protocol_version: dom_core::required_block_version_for_network(
            CoreNetwork::Regtest.magic(),
            height,
        ),
        range_proof_serialization_version: RANGE_PROOF_SERIALIZATION_VERSION,
    }
}

#[test]
fn regression_reorg_window_prunes_blocks_and_keeps_durable_counters() {
    let identity = identity();
    let seed = CanonicalWalletSeed::from_entropy(&[0x21; 32]).unwrap();
    let chain = RecoveryChainContext {
        network_magic: identity.network_magic,
        chain_id: identity.chain_id,
    };
    let domain_identity = NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: identity.chain_id,
        genesis_id: identity.genesis_hash,
    };
    let mut state = offline_restore_state(&seed, domain_identity);

    // One legacy proof-only output early in the chain: it is pruned out of the
    // rolling window later but must stay in the durable counters.
    let legacy_blinding = BlindingFactor::from_bytes([9; 32]).unwrap();
    let (legacy_proof, legacy_commitment) = range_proof_prove_bytes(123, &legacy_blinding).unwrap();
    let total = RECOVERY_CANONICAL_WINDOW_BLOCKS + 60;
    let observed_tip = CoreBlockReference {
        height: total - 1,
        hash: window_hash(total - 1, 0x10),
    };
    let mut start = 0u64;
    while start < total {
        let end = (start + 512).min(total);
        let blocks = (start..end)
            .map(|height| {
                let previous = if height == 0 {
                    [0u8; 32]
                } else {
                    window_hash(height - 1, 0x10)
                };
                let mut block = window_block(height, 0x10, previous);
                if height == 5 {
                    block.outputs.push(dom_wallet_core_sync::CoreScanOutput {
                        commitment: legacy_commitment,
                        range_proof: legacy_proof.clone(),
                        recovery_capsule: Vec::new(),
                        recovery_version: 0,
                        is_coinbase: false,
                        block_height: height,
                        block_hash: block.block_hash,
                        output_position: 0,
                    });
                }
                block
            })
            .collect();
        let batch = CoreScanBatch {
            observed_tip,
            blocks,
            commit_cursor: None,
        };
        apply_recovery_batch(&seed, chain, &identity, &mut state, &batch).unwrap();
        start = end;
    }

    assert_eq!(
        state.recovery_canonical_blocks.len() as u64,
        RECOVERY_CANONICAL_WINDOW_BLOCKS,
        "canonical anchors must be pruned to the rolling window"
    );
    assert_eq!(
        state.recovery_canonical_blocks.first().unwrap().height,
        total - RECOVERY_CANONICAL_WINDOW_BLOCKS
    );
    assert_eq!(
        state.recovery_canonical_blocks.last().unwrap().height,
        total - 1
    );
    assert_eq!(state.recovery_scanned_blocks, total);
    assert_eq!(state.recovery_scanned_outputs, 1);
    assert_eq!(state.legacy_proof_only_outputs, 1);
    state.validate().unwrap();

    // Reorg detection material stays available inside the window while pruned
    // heights rely on the durable counters instead of the anchor list.
    let safe_height = total - 4;
    assert!(state
        .recovery_canonical_blocks
        .iter()
        .any(|block| block.height == safe_height));
    assert!(!state
        .recovery_canonical_blocks
        .iter()
        .any(|block| block.height == 5));

    rewind_recovery_state(&mut state, safe_height, total - 1).unwrap();
    assert_eq!(state.recovery_scanned_blocks, total - 3);
    assert_eq!(state.recovery_scanned_outputs, 1);
    assert_eq!(state.legacy_proof_only_outputs, 1);

    let replacement = (safe_height + 1..total)
        .map(|height| {
            let previous = if height == safe_height + 1 {
                window_hash(safe_height, 0x10)
            } else {
                window_hash(height - 1, 0x60)
            };
            window_block(height, 0x60, previous)
        })
        .collect();
    let batch = CoreScanBatch {
        observed_tip: CoreBlockReference {
            height: total - 1,
            hash: window_hash(total - 1, 0x60),
        },
        blocks: replacement,
        commit_cursor: None,
    };
    apply_recovery_batch(&seed, chain, &identity, &mut state, &batch).unwrap();
    assert_eq!(state.recovery_scanned_blocks, total);
    assert_eq!(
        state.recovery_canonical_blocks.last().unwrap().block_hash,
        window_hash(total - 1, 0x60)
    );
    state.validate().unwrap();

    // Durable counters survive the pruned window through an encrypted reload.
    let temp = TempDir::new().unwrap();
    let directory = WalletDirectory::create(
        temp.path().join("window"),
        &state,
        &password(),
        KdfParameters::TEST,
    )
    .unwrap();
    let reloaded = directory.load(&password()).unwrap();
    assert_eq!(reloaded.recovery_scanned_blocks, total);
    assert_eq!(reloaded.recovery_scanned_outputs, 1);
    assert_eq!(reloaded.legacy_proof_only_outputs, 1);
    assert_eq!(
        reloaded.recovery_canonical_blocks.len() as u64,
        RECOVERY_CANONICAL_WINDOW_BLOCKS
    );
}

#[test]
fn regression_pre_window_full_list_state_migrates_and_prunes_on_next_batch() {
    let identity = identity();
    let seed = CanonicalWalletSeed::from_entropy(&[0x22; 32]).unwrap();
    let chain = RecoveryChainContext {
        network_magic: identity.network_magic,
        chain_id: identity.chain_id,
    };
    let domain_identity = NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: identity.chain_id,
        genesis_id: identity.genesis_hash,
    };
    let mut state = offline_restore_state(&seed, domain_identity);

    // Simulate an old encrypted state that still carries its complete block
    // list and whole-history legacy sum, with the durable counters unset.
    let legacy_total = RECOVERY_CANONICAL_WINDOW_BLOCKS + 400;
    for height in 0..legacy_total {
        state
            .recovery_canonical_blocks
            .push(RecoveryCanonicalBlock {
                height,
                block_hash: window_hash(height, 0x10),
                previous_block_hash: if height == 0 {
                    [0u8; 32]
                } else {
                    window_hash(height - 1, 0x10)
                },
                output_count: 1,
                legacy_proof_only_outputs: u32::from(height % 700 == 3),
            });
    }
    let expected_legacy = (0..legacy_total).filter(|height| height % 700 == 3).count() as u64;
    state.legacy_proof_only_outputs = expected_legacy;
    assert_eq!(state.recovery_scanned_blocks, 0);
    state.validate().unwrap();

    let blocks = (legacy_total..legacy_total + 2)
        .map(|height| window_block(height, 0x10, window_hash(height - 1, 0x10)))
        .collect();
    let batch = CoreScanBatch {
        observed_tip: CoreBlockReference {
            height: legacy_total + 1,
            hash: window_hash(legacy_total + 1, 0x10),
        },
        blocks,
        commit_cursor: None,
    };
    apply_recovery_batch(&seed, chain, &identity, &mut state, &batch).unwrap();

    assert_eq!(state.recovery_scanned_blocks, legacy_total + 2);
    assert_eq!(state.recovery_scanned_outputs, legacy_total);
    assert_eq!(state.legacy_proof_only_outputs, expected_legacy);
    assert_eq!(
        state.recovery_canonical_blocks.len() as u64,
        RECOVERY_CANONICAL_WINDOW_BLOCKS,
        "migrated full list must be pruned to the rolling window"
    );
    assert_eq!(
        state.recovery_canonical_blocks.last().unwrap().height,
        legacy_total + 1
    );
    state.validate().unwrap();
}

fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn assert_restored_spend(state: &WalletState, identity: &CoreChainIdentity, commitment: [u8; 33]) {
    let source = RestoredSpendSource::load(state, &commitment).unwrap();
    assert_eq!(source.commitment(), commitment);
    let input_value = source.value();
    let mut spend = SpendBuilder::new(&identity.chain_id);
    spend.add_inputs(vec![source]).unwrap();
    spend
        .add_output(input_value - 10, BlindingFactor::random())
        .unwrap();
    spend.fee(10);
    let transaction = spend.build().unwrap();
    assert!(transaction.inputs.contains(&TransactionInput {
        commitment: dom_crypto::pedersen::Commitment::from_compressed_bytes(&commitment).unwrap(),
    }));
}
