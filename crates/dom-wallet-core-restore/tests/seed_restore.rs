use dom_consensus::{Transaction, TransactionInput};
use dom_crypto::{
    pedersen::BlindingFactor, range_proof_prove_bytes, recovery::RECOVERY_VERSION,
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
    RestoredSpendSource, SeedRestoreCompletion, SeedRestoreError, SeedRestoreProgress,
    SeedRestoreService, SeedRestoreWarning,
};
use dom_wallet_core_sync::{CoreBlockReference, CoreChainIdentity};
use dom_wallet_crypto::KdfParameters;
use dom_wallet_domain::{
    Network, NetworkIdentity, OutputState, RecoveryOutputClass, SeedRestoreStatus, WalletState,
};
use dom_wallet_storage::{default_node_configuration, WalletDirectory};
use std::{
    fs,
    sync::{Arc, Mutex},
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
            })),
        }
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
        let state = self.state.lock().unwrap();
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
        protocol_version: dom_core::PROTOCOL_VERSION,
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
