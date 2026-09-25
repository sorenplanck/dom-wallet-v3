//! Shared builders for the storage regression suites.
#![allow(dead_code)]

use dom_wallet_crypto::KdfParameters;
use dom_wallet_domain::{
    Network, NetworkIdentity, OutputRecord, OutputState, PrivateOutputBlinding,
    RecoveredOutputDomain, RecoveredOutputMetadata, RecoveryCanonicalBlock, WalletState,
};
use dom_wallet_storage::{default_node_configuration, WalletDirectory};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const PASSWORD: &str = "large-state-password";
pub const KDF: KdfParameters = KdfParameters::TEST;
pub const CURSOR_ANCHOR: u64 = 43_264;
pub const BATCH: u64 = 256;
pub const WINDOW: u64 = 2_048;

/// Deterministic pseudo-random bytes: realistic digit widths in the legacy
/// numeric encoding without depending on an RNG crate.
pub fn filled<const N: usize>(seed: u64) -> [u8; N] {
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

pub fn identity() -> NetworkIdentity {
    NetworkIdentity {
        network: Network::Mainnet,
        chain_id: filled(1),
        genesis_id: filled(2),
    }
}

pub fn cursor_bytes(anchor: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 86];
    bytes[..8].copy_from_slice(&anchor.to_le_bytes());
    bytes
}

pub fn block_hash(height: u64) -> [u8; 32] {
    filled(1_000_000 + height)
}

/// Rolling canonical window ending at `tip`, linked by previous hashes.
pub fn window_ending_at(tip: u64) -> Vec<RecoveryCanonicalBlock> {
    (tip + 1 - WINDOW..=tip)
        .map(|height| RecoveryCanonicalBlock {
            height,
            block_hash: block_hash(height),
            previous_block_hash: block_hash(height - 1),
            output_count: 1,
            legacy_proof_only_outputs: 0,
        })
        .collect()
}

pub fn push_coinbase_outputs(state: &mut WalletState, first: u64, count: u64) {
    let account = state.default_account.id;
    for index in first..first + count {
        let id = Uuid::from_u128(u128::from(index) + 1);
        state.outputs.push(OutputRecord {
            id,
            account_id: account,
            commitment: Some(filled(index * 3 + 7)),
            value: 3_300_000_000 + index,
            state: OutputState::Confirmed,
            discovered_height: 1 + index % CURSOR_ANCHOR,
            reserved_by: None,
        });
        state.private_output_blindings.push(PrivateOutputBlinding {
            output_id: id,
            blinding: filled(index * 3 + 8),
        });
        state
            .recovered_output_metadata
            .push(RecoveredOutputMetadata {
                output_id: id,
                recovery_account: 0,
                derivation_index: index + 1,
                domain: RecoveredOutputDomain::Coinbase,
                is_coinbase: true,
                block_hash: filled(index * 3 + 9),
                output_position: 0,
            });
    }
    state.recovery_allocation_floors.coinbase = first + count;
    state.non_reuse_floor = state.non_reuse_floor.max(first + count);
}

/// A synthetic heavy miner at cursor 43264 with `outputs` owned outputs.
pub fn heavy_wallet_state(outputs: u64) -> WalletState {
    let mut state = WalletState::new(
        identity(),
        filled(3),
        default_node_configuration(identity()),
    );
    push_coinbase_outputs(&mut state, 0, outputs);
    state.recovery_canonical_blocks = window_ending_at(CURSOR_ANCHOR);
    state.recovery_scanned_blocks = CURSOR_ANCHOR + 1;
    state.recovery_scanned_outputs = CURSOR_ANCHOR + 1;
    state.core_scan_cursor = Some(cursor_bytes(CURSOR_ANCHOR));
    state
}

/// What one scan batch does to the persisted state: new canonical anchors,
/// newly discovered owned outputs, and the advanced cursor.
pub fn apply_synthetic_batch(state: &mut WalletState, new_outputs: u64) {
    let anchor = u64::from_le_bytes(
        state.core_scan_cursor.as_ref().expect("cursor")[..8]
            .try_into()
            .expect("anchor bytes"),
    );
    let next_anchor = anchor + BATCH;
    for height in anchor + 1..=next_anchor {
        state
            .recovery_canonical_blocks
            .push(RecoveryCanonicalBlock {
                height,
                block_hash: block_hash(height),
                previous_block_hash: block_hash(height - 1),
                output_count: 1,
                legacy_proof_only_outputs: 0,
            });
    }
    let keep_from = next_anchor + 1 - WINDOW;
    state
        .recovery_canonical_blocks
        .retain(|block| block.height >= keep_from);
    state.recovery_scanned_blocks += BATCH;
    state.recovery_scanned_outputs += BATCH;
    let first = state.outputs.len() as u64;
    push_coinbase_outputs(state, first, new_outputs);
    state.core_scan_cursor = Some(cursor_bytes(next_anchor));
}

pub fn anchor_of(state: &WalletState) -> u64 {
    u64::from_le_bytes(
        state.core_scan_cursor.as_ref().expect("cursor")[..8]
            .try_into()
            .expect("anchor"),
    )
}

pub fn active_state_path(root: &Path) -> PathBuf {
    let active = fs::read_to_string(root.join("active-generation")).expect("active pointer");
    root.join("generations").join(active).join("state.envelope")
}

pub fn staging_leftovers(root: &Path) -> Vec<String> {
    fs::read_dir(root.join("generations"))
        .expect("generations")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with('.'))
        .collect()
}

pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create copy");
    for entry in fs::read_dir(from).expect("read fixture") {
        let entry = entry.expect("fixture entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy fixture file");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(to, fs::Permissions::from_mode(0o700)).expect("private dir");
    }
}

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v1")
}

pub fn fixture_expected() -> serde_json::Value {
    serde_json::from_slice(&fs::read(fixture_dir().join("expected.json")).unwrap()).unwrap()
}

/// Rebind a synthetic state to the identity of an existing wallet directory.
pub fn adopt(mut state: WalletState, base: &WalletState) -> WalletState {
    state.wallet_id = base.wallet_id;
    state.default_account = base.default_account.clone();
    let account = base.default_account.id;
    state
        .outputs
        .iter_mut()
        .for_each(|output| output.account_id = account);
    state.root_material = base.root_material;
    state
}

/// Create a wallet directory holding `outputs` synthetic owned outputs.
pub fn wallet_with_outputs(root: &Path, outputs: u64) -> (WalletDirectory, WalletState) {
    let wallet = WalletDirectory::create(root, &heavy_wallet_state(0), PASSWORD, KDF)
        .expect("create wallet");
    let base = wallet.load(PASSWORD).expect("load");
    let state = adopt(heavy_wallet_state(outputs), &base);
    let committed = wallet
        .commit(base.generation, state, PASSWORD, KDF)
        .expect("commit synthetic wallet");
    (wallet, committed)
}

pub fn generation_dirs(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root.join("generations"))
        .expect("generations")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    names.sort();
    names
}

pub fn unused_kdf() -> KdfParameters {
    KDF
}
