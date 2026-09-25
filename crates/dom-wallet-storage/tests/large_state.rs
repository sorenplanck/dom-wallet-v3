//! Regression coverage for the wallet-state storage limit (Mainnet report:
//! wallet cursor frozen at 43264 while the node followed the tip).
//!
//! The legacy v1 envelope serialized its ciphertext as a JSON array of decimal
//! numbers (~3.6 bytes per byte) under a 16 MiB bound, so a wallet with a few
//! thousand owned outputs could no longer commit any scan batch. These tests
//! pin the old failure, the compact v2 replacement, the lazy crash-safe
//! migration of legacy wallets, and fail-closed behaviour on corrupted files.

mod common;

use common::*;
use dom_wallet_crypto::LEGACY_V1_MAX_ENVELOPE_BYTES;
use dom_wallet_domain::{Network, NetworkIdentity, WalletState};
use dom_wallet_storage::{StateEncoding, StorageError, WalletDirectory, MAX_STATE_ENVELOPE_BYTES};
use std::fs;
use std::path::Path;

/// H + J: the old encoding cannot commit a >= 6000-output wallet; the new one
/// commits it, survives a restart, preserves state and cursor, and keeps
/// advancing the cursor batch after batch.
#[test]
fn regression_six_thousand_output_wallet_commits_restarts_and_keeps_advancing() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("heavy-miner");
    let small = heavy_wallet_state(0);
    let wallet = WalletDirectory::create(&root, &small, PASSWORD, KDF).expect("create wallet");
    let current = wallet.load(PASSWORD).expect("load");

    let mut heavy = heavy_wallet_state(6_000);
    heavy.wallet_id = current.wallet_id;
    heavy.default_account = current.default_account.clone();
    heavy
        .outputs
        .iter_mut()
        .for_each(|output| output.account_id = current.default_account.id);
    heavy.root_material = current.root_material;

    // OLD BEHAVIOR: the legacy writer refuses the state, typed and sized.
    let before = fs::read(active_state_path(&root)).expect("active bytes");
    let old = wallet.commit_with_encoding(
        current.generation,
        heavy.clone(),
        PASSWORD,
        KDF,
        StateEncoding::LegacyV1,
    );
    match old {
        Err(StorageError::StateTooLarge {
            encoding: StateEncoding::LegacyV1,
            plaintext_bytes,
            envelope_bytes: Some(envelope_bytes),
            envelope_limit_bytes,
            ..
        }) => {
            assert_eq!(envelope_limit_bytes, LEGACY_V1_MAX_ENVELOPE_BYTES as u64);
            assert!(envelope_bytes > envelope_limit_bytes);
            assert!(
                plaintext_bytes < envelope_limit_bytes,
                "only the encoding overflowed"
            );
        }
        other => panic!("legacy commit must fail with StateTooLarge, got {other:?}"),
    }
    // Nothing was published or left behind by the failed attempt.
    assert_eq!(fs::read(active_state_path(&root)).expect("active"), before);
    assert!(staging_leftovers(&root).is_empty());
    assert_eq!(
        wallet.load(PASSWORD).expect("still loads").generation,
        current.generation
    );

    // NEW BEHAVIOR: the compact writer commits the same state.
    let committed = wallet
        .commit(current.generation, heavy.clone(), PASSWORD, KDF)
        .expect("compact commit succeeds");
    let compact_size = fs::metadata(active_state_path(&root)).expect("size").len();
    assert!(compact_size < LEGACY_V1_MAX_ENVELOPE_BYTES as u64 / 2);
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );

    // J: destroy and reopen the directory, reload and validate everything.
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen after restart");
    let reloaded = wallet.load(PASSWORD).expect("reload after restart");
    reloaded.validate().expect("all invariants hold");
    assert_eq!(reloaded, committed);
    assert_eq!(reloaded.outputs.len(), 6_000);
    assert_eq!(reloaded.private_output_blindings.len(), 6_000);
    assert_eq!(anchor_of(&reloaded), CURSOR_ANCHOR);

    // Continue synchronizing: 43264 -> 43520 -> 43776, discovering outputs.
    let mut state = reloaded;
    for expected_anchor in [CURSOR_ANCHOR + BATCH, CURSOR_ANCHOR + 2 * BATCH] {
        let mut next = state.clone();
        apply_synthetic_batch(&mut next, BATCH);
        state = wallet
            .commit(state.generation, next, PASSWORD, KDF)
            .expect("batch commit");
        assert_eq!(anchor_of(&state), expected_anchor);
    }
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen");
    let final_state = wallet.load(PASSWORD).expect("reload");
    assert_eq!(anchor_of(&final_state), CURSOR_ANCHOR + 2 * BATCH);
    assert_eq!(final_state.outputs.len(), 6_000 + 2 * BATCH as usize);
    assert_eq!(final_state.recovery_canonical_blocks.len() as u64, WINDOW);
}

/// I at the storage boundary: a legacy wallet just under the old limit at
/// cursor 43264 whose next batch (43265..=43520) crosses it.
#[test]
fn batch_boundary_43264_to_43520_crosses_the_old_limit_only_in_the_legacy_format() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("boundary");
    // Grow the legacy wallet until it sits just below the legacy bound.
    let mut outputs = 4_800;
    let (wallet, legacy_state) = loop {
        let _ = fs::remove_dir_all(&root);
        let mut state = heavy_wallet_state(outputs);
        let wallet =
            WalletDirectory::create(&root, &heavy_wallet_state(0), PASSWORD, KDF).expect("create");
        let base = wallet.load(PASSWORD).expect("load");
        state.wallet_id = base.wallet_id;
        state.default_account = base.default_account.clone();
        state
            .outputs
            .iter_mut()
            .for_each(|output| output.account_id = base.default_account.id);
        state.root_material = base.root_material;
        let committed = wallet
            .commit_with_encoding(
                base.generation,
                state,
                PASSWORD,
                KDF,
                StateEncoding::LegacyV1,
            )
            .expect("legacy wallet below the old limit");
        let size = fs::metadata(active_state_path(&root)).unwrap().len() as usize;
        if size > LEGACY_V1_MAX_ENVELOPE_BYTES - 400 * 1024 {
            break (wallet, committed);
        }
        drop(wallet);
        outputs += 100;
    };
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::LegacyV1
    );
    assert_eq!(anchor_of(&legacy_state), CURSOR_ANCHOR);

    let mut batch = legacy_state.clone();
    apply_synthetic_batch(&mut batch, BATCH);
    assert_eq!(anchor_of(&batch), 43_520);

    // Old writer: the batch cannot be committed; cursor stays at 43264.
    assert!(matches!(
        wallet.commit_with_encoding(
            legacy_state.generation,
            batch.clone(),
            PASSWORD,
            KDF,
            StateEncoding::LegacyV1
        ),
        Err(StorageError::StateTooLarge { .. })
    ));
    assert_eq!(anchor_of(&wallet.load(PASSWORD).unwrap()), CURSOR_ANCHOR);

    // New writer: the same batch commits and migrates the wallet.
    let committed = wallet
        .commit(legacy_state.generation, batch, PASSWORD, KDF)
        .expect("compact batch commit");
    assert_eq!(anchor_of(&committed), 43_520);
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen");
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    let reloaded = wallet.load(PASSWORD).expect("reload");
    assert_eq!(anchor_of(&reloaded), 43_520);
    assert_eq!(reloaded.outputs.len(), outputs as usize + BATCH as usize);
}

/// K: a wallet written by the released (pre-v2) code opens, is preserved,
/// migrates on the next commit and reopens; the legacy generation is kept.
#[test]
fn legacy_fixture_opens_preserves_state_and_migrates_on_next_commit() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v1");
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("expected.json")).unwrap()).unwrap();
    let password = expected["password"].as_str().unwrap();
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("legacy-wallet");
    copy_dir(&fixture.join("wallet"), &root);
    let untouched = fs::read(active_state_path(&root)).unwrap();

    let wallet = WalletDirectory::open(&root).expect("open legacy wallet");
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::LegacyV1
    );
    let state = wallet.load(password).expect("new code loads legacy state");
    // Opening and loading never rewrites the legacy generation.
    assert_eq!(fs::read(active_state_path(&root)).unwrap(), untouched);
    assert_eq!(
        state.wallet_id.to_string(),
        expected["wallet_id"].as_str().unwrap()
    );
    assert_eq!(state.generation, expected["generation"].as_u64().unwrap());
    assert_eq!(
        state.outputs.len() as u64,
        expected["outputs"].as_u64().unwrap()
    );
    assert_eq!(state.private_output_blindings.len(), state.outputs.len());
    assert_eq!(
        state.recovery_canonical_blocks.len() as u64,
        expected["recovery_canonical_blocks"].as_u64().unwrap()
    );
    assert_eq!(state.core_scan_cursor.as_ref().unwrap().len(), 86);
    assert!(
        wallet.load(password.trim_end_matches('d')).is_err(),
        "wrong password rejected"
    );

    let legacy_generation = state.generation;
    let migrated = wallet
        .commit(state.generation, state.clone(), password, KDF)
        .expect("commit migrates to compact");
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    let raw: serde_json::Value =
        serde_json::from_slice(&fs::read(active_state_path(&root)).unwrap()).unwrap();
    assert_eq!(raw["header"]["envelope_version"], 2);
    assert!(raw["ciphertext"].is_string());

    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen migrated wallet");
    let reloaded = wallet.load(password).expect("reload migrated wallet");
    assert_eq!(reloaded, migrated);
    let mut comparable = reloaded.clone();
    comparable.generation = state.generation;
    assert_eq!(comparable, state, "migration preserved every field");
    // The legacy generation stays readable for recovery.
    let previous = wallet
        .load_generation_for_recovery(legacy_generation, password)
        .expect("legacy generation retained");
    assert_eq!(previous, state);
    // Idempotent: further commits keep the compact format.
    let again = wallet
        .commit(reloaded.generation, reloaded, password, KDF)
        .expect("second commit");
    assert_eq!(again.generation, legacy_generation + 2);
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
}

#[test]
fn legacy_backup_fixture_still_imports() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v1");
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.join("expected.json")).unwrap()).unwrap();
    let directory = tempfile::tempdir().expect("tempdir");
    let destination = directory.path().join("imported");
    let identity = NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: [4; 32],
        genesis_id: [5; 32],
    };
    let wallet = WalletDirectory::import_backup(
        &destination,
        fixture.join("legacy.backup"),
        expected["backup_password"].as_str().unwrap(),
        "imported-wallet-password",
        &identity,
        KDF,
    )
    .expect("legacy backup imports");
    let state = wallet
        .load("imported-wallet-password")
        .expect("load imported");
    assert_eq!(
        state.wallet_id.to_string(),
        expected["wallet_id"].as_str().unwrap()
    );
    assert_eq!(
        state.outputs.len() as u64,
        expected["outputs"].as_u64().unwrap()
    );
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
}

/// A crash after the compact generation was staged but before the pointer
/// moved leaves the legacy generation authoritative; the next commit cleans
/// the orphan and publishes normally.
#[test]
fn interrupted_migration_keeps_the_legacy_generation_authoritative() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v1");
    let password = "legacy-fixture-password";
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("interrupted");
    copy_dir(&fixture.join("wallet"), &root);
    let wallet = WalletDirectory::open(&root).expect("open");
    let state = wallet.load(password).expect("load");
    let staged = wallet
        .stage_generation(state.generation, state.clone(), password, KDF)
        .expect("stage compact generation");
    // Simulated crash: never published.
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen after crash");
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::LegacyV1
    );
    let recovered = wallet
        .load(password)
        .expect("legacy state still authoritative");
    assert_eq!(recovered, state);
    let committed = wallet
        .commit(state.generation, recovered, password, KDF)
        .expect("next commit replaces the orphan");
    assert_eq!(committed.generation, staged.generation);
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
}

fn fresh_compact_wallet(root: &Path) -> (WalletDirectory, WalletState) {
    let state = heavy_wallet_state(25);
    let wallet = WalletDirectory::create(root, &state, PASSWORD, KDF).expect("create");
    let loaded = wallet.load(PASSWORD).expect("load");
    let committed = wallet
        .commit(loaded.generation, loaded, PASSWORD, KDF)
        .expect("second generation");
    (wallet, committed)
}

/// L: corrupted inputs fail loudly and never turn into an empty or silently
/// replaced wallet; restoring the original bytes restores the wallet.
#[test]
fn corrupted_state_envelopes_fail_closed_without_losing_the_wallet() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("corruption");
    let (wallet, committed) = fresh_compact_wallet(&root);
    let path = active_state_path(&root);
    let original = fs::read(&path).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&original).unwrap();

    let assert_fails_then_recovers = |bytes: Vec<u8>, label: &str| {
        fs::write(&path, &bytes).unwrap();
        let error = wallet.load(PASSWORD).expect_err(label);
        assert!(
            matches!(
                error,
                StorageError::AuthenticatedPayloadCorrupt | StorageError::FileSizeOutOfBounds
            ),
            "{label}: unexpected {error:?}"
        );
        // The previous generation remains a recovery source.
        let previous = wallet
            .load_generation_for_recovery(committed.generation - 1, PASSWORD)
            .expect("previous generation intact");
        assert_eq!(previous.outputs.len(), committed.outputs.len());
        fs::write(&path, &original).unwrap();
        assert_eq!(
            wallet.load(PASSWORD).expect("restored"),
            committed,
            "{label}"
        );
    };

    // Truncated file.
    assert_fails_then_recovers(original[..original.len() / 2].to_vec(), "truncated");
    // Valid base64 carrying different ciphertext bytes.
    let mut flipped = json.clone();
    let text = flipped["ciphertext"].as_str().unwrap().to_owned();
    let replacement = if text.starts_with('A') { "B" } else { "A" };
    flipped["ciphertext"] = serde_json::Value::String(format!("{replacement}{}", &text[1..]));
    assert_fails_then_recovers(serde_json::to_vec(&flipped).unwrap(), "invalid ciphertext");
    // Unknown envelope version.
    let mut unknown = json.clone();
    unknown["header"]["envelope_version"] = serde_json::Value::from(99);
    assert_fails_then_recovers(serde_json::to_vec(&unknown).unwrap(), "unknown version");
    // Legacy representation under a v2 header.
    let mut mismatched = json.clone();
    mismatched["ciphertext"] = serde_json::Value::Array(vec![serde_json::Value::from(1); 64]);
    assert_fails_then_recovers(serde_json::to_vec(&mismatched).unwrap(), "representation");
    // Envelope above the hard safety limit (sparse; nothing is allocated).
    let oversized = fs::OpenOptions::new().write(true).open(&path).unwrap();
    oversized
        .set_len(MAX_STATE_ENVELOPE_BYTES as u64 + 1)
        .unwrap();
    drop(oversized);
    assert!(matches!(
        wallet.load(PASSWORD),
        Err(StorageError::FileSizeOutOfBounds)
    ));
    fs::write(&path, &original).unwrap();
    assert_eq!(wallet.load(PASSWORD).unwrap(), committed);

    // Authentication failure: wrong password is a typed error, never data loss.
    assert!(matches!(
        wallet.load("not-the-password"),
        Err(StorageError::InvalidPassword)
    ));
    assert_eq!(wallet.load(PASSWORD).unwrap(), committed);
}

/// A "legacy" envelope bigger than any released writer could produce is
/// rejected even though it is below the new hard limit.
#[test]
fn oversized_legacy_envelope_is_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("oversized-legacy");
    let (wallet, _) = fresh_compact_wallet(&root);
    let path = active_state_path(&root);
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    json["header"]["envelope_version"] = serde_json::Value::from(1);
    json["ciphertext"] = serde_json::Value::Array(
        std::iter::repeat_n(
            serde_json::Value::from(255),
            LEGACY_V1_MAX_ENVELOPE_BYTES / 4 + 1,
        )
        .collect(),
    );
    let bytes = serde_json::to_vec(&json).unwrap();
    assert!(bytes.len() > LEGACY_V1_MAX_ENVELOPE_BYTES);
    assert!(bytes.len() < MAX_STATE_ENVELOPE_BYTES);
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        wallet.load(PASSWORD),
        Err(StorageError::AuthenticatedPayloadCorrupt)
    ));
}

fn pad_file_to(path: &Path, total: u64) {
    let file = fs::OpenOptions::new().append(true).open(path).unwrap();
    let current = file.metadata().unwrap().len();
    assert!(current <= total);
    // Trailing JSON whitespace, written in chunks.
    let chunk = vec![b' '; 1 << 20];
    let mut remaining = total - current;
    let mut writer = std::io::BufWriter::new(file);
    while remaining > 0 {
        let take = remaining.min(chunk.len() as u64) as usize;
        std::io::Write::write_all(&mut writer, &chunk[..take]).unwrap();
        remaining -= take as u64;
    }
}

/// Byte-exact file bounds through the complete open path (structural
/// inspection, open, load): below/at the bound opens, one byte above fails
/// closed, for the compact bound and for the legacy v1 bound.
#[test]
fn state_file_bounds_below_at_and_above_through_the_full_open_path() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("bounds");
    let (wallet, committed) = fresh_compact_wallet(&root);
    drop(wallet);
    let path = active_state_path(&root);
    let original = fs::read(&path).unwrap();
    for total in [
        MAX_STATE_ENVELOPE_BYTES as u64 - 1,
        MAX_STATE_ENVELOPE_BYTES as u64,
    ] {
        fs::write(&path, &original).unwrap();
        pad_file_to(&path, total);
        WalletDirectory::inspect_structure(&root).expect("inspect at bound");
        let wallet = WalletDirectory::open(&root).expect("open at bound");
        assert_eq!(wallet.load(PASSWORD).unwrap(), committed);
    }
    fs::write(&path, &original).unwrap();
    pad_file_to(&path, MAX_STATE_ENVELOPE_BYTES as u64 + 1);
    assert!(WalletDirectory::open(&root).is_err());
    assert!(WalletDirectory::inspect_structure(&root).is_err());
    fs::write(&path, &original).unwrap();
    assert_eq!(
        WalletDirectory::open(&root)
            .unwrap()
            .load(PASSWORD)
            .unwrap(),
        committed
    );

    // Legacy v1 bound, from the released-code fixture.
    let expected = fixture_expected();
    let password = expected["password"].as_str().unwrap();
    let legacy_root = directory.path().join("legacy-bounds");
    copy_dir(&fixture_dir().join("wallet"), &legacy_root);
    let legacy_path = active_state_path(&legacy_root);
    let legacy_original = fs::read(&legacy_path).unwrap();
    let reference = WalletDirectory::open(&legacy_root)
        .unwrap()
        .load(password)
        .unwrap();
    for total in [
        LEGACY_V1_MAX_ENVELOPE_BYTES as u64 - 1,
        LEGACY_V1_MAX_ENVELOPE_BYTES as u64,
    ] {
        fs::write(&legacy_path, &legacy_original).unwrap();
        pad_file_to(&legacy_path, total);
        let wallet = WalletDirectory::open(&legacy_root).expect("open legacy at bound");
        assert_eq!(wallet.load(password).unwrap(), reference);
    }
    fs::write(&legacy_path, &legacy_original).unwrap();
    pad_file_to(&legacy_path, LEGACY_V1_MAX_ENVELOPE_BYTES as u64 + 1);
    assert!(WalletDirectory::open(&legacy_root).is_err());
}
