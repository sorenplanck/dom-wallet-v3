//! Migration, pre-migration snapshot retention, rollback boundaries and
//! backups across the legacy (v1) and compact (v2) envelopes.
//!
//! Three distinct guarantees are exercised separately:
//! - read compatibility: the new code reads every v1 file (state, rescan plan,
//!   authenticator, backups) produced by the released code;
//! - snapshot recovery: the exact pre-migration v1 generation stays on disk,
//!   protected from cleanup, until explicitly released;
//! - no implicit downgrade: nothing rewrites the current state as v1.

mod common;

use common::*;
use dom_wallet_crypto::LEGACY_V1_MAX_ENVELOPE_BYTES;
use dom_wallet_domain::{Network, NetworkIdentity, ScanBounds, ScanTarget};
use dom_wallet_storage::{StateEncoding, StorageError, WalletDirectory};
use std::fs;

fn fixture_identity() -> NetworkIdentity {
    NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: [4; 32],
        genesis_id: [5; 32],
    }
}

fn copied_fixture_wallet(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join(name);
    copy_dir(&fixture_dir().join("wallet"), &root);
    (directory, root)
}

#[test]
fn pre_migration_snapshot_survives_cleanup_until_explicitly_released() {
    let expected = fixture_expected();
    let password = expected["password"].as_str().unwrap();
    let (_directory, root) = copied_fixture_wallet("snapshot");
    let wallet = WalletDirectory::open(&root).expect("open");
    let legacy = wallet.load(password).expect("load legacy");
    let legacy_generation = legacy.generation;
    assert_eq!(wallet.pre_migration_snapshot_generation().unwrap(), None);

    // Migration plus several compact commits.
    let mut state = legacy.clone();
    for _ in 0..4 {
        state = wallet
            .commit(state.generation, state.clone(), password, KDF)
            .expect("compact commit");
    }
    assert_eq!(
        wallet.pre_migration_snapshot_generation().unwrap(),
        Some(legacy_generation)
    );
    assert_eq!(
        wallet.generation_encoding(legacy_generation).unwrap(),
        StateEncoding::LegacyV1
    );

    // Routine cleanup keeps: active, one superseded generation, the snapshot.
    wallet.cleanup_superseded_generations(&[]).expect("cleanup");
    let active = state.generation;
    let mut expected_dirs = vec![
        format!("generation-{legacy_generation:020}"),
        format!("generation-{:020}", active - 1),
        format!("generation-{active:020}"),
    ];
    expected_dirs.sort();
    assert_eq!(generation_dirs(&root), expected_dirs);
    // The exact pre-update state is recoverable (read-only).
    let recovered = wallet
        .load_generation_for_recovery(legacy_generation, password)
        .expect("snapshot recovery");
    assert_eq!(recovered, legacy);
    // Idempotent.
    wallet
        .cleanup_superseded_generations(&[])
        .expect("cleanup again");
    assert_eq!(generation_dirs(&root), expected_dirs);

    // Explicit release after validation; retention is bounded.
    wallet.release_pre_migration_snapshot().expect("release");
    assert_eq!(wallet.pre_migration_snapshot_generation().unwrap(), None);
    assert_eq!(
        fs::read_to_string(root.join("pre-migration-snapshot")).unwrap(),
        "released"
    );
    assert!(!generation_dirs(&root).contains(&format!("generation-{legacy_generation:020}")));
    wallet
        .release_pre_migration_snapshot()
        .expect("release is idempotent");
    let after = wallet
        .commit(state.generation, state.clone(), password, KDF)
        .expect("commits continue");
    assert_eq!(wallet.pre_migration_snapshot_generation().unwrap(), None);
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen");
    assert_eq!(wallet.load(password).unwrap(), after);
}

#[test]
fn snapshot_marker_written_before_a_crashed_publication_never_releases_the_active_state() {
    let expected = fixture_expected();
    let password = expected["password"].as_str().unwrap();
    let (_directory, root) = copied_fixture_wallet("marker-crash");
    let wallet = WalletDirectory::open(&root).expect("open");
    let legacy = wallet.load(password).expect("load");
    // Simulate: marker durably written, then a crash before the pointer moved.
    fs::write(
        root.join("pre-migration-snapshot"),
        format!("generation-{:020}", legacy.generation),
    )
    .unwrap();
    drop(wallet);
    let wallet = WalletDirectory::open(&root).expect("reopen");
    assert_eq!(wallet.load(password).unwrap(), legacy);
    assert_eq!(
        wallet.pre_migration_snapshot_generation().unwrap(),
        Some(legacy.generation)
    );
    // The snapshot is the active generation: releasing it is refused.
    assert!(matches!(
        wallet.release_pre_migration_snapshot(),
        Err(StorageError::GenerationConflict)
    ));
    wallet.cleanup_superseded_generations(&[]).expect("cleanup");
    assert_eq!(wallet.load(password).unwrap(), legacy);
    // Completing the migration later keeps pointing at the same snapshot.
    let migrated = wallet
        .commit(legacy.generation, legacy.clone(), password, KDF)
        .expect("migrate");
    assert_eq!(
        wallet.pre_migration_snapshot_generation().unwrap(),
        Some(legacy.generation)
    );
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    assert_eq!(migrated.generation, legacy.generation + 1);
}

#[test]
fn wallets_created_by_the_new_code_have_no_snapshot() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("fresh");
    let (wallet, state) = wallet_with_outputs(&root, 10);
    assert_eq!(wallet.pre_migration_snapshot_generation().unwrap(), None);
    assert_eq!(
        fs::read_to_string(root.join("pre-migration-snapshot")).unwrap(),
        "none"
    );
    wallet.release_pre_migration_snapshot().expect("no-op");
    assert_eq!(wallet.load(PASSWORD).unwrap(), state);
}

/// Pre-authenticator legacy wallets: loading adds the authenticator but never
/// rewrites or migrates the state generation.
#[test]
fn opening_a_legacy_wallet_never_migrates_its_state() {
    let expected = fixture_expected();
    let password = expected["password"].as_str().unwrap();
    let (_directory, root) = copied_fixture_wallet("open-only");
    fs::remove_file(root.join("authentication.envelope")).unwrap();
    let state_path = active_state_path(&root);
    let before = fs::read(&state_path).unwrap();
    let before_generations = generation_dirs(&root);
    for _ in 0..3 {
        let wallet = WalletDirectory::open(&root).expect("open");
        WalletDirectory::inspect_structure(&root).expect("inspect");
        let state = wallet.load(password).expect("load");
        assert_eq!(
            state.wallet_id.to_string(),
            expected["wallet_id"].as_str().unwrap()
        );
        assert_eq!(
            wallet.active_state_encoding().unwrap(),
            StateEncoding::LegacyV1
        );
        let plan = wallet
            .load_rescan_plan(&state, password)
            .expect("legacy rescan plan readable")
            .expect("plan present");
        assert_eq!(
            plan.plan_id.to_string(),
            expected["rescan_plan_id"].as_str().unwrap()
        );
    }
    assert_eq!(
        fs::read(&state_path).unwrap(),
        before,
        "state untouched by opening"
    );
    assert_eq!(generation_dirs(&root), before_generations);
    assert!(!root.join("pre-migration-snapshot").exists());
    assert!(
        root.join("authentication.envelope").exists(),
        "authenticator restored"
    );
}

#[test]
fn legacy_backup_with_rescan_plan_imports_and_keeps_the_plan() {
    let expected = fixture_expected();
    let directory = tempfile::tempdir().expect("tempdir");
    let destination = directory.path().join("imported");
    let wallet = WalletDirectory::import_backup(
        &destination,
        fixture_dir().join("legacy-with-rescan-plan.backup"),
        expected["backup_password"].as_str().unwrap(),
        "imported-wallet-password",
        &fixture_identity(),
        KDF,
    )
    .expect("legacy backup with plan imports");
    let state = wallet.load("imported-wallet-password").expect("load");
    assert_eq!(
        state.wallet_id.to_string(),
        expected["wallet_id"].as_str().unwrap()
    );
    assert_eq!(
        state.outputs.len() as u64,
        expected["outputs"].as_u64().unwrap()
    );
    let plan = wallet
        .load_rescan_plan(&state, "imported-wallet-password")
        .unwrap()
        .expect("plan imported");
    assert_eq!(
        plan.plan_id.to_string(),
        expected["rescan_plan_id"].as_str().unwrap()
    );
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    // A legacy backup file is bigger than 16 MiB? No: the legacy backup bound
    // was 20 MiB and its envelope is not held to the 16 MiB state-file bound.
    assert!(
        fs::metadata(fixture_dir().join("legacy.backup"))
            .unwrap()
            .len()
            < 20 * 1024 * 1024
    );
}

/// A compact wallet whose envelope is larger than the old 16 MiB bound goes
/// through every storage path: create/commit, structural inspection, open,
/// load, rescan plan, backup export, import elsewhere, and further commits.
#[test]
fn compact_wallet_above_sixteen_mib_passes_every_storage_path() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("twenty-thousand");
    let (wallet, committed) = wallet_with_outputs(&root, 21_000);
    // The legacy writer rejects this state before any KDF work: its
    // plaintext alone already exceeds the legacy bound.
    assert!(matches!(
        wallet.commit_with_encoding(
            committed.generation,
            committed.clone(),
            PASSWORD,
            KDF,
            StateEncoding::LegacyV1
        ),
        Err(StorageError::StateTooLarge {
            envelope_bytes: None,
            ..
        })
    ));
    let envelope_len = fs::metadata(active_state_path(&root)).unwrap().len();
    assert!(
        envelope_len > LEGACY_V1_MAX_ENVELOPE_BYTES as u64,
        "the compact envelope itself exceeds 16 MiB ({envelope_len})"
    );
    let mut planned = committed.clone();
    planned
        .prepare_rescan(ScanTarget {
            target_height: CURSOR_ANCHOR,
            target_block_hash: block_hash(CURSOR_ANCHOR),
            source_identity: "large-wallet-test".into(),
            scan_bounds: ScanBounds {
                start_height: 1,
                end_height: CURSOR_ANCHOR,
                max_pages: 200,
                max_records_per_page: 256,
            },
            evidence_version: 1,
        })
        .unwrap();
    let plan = planned.rescan_plan.clone().unwrap();
    wallet
        .save_rescan_plan(&committed, &plan, PASSWORD, KDF)
        .expect("large rescan plan (carries every provisional output)");
    drop(wallet);

    WalletDirectory::inspect_structure(&root).expect("structural inspection");
    let wallet = WalletDirectory::open(&root).expect("open");
    let loaded = wallet.load(PASSWORD).expect("load");
    assert_eq!(loaded, committed);
    assert_eq!(
        wallet.load_rescan_plan(&loaded, PASSWORD).unwrap().unwrap(),
        plan
    );

    let backup = directory.path().join("large.backup");
    wallet
        .export_backup(PASSWORD, "backup-password-xyz", KDF, &backup)
        .expect("export large backup");
    assert!(fs::metadata(&backup).unwrap().len() > 20 * 1024 * 1024);
    let imported_root = directory.path().join("imported");
    let imported = WalletDirectory::import_backup(
        &imported_root,
        &backup,
        "backup-password-xyz",
        "new-wallet-password",
        &identity(),
        KDF,
    )
    .expect("import large backup");
    let restored = imported.load("new-wallet-password").expect("load imported");
    let mut comparable = restored.clone();
    comparable.generation = loaded.generation;
    assert_eq!(comparable, loaded, "backup preserved the whole state");
    assert_eq!(
        imported
            .load_rescan_plan(&restored, "new-wallet-password")
            .unwrap()
            .unwrap(),
        plan
    );

    // Synchronization continues on the restored copy.
    let mut next = restored.clone();
    apply_synthetic_batch(&mut next, BATCH);
    let advanced = imported
        .commit(restored.generation, next, "new-wallet-password", KDF)
        .expect("restored wallet keeps committing");
    assert_eq!(anchor_of(&advanced), CURSOR_ANCHOR + BATCH);
    drop(imported);
    let imported = WalletDirectory::open(&imported_root).expect("reopen imported");
    assert_eq!(
        anchor_of(&imported.load("new-wallet-password").unwrap()),
        CURSOR_ANCHOR + BATCH
    );
}

/// The legacy writer refuses states that do not fit: there is no downgrade of
/// a large current state and nothing is ever dropped to make it fit.
#[test]
fn legacy_export_of_an_oversized_state_is_refused_not_truncated() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("no-downgrade");
    let (wallet, committed) = wallet_with_outputs(&root, 6_000);
    let before = fs::read(active_state_path(&root)).unwrap();
    assert!(matches!(
        wallet.commit_with_encoding(
            committed.generation,
            committed.clone(),
            PASSWORD,
            KDF,
            StateEncoding::LegacyV1
        ),
        Err(StorageError::StateTooLarge { .. })
    ));
    assert_eq!(fs::read(active_state_path(&root)).unwrap(), before);
    assert_eq!(wallet.load(PASSWORD).unwrap(), committed);
}

/// A wallet created by the new code, taken back to a released build that
/// wrote v1 generations, then upgraded again: the most recent superseded v1
/// generation is retained as the snapshot (bounded: one).
#[test]
fn downgrade_then_upgrade_retains_the_latest_legacy_generation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("round-trip");
    let (wallet, state) = wallet_with_outputs(&root, 5);
    assert_eq!(wallet.pre_migration_snapshot_generation().unwrap(), None);
    // What a released build does on its next commits: v1 generations.
    let mut state = state;
    for _ in 0..2 {
        state = wallet
            .commit_with_encoding(
                state.generation,
                state.clone(),
                PASSWORD,
                KDF,
                StateEncoding::LegacyV1,
            )
            .unwrap();
    }
    let last_legacy = state.generation;
    let upgraded = wallet
        .commit(state.generation, state.clone(), PASSWORD, KDF)
        .unwrap();
    assert_eq!(
        wallet.pre_migration_snapshot_generation().unwrap(),
        Some(last_legacy)
    );
    wallet.cleanup_superseded_generations(&[]).unwrap();
    assert_eq!(
        wallet
            .load_generation_for_recovery(last_legacy, PASSWORD)
            .unwrap(),
        state
    );
    assert_eq!(wallet.load(PASSWORD).unwrap(), upgraded);
}
