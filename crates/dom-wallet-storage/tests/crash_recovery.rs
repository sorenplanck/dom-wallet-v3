//! Crash points of the generation publication protocol during and after the
//! legacy -> compact migration. Each test reconstructs the exact on-disk
//! state a crash leaves behind, restarts, and requires one coherent
//! generation: state and cursor always come from the same encrypted file.

mod common;

use common::*;
use dom_wallet_storage::{StateEncoding, StorageError, WalletDirectory};
use std::fs;

fn legacy_copy(name: &str) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join(name);
    copy_dir(&fixture_dir().join("wallet"), &root);
    let password = fixture_expected()["password"].as_str().unwrap().to_owned();
    (directory, root, password)
}

/// Crash while the compact generation was still being written: a partial
/// staging directory is left behind.
#[test]
fn crash_during_generation_write_leaves_the_previous_generation_authoritative() {
    let (_directory, root, password) = legacy_copy("partial-write");
    let wallet = WalletDirectory::open(&root).unwrap();
    let legacy = wallet.load(&password).unwrap();
    drop(wallet);
    let staging = root.join("generations").join(format!(
        ".generation-{:020}.crash.staging",
        legacy.generation + 1
    ));
    fs::create_dir(&staging).unwrap();
    fs::write(
        staging.join("state.envelope"),
        b"{\"header\":{\"magic\":[68,79",
    )
    .unwrap();

    let wallet = WalletDirectory::open(&root).expect("reopen");
    assert_eq!(wallet.load(&password).unwrap(), legacy);
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::LegacyV1
    );
    let migrated = wallet
        .commit(legacy.generation, legacy.clone(), &password, KDF)
        .expect("commit after the crash");
    assert_eq!(migrated.generation, legacy.generation + 1);
    // Cleanup never touches dot-prefixed staging names.
    wallet.cleanup_superseded_generations(&[]).unwrap();
    assert_eq!(wallet.load(&password).unwrap(), migrated);
}

/// Crash after the pointer moved but before metadata was rewritten: the
/// existing interrupted-publication repair adopts the new generation, whose
/// state and cursor come together from the same file.
#[test]
fn crash_between_pointer_and_metadata_is_repaired_to_the_new_generation() {
    let (_directory, root, password) = legacy_copy("pointer-first");
    let wallet = WalletDirectory::open(&root).unwrap();
    let legacy = wallet.load(&password).unwrap();
    let mut next = legacy.clone();
    let mut cursor = next.core_scan_cursor.clone().unwrap();
    cursor[0] ^= 0xff;
    next.core_scan_cursor = Some(cursor.clone());
    let staged = wallet
        .stage_generation(legacy.generation, next, &password, KDF)
        .expect("stage compact generation");
    let metadata_before = fs::read(root.join("metadata.json")).unwrap();
    // First half of publish_pointer_and_metadata, then the crash.
    fs::write(
        root.join("active-generation"),
        format!("generation-{:020}", staged.generation),
    )
    .unwrap();
    drop(wallet);

    WalletDirectory::inspect_structure(&root).expect("interrupted publication is coherent");
    let wallet = WalletDirectory::open(&root).expect("reopen");
    let recovered = wallet.load(&password).expect("repair on load");
    assert_eq!(recovered, staged);
    assert_eq!(
        recovered.core_scan_cursor,
        Some(cursor),
        "cursor from the same generation"
    );
    assert_ne!(
        fs::read(root.join("metadata.json")).unwrap(),
        metadata_before,
        "metadata repaired"
    );
    assert_eq!(
        wallet.active_state_encoding().unwrap(),
        StateEncoding::CompactV2
    );
    // The legacy generation is still there for recovery.
    assert_eq!(
        wallet
            .load_generation_for_recovery(legacy.generation, &password)
            .unwrap(),
        legacy
    );
    let next = wallet
        .commit(recovered.generation, recovered.clone(), &password, KDF)
        .expect("normal commits resume");
    assert_eq!(next.generation, staged.generation + 1);
}

/// A pointer to a damaged generation fails closed; the previous generation
/// is recoverable and nothing silently falls back to an older cursor.
#[test]
fn damaged_active_generation_fails_closed_and_previous_stays_recoverable() {
    let (_directory, root, password) = legacy_copy("damaged");
    let wallet = WalletDirectory::open(&root).unwrap();
    let legacy = wallet.load(&password).unwrap();
    let migrated = wallet
        .commit(legacy.generation, legacy.clone(), &password, KDF)
        .unwrap();
    drop(wallet);
    let state = active_state_path(&root);
    let bytes = fs::read(&state).unwrap();
    fs::write(&state, &bytes[..bytes.len() - 40]).unwrap();

    let previous_path = root
        .join("generations")
        .join(format!("generation-{:020}", legacy.generation))
        .join("state.envelope");
    let previous_bytes = fs::read(&previous_path).unwrap();
    // Opening refuses the damaged active generation (typed, fail closed);
    // it never falls back to an older generation and older cursor.
    assert!(matches!(
        WalletDirectory::open(&root),
        Err(StorageError::AuthenticatedPayloadCorrupt)
    ));
    assert_eq!(fs::read(&previous_path).unwrap(), previous_bytes);
    assert_eq!(
        fs::read(&state).unwrap(),
        bytes[..bytes.len() - 40].to_vec()
    );
    // Once the damaged file is restored (e.g. from a copy), both the current
    // and the retained pre-migration generation load.
    fs::write(&state, &bytes).unwrap();
    let wallet = WalletDirectory::open(&root).expect("open after repair");
    assert_eq!(wallet.load(&password).unwrap(), migrated);
    assert_eq!(
        wallet
            .load_generation_for_recovery(legacy.generation, &password)
            .expect("previous generation"),
        legacy
    );
}
