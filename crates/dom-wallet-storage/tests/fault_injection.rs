//! Fault injection against the storage commit protocol.
//!
//! These tests close the last gap named by the operational status report:
//! a commit interrupted by a full disk, a read-only filesystem, or a
//! permission failure must fail closed with a typed error, leave the
//! active generation exactly where it was, keep the wallet readable, and
//! recover completely once the fault clears.
//!
//! Two fault mechanisms are used so the suite works both privileged and
//! unprivileged. `RLIMIT_FSIZE` (with `SIGXFSZ` ignored) makes a write
//! fail mid-commit for any user, root included. Real mounts — a small
//! tmpfs for genuine `ENOSPC` and a read-only remount for `EROFS` — are
//! used when the test runs as root and the environment permits mounting;
//! when it cannot, the mount-based test states so and passes vacuously
//! while the rlimit and chmod paths still prove the invariants.

#![cfg(unix)]

use dom_wallet_crypto::KdfParameters;
use dom_wallet_domain::{Network, NetworkIdentity, WalletState};
use dom_wallet_storage::{default_node_configuration, StorageError, WalletDirectory};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Process-wide faults (rlimits) must never overlap another test.
static SERIAL: Mutex<()> = Mutex::new(());

fn identity() -> NetworkIdentity {
    NetworkIdentity {
        network: Network::PrivateTestnet,
        chain_id: [4; 32],
        genesis_id: [5; 32],
    }
}

fn fresh_state() -> WalletState {
    WalletState::new(identity(), [6; 32], default_node_configuration(identity()))
}

fn active_generation_bytes(root: &Path) -> Vec<u8> {
    fs::read(root.join("active-generation")).expect("active pointer must exist")
}

fn staging_leftovers(root: &Path) -> Vec<String> {
    fs::read_dir(root.join("generations"))
        .expect("generations dir must exist")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("staging"))
        .collect()
}

/// Cap the bytes this process may write to any file; restores on drop.
struct FileSizeCap {
    previous: libc::rlimit,
}

impl FileSizeCap {
    fn install(limit_bytes: u64) -> Self {
        unsafe {
            // Without this the kernel delivers SIGXFSZ and kills the test
            // runner instead of failing the write with EFBIG.
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let mut previous = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                libc::getrlimit(libc::RLIMIT_FSIZE, &mut previous),
                0,
                "getrlimit failed"
            );
            let capped = libc::rlimit {
                rlim_cur: limit_bytes,
                rlim_max: previous.rlim_max,
            };
            assert_eq!(
                libc::setrlimit(libc::RLIMIT_FSIZE, &capped),
                0,
                "setrlimit failed"
            );
            Self { previous }
        }
    }
}

impl Drop for FileSizeCap {
    fn drop(&mut self) {
        unsafe {
            libc::setrlimit(libc::RLIMIT_FSIZE, &self.previous);
        }
    }
}

/// A tmpfs mount that unmounts on drop, even when an assertion panics.
struct TmpfsMount {
    path: PathBuf,
}

impl TmpfsMount {
    fn try_mount(path: &Path, size: &str) -> Option<Self> {
        let mounted = Command::new("mount")
            .args(["-t", "tmpfs", "-o", &format!("size={size}"), "tmpfs"])
            .arg(path)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        mounted.then(|| Self {
            path: path.to_path_buf(),
        })
    }

    fn remount(&self, mode: &str) -> bool {
        Command::new("mount")
            .args(["-o", &format!("remount,{mode}")])
            .arg(&self.path)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

impl Drop for TmpfsMount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.path).status();
    }
}

/// A write that dies mid-commit must not move the active generation, must
/// not corrupt the readable state, and must not poison later commits.
#[test]
fn interrupted_commit_never_moves_the_active_generation() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("wallet");
    let wallet =
        WalletDirectory::create(&root, &fresh_state(), "correct", KdfParameters::TEST).unwrap();
    let before = active_generation_bytes(&root);
    let original = wallet.load("correct").unwrap();

    {
        let _cap = FileSizeCap::install(64);
        let error = wallet
            .commit(0, original.clone(), "correct", KdfParameters::TEST)
            .expect_err("a write capped at 64 bytes cannot complete a commit");
        assert!(
            matches!(error, StorageError::Io(_)),
            "the failure must surface as the typed I/O error, got {error:?}"
        );
    }

    assert_eq!(
        active_generation_bytes(&root),
        before,
        "a failed commit must not move the active generation pointer"
    );
    assert!(
        staging_leftovers(&root).is_empty(),
        "the failed staging directory must have been removed"
    );
    let reloaded = wallet.load("correct").unwrap();
    assert_eq!(reloaded.generation, original.generation);
    assert_eq!(reloaded.wallet_id, original.wallet_id);

    // The fault is gone: the same commit must now succeed cleanly.
    let committed = wallet
        .commit(0, reloaded, "correct", KdfParameters::TEST)
        .expect("commit must succeed once the fault clears");
    assert_eq!(committed.generation, original.generation + 1);
    assert_eq!(
        wallet.load("correct").unwrap().generation,
        committed.generation
    );
}

/// Genuine ENOSPC on a 1 MiB tmpfs: the commit fails typed, the wallet
/// stays readable, and freeing space restores full function.
#[test]
fn disk_full_commit_fails_closed_and_recovers() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let mount_point = temp.path().join("small-disk");
    fs::create_dir(&mount_point).unwrap();
    let Some(_mount) = TmpfsMount::try_mount(&mount_point, "1m") else {
        eprintln!("skipping: this environment cannot mount a tmpfs (needs root)");
        return;
    };

    let root = mount_point.join("wallet");
    let wallet =
        WalletDirectory::create(&root, &fresh_state(), "correct", KdfParameters::TEST).unwrap();
    let before = active_generation_bytes(&root);
    let original = wallet.load("correct").unwrap();

    // Exhaust the filesystem. The write stops at ENOSPC by design.
    let filler = mount_point.join("filler");
    let mut written = fs::write(&filler, vec![0u8; 1024 * 1024]).is_ok();
    if written {
        // Filesystem larger than requested; keep filling in 64 KiB steps.
        let mut chunk = 1;
        while written && chunk < 64 {
            written = fs::write(
                mount_point.join(format!("filler-{chunk}")),
                vec![0u8; 64 * 1024],
            )
            .is_ok();
            chunk += 1;
        }
    }

    let error = wallet
        .commit(0, original.clone(), "correct", KdfParameters::TEST)
        .expect_err("a full disk cannot complete a commit");
    assert!(
        matches!(error, StorageError::Io(_)),
        "the failure must surface as the typed I/O error, got {error:?}"
    );
    assert_eq!(
        active_generation_bytes(&root),
        before,
        "a failed commit must not move the active generation pointer"
    );
    let reloaded = wallet
        .load("correct")
        .expect("the wallet must stay readable on a full disk");
    assert_eq!(reloaded.generation, original.generation);

    // Space returns: the wallet must work again without any repair step.
    let _ = fs::remove_file(&filler);
    for chunk in 1..64 {
        let _ = fs::remove_file(mount_point.join(format!("filler-{chunk}")));
    }
    let committed = wallet
        .commit(0, reloaded, "correct", KdfParameters::TEST)
        .expect("commit must succeed once space is freed");
    assert_eq!(committed.generation, original.generation + 1);
}

/// A read-only filesystem (or, unprivileged, a write-protected directory):
/// writes fail typed, reads keep working, and restoring write access
/// restores full function.
#[test]
fn read_only_wallet_fails_closed_and_recovers() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let is_root = unsafe { libc::geteuid() } == 0;

    if is_root {
        // Root ignores permission bits, so protect via a read-only remount.
        let mount_point = temp.path().join("small-disk");
        fs::create_dir(&mount_point).unwrap();
        let Some(mount) = TmpfsMount::try_mount(&mount_point, "4m") else {
            eprintln!("skipping: running as root but cannot mount a tmpfs");
            return;
        };
        let root = mount_point.join("wallet");
        let original = {
            let wallet =
                WalletDirectory::create(&root, &fresh_state(), "correct", KdfParameters::TEST)
                    .unwrap();
            wallet.load("correct").unwrap()
            // The wallet holds its writer lock open for writing, and the
            // kernel rightly refuses a read-only remount while any file is
            // open writable, so the handle is dropped here. The simulated
            // fault is a filesystem that turned read-only under a wallet
            // that is not currently open.
        };
        let before = active_generation_bytes(&root);
        assert!(mount.remount("ro"), "read-only remount must succeed");

        // On a read-only filesystem the wallet cannot even take its writer
        // lock: opening fails closed with the typed I/O error instead of
        // pretending a writable session exists.
        let error = WalletDirectory::open(&root)
            .expect_err("a read-only filesystem cannot host a writable wallet session");
        assert!(matches!(error, StorageError::Io(_)), "got {error:?}");
        assert_eq!(
            active_generation_bytes(&root),
            before,
            "failing to open must not touch the tree"
        );

        assert!(mount.remount("rw"), "read-write remount must succeed");
        let wallet = WalletDirectory::open(&root)
            .expect("open must succeed once the filesystem is writable");
        let reloaded = wallet.load("correct").unwrap();
        assert_eq!(reloaded.generation, original.generation);
        let committed = wallet
            .commit(0, reloaded, "correct", KdfParameters::TEST)
            .expect("commit must succeed once the filesystem is writable");
        assert_eq!(committed.generation, original.generation + 1);
    } else {
        // Unprivileged: the permission bits themselves are the fault.
        let root = temp.path().join("wallet");
        let wallet =
            WalletDirectory::create(&root, &fresh_state(), "correct", KdfParameters::TEST).unwrap();
        let before = active_generation_bytes(&root);
        let original = wallet.load("correct").unwrap();
        let generations = root.join("generations");
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();

        let error = wallet
            .commit(0, original.clone(), "correct", KdfParameters::TEST)
            .expect_err("a write-protected directory cannot complete a commit");
        assert!(matches!(error, StorageError::Io(_)), "got {error:?}");

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(active_generation_bytes(&root), before);
        let reloaded = wallet.load("correct").unwrap();
        assert_eq!(reloaded.generation, original.generation);
        let committed = wallet
            .commit(0, reloaded, "correct", KdfParameters::TEST)
            .expect("commit must succeed once permissions are restored");
        assert_eq!(committed.generation, original.generation + 1);
    }
}
