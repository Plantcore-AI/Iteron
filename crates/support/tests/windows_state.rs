#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iteron_support::durable_windows_state::{
    WindowsSnapshotStore, WindowsStateError, provision_private_directory,
};

struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "iteron-windows-state-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        provision_private_directory(&path).expect("private local NTFS fixture");
        Self(path)
    }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exclusive_writer_replacement_and_reopen() {
    let directory = PrivateDirectory::new();
    let mut store = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    assert_eq!(store.load().unwrap(), None);
    assert!(matches!(
        WindowsSnapshotStore::open(&directory.0, "state"),
        Err(WindowsStateError::Conflict)
    ));
    store.publish(b"first", true).unwrap();
    store.publish(b"second", false).unwrap();
    drop(store);
    let mut reopened = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    assert_eq!(reopened.load().unwrap(), Some(b"second".to_vec()));
}

#[test]
fn rename_failure_poison_and_restart_preserves_previous() {
    let directory = PrivateDirectory::new();
    let mut store = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    store.publish(b"previous", true).unwrap();
    // Allow readers/writers but deny delete sharing: the actual relative rename must fail.
    let target = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(directory.0.join("state.json"))
        .unwrap();
    assert_eq!(
        store.publish(b"candidate", false),
        Err(WindowsStateError::OutcomeUnknown)
    );
    assert_eq!(store.load(), Err(WindowsStateError::OutcomeUnknown));
    assert_eq!(
        store.publish(b"must-not-retry", false),
        Err(WindowsStateError::OutcomeUnknown)
    );
    drop(target);
    drop(store);
    let mut reopened = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    assert_eq!(reopened.load().unwrap(), Some(b"previous".to_vec()));
    reopened.publish(b"reconciled", false).unwrap();
}

#[test]
fn lost_snapshot_and_hardlink_are_refused() {
    let directory = PrivateDirectory::new();
    let mut store = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    store.publish(b"committed", true).unwrap();
    drop(store);
    std::fs::hard_link(directory.0.join("state.json"), directory.0.join("alias")).unwrap();
    let mut store = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    assert_eq!(store.load(), Err(WindowsStateError::Unavailable));
    drop(store);
    std::fs::remove_file(directory.0.join("alias")).unwrap();
    std::fs::remove_file(directory.0.join("state.json")).unwrap();
    let mut store = WindowsSnapshotStore::open(&directory.0, "state").unwrap();
    assert_eq!(store.load(), Err(WindowsStateError::OutcomeUnknown));
    assert_eq!(
        store.publish(b"new-tree", true),
        Err(WindowsStateError::OutcomeUnknown)
    );
}

#[test]
fn inherited_public_directory_and_path_components_are_refused() {
    let directory = PrivateDirectory::new();
    assert!(matches!(
        WindowsSnapshotStore::open(&directory.0, "../outside"),
        Err(WindowsStateError::Unavailable)
    ));
    assert!(matches!(
        WindowsSnapshotStore::open(&std::env::temp_dir(), "state"),
        Err(WindowsStateError::Unavailable)
    ));
    assert!(matches!(
        WindowsSnapshotStore::open(&PathBuf::from("relative"), "state"),
        Err(WindowsStateError::Unavailable)
    ));
}

#[test]
fn directory_junction_does_not_gain_storage_authority() {
    let directory = PrivateDirectory::new();
    let alias = directory.0.with_extension("junction");
    let status = Command::new("cmd.exe")
        .args(["/D", "/S", "/C"])
        .arg(format!(
            "mklink /J \"{}\" \"{}\"",
            alias.display(),
            directory.0.display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "native Windows junction fixture must be created"
    );
    let refused = matches!(
        WindowsSnapshotStore::open(&alias, "state"),
        Err(WindowsStateError::Unavailable)
    );
    assert_eq!(
        provision_private_directory(&alias.join("child")),
        Err(WindowsStateError::Unavailable)
    );
    assert!(!directory.0.join("child").exists());
    std::fs::remove_dir(alias).unwrap();
    assert!(refused);
}

#[test]
fn process_crash_releases_lease_and_preserves_publication() {
    let directory = PrivateDirectory::new();
    // The child provisions both new namespace links itself before publishing the completion.
    let namespace = directory
        .0
        .join("advisory-maintenance-v1")
        .join("run-scope");
    let ready = namespace.join("child.ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "windows_state_process_child", "--nocapture"])
        .env("ITERON_WINDOWS_STATE_CHILD_DIR", &namespace)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child failed before durable publication: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child publication exceeded the bounded fixture deadline");
    }
    assert!(matches!(
        WindowsSnapshotStore::open(&namespace, "state"),
        Err(WindowsStateError::Conflict)
    ));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut reopened = WindowsSnapshotStore::open(&namespace, "state").unwrap();
    assert_eq!(
        reopened.load().unwrap(),
        Some(b"published-before-crash".to_vec())
    );
}

#[test]
fn windows_state_process_child() {
    let Some(directory) = std::env::var_os("ITERON_WINDOWS_STATE_CHILD_DIR") else {
        return;
    };
    let directory = PathBuf::from(directory);
    provision_private_directory(directory.parent().unwrap()).unwrap();
    provision_private_directory(&directory).unwrap();
    let mut store = WindowsSnapshotStore::open(&directory, "state").unwrap();
    store.publish(b"published-before-crash", true).unwrap();
    let mut ready = File::create(directory.join("child.ready")).unwrap();
    ready.write_all(b"ready").unwrap();
    ready.sync_all().unwrap();
    // Parent forcibly terminates this process with an active lease; this bounded fallback avoids
    // leaking an abandoned child when the parent fails its fixture.
    std::thread::sleep(Duration::from_secs(30));
}
