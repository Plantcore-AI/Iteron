//! Real native process, directory, token, ACL and external-network oracles. Run on Windows.
use super::*;
use crate::owned_windows_job::OwnedWindowsPipes;
use std::io::{BufRead, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HELPER: &str = "windows_process_isolation::tests::native_isolated_child_fixture";
const MODE: &str = "ITERON_ISOLATION_FIXTURE_MODE";
const ROOT: &str = "ITERON_ISOLATION_FIXTURE_ROOT";
const SCRATCH: &str = "ITERON_ISOLATION_FIXTURE_SCRATCH";
const OUTSIDE: &str = "ITERON_ISOLATION_FIXTURE_OUTSIDE";

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let mut guid = unsafe { std::mem::zeroed::<windows_sys::core::GUID>() };
        profile::hresult(unsafe { windows_sys::Win32::System::Com::CoCreateGuid(&mut guid) })
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "iteron-isolation-native-{}-{:08x}-{:04x}-{:04x}",
            std::process::id(),
            guid.data1,
            guid.data2,
            guid.data3,
        ));
        std::fs::create_dir(&path).unwrap();
        for name in ["workspace", "scratch", "outside"] {
            std::fs::create_dir(path.join(name)).unwrap();
        }
        std::fs::write(path.join("workspace/input"), b"workspace-input").unwrap();
        std::fs::write(path.join("outside/input"), b"synthetic-outside-canary").unwrap();
        Self(path)
    }
    fn environment(&self, mode: &str) -> Vec<(OsString, OsString)> {
        let mut env = Vec::new();
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                env.push((name.into(), value));
            }
        }
        env.extend([
            (MODE.into(), mode.into()),
            (ROOT.into(), self.0.join("workspace").into_os_string()),
            (SCRATCH.into(), self.0.join("scratch").into_os_string()),
            (OUTSIDE.into(), self.0.join("outside").into_os_string()),
            ("RUST_TEST_THREADS".into(), "1".into()),
        ]);
        env
    }
    fn prepare(
        &self,
        env: &[(OsString, OsString)],
        writable: bool,
    ) -> Arc<WindowsProcessIsolation> {
        let writes = if writable {
            vec![self.0.join("workspace")]
        } else {
            Vec::new()
        };
        WindowsProcessIsolation::prepare(WindowsIsolationPolicy {
            workspace: &self.0.join("workspace"),
            scratch: &self.0.join("scratch"),
            executable: &std::env::current_exe().unwrap(),
            environment: env,
            write_roots: &writes,
            read_only_roots: &[],
            allow_egress: false,
        })
        .unwrap()
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn native_isolated_child_fixture() {
    let Some(mode) = std::env::var_os(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
    let scratch = PathBuf::from(std::env::var_os(SCRATCH).unwrap());
    let outside = PathBuf::from(std::env::var_os(OUTSIDE).unwrap());
    assert_eq!(
        std::env::current_dir().unwrap().canonicalize().unwrap(),
        root.canonicalize().unwrap()
    );
    assert_eq!(
        std::fs::read(root.join("input")).unwrap(),
        b"workspace-input"
    );
    assert_eq!(
        std::fs::read(outside.join("input")).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::write(outside.join("escaped"), b"outside-write")
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    std::fs::write(scratch.join("scratch-positive"), b"owned-scratch").unwrap();
    assert!(std::env::var_os("ITERON_ISOLATION_SYNTHETIC_SECRET").is_none());
    match mode.to_str().unwrap() {
        "write" | "hold" | "network" => {
            std::fs::write(root.join("ready"), b"actual-isolated-process").unwrap();
        }
        "read-only" => {
            assert_eq!(
                std::fs::write(root.join("forbidden"), b"read-only-write")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        _ => panic!("invalid isolated fixture mode"),
    }
    if mode == "write" {
        // Retained permission handles must allow ordinary atomic editing while the child lives.
        std::fs::write(root.join("replacement"), b"actual-atomic-edit").unwrap();
        std::fs::rename(root.join("replacement"), root.join("input")).unwrap();
        // Native link creation may require fewer rights than opening file contents. Either it
        // refuses, or the alias remains unreadable/unwritable because no ACL propagation occurs.
        if std::fs::hard_link(outside.join("input"), root.join("foreign-alias")).is_ok() {
            assert_eq!(
                std::fs::read(root.join("foreign-alias"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                std::fs::write(root.join("foreign-alias"), b"escaped-link-write")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
    if mode == "hold" {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .take(128)
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "after-rejected-clone\n");
        std::fs::write(root.join("after-rejection"), b"original-live-grant").unwrap();
    }
    if mode == "network" {
        let address = "1.1.1.1:443".parse().unwrap();
        let refused =
            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap_err();
        assert_eq!(
            refused.raw_os_error(),
            Some(10013),
            "must be actual WSAEACCES, never mere offline timeout"
        );
    }
    println!("@actual-isolated-ok");
    std::io::stdout().flush().unwrap();
}

fn arguments() -> Vec<OsString> {
    ["--exact", HELPER, "--nocapture"]
        .into_iter()
        .map(OsString::from)
        .collect()
}
async fn spawn(
    workspace: &Workspace,
    env: &[(OsString, OsString)],
    lease: Arc<WindowsProcessIsolation>,
) -> OwnedWindowsPipes {
    OwnedWindowsPipes::spawn_with_isolation(
        &std::env::current_exe().unwrap(),
        &arguments(),
        &workspace.0.join("workspace"),
        env,
        Some(lease),
    )
    .await
    .unwrap()
}
async fn finish(mut child: OwnedWindowsPipes) {
    let job = child.job();
    let stdout = child.take_output().unwrap();
    let stderr = child.take_error().unwrap();
    let out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    });
    let err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    });
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    let out = out.await.unwrap();
    let err = err.await.unwrap();
    assert!(
        status.success(),
        "native child must execute assertions, not merely start"
    );
    assert!(String::from_utf8_lossy(&out).contains("@actual-isolated-ok"));
    assert!(out.len() <= 16 * 1024 && err.len() <= 16 * 1024);
    assert!(job.confirm_empty(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn native_isolation_writes_only_admitted_workspace_and_scratch() {
    let workspace = Workspace::new();
    let env = workspace.environment("write");
    let lease = workspace.prepare(&env, true);
    assert_eq!(lease.profile.network_capability_count(), 0);
    finish(spawn(&workspace, &env, lease.clone()).await).await;
    assert_eq!(
        std::fs::read(workspace.0.join("workspace/ready")).unwrap(),
        b"actual-isolated-process"
    );
    assert!(!workspace.0.join("outside/escaped").exists());
    assert_eq!(lease.lock().unwrap().phase, Phase::Retired);
    for path in [
        workspace.0.join("workspace/ready"),
        workspace.0.join("workspace/input"),
        workspace.0.join("scratch/scratch-positive"),
    ] {
        let actual = BoundObject::open(&path, false, false).unwrap();
        assert!(
            !actual.has_sid(lease.profile.sid()).unwrap(),
            "created/replaced object must actually lose the retired SID"
        );
    }
    assert_eq!(
        std::fs::read(workspace.0.join("workspace/input")).unwrap(),
        b"actual-atomic-edit"
    );
    assert_eq!(
        std::fs::read(workspace.0.join("outside/input")).unwrap(),
        b"synthetic-outside-canary"
    );
}

#[tokio::test]
async fn native_isolation_read_only_workspace_retains_private_scratch_write() {
    let workspace = Workspace::new();
    let env = workspace.environment("read-only");
    finish(spawn(&workspace, &env, workspace.prepare(&env, false)).await).await;
    assert!(!workspace.0.join("workspace/forbidden").exists());
}

#[tokio::test]
async fn native_isolation_denies_external_network_with_actual_access_error() {
    // The trusted host must actually reach this exact public endpoint first. An offline host
    // cannot make a timeout look like sandbox enforcement.
    let address = "1.1.1.1:443".parse().unwrap();
    std::net::TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    let workspace = Workspace::new();
    let env = workspace.environment("network");
    finish(spawn(&workspace, &env, workspace.prepare(&env, true)).await).await;
}

#[tokio::test]
async fn native_second_arc_launch_cannot_retire_first_live_grants() {
    let workspace = Workspace::new();
    let env = workspace.environment("hold");
    let lease = workspace.prepare(&env, true);
    let mut child = spawn(&workspace, &env, lease.clone()).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !workspace.0.join("workspace/ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let refused = OwnedWindowsPipes::spawn_with_isolation(
        &std::env::current_exe().unwrap(),
        &arguments(),
        &workspace.0.join("workspace"),
        &env,
        Some(lease),
    )
    .await;
    assert!(refused.is_err());
    let mut input = child.take_input().unwrap();
    input.write_all(b"after-rejected-clone\n").await.unwrap();
    input.shutdown().await.unwrap();
    drop(input);
    finish(child).await;
    assert_eq!(
        std::fs::read(workspace.0.join("workspace/after-rejection")).unwrap(),
        b"original-live-grant"
    );
}

#[test]
fn native_workspace_capability_never_substitutes_another_directory() {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    let workspace = Workspace::new();
    let other = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(workspace.0.join("outside"))
        .unwrap();
    let env = workspace.environment("write");
    assert!(
        WindowsProcessIsolation::prepare_from_workspace(
            WindowsIsolationPolicy {
                workspace: &workspace.0.join("workspace"),
                scratch: &workspace.0.join("scratch"),
                executable: &std::env::current_exe().unwrap(),
                environment: &env,
                write_roots: &[workspace.0.join("workspace")],
                read_only_roots: &[],
                allow_egress: false,
            },
            &other
        )
        .is_err()
    );
}

#[test]
fn native_verbatim_system_image_uses_existing_protected_permissions() {
    use std::os::windows::ffi::OsStringExt;
    let mut directory = [0_u16; 32_768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            directory.as_mut_ptr(),
            directory.len() as u32,
        )
    };
    assert!(length > 0 && (length as usize) < directory.len());
    let normal = PathBuf::from(OsString::from_wide(&directory[..length as usize])).join("cmd.exe");
    let verbatim = normal.canonicalize().unwrap();
    assert!(is_system_image(&normal).unwrap());
    assert!(is_system_image(&verbatim).unwrap());
    let workspace = Workspace::new();
    let env = workspace.environment("write");
    let lease = WindowsProcessIsolation::prepare(WindowsIsolationPolicy {
        workspace: &workspace.0.join("workspace"),
        scratch: &workspace.0.join("scratch"),
        executable: &verbatim,
        environment: &env,
        write_roots: &[workspace.0.join("workspace")],
        read_only_roots: &[],
        allow_egress: false,
    })
    .unwrap();
    assert!(!lease.lock().unwrap().grants[lease.executable_index].manage_acl);
}

#[tokio::test]
async fn native_preexisting_outside_hardlink_refuses_before_any_grant_or_child_code() {
    let workspace = Workspace::new();
    std::fs::hard_link(
        workspace.0.join("outside/input"),
        workspace.0.join("workspace/foreign-alias"),
    )
    .unwrap();
    let env = workspace.environment("write");
    let lease = workspace.prepare(&env, true);
    let refused = OwnedWindowsPipes::spawn_with_isolation(
        &std::env::current_exe().unwrap(),
        &arguments(),
        &workspace.0.join("workspace"),
        &env,
        Some(lease.clone()),
    )
    .await;
    assert!(refused.is_err());
    assert!(!workspace.0.join("workspace/ready").exists());
    let outside = BoundObject::open(&workspace.0.join("outside/input"), false, false).unwrap();
    assert!(!outside.has_sid(lease.profile.sid()).unwrap());
    assert_eq!(
        std::fs::read(workspace.0.join("outside/input")).unwrap(),
        b"synthetic-outside-canary"
    );
}
