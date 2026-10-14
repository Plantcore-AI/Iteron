//! Actual Windows ConPTY/Job integration. The helper is this test executable, so these oracles
//! need no shell installation and cannot substitute a mock process table for native receipts.
use super::*;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

const HELPER: &str = "owned_windows_job::conpty::tests::native_conpty_child_fixture";
const MODE: &str = "ITERON_NATIVE_CONPTY_FIXTURE_MODE";
const ROOT: &str = "ITERON_NATIVE_CONPTY_FIXTURE_ROOT";
const ENV: &str = "ITERON_NATIVE_CONPTY_FIXTURE_VALUE";

struct Workspace(PathBuf);
impl Workspace {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-native-conpty-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn arguments() -> Vec<OsString> {
    ["--exact", HELPER, "--nocapture"]
        .into_iter()
        .map(OsString::from)
        .collect()
}
fn environment(root: &Path, mode: &str) -> Vec<(OsString, OsString)> {
    let mut environment = std::env::vars_os()
        .filter(|(name, _)| name != MODE && name != ROOT && name != ENV)
        .collect::<Vec<_>>();
    environment.extend([
        (MODE.into(), mode.into()),
        (ROOT.into(), root.as_os_str().to_owned()),
        (ENV.into(), "exact-pinned-native-value".into()),
    ]);
    environment
}
async fn spawn(root: &Path, mode: &str) -> OwnedWindowsPty {
    OwnedWindowsPty::spawn(
        &std::env::current_exe().unwrap(),
        &arguments(),
        root,
        &environment(root, mode),
        35,
        120,
    )
    .await
    .unwrap()
}

fn terminal_size() -> (i16, i16) {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    assert_ne!(
        unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) },
        0
    );
    (
        info.srWindow.Bottom - info.srWindow.Top + 1,
        info.srWindow.Right - info.srWindow.Left + 1,
    )
}

#[test]
fn native_conpty_child_fixture() {
    let Some(mode) = std::env::var_os(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
    match mode.to_str().unwrap() {
        "echo" => {
            let mut native_mode = 0;
            assert_ne!(
                unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut native_mode) },
                0
            );
            assert_eq!(
                std::env::current_dir().unwrap().canonicalize().unwrap(),
                root.canonicalize().unwrap()
            );
            assert_eq!(std::env::var(ENV).unwrap(), "exact-pinned-native-value");
            let (rows, cols) = terminal_size();
            println!("@ready:{rows}:{cols}");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .take(1024)
                .read_line(&mut line)
                .unwrap();
            println!("@echo:{}", line.trim_end());
            std::io::stdout().flush().unwrap();
            line.clear();
            std::io::stdin()
                .lock()
                .take(1024)
                .read_line(&mut line)
                .unwrap();
            let (rows, cols) = terminal_size();
            println!("@size:{rows}:{cols}");
            std::io::stdout().flush().unwrap();
        }
        "marker" => {
            std::fs::write(root.join("executed"), b"actual-app-code").unwrap();
        }
        "tree" => {
            let child = Command::new(std::env::current_exe().unwrap())
                .args(arguments())
                .env(MODE, "descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !root.join("descendant-ready").exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(CLEANUP_POLL);
            }
            drop(child); // No terminate API: it must remain an actual inherited Job member.
        }
        "descendant" => {
            std::fs::write(root.join("descendant-ready"), b"actual-native-child").unwrap();
            std::thread::sleep(Duration::from_secs(3));
            std::fs::write(root.join("escaped"), b"escaped-physical-tree").unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "wait" => {
            std::fs::write(root.join("running"), b"actual-native-child").unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        _ => panic!("invalid native fixture mode"),
    }
}

async fn read_marker(output: &mut WindowsPtyOutput, marker: &str) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut retained = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = output.read(&mut chunk).await.unwrap();
            assert!(count > 0, "native PTY closed before {marker}");
            assert!(retained.len() + count <= 256 * 1024);
            retained.extend_from_slice(&chunk[..count]);
            if String::from_utf8_lossy(&retained).contains(marker) {
                return retained;
            }
        }
    })
    .await
    .unwrap()
}
fn drain(mut output: WindowsPtyOutput) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut retained = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let count = output.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            assert!(retained.len() + count <= 256 * 1024);
            retained.extend_from_slice(&chunk[..count]);
        }
        retained
    })
}
async fn marker(root: &Path, name: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.join(name).exists() {
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_conpty_real_stdin_resize_cwd_environment_wait_and_eof() {
    let root = Workspace::new("interactive");
    let mut child = spawn(&root.0, "echo").await;
    let job = child.job();
    let resize = child.resize_control();
    let mut input = child.take_input().unwrap();
    let mut output = child.take_output().unwrap();
    assert!(child.take_input().is_none() && child.take_output().is_none());
    read_marker(&mut output, "@ready:35:120").await;
    input.write_all(b"exact-native-input\r").await.unwrap();
    read_marker(&mut output, "@echo:exact-native-input").await;
    resize.resize(40, 180).unwrap();
    input.write_all(b"check-resized-console\r").await.unwrap();
    read_marker(&mut output, "@size:40:180").await;
    let output = drain(output);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert!(child.child.is_none() && child.status == Some(status));
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(
        resize.resize(1, 1).is_err(),
        "retired consoles cannot be resized"
    );
    tokio::time::timeout(Duration::from_secs(5), output)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn native_conpty_leader_exit_retires_actual_redirected_descendant_job() {
    let root = Workspace::new("natural-tree");
    let mut child = spawn(&root.0, "tree").await;
    let job = child.job();
    let output = drain(child.take_output().unwrap());
    marker(&root.0, "descendant-ready").await;
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert_eq!(job.active_processes().unwrap(), 0);
    assert!(!root.0.join("escaped").exists());
    tokio::time::timeout(Duration::from_secs(5), output)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn native_conpty_drop_retains_actual_handle_custody_until_job_zero() {
    let root = Workspace::new("dropped");
    let child = spawn(&root.0, "wait").await;
    let job = child.job();
    marker(&root.0, "running").await;
    assert_eq!(job.active_processes().unwrap(), 1);
    drop(child);
    assert!(
        job.confirm_empty(MAX_CLEANUP_WAIT).await,
        "leader handle retirement is physical, not last-Job-close inference"
    );
}

#[tokio::test]
async fn native_conpty_refused_before_resume_has_no_execution_and_known_physical_cleanup() {
    let root = Workspace::new("refused-resume");
    let launch = Launch::capture(
        &std::env::current_exe().unwrap(),
        &arguments(),
        &root.0,
        &environment(&root.0, "marker"),
    )
    .unwrap();
    let error = OwnedWindowsPty::spawn_captured(
        launch,
        35,
        120,
        None,
        Some(|child, job| {
            assert!(child.id().is_some());
            assert_eq!(job.active_processes().unwrap(), 1);
            Err(io::Error::other("physical pre-resume refusal"))
        }),
    )
    .await
    .unwrap_err();
    assert!(error.not_dispatched() && error.cleanup_known());
    assert!(error.custody.is_none());
    assert!(!root.0.join("executed").exists());
}

#[tokio::test]
async fn native_conpty_invalid_abi_refuses_before_any_process_or_console() {
    let root = Workspace::new("invalid-abi");
    let error = OwnedWindowsPty::spawn(Path::new("relative.exe"), &[], &root.0, &[], 1, 1)
        .await
        .unwrap_err();
    assert!(error.not_dispatched());
    let error = OwnedWindowsPty::spawn(
        &std::env::current_exe().unwrap(),
        &[],
        &root.0,
        &[("ORDINARY".into(), "private-invalid\0value".into())],
        1,
        1,
    )
    .await
    .unwrap_err();
    assert!(error.not_dispatched());
    assert!(!error.to_string().contains("private-invalid"));
    assert!(std::fs::read_dir(&root.0).unwrap().next().is_none());
}
