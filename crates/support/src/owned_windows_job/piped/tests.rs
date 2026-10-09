//! Native inherited pipe/Job oracles, using this real test executable and actual IO EOF.
use super::*;
use std::io::{Read, Write};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const HELPER: &str = "owned_windows_job::piped::tests::native_piped_child_fixture";
const MODE: &str = "ITERON_NATIVE_PIPE_FIXTURE_MODE";
const ROOT: &str = "ITERON_NATIVE_PIPE_FIXTURE_ROOT";
struct Workspace(std::path::PathBuf);
impl Workspace {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-native-pipe-{label}-{}-{}",
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
    let mut env = std::env::vars_os()
        .filter(|(key, _)| key != MODE && key != ROOT)
        .collect::<Vec<_>>();
    env.extend([
        (MODE.into(), mode.into()),
        (ROOT.into(), root.as_os_str().to_owned()),
    ]);
    env
}
async fn spawn(root: &Path, mode: &str) -> OwnedWindowsPipes {
    OwnedWindowsPipes::spawn_with_isolation(
        &std::env::current_exe().unwrap(),
        &arguments(),
        root,
        &environment(root, mode),
        None,
    )
    .await
    .unwrap()
}
#[test]
fn native_piped_child_fixture() {
    let Some(mode) = std::env::var_os(MODE) else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
    match mode.to_str().unwrap() {
        "echo" => {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            };
            let mut native_mode = 0;
            assert_eq!(
                unsafe { GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut native_mode) },
                0
            );
            assert_eq!(
                unsafe { GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut native_mode) },
                0
            );
            assert_eq!(
                std::env::current_dir().unwrap().canonicalize().unwrap(),
                root.canonicalize().unwrap()
            );
            println!("@actual-pipe-ready");
            std::io::stdout().flush().unwrap();
            eprintln!("@actual-distinct-stderr");
            std::io::stderr().flush().unwrap();
            let mut input = String::new();
            std::io::stdin()
                .lock()
                .take(4096)
                .read_to_string(&mut input)
                .unwrap();
            assert_eq!(input, "native-input\n");
            println!("@actual-pipe-eof:{input}");
            std::io::stdout().flush().unwrap();
        }
        "wait" => {
            std::fs::write(root.join("running"), b"actual-pipe-process").unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "marker" => {
            std::fs::write(root.join("executed"), b"actual-app-code").unwrap();
        }
        _ => panic!("unexpected native pipe helper mode"),
    }
}
fn drain(output: WindowsPipeOutput) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut bytes = Vec::new();
        output
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        assert!(bytes.len() <= 256 * 1024);
        bytes
    })
}
#[tokio::test]
async fn native_piped_stdio_is_distinct_with_real_eof_wait_and_job_zero() {
    let root = Workspace::new("stdio");
    let mut child = spawn(&root.0, "echo").await;
    let job = child.job();
    let stdout = drain(child.take_output().unwrap());
    let stderr = drain(child.take_error().unwrap());
    let mut input = child.take_input().unwrap();
    input.write_all(b"native-input\n").await.unwrap();
    input.shutdown().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let stdout = tokio::time::timeout(Duration::from_secs(5), stdout)
        .await
        .unwrap()
        .unwrap();
    let stderr = tokio::time::timeout(Duration::from_secs(5), stderr)
        .await
        .unwrap()
        .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(
        stdout.contains("@actual-pipe-eof:native-input"),
        "{stdout:?}"
    );
    assert!(!stdout.contains("@actual-distinct-stderr"));
    assert!(stderr.contains("@actual-distinct-stderr"), "{stderr:?}");
    assert!(!stderr.contains("@actual-pipe-eof"));
    assert!(child.child.is_none() && child.status.is_some());
    assert_eq!(job.active_processes().unwrap(), 0);
}
#[tokio::test]
async fn native_piped_drop_keeps_physical_custody_until_real_job_zero() {
    let root = Workspace::new("drop");
    let child = spawn(&root.0, "wait").await;
    let job = child.job();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.0.join("running").exists() {
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(job.active_processes().unwrap(), 1);
    drop(child);
    assert!(job.confirm_empty(Duration::from_secs(5)).await);
    assert_eq!(job.active_processes().unwrap(), 0);
}
#[tokio::test]
async fn native_piped_pre_resume_refusal_is_reaped_without_executing_app_code() {
    let root = Workspace::new("before-resume");
    let launch = Launch::capture(
        &std::env::current_exe().unwrap(),
        &arguments(),
        &root.0,
        &environment(&root.0, "marker"),
    )
    .unwrap();
    let error = OwnedWindowsPipes::spawn_captured(
        launch,
        None,
        Some(|process, job| {
            assert!(process.id().is_some());
            assert_eq!(job.active_processes().unwrap(), 1);
            Err(io::Error::other("real suspended observation refusal"))
        }),
    )
    .await
    .unwrap_err();
    assert!(error.not_dispatched() && error.cleanup_known());
    assert!(!root.0.join("executed").exists());
}
