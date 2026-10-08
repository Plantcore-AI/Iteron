use super::*;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

const CHILD_TEST: &str = "owned_windows_job::tests::owned_windows_job_child_fixture";
const MODE: &str = "ITERON_WINDOWS_JOB_FIXTURE_MODE";
const ROOT: &str = "ITERON_WINDOWS_JOB_FIXTURE_ROOT";

fn workspace(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-windows-job-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&root).unwrap();
    root
}
fn command(root: &std::path::Path, mode: &str) -> StdCommand {
    let mut command = StdCommand::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(CHILD_TEST)
        .arg("--nocapture")
        .env(MODE, mode)
        .env(ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
async fn marker(root: &std::path::Path, name: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.join(name).exists() {
            tokio::time::sleep(CLEANUP_POLL).await;
        }
    })
    .await
    .unwrap();
}

/// This is the real independently launched executable, not a mock Job/process table.
#[test]
fn owned_windows_job_child_fixture() {
    let Some(mode) = std::env::var_os(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
    match mode.to_str().unwrap() {
        "marker" => {
            std::fs::write(root.join("ran"), b"actual-user-code").unwrap();
        }
        "wait" => {
            std::fs::write(root.join("alive"), std::process::id().to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "background" => {
            let mut background = command(&root, "wait");
            background.stdout(Stdio::null()).stderr(Stdio::null());
            let _descendant = background.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !root.join("alive").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(CLEANUP_POLL);
            }
        }
        "custody_host" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let _owned = OwnedWindowsChild::spawn(&mut command(&root, "wait"))
                    .await
                    .unwrap();
                marker(&root, "alive").await;
                marker(&root, "release").await;
                // Bypass every Rust Drop: Windows closing the host's last Job handle is the
                // actual process-crash safeguard. The observer owns only the descendant handle.
                std::process::exit(0);
            });
        }
        _ => panic!("unknown Windows native fixture mode"),
    }
}

#[tokio::test]
async fn owned_windows_job_assigns_before_exact_primary_resume_and_observes_actual_exit() {
    let root = workspace("ordering");
    let observed = std::sync::atomic::AtomicBool::new(false);
    let before = |child: &StdChild, job: &OwnedWindowsJob| {
        assert!(!root.join("ran").exists());
        assert_eq!(job.active_processes().unwrap(), 1);
        let mut member = 0;
        assert_ne!(
            unsafe { IsProcessInJob(child.as_raw_handle(), job.raw(), &mut member) },
            0
        );
        assert_eq!(member, 1);
        observed.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    };
    let mut child = OwnedWindowsChild::spawn_inner(&mut command(&root, "marker"), Some(&before))
        .await
        .unwrap();
    assert!(observed.load(std::sync::atomic::Ordering::Acquire));
    let mut stdout = child.stdout.take().unwrap().take(16 * 1024);
    let mut stderr = child.stderr.take().unwrap().take(16 * 1024);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert!(
        child.child.is_none(),
        "real wait receipt retires the process handle before Job0"
    );
    assert!(child.status.is_some());
    let mut out = Vec::new();
    let mut err = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a.unwrap();
        b.unwrap();
    })
    .await
    .unwrap();
    assert!(child.job.confirm_empty(Duration::from_secs(1)).await);
    assert_eq!(
        std::fs::read(root.join("ran")).unwrap(),
        b"actual-user-code"
    );
    drop(child);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_pre_resume_refusal_reaps_without_running_user_code() {
    let root = workspace("refusal");
    let before = |_child: &StdChild, job: &OwnedWindowsJob| {
        assert_eq!(job.active_processes().unwrap(), 1);
        Err(io::Error::other("injected before actual ResumeThread"))
    };
    let error = OwnedWindowsChild::spawn_inner(&mut command(&root, "marker"), Some(&before))
        .await
        .unwrap_err();
    assert!(error.not_dispatched());
    assert!(error.cleanup_known());
    assert!(!root.join("ran").exists());
    assert!(error.custody.is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_stdio_refusal_preserves_suspended_custody_until_real_reap() {
    let root = workspace("stdio-refusal");
    let mut launch = command(&root, "marker");
    launch.stderr(Stdio::null());
    let error = OwnedWindowsChild::spawn(&mut launch).await.unwrap_err();
    assert!(error.not_dispatched());
    assert!(error.cleanup_known());
    assert!(!root.join("ran").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_noninitial_resume_count_refuses_and_cleans_the_exact_tree() {
    let root = workspace("suspend-count");
    let before = |child: &StdChild, _job: &OwnedWindowsJob| {
        let thread = primary_thread(child.id()).unwrap();
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::SuspendThread(thread.as_raw_handle()) },
            1
        );
        Ok(())
    };
    let error = OwnedWindowsChild::spawn_inner(&mut command(&root, "marker"), Some(&before))
        .await
        .unwrap_err();
    assert_eq!(error.stage, "primary thread resume");
    assert!(error.cleanup_known());
    assert!(
        !error.not_dispatched(),
        "a failed activation is never a successful launch"
    );
    assert!(!root.join("ran").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_redirected_descendant_requires_actual_job_zero_after_leader_exit() {
    let root = workspace("descendant");
    let mut child = OwnedWindowsChild::spawn(&mut command(&root, "background"))
        .await
        .unwrap();
    marker(&root, "alive").await;
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    assert!(
        child.job.active_processes().unwrap() > 0,
        "leader exit is insufficient"
    );
    child.job.terminate().unwrap();
    assert!(child.job.confirm_empty(Duration::from_secs(1)).await);
    drop(child);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_future_drop_terminates_retained_members_with_real_job_observation() {
    let root = workspace("drop");
    let child = OwnedWindowsChild::spawn(&mut command(&root, "wait"))
        .await
        .unwrap();
    marker(&root, "alive").await;
    let observed_job = child.job();
    assert!(observed_job.active_processes().unwrap() > 0);
    drop(child);
    assert!(observed_job.confirm_empty(Duration::from_secs(1)).await);
    drop(observed_job);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_native_host_exit_uses_kill_on_close_without_rust_destructors() {
    let root = workspace("host-exit");
    let mut command = tokio::process::Command::from(command(&root, "custody_host"));
    command.kill_on_drop(true);
    let mut host = command.spawn().unwrap();
    marker(&root, "alive").await;
    let pid: u32 = std::fs::read_to_string(root.join("alive"))
        .unwrap()
        .parse()
        .unwrap();
    let observed = own_handle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) }).unwrap();
    std::fs::write(root.join("release"), b"exit-now").unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), host.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert_eq!(
        unsafe { WaitForSingleObject(observed.as_raw_handle(), 1000) },
        WAIT_OBJECT_0
    );
    drop(observed);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_string_projection_retains_actual_unassigned_suspended_process_cleanup() {
    let root = workspace("unassigned-string-projection");
    let admission = custody::Admission::acquire().unwrap();
    let job = Arc::new(OwnedWindowsJob::create().unwrap());
    let mut launch = command(&root, "marker");
    launch.creation_flags(CREATE_SUSPENDED);
    let child = launch.spawn().unwrap();
    let observed = own_handle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, child.id()) }).unwrap();
    // Real native process, intentionally not assigned/resumed, as after assignment refusal.
    // The actual consumer projects only the public message and drops its error capsule.
    let owned = OwnedWindowsChild {
        original_pid: child.id(),
        child: Some(child),
        custody: Some(admission),
        job: job.clone(),
        status: None,
        stdout: None,
        stderr: None,
    };
    let error = WindowsJobLaunchError {
        stage: "unobserved assignment refusal fixture",
        os_error: None,
        execution_may_have_started: false,
        cleanup_known: false,
        custody: Some(Box::new(owned)),
    };
    assert!(!error.not_dispatched());
    let _public_message = error.to_string();
    drop(error);
    assert_eq!(
        unsafe { WaitForSingleObject(observed.as_raw_handle(), 2000) },
        WAIT_OBJECT_0
    );
    assert!(!root.join("ran").exists());
    assert!(job.confirm_empty(Duration::from_secs(1)).await);
    drop(observed);
    drop(job);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_string_projection_closes_actual_assigned_tree_after_error_drop() {
    let root = workspace("assigned-string-projection");
    let child = OwnedWindowsChild::spawn(&mut command(&root, "wait"))
        .await
        .unwrap();
    marker(&root, "alive").await;
    let observed = child.job();
    let error = WindowsJobLaunchError {
        stage: "unobserved post-resume fixture",
        os_error: None,
        execution_may_have_started: true,
        cleanup_known: false,
        custody: Some(Box::new(child)),
    };
    let _public_message = error.to_string();
    drop(error);
    // The observer retains only the Job, so zero also requires the custody worker to release
    // its actual process reference after try_wait; last Job close cannot fake this observation.
    assert!(observed.confirm_empty(Duration::from_secs(1)).await);
    drop(observed);
    std::fs::remove_dir_all(root).unwrap();
}
