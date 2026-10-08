use super::*;
use std::process::Stdio;

#[tokio::test]
async fn owned_windows_job_collector_preserves_failed_status_with_known_real_tree_cleanup() {
    let mut native = std::process::Command::new("cmd.exe");
    native
        .arg("/d")
        .arg("/s")
        .arg("/c")
        .arg("exit /b 7")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = iteron_support::owned_windows_job::OwnedWindowsChild::spawn(&mut native)
        .await
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (observer, _events) = OutputObserver::bounded("windows-native-failure", 1, 4);
    let observer = observer.with_owned_group_cleanup();
    let confinement =
        Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
    let output = collect_owned_child_output(child, stdout, stderr, &confinement)
        .await
        .unwrap();
    assert_eq!(output.exit_code, 7);
    assert!(!output.timed_out);
    assert!(observer.owned_group_cleanup_known());
}

#[tokio::test]
async fn owned_windows_job_collector_ordinary_observer_does_not_fabricate_cleanup_proof() {
    let mut native = std::process::Command::new("cmd.exe");
    native
        .arg("/d")
        .arg("/s")
        .arg("/c")
        .arg("exit /b 0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = iteron_support::owned_windows_job::OwnedWindowsChild::spawn(&mut native)
        .await
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (observer, _events) = OutputObserver::bounded("windows-native-ordinary", 1, 4);
    let confinement =
        Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
    let output = collect_owned_child_output(child, stdout, stderr, &confinement)
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0);
    assert!(!observer.owned_group_cleanup_known());
}

/// This is the real previously configured Bash execution path. The Windows native gate must
/// provide Bash; absence is a failed prerequisite, not a substituted fake successful command.
#[tokio::test]
async fn owned_windows_job_collector_actual_configured_shell_releases_known_writer_cleanup() {
    let (observer, _events) = OutputObserver::bounded("windows-configured-shell", 1, 4);
    let observer = observer.with_owned_group_cleanup();
    let confinement =
        Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
    let output = run_direct("exit 1", &confinement)
        .await
        .expect("native Windows Bash prerequisite");
    assert_eq!(output.exit_code, 1);
    assert!(!output.timed_out);
    assert!(observer.owned_group_cleanup_known());
}
