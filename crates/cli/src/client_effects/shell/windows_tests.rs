use super::*;

fn root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-windows-operator-shell-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&root).unwrap();
    root
}

#[tokio::test]
async fn owned_windows_job_operator_shell_actual_failed_command_is_completed_and_cleanup_known() {
    let root = root("failure");
    let (_cancel, mut cancelled) = tokio::sync::watch::channel(false);
    let receipt = execute(
        &root,
        "printf actual > marker; exit 1",
        &[],
        PermissionMode::Default,
        &PermissionRules::new(),
        &mut cancelled,
    )
    .await;
    assert_eq!(
        receipt.outcome,
        ShellOutcome::Completed,
        "native Windows Bash prerequisite"
    );
    assert_eq!(receipt.cleanup, ShellCleanup::Reaped);
    assert!(!receipt.ok);
    assert_eq!(receipt.code, 1);
    assert_eq!(std::fs::read(root.join("marker")).unwrap(), b"actual");
    assert!(receipt.windows_custody.is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_operator_shell_redirected_background_is_stopped_before_lease_release() {
    let root = root("background");
    let (_cancel, mut cancelled) = tokio::sync::watch::channel(false);
    let started = tokio::time::Instant::now();
    let receipt = execute(
        &root,
        "sleep 30 </dev/null >/dev/null 2>&1 & printf actual > marker; exit 0",
        &[],
        PermissionMode::Default,
        &PermissionRules::new(),
        &mut cancelled,
    )
    .await;
    assert_eq!(
        receipt.outcome,
        ShellOutcome::Completed,
        "native Windows Bash prerequisite"
    );
    assert_eq!(receipt.cleanup, ShellCleanup::Reaped);
    assert!(receipt.ok);
    assert!(started.elapsed() < Duration::from_secs(5));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn owned_windows_job_operator_shell_cancel_retains_unknown_effects_after_actual_tree_reap() {
    let root = root("cancel");
    let directory = root.clone();
    let (cancel, mut cancelled) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(async move {
        execute(
            &directory,
            "printf actual > marker; exec sleep 30",
            &[],
            PermissionMode::Default,
            &PermissionRules::new(),
            &mut cancelled,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.join("marker").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native Windows Bash prerequisite and actual command start");
    cancel.send(true).unwrap();
    let receipt = tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.outcome, ShellOutcome::OutcomeUnknown);
    assert_eq!(receipt.cleanup, ShellCleanup::Reaped);
    assert_eq!(std::fs::read(root.join("marker")).unwrap(), b"actual");
    std::fs::remove_dir_all(root).unwrap();
}
