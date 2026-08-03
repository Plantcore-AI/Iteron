use super::*;

#[test]
fn copied_text_is_secret_and_terminal_control_safe_and_bounded() {
    let secret = format!("sk-{}", "a".repeat(48));
    let safe = safe_text(&format!("before {secret}\u{1b}]52;bad\u{7} after")).unwrap();
    assert!(!safe.contains(&secret));
    assert!(!safe.contains('\u{1b}'));
    assert!(!safe.contains('\u{7}'));
    assert_eq!(
        safe_text(&"x".repeat(MAX_CLIPBOARD_BYTES + 1)),
        Err(ClipboardError::TooLarge)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn direct_argv_adapter_reports_success_and_typed_failure() {
    let output = std::env::temp_dir().join(format!(
        "core-clipboard-{}-{:?}.txt",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&output);
    let success = [CommandSpec::new("/usr/bin/tee", [output.as_os_str()])];
    assert!(copy_text_with_specs("你好 😀", &success).await.is_ok());
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "你好 😀");
    let _ = std::fs::remove_file(output);

    let failure = [CommandSpec::new(
        "/usr/bin/false",
        std::iter::empty::<&str>(),
    )];
    assert!(matches!(
        copy_text_with_specs("text", &failure).await,
        Err(ClipboardError::DispatchedOutcomeUnknown { .. })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn dispatched_failure_never_falls_through_to_a_second_adapter() {
    let output = std::env::temp_dir().join(format!(
        "core-clipboard-fallback-{}-{:?}.txt",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&output);
    let specs = [
        CommandSpec::new("/usr/bin/false", std::iter::empty::<&str>()),
        CommandSpec::new("/usr/bin/tee", [output.as_os_str()]),
    ];
    assert!(matches!(
        copy_text_with_specs("must run once", &specs).await,
        Err(ClipboardError::DispatchedOutcomeUnknown { .. })
    ));
    assert!(!output.exists(), "a dispatched failure retried the payload");
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_explicitly_kills_and_reaps_with_unknown_outcome() {
    let spec = CommandSpec::new("/bin/sleep", ["10"]);
    let started = std::time::Instant::now();
    let report = run_report(&spec, b"", Duration::from_millis(25), InjectedFault::None).await;
    assert!(matches!(
        report.result,
        Err(ClipboardError::DispatchedOutcomeUnknown {
            stage: PostSpawnStage::Timeout,
            cleanup: CleanupState::Reaped,
        })
    ));
    assert_eq!(report.cleanup, Some(CleanupState::Reaped));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "timeout did not complete its bounded kill/reap path"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn every_injected_post_spawn_error_explicitly_kills_and_reaps() {
    let spec = CommandSpec::new("/bin/sleep", ["10"]);
    for (fault, stage) in [
        (InjectedFault::MissingStdin, PostSpawnStage::MissingStdin),
        (InjectedFault::Write, PostSpawnStage::Write),
        (InjectedFault::Shutdown, PostSpawnStage::Shutdown),
        (InjectedFault::Wait, PostSpawnStage::Wait),
    ] {
        let report = run_report(&spec, b"payload", Duration::from_secs(1), fault).await;
        assert_eq!(report.cleanup, Some(CleanupState::Reaped), "{stage}");
        assert!(matches!(
            report.result,
            Err(ClipboardError::DispatchedOutcomeUnknown {
                stage: observed,
                cleanup: CleanupState::Reaped,
            }) if observed == stage
        ));
    }
}

#[cfg(unix)]
#[test]
fn adapter_admission_rejects_symlinks_and_non_root_writable_files() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let root = std::env::temp_dir().join(format!(
        "core-clipboard-trust-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let executable = root.join("adapter");
    std::fs::write(&executable, b"not executable code").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();
    let link = root.join("adapter-link");
    symlink("/usr/bin/true", &link).unwrap();

    assert!(!trusted_adapter(&executable));
    assert!(!trusted_adapter(&link));
    assert!(
        installed([
            CommandSpec::new(executable, std::iter::empty::<&str>()),
            CommandSpec::new(link, std::iter::empty::<&str>()),
        ])
        .is_empty()
    );
    let _ = std::fs::remove_dir_all(root);
}
