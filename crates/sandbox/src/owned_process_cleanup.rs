//! Bounded quiescence observation for the exact private group minted before native spawn.

/// This proves only the owned Unix process group, not arbitrary processes that escaped its scope.
/// Platforms without such an observation stay unavailable; no leader exit is promoted to proof.
pub(crate) async fn confirm_owned_group_shutdown(group: Option<u32>) -> bool {
    #[cfg(unix)]
    {
        let Some(group) = group
            .and_then(|group| i32::try_from(group).ok())
            .filter(|group| *group > 1)
        else {
            return false;
        };
        // The trusted collector obtains this PGID before wait() can clear Child::id().
        // ESRCH is the sole positive absence observation; EPERM and other errors stay unknown.
        let absent = || {
            if unsafe { libc::kill(-group, 0) } == 0 {
                return false;
            }
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        };
        if absent() {
            return true;
        }
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        while tokio::time::Instant::now() < deadline {
            if absent() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        absent()
    }
    #[cfg(not(unix))]
    {
        let _ = group;
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::{Confinement, OutputObserver, run_direct};

    #[tokio::test]
    async fn failed_actual_command_is_not_confused_with_missing_physical_cleanup() {
        let (observer, _events) = OutputObserver::bounded("native-failure", 1, 4);
        let observer = observer.with_owned_group_cleanup();
        let conf =
            Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
        let output = run_direct("exit 1", &conf).await.unwrap();
        assert_eq!(output.exit_code, 1);
        assert!(observer.owned_group_cleanup_known());
    }

    #[tokio::test]
    async fn ordinary_output_observer_does_not_claim_group_cleanup() {
        let (observer, _events) = OutputObserver::bounded("native-ordinary", 1, 4);
        let conf =
            Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
        let output = run_direct("exit 0", &conf).await.unwrap();
        assert_eq!(output.exit_code, 0);
        assert!(!observer.owned_group_cleanup_known());
    }

    #[tokio::test]
    async fn redirected_background_group_is_stopped_or_has_explicitly_unavailable_proof() {
        let (observer, _events) = OutputObserver::bounded("native-background", 1, 4);
        let observer = observer.with_owned_group_cleanup();
        let conf =
            Confinement::unconfined(std::env::temp_dir()).with_output_observer(observer.clone());
        let started = tokio::time::Instant::now();
        let output = run_direct(
            r#"printf '%s\n' "$$"; sleep 30 </dev/null >/dev/null 2>&1 & exit 1"#,
            &conf,
        )
        .await
        .unwrap();
        assert_eq!(output.exit_code, 1);
        // Some hosts retain an orphan zombie until PID 1 reaps it; absence must not be guessed.
        // Positive proof is accepted only through the actual collector's ESRCH observation.
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        let group: i32 = output.stdout.trim().parse().unwrap();
        if observer.owned_group_cleanup_known() {
            assert_eq!(unsafe { libc::kill(-group, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }
}
