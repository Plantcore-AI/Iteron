//! Bounded quiescence observation for the exact private group minted before native spawn.

use std::process::ExitStatus;
use tokio::process::Child;

/// Keep the leader unreaped through the last group signal. Once the actual wait consumes its
/// identity, the old numeric group may only be observed; neither Drop nor retry may signal it.
pub(crate) struct OwnedProcessGroup {
    retained_leader: Option<u32>,
}

impl OwnedProcessGroup {
    pub(crate) fn capture(child: &Child) -> Self {
        Self {
            retained_leader: child.id(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn signal_retained(&self, signal: libc::c_int) {
        if let Some(pid) = self
            .retained_leader
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 1)
        {
            // The collector has not consumed this leader's wait identity yet.
            unsafe { libc::kill(-pid, signal) };
        }
    }

    #[cfg(unix)]
    async fn observe_retained_exit(&mut self) -> std::io::Result<()> {
        let Some(pid) = self.retained_leader else {
            return Ok(());
        };
        let mut exited = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    tokio::task::yield_now().await;
                    continue;
                }
                // Any uncertain wait identity forbids further numeric signals.
                self.retained_leader = None;
                return Err(error);
            }
            if unsafe { info.si_pid() } == pid as i32 {
                return Ok(());
            }
            if exited.recv().await.is_none() {
                return Err(std::io::Error::other("owned child exit observation closed"));
            }
        }
    }

    pub(crate) async fn wait_and_close(
        &mut self,
        child: &mut Child,
    ) -> std::io::Result<ExitStatus> {
        #[cfg(unix)]
        {
            self.observe_retained_exit().await?;
            // The exited leader remains unreaped, so redirected background members still have
            // an exact owned group identity. End them before consuming the leader's receipt.
            self.signal_retained(libc::SIGKILL);
        }
        let result = child.wait().await;
        self.retained_leader = None;
        result
    }

    pub(crate) async fn kill_and_reap(&mut self, child: &mut Child) -> std::io::Result<ExitStatus> {
        #[cfg(unix)]
        self.signal_retained(libc::SIGKILL);
        let _ = child.start_kill();
        // start_kill may internally observe a completed direct child. No later group signal is
        // needed or authorized after the last signal above, including cancellation during wait.
        self.retained_leader = None;
        child.wait().await
    }
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        self.signal_retained(libc::SIGKILL);
    }
}

/// This proves only the owned Unix process group, not arbitrary processes that escaped its scope.
/// It is observation-only after reap: a reused numeric group must never receive a cleanup signal.
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
    async fn numeric_absence_observation_never_signals_an_actual_live_group() {
        let mut command = tokio::process::Command::new("bash");
        command
            .arg("-c")
            .arg("exec sleep 30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        crate::configure_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let group = child.id();
        let mut owner = super::OwnedProcessGroup::capture(&child);
        let proof = super::confirm_owned_group_shutdown(group).await;
        let live = child.try_wait().unwrap().is_none();
        owner.kill_and_reap(&mut child).await.unwrap();
        assert!(!proof);
        assert!(
            live,
            "a post-reap numeric observation cannot signal a reused live group"
        );
    }

    #[tokio::test]
    async fn actual_wait_retires_the_last_signal_identity_before_observation_or_drop() {
        let mut command = tokio::process::Command::new("bash");
        command.arg("-c").arg("exit 7").kill_on_drop(true);
        crate::configure_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let group = child.id();
        let mut owner = super::OwnedProcessGroup::capture(&child);
        let status = owner.wait_and_close(&mut child).await.unwrap();
        assert_eq!(status.code(), Some(7));
        assert!(owner.retained_leader.is_none());
        assert!(super::confirm_owned_group_shutdown(group).await);
        drop(owner);
    }

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
