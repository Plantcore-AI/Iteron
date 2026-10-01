//! Killable, bounded transcript-export helper process and private pipe protocol.

use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Stdio;
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use super::ProcessRegistry;
use super::export as transcript_export;
#[cfg(any(target_os = "linux", target_os = "macos", windows, all(test, unix)))]
use super::{ReapOutcome, RegisteredChild};

mod protocol;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use protocol::encode_worker_request;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use protocol::{MAX_WORKER_RESPONSE_BYTES, WORKER_ENV};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use protocol::{WorkerResponse, decode_worker_response};
pub(crate) use protocol::{worker_main, worker_requested};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const EXPORT_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
pub(crate) const REAP_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
pub(crate) enum Cleanup {
    Reaped,
    AlreadyReaped,
    OutcomeUnknown,
}

impl std::fmt::Display for Cleanup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Reaped => "worker was killed and reaped",
            Self::AlreadyReaped => "worker had already exited and was reaped",
            Self::OutcomeUnknown => "worker kill was requested but reap outcome is unknown",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
pub(crate) enum PostDispatchStage {
    Stdin,
    RequestWriteOrShutdown,
    Wait,
    Exit,
    MissingResponse,
    OversizeResponse,
    MalformedResponse,
    HelperReported,
    Deadline,
    Cancelled,
}

impl std::fmt::Display for PostDispatchStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Stdin => "helper stdin setup",
            Self::RequestWriteOrShutdown => "request write/shutdown",
            Self::Wait => "helper wait",
            Self::Exit => "helper exit",
            Self::MissingResponse => "missing helper response",
            Self::OversizeResponse => "oversize helper response",
            Self::MalformedResponse => "malformed helper response",
            Self::HelperReported => "helper-reported durability",
            Self::Deadline => "helper deadline",
            Self::Cancelled => "cancellation after dispatch",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
pub(crate) enum WorkerFailure {
    KnownFailure(String),
    OutcomeUnknown {
        stage: PostDispatchStage,
        detail: String,
        cleanup: Cleanup,
    },
}

#[derive(Debug)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", windows)),
    allow(dead_code)
)]
pub(crate) enum WorkerRun {
    Completed(Result<PathBuf, WorkerFailure>),
    Cancelled,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFault {
    None,
    #[cfg(all(test, target_os = "linux"))]
    RequestWriteOrShutdown,
    #[cfg(all(test, target_os = "linux"))]
    Wait,
    #[cfg(all(test, target_os = "linux"))]
    Exit,
    #[cfg(all(test, target_os = "linux"))]
    MissingResponse,
    #[cfg(all(test, target_os = "linux"))]
    OversizeResponse,
    #[cfg(all(test, target_os = "linux"))]
    MalformedResponse,
}

#[cfg(all(target_os = "linux", test))]
impl InjectedFault {
    fn stage(self) -> Option<PostDispatchStage> {
        match self {
            Self::None => None,
            Self::RequestWriteOrShutdown => Some(PostDispatchStage::RequestWriteOrShutdown),
            Self::Wait => Some(PostDispatchStage::Wait),
            Self::Exit => Some(PostDispatchStage::Exit),
            Self::MissingResponse => Some(PostDispatchStage::MissingResponse),
            Self::OversizeResponse => Some(PostDispatchStage::OversizeResponse),
            Self::MalformedResponse => Some(PostDispatchStage::MalformedResponse),
        }
    }
}

// Reachable wherever its callers are. `Request::ProcessDelay` is `all(test, unix)` and spawns a
// real child, but `Request::Delay` is plain `#[cfg(test)]` and waits on this from every target, so
// gating the helper on unix left the Windows test build with a call to a function that had been
// configured out. `cargo check --workspace` never saw it — it does not build test targets — so the
// break only surfaced in the release leg, which does.
#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]
pub(crate) async fn cancelled(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

#[cfg(any(target_os = "linux", target_os = "macos", windows, all(test, unix)))]
pub(crate) async fn kill_and_reap(child: &mut RegisteredChild) -> Cleanup {
    let _ = child.start_kill();
    match tokio::time::timeout(REAP_DEADLINE, child.wait()).await {
        Ok(Ok(_)) => Cleanup::Reaped,
        Ok(Err(_)) | Err(_) => match child.reap_sync() {
            ReapOutcome::Reaped => Cleanup::Reaped,
            ReapOutcome::AlreadySettled => Cleanup::AlreadyReaped,
            ReapOutcome::OutcomeUnknown => Cleanup::OutcomeUnknown,
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn outcome_unknown(
    child: &mut RegisteredChild,
    stage: PostDispatchStage,
    detail: impl Into<String>,
) -> WorkerRun {
    let cleanup = kill_and_reap(child).await;
    WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
        stage,
        detail: detail.into(),
        cleanup,
    }))
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) async fn run_export_worker(
    workspace: &Path,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
    bytes: &[u8],
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    processes: &ProcessRegistry,
) -> WorkerRun {
    run_export_worker_inner(
        workspace,
        requested,
        collision,
        bytes,
        cancelled_rx,
        processes,
        InjectedFault::None,
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn run_export_worker_inner(
    workspace: &Path,
    requested: &str,
    collision: transcript_export::CollisionPolicy,
    bytes: &[u8],
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    processes: &ProcessRegistry,
    fault: InjectedFault,
) -> WorkerRun {
    #[cfg(not(test))]
    let _ = fault;
    let frame = match encode_worker_request(workspace, requested, collision, bytes) {
        Ok(frame) => frame,
        Err(error) => {
            return WorkerRun::Completed(Err(WorkerFailure::KnownFailure(error)));
        }
    };
    #[cfg(test)]
    let injected = fault != InjectedFault::None;
    #[cfg(not(test))]
    let injected = false;
    let executable = if injected {
        PathBuf::from("/bin/sleep")
    } else {
        match std::env::current_exe() {
            Ok(executable) => executable,
            Err(_) => {
                return WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
                    "export helper executable is unavailable".into(),
                )));
            }
        }
    };
    let mut command = tokio::process::Command::new(executable);
    if injected {
        command.arg("30");
    }
    command
        .env_clear()
        .env(WORKER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: this closure runs after fork and before exec and invokes only async-signal-safe libc
    // syscalls. Rechecking the parent closes the race where it died immediately before `prctl`.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt as _;

        command.as_std_mut().pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() == 1 {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = match processes.spawn(&mut command) {
        Ok(child) => child,
        Err(_) => {
            return WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
                "export helper could not start".into(),
            )));
        }
    };
    let Some(mut stdin) = child.take_stdin() else {
        return outcome_unknown(
            &mut child,
            PostDispatchStage::Stdin,
            "spawned helper had no request pipe",
        )
        .await;
    };
    let Some(stdout) = child.take_stdout() else {
        drop(stdin);
        return outcome_unknown(
            &mut child,
            PostDispatchStage::MissingResponse,
            "spawned helper had no response pipe",
        )
        .await;
    };
    let deadline = tokio::time::Instant::now()
        + iteron_tunables::param_duration(
            "cli.tui.transcript_effect.worker.export_deadline",
            EXPORT_DEADLINE,
        )
        .min(EXPORT_DEADLINE);
    let write = async {
        stdin.write_all(&frame).await?;
        stdin.shutdown().await
    };
    tokio::select! {
        _ = cancelled(cancelled_rx) => {
            drop(stdin);
            return outcome_unknown(&mut child, PostDispatchStage::Cancelled, "cancellation was requested after helper dispatch").await;
        }
        result = tokio::time::timeout_at(deadline, write) => match result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                drop(stdin);
                return outcome_unknown(
                    &mut child,
                    PostDispatchStage::RequestWriteOrShutdown,
                    "the bounded request could not be written and shut down",
                ).await;
            }
            Err(_) => {
                drop(stdin);
                return outcome_unknown(
                    &mut child,
                    PostDispatchStage::Deadline,
                    "the request pipe exceeded the five-second deadline",
                ).await;
            }
        }
    }
    drop(stdin);

    #[cfg(all(test, target_os = "linux"))]
    if let Some(stage) = fault.stage() {
        return outcome_unknown(
            &mut child,
            stage,
            "deterministically injected post-dispatch evidence loss",
        )
        .await;
    }

    let (_, response) = match settle_response(&mut child, stdout, cancelled_rx, deadline).await {
        Ok(observed) => observed,
        Err(outcome) => return outcome,
    };
    if response.len() > MAX_WORKER_RESPONSE_BYTES {
        return WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
            stage: PostDispatchStage::OversizeResponse,
            detail: "helper response exceeded the 32 KiB bound".into(),
            cleanup: Cleanup::AlreadyReaped,
        }));
    }
    WorkerRun::Completed(match decode_worker_response(workspace, &response) {
        Ok(WorkerResponse::Published(path)) => Ok(path),
        Ok(WorkerResponse::KnownFailure(error)) => Err(WorkerFailure::KnownFailure(error)),
        Ok(WorkerResponse::OutcomeUnknown(detail)) => Err(WorkerFailure::OutcomeUnknown {
            stage: PostDispatchStage::HelperReported,
            detail,
            cleanup: Cleanup::AlreadyReaped,
        }),
        Err(error) => Err(WorkerFailure::OutcomeUnknown {
            stage: if response.is_empty() {
                PostDispatchStage::MissingResponse
            } else {
                PostDispatchStage::MalformedResponse
            },
            detail: error,
            cleanup: Cleanup::AlreadyReaped,
        }),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn settle_response(
    child: &mut RegisteredChild,
    stdout: tokio::process::ChildStdout,
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<(std::process::ExitStatus, Vec<u8>), WorkerRun> {
    // Drain while waiting: a helper may block writing more than the native pipe capacity.
    // Both operations share the original absolute deadline and cancellation/settlement path.
    let (status, response) = tokio::select! {
        _ = cancelled(cancelled_rx) => {
            return Err(outcome_unknown(child, PostDispatchStage::Cancelled, "cancellation was requested after helper dispatch").await);
        }
        joined = tokio::time::timeout_at(deadline, async {
            tokio::join!(child.wait(), async {
                let mut response = Vec::new();
                stdout.take((MAX_WORKER_RESPONSE_BYTES + 1) as u64).read_to_end(&mut response).await.map(|_| response)
            })
        }) => match joined {
            Ok(pair) => pair,
            Err(_) => return Err(outcome_unknown(child, PostDispatchStage::Deadline, "helper exit/response exceeded the five-second deadline").await),
        }
    };
    let status = match status {
        Ok(status) => status,
        Err(_) => {
            return Err(outcome_unknown(
                child,
                PostDispatchStage::Wait,
                "the helper wait result was unavailable",
            )
            .await);
        }
    };
    if !status.success() {
        return Err(WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
            stage: PostDispatchStage::Exit,
            detail: format!("helper exited with {status}"),
            cleanup: Cleanup::AlreadyReaped,
        })));
    }
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            return Err(WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
                stage: PostDispatchStage::MalformedResponse,
                detail: "helper response pipe could not be read".into(),
                cleanup: Cleanup::AlreadyReaped,
            })));
        }
    };
    Ok((status, response))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) async fn run_export_worker(
    _workspace: &Path,
    _requested: &str,
    _collision: transcript_export::CollisionPolicy,
    _bytes: &[u8],
    _cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    _processes: &super::ProcessRegistry,
) -> WorkerRun {
    WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
        "secure transcript export is unsupported on this platform".into(),
    )))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_four_kib_pipe_drains_a_larger_response_before_confirming_exit() {
        use std::os::fd::AsRawFd as _;
        let processes = ProcessRegistry::default();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("i=0; while [ $i -lt 16384 ]; do printf x; i=$((i+1)); done")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = processes.spawn(&mut command).unwrap();
        let stdout = child.take_stdout().unwrap();
        // SAFETY: actual owned pipe fd; shrink its kernel capacity below the actual response.
        assert_eq!(
            unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
            4096
        );
        let (_cancel, mut cancelled) = tokio::sync::watch::channel(false);
        let (status, bytes) = settle_response(
            &mut child,
            stdout,
            &mut cancelled,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(status.success());
        assert_eq!(bytes, vec![b'x'; 16384]);
        assert!(processes.is_empty());
    }
    #[tokio::test]
    async fn response_wait_is_bounded_and_cancelled_dispatch_never_becomes_known_failure() {
        let processes = ProcessRegistry::default();
        let mut command = tokio::process::Command::new("/bin/sleep");
        command
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = processes.spawn(&mut command).unwrap();
        let stdout = child.take_stdout().unwrap();
        let (_cancel, mut cancelled) = tokio::sync::watch::channel(true);
        let result = settle_response(
            &mut child,
            stdout,
            &mut cancelled,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await;
        assert!(matches!(
            result,
            Err(WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
                stage: PostDispatchStage::Cancelled,
                cleanup: Cleanup::Reaped | Cleanup::AlreadyReaped,
                ..
            })))
        ));
        assert!(processes.is_empty());
    }

    #[tokio::test]
    async fn injected_pipeline_faults_classify_every_ambiguous_post_dispatch_stage_unknown() {
        let workspace = Path::new("/tmp");
        for (fault, expected) in [
            (
                InjectedFault::RequestWriteOrShutdown,
                PostDispatchStage::RequestWriteOrShutdown,
            ),
            (InjectedFault::Wait, PostDispatchStage::Wait),
            (InjectedFault::Exit, PostDispatchStage::Exit),
            (
                InjectedFault::MissingResponse,
                PostDispatchStage::MissingResponse,
            ),
            (
                InjectedFault::OversizeResponse,
                PostDispatchStage::OversizeResponse,
            ),
            (
                InjectedFault::MalformedResponse,
                PostDispatchStage::MalformedResponse,
            ),
        ] {
            let processes = ProcessRegistry::default();
            let (_cancel, mut cancelled) = tokio::sync::watch::channel(false);
            let run = run_export_worker_inner(
                workspace,
                "transcript.md",
                transcript_export::CollisionPolicy::Refuse,
                b"bounded fixture",
                &mut cancelled,
                &processes,
                fault,
            )
            .await;
            assert!(matches!(
                run,
                WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
                    stage,
                    cleanup: Cleanup::Reaped,
                    ..
                })) if stage == expected
            ));
            assert!(
                processes.is_empty(),
                "{expected} left a helper registered after its injected fault"
            );
        }
    }
}
