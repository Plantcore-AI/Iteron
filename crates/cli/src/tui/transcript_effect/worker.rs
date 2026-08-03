//! Killable, bounded transcript-export helper process and private pipe protocol.

use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

#[cfg(target_os = "linux")]
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::transcript_export;
#[cfg(any(target_os = "linux", all(test, unix)))]
#[cfg(target_os = "linux")]
use super::ProcessRegistry;
#[cfg(any(target_os = "linux", all(test, unix)))]
use super::RegisteredChild;

mod protocol;
#[cfg(target_os = "linux")]
use protocol::encode_worker_request;
#[cfg(target_os = "linux")]
use protocol::{MAX_WORKER_RESPONSE_BYTES, WORKER_ENV};
#[cfg(target_os = "linux")]
use protocol::{WorkerResponse, decode_worker_response};
pub(crate) use protocol::{worker_main, worker_requested};

#[cfg(target_os = "linux")]
const EXPORT_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", test))]
pub(super) const REAP_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum Cleanup {
    Reaped,
    AlreadyReaped,
}

impl std::fmt::Display for Cleanup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Reaped => "worker was killed and reaped",
            Self::AlreadyReaped => "worker had already exited and was reaped",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum PostDispatchStage {
    Stdin,
    RequestWriteOrShutdown,
    Wait,
    Exit,
    MissingResponse,
    OversizeResponse,
    MalformedResponse,
    HelperReported,
    Deadline,
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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum WorkerFailure {
    KnownFailure(String),
    OutcomeUnknown {
        stage: PostDispatchStage,
        detail: String,
        cleanup: Cleanup,
    },
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum WorkerRun {
    Completed(Result<PathBuf, WorkerFailure>),
    Cancelled,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedFault {
    None,
    #[cfg(test)]
    RequestWriteOrShutdown,
    #[cfg(test)]
    Wait,
    #[cfg(test)]
    Exit,
    #[cfg(test)]
    MissingResponse,
    #[cfg(test)]
    OversizeResponse,
    #[cfg(test)]
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

#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) async fn cancelled(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) async fn kill_and_reap(child: &mut RegisteredChild) -> Cleanup {
    let _ = child.start_kill();
    match tokio::time::timeout(REAP_DEADLINE, child.wait()).await {
        Ok(Ok(_)) => Cleanup::Reaped,
        Ok(Err(_)) => {
            if child.reap_sync() {
                Cleanup::Reaped
            } else {
                Cleanup::AlreadyReaped
            }
        }
        Err(_) => {
            if child.reap_sync() {
                Cleanup::Reaped
            } else {
                Cleanup::AlreadyReaped
            }
        }
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub(super) async fn run_export_worker(
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

#[cfg(target_os = "linux")]
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
    let deadline = tokio::time::Instant::now() + EXPORT_DEADLINE;
    let write = async {
        stdin.write_all(&frame).await?;
        stdin.shutdown().await
    };
    tokio::select! {
        _ = cancelled(cancelled_rx) => {
            drop(stdin);
            let _ = kill_and_reap(&mut child).await;
            return WorkerRun::Cancelled;
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

    #[cfg(test)]
    if let Some(stage) = fault.stage() {
        return outcome_unknown(
            &mut child,
            stage,
            "deterministically injected post-dispatch evidence loss",
        )
        .await;
    }

    let status = tokio::select! {
        _ = cancelled(cancelled_rx) => {
            let _ = kill_and_reap(&mut child).await;
            return WorkerRun::Cancelled;
        }
        result = tokio::time::timeout_at(deadline, child.wait()) => match result {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                return outcome_unknown(
                    &mut child,
                    PostDispatchStage::Wait,
                    "the helper wait result was unavailable",
                ).await;
            }
            Err(_) => {
                return outcome_unknown(
                    &mut child,
                    PostDispatchStage::Deadline,
                    "the helper exceeded the five-second deadline",
                ).await;
            }
        }
    };
    if !status.success() {
        return WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
            stage: PostDispatchStage::Exit,
            detail: format!("helper exited with {status}"),
            cleanup: Cleanup::AlreadyReaped,
        }));
    }
    let mut response = Vec::new();
    if stdout
        .take((MAX_WORKER_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .is_err()
    {
        return WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
            stage: PostDispatchStage::MalformedResponse,
            detail: "helper response pipe could not be read".into(),
            cleanup: Cleanup::AlreadyReaped,
        }));
    }
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

#[cfg(not(target_os = "linux"))]
pub(super) async fn run_export_worker(
    _workspace: &Path,
    _requested: &str,
    _collision: transcript_export::CollisionPolicy,
    _bytes: &[u8],
    _cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    _processes: &super::ProcessRegistry,
) -> WorkerRun {
    WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
        "secure transcript export requires Linux anonymous-inode publication".into(),
    )))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

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
