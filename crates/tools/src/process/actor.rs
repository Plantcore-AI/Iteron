use super::types::JobId;
use super::types::{ActionError, JobShared, JobState, lock};
use super::{
    CONTROL_QUEUE_CAPACITY, MAX_JOB_RUNTIME_SECS, OUTPUT_DRAIN_SECS, ProcessLifecycleKind,
    ProcessLifecycleNotice, ProcessLifecycleObserver, STDIN_WRITE_SECS, STOP_QUEUE_CAPACITY,
};
use core_sandbox::{ConfinedProcess, ConfinedProcessControl};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};

pub(super) struct WriteControl {
    pub(super) bytes: Vec<u8>,
    pub(super) eof: bool,
    pub(super) reply: oneshot::Sender<Result<(), ActionError>>,
}

pub(super) enum StopControl {
    Request(oneshot::Sender<bool>),
    Cleanup,
}

pub(super) struct ActorChannels {
    pub(super) writes: mpsc::Sender<WriteControl>,
    pub(super) stop: mpsc::Sender<StopControl>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

pub(super) fn spawn_actor(
    job_id: JobId,
    process: ConfinedProcess,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::process::ChildStderr,
    shared: Arc<JobShared>,
    lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
) -> ActorChannels {
    let (writes, write_receiver) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (stop, stop_receiver) = mpsc::channel(STOP_QUEUE_CAPACITY);
    let (event_sender, events) = mpsc::channel(4);
    let stdout_task = tokio::spawn(drain_output(
        stdout,
        Arc::clone(&shared.stdout),
        event_sender.clone(),
        shared.revision.clone(),
    ));
    let stderr_task = tokio::spawn(drain_output(
        stderr,
        Arc::clone(&shared.stderr),
        event_sender,
        shared.revision.clone(),
    ));
    let task = tokio::spawn(run_job(
        job_id,
        process,
        stdin,
        write_receiver,
        stop_receiver,
        events,
        shared,
        lifecycle_observer,
        stdout_task,
        stderr_task,
    ));
    ActorChannels { writes, stop, task }
}

enum DrainEvent {
    Limit,
    ReadFailed,
}

enum TerminalCause {
    Natural,
    Stop,
    Timeout,
    OutputLimit,
    IoFailure,
    OwnerDropped,
    WaitFailed,
}

struct ControllerExitGuard {
    job_id: JobId,
    shared: Arc<JobShared>,
    process_control: ConfinedProcessControl,
    lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
    committed: bool,
}

impl Drop for ControllerExitGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.process_control.force_kill();
        let terminal = {
            let mut state = lock(&self.shared.state);
            if !state.is_terminal() {
                *state = JobState::CleanupUnknown {
                    trigger: "controller_dropped",
                };
                true
            } else {
                false
            }
        };
        self.shared.notify();
        if terminal {
            notify_terminal(
                self.job_id,
                &JobState::CleanupUnknown {
                    trigger: "controller_dropped",
                },
                &self.lifecycle_observer,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_job(
    job_id: JobId,
    mut process: ConfinedProcess,
    stdin: tokio::process::ChildStdin,
    mut writes: mpsc::Receiver<WriteControl>,
    mut stops: mpsc::Receiver<StopControl>,
    mut events: mpsc::Receiver<DrainEvent>,
    shared: Arc<JobShared>,
    lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
    stdout_task: tokio::task::JoinHandle<()>,
    stderr_task: tokio::task::JoinHandle<()>,
) {
    notify_kind(job_id, ProcessLifecycleKind::Spawned, &lifecycle_observer);
    let mut exit_guard = ControllerExitGuard {
        job_id,
        shared: Arc::clone(&shared),
        process_control: process.control(),
        lifecycle_observer: Arc::clone(&lifecycle_observer),
        committed: false,
    };
    let mut stdin = Some(stdin);
    let deadline = tokio::time::sleep(Duration::from_secs(MAX_JOB_RUNTIME_SECS));
    tokio::pin!(deadline);
    let mut stop_reply = None;
    let mut events_open = true;
    let (cause, status) = loop {
        tokio::select! {
            biased;
            stop = stops.recv() => {
                match stop {
                    Some(StopControl::Request(reply)) => stop_reply = Some(reply),
                    Some(StopControl::Cleanup) | None => {}
                }
                mark_stopping(&shared);
                let status = process.terminate_and_reap().await;
                let cause = if stop_reply.is_some() {
                    TerminalCause::Stop
                } else {
                    TerminalCause::OwnerDropped
                };
                break (cause, status);
            }
            waited = process.wait() => {
                break match waited {
                    Ok(status) => (TerminalCause::Natural, Some(status)),
                    Err(_) => (TerminalCause::WaitFailed, None),
                };
            }
            _ = &mut deadline => {
                mark_stopping(&shared);
                let status = process.terminate_and_reap().await;
                break (TerminalCause::Timeout, status);
            }
            event = events.recv(), if events_open => {
                match event {
                    Some(DrainEvent::Limit) => {
                        mark_stopping(&shared);
                        let status = process.terminate_and_reap().await;
                        break (TerminalCause::OutputLimit, status);
                    }
                    Some(DrainEvent::ReadFailed) => {
                        mark_stopping(&shared);
                        let status = process.terminate_and_reap().await;
                        break (TerminalCause::IoFailure, status);
                    }
                    None => events_open = false,
                }
            }
            write = writes.recv() => {
                let Some(WriteControl { bytes, eof, reply }) = write else {
                    continue;
                };
                let result = write_stdin(&mut stdin, &bytes, eof).await;
                let failed = matches!(result, Err(ActionError::Unknown(_)));
                let _ = reply.send(result);
                if failed {
                    mark_stopping(&shared);
                    let status = process.terminate_and_reap().await;
                    break (TerminalCause::IoFailure, status);
                }
            }
        }
    };
    // Close admission before final drains. Every control already accepted into a bounded queue
    // receives a terminal answer; no caller waits on a reply sender silently dropped at actor exit.
    writes.close();
    stops.close();
    reject_pending_writes(&mut writes);
    let mut stop_replies = Vec::with_capacity(STOP_QUEUE_CAPACITY + 1);
    if let Some(reply) = stop_reply {
        stop_replies.push(reply);
    }
    while let Ok(control) = stops.try_recv() {
        if let StopControl::Request(reply) = control {
            stop_replies.push(reply);
        }
    }
    drop(stdin);
    finish_drains(stdout_task, stderr_task, &shared).await;
    let authoritative = status.is_some();
    let terminal = terminal_state(cause, status);
    *lock(&shared.state) = terminal.clone();
    shared.notify();
    notify_terminal(job_id, &terminal, &lifecycle_observer);
    for reply in stop_replies {
        let _ = reply.send(authoritative);
    }
    exit_guard.committed = true;
}

fn notify_terminal(
    job_id: JobId,
    state: &JobState,
    observer: &Arc<Mutex<Option<ProcessLifecycleObserver>>>,
) {
    let kind = match state {
        JobState::Exited { .. } => ProcessLifecycleKind::Exited,
        JobState::Stopped { .. } => ProcessLifecycleKind::Stopped,
        JobState::TimedOut { .. } => ProcessLifecycleKind::TimedOut,
        JobState::OutputLimitExceeded { .. } => ProcessLifecycleKind::OutputLimitExceeded,
        JobState::IoFailed { .. } => ProcessLifecycleKind::IoFailed,
        JobState::CleanupUnknown { .. } => ProcessLifecycleKind::CleanupUnknown,
        JobState::Running | JobState::Stopping => return,
    };
    notify_kind(job_id, kind, observer);
}

fn notify_kind(
    job_id: JobId,
    kind: ProcessLifecycleKind,
    observer: &Arc<Mutex<Option<ProcessLifecycleObserver>>>,
) {
    let observer = lock(observer).clone();
    if let Some(observer) = observer {
        observer(ProcessLifecycleNotice {
            job_id: job_id.to_string(),
            kind,
        });
    }
}

fn reject_pending_writes(writes: &mut mpsc::Receiver<WriteControl>) {
    while let Ok(WriteControl { reply, .. }) = writes.try_recv() {
        let _ = reply.send(Err(ActionError::Definite(
            "stdin was not applied because the job is stopping".into(),
        )));
    }
}

async fn write_stdin(
    stdin: &mut Option<tokio::process::ChildStdin>,
    bytes: &[u8],
    eof: bool,
) -> Result<(), ActionError> {
    let Some(handle) = stdin.as_mut() else {
        return Err(ActionError::Definite("job stdin is already closed".into()));
    };
    let operation = async {
        if !bytes.is_empty() {
            handle.write_all(bytes).await?;
        }
        if eof {
            handle.shutdown().await?;
        }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(Duration::from_secs(STDIN_WRITE_SECS), operation).await {
        Ok(Ok(())) => {
            if eof {
                *stdin = None;
            }
            Ok(())
        }
        Ok(Err(error)) => Err(ActionError::Unknown(format!(
            "stdin write may have been partially applied: {error}"
        ))),
        Err(_) => Err(ActionError::Unknown(
            "stdin write may have been partially applied before its deadline".into(),
        )),
    }
}

async fn drain_output<R: AsyncRead + Unpin>(
    mut reader: R,
    ring: Arc<Mutex<super::output::OutputRing>>,
    events: mpsc::Sender<DrainEvent>,
    revision: watch::Sender<u64>,
) {
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                if lock(&ring).push(&chunk[..read]) {
                    let _ = events.try_send(DrainEvent::Limit);
                }
                revision.send_modify(|value| *value = value.wrapping_add(1));
            }
            Err(_) => {
                let _ = events.try_send(DrainEvent::ReadFailed);
                break;
            }
        }
    }
    lock(&ring).close();
    revision.send_modify(|value| *value = value.wrapping_add(1));
}

async fn finish_drains(
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
    shared: &JobShared,
) {
    let _ = tokio::join!(finish_drain(stdout), finish_drain(stderr));
    lock(&shared.stdout).close();
    lock(&shared.stderr).close();
    shared.notify();
}

async fn finish_drain(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(Duration::from_secs(OUTPUT_DRAIN_SECS), &mut task)
        .await
        .is_err()
    {
        task.abort();
    }
}

fn terminal_state(cause: TerminalCause, status: Option<std::process::ExitStatus>) -> JobState {
    let Some(status) = status else {
        let trigger = match cause {
            TerminalCause::Natural | TerminalCause::WaitFailed => "wait_failed",
            TerminalCause::Stop => "stop",
            TerminalCause::Timeout => "timeout",
            TerminalCause::OutputLimit => "output_limit",
            TerminalCause::IoFailure => "io_failure",
            TerminalCause::OwnerDropped => "owner_drop",
        };
        return JobState::CleanupUnknown { trigger };
    };
    let (exit_code, signal) = exit_parts(&status);
    match cause {
        TerminalCause::Natural => JobState::Exited { exit_code, signal },
        TerminalCause::Stop | TerminalCause::OwnerDropped => {
            JobState::Stopped { exit_code, signal }
        }
        TerminalCause::Timeout => JobState::TimedOut { exit_code, signal },
        TerminalCause::OutputLimit => JobState::OutputLimitExceeded { exit_code, signal },
        TerminalCause::IoFailure => JobState::IoFailed { exit_code, signal },
        TerminalCause::WaitFailed => JobState::CleanupUnknown {
            trigger: "wait_failed",
        },
    }
}

fn exit_parts(status: &std::process::ExitStatus) -> (Option<i32>, Option<i32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        (status.code(), status.signal())
    }
    #[cfg(not(unix))]
    {
        (status.code(), None)
    }
}

fn mark_stopping(shared: &JobShared) {
    let mut state = lock(&shared.state);
    if !state.is_terminal() {
        *state = JobState::Stopping;
    }
    drop(state);
    shared.notify();
}
