//! Single-flight supervision for transcript clipboard and export effects.
//!
//! Export is isolated in a separately killable instance of the current executable. The child gets
//! a bounded binary request on stdin, an empty environment, and no terminal handles. Cancellation,
//! deadline, and every post-spawn error signal and bounded-wait it; the Linux child also requests
//! `SIGKILL` if its parent dies. Reap confirmation is typed separately from an unknown result, so a
//! kernel wait failure can never become a false joined-success claim.

use std::path::PathBuf;
#[cfg(all(test, unix))]
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[cfg(test)]
use std::time::Duration;

use crate::block;

use super::{clipboard, transcript_export};

mod worker;
use worker::{WorkerFailure, WorkerRun};
pub(crate) use worker::{worker_main, worker_requested};
mod process;
pub(super) use process::{ProcessRegistry, ReapOutcome, RegisteredChild};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Viewer,
    Slash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Success,
    KnownFailure,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlKind {
    Compact,
    Side,
}

impl ControlKind {
    fn label(self) -> &'static str {
        match self {
            Self::Compact => "compaction",
            Self::Side => "side conversation",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ControlCompletion {
    pub(crate) kind: ControlKind,
    pub(crate) reply: Option<crate::app_server::ControlReply>,
    pub(crate) cancellation_requested: bool,
}

#[derive(Debug)]
pub(crate) struct Event {
    pub(crate) origin: Origin,
    pub(crate) outcome: Disposition,
    pub(crate) message: String,
    pub(crate) shell: Option<super::inline_shell::ShellCompletion>,
    pub(crate) control: Option<ControlCompletion>,
    final_slot: bool,
}

impl Event {
    pub(crate) fn is_final(&self) -> bool {
        self.final_slot
    }
}

pub(crate) enum Request {
    Copy {
        text: String,
        subject: &'static str,
        origin: Origin,
    },
    Export {
        workspace: PathBuf,
        blocks: Vec<Arc<block::Block>>,
        selected_ids: Option<Vec<u64>>,
        requested: String,
        collision: transcript_export::CollisionPolicy,
        origin: Origin,
    },
    Shell {
        workspace: PathBuf,
        command: String,
        sensitive_env_names: Vec<String>,
        mode: iteron_protocol::PermissionMode,
        rules: iteron_protocol::PermissionRules,
    },
    Control {
        sender: tokio::sync::mpsc::Sender<crate::app_server::ControlRequest>,
        control: crate::app_server::Control,
        interrupt: Arc<AtomicBool>,
        kind: ControlKind,
    },
    #[cfg(test)]
    Delay { duration: Duration, origin: Origin },
    #[cfg(all(test, unix))]
    ProcessDelay {
        started: tokio::sync::oneshot::Sender<u32>,
        origin: Origin,
    },
}

impl Request {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Copy { .. } => "copy",
            Self::Export { .. } => "export",
            Self::Shell { .. } => "shell",
            Self::Control { kind, .. } => kind.label(),
            #[cfg(test)]
            Self::Delay { .. } => "test effect",
            #[cfg(all(test, unix))]
            Self::ProcessDelay { .. } => "test process",
        }
    }

    fn interrupt_flag(&self) -> Option<Arc<AtomicBool>> {
        match self {
            Self::Control { interrupt, .. } => Some(interrupt.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Busy;

pub(crate) struct Supervisor {
    sender: tokio::sync::mpsc::Sender<Event>,
    receiver: tokio::sync::mpsc::Receiver<Event>,
    task: Option<tokio::task::JoinHandle<()>>,
    cancel: Option<tokio::sync::watch::Sender<bool>>,
    cancel_interrupt: Option<Arc<AtomicBool>>,
    label: Option<&'static str>,
    processes: ProcessRegistry,
}

impl Default for Supervisor {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        Self {
            sender,
            receiver,
            task: None,
            cancel: None,
            cancel_interrupt: None,
            label: None,
            processes: ProcessRegistry::default(),
        }
    }
}

impl Supervisor {
    pub(crate) fn is_active(&self) -> bool {
        self.task.is_some()
    }

    pub(crate) fn label(&self) -> Option<&'static str> {
        self.label
    }

    pub(crate) fn start(&mut self, request: Request) -> Result<(), Busy> {
        if self.task.is_some() {
            return Err(Busy);
        }
        let label = request.label();
        let cancel_interrupt = request.interrupt_flag();
        let sender = self.sender.clone();
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        self.label = Some(label);
        self.cancel = Some(cancel);
        self.cancel_interrupt = cancel_interrupt;
        self.task = Some(tokio::spawn(run(
            request,
            sender,
            cancelled,
            self.processes.clone(),
        )));
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Option<Event> {
        let event = self.receiver.recv().await?;
        if event.final_slot {
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            self.cancel = None;
            self.cancel_interrupt = None;
            self.label = None;
        }
        Some(event)
    }

    /// Request cancellation without waiting for process cleanup. The render/input loop stays live;
    /// the existing completion channel reports the bounded cleanup terminal asynchronously.
    pub(crate) fn cancel(&self) -> bool {
        if let Some(interrupt) = &self.cancel_interrupt {
            interrupt.store(true, Ordering::SeqCst);
        }
        self.cancel
            .as_ref()
            .is_some_and(|cancel| cancel.send(true).is_ok())
    }

    /// Cancel the active effect and join its owned task after its finite exact-handle cleanup path.
    /// Each child has a non-cloneable registry ticket and, on Linux, carries a parent-death signal
    /// as a final containment layer; lack of reap evidence is retained as outcome-unknown.
    pub(crate) async fn shutdown(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        if let Some(cancel) = self.cancel.take() {
            if let Some(interrupt) = &self.cancel_interrupt {
                interrupt.store(true, Ordering::SeqCst);
            }
            let _ = cancel.send(true);
        }
        // Every production branch owns its own bounded deadline and typed kill/reap attempt.
        // Await the task so it can preserve Reaped versus OutcomeUnknown instead of aborting the
        // cleanup state machine between signal and its finite evidence window.
        let _ = task.await;
        self.label = None;
        self.cancel_interrupt = None;
        while self.receiver.try_recv().is_ok() {}
    }

    /// Finally-style boundary used by the TUI: preserve its exact normal/error outcome only after
    /// all owned effect work has settled.
    pub(crate) async fn finish<T>(&mut self, outcome: T) -> T {
        self.shutdown().await;
        outcome
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        if let Some(cancel) = self.cancel.take() {
            if let Some(interrupt) = &self.cancel_interrupt {
                interrupt.store(true, Ordering::SeqCst);
            }
            let _ = cancel.send(true);
        }
        self.processes.close_and_reap();
        task.abort();
        self.label = None;
        self.cancel_interrupt = None;
    }
}

async fn send(sender: &tokio::sync::mpsc::Sender<Event>, event: Event) {
    let _ = sender.send(event).await;
}

async fn run(
    request: Request,
    sender: tokio::sync::mpsc::Sender<Event>,
    mut cancelled: tokio::sync::watch::Receiver<bool>,
    processes: ProcessRegistry,
) {
    match request {
        Request::Copy {
            text,
            subject,
            origin,
        } => {
            // Clipboard owns its own three-second deadline plus explicit kill-and-reap path. Let it
            // settle instead of dropping that cleanup future when frontend shutdown is requested.
            let (outcome, message) = match clipboard::copy_text(&text, &processes).await {
                Ok(adapter) => (
                    Disposition::Success,
                    format!("copied {subject} via {adapter}"),
                ),
                Err(error @ clipboard::ClipboardError::DispatchedOutcomeUnknown { .. }) => (
                    Disposition::OutcomeUnknown,
                    format!("copy outcome unknown after dispatch: {error}"),
                ),
                Err(error) => (
                    Disposition::KnownFailure,
                    format!("copy failed before dispatch: {error}"),
                ),
            };
            send(
                &sender,
                Event {
                    origin,
                    outcome,
                    message,
                    shell: None,
                    control: None,
                    final_slot: true,
                },
            )
            .await;
        }
        Request::Export {
            workspace,
            blocks,
            selected_ids,
            requested,
            collision,
            origin,
        } => {
            let bytes = match transcript_export::body(&blocks, selected_ids.as_deref()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    send(
                        &sender,
                        Event {
                            origin,
                            outcome: Disposition::KnownFailure,
                            message: format!("export failed before dispatch: {error}"),
                            shell: None,
                            control: None,
                            final_slot: true,
                        },
                    )
                    .await;
                    return;
                }
            };
            if let Some(event) = export_event(
                origin,
                worker::run_export_worker(
                    &workspace,
                    &requested,
                    collision,
                    &bytes,
                    &mut cancelled,
                    &processes,
                )
                .await,
            ) {
                send(&sender, event).await;
            }
        }
        Request::Shell {
            workspace,
            command,
            sensitive_env_names,
            mode,
            rules,
        } => {
            let completion = super::inline_shell::run_bash_inline(
                &workspace,
                &command,
                &sensitive_env_names,
                mode,
                &rules,
                &mut cancelled,
            )
            .await;
            let outcome = if completion.ok {
                Disposition::Success
            } else {
                Disposition::KnownFailure
            };
            send(
                &sender,
                Event {
                    origin: Origin::Slash,
                    outcome,
                    message: if completion.ok {
                        "shell completed".into()
                    } else {
                        "shell stopped".into()
                    },
                    shell: Some(completion),
                    control: None,
                    final_slot: true,
                },
            )
            .await;
        }
        Request::Control {
            sender: control_sender,
            control,
            interrupt,
            kind,
        } => {
            let (reply, reply_rx) = tokio::sync::oneshot::channel();
            let request = crate::app_server::ControlRequest { control, reply };
            let dispatch = tokio::select! {
                biased;
                _ = cancelled.changed() => None,
                sent = control_sender.send(request) => Some(sent.is_ok()),
            };
            if dispatch != Some(true) {
                // No runtime request owns the flag, so this branch must clear the eager signal set
                // synchronously by `Supervisor::cancel`.
                interrupt.store(false, Ordering::SeqCst);
                let cancellation_requested = dispatch.is_none();
                send(
                    &sender,
                    Event {
                        origin: Origin::Slash,
                        outcome: Disposition::KnownFailure,
                        message: if cancellation_requested {
                            format!("{} cancelled before dispatch", kind.label())
                        } else {
                            format!("{} could not reach the runtime", kind.label())
                        },
                        shell: None,
                        control: Some(ControlCompletion {
                            kind,
                            reply: None,
                            cancellation_requested,
                        }),
                        final_slot: true,
                    },
                )
                .await;
                return;
            }

            let mut reply_rx = reply_rx;
            let mut cancellation_requested = false;
            let reply = loop {
                tokio::select! {
                    biased;
                    changed = cancelled.changed(), if !cancellation_requested => {
                        cancellation_requested = true;
                        let _ = changed;
                    }
                    reply = &mut reply_rx => break reply.ok(),
                }
            };
            let outcome = if matches!(&reply, Some(crate::app_server::ControlReply::Refused(_)))
                || reply.is_none()
            {
                Disposition::KnownFailure
            } else {
                Disposition::Success
            };
            send(
                &sender,
                Event {
                    origin: Origin::Slash,
                    outcome,
                    message: if reply.is_some() {
                        format!("{} settled", kind.label())
                    } else {
                        format!("{} lost its runtime reply", kind.label())
                    },
                    shell: None,
                    control: Some(ControlCompletion {
                        kind,
                        reply,
                        cancellation_requested,
                    }),
                    final_slot: true,
                },
            )
            .await;
        }
        #[cfg(test)]
        Request::Delay { duration, origin } => {
            tokio::select! {
                _ = worker::cancelled(&mut cancelled) => return,
                _ = tokio::time::sleep(duration) => {}
            }
            send(
                &sender,
                Event {
                    origin,
                    outcome: Disposition::Success,
                    message: "test effect complete".into(),
                    shell: None,
                    control: None,
                    final_slot: true,
                },
            )
            .await;
        }
        #[cfg(all(test, unix))]
        Request::ProcessDelay { started, origin } => {
            run_test_process(started, origin, &sender, &mut cancelled, &processes).await;
        }
    }
}

fn export_event(origin: Origin, run: WorkerRun) -> Option<Event> {
    let (outcome, message) = match run {
        WorkerRun::Completed(Ok(path)) => (
            Disposition::Success,
            format!("exported -> {}", path.display()),
        ),
        WorkerRun::Completed(Err(WorkerFailure::KnownFailure(error))) => (
            Disposition::KnownFailure,
            format!("export failed before dispatch: {error}"),
        ),
        WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
            stage,
            detail,
            cleanup,
        })) => (
            Disposition::OutcomeUnknown,
            format!("export outcome unknown after dispatch ({stage}: {detail}); {cleanup}"),
        ),
        WorkerRun::Cancelled => return None,
    };
    Some(Event {
        origin,
        outcome,
        message,
        shell: None,
        control: None,
        final_slot: true,
    })
}

#[cfg(all(test, unix))]
async fn run_test_process(
    started: tokio::sync::oneshot::Sender<u32>,
    origin: Origin,
    sender: &tokio::sync::mpsc::Sender<Event>,
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
    processes: &ProcessRegistry,
) {
    let mut command = tokio::process::Command::new("/bin/sleep");
    command
        .arg("30")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match processes.spawn(&mut command) {
        Ok(child) => child,
        Err(_) => return,
    };
    let Some(pid) = child.id() else {
        let _ = worker::kill_and_reap(&mut child).await;
        return;
    };
    let _ = started.send(pid);
    tokio::select! {
        _ = worker::cancelled(cancelled_rx) => {
            let _ = worker::kill_and_reap(&mut child).await;
        }
        _ = child.wait() => {
            send(sender, Event {
                origin,
                outcome: Disposition::Success,
                message: "test process complete".into(),
                shell: None,
                control: None,
                final_slot: true,
            }).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injected_post_dispatch_faults_are_typed_unknown_with_exact_ui_text() {
        use worker::{Cleanup, PostDispatchStage};

        for (stage, label) in [
            (
                PostDispatchStage::RequestWriteOrShutdown,
                "request write/shutdown",
            ),
            (PostDispatchStage::Wait, "helper wait"),
            (PostDispatchStage::Exit, "helper exit"),
            (
                PostDispatchStage::MissingResponse,
                "missing helper response",
            ),
            (
                PostDispatchStage::OversizeResponse,
                "oversize helper response",
            ),
            (
                PostDispatchStage::MalformedResponse,
                "malformed helper response",
            ),
        ] {
            let event = export_event(
                Origin::Viewer,
                WorkerRun::Completed(Err(WorkerFailure::OutcomeUnknown {
                    stage,
                    detail: "injected evidence loss".into(),
                    cleanup: Cleanup::Reaped,
                })),
            )
            .expect("post-dispatch ambiguity emits one terminal event");
            assert_eq!(event.outcome, Disposition::OutcomeUnknown, "{label}");
            assert_eq!(
                event.message,
                format!(
                    "export outcome unknown after dispatch ({label}: injected evidence loss); \
                     worker was killed and reaped"
                )
            );
            assert!(event.is_final());
        }

        let known = export_event(
            Origin::Slash,
            WorkerRun::Completed(Err(WorkerFailure::KnownFailure(
                "request exceeds bound".into(),
            ))),
        )
        .unwrap();
        assert_eq!(known.outcome, Disposition::KnownFailure);
        assert_eq!(
            known.message,
            "export failed before dispatch: request exceeds bound"
        );
    }

    #[tokio::test]
    async fn active_effect_is_single_flight_while_unrelated_events_remain_responsive() {
        let mut supervisor = Supervisor::default();
        supervisor
            .start(Request::Delay {
                duration: Duration::from_millis(50),
                origin: Origin::Viewer,
            })
            .unwrap();
        assert!(supervisor.is_active());
        assert!(
            supervisor
                .start(Request::Delay {
                    duration: Duration::ZERO,
                    origin: Origin::Viewer,
                })
                .is_err()
        );

        let (unrelated_tx, mut unrelated_rx) = tokio::sync::mpsc::channel(1);
        unrelated_tx.send("approval").await.unwrap();
        tokio::select! {
            event = unrelated_rx.recv() => assert_eq!(event, Some("approval")),
            _ = supervisor.recv() => panic!("the pending effect blocked an unrelated event"),
        }
        assert!(supervisor.is_active());
        let event = supervisor.recv().await.unwrap();
        assert_eq!(event.message, "test effect complete");
        assert!(!supervisor.is_active());
    }

    #[tokio::test]
    async fn shutdown_joins_a_bounded_active_effect_and_clears_the_slot() {
        let mut supervisor = Supervisor::default();
        supervisor
            .start(Request::Delay {
                duration: Duration::from_millis(5),
                origin: Origin::Slash,
            })
            .unwrap();
        supervisor.shutdown().await;
        assert!(!supervisor.is_active());
        assert_eq!(supervisor.label(), None);
    }

    #[tokio::test]
    async fn control_cancel_interrupts_eagerly_and_waits_for_authoritative_settlement() {
        let mut supervisor = Supervisor::default();
        let (control, mut requests) = tokio::sync::mpsc::channel(1);
        let interrupt = Arc::new(AtomicBool::new(false));
        supervisor
            .start(Request::Control {
                sender: control,
                control: crate::app_server::Control::Side(crate::app_server::SideRequest::Status),
                interrupt: interrupt.clone(),
                kind: ControlKind::Side,
            })
            .unwrap();

        let request = requests.recv().await.expect("control was dispatched");
        assert!(supervisor.cancel());
        assert!(
            interrupt.load(Ordering::SeqCst),
            "the input path must not wait for the supervisor task to wake"
        );

        // The resident runtime owns terminal settlement and clears the standalone flag only after
        // its provider/Hook work has stopped. Model that ordering before sending its reply.
        interrupt.store(false, Ordering::SeqCst);
        request
            .reply
            .send(crate::app_server::ControlReply::Refused(
                "interrupted".into(),
            ))
            .unwrap();
        let event = supervisor.recv().await.expect("control terminal event");
        let completion = event.control.expect("typed control completion");
        assert!(completion.cancellation_requested);
        assert!(!interrupt.load(Ordering::SeqCst));
        assert!(!supervisor.is_active());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_kills_and_reaps_the_owned_process_before_returning() {
        let mut supervisor = Supervisor::default();
        let (started, pid) = tokio::sync::oneshot::channel();
        supervisor
            .start(Request::ProcessDelay {
                started,
                origin: Origin::Slash,
            })
            .unwrap();
        let pid = pid.await.unwrap();
        supervisor.shutdown().await;

        // SAFETY: signal 0 performs no mutation and only asks whether this exact PID still exists.
        let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(probe, -1, "shutdown returned with the helper process alive");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn direct_owner_drop_synchronously_reaps_the_registered_helper() {
        let mut supervisor = Supervisor::default();
        let (started, pid) = tokio::sync::oneshot::channel();
        supervisor
            .start(Request::ProcessDelay {
                started,
                origin: Origin::Viewer,
            })
            .unwrap();
        let pid = pid.await.unwrap();

        drop(supervisor);

        // SAFETY: signal 0 is a read-only liveness probe for the exact registered child pid.
        let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(probe, -1, "Supervisor::drop returned with its helper alive");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_early_tui_error_class_crosses_the_same_reaping_boundary() {
        for stage in ["draw", "input", "editor", "dispatch"] {
            let mut supervisor = Supervisor::default();
            let (started, pid) = tokio::sync::oneshot::channel();
            supervisor
                .start(Request::ProcessDelay {
                    started,
                    origin: Origin::Viewer,
                })
                .unwrap();
            let pid = pid.await.unwrap();
            let outcome: Result<(), &str> = Err(stage);
            assert_eq!(supervisor.finish(outcome).await, Err(stage));

            // SAFETY: signal 0 is a read-only liveness probe for the exact child PID.
            let probe = unsafe { libc::kill(pid as libc::pid_t, 0) };
            assert_eq!(probe, -1, "{stage} returned with an effect helper alive");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }
}
