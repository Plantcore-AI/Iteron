//! Single-flight supervision for transcript clipboard and export effects.
//!
//! Export is isolated in a separately killable instance of the current executable. The child gets
//! a bounded binary request on stdin, an empty environment, and no terminal handles. Cancellation,
//! deadline, and every post-spawn error explicitly kill and reap it; the Linux child also requests
//! `SIGKILL` if its parent dies. This keeps a blocked filesystem syscall out of the TUI process and
//! prevents a detached blocking thread from publishing after frontend shutdown returns.

use std::path::PathBuf;
#[cfg(all(test, unix))]
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use crate::block;

use super::{clipboard, transcript_export};

mod worker;
use worker::WorkerRun;
pub(crate) use worker::{worker_main, worker_requested};

const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(7);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Viewer,
    Slash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Ok,
    Warn,
}

#[derive(Debug)]
pub(crate) struct Event {
    pub(crate) origin: Origin,
    pub(crate) level: Level,
    pub(crate) message: String,
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
            #[cfg(test)]
            Self::Delay { .. } => "test effect",
            #[cfg(all(test, unix))]
            Self::ProcessDelay { .. } => "test process",
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
    label: Option<&'static str>,
}

impl Default for Supervisor {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        Self {
            sender,
            receiver,
            task: None,
            cancel: None,
            label: None,
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
        let sender = self.sender.clone();
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        self.label = Some(label);
        self.cancel = Some(cancel);
        self.task = Some(tokio::spawn(run(request, sender, cancelled)));
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Option<Event> {
        let event = self.receiver.recv().await?;
        if event.final_slot {
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            self.cancel = None;
            self.label = None;
        }
        Some(event)
    }

    /// Cancel the active effect and wait for its owned process to be reaped. The outer task is
    /// aborted only after the effect-specific bound has already expired; child processes are also
    /// `kill_on_drop` and, on Linux, carry a parent-death signal as a final containment layer.
    pub(crate) async fn shutdown(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(true);
        }
        if tokio::time::timeout(SHUTDOWN_DEADLINE, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = tokio::time::timeout(worker::REAP_DEADLINE, task).await;
        }
        self.label = None;
        while self.receiver.try_recv().is_ok() {}
    }

    /// Finally-style boundary used by the TUI: preserve its exact normal/error outcome only after
    /// all owned effect work has settled.
    pub(crate) async fn finish<T>(&mut self, outcome: T) -> T {
        self.shutdown().await;
        outcome
    }
}

async fn send(sender: &tokio::sync::mpsc::Sender<Event>, event: Event) {
    let _ = sender.send(event).await;
}

async fn run(
    request: Request,
    sender: tokio::sync::mpsc::Sender<Event>,
    mut cancelled: tokio::sync::watch::Receiver<bool>,
) {
    match request {
        Request::Copy {
            text,
            subject,
            origin,
        } => {
            // Clipboard owns its own three-second deadline plus explicit kill-and-reap path. Let it
            // settle instead of dropping that cleanup future when frontend shutdown is requested.
            let (level, message) = match clipboard::copy_text(&text).await {
                Ok(adapter) => (Level::Ok, format!("copied {subject} via {adapter}")),
                Err(error) => (Level::Warn, format!("copy failed: {error}")),
            };
            send(
                &sender,
                Event {
                    origin,
                    level,
                    message,
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
                            level: Level::Warn,
                            message: format!("export failed: {error}"),
                            final_slot: true,
                        },
                    )
                    .await;
                    return;
                }
            };
            match worker::run_export_worker(
                &workspace,
                &requested,
                collision,
                &bytes,
                &mut cancelled,
            )
            .await
            {
                WorkerRun::Completed(Ok(path)) => {
                    send(
                        &sender,
                        Event {
                            origin,
                            level: Level::Ok,
                            message: format!("exported -> {}", path.display()),
                            final_slot: true,
                        },
                    )
                    .await;
                }
                WorkerRun::Completed(Err(error)) => {
                    send(
                        &sender,
                        Event {
                            origin,
                            level: Level::Warn,
                            message: format!("export failed: {error}"),
                            final_slot: true,
                        },
                    )
                    .await;
                }
                WorkerRun::TimedOut { reaped } => {
                    send(
                        &sender,
                        Event {
                            origin,
                            level: Level::Warn,
                            message: format!(
                                "export exceeded 5s; outcome unknown; worker {}",
                                if reaped {
                                    "was killed and reaped"
                                } else {
                                    "could not be reaped within 1s"
                                }
                            ),
                            final_slot: true,
                        },
                    )
                    .await;
                }
                WorkerRun::Cancelled => {}
            }
        }
        #[cfg(test)]
        Request::Delay { duration, origin } => {
            tokio::time::sleep(duration).await;
            send(
                &sender,
                Event {
                    origin,
                    level: Level::Ok,
                    message: "test effect complete".into(),
                    final_slot: true,
                },
            )
            .await;
        }
        #[cfg(all(test, unix))]
        Request::ProcessDelay { started, origin } => {
            run_test_process(started, origin, &sender, &mut cancelled).await;
        }
    }
}

#[cfg(all(test, unix))]
async fn run_test_process(
    started: tokio::sync::oneshot::Sender<u32>,
    origin: Origin,
    sender: &tokio::sync::mpsc::Sender<Event>,
    cancelled_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    let mut child = match tokio::process::Command::new("/bin/sleep")
        .arg("30")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
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
                level: Level::Ok,
                message: "test process complete".into(),
                final_slot: true,
            }).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
