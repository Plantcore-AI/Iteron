//! Single-flight supervision for transcript clipboard and export effects.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::block;

use super::{clipboard, transcript_export};

const EXPORT_DEADLINE: Duration = Duration::from_secs(5);
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
}

impl Request {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Copy { .. } => "copy",
            Self::Export { .. } => "export",
            #[cfg(test)]
            Self::Delay { .. } => "test effect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Busy;

pub(crate) struct Supervisor {
    sender: tokio::sync::mpsc::Sender<Event>,
    receiver: tokio::sync::mpsc::Receiver<Event>,
    task: Option<tokio::task::JoinHandle<()>>,
    label: Option<&'static str>,
}

impl Default for Supervisor {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        Self {
            sender,
            receiver,
            task: None,
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
        self.label = Some(label);
        self.task = Some(tokio::spawn(run(request, sender)));
        Ok(())
    }

    pub(crate) async fn recv(&mut self) -> Option<Event> {
        let event = self.receiver.recv().await?;
        if event.final_slot {
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
            self.label = None;
        }
        Some(event)
    }

    pub(crate) async fn shutdown(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        if tokio::time::timeout(SHUTDOWN_DEADLINE, &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
        }
        self.label = None;
        while self.receiver.try_recv().is_ok() {}
    }
}

async fn send(sender: &tokio::sync::mpsc::Sender<Event>, event: Event) {
    let _ = sender.send(event).await;
}

async fn run(request: Request, sender: tokio::sync::mpsc::Sender<Event>) {
    match request {
        Request::Copy {
            text,
            subject,
            origin,
        } => {
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
            let mut worker = tokio::task::spawn_blocking(move || {
                transcript_export::export(
                    &workspace,
                    &blocks,
                    selected_ids.as_deref(),
                    &requested,
                    collision,
                )
            });
            match tokio::time::timeout(EXPORT_DEADLINE, &mut worker).await {
                Ok(joined) => {
                    let (level, message) = match joined {
                        Ok(Ok(path)) => (Level::Ok, format!("exported -> {}", path.display())),
                        Ok(Err(error)) => (Level::Warn, format!("export failed: {error}")),
                        Err(_) => (Level::Warn, "export worker failed before completion".into()),
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
                Err(_) => {
                    send(
                        &sender,
                        Event {
                            origin,
                            level: Level::Warn,
                            message: "export exceeded 5s; outcome unknown; worker cleanup pending"
                                .into(),
                            final_slot: false,
                        },
                    )
                    .await;
                    let _ = worker.await;
                    send(
                        &sender,
                        Event {
                            origin,
                            level: Level::Warn,
                            message:
                                "export worker settled after deadline; outcome remains unknown"
                                    .into(),
                            final_slot: true,
                        },
                    )
                    .await;
                }
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
            biased;
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
}
