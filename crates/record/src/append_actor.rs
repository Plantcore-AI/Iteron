//! Bounded per-run append batching.

use super::{
    Barrier, ChainLine, MAX_ROLLOUT_BYTES, MAX_ROLLOUT_EVENTS, MAX_ROLLOUT_PHYSICAL_LINES,
    RecordError, Rollout, SessionProjectionState, barrier_for, content_store,
    ensure_record_line_size, ensure_rollout_size, hash_line, policy_bundle, redact, sync_line,
    validate_event_bounds, validate_terminal_identity,
};
use iteron_protocol::{Event, EventKind, RunId, Seq};
use std::fs::File;
use std::io::Write as _;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};

const DEFAULT_APPEND_QUEUE: usize = 64;
const HARD_MAX_APPEND_QUEUE: usize = 1_024;
const MAX_APPEND_BATCH_EVENTS: usize = 256;

fn closes_session_projection(kind: &EventKind) -> bool {
    matches!(kind, EventKind::TurnEnd { .. } | EventKind::Done { .. })
        || matches!(
            kind,
            EventKind::PolicyOutcome { evidence }
                if evidence.scope == iteron_protocol::PolicyOutcomeScope::Run
        )
}

fn append_batch_limit() -> usize {
    iteron_tunables::param_usize(
        "record.append_actor.max_append_batch_events",
        MAX_APPEND_BATCH_EVENTS,
    )
    .clamp(1, MAX_APPEND_BATCH_EVENTS)
}

fn append_queue_capacity() -> usize {
    let hard = iteron_tunables::param_usize(
        "record.append_actor.hard_max_append_queue",
        HARD_MAX_APPEND_QUEUE,
    )
    .clamp(1, HARD_MAX_APPEND_QUEUE);
    iteron_tunables::param_usize(
        "record.append_actor.default_append_queue",
        DEFAULT_APPEND_QUEUE,
    )
    .clamp(1, hard)
}

pub(crate) struct PreparedAppend {
    pub(crate) event: Event,
    pub(crate) seq: Seq,
    pub(crate) hash: String,
    pub(crate) line: String,
}

struct WriteBatch {
    expected_bytes: u64,
    bytes: Vec<u8>,
    barrier: Barrier,
    #[cfg(test)]
    inject_sync_fault: bool,
}

impl Rollout {
    /// Append one semantic batch with exactly one durability barrier. At most one TurnEnd/Done may
    /// occur and it must be the final event, so a caller cannot accidentally acknowledge two
    /// semantic boundaries with one device flush. On any write/barrier failure the writer remains
    /// poisoned and recovery proceeds through the ordinary reopen/tail-scan path.
    pub fn append_batch(&mut self, events: &[Event]) -> Result<Vec<Seq>, RecordError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let max = append_batch_limit();
        if events.len() > max {
            return Err(RecordError::InvalidAppendBatch {
                reason: "event count exceeds the bounded batch limit",
            });
        }
        let boundaries = events
            .iter()
            .enumerate()
            .filter(|(_, event)| {
                matches!(
                    &event.kind,
                    EventKind::TurnEnd { .. } | EventKind::Done { .. }
                )
            })
            .collect::<Vec<_>>();
        if boundaries.len() > 1
            || boundaries
                .first()
                .is_some_and(|(index, _)| *index + 1 != events.len())
        {
            return Err(RecordError::InvalidAppendBatch {
                reason: "a semantic boundary must be unique and final",
            });
        }
        if self.poisoned {
            return Err(RecordError::WriterPoisoned);
        }
        let event_limit =
            iteron_tunables::param_integer("record.lib.max_rollout_events", MAX_ROLLOUT_EVENTS);
        let physical_limit = iteron_tunables::param_integer(
            "record.lib.max_rollout_physical_lines",
            MAX_ROLLOUT_PHYSICAL_LINES,
        );
        if self.event_count.saturating_add(events.len()) > event_limit {
            return Err(RecordError::TooManyEvents { max: event_limit });
        }
        if self.physical_line_count.saturating_add(events.len()) > physical_limit {
            return Err(RecordError::TooManyRecordLines {
                max: physical_limit,
            });
        }
        let current_bytes = self.durable_bytes;
        let runs_dir = self.path.parent().ok_or_else(|| {
            RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rollout path has no runs directory",
            ))
        })?;
        let mut next_seq = self.seq;
        let mut next_hash = self.last_hash.clone();
        let mut next_bytes = current_bytes;
        let mut prepared = Vec::with_capacity(events.len());
        for source in events {
            if matches!(&source.kind, EventKind::PolicyBundleSnapshot { .. }) && next_seq != Seq(2)
            {
                return Err(policy_bundle::PolicyBundleCheckpointError::GenesisOrder(
                    "policy checkpoint must be physical sequence two",
                )
                .into());
            }
            source
                .kind
                .validate_compatibility_tag()
                .map_err(|reason| RecordError::InvalidEventSchema { reason })?;
            validate_terminal_identity(&source.kind)
                .map_err(|reason| RecordError::InvalidEventSchema { reason })?;
            validate_event_bounds(source)?;
            let mut event = redact::redact_event(source);
            event.seq = next_seq;
            validate_event_bounds(&event)?;
            let mut payload = serde_json::to_value(&event)?;
            content_store::externalize_event_payload(
                runs_dir,
                &self.tenant,
                &self.run,
                next_seq,
                &mut payload,
            )?;
            let hash = hash_line(&next_hash, next_seq.0, &payload);
            let line = ChainLine {
                seq: next_seq.0,
                tenant: self.tenant.0.clone(),
                prev: next_hash,
                hash: hash.clone(),
                ts_us: Some(
                    u64::try_from(self.opened_at.elapsed().as_micros()).unwrap_or(u64::MAX),
                ),
                payload,
            };
            let mut line = serde_json::to_string(&line)?;
            line.push('\n');
            ensure_record_line_size(line.len())?;
            next_bytes =
                next_bytes
                    .checked_add(line.len() as u64)
                    .ok_or(RecordError::RolloutTooLarge {
                        bytes: u64::MAX,
                        max: iteron_tunables::param_integer(
                            "record.lib.max_rollout_bytes",
                            MAX_ROLLOUT_BYTES,
                        ),
                    })?;
            ensure_rollout_size(next_bytes)?;
            prepared.push(PreparedAppend {
                event,
                seq: next_seq,
                hash: hash.clone(),
                line,
            });
            next_hash = hash;
            next_seq = next_seq.next();
        }

        self.commit_prepared(prepared, current_bytes, next_hash, next_seq, next_bytes)
    }

    /// Write one prepared batch under exactly one durability barrier and advance the descriptor's
    /// committed state.
    ///
    /// Shared with `Rollout::append`. The single-event path prepares its own line rather than
    /// calling `append_batch`, because the binding `Event -> serde_json::to_value ->
    /// ChainLine.payload` is a frozen surface that has to be readable in the method that owns it.
    /// Preparation is therefore stated twice; committing is not, so there remains exactly one place
    /// where bytes reach the device and exactly one place that advances seq, hash, and the
    /// projection.
    pub(crate) fn commit_prepared(
        &mut self,
        prepared: Vec<PreparedAppend>,
        current_bytes: u64,
        next_hash: String,
        next_seq: Seq,
        next_bytes: u64,
    ) -> Result<Vec<Seq>, RecordError> {
        self.poisoned = true;
        let batch_bytes = prepared
            .iter()
            .map(|append| append.line.len())
            .sum::<usize>();
        let mut batch = Vec::with_capacity(batch_bytes);
        for append in &prepared {
            batch.extend_from_slice(append.line.as_bytes());
        }
        let barrier = prepared
            .last()
            .map(|append| barrier_for(&append.event.kind))
            .unwrap_or(Barrier::Line);
        let ticket = self
            .append_actor
            .enqueue(WriteBatch {
                expected_bytes: current_bytes,
                bytes: batch,
                barrier,
                #[cfg(test)]
                inject_sync_fault: super::take_append_sync_fault(),
            })
            .map_err(RecordError::from)?;
        ticket.wait()?;
        #[cfg(test)]
        self.observe_barrier(barrier);

        self.last_hash = next_hash;
        self.seq = next_seq;
        self.event_count = self.event_count.saturating_add(prepared.len());
        self.physical_line_count = self.physical_line_count.saturating_add(prepared.len());
        self.durable_bytes = next_bytes;
        self.poisoned = false;
        let projection_was_ready =
            matches!(self.session_projection, SessionProjectionState::Ready(_));
        if projection_was_ready {
            for append in &prepared {
                if let SessionProjectionState::Ready(projection) = &mut self.session_projection
                    && projection
                        .observe_committed(&append.event, append.seq, &append.hash)
                        .is_err()
                {
                    self.session_projection = SessionProjectionState::Disabled;
                    break;
                }
            }
        } else if prepared
            .iter()
            .any(|append| matches!(&append.event.kind, EventKind::TurnStart))
        {
            let _ = self.ensure_session_projection();
        }
        if prepared
            .iter()
            .any(|append| closes_session_projection(&append.event.kind))
        {
            // The rollout batch and its barrier are already durable. Refresh only the rebuildable
            // projection now, so a just-finished run is immediately visible through the bounded
            // session index with a tail that matches this boundary. The run-scoped policy terminal
            // is also a boundary: AppServer appends it during session shutdown, after `Done` and
            // after the runtime's ordinary refresh. Projection failure must not turn an
            // acknowledged authoritative append into a reported record failure.
            let _ = self.refresh_session_cache();
        }
        Ok(prepared.into_iter().map(|append| append.seq).collect())
    }
}

enum Command {
    Write {
        batch: WriteBatch,
        reply: std::sync::mpsc::Sender<Result<(), RecordError>>,
    },
    Shutdown(std::sync::mpsc::Sender<()>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppendActorError {
    #[error("rollout append worker could not start: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("rollout append queue is closed")]
    QueueClosed,
    #[error("rollout append actor panicked")]
    WorkerPanicked,
    #[error("rollout append queue is full")]
    QueueFull,
}

impl From<AppendActorError> for RecordError {
    fn from(error: AppendActorError) -> Self {
        Self::Io(std::io::Error::other(error))
    }
}

struct AppendTicket {
    reply: Receiver<Result<(), RecordError>>,
}

impl AppendTicket {
    fn wait(self) -> Result<(), RecordError> {
        self.reply
            .recv()
            .unwrap_or(Err(RecordError::WriterPoisoned))
    }
}

/// One bounded worker owns the only append descriptor for one live `Rollout`. The public façade
/// prepares and validates a whole semantic batch before enqueueing it; the worker performs its one
/// write and one durability barrier, then returns the authoritative commit receipt.
pub(crate) struct RolloutAppendActor {
    sender: SyncSender<Command>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RolloutAppendActor {
    pub(super) fn spawn(mut file: File, run: &RunId) -> Result<Self, AppendActorError> {
        let capacity = append_queue_capacity();
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        let name = format!("iteron-record-{}", run.0);
        let worker = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                run_worker(&mut file, receiver);
            })
            .map_err(AppendActorError::Spawn)?;
        Ok(Self {
            sender,
            worker: Some(worker),
        })
    }

    fn enqueue(&self, batch: WriteBatch) -> Result<AppendTicket, AppendActorError> {
        let (reply, receiver) = std::sync::mpsc::channel();
        match self.sender.try_send(Command::Write { batch, reply }) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                return Err(AppendActorError::QueueFull);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(AppendActorError::QueueClosed);
            }
        }
        Ok(AppendTicket { reply: receiver })
    }

    fn stop(&mut self) -> Result<(), AppendActorError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        let (reply, receiver) = std::sync::mpsc::channel();
        let command_sent = self.sender.send(Command::Shutdown(reply)).is_ok();
        let acknowledged = command_sent && receiver.recv().is_ok();
        let joined = worker.join().is_ok();
        if !joined {
            Err(AppendActorError::WorkerPanicked)
        } else if !command_sent || !acknowledged {
            Err(AppendActorError::QueueClosed)
        } else {
            Ok(())
        }
    }
}

fn run_worker(file: &mut File, receiver: Receiver<Command>) -> usize {
    let mut poisoned = false;
    let mut pending = None;
    let mut barriers = 0usize;
    loop {
        let command = match pending.take() {
            Some(command) => command,
            None => match receiver.recv() {
                Ok(command) => command,
                Err(_) => break,
            },
        };
        match command {
            Command::Write { batch, reply } => {
                let mut writes = vec![(batch, reply)];
                while writes.len() < append_batch_limit()
                    && writes.last().is_some_and(|(batch, _)| {
                        batch.barrier != Barrier::Turn && !batch.injects_sync_fault()
                    })
                {
                    match receiver.try_recv() {
                        Ok(Command::Write { batch, reply }) => {
                            // A fault-injection command is kept isolated so its rollback receipt
                            // cannot ambiguously cover a neighbouring caller.
                            if batch.injects_sync_fault() {
                                pending = Some(Command::Write { batch, reply });
                                break;
                            }
                            writes.push((batch, reply));
                        }
                        Ok(command @ Command::Shutdown(_)) => {
                            pending = Some(command);
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => break,
                    }
                }
                let result = if poisoned {
                    Err(RecordError::WriterPoisoned)
                } else {
                    poisoned = true;
                    let result = write_queued_batches(file, &writes);
                    if result.is_ok() {
                        poisoned = false;
                        barriers = barriers.saturating_add(1);
                    }
                    result
                };
                let failure = result.as_ref().err().map(ToString::to_string);
                for (_, reply) in writes {
                    let receipt = match &failure {
                        None => Ok(()),
                        Some(message) => {
                            Err(RecordError::Io(std::io::Error::other(message.clone())))
                        }
                    };
                    let _ = reply.send(receipt);
                }
            }
            Command::Shutdown(reply) => {
                let _ = file.unlock();
                let _ = reply.send(());
                break;
            }
        }
    }
    barriers
}

impl WriteBatch {
    fn injects_sync_fault(&self) -> bool {
        #[cfg(test)]
        {
            self.inject_sync_fault
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

impl Drop for RolloutAppendActor {
    fn drop(&mut self) {
        // Releasing a Rollout is the writer-ownership boundary used by resume/adopt. Join the
        // worker here so returning from drop means the descriptor and its exclusive lock are
        // actually gone; detaching would race the next owner opening the same run.
        let _ = self.stop();
    }
}

fn write_queued_batches(
    file: &mut File,
    batches: &[(WriteBatch, std::sync::mpsc::Sender<Result<(), RecordError>>)],
) -> Result<(), RecordError> {
    let mut expected = file.metadata()?.len();
    let mut barrier = Barrier::Line;
    for (batch, _) in batches {
        if expected != batch.expected_bytes {
            return Err(RecordError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "rollout length changed outside the active writer",
            )));
        }
        file.write_all(&batch.bytes)?;
        #[cfg(test)]
        if batch.inject_sync_fault {
            super::inject_append_sync_fault(file, batch.expected_bytes)?;
        }
        expected = expected
            .checked_add(batch.bytes.len() as u64)
            .ok_or_else(|| RecordError::Io(std::io::Error::other("rollout length overflow")))?;
        barrier = batch.barrier;
    }
    match barrier {
        Barrier::Line => sync_line(file)?,
        Barrier::Turn => file.sync_data()?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay;
    use iteron_protocol::{TenantId, TurnId};

    #[test]
    fn adjacent_actor_tickets_share_one_ordered_durability_barrier() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-record-actor-coalesce-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("coalesced.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        let (first_reply, first) = std::sync::mpsc::channel();
        let (second_reply, second) = std::sync::mpsc::channel();
        sender
            .try_send(Command::Write {
                batch: WriteBatch {
                    expected_bytes: 0,
                    bytes: b"a\n".to_vec(),
                    barrier: Barrier::Line,
                    inject_sync_fault: false,
                },
                reply: first_reply,
            })
            .unwrap();
        sender
            .try_send(Command::Write {
                batch: WriteBatch {
                    expected_bytes: 2,
                    bytes: b"b\n".to_vec(),
                    barrier: Barrier::Line,
                    inject_sync_fault: false,
                },
                reply: second_reply,
            })
            .unwrap();
        drop(sender);

        assert_eq!(run_worker(&mut file, receiver), 1);
        first.recv().unwrap().unwrap();
        second.recv().unwrap().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"a\nb\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn semantic_batch_uses_one_barrier_and_replays_every_event() {
        let dir = std::env::temp_dir().join(format!("iteron-record-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let run = RunId("batch".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        let events = vec![
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            },
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnEnd {
                    usage: iteron_protocol::Usage::default(),
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            },
        ];
        assert_eq!(rollout.append_batch(&events).unwrap(), vec![Seq(0), Seq(1)]);
        assert_eq!(rollout.barriers_taken(), (0, 1));
        drop(rollout);
        assert_eq!(replay(&dir.join("batch.jsonl")).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn terminal_must_be_unique_and_final_before_writer_enqueue() {
        let dir = std::env::temp_dir().join(format!(
            "iteron-record-terminal-authority-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let run = RunId("terminal-authority".into());
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        let events = [
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Done {
                    outcome: "complete".into(),
                },
            },
            Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Notice {
                    text: "late".into(),
                },
            },
        ];
        assert!(matches!(
            rollout.append_batch(&events),
            Err(RecordError::InvalidAppendBatch { .. })
        ));
        assert_eq!(rollout.next_sequence(), Seq::ZERO);
        assert_eq!(rollout.barriers_taken(), (0, 0));
        drop(rollout);
        assert!(
            replay(&dir.join("terminal-authority.jsonl"))
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn embedded_actor_is_the_unique_writer_and_drop_releases_its_lock() {
        let dir =
            std::env::temp_dir().join(format!("iteron-record-actor-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let run = RunId("actor-lock".into());
        let tenant = TenantId::default();
        let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
        assert_eq!(
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Notice {
                        text: "owned".into(),
                    },
                })
                .unwrap(),
            Seq::ZERO
        );
        assert!(matches!(
            Rollout::open_existing(&dir, &run, tenant.clone()),
            Err(RecordError::WriterBusy { .. })
        ));

        // `Drop` joins the actor instead of detaching it: once it returns, resume immediately owns
        // the same descriptor lock and authoritative chain head.
        drop(rollout);
        let mut resumed = Rollout::open_existing(&dir, &run, tenant).unwrap();
        assert_eq!(resumed.next_sequence(), Seq(1));
        assert_eq!(
            resumed
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Notice {
                        text: "resumed".into(),
                    },
                })
                .unwrap(),
            Seq(1)
        );
        drop(resumed);
        assert_eq!(replay(&dir.join("actor-lock.jsonl")).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}
