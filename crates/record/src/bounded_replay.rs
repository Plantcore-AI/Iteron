//! Explicit aggregate work admission for readonly projections, including decrypted CAS payloads.
use crate::{Event, RecordError, RunId};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct ReplayReadLimits {
    pub physical_bytes: usize,
    pub hydrated_bytes: usize,
    pub events: usize,
}
impl ReplayReadLimits {
    pub(crate) fn budget(self) -> Result<ReplayReadBudget, RecordError> {
        if self.physical_bytes == 0
            || self.physical_bytes as u64 > crate::MAX_ROLLOUT_BYTES
            || self.hydrated_bytes == 0
            || self.hydrated_bytes as u64 > crate::MAX_ROLLOUT_BYTES
            || self.events == 0
            || self.events > crate::MAX_ROLLOUT_EVENTS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid bounded replay limits",
            )
            .into());
        }
        Ok(ReplayReadBudget {
            limits: self,
            physical: 0,
            hydrated: 0,
            events: 0,
        })
    }
}

pub(crate) struct ReplayReadBudget {
    limits: ReplayReadLimits,
    physical: usize,
    hydrated: usize,
    events: usize,
}
impl ReplayReadBudget {
    pub(crate) fn line(&mut self, bytes: usize, event: bool) -> Result<(), RecordError> {
        self.physical = self.physical.checked_add(bytes).ok_or_else(bound_error)?;
        self.hydrated = self.hydrated.checked_add(bytes).ok_or_else(bound_error)?;
        if event {
            self.events = self.events.checked_add(1).ok_or_else(bound_error)?;
        }
        if self.physical > self.limits.physical_bytes
            || self.hydrated > self.limits.hydrated_bytes
            || self.events > self.limits.events
        {
            return Err(bound_error());
        }
        Ok(())
    }
    pub(crate) fn remaining_content(&self) -> usize {
        self.limits.hydrated_bytes.saturating_sub(self.hydrated)
    }
    pub(crate) fn content(
        &mut self,
        bytes: usize,
    ) -> Result<(), crate::content_store::ContentStoreError> {
        self.hydrated = self.hydrated.saturating_add(bytes);
        if self.hydrated > self.limits.hydrated_bytes {
            return Err(crate::content_store::ContentStoreError::ContentTooLarge {
                max: self.limits.hydrated_bytes,
            });
        }
        Ok(())
    }
}
fn bound_error() -> RecordError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "bounded replay work admission exceeded",
    )
    .into()
}

/// Verifies a physical record with aggregate admission before retaining/decrypting its payloads.
/// This port preserves the ordinary chain/tenant/lineage gates and never repairs a journal.
pub fn replay_bounded(path: &Path, limits: ReplayReadLimits) -> Result<Vec<Event>, RecordError> {
    crate::session::bounded_physical_events(path, limits)
}

/// Verified metadata computed inside the same explicit aggregate budget, with no unbounded cache
/// fallback. Fork validation and hydration share one budget rather than restarting at each parent.
pub fn meta_bounded(
    runs: &Path,
    run: &RunId,
    limits: ReplayReadLimits,
) -> Result<crate::SessionMeta, RecordError> {
    crate::session::bounded_meta(runs, run, limits)
}

pub fn load_forked_scoped_bounded(
    runs: &Path,
    run: &RunId,
    limits: ReplayReadLimits,
) -> Result<Vec<crate::ScopedEvent>, RecordError> {
    crate::session::bounded_scoped(runs, run, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Rollout, TenantId};
    use iteron_protocol::{Effort, EventKind, Message, Seq, TurnId};

    #[test]
    fn small_physical_journal_cannot_bypass_aggregate_cas_hydration_budget() {
        let root = std::env::temp_dir().join(format!(
            "iteron-bounded-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let run = RunId("run-cas-budget".into());
        let mut rollout = Rollout::open(&root, &run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: root.to_string_lossy().into(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        for sequence in 1..=4 {
            rollout
                .append(&Event {
                    seq: Seq(sequence),
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text(format!(
                            "{sequence}{}",
                            "x".repeat(128 * 1024)
                        )),
                    },
                })
                .unwrap();
        }
        let path = rollout.path().to_owned();
        drop(rollout);
        assert!(std::fs::metadata(&path).unwrap().len() < 16 * 1024);
        let small = ReplayReadLimits {
            physical_bytes: 16 * 1024,
            hydrated_bytes: 256 * 1024,
            events: 8,
        };
        assert!(replay_bounded(&path, small).is_err());
        assert!(meta_bounded(&root, &run, small).is_err());
        assert!(load_forked_scoped_bounded(&root, &run, small).is_err());
        let admitted = ReplayReadLimits {
            hydrated_bytes: 1024 * 1024,
            ..small
        };
        let events = replay_bounded(&path, admitted).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[4].seq, Seq(4));
        assert!(
            replay_bounded(
                &path,
                ReplayReadLimits {
                    events: 4,
                    ..admitted
                }
            )
            .is_err()
        );
        assert!(
            replay_bounded(
                &path,
                ReplayReadLimits {
                    physical_bytes: 1,
                    ..admitted
                }
            )
            .is_err()
        );
        assert!(
            replay_bounded(
                &path,
                ReplayReadLimits {
                    hydrated_bytes: 0,
                    ..admitted
                }
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
