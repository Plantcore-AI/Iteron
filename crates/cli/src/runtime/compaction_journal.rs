//! Actual compaction publication boundary and its session/submission lifetime state. A candidate
//! becomes eligible for transcript replacement only after the real retained seed is synced.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::context_preparation_events::ContextPreparationEvents;
use super::turn_publication::TurnPublicationOwner;
use iteron_ctx::{CompactionPlan, CompactionPolicy, ContextLedgerStore, RequestEstimator};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, LifecyclePayload, Message, Seq, ToolSpec, TurnId};
use iteron_record::{RecordError, Rollout};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Default)]
pub(super) struct CompactionStateOwner {
    failed_closed: bool,
    compacted_in_submission: bool,
    last_committed_turn: Option<u64>,
}
impl CompactionStateOwner {
    pub(super) fn failed_closed(&self) -> bool {
        self.failed_closed
    }
    pub(super) fn close(&mut self) {
        self.failed_closed = true;
    }
    pub(super) fn begin_submission(&mut self) {
        self.compacted_in_submission = false;
    }
    pub(super) fn compacted(&self) -> bool {
        self.compacted_in_submission
    }
    pub(super) fn last_committed_turn(&self) -> Option<u64> {
        self.last_committed_turn
    }
    pub(super) fn restore(&mut self, last: Option<u64>) {
        self.compacted_in_submission = false;
        self.last_committed_turn = last;
    }
    fn committed(&mut self, turn: TurnId) {
        self.compacted_in_submission = true;
        self.last_committed_turn = Some(u64::from(turn.0));
    }
}

pub(super) struct CompactionCommitReceipt {
    sequence: Seq,
    summarized: usize,
    submitted_summary_sha256: [u8; 32],
}
impl CompactionCommitReceipt {
    pub(super) fn matches(&self, summarized: usize, digest: &[u8; 32]) -> bool {
        self.sequence != Seq::ZERO
            && self.summarized == summarized
            && &self.submitted_summary_sha256 == digest
    }
}

pub(super) struct CompactionCommitScope {
    pub(super) system: String,
    pub(super) tools: Vec<ToolSpec>,
    pub(super) policy: CompactionPolicy,
    pub(super) context_window: Option<u64>,
    pub(super) output_reserve: u32,
    pub(super) context_ledgers: ContextLedgerStore,
    pub(super) events: ContextPreparationEvents,
}
pub(super) struct CompactionCommitJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) publications: &'a mut TurnPublicationOwner,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}
impl CompactionCommitJournal<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit(
        &mut self,
        turn: TurnId,
        before_messages: &[Message],
        plan: &CompactionPlan,
        summary: &str,
        reason_code: &'static str,
        coverage_verified: bool,
        scope: CompactionCommitScope,
        estimator: &RequestEstimator,
        state: &mut CompactionStateOwner,
    ) -> Result<CompactionCommitReceipt, KernelError> {
        self.ensure_healthy()?;
        let rebuilt = iteron_ctx::CompactionPolicy::rebuild(plan, summary.to_owned());
        let before = before_messages.len();
        let after = rebuilt.len();
        let tools = &scope.tools;
        let system = &scope.system;
        let before_estimate = estimator.estimate_uncached(system, before_messages, tools);
        let after_estimate = estimator.estimate_uncached(system, &rebuilt, tools);
        let trigger = scope
            .policy
            .effective_trigger_tokens(scope.context_window, scope.output_reserve);
        let compaction = iteron_ctx::CompactionEvidence {
            trigger_tokens: u64::try_from(trigger).unwrap_or(u64::MAX),
            before_tokens: u64::try_from(before_estimate.total_tokens).unwrap_or(u64::MAX),
            after_tokens: u64::try_from(after_estimate.total_tokens).unwrap_or(u64::MAX),
            obligations_preserved: plan.obligations_preserved().saturating_add(
                if coverage_verified {
                    plan.obligations_lost()
                } else {
                    0
                },
            ),
            obligations_lost: if coverage_verified {
                0
            } else {
                plan.obligations_lost()
            },
            reason_code: reason_code.into(),
        };
        let mut ledger = iteron_ctx::ContextLedger::new(turn, estimator.tokenizer_identity());
        ledger.model_context_window = scope.context_window;
        let output_reserve = scope.output_reserve;
        ledger.usable_window = scope
            .context_window
            .map(|window| window.saturating_sub(u64::from(output_reserve)));
        ledger.output_reserved_tokens = u64::from(output_reserve);
        ledger.record_transform(iteron_ctx::ContextTransformEvidence {
            kind: iteron_ctx::ContextTransformKind::Compact,
            policy_id: "core/compaction@1".into(),
            input_segments: u32::try_from(before).unwrap_or(u32::MAX),
            output_segments: u32::try_from(after).unwrap_or(u32::MAX),
            input_bytes: before_messages.iter().fold(0u64, |total, message| {
                total.saturating_add(
                    u64::try_from(serde_json::to_vec(message).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                )
            }),
            output_bytes: rebuilt.iter().fold(0u64, |total, message| {
                total.saturating_add(
                    u64::try_from(serde_json::to_vec(message).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                )
            }),
            input_tokens: compaction.before_tokens,
            output_tokens: compaction.after_tokens,
            elapsed_us: 0,
        });
        ledger.compaction = Some(compaction.clone());
        let sequence = self.append_compaction(
            turn,
            EventKind::Compaction {
                messages: iteron_ctx::compaction_seed(plan, summary),
            },
        )?;
        scope.context_ledgers.publish(ledger);
        state.committed(turn);
        scope.events.emit_optional(
            "context.compaction.completed",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        scope.events.emit_optional(
            "context.segment.removed",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_range".into()),
                ..LifecyclePayload::default()
            },
        );
        scope.events.emit_optional(
            "context.segment.updated",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_summary".into()),
                ..LifecyclePayload::default()
            },
        );
        if compaction.obligations_preserved > 0 {
            scope.events.emit_optional(
                "context.obligation.preserved",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(compaction.obligations_preserved)),
                    reason_code: Some(reason_code.into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if compaction.obligations_lost > 0 {
            scope.events.emit_optional(
                "context.obligation.lost",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(compaction.obligations_lost)),
                    reason_code: Some("obligation_preservation_bound".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.notice(turn, format!("compacted {before} messages -> {after}"));
        Ok(CompactionCommitReceipt {
            sequence,
            summarized: plan.to_summarize.len(),
            submitted_summary_sha256: Sha256::digest(summary.as_bytes()).into(),
        })
    }
    fn ensure_healthy(&self) -> Result<(), KernelError> {
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "compaction record writer is unavailable",
            ))));
        }
        Ok(())
    }
    fn append_compaction(&mut self, turn: TurnId, kind: EventKind) -> Result<Seq, KernelError> {
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::Compaction) {
            *self.fault = None;
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected compaction append refusal",
            ))));
        }
        let mut event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let started = Instant::now();
        let committed = self.rollout.append(&event);
        self.ledger
            .record_fsync_latency_us(super::provider_accounting::elapsed_us(started));
        match committed {
            Ok(sequence) => {
                event.seq = sequence;
                self.publications.observe_committed(&event);
                Ok(sequence)
            }
            Err(error) => Err(self.record_error(error)),
        }
    }
    fn notice(&mut self, turn: TurnId, text: String) {
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::BestEffort) {
            *self.fault = None;
            let _ = self.record_error(RecordError::Io(std::io::Error::other(
                "injected compaction observation refusal",
            )));
            return;
        }
        let started = Instant::now();
        match self.rollout.queue_observation(Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Notice { text },
        }) {
            Ok(true) => self
                .ledger
                .record_fsync_latency_us(super::provider_accounting::elapsed_us(started)),
            Ok(false) => {}
            Err(error) => {
                let _ = self.record_error(error);
            }
        }
    }
    fn record_error(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
