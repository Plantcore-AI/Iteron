//! Record-sourced answer/finalization facts. Recovery retains one message witness and a bounded
//! recent window; it does not reinterpret presentation events or ancestor records as this run.

use super::{Agent, KernelError, route_validation::replay_scoped_rollout};
use iteron_protocol::turn_publication::{
    MAX_TURN_PUBLICATION_EVENTS, TURN_PUBLICATION_VERSION, TurnPublicationEventV1,
    TurnPublicationFactV1,
};
use iteron_protocol::{
    Block, Event, EventKind, Message, Outcome, Role, RunId, Seq, TenantId, TurnId,
};
use iteron_record::Rollout;
use iteron_record::ScopedEvent;
use std::collections::VecDeque;

#[cfg(test)]
#[path = "turn_publication_tests.rs"]
mod tests;

struct AnswerWitness {
    turn: TurnId,
    source: Seq,
    available: bool,
}

/// The only recovery authority is the record owner's verified, physically scoped projection.
/// A new answer tag must join an earlier eligible Message. Finalization joins an actual Done.
struct PublicationRecovery {
    run: RunId,
    witness: Option<AnswerWitness>,
    recent: VecDeque<TurnPublicationEventV1>,
}

/// Single retained publication projection. Recovery reads the bounded canonical record once on
/// construction/adoption. The hot path consumes actual committed receipts, never the whole WAL.
pub(super) struct TurnPublicationOwner {
    verified: Option<PublicationRecovery>,
}

impl TurnPublicationOwner {
    pub(super) fn for_rollout(rollout: &Rollout) -> Self {
        if rollout.next_sequence() == Seq::ZERO {
            return Self {
                verified: Some(PublicationRecovery::new(rollout.run_id().clone())),
            };
        }
        match replay_scoped_rollout(rollout.path()) {
            Ok(events) => Self::from_verified_scoped(&events, rollout.tenant(), rollout.run_id()),
            Err(_) => Self { verified: None },
        }
    }

    pub(super) fn from_verified_scoped(
        events: &[ScopedEvent],
        tenant: &TenantId,
        run: &RunId,
    ) -> Self {
        Self {
            verified: recover_state(events, tenant, run).ok(),
        }
    }

    pub(super) fn observe_committed(&mut self, event: &Event) {
        if self
            .verified
            .as_mut()
            .is_some_and(|owner| owner.observe(event).is_err())
        {
            // A presentation projection error cannot reverse a journal receipt. Recovery status
            // becomes unavailable rather than retaining a false verified prefix.
            self.verified = None;
        }
    }

    fn observations(&self) -> Result<Vec<TurnPublicationEventV1>, KernelError> {
        let owner = self.verified.as_ref().ok_or_else(invalid_recovery)?;
        Ok(owner.recent.iter().cloned().collect())
    }
}

impl PublicationRecovery {
    fn new(run: RunId) -> Self {
        Self {
            run,
            witness: None,
            recent: VecDeque::new(),
        }
    }

    fn observe(&mut self, event: &Event) -> Result<(), KernelError> {
        let fact = match &event.kind {
            EventKind::Message { message } => {
                self.witness = eligible_answer(message).then_some(AnswerWitness {
                    turn: event.turn,
                    source: event.seq,
                    available: false,
                });
                return Ok(());
            }
            EventKind::TurnPublicationV1 {
                fact: TurnPublicationFactV1::AnswerAvailable { message_seq },
            } => {
                let witness = self.witness.as_mut().ok_or_else(invalid_recovery)?;
                if witness.turn != event.turn
                    || witness.source.0 != *message_seq
                    || witness.available
                {
                    return Err(invalid_recovery());
                }
                witness.available = true;
                TurnPublicationFactV1::AnswerAvailable {
                    message_seq: *message_seq,
                }
            }
            // A standalone publication tag cannot manufacture a terminal. The live producer
            // projects the existing Done receipt without writing an additional terminal tag.
            EventKind::TurnPublicationV1 { .. } => return Err(invalid_recovery()),
            EventKind::Done { outcome } => {
                let outcome = recorded_outcome(outcome).ok_or_else(invalid_recovery)?;
                TurnPublicationFactV1::finalized(&outcome).map_err(|_| invalid_recovery())?
            }
            _ => return Ok(()),
        };
        let event = observation(&self.run, event.turn, event.seq, fact);
        event.validate().map_err(|_| invalid_recovery())?;
        if self.recent.len() == MAX_TURN_PUBLICATION_EVENTS {
            self.recent.pop_front();
        }
        self.recent.push_back(event);
        Ok(())
    }
}

fn eligible_answer(message: &Message) -> bool {
    message.role == Role::Assistant && eligible_answer_blocks(&message.content)
}

fn eligible_answer_blocks(blocks: &[Block]) -> bool {
    blocks
        .iter()
        .any(|block| matches!(block, Block::Text { text } if !text.trim().is_empty()))
        && !blocks.iter().any(|block| {
            matches!(
                block,
                Block::ToolUse(_) | Block::ToolResult(_) | Block::ToolImage(_)
            )
        })
}

fn recorded_outcome(outcome: &str) -> Option<Outcome> {
    // This is the closed canonical Done vocabulary, not free text from a UiEvent or socket frame.
    Some(match outcome {
        "Done" => Outcome::Done,
        "Drained" => Outcome::Drained,
        "Interrupted" => Outcome::Interrupted,
        "Stuck" => Outcome::Stuck,
        "HarnessError" => Outcome::HarnessError,
        "BudgetExhausted(\"max_turns\")" => Outcome::BudgetExhausted("max_turns"),
        "BudgetExhausted(\"max_tokens\")" => Outcome::BudgetExhausted("max_tokens"),
        "BudgetExhausted(\"max_usd\")" => Outcome::BudgetExhausted("max_usd"),
        "BudgetExhausted(\"max_wall_secs\")" => Outcome::BudgetExhausted("max_wall_secs"),
        "BudgetExhausted(\"verify_attempts\")" => Outcome::BudgetExhausted("verify_attempts"),
        _ => return None,
    })
}

fn observation(
    run: &RunId,
    turn: TurnId,
    source: Seq,
    fact: TurnPublicationFactV1,
) -> TurnPublicationEventV1 {
    TurnPublicationEventV1 {
        contract_version: TURN_PUBLICATION_VERSION,
        run_id: run.clone(),
        turn_id: turn,
        source_seq: source.0,
        fact,
    }
}

fn invalid_recovery() -> KernelError {
    KernelError::ContextResolution("turn publication record provenance is unavailable".into())
}

fn recover_state(
    events: &[ScopedEvent],
    tenant: &TenantId,
    run: &RunId,
) -> Result<PublicationRecovery, KernelError> {
    let mut recovery = PublicationRecovery::new(run.clone());
    for scoped in events {
        if &scoped.tenant == tenant && &scoped.run_id == run {
            recovery.observe(&scoped.event)?;
        }
    }
    Ok(recovery)
}

#[cfg(test)]
fn recover(
    events: &[ScopedEvent],
    tenant: &TenantId,
    run: &RunId,
) -> Result<Vec<TurnPublicationEventV1>, KernelError> {
    Ok(recover_state(events, tenant, run)?
        .recent
        .into_iter()
        .collect())
}

impl Agent {
    /// Recent facts from the retained record projection. No IO or unbounded historical fold is
    /// performed on completion/read; constructor/adoption recovery preserves physical scope.
    pub(crate) fn recovered_turn_publications_v1(
        &self,
    ) -> Result<Vec<TurnPublicationEventV1>, KernelError> {
        self.turn_publications.observations()
    }

    /// Called only by the actual non-tool EndTurn branch after steering/verification decisions.
    /// The working transcript and source sequence advance together only after Message fsync.
    pub(super) fn publish_available_answer(
        &mut self,
        turn: TurnId,
        blocks: &[Block],
    ) -> Result<(), KernelError> {
        if !eligible_answer_blocks(blocks) {
            return Ok(());
        }
        let message_seq = self.last_assistant_source.ok_or_else(invalid_recovery)?.0;
        let fact = TurnPublicationFactV1::AnswerAvailable { message_seq };
        fact.validate().map_err(|_| invalid_recovery())?;
        let source =
            self.emit_durable_seq(turn, EventKind::TurnPublicationV1 { fact: fact.clone() })?;
        let event = observation(self.rollout.run_id(), turn, source, fact);
        event.validate().map_err(|_| invalid_recovery())?;
        self.turn_publication_ui(event);
        Ok(())
    }

    /// The caller owns the actual confirmed Idle/Done batch receipt. Presentation refusal cannot
    /// reverse that committed terminal; recovery can still read the original Done sequence.
    pub(super) fn publish_finalized_turn(
        &self,
        turn: TurnId,
        source: Seq,
        fact: TurnPublicationFactV1,
    ) {
        self.turn_publication_ui(observation(self.rollout.run_id(), turn, source, fact));
    }
}
