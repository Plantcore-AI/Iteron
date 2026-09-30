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
        && !blocks
            .iter()
            .any(|block| matches!(block, Block::ToolUse(_) | Block::ToolResult(_)))
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

fn recover(
    events: &[ScopedEvent],
    tenant: &TenantId,
    run: &RunId,
) -> Result<Vec<TurnPublicationEventV1>, KernelError> {
    let mut recovery = PublicationRecovery::new(run.clone());
    for scoped in events {
        if &scoped.tenant == tenant && &scoped.run_id == run {
            recovery.observe(&scoped.event)?;
        }
    }
    Ok(recovery.recent.into_iter().collect())
}

impl Agent {
    /// Recent facts from the record owner's bounded, verified canonical replay. Ancestor scopes
    /// stay distinct, and a partial/interrupted Message without an answer tag is never available.
    pub(crate) fn recovered_turn_publications_v1(
        &self,
    ) -> Result<Vec<TurnPublicationEventV1>, KernelError> {
        let events = replay_scoped_rollout(self.rollout.path())?;
        recover(&events, self.rollout.tenant(), self.rollout.run_id())
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
