//! Content-free answer and finalization observations with exact durable record provenance.
//!
//! These facts do not grant authority. An available answer does not claim a successful terminal,
//! completed maintenance, or delivery of every streamed byte. `turn_id` is the runtime provider
//! turn, distinct from the App Server's user-facing `ProductTurnId`.

use crate::{Outcome, RunId, SessionId, TurnId};
use serde::{Deserialize, Serialize};

pub const TURN_PUBLICATION_VERSION: u32 = 1;
pub const MAX_TURN_PUBLICATION_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnFinalOutcomeV1 {
    Done,
    Drained,
    BudgetExhausted,
    Interrupted,
    Stuck,
    HarnessError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TurnPublicationFactV1 {
    /// Only the actual final non-tool EndTurn producer may publish this after Message fsync.
    AnswerAvailable { message_seq: u64 },
    /// The source is the existing confirmed Done event, with no second terminal append.
    TurnFinalized {
        outcome: TurnFinalOutcomeV1,
        budget_limit: Option<String>,
    },
}

impl TurnPublicationFactV1 {
    /// Pure representation mapping. Calling this does not prove any durable terminal exists.
    pub fn finalized(outcome: &Outcome) -> Result<Self, &'static str> {
        let (outcome, budget_limit) = match outcome {
            Outcome::Done => (TurnFinalOutcomeV1::Done, None),
            Outcome::Drained => (TurnFinalOutcomeV1::Drained, None),
            Outcome::BudgetExhausted(limit) => {
                if !valid_budget_limit(limit) {
                    return Err("unsupported_budget_limit");
                }
                (
                    TurnFinalOutcomeV1::BudgetExhausted,
                    Some((*limit).to_owned()),
                )
            }
            Outcome::Interrupted => (TurnFinalOutcomeV1::Interrupted, None),
            Outcome::Stuck => (TurnFinalOutcomeV1::Stuck, None),
            Outcome::HarnessError => (TurnFinalOutcomeV1::HarnessError, None),
        };
        Ok(Self::TurnFinalized {
            outcome,
            budget_limit,
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::AnswerAvailable { message_seq } if *message_seq == 0 => {
                Err("invalid_message_source")
            }
            Self::AnswerAvailable { .. } => Ok(()),
            Self::TurnFinalized {
                outcome,
                budget_limit,
            } => match (outcome, budget_limit) {
                (TurnFinalOutcomeV1::BudgetExhausted, Some(limit)) if valid_budget_limit(limit) => {
                    Ok(())
                }
                (TurnFinalOutcomeV1::BudgetExhausted, _) => Err("invalid_budget_limit"),
                (_, None) => Ok(()),
                (_, Some(_)) => Err("unexpected_budget_limit"),
            },
        }
    }
}

fn valid_budget_limit(limit: &str) -> bool {
    matches!(
        limit,
        "max_turns" | "max_tokens" | "max_usd" | "max_wall_secs" | "verify_attempts"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnPublicationEventV1 {
    pub contract_version: u32,
    pub run_id: RunId,
    pub turn_id: TurnId,
    /// Actual committed AnswerAvailable event or existing Done event sequence in this run.
    pub source_seq: u64,
    pub fact: TurnPublicationFactV1,
}

impl TurnPublicationEventV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.contract_version != TURN_PUBLICATION_VERSION {
            return Err("publication_version_mismatch");
        }
        if self.run_id.0.is_empty()
            || self.run_id.0.len() > 200
            || self.run_id.0.chars().any(char::is_control)
        {
            return Err("invalid_publication_run");
        }
        if self.source_seq == 0 || self.turn_id.0 == 0 {
            return Err("invalid_publication_source");
        }
        self.fact.validate()?;
        if matches!(&self.fact, TurnPublicationFactV1::AnswerAvailable { message_seq } if *message_seq >= self.source_seq)
        {
            return Err("answer_precedes_message_commit");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationRecoveryV1 {
    /// Recovery facts came from the verified current-run record owner. Retention remains bounded.
    VerifiedRecord,
    /// No recovery port was installed, including unsealed test embeddings.
    LiveOnly,
    /// The record could not be safely recovered. Live observations are still individually sourced.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnPublicationSnapshotV1 {
    pub contract_version: u32,
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub recovery: PublicationRecoveryV1,
    /// Recent current-run facts, bounded to MAX_TURN_PUBLICATION_EVENTS. Not complete history.
    pub events: Vec<TurnPublicationEventV1>,
    pub resident_evictions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TurnPublicationReadV1 {
    Read { thread_id: SessionId },
}

impl TurnPublicationReadV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::Read { thread_id } => thread_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_requires_an_earlier_message_and_supported_version() {
        let mut event = TurnPublicationEventV1 {
            contract_version: TURN_PUBLICATION_VERSION,
            run_id: RunId("run".into()),
            turn_id: TurnId(2),
            source_seq: 8,
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 7 },
        };
        assert!(event.validate().is_ok());
        event.source_seq = 7;
        assert!(event.validate().is_err());
        event.source_seq = 8;
        event.contract_version = 2;
        assert!(event.validate().is_err());
    }

    #[test]
    fn finalization_uses_closed_owned_outcomes_and_budget_vocabulary() {
        for outcome in [
            Outcome::Done,
            Outcome::Drained,
            Outcome::Interrupted,
            Outcome::Stuck,
            Outcome::HarnessError,
            Outcome::BudgetExhausted("max_tokens"),
        ] {
            let fact = TurnPublicationFactV1::finalized(&outcome).unwrap();
            fact.validate().unwrap();
            let bytes = serde_json::to_vec(&fact).unwrap();
            let decoded: TurnPublicationFactV1 = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded, fact);
        }
        assert!(TurnPublicationFactV1::finalized(&Outcome::BudgetExhausted("future")).is_err());
        assert!(
            TurnPublicationFactV1::TurnFinalized {
                outcome: TurnFinalOutcomeV1::Done,
                budget_limit: Some("max_tokens".into())
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_value::<TurnPublicationFactV1>(serde_json::json!({
                "type":"turn_finalized", "outcome":"done", "budget_limit":null, "effects_known":true
            }))
            .is_err()
        );
    }

    #[test]
    fn old_reader_skips_new_answer_tag_without_changing_existing_done_bytes() {
        #[derive(Debug, Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum LegacyKind {
            Done {
                outcome: String,
            },
            #[serde(other)]
            Unknown,
        }
        let current = crate::EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 4 },
        };
        assert!(matches!(
            serde_json::from_value::<LegacyKind>(serde_json::to_value(current).unwrap()).unwrap(),
            LegacyKind::Unknown
        ));
        let done = crate::EventKind::Done {
            outcome: "Done".into(),
        };
        assert!(
            matches!(serde_json::from_value::<LegacyKind>(serde_json::to_value(done).unwrap()).unwrap(), LegacyKind::Done { outcome } if outcome == "Done")
        );
    }
}
