//! Bounded `core/collaboration` strategy for fan execution width.

use core_protocol::Capability;
use core_protocol::capability_set::CapabilitySet;
use core_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const COLLABORATION_SLOT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborationObservation {
    pub version: u16,
    pub active_workers: usize,
    /// Caller-owned ceiling derived from product cap, machine capacity and admitted workers.
    pub max_concurrency: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CollaborationDecision {
    Run {
        concurrency: usize,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollaborationProposal {
    pub concurrency: usize,
    pub eligible: CapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollaborationError {
    WrongSlot,
    InvalidObservation,
    InvalidDecision,
    Widened,
    NotAdmitted,
}

impl fmt::Display for CollaborationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongSlot => "strategy does not implement core/collaboration",
            Self::InvalidObservation => "collaboration observation is invalid",
            Self::InvalidDecision => "collaboration decision is invalid",
            Self::Widened => "collaboration decision exceeded the caller concurrency ceiling",
            Self::NotAdmitted => "collaboration decision was not admitted read-only",
        })
    }
}

impl std::error::Error for CollaborationError {}

#[derive(Debug, Clone)]
pub struct CollaborationStrategy {
    slot: SlotId,
}

impl Default for CollaborationStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/collaboration".into()),
        }
    }
}

impl CollaborationStrategy {
    pub fn select_with(
        slot: &dyn StrategySlot,
        input: &CollaborationObservation,
        ceiling: CapabilitySet,
    ) -> Result<CollaborationProposal, CollaborationError> {
        if slot.slot().as_persisted_str() != "core/collaboration" {
            return Err(CollaborationError::WrongSlot);
        }
        validate_observation(input)?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload: serde_json::to_value(input)
                .map_err(|_| CollaborationError::InvalidObservation)?,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::ReadOnly) {
            return Err(CollaborationError::NotAdmitted);
        }
        let decision = serde_json::from_value::<CollaborationDecision>(outcome.decision)
            .map_err(|_| CollaborationError::InvalidDecision)?;
        let CollaborationDecision::Run { concurrency } = decision else {
            return Err(CollaborationError::InvalidDecision);
        };
        if concurrency == 0
            || concurrency > input.max_concurrency
            || concurrency > input.active_workers
        {
            return Err(CollaborationError::Widened);
        }
        Ok(CollaborationProposal {
            concurrency,
            eligible: outcome.admitted,
        })
    }
}

fn validate_observation(input: &CollaborationObservation) -> Result<(), CollaborationError> {
    if input.version != COLLABORATION_SLOT_VERSION
        || input.active_workers == 0
        || input.max_concurrency == 0
        || input.max_concurrency > input.active_workers
    {
        return Err(CollaborationError::InvalidObservation);
    }
    Ok(())
}

impl StrategySlot for CollaborationStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return unknown();
        }
        let Ok(input) =
            serde_json::from_value::<CollaborationObservation>(observation.payload.clone())
        else {
            return unknown();
        };
        if validate_observation(&input).is_err() {
            return unknown();
        }
        SlotOutcome {
            admitted: CapabilitySet::only(Capability::ReadOnly).intersect(observation.ceiling),
            decision: serde_json::to_value(CollaborationDecision::Run {
                concurrency: input.max_concurrency,
            })
            .expect("collaboration decision serializes"),
        }
    }
}

fn unknown() -> SlotOutcome {
    SlotOutcome {
        admitted: CapabilitySet::none(),
        decision: serde_json::to_value(CollaborationDecision::Unknown)
            .expect("unknown collaboration decision serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_uses_the_caller_bounded_width() {
        let proposal = CollaborationStrategy::select_with(
            &CollaborationStrategy::default(),
            &CollaborationObservation {
                version: COLLABORATION_SLOT_VERSION,
                active_workers: 8,
                max_concurrency: 3,
            },
            CapabilitySet::only(Capability::ReadOnly),
        )
        .unwrap();
        assert_eq!(proposal.concurrency, 3);
    }

    #[test]
    fn replacement_cannot_widen_machine_or_worker_ceiling() {
        struct Fixed(SlotId);
        impl StrategySlot for Fixed {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: observation.ceiling,
                    decision: serde_json::to_value(CollaborationDecision::Run { concurrency: 4 })
                        .unwrap(),
                }
            }
        }
        assert_eq!(
            CollaborationStrategy::select_with(
                &Fixed(SlotId("core/collaboration".into())),
                &CollaborationObservation {
                    version: COLLABORATION_SLOT_VERSION,
                    active_workers: 8,
                    max_concurrency: 2,
                },
                CapabilitySet::only(Capability::ReadOnly),
            ),
            Err(CollaborationError::Widened)
        );
    }
}
