//! Bounded `core/planner` strategy for selecting already-normalized investigation leaves.

use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::TaskClass;

pub const PLANNER_SLOT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerObservation {
    pub version: u16,
    pub class: TaskClass,
    /// Caller-normalized objectives. Decisions name positions, never author prompt bytes.
    pub leaves: Vec<String>,
    pub max_leaves: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerPlan {
    pub selected: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerDecision {
    Plan {
        plan: PlannerPlan,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerProposal {
    pub plan: PlannerPlan,
    pub eligible: CapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerError {
    WrongSlot,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    Widened(&'static str),
    NotAdmitted,
}

impl fmt::Display for PlannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSlot => formatter.write_str("strategy does not implement core/planner"),
            Self::InvalidObservation(reason)
            | Self::InvalidDecision(reason)
            | Self::Widened(reason) => formatter.write_str(reason),
            Self::NotAdmitted => formatter.write_str("planner was not admitted read-only"),
        }
    }
}

impl std::error::Error for PlannerError {}

#[derive(Debug, Clone)]
pub struct PlannerStrategy {
    slot: SlotId,
}

impl Default for PlannerStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/planner".into()),
        }
    }
}

impl PlannerStrategy {
    pub fn plan_with(
        slot: &dyn StrategySlot,
        input: &PlannerObservation,
        ceiling: CapabilitySet,
    ) -> Result<PlannerProposal, PlannerError> {
        if slot.slot().as_persisted_str() != "core/planner" {
            return Err(PlannerError::WrongSlot);
        }
        validate_observation(input)?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload: serde_json::to_value(input)
                .map_err(|_| PlannerError::InvalidObservation("planner observation is invalid"))?,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::ReadOnly) {
            return Err(PlannerError::NotAdmitted);
        }
        let decision = serde_json::from_value::<PlannerDecision>(outcome.decision)
            .map_err(|_| PlannerError::InvalidDecision("planner decision is invalid"))?;
        let PlannerDecision::Plan { plan } = decision else {
            return Err(PlannerError::InvalidDecision(
                "planner decision has an unsupported version",
            ));
        };
        validate_plan(&plan, input)?;
        Ok(PlannerProposal {
            plan,
            eligible: outcome.admitted,
        })
    }
}

fn validate_observation(input: &PlannerObservation) -> Result<(), PlannerError> {
    if input.version != PLANNER_SLOT_VERSION {
        return Err(PlannerError::InvalidObservation(
            "unsupported planner observation version",
        ));
    }
    if input.leaves.len() > crate::FAN_CAP.saturating_mul(16) {
        return Err(PlannerError::InvalidObservation(
            "planner observation exceeds its leaf bound",
        ));
    }
    if input.max_leaves > crate::FAN_CAP {
        return Err(PlannerError::InvalidObservation(
            "planner breadth exceeds the product ceiling",
        ));
    }
    if input
        .leaves
        .iter()
        .any(|leaf| leaf.is_empty() || leaf.chars().count() > crate::LEAF_MAX_CHARS)
    {
        return Err(PlannerError::InvalidObservation(
            "planner leaves are not normalized",
        ));
    }
    Ok(())
}

fn validate_plan(plan: &PlannerPlan, input: &PlannerObservation) -> Result<(), PlannerError> {
    if plan.selected.len() > input.max_leaves {
        return Err(PlannerError::Widened(
            "planner selected more leaves than the caller allowed",
        ));
    }
    let mut seen = Vec::with_capacity(plan.selected.len());
    for selected in &plan.selected {
        if *selected >= input.leaves.len() {
            return Err(PlannerError::Widened(
                "planner selected a leaf the caller never gathered",
            ));
        }
        if seen.contains(selected) {
            return Err(PlannerError::InvalidDecision(
                "planner selected the same leaf twice",
            ));
        }
        seen.push(*selected);
    }
    Ok(())
}

impl StrategySlot for PlannerStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return unknown();
        }
        let Ok(input) = serde_json::from_value::<PlannerObservation>(observation.payload.clone())
        else {
            return unknown();
        };
        if validate_observation(&input).is_err() {
            return unknown();
        }
        SlotOutcome {
            admitted: CapabilitySet::only(Capability::ReadOnly).intersect(observation.ceiling),
            decision: serde_json::to_value(PlannerDecision::Plan {
                plan: PlannerPlan {
                    selected: (0..input.leaves.len().min(input.max_leaves)).collect(),
                },
            })
            .expect("planner decision serializes"),
        }
    }
}

fn unknown() -> SlotOutcome {
    SlotOutcome {
        admitted: CapabilitySet::none(),
        decision: serde_json::to_value(PlannerDecision::Unknown)
            .expect("unknown planner decision serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> PlannerObservation {
        PlannerObservation {
            version: PLANNER_SLOT_VERSION,
            class: TaskClass::MultiFile,
            leaves: vec!["a".into(), "b".into(), "c".into()],
            max_leaves: 2,
        }
    }

    #[test]
    fn baseline_selects_only_the_bounded_prefix() {
        let proposal = PlannerStrategy::plan_with(
            &PlannerStrategy::default(),
            &observation(),
            CapabilitySet::only(Capability::ReadOnly),
        )
        .unwrap();
        assert_eq!(proposal.plan.selected, vec![0, 1]);
    }

    #[test]
    fn a_replacement_cannot_conjure_or_duplicate_leaves() {
        struct Fixed(Vec<usize>, SlotId);
        impl StrategySlot for Fixed {
            fn slot(&self) -> &SlotId {
                &self.1
            }
            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: observation.ceiling,
                    decision: serde_json::to_value(PlannerDecision::Plan {
                        plan: PlannerPlan {
                            selected: self.0.clone(),
                        },
                    })
                    .unwrap(),
                }
            }
        }
        let mut input = observation();
        input.leaves.truncate(1);
        input.max_leaves = 1;
        for selected in [vec![1], vec![0, 0]] {
            assert!(
                PlannerStrategy::plan_with(
                    &Fixed(selected, SlotId("core/planner".into())),
                    &input,
                    CapabilitySet::only(Capability::ReadOnly),
                )
                .is_err()
            );
        }
    }
}
