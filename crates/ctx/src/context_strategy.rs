//! The pure `core/context` strategy behind the frozen `StrategySlot` seam.
//!
//! This module selects context. It never materializes a path, reads a store, or discovers a
//! skill. [`crate::ContextPort`] owns that world-facing half so a policy remains a bounded,
//! deterministic function of an already-gathered observation.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::context::{
    ContextRequest, ContextSelector, InstructionScope, MAX_CONTEXT_GRANT_BYTES, RequestId,
};
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use iteron_protocol::{Capability, Trust};
use serde::{Deserialize, Serialize};

pub const CONTEXT_SLOT_VERSION: u16 = 1;
pub const MAX_CONTEXT_OUTLINE_DEPTH: u8 = 8;
const MAX_CONTEXT_TASK_BYTES: usize = 64 * 1024;

/// Versioned, already-gathered input to the built-in context policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSlotObservation {
    pub version: u16,
    pub request_id: RequestId,
    pub include_outline: bool,
    pub root: String,
    pub depth: u8,
    pub instruction_scopes: Vec<InstructionScope>,
    pub memory_keys: Vec<String>,
    pub transcript_turns: u16,
    pub include_environment: bool,
    /// Compatibility bridge for the existing deterministic lexical recall path. The frozen ABI
    /// can request named `MemoryKeys` but cannot yet express relevance recall.
    pub recall_memory: bool,
    pub include_skills: bool,
    pub max_bytes: u32,
    pub trust_ceiling: Trust,
    pub task: String,
}

impl ContextSlotObservation {
    /// The conservative baseline used until a pinned PolicyManifest supplies another policy.
    pub fn baseline(request_id: RequestId, task: impl Into<String>) -> Self {
        Self {
            version: CONTEXT_SLOT_VERSION,
            request_id,
            include_outline: true,
            root: ".".into(),
            depth: 2,
            instruction_scopes: vec![
                InstructionScope::User,
                InstructionScope::Project,
                InstructionScope::Directory,
            ],
            memory_keys: Vec::new(),
            transcript_turns: 0,
            include_environment: true,
            recall_memory: true,
            include_skills: true,
            max_bytes: MAX_CONTEXT_GRANT_BYTES,
            trust_ceiling: Trust::Workspace,
            task: task.into(),
        }
    }
}

/// A request plus the local-only choices intentionally absent from the frozen ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlan {
    pub request: ContextRequest,
    pub recall_memory: bool,
    pub include_skills: bool,
    pub task: String,
}

/// The version-skew boundary for a context-slot decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContextSlotDecision {
    Plan {
        plan: ContextPlan,
    },
    #[serde(other)]
    Unknown,
}

/// Hand-written baseline implementation of `core/context`.
#[derive(Debug, Clone)]
pub struct ContextStrategy {
    slot: SlotId,
}

impl Default for ContextStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/context".into()),
        }
    }
}

impl ContextStrategy {
    /// Typed facade for callers. Capability admission still occurs through `decide_narrowed`.
    pub fn select(
        &self,
        input: &ContextSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<ContextPlan, &'static str> {
        Self::select_with(self, input, ceiling)
    }

    /// Decode and validate any pinned implementation of the frozen slot trait.
    pub fn select_with(
        slot: &dyn StrategySlot,
        input: &ContextSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<ContextPlan, &'static str> {
        let payload = serde_json::to_value(input).map_err(|_| "context observation is invalid")?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::ReadOnly) {
            return Err("context selection was not admitted as read-only");
        }
        match serde_json::from_value(outcome.decision).map_err(|_| "context decision is invalid")? {
            ContextSlotDecision::Plan { plan } => {
                plan.request.validate()?;
                if plan.request.slot != *slot.slot() {
                    return Err("context decision attributes its request to another slot");
                }
                if plan.request.request_id != input.request_id {
                    return Err("context decision changed the caller request identity");
                }
                if plan.request.max_bytes > input.max_bytes
                    || plan.request.trust_ceiling > input.trust_ceiling
                {
                    return Err("context decision widened the caller's byte or trust ceiling");
                }
                if plan.task != input.task || plan.task.len() > MAX_CONTEXT_TASK_BYTES {
                    return Err("context decision changed or exceeded the bounded task query");
                }
                if !plan_fits_observation(&plan, input) {
                    return Err("context decision selected outside the gathered observation");
                }
                Ok(plan)
            }
            ContextSlotDecision::Unknown => Err("context slot version is unsupported"),
        }
    }

    fn decide_typed(&self, input: ContextSlotObservation) -> Result<ContextPlan, &'static str> {
        if input.version != CONTEXT_SLOT_VERSION {
            return Err("unsupported context slot version");
        }
        if input.task.len() > MAX_CONTEXT_TASK_BYTES {
            return Err("context task exceeds its local observation bound");
        }
        if input.depth > MAX_CONTEXT_OUTLINE_DEPTH {
            return Err("context outline depth exceeds the local traversal bound");
        }
        let mut request = ContextRequest::new(input.request_id, self.slot.clone(), input.max_bytes);
        request.trust_ceiling = input.trust_ceiling;
        if input.include_outline {
            request = request.with_selector(ContextSelector::RepoOutline {
                root: input.root,
                depth: input.depth,
            });
        }
        for scope in input.instruction_scopes {
            request = request.with_selector(ContextSelector::Instructions { scope });
        }
        if !input.memory_keys.is_empty() {
            request = request.with_selector(ContextSelector::MemoryKeys {
                keys: input.memory_keys,
            });
        }
        if input.transcript_turns > 0 {
            request = request.with_selector(ContextSelector::Transcript {
                last_n_turns: input.transcript_turns,
            });
        }
        if input.include_environment {
            request = request.with_selector(ContextSelector::EnvironmentFacts);
        }
        request.validate()?;
        Ok(ContextPlan {
            request,
            recall_memory: input.recall_memory,
            include_skills: input.include_skills,
            task: input.task,
        })
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(ContextSlotDecision::Unknown)
                .expect("unit context decision serializes"),
        }
    }
}

fn plan_fits_observation(plan: &ContextPlan, input: &ContextSlotObservation) -> bool {
    if (plan.include_skills && !input.include_skills)
        || (plan.recall_memory && !input.recall_memory)
    {
        return false;
    }
    plan.request
        .selectors
        .iter()
        .all(|selector| match selector {
            ContextSelector::RepoOutline { root, depth } => {
                input.include_outline && root == &input.root && *depth <= input.depth
            }
            ContextSelector::Instructions { scope } => input.instruction_scopes.contains(scope),
            ContextSelector::MemoryKeys { keys } => {
                keys.iter().all(|key| input.memory_keys.contains(key))
            }
            ContextSelector::Transcript { last_n_turns } => *last_n_turns <= input.transcript_turns,
            ContextSelector::EnvironmentFacts => input.include_environment,
            ContextSelector::Unknown => false,
        })
}

impl StrategySlot for ContextStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ContextSlotObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        let Ok(plan) = self.decide_typed(input) else {
            return Self::unknown_outcome();
        };
        SlotOutcome {
            admitted: CapabilitySet::only(Capability::ReadOnly).intersect(observation.ceiling),
            decision: serde_json::to_value(ContextSlotDecision::Plan { plan })
                .expect("context plan serializes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_a_valid_frozen_request() {
        let strategy = ContextStrategy::default();
        let plan = strategy
            .select(
                &ContextSlotObservation::baseline(RequestId(7), "fix parser"),
                CapabilitySet::only(Capability::ReadOnly),
            )
            .unwrap();
        plan.request.validate().unwrap();
        assert_eq!(plan.request.slot, SlotId("core/context".into()));
        assert!(plan.include_skills);
    }

    #[test]
    fn unknown_version_degrades_without_authority() {
        let strategy = ContextStrategy::default();
        let mut input = ContextSlotObservation::baseline(RequestId(8), "task");
        input.version = CONTEXT_SLOT_VERSION + 1;
        assert_eq!(
            strategy.select(&input, CapabilitySet::only(Capability::ReadOnly)),
            Err("context selection was not admitted as read-only")
        );
    }

    #[test]
    fn caller_ceiling_can_only_remove_context_authority() {
        let strategy = ContextStrategy::default();
        let input = ContextSlotObservation::baseline(RequestId(9), "task");
        assert!(strategy.select(&input, CapabilitySet::none()).is_err());
    }

    #[test]
    fn replacement_cannot_widen_request_bounds() {
        struct Widening(SlotId);
        impl StrategySlot for Widening {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: ContextSlotObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                let request = ContextRequest::new(
                    input.request_id,
                    self.0.clone(),
                    input.max_bytes.saturating_add(1),
                );
                SlotOutcome {
                    admitted: CapabilitySet::only(Capability::ReadOnly),
                    decision: serde_json::to_value(ContextSlotDecision::Plan {
                        plan: ContextPlan {
                            request,
                            recall_memory: false,
                            include_skills: false,
                            task: input.task,
                        },
                    })
                    .unwrap(),
                }
            }
        }

        let mut input = ContextSlotObservation::baseline(RequestId(10), "task");
        input.max_bytes = 1_024;
        let result = ContextStrategy::select_with(
            &Widening(SlotId("core/context".into())),
            &input,
            CapabilitySet::only(Capability::ReadOnly),
        );
        assert_eq!(
            result,
            Err("context decision widened the caller's byte or trust ceiling")
        );
    }
}
