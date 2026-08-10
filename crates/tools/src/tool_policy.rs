//! The pure `core/tool_policy` strategy behind the frozen `StrategySlot` seam.

use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::intent::ToolIntent;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use iteron_protocol::{Capability, Purity, ToolUse, Trust};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const TOOL_POLICY_SLOT_VERSION: u16 = 1;

/// The only tool metadata policy may use. A [`crate::Registry`] gathers it from `ToolSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredToolPolicy {
    pub name: String,
    pub purity: Purity,
    pub capability: Capability,
}

/// Versioned, already-gathered input to the built-in tool policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolPolicyObservation {
    pub version: u16,
    pub call: ToolUse,
    pub registered: RegisteredToolPolicy,
    pub argument_trust: Trust,
}

/// Version-skew boundary for a tool-policy decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolPolicyDecision {
    Candidate {
        call: ToolUse,
        purity: Purity,
        capability: Capability,
        argument_trust: Trust,
    },
    #[serde(other)]
    Unknown,
}

/// A deny-by-default intent plus the capability the pure policy found eligible.
///
/// `eligible` has already been intersected with the caller's ceiling. It is evidence for the
/// kernel gate, not authority to execute: `intent.admitted` stays empty until the gate admits it.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPolicyProposal {
    pub intent: ToolIntent,
    pub eligible: CapabilitySet,
}

impl ToolPolicyProposal {
    /// Apply a gate decision by intersection. This is the only widening point from the denied
    /// constructor, and it cannot admit a class the pure policy did not mark eligible.
    pub fn admit(mut self, gate_admission: CapabilitySet) -> ToolIntent {
        self.intent.admitted = self.eligible.intersect(gate_admission);
        self.intent
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolPolicyError {
    UnknownTool(String),
    InvalidObservation(&'static str),
    UnsupportedVersion,
    NotEligible,
}

impl fmt::Display for ToolPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool(name) => write!(formatter, "unknown tool `{name}`"),
            Self::InvalidObservation(reason) => formatter.write_str(reason),
            Self::UnsupportedVersion => formatter.write_str("unsupported tool-policy version"),
            Self::NotEligible => formatter.write_str("tool policy admitted no eligible capability"),
        }
    }
}

impl std::error::Error for ToolPolicyError {}

/// Hand-written baseline implementation of `core/tool_policy`.
#[derive(Debug, Clone)]
pub struct ToolPolicy {
    slot: SlotId,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            slot: SlotId("iteron/tool_policy".into()),
        }
    }
}

impl ToolPolicy {
    /// Produce a gate candidate without invoking a tool or granting execution authority.
    pub fn propose(
        &self,
        input: &ToolPolicyObservation,
        ceiling: CapabilitySet,
    ) -> Result<ToolPolicyProposal, ToolPolicyError> {
        Self::propose_with(self, input, ceiling)
    }

    /// Decode and validate any pinned implementation of the frozen slot trait.
    pub fn propose_with(
        slot: &dyn StrategySlot,
        input: &ToolPolicyObservation,
        ceiling: CapabilitySet,
    ) -> Result<ToolPolicyProposal, ToolPolicyError> {
        if input.version != TOOL_POLICY_SLOT_VERSION {
            return Err(ToolPolicyError::UnsupportedVersion);
        }
        let payload = serde_json::to_value(input)
            .map_err(|_| ToolPolicyError::InvalidObservation("tool observation is invalid"))?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        if outcome.admitted.is_empty() {
            return Err(ToolPolicyError::NotEligible);
        }
        let decision = serde_json::from_value::<ToolPolicyDecision>(outcome.decision)
            .map_err(|_| ToolPolicyError::InvalidObservation("tool decision is invalid"))?;
        let ToolPolicyDecision::Candidate {
            call,
            purity,
            capability,
            argument_trust,
        } = decision
        else {
            return Err(ToolPolicyError::UnsupportedVersion);
        };
        if call != input.call
            || purity != input.registered.purity
            || capability != input.registered.capability
            || argument_trust != input.argument_trust
            || outcome.admitted != CapabilitySet::only(capability).intersect(ceiling)
        {
            return Err(ToolPolicyError::InvalidObservation(
                "tool decision does not preserve registry metadata and caller input",
            ));
        }
        let intent = ToolIntent::denied(slot.slot().clone(), call, purity, argument_trust);
        intent
            .validate()
            .map_err(ToolPolicyError::InvalidObservation)?;
        Ok(ToolPolicyProposal {
            intent,
            eligible: outcome.admitted,
        })
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(ToolPolicyDecision::Unknown)
                .expect("unit tool-policy decision serializes"),
        }
    }
}

impl StrategySlot for ToolPolicy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ToolPolicyObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.version != TOOL_POLICY_SLOT_VERSION
            || input.call.name != input.registered.name
            || ToolIntent::denied(
                self.slot.clone(),
                input.call.clone(),
                input.registered.purity,
                input.argument_trust,
            )
            .validate()
            .is_err()
        {
            return Self::unknown_outcome();
        }
        SlotOutcome {
            admitted: CapabilitySet::only(input.registered.capability)
                .intersect(observation.ceiling),
            decision: serde_json::to_value(ToolPolicyDecision::Candidate {
                call: input.call,
                purity: input.registered.purity,
                capability: input.registered.capability,
                argument_trust: input.argument_trust,
            })
            .expect("tool-policy plan serializes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Registry, boxfut};
    use iteron_protocol::{ToolResult, ToolSpec};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn call() -> ToolUse {
        ToolUse {
            id: "toolu_policy".into(),
            name: "sample".into(),
            input: json!({"path": "src/lib.rs"}),
        }
    }

    #[test]
    fn every_capability_class_is_intersected_as_a_set() {
        let policy = ToolPolicy::default();
        for capability in [
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ] {
            let observation = ToolPolicyObservation {
                version: TOOL_POLICY_SLOT_VERSION,
                call: call(),
                registered: RegisteredToolPolicy {
                    name: "sample".into(),
                    purity: Purity::Effecting,
                    capability,
                },
                argument_trust: Trust::Workspace,
            };
            let proposal = policy
                .propose(&observation, CapabilitySet::only(capability))
                .unwrap();
            assert!(proposal.eligible.contains(capability));
            assert!(proposal.intent.admitted.is_empty());
            assert_eq!(proposal.intent.purity, Purity::Effecting);

            let other = if capability == Capability::ReadOnly {
                Capability::CodeExecuting
            } else {
                Capability::ReadOnly
            };
            assert!(
                policy
                    .propose(&observation, CapabilitySet::only(other))
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn registry_metadata_is_authoritative_and_policy_never_executes() {
        let executions = Arc::new(AtomicUsize::new(0));
        let observed = executions.clone();
        let mut registry = Registry::read_only(".").unwrap();
        registry
            .register_external(
                ToolSpec {
                    name: "sample".into(),
                    description: "sample".into(),
                    input_schema: json!({"type": "object"}),
                    purity: Purity::Effecting,
                    capability: Capability::TrustMutating,
                },
                move |call, _root| {
                    let observed = observed.clone();
                    boxfut::box_it(async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        ToolResult {
                            tool_use_id: call.id,
                            content: String::new(),
                            is_error: false,
                            trust: Trust::Trusted,
                            latency_ms: 0,
                        }
                    })
                },
            )
            .unwrap();

        let proposal = registry
            .propose_intent(
                &ToolPolicy::default(),
                call(),
                Trust::Untrusted,
                CapabilitySet::only(Capability::TrustMutating),
            )
            .unwrap();
        assert!(proposal.eligible.contains(Capability::TrustMutating));
        assert_eq!(proposal.intent.purity, Purity::Effecting);
        assert_eq!(proposal.intent.argument_trust, Trust::Untrusted);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        let denied = registry
            .run_admitted_intent(proposal.intent.clone())
            .await
            .into_result();
        assert!(denied.is_error);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_version_and_name_mismatch_fail_closed() {
        let policy = ToolPolicy::default();
        let mut observation = ToolPolicyObservation {
            version: TOOL_POLICY_SLOT_VERSION + 1,
            call: call(),
            registered: RegisteredToolPolicy {
                name: "other".into(),
                purity: Purity::Pure,
                capability: Capability::ReadOnly,
            },
            argument_trust: Trust::Workspace,
        };
        assert_eq!(
            policy.propose(&observation, CapabilitySet::only(Capability::ReadOnly)),
            Err(ToolPolicyError::UnsupportedVersion)
        );
        observation.version = TOOL_POLICY_SLOT_VERSION;
        assert_eq!(
            policy.propose(&observation, CapabilitySet::only(Capability::ReadOnly)),
            Err(ToolPolicyError::NotEligible)
        );
    }

    #[test]
    fn replacement_cannot_reclassify_registry_metadata() {
        struct Liar(SlotId);
        impl StrategySlot for Liar {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: ToolPolicyObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                SlotOutcome {
                    admitted: CapabilitySet::only(input.registered.capability),
                    decision: serde_json::to_value(ToolPolicyDecision::Candidate {
                        call: input.call,
                        purity: Purity::Pure,
                        capability: input.registered.capability,
                        argument_trust: input.argument_trust,
                    })
                    .unwrap(),
                }
            }
        }

        let input = ToolPolicyObservation {
            version: TOOL_POLICY_SLOT_VERSION,
            call: call(),
            registered: RegisteredToolPolicy {
                name: "sample".into(),
                purity: Purity::Effecting,
                capability: Capability::TrustMutating,
            },
            argument_trust: Trust::Workspace,
        };
        let result = ToolPolicy::propose_with(
            &Liar(SlotId("iteron/tool_policy".into())),
            &input,
            CapabilitySet::only(Capability::TrustMutating),
        );
        assert!(matches!(
            result,
            Err(ToolPolicyError::InvalidObservation(_))
        ));
    }
}
