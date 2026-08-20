//! The pure `core/scheduler` strategy behind the frozen [`StrategySlot`] seam.
//!
//! This module chooses bounded retry/backoff and concurrency parameters. It never acquires a
//! semaphore, sleeps, samples jitter, calls a provider, or admits an effect. [`crate::Governor`]
//! and [`crate::RetryProvider`] remain caller-side mechanisms that may apply the returned plan.

use crate::BackoffPolicy;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const SCHEDULER_SLOT_VERSION: u16 = 1;

/// Versioned, already-gathered hard ceilings for one scheduler decision.
///
/// The caller owns these limits. A strategy may choose a longer base delay, a shorter cap, fewer
/// attempts, or fewer permits, but it cannot make retries more aggressive or widen concurrency.
/// All values are fixed-width so the JSON decision is platform independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerSlotObservation {
    pub version: u16,
    /// Operator/caller-owned minimum delay before the first retry.
    pub min_retry_base_ms: u64,
    /// Deadline/budget-derived maximum delay for any single retry.
    pub max_retry_cap_ms: u64,
    /// Includes the first physical attempt.
    pub max_attempts: u32,
    /// Maximum number of simultaneously admitted work items.
    pub max_concurrency: u32,
}

impl SchedulerSlotObservation {
    /// Build the conservative baseline from an already-trusted retry policy and concurrency cap.
    pub fn baseline(
        retry: BackoffPolicy,
        max_concurrency: u32,
    ) -> Result<Self, SchedulerSlotError> {
        let observation = Self {
            version: SCHEDULER_SLOT_VERSION,
            min_retry_base_ms: retry.base_ms,
            max_retry_cap_ms: retry.cap_ms,
            max_attempts: retry.max_attempts,
            max_concurrency,
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), SchedulerSlotError> {
        if self.version != SCHEDULER_SLOT_VERSION {
            return Err(SchedulerSlotError::UnsupportedVersion);
        }
        if self.min_retry_base_ms == 0 {
            return Err(SchedulerSlotError::InvalidObservation(
                "retry base must be non-zero",
            ));
        }
        if self.max_retry_cap_ms < self.min_retry_base_ms {
            return Err(SchedulerSlotError::InvalidObservation(
                "retry cap must not be below the retry base floor",
            ));
        }
        if self.max_attempts == 0 {
            return Err(SchedulerSlotError::InvalidObservation(
                "retry attempts must include one physical attempt",
            ));
        }
        if self.max_concurrency == 0 {
            return Err(SchedulerSlotError::InvalidObservation(
                "scheduler concurrency must be non-zero",
            ));
        }
        Ok(())
    }
}

/// A bounded scheduler decision. Safety rules such as pre-stream-only retry are deliberately not
/// represented here: callers enforce them as mechanism, never as strategy choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerPlan {
    pub retry_base_ms: u64,
    pub retry_cap_ms: u64,
    /// Includes the first physical attempt.
    pub max_attempts: u32,
    pub concurrency_permits: u32,
}

impl SchedulerPlan {
    /// Convert the pure decision into the existing caller-side retry mechanism's policy.
    pub fn backoff_policy(self) -> BackoffPolicy {
        BackoffPolicy {
            base_ms: self.retry_base_ms,
            cap_ms: self.retry_cap_ms,
            max_attempts: self.max_attempts,
        }
    }

    /// Convert the fixed-width wire value only after validation has established it is non-zero.
    pub fn concurrency_permits(self) -> usize {
        self.concurrency_permits as usize
    }

    fn validate_against(
        &self,
        observation: &SchedulerSlotObservation,
    ) -> Result<(), SchedulerSlotError> {
        if self.retry_base_ms < observation.min_retry_base_ms {
            return Err(SchedulerSlotError::DecisionWidened(
                "retry base fell below the caller's floor",
            ));
        }
        if self.retry_cap_ms < self.retry_base_ms
            || self.retry_cap_ms > observation.max_retry_cap_ms
        {
            return Err(SchedulerSlotError::DecisionWidened(
                "retry cap escaped the caller's bounded interval",
            ));
        }
        if self.max_attempts == 0 || self.max_attempts > observation.max_attempts {
            return Err(SchedulerSlotError::DecisionWidened(
                "retry attempts exceeded the caller's ceiling",
            ));
        }
        if self.concurrency_permits == 0 || self.concurrency_permits > observation.max_concurrency {
            return Err(SchedulerSlotError::DecisionWidened(
                "concurrency permits exceeded the caller's ceiling",
            ));
        }
        Ok(())
    }
}

/// The version-skew boundary for a scheduler-slot decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchedulerSlotDecision {
    Plan {
        plan: SchedulerPlan,
    },
    #[serde(other)]
    Unknown,
}

/// A plan plus the capabilities that remain eligible after intersection with the caller ceiling.
/// Eligibility is evidence for a later gate, never authority to execute work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerProposal {
    pub plan: SchedulerPlan,
    pub eligible: CapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerSlotError {
    WrongSlot,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    DecisionWidened(&'static str),
    UnsupportedVersion,
}

impl fmt::Display for SchedulerSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSlot => formatter.write_str("strategy does not implement core/scheduler"),
            Self::InvalidObservation(reason) => formatter.write_str(reason),
            Self::InvalidDecision(reason) => formatter.write_str(reason),
            Self::DecisionWidened(reason) => formatter.write_str(reason),
            Self::UnsupportedVersion => formatter.write_str("unsupported scheduler slot version"),
        }
    }
}

impl std::error::Error for SchedulerSlotError {}

/// Hand-written baseline implementation of `core/scheduler`.
#[derive(Debug, Clone)]
pub struct SchedulerStrategy {
    slot: SlotId,
}

impl Default for SchedulerStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/scheduler".into()),
        }
    }
}

impl SchedulerStrategy {
    pub fn plan(
        &self,
        input: &SchedulerSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<SchedulerProposal, SchedulerSlotError> {
        Self::plan_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    pub fn plan_with(
        slot: &dyn StrategySlot,
        input: &SchedulerSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<SchedulerProposal, SchedulerSlotError> {
        if slot.slot().as_persisted_str() != "core/scheduler" {
            return Err(SchedulerSlotError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input).map_err(|_| {
            SchedulerSlotError::InvalidObservation("scheduler observation is invalid")
        })?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        let decision = serde_json::from_value::<SchedulerSlotDecision>(outcome.decision)
            .map_err(|_| SchedulerSlotError::InvalidDecision("scheduler decision is invalid"))?;
        let SchedulerSlotDecision::Plan { plan } = decision else {
            return Err(SchedulerSlotError::UnsupportedVersion);
        };
        plan.validate_against(input)?;
        Ok(SchedulerProposal {
            plan,
            eligible: outcome.admitted,
        })
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(SchedulerSlotDecision::Unknown)
                .expect("unit scheduler decision serializes"),
        }
    }
}

impl StrategySlot for SchedulerStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<SchedulerSlotObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        let plan = SchedulerPlan {
            retry_base_ms: input.min_retry_base_ms,
            retry_cap_ms: input.max_retry_cap_ms,
            max_attempts: input.max_attempts,
            concurrency_permits: input.max_concurrency,
        };
        SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(SchedulerSlotDecision::Plan { plan })
                .expect("scheduler plan serializes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{Capability, slot::StrategySlot};

    fn observation() -> SchedulerSlotObservation {
        SchedulerSlotObservation::baseline(BackoffPolicy::default(), 8).unwrap()
    }

    #[test]
    fn baseline_plan_preserves_caller_bounds() {
        let proposal = SchedulerStrategy::default()
            .plan(&observation(), CapabilitySet::only(Capability::ReadOnly))
            .unwrap();
        assert_eq!(proposal.plan.retry_base_ms, 500);
        assert_eq!(proposal.plan.retry_cap_ms, 30_000);
        assert_eq!(proposal.plan.max_attempts, 3);
        assert_eq!(proposal.plan.concurrency_permits, 8);
        assert!(proposal.eligible.contains(Capability::ReadOnly));
    }

    #[test]
    fn malformed_or_unknown_observations_fail_closed() {
        let strategy = SchedulerStrategy::default();
        let mut input = observation();
        input.version += 1;
        assert_eq!(
            strategy.plan(&input, CapabilitySet::none()),
            Err(SchedulerSlotError::UnsupportedVersion)
        );

        input.version = SCHEDULER_SLOT_VERSION;
        input.max_concurrency = 0;
        assert!(matches!(
            strategy.plan(&input, CapabilitySet::none()),
            Err(SchedulerSlotError::InvalidObservation(_))
        ));
    }

    #[test]
    fn unknown_wire_version_degrades_without_authority() {
        let strategy = SchedulerStrategy::default();
        let mut input = observation();
        input.version += 1;
        let outcome = strategy.decide(&SlotObservation {
            slot: strategy.slot().clone(),
            ceiling: CapabilitySet::only(Capability::IrreversibleExternal),
            payload: serde_json::to_value(input).unwrap(),
        });
        assert!(outcome.admitted.is_empty());
        assert_eq!(
            serde_json::from_value::<SchedulerSlotDecision>(outcome.decision).unwrap(),
            SchedulerSlotDecision::Unknown
        );
    }

    #[test]
    fn replacement_cannot_widen_numeric_ceilings() {
        struct Widening(SlotId);
        impl StrategySlot for Widening {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: SchedulerSlotObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                SlotOutcome {
                    admitted: CapabilitySet::from_iter_capabilities([
                        Capability::ReadOnly,
                        Capability::IrreversibleExternal,
                    ]),
                    decision: serde_json::to_value(SchedulerSlotDecision::Plan {
                        plan: SchedulerPlan {
                            retry_base_ms: input.min_retry_base_ms.saturating_sub(1),
                            retry_cap_ms: input.max_retry_cap_ms,
                            max_attempts: input.max_attempts.saturating_add(1),
                            concurrency_permits: input.max_concurrency.saturating_add(1),
                        },
                    })
                    .unwrap(),
                }
            }
        }

        let result = SchedulerStrategy::plan_with(
            &Widening(SlotId("core/scheduler".into())),
            &observation(),
            CapabilitySet::only(Capability::ReadOnly),
        );
        assert!(matches!(
            result,
            Err(SchedulerSlotError::DecisionWidened(_))
        ));
    }

    #[test]
    fn replacement_capabilities_are_intersected_with_the_caller_ceiling() {
        struct Greedy(SlotId);
        impl StrategySlot for Greedy {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: SchedulerSlotObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                SlotOutcome {
                    admitted: CapabilitySet::from_iter_capabilities([
                        Capability::ReadOnly,
                        Capability::IrreversibleExternal,
                    ]),
                    decision: serde_json::to_value(SchedulerSlotDecision::Plan {
                        plan: SchedulerPlan {
                            retry_base_ms: input.min_retry_base_ms,
                            retry_cap_ms: input.max_retry_cap_ms,
                            max_attempts: input.max_attempts,
                            concurrency_permits: input.max_concurrency,
                        },
                    })
                    .unwrap(),
                }
            }
        }

        let proposal = SchedulerStrategy::plan_with(
            &Greedy(SlotId("core/scheduler".into())),
            &observation(),
            CapabilitySet::only(Capability::ReadOnly),
        )
        .unwrap();
        assert!(proposal.eligible.contains(Capability::ReadOnly));
        assert!(!proposal.eligible.contains(Capability::IrreversibleExternal));
    }

    #[test]
    fn a_narrower_replacement_is_accepted_and_remains_deterministic() {
        struct Narrowing(SlotId);
        impl StrategySlot for Narrowing {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                let input: SchedulerSlotObservation =
                    serde_json::from_value(observation.payload.clone()).unwrap();
                SlotOutcome {
                    admitted: observation.ceiling,
                    decision: serde_json::to_value(SchedulerSlotDecision::Plan {
                        plan: SchedulerPlan {
                            retry_base_ms: input.min_retry_base_ms * 2,
                            retry_cap_ms: input.max_retry_cap_ms / 2,
                            max_attempts: input.max_attempts - 1,
                            concurrency_permits: input.max_concurrency / 2,
                        },
                    })
                    .unwrap(),
                }
            }
        }

        let slot = Narrowing(SlotId("core/scheduler".into()));
        let input = observation();
        let first =
            SchedulerStrategy::plan_with(&slot, &input, CapabilitySet::only(Capability::ReadOnly))
                .unwrap();
        let second =
            SchedulerStrategy::plan_with(&slot, &input, CapabilitySet::only(Capability::ReadOnly))
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.plan.max_attempts, 2);
        assert_eq!(first.plan.concurrency_permits, 4);
    }

    #[test]
    fn another_slot_identity_is_rejected_before_decision() {
        struct Other(SlotId);
        impl StrategySlot for Other {
            fn slot(&self) -> &SlotId {
                &self.0
            }

            fn decide(&self, _: &SlotObservation) -> SlotOutcome {
                panic!("wrong slot must be rejected before it is called")
            }
        }

        assert_eq!(
            SchedulerStrategy::plan_with(
                &Other(SlotId("core/context".into())),
                &observation(),
                CapabilitySet::none(),
            ),
            Err(SchedulerSlotError::WrongSlot)
        );
    }
}
