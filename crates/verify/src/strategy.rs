//! The pure `core/verifier` strategy behind the frozen [`StrategySlot`] seam.
//!
//! Every acceptance claim in this program runs through this crate: each gap's `accept` command,
//! the eval oracle, and the kernel's refusal to take `done` from a failing verifier. Which oracle
//! answers, and how wide a run has to be before its answer counts, was fixed in code. A vertical
//! pack that wants its own oracle had to change the kernel to get one.
//!
//! This module makes that a slot decision. It chooses; it never runs anything. No process is
//! spawned here, no file is read, no network is touched — [`crate::oracle`] owns execution and
//! [`iteron_sandbox`] owns the confinement it runs under.
//!
//! Two rules are structural rather than advisory:
//!
//! **A decision may only strengthen.** The caller supplies a floor; a strategy may demand a
//! stronger oracle or a wider scope, never a weaker one. Widening is not expressible — a decision
//! that tries is rejected by [`VerifierPlan::validate_against`], not merely discouraged.
//!
//! **The default gating scope is the whole workspace.** The fleet's lesson was that a lane whose
//! own acceptance test passes can still break the workspace, so a lane-scoped pass is not an
//! acceptance claim. [`VerifierScope::Workspace`] is the floor callers get from
//! [`VerifierSlotObservation::gating`], and [`GateOutcome::gate`] refuses a run whose lane passed
//! and whose workspace suite did not.

use crate::oracle::{OracleStrength, VerificationOutcome};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const VERIFIER_SLOT_VERSION: u16 = 1;

/// The most repeats a plan may ask for. A flake is evidence, not something to grind away at.
pub const MAX_VERIFIER_ATTEMPTS: u32 = 3;

/// How wide a verification run has to be for its verdict to count.
///
/// Ordered, and the order is the point: `Workspace` is strictly stronger than `Lane`, so a
/// decision may move a run up this ladder and never down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierScope {
    /// Only the lane's own acceptance command. Sufficient for feedback, never for a gate.
    Lane = 0,
    /// The full workspace suite. The default for gating.
    Workspace = 1,
}

impl fmt::Display for VerifierScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lane => "lane",
            Self::Workspace => "workspace",
        })
    }
}

/// The already-gathered floors for one verification decision.
///
/// The caller owns these. A strategy sees only what is here: no path, no command, no environment.
/// That is the observable contract — a verifier may not learn what it was not shown, and it has no
/// way to reach the world from inside [`StrategySlot::decide`], which is synchronous and pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSlotObservation {
    pub version: u16,
    /// The weakest oracle whose verdict the caller will accept.
    pub minimum_strength: OracleStrength,
    /// The narrowest run the caller will accept.
    pub scope_floor: VerifierScope,
    /// Whether the model has claimed the task is finished. A gate never trusts this; it is here
    /// because a strategy may reasonably demand more of a run that is about to accept `done`.
    pub claims_done: bool,
}

impl VerifierSlotObservation {
    /// The floors a completion gate uses: a Strong oracle over the whole workspace.
    ///
    /// A weaker oracle may not veto (ADR-005 R6), so anything below `Strong` cannot gate at all.
    pub fn gating(claims_done: bool) -> Self {
        Self {
            version: VERIFIER_SLOT_VERSION,
            minimum_strength: OracleStrength::Strong,
            scope_floor: VerifierScope::Workspace,
            claims_done,
        }
    }

    /// The floors for non-gating feedback, where a lane-scoped answer is useful and harmless.
    pub fn advisory() -> Self {
        Self {
            version: VERIFIER_SLOT_VERSION,
            minimum_strength: OracleStrength::Weak,
            scope_floor: VerifierScope::Lane,
            claims_done: false,
        }
    }

    fn validate(&self) -> Result<(), VerifierSlotError> {
        if self.version != VERIFIER_SLOT_VERSION {
            return Err(VerifierSlotError::UnsupportedVersion);
        }
        Ok(())
    }
}

/// What a verification run must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierPlan {
    pub strength: OracleStrength,
    pub scope: VerifierScope,
    /// Repeats allowed in order to observe a flake. One means no repeat.
    pub attempts: u32,
    /// Whether a disagreement between attempts is reported. Any repeat must report.
    pub report_flake: bool,
}

impl VerifierPlan {
    /// Reject a decision that weakened anything the caller pinned.
    ///
    /// The failure is typed rather than clamped. Silently strengthening a weakened plan back to
    /// the floor would let a slot ship a policy nobody notices is being ignored, and the whole
    /// reason this is a slot is that its choice is supposed to be visible.
    pub fn validate_against(
        &self,
        input: &VerifierSlotObservation,
    ) -> Result<(), VerifierSlotError> {
        if self.strength < input.minimum_strength {
            return Err(VerifierSlotError::DecisionWeakened(
                "verifier strength is below the caller's floor",
            ));
        }
        if self.scope < input.scope_floor {
            return Err(VerifierSlotError::DecisionWeakened(
                "verifier scope is narrower than the caller's floor",
            ));
        }
        if self.attempts == 0 || self.attempts > MAX_VERIFIER_ATTEMPTS {
            return Err(VerifierSlotError::InvalidDecision(
                "verifier attempts must be between one and the bounded maximum",
            ));
        }
        // A retry that nobody hears about turns a flaky suite into a green one. If a plan wants a
        // second look it has to say so in the verdict.
        if self.attempts > 1 && !self.report_flake {
            return Err(VerifierSlotError::InvalidDecision(
                "a plan that retries must report the disagreement rather than absorb it",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerifierSlotDecision {
    Plan {
        plan: VerifierPlan,
    },
    /// A decoder that does not recognise the payload degrades here rather than guessing.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierSlotError {
    UnsupportedVersion,
    WrongSlot,
    DecisionWeakened(&'static str),
    InvalidDecision(&'static str),
}

impl fmt::Display for VerifierSlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("unsupported verifier slot version"),
            Self::WrongSlot => formatter.write_str("slot identity is not core/verifier"),
            Self::DecisionWeakened(reason) | Self::InvalidDecision(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for VerifierSlotError {}

/// A plan a caller may act on, with the authority the slot admitted for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierProposal {
    pub plan: VerifierPlan,
    pub eligible: CapabilitySet,
}

/// The built-in `core/verifier`: never weaker than the floor, and never narrower.
pub struct VerifierStrategy {
    slot: SlotId,
}

impl Default for VerifierStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/verifier".into()),
        }
    }
}

impl VerifierStrategy {
    pub fn plan(
        &self,
        input: &VerifierSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<VerifierProposal, VerifierSlotError> {
        Self::plan_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    ///
    /// This is the seam: a vertical pack supplies its own `dyn StrategySlot` and the caller keeps
    /// the same guarantees, because the checks live here rather than inside any implementation.
    pub fn plan_with(
        slot: &dyn StrategySlot,
        input: &VerifierSlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<VerifierProposal, VerifierSlotError> {
        if slot.slot().as_persisted_str() != "core/verifier" {
            return Err(VerifierSlotError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input)
            .map_err(|_| VerifierSlotError::InvalidDecision("verifier observation is invalid"))?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        let decision = serde_json::from_value::<VerifierSlotDecision>(outcome.decision)
            .map_err(|_| VerifierSlotError::InvalidDecision("verifier decision is invalid"))?;
        let VerifierSlotDecision::Plan { plan } = decision else {
            return Err(VerifierSlotError::UnsupportedVersion);
        };
        plan.validate_against(input)?;
        Ok(VerifierProposal {
            plan,
            eligible: outcome.admitted,
        })
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(VerifierSlotDecision::Unknown)
                .expect("unit verifier decision serializes"),
        }
    }

    fn decide_plan(input: &VerifierSlotObservation) -> VerifierPlan {
        VerifierPlan {
            strength: input.minimum_strength,
            scope: input.scope_floor,
            attempts: 1,
            report_flake: true,
        }
    }
}

impl StrategySlot for VerifierStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<VerifierSlotObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(VerifierSlotDecision::Plan {
                plan: Self::decide_plan(&input),
            })
            .expect("verifier decision serializes"),
        }
    }
}

/// An in-repo alternative implementation, which exists to prove the seam is real.
///
/// It always demands the full workspace at Strong, whatever floor the caller supplied, and takes a
/// second look when the model claims it is done. A pack can ship exactly this shape without the
/// kernel knowing it happened — which is the property #51 asked for.
pub struct WorkspaceGateVerifier {
    slot: SlotId,
}

impl Default for WorkspaceGateVerifier {
    fn default() -> Self {
        Self {
            slot: SlotId("core/verifier".into()),
        }
    }
}

impl StrategySlot for WorkspaceGateVerifier {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return VerifierStrategy::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<VerifierSlotObservation>(observation.payload.clone())
        else {
            return VerifierStrategy::unknown_outcome();
        };
        SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(VerifierSlotDecision::Plan {
                plan: VerifierPlan {
                    strength: OracleStrength::Strong,
                    scope: VerifierScope::Workspace,
                    attempts: if input.claims_done { 2 } else { 1 },
                    report_flake: true,
                },
            })
            .expect("verifier decision serializes"),
        }
    }
}

/// What a gate concluded, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// Every run the plan required passed.
    Accepted,
    /// A run reported the candidate incorrect.
    Rejected { scope: VerifierScope },
    /// A run could not produce a verdict. Not a candidate failure, and never an acceptance.
    Indeterminate { scope: VerifierScope },
    /// Repeats disagreed. Reported rather than absorbed by taking the pass.
    Flaky { scope: VerifierScope },
}

impl GateOutcome {
    pub const fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Decide a gate from the runs a plan required.
    ///
    /// The fleet's lesson, encoded: a lane pass is not an acceptance. When the plan's scope is
    /// `Workspace`, the workspace verdict decides, and a green lane cannot stand in for a missing
    /// or failing workspace run.
    pub fn gate(
        plan: &VerifierPlan,
        lane: Option<VerificationOutcome>,
        workspace: Option<VerificationOutcome>,
    ) -> Self {
        if plan.scope == VerifierScope::Workspace {
            return match workspace {
                Some(VerificationOutcome::Pass) => Self::Accepted,
                Some(VerificationOutcome::TestFailure) => Self::Rejected {
                    scope: VerifierScope::Workspace,
                },
                // A workspace run that never produced a verdict is not an acceptance, however
                // green the lane was.
                _ => Self::Indeterminate {
                    scope: VerifierScope::Workspace,
                },
            };
        }
        match lane {
            Some(VerificationOutcome::Pass) => Self::Accepted,
            Some(VerificationOutcome::TestFailure) => Self::Rejected {
                scope: VerifierScope::Lane,
            },
            _ => Self::Indeterminate {
                scope: VerifierScope::Lane,
            },
        }
    }

    /// Fold a plan's repeats into one outcome, reporting disagreement instead of taking the pass.
    pub fn from_attempts(plan: &VerifierPlan, attempts: &[GateOutcome]) -> Self {
        let Some(first) = attempts.first() else {
            return Self::Indeterminate { scope: plan.scope };
        };
        if attempts.iter().all(|outcome| outcome == first) {
            return *first;
        }
        Self::Flaky { scope: plan.scope }
    }
}

#[cfg(test)]
#[path = "strategy_tests.rs"]
mod tests;
