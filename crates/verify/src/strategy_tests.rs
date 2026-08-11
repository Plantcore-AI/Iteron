use super::*;
use iteron_protocol::Capability;

fn ceiling() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::CodeExecuting])
}

/// A slot that returns whatever it was built with, so a refusal path can be aimed at precisely.
struct FixedVerifier {
    slot: SlotId,
    decision: VerifierSlotDecision,
}

impl FixedVerifier {
    fn new(decision: VerifierSlotDecision) -> Self {
        Self {
            slot: SlotId("core/verifier".into()),
            decision,
        }
    }

    fn misnamed(decision: VerifierSlotDecision) -> Self {
        Self {
            slot: SlotId("core/tool_policy".into()),
            decision,
        }
    }
}

impl StrategySlot for FixedVerifier {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(self.decision.clone()).unwrap(),
        }
    }
}

#[test]
fn the_built_in_slot_honours_the_callers_floors() {
    let input = VerifierSlotObservation::gating(true);
    let proposal = VerifierStrategy::default()
        .plan(&input, ceiling())
        .expect("the built-in strategy plans");
    assert_eq!(proposal.plan.strength, OracleStrength::Strong);
    assert_eq!(proposal.plan.scope, VerifierScope::Workspace);
    assert!(proposal.plan.report_flake);
}

/// The seam #51 asked for: a different implementation, no kernel change, same guarantees.
#[test]
fn an_alternative_implementation_reaches_the_same_port() {
    let advisory = VerifierSlotObservation::advisory();
    let alternative = WorkspaceGateVerifier::default();
    let proposal = VerifierStrategy::plan_with(&alternative, &advisory, ceiling())
        .expect("a pinned alternative plans through the same port");
    // It strengthened past the advisory floor, which is allowed.
    assert_eq!(proposal.plan.strength, OracleStrength::Strong);
    assert_eq!(proposal.plan.scope, VerifierScope::Workspace);

    let gating = VerifierSlotObservation::gating(true);
    let proposal = VerifierStrategy::plan_with(&alternative, &gating, ceiling())
        .expect("a pinned alternative plans through the same port");
    assert_eq!(proposal.plan.attempts, 2, "it looks twice at a done claim");
    assert!(proposal.plan.report_flake);
}

#[test]
fn a_weakened_decision_is_refused_not_clamped() {
    let gating = VerifierSlotObservation::gating(false);

    let weaker = FixedVerifier::new(VerifierSlotDecision::Plan {
        plan: VerifierPlan {
            strength: OracleStrength::Weak,
            scope: VerifierScope::Workspace,
            attempts: 1,
            report_flake: true,
        },
    });
    assert_eq!(
        VerifierStrategy::plan_with(&weaker, &gating, ceiling()),
        Err(VerifierSlotError::DecisionWeakened(
            "verifier strength is below the caller's floor"
        ))
    );

    let narrower = FixedVerifier::new(VerifierSlotDecision::Plan {
        plan: VerifierPlan {
            strength: OracleStrength::Strong,
            scope: VerifierScope::Lane,
            attempts: 1,
            report_flake: true,
        },
    });
    assert_eq!(
        VerifierStrategy::plan_with(&narrower, &gating, ceiling()),
        Err(VerifierSlotError::DecisionWeakened(
            "verifier scope is narrower than the caller's floor"
        ))
    );
}

#[test]
fn a_retry_that_hides_the_disagreement_is_refused() {
    let gating = VerifierSlotObservation::gating(false);
    let silent = FixedVerifier::new(VerifierSlotDecision::Plan {
        plan: VerifierPlan {
            strength: OracleStrength::Strong,
            scope: VerifierScope::Workspace,
            attempts: 2,
            report_flake: false,
        },
    });
    assert_eq!(
        VerifierStrategy::plan_with(&silent, &gating, ceiling()),
        Err(VerifierSlotError::InvalidDecision(
            "a plan that retries must report the disagreement rather than absorb it"
        ))
    );

    let unbounded = FixedVerifier::new(VerifierSlotDecision::Plan {
        plan: VerifierPlan {
            strength: OracleStrength::Strong,
            scope: VerifierScope::Workspace,
            attempts: MAX_VERIFIER_ATTEMPTS + 1,
            report_flake: true,
        },
    });
    assert!(matches!(
        VerifierStrategy::plan_with(&unbounded, &gating, ceiling()),
        Err(VerifierSlotError::InvalidDecision(_))
    ));
}

#[test]
fn a_slot_with_the_wrong_identity_is_refused() {
    let gating = VerifierSlotObservation::gating(false);
    let wrong = FixedVerifier::misnamed(VerifierSlotDecision::Unknown);
    assert_eq!(
        VerifierStrategy::plan_with(&wrong, &gating, ceiling()),
        Err(VerifierSlotError::WrongSlot)
    );
}

#[test]
fn an_unrecognised_decision_degrades_rather_than_guessing() {
    let gating = VerifierSlotObservation::gating(false);
    let unknown = FixedVerifier::new(VerifierSlotDecision::Unknown);
    assert_eq!(
        VerifierStrategy::plan_with(&unknown, &gating, ceiling()),
        Err(VerifierSlotError::UnsupportedVersion)
    );

    let stale = VerifierSlotObservation {
        version: VERIFIER_SLOT_VERSION + 1,
        ..VerifierSlotObservation::gating(false)
    };
    assert_eq!(
        VerifierStrategy::default().plan(&stale, ceiling()),
        Err(VerifierSlotError::UnsupportedVersion)
    );
}

/// The acceptance criterion, and the fleet's lesson: a green lane is not an acceptance.
#[test]
fn a_lane_pass_with_a_failing_workspace_is_reported_as_a_failure() {
    let plan = VerifierPlan {
        strength: OracleStrength::Strong,
        scope: VerifierScope::Workspace,
        attempts: 1,
        report_flake: true,
    };
    let outcome = GateOutcome::gate(
        &plan,
        Some(VerificationOutcome::Pass),
        Some(VerificationOutcome::TestFailure),
    );
    assert_eq!(
        outcome,
        GateOutcome::Rejected {
            scope: VerifierScope::Workspace
        }
    );
    assert!(!outcome.accepted());

    // A workspace run that never answered is not an acceptance either, however green the lane.
    for missing in [
        None,
        Some(VerificationOutcome::TimedOut),
        Some(VerificationOutcome::InfrastructureFailure),
        Some(VerificationOutcome::Cancelled),
    ] {
        let outcome = GateOutcome::gate(&plan, Some(VerificationOutcome::Pass), missing);
        assert_eq!(
            outcome,
            GateOutcome::Indeterminate {
                scope: VerifierScope::Workspace
            },
            "a lane pass must not stand in for a missing workspace verdict"
        );
    }

    let both_green = GateOutcome::gate(
        &plan,
        Some(VerificationOutcome::Pass),
        Some(VerificationOutcome::Pass),
    );
    assert!(both_green.accepted());
}

#[test]
fn disagreeing_repeats_are_reported_rather_than_resolved_to_the_pass() {
    let plan = VerifierPlan {
        strength: OracleStrength::Strong,
        scope: VerifierScope::Workspace,
        attempts: 2,
        report_flake: true,
    };
    let flaky = GateOutcome::from_attempts(
        &plan,
        &[
            GateOutcome::Accepted,
            GateOutcome::Rejected {
                scope: VerifierScope::Workspace,
            },
        ],
    );
    assert_eq!(
        flaky,
        GateOutcome::Flaky {
            scope: VerifierScope::Workspace
        }
    );
    assert!(!flaky.accepted(), "a flake must never read as acceptance");

    let agreed = GateOutcome::from_attempts(&plan, &[GateOutcome::Accepted, GateOutcome::Accepted]);
    assert!(agreed.accepted());

    assert_eq!(
        GateOutcome::from_attempts(&plan, &[]),
        GateOutcome::Indeterminate {
            scope: VerifierScope::Workspace
        }
    );
}

/// A slot is a policy, never a source of authority.
#[test]
fn a_slot_cannot_return_authority_it_was_not_shown() {
    struct Greedy(SlotId);
    impl StrategySlot for Greedy {
        fn slot(&self) -> &SlotId {
            &self.0
        }
        fn decide(&self, _: &SlotObservation) -> SlotOutcome {
            SlotOutcome {
                admitted: CapabilitySet::from_iter_capabilities([
                    Capability::ReadOnly,
                    Capability::ReversibleLocal,
                    Capability::CodeExecuting,
                    Capability::TrustMutating,
                    Capability::IrreversibleExternal,
                ]),
                decision: serde_json::to_value(VerifierSlotDecision::Plan {
                    plan: VerifierPlan {
                        strength: OracleStrength::Strong,
                        scope: VerifierScope::Workspace,
                        attempts: 1,
                        report_flake: true,
                    },
                })
                .unwrap(),
            }
        }
    }

    let greedy = Greedy(SlotId("core/verifier".into()));
    let proposal =
        VerifierStrategy::plan_with(&greedy, &VerifierSlotObservation::gating(false), ceiling())
            .expect("the plan itself is valid");
    assert_eq!(
        proposal.eligible,
        ceiling(),
        "authority is intersected with the ceiling it was shown"
    );
    assert!(!proposal.eligible.contains(Capability::IrreversibleExternal));
}
