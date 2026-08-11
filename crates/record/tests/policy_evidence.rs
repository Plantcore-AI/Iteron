use iteron_protocol::{
    Event, EventKind, PolicyActionId, PolicyActionV1, PolicyDecisionDisposition,
    PolicyDecisionEvidence, PolicyOpportunityId, PolicyOutcomeEvidence, PolicyOutcomeScope,
    PolicyRuntimeIdentity, PolicyTerminalOutcome, PolicyVerifierOutcome, RunId, Seq, TenantId,
    TurnId,
    policy_evidence::{
        POLICY_DECISION_EVIDENCE_SCHEMA_VERSION, POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
    },
    slot::SlotId,
};
use iteron_record::{Rollout, replay};
use std::path::PathBuf;

fn tmpdir() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "core-policy-evidence-{}-{nonce}",
        std::process::id()
    ))
}

fn identity() -> PolicyRuntimeIdentity {
    PolicyRuntimeIdentity {
        bundle_id: "iteron:baseline".into(),
        bundle_digest_sha256: "a".repeat(64),
        policy_id: "iteron://policies/router/baseline-v1".into(),
        policy_version: "1.0.0".into(),
        policy_digest_sha256: "b".repeat(64),
    }
}

fn decision() -> PolicyDecisionEvidence {
    let slot = SlotId("core/router".into());
    PolicyDecisionEvidence {
        schema_version: POLICY_DECISION_EVIDENCE_SCHEMA_VERSION,
        opportunity_id: PolicyOpportunityId("route:0".into()),
        run_id: RunId("run-policy".into()),
        turn_id: Some(TurnId(1)),
        slot: slot.clone(),
        policy: identity(),
        eligible_actions: vec![
            PolicyActionId::for_slot(&slot, PolicyActionV1::RouterDirect).unwrap(),
        ],
        selected_action: Some(
            PolicyActionId::for_slot(&slot, PolicyActionV1::RouterDirect).unwrap(),
        ),
        disposition: PolicyDecisionDisposition::Selected,
        selected_score_micros: None,
        propensity_ppm: Some(1_000_000),
        feature_schema_id: "iteron:router-features-v1".into(),
        feature_digest_sha256: "c".repeat(64),
        fixed_invariants_digest_sha256: "d".repeat(64),
        tunables_digest_sha256: "e".repeat(64),
        decision_ordinal: 0,
        decided_at_us: 1,
    }
}

fn outcome() -> PolicyOutcomeEvidence {
    PolicyOutcomeEvidence {
        schema_version: POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
        scope: PolicyOutcomeScope::Turn,
        run_id: RunId("run-policy".into()),
        turn_id: Some(TurnId(1)),
        terminal: PolicyTerminalOutcome::Succeeded,
        opportunity_count: 1,
        opportunities_digest_sha256: "f".repeat(64),
        quality_micros: None,
        cost_microusd: Some(42),
        input_tokens: Some(100),
        output_tokens: Some(10),
        latency_us: 123,
        verifier: PolicyVerifierOutcome::Passed,
        harness_error_code: None,
        outcome_ordinal: 0,
    }
}

#[test]
fn valid_policy_evidence_roundtrips_and_invalid_selection_never_enters_record() {
    let dir = tmpdir();
    let run = RunId("run-policy".into());
    let tenant = TenantId::default();
    let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::PolicyDecision {
                evidence: decision(),
            },
        })
        .unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::PolicyOutcome {
                evidence: outcome(),
            },
        })
        .unwrap();

    let mut invalid = decision();
    invalid.selected_action =
        Some(PolicyActionId::for_slot(&invalid.slot, PolicyActionV1::RouterFanOut).unwrap());
    assert!(
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::PolicyDecision { evidence: invalid },
            })
            .is_err()
    );
    drop(rollout);

    let events = replay(&dir.join("run-policy.jsonl")).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0].kind, EventKind::PolicyDecision { .. }));
    assert!(matches!(events[1].kind, EventKind::PolicyOutcome { .. }));
    std::fs::remove_dir_all(dir).unwrap();
}
