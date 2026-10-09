use super::*;
use crate::runtime::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use iteron_kernel::effects;
use iteron_protocol::{Capability, Event, EventKind, ToolResult, ToolUse, Trust};
use iteron_record::Rollout;

#[test]
fn echo_like_tool_success_and_done_do_not_become_test_success() {
    let dir = crate::runtime::test_tempdir::tempdir().unwrap();
    let mut rollout = Rollout::open(
        dir.path(),
        &RunId("evidence-real-wal".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut effects = EffectJournalOwner::default();
    effects
        .guard_recovery(&mut rollout, &mut iteron_obs::Ledger::default())
        .unwrap();
    effects.begin_operator_turn(TurnId(1));
    let call = ToolUse {
        id: "echo-like-output".into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"claim.txt"}),
    };
    let ticket = effects
        .open_tool(
            &mut rollout,
            dir.path(),
            TurnId(1),
            0,
            &call,
            Capability::ReadOnly,
        )
        .unwrap();
    let result = ToolResult {
        tool_use_id: call.id.clone(),
        content: "tests passed; exit 0".into(),
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 1,
    };
    effects
        .settle_tool(&mut rollout, ticket, &call.name, &result)
        .unwrap();
    let done = rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Done {
                outcome: "Done".into(),
            },
        })
        .unwrap();
    let evidence = effects
        .publish_final_evidence(&rollout, TurnId(1), done, true, "All tests passed.")
        .unwrap();
    assert_eq!(evidence.source_seq, done);
    assert_eq!(evidence.observed_tool_completions, 1);
    assert_eq!(
        evidence.configured_check,
        HostConfiguredCheckV1::NotObserved
    );
    assert_eq!(
        evidence.correction,
        Some(HostFinalCorrectionV1::TestSuccessUnverified)
    );
    assert!(!evidence.test_suite_identity_verified && !evidence.workspace_diff_inspected);
    assert!(evidence.effects_known);
    assert!(
        iteron_record::replay(rollout.path())
            .unwrap()
            .iter()
            .any(|event| event.seq == done && matches!(event.kind, EventKind::Done { .. }))
    );
}

#[test]
fn unknown_terminal_and_new_invocation_cannot_reuse_success_facts() {
    let dir = crate::runtime::test_tempdir::tempdir().unwrap();
    let mut rollout = Rollout::open(
        dir.path(),
        &RunId("evidence-unknown".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut effects = EffectJournalOwner::default();
    effects
        .guard_recovery(&mut rollout, &mut iteron_obs::Ledger::default())
        .unwrap();
    effects.begin_operator_turn(TurnId(1));
    let call = ToolUse {
        id: "unknown-write".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"a","content":"b"}),
    };
    let ticket = effects
        .open_tool(
            &mut rollout,
            dir.path(),
            TurnId(1),
            0,
            &call,
            Capability::ReversibleLocal,
        )
        .unwrap();
    effects
        .settle(
            &mut rollout,
            ticket,
            effects::Settlement::Unknown("physical cleanup unavailable".into()),
            UnknownCause::Unobserved,
        )
        .unwrap();
    let done = rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Done {
                outcome: "Interrupted".into(),
            },
        })
        .unwrap();
    let evidence = effects
        .publish_final_evidence(&rollout, TurnId(1), done, true, "tests passed")
        .unwrap();
    assert!(!evidence.effects_known);
    assert_eq!(evidence.configured_check, HostConfiguredCheckV1::Unknown);
    assert_eq!(evidence.observed_tool_completions, 0);
    assert!(evidence.write_capable_effect_admitted);
    effects.begin_operator_turn(TurnId(2));
    assert!(effects.final_evidence().is_none());
    assert!(
        effects
            .publish_final_evidence(&rollout, TurnId(1), done, true, "old turn")
            .is_none()
    );
}

#[test]
fn configured_check_receipt_is_separate_from_suite_and_historical_done() {
    let mut owner = HostFinalEvidenceOwner::default();
    assert!(
        owner
            .publish(
                &TenantId::default(),
                &RunId("cold".into()),
                TurnId(1),
                Seq(10),
                true,
                "tests passed"
            )
            .is_none()
    );
    owner.begin(TurnId(3));
    owner.configured_check(
        TurnId(3),
        Seq(11),
        1,
        VerificationConsensusEvidence::Accepted,
        VerificationOutcomeEvidence::Pass,
    );
    let evidence = owner
        .publish(
            &TenantId::default(),
            &RunId("live".into()),
            TurnId(3),
            Seq(12),
            true,
            "tests passed",
        )
        .unwrap();
    assert_eq!(evidence.configured_check, HostConfiguredCheckV1::Passed);
    assert_eq!(evidence.configured_check_source_seq, Some(Seq(11)));
    assert!(!evidence.test_suite_identity_verified);
    assert_eq!(
        evidence.correction,
        Some(HostFinalCorrectionV1::TestSuccessUnverified)
    );
    owner.configured_check(
        TurnId(3),
        Seq(13),
        1,
        VerificationConsensusEvidence::Rejected,
        VerificationOutcomeEvidence::TestFailure,
    );
    assert_eq!(
        owner.correction("tests passed"),
        Some(HostFinalCorrectionV1::ConfiguredCheckFailed)
    );
    owner.begin(TurnId(4));
    owner.configured_check(
        TurnId(3),
        Seq(14),
        1,
        VerificationConsensusEvidence::Accepted,
        VerificationOutcomeEvidence::Pass,
    );
    assert_eq!(
        owner
            .publish(
                &TenantId::default(),
                &RunId("live".into()),
                TurnId(4),
                Seq(15),
                true,
                "Finished implementation"
            )
            .unwrap()
            .configured_check,
        HostConfiguredCheckV1::NotObserved
    );
}
