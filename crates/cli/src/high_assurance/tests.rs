use super::journal::HighAssuranceJournal;
use super::owner::{HighAssuranceAdmission, HighAssuranceOwner};
use super::types::{
    HighAssurancePolicy, HighAssuranceProfileV1, HighAssuranceScope, HumanApprovalChallengeV1,
    HumanEnrollmentV1, SignedHumanApprovalV1,
};
use ed25519_dalek::{Signer, SigningKey};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::{
    Capability, EventKind, RunId, TenantId, ToolUse, capability_set::CapabilitySet,
};
use iteron_record::Rollout;
use std::sync::Arc;

fn directory() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "iteron-two-human-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn configuration() -> HighAssuranceProfileV1 {
    HighAssuranceProfileV1 {
        version: 1,
        profile_id: "explicit-high-assurance".into(),
        humans: [("human-a", [71; 32]), ("human-b", [72; 32])]
            .into_iter()
            .map(|(subject, key)| HumanEnrollmentV1 {
                subject: subject.into(),
                public_key_hex: hex::encode(
                    SigningKey::from_bytes(&key).verifying_key().to_bytes(),
                ),
            })
            .collect(),
        approval_ttl_secs: 30,
        max_cost_microusd: 100_000,
        verifier_commands: vec!["cargo check --locked".into()],
        verifier_timeout_secs: 15,
        max_verifier_runs: 2,
    }
}
fn approve(
    owner: &HighAssuranceOwner,
    challenge: &HumanApprovalChallengeV1,
    subject: &str,
    key: [u8; 32],
    now: u64,
) -> Result<(), &'static str> {
    let signature = SigningKey::from_bytes(&key).sign(&challenge.signing_bytes()?);
    owner.approve(
        SignedHumanApprovalV1 {
            version: 1,
            subject: subject.into(),
            challenge: challenge.clone(),
            signature_hex: hex::encode(signature.to_bytes()),
        },
        now,
    )
}
fn call() -> ToolUse {
    ToolUse {
        id: "first-call".into(),
        name: "write_file".into(),
        input: serde_json::json!({"path":"result.txt","content":"exact approved change"}),
    }
}

#[test]
fn two_actual_signatures_authorize_one_exact_operation_only_after_real_durable_audit() {
    let directory = directory();
    let run = RunId("authorization".into());
    let tenant = TenantId::default();
    let policy = Arc::new(HighAssurancePolicy::from_operator(configuration()).unwrap());
    let scope = HighAssuranceScope::from_host(tenant.clone(), run.clone(), &directory).unwrap();
    let owner = HighAssuranceOwner::from_host(policy.clone(), scope.clone());
    let mut rollout = Rollout::open(&directory, &run, tenant.clone()).unwrap();
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    rollout
        .append(&iteron_protocol::Event {
            seq: iteron_protocol::Seq::ZERO,
            turn: iteron_protocol::TurnId(0),
            kind: EventKind::Notice {
                text: "fixture prefix".into(),
            },
        })
        .unwrap();
    let mut journal = HighAssuranceJournal {
        rollout: &mut rollout,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
    };
    let required = CapabilitySet::only(Capability::ReversibleLocal);
    let HighAssuranceAdmission::Pending { challenge, .. } = owner
        .authorize(
            &call(),
            required,
            iteron_protocol::TurnId(1),
            10,
            &mut journal,
        )
        .unwrap()
    else {
        panic!("two human signatures required")
    };
    approve(&owner, &challenge, "human-a", [71; 32], 11).unwrap();
    // Two client submissions of the same authenticated human remain one human.
    approve(&owner, &challenge, "human-a", [71; 32], 11).unwrap();
    assert!(matches!(
        owner
            .authorize(
                &call(),
                required,
                iteron_protocol::TurnId(1),
                12,
                &mut journal
            )
            .unwrap(),
        HighAssuranceAdmission::Pending {
            authenticated_humans: 1,
            ..
        }
    ));
    assert!(approve(&owner, &challenge, "human-b", [71; 32], 12).is_err());
    approve(&owner, &challenge, "human-b", [72; 32], 12).unwrap();
    assert!(
        matches!(owner.authorize(&call(),required,iteron_protocol::TurnId(1),13,&mut journal).unwrap(),HighAssuranceAdmission::Authorized {audit_seq} if audit_seq>0)
    );
    let rows = iteron_record::replay(journal.rollout.path()).unwrap();
    assert_eq!(rows.len(), 2);
    let EventKind::Notice { text } = &rows[1].kind else {
        panic!("actual audit barrier")
    };
    let audit: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        audit["signer_commitments_sha256"].as_array().unwrap().len(),
        2
    );
    assert!(!text.contains("exact approved change"));
    assert!(!text.contains("human-a"));
    assert!(matches!(
        owner
            .authorize(
                &call(),
                required,
                iteron_protocol::TurnId(1),
                14,
                &mut journal
            )
            .unwrap(),
        HighAssuranceAdmission::Pending {
            authenticated_humans: 0,
            ..
        }
    ));
    assert!(approve(&owner, &challenge, "human-a", [71; 32], 14).is_err());
    drop(journal);
    drop(rollout);
    let reopened = Rollout::open_existing(&directory, &run, tenant).unwrap();
    assert_eq!(iteron_record::replay(reopened.path()).unwrap().len(), 2);
    // Actual WAL receipts remain audit evidence, never a recovered permission grant.
    let restarted = HighAssuranceOwner::from_host(policy, scope);
    assert!(restarted.view(14).unwrap().pending.is_empty());
    assert!(approve(&restarted, &challenge, "human-a", [71; 32], 14).is_err());
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scope_expiry_operation_mutation_and_untrusted_human_alias_cannot_reuse_approval() {
    let directory = directory();
    let run = RunId("scope".into());
    let tenant = TenantId::default();
    let owner = HighAssuranceOwner::from_host(
        Arc::new(HighAssurancePolicy::from_operator(configuration()).unwrap()),
        HighAssuranceScope::from_host(tenant.clone(), run.clone(), &directory).unwrap(),
    );
    let mut rollout = Rollout::open(&directory, &run, tenant).unwrap();
    let mut ledger = Ledger::default();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut journal = HighAssuranceJournal {
        rollout: &mut rollout,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
    };
    let required = CapabilitySet::only(Capability::ReversibleLocal);
    let HighAssuranceAdmission::Pending { challenge, .. } = owner
        .authorize(
            &call(),
            required,
            iteron_protocol::TurnId(1),
            10,
            &mut journal,
        )
        .unwrap()
    else {
        panic!()
    };
    assert!(approve(&owner, &challenge, "unverified-client-id", [71; 32], 11).is_err());
    let mut foreign = challenge.clone();
    foreign.scope_sha256 = "a".repeat(64);
    assert!(approve(&owner, &foreign, "human-a", [71; 32], 11).is_err());
    approve(&owner, &challenge, "human-a", [71; 32], 11).unwrap();
    approve(&owner, &challenge, "human-b", [72; 32], 11).unwrap();
    let mut altered = call();
    altered.input["path"] = "other.txt".into();
    assert!(matches!(
        owner
            .authorize(
                &altered,
                required,
                iteron_protocol::TurnId(1),
                12,
                &mut journal
            )
            .unwrap(),
        HighAssuranceAdmission::Pending {
            authenticated_humans: 0,
            ..
        }
    ));
    assert!(approve(&owner, &challenge, "human-a", [71; 32], 40).is_err());
    assert!(matches!(
        owner
            .authorize(
                &call(),
                required,
                iteron_protocol::TurnId(2),
                40,
                &mut journal
            )
            .unwrap(),
        HighAssuranceAdmission::Pending {
            authenticated_humans: 0,
            ..
        }
    ));
    assert!(
        iteron_record::replay(journal.rollout.path())
            .unwrap()
            .is_empty()
    );
    drop(journal);
    drop(rollout);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn duplicate_enrollment_key_is_not_a_second_human_and_verifier_admissions_are_finite() {
    let mut config = configuration();
    config.humans[1].public_key_hex = config.humans[0].public_key_hex.clone();
    assert!(HighAssurancePolicy::from_operator(config).is_err());
    let directory = directory();
    let owner = HighAssuranceOwner::from_host(
        Arc::new(HighAssurancePolicy::from_operator(configuration()).unwrap()),
        HighAssuranceScope::from_host(TenantId::default(), RunId("verifier".into()), &directory)
            .unwrap(),
    );
    let run = RunId("verifier".into());
    let mut rollout = Rollout::open(&directory, &run, TenantId::default()).unwrap();
    let mut admissions = iteron_kernel::effect_admission::EffectAdmissions::default();
    let mut make_ticket = |ordinal| {
        iteron_kernel::effects::open_effect(
            &mut rollout,
            &mut admissions,
            iteron_kernel::effects::BrokeredEffect {
                turn: iteron_protocol::TurnId(1),
                effect_id: iteron_protocol::EffectId(format!("vf-1-{ordinal}")),
                tool_use_id: format!("verify-correlation-{ordinal}"),
                kind: "verify".into(),
                capability: Capability::CodeExecuting,
                audit_arguments: serde_json::json!({"command_sha256":"a".repeat(64)}),
                workspace: "fixture".into(),
                provider_route_attempt: None,
            },
        )
        .unwrap()
    };
    let first = make_ticket(1);
    let second = make_ticket(2);
    let third = make_ticket(3);
    assert!(
        owner
            .observe_verifier_terminal(first.effect_id(), Some(1))
            .is_err()
    );
    owner.admit_verifier(&first).unwrap();
    owner
        .observe_verifier_terminal(first.effect_id(), Some(7))
        .unwrap();
    assert!(
        owner
            .observe_verifier_terminal(first.effect_id(), Some(7))
            .is_err()
    );
    owner.admit_verifier(&second).unwrap();
    assert!(owner.admit_verifier(&third).is_err());
    assert_eq!(owner.view(1).unwrap().verifier_admissions, 2);
    assert_eq!(owner.view(1).unwrap().verifier_wall_ms, Some(7));
    let recovered = HighAssuranceOwner::from_host(
        owner.policy().clone(),
        HighAssuranceScope::from_host(TenantId::default(), run, &directory).unwrap(),
    );
    assert!(
        recovered
            .recover_verified_verifiers(&iteron_record::replay(rollout.path()).unwrap())
            .is_err()
    );
    drop(rollout);
    std::fs::remove_dir_all(directory).unwrap();
}
