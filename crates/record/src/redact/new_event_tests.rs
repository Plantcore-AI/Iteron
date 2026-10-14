//! Actual writer/reopen evidence for newly typed events, independent of generic JSON scrubbing.
use super::{redact_event, scrub};
use crate::{RecordError, Rollout};
use iteron_protocol::agent_cohort::{AgentCohortInstallationV1, AgentCohortOriginV1};
use iteron_protocol::agent_control::{AgentEpochV1, AgentIdV1, AgentMessageIdV1};
use iteron_protocol::agent_input::{AgentInputAdmissionV1, AgentInputSourceV1};
use iteron_protocol::memory_reference::MemoryReferenceAdmissionV1;
use iteron_protocol::task_plan::{PlanStepStatusV1, PlanStepV1, TaskPlanSnapshotV1};
use iteron_protocol::turn_publication::{TurnFinalOutcomeV1, TurnPublicationFactV1};
use iteron_protocol::{EffectId, Effort, Event, EventKind, RunId, Seq, TenantId, TurnId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "iteron-record-new-redaction-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn event(kind: EventKind) -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind,
    }
}
fn installation() -> AgentCohortInstallationV1 {
    AgentCohortInstallationV1 {
        origin: AgentCohortOriginV1 {
            version: 1,
            tenant: TenantId("redaction-tenant".into()),
            run_id: RunId("original-root".into()),
            config_sha256: format!("sha256:{}", "a".repeat(64)),
        },
        installed_run: RunId("current-root".into()),
    }
}
fn admitted_input() -> AgentInputAdmissionV1 {
    AgentInputAdmissionV1 {
        version: 1,
        receiver: AgentIdV1(2),
        epoch: AgentEpochV1 {
            incarnation: 1,
            turn: 3,
        },
        projection_sha256: "b".repeat(64),
        sources: vec![AgentInputSourceV1 {
            message_id: AgentMessageIdV1(7),
            sender: AgentIdV1(1),
            content_sha256: "c".repeat(64),
        }],
    }
}
fn memory_reference() -> MemoryReferenceAdmissionV1 {
    MemoryReferenceAdmissionV1 {
        version: 1,
        deleted: false,
        record_id: format!("m-{}", "d".repeat(64)),
        record_revision: 2,
        record_sha256: "d".repeat(64),
        workspace_sha256: "e".repeat(64),
        source_sha256: "f".repeat(64),
        body_sha256: "1".repeat(64),
        message_sha256: "2".repeat(64),
    }
}
fn plan(secret: &str) -> TaskPlanSnapshotV1 {
    TaskPlanSnapshotV1 {
        version: 1,
        revision: 2,
        based_on_submission_seq: Seq(1),
        steps: vec![PlanStepV1 {
            description: format!("inspect source with {secret}"),
            status: PlanStepStatusV1::Pending,
        }],
        obligations: vec![format!("rotate {secret}")],
    }
}
fn secret() -> &'static str {
    concat!("sk-", "ant-api03-AbCdEfGhIjKlMnOpQrStUvWx")
}

#[test]
fn actual_writer_reopen_scrubs_plan_text_and_preserves_all_typed_receipts() {
    let directory = Directory::new();
    let run = RunId("current-root".into());
    let tenant = TenantId("redaction-tenant".into());
    let mut writer = Rollout::open(&directory.0, &run, tenant.clone()).unwrap();
    writer
        .append(&event(EventKind::RunStart {
            cwd: directory.0.to_string_lossy().into(),
            model: "fixture".into(),
            effort: Effort::Low,
            created_at: 1,
            environment: None,
            parent_run: None,
            forked_at: None,
            parent_hash_at_seq: None,
            config_digest: "fixture".into(),
            agent_definition_tag: None,
            max_usd: None,
        }))
        .unwrap();
    let effect_id = EffectId("fx1:t00000000:subagent:n0000".into());
    let kinds = vec![
        EventKind::AgentCohortInstalledV1 {
            installation: installation(),
        },
        EventKind::OrdinaryExtensionBindingsV1 {
            catalog_sha256: "3".repeat(64),
            bindings: 1,
        },
        EventKind::TaskPlanUpdatedV1 {
            plan: plan(secret()),
        },
        EventKind::AgentInputAdmittedV1 {
            admission: admitted_input(),
        },
        EventKind::MemoryReferenceAdmittedV1 {
            admission: memory_reference(),
        },
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 1 },
        },
        EventKind::ChildAccountingPendingV1 {
            effect_id: effect_id.clone(),
        },
        EventKind::ChildAccountingResolvedV1 { effect_id },
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::TurnFinalized {
                outcome: TurnFinalOutcomeV1::BudgetExhausted,
                budget_limit: Some("max_tokens".into()),
            },
        },
    ];
    let mut expected = Vec::new();
    for kind in kinds {
        let mut source = event(kind);
        let carries_plan_text = matches!(&source.kind, EventKind::TaskPlanUpdatedV1 { .. });
        let committed = writer.append(&source).unwrap();
        source.seq = committed;
        // Every non-plan payload must equal the original typed input, not another invocation
        // of the redactor under test. Plan text is checked independently below.
        expected.push((!carries_plan_text).then_some(source));
    }
    drop(writer);
    let reopened = Rollout::open_existing(&directory.0, &run, tenant).unwrap();
    drop(reopened);
    let path = directory.0.join(format!("{}.jsonl", run.0));
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains(secret()));
    assert!(raw.contains("[REDACTED"));
    let replay = crate::replay(&path).unwrap();
    assert_eq!(replay.len(), expected.len() + 1);
    for (actual, expected) in replay[1..].iter().zip(&expected) {
        if let Some(expected) = expected {
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
    }
    let EventKind::TaskPlanUpdatedV1 { plan: redacted } = &replay[3].kind else {
        panic!("plan tag changed")
    };
    redacted.validate().unwrap();
    assert_eq!(redacted.based_on_submission_seq, Seq(1));
    assert_eq!(redacted.steps[0].status, PlanStepStatusV1::Pending);
    assert_ne!(
        redacted.steps[0].description,
        plan(secret()).steps[0].description
    );
    let EventKind::MemoryReferenceAdmittedV1 { admission } = &replay[5].kind else {
        panic!("reference tag changed")
    };
    assert_eq!(admission, &memory_reference());
    assert_ne!(scrub(&admission.record_sha256), admission.record_sha256);
}

#[test]
fn secret_structural_identity_and_malformed_receipts_refuse_before_wal_append() {
    let directory = Directory::new();
    let run = RunId("refusals".into());
    let mut writer = Rollout::open(&directory.0, &run, TenantId::default()).unwrap();
    let path = directory.0.join("refusals.jsonl");
    let before = std::fs::read(&path).unwrap();
    for slot in 0..3 {
        let mut installation = installation();
        match slot {
            0 => installation.origin.tenant.0 = secret().into(),
            1 => installation.origin.run_id.0 = secret().into(),
            _ => installation.installed_run.0 = secret().into(),
        }
        assert!(matches!(
            writer.append(&event(EventKind::AgentCohortInstalledV1 { installation })),
            Err(RecordError::InvalidEventSchema { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let mut reference = memory_reference();
    reference.record_id = secret().into();
    let mut invalid_input = admitted_input();
    invalid_input.sources[0].content_sha256 = secret().into();
    let mut invalid_plan = plan("ordinary task text");
    invalid_plan.revision = 0;
    let invalid = vec![
        EventKind::MemoryReferenceAdmittedV1 {
            admission: reference,
        },
        EventKind::OrdinaryExtensionBindingsV1 {
            catalog_sha256: secret().into(),
            bindings: 1,
        },
        EventKind::AgentInputAdmittedV1 {
            admission: invalid_input,
        },
        EventKind::TaskPlanUpdatedV1 { plan: invalid_plan },
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::AnswerAvailable { message_seq: 0 },
        },
        EventKind::TurnPublicationV1 {
            fact: TurnPublicationFactV1::TurnFinalized {
                outcome: TurnFinalOutcomeV1::BudgetExhausted,
                budget_limit: Some(secret().into()),
            },
        },
        EventKind::ChildAccountingPendingV1 {
            effect_id: EffectId(secret().into()),
        },
        EventKind::ChildAccountingResolvedV1 {
            effect_id: EffectId(secret().into()),
        },
    ];
    for kind in invalid {
        assert!(matches!(
            writer.append(&event(kind)),
            Err(RecordError::InvalidEventSchema { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn direct_public_redactor_masks_structural_secrets_without_wal_preconditions() {
    for slot in 0..3 {
        let mut installation = installation();
        match slot {
            0 => installation.origin.tenant.0 = secret().into(),
            1 => installation.origin.run_id.0 = secret().into(),
            _ => installation.installed_run.0 = secret().into(),
        }
        // Shape validation alone permits these portable strings; this utility also serves
        // display callers that never submitted the event through the record writer.
        installation.validate().unwrap();
        let projected = redact_event(&event(EventKind::AgentCohortInstalledV1 { installation }));
        let encoded = serde_json::to_string(&projected).unwrap();
        assert!(!encoded.contains(secret()));
        assert!(encoded.contains("[REDACTED"));
    }
    for kind in [
        EventKind::ChildAccountingPendingV1 {
            effect_id: EffectId(secret().into()),
        },
        EventKind::ChildAccountingResolvedV1 {
            effect_id: EffectId(secret().into()),
        },
    ] {
        let encoded = serde_json::to_string(&redact_event(&event(kind))).unwrap();
        assert!(!encoded.contains(secret()));
        assert!(encoded.contains("[REDACTED"));
    }
}
