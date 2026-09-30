use super::{ContextRequestObservation, RequestContextEvidenceOwner, RequestContextScope};
use iteron_ctx::{ContextSourceClass, RequestEstimator};
use iteron_protocol::{Capability, Purity, ToolSpec, Trust, TurnId};
use sha2::{Digest, Sha256};

fn build(system: &str, tools: &[ToolSpec], trust: Trust) -> iteron_ctx::ContextLedger {
    let estimator = RequestEstimator::new();
    RequestContextEvidenceOwner::default()
        .build_request(
            TurnId(7),
            RequestContextScope {
                execution_window: Some(16_000),
                request_trust: trust,
                estimator: &estimator,
                file: None,
                image: None,
            },
            ContextRequestObservation {
                system,
                messages: &[],
                tools,
                images: &[],
                estimate: iteron_ctx::estimate_request_context(system, &[], tools),
                output_reserved_tokens: 200,
                elapsed_us: 0,
            },
        )
        .ledger
}

#[test]
fn effective_system_commitment_includes_injected_bytes_without_retaining_content() {
    let canary = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let effective = format!("kernel prefix\nproject facts\napi_key={canary}");
    let ledger = build(&effective, &[], Trust::Untrusted);
    let system = ledger
        .segments
        .iter()
        .find(|segment| segment.source_class == ContextSourceClass::KernelSystem)
        .unwrap();
    assert_eq!(
        system.source_digest_sha256,
        <[u8; 32]>::from(Sha256::digest(effective.as_bytes()))
    );
    assert_ne!(
        system.source_digest_sha256,
        <[u8; 32]>::from(Sha256::digest(b"kernel prefix"))
    );
    assert_eq!(system.bytes_after, effective.len() as u64);
    assert_eq!(system.trust, Trust::Untrusted);
    assert!(!serde_json::to_string(&ledger).unwrap().contains(canary));
}

#[test]
fn distinct_schema_field_boundaries_cannot_share_the_same_request_commitment() {
    let schema = serde_json::json!({"type":"object"});
    let first = [ToolSpec {
        name: "a".into(),
        description: "bc".into(),
        input_schema: schema.clone(),
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    }];
    let second = [ToolSpec {
        name: "ab".into(),
        description: "c".into(),
        input_schema: schema,
        purity: Purity::Pure,
        capability: Capability::ReadOnly,
    }];
    let identity = |tools: &[ToolSpec]| {
        build("system", tools, Trust::Trusted)
            .segments
            .into_iter()
            .find(|segment| segment.source_class == ContextSourceClass::ToolSchema)
            .unwrap()
            .source_digest_sha256
    };
    assert_ne!(identity(&first), identity(&second));
}

#[test]
fn materialization_overflow_remains_visible_and_does_not_grow_the_source_owner() {
    let estimator = RequestEstimator::new();
    let mut owner = RequestContextEvidenceOwner::default();
    owner.replace_recorded("one actual recorded context", Trust::Workspace, &estimator);
    let source = owner.segments()[0].clone();
    let audit = iteron_ctx::ContextMaterializationAudit {
        segments: vec![source; iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS + 5],
        dropped: 2,
        ..Default::default()
    };
    owner.replace_materialized(&audit, 9);
    assert_eq!(
        owner.segments().len(),
        iteron_ctx::MAX_CONTEXT_LEDGER_SEGMENTS
    );
    let request = owner.build_request(
        TurnId(8),
        RequestContextScope {
            execution_window: None,
            request_trust: Trust::Workspace,
            estimator: &estimator,
            file: None,
            image: None,
        },
        ContextRequestObservation {
            system: "system",
            messages: &[],
            tools: &[],
            images: &[],
            estimate: iteron_ctx::estimate_request_context("system", &[], &[]),
            output_reserved_tokens: 10,
            elapsed_us: 0,
        },
    );
    assert!(request.ledger.dropped >= 7);
    owner.clear();
    assert!(owner.segments().is_empty());
}
