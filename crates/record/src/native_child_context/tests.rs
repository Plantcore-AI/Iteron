use super::*;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{
    Event, EventKind, PermissionMode, PermissionRules, PricingRoute, RunId, TenantId, TurnId,
};
#[test]
fn actual_native_context_record_requires_exact_scope_sequence_and_chain() {
    let root = std::env::temp_dir().join(format!(
        "iteron-native-context-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut writer = crate::Rollout::open(
        &root,
        &RunId("native-source".into()),
        TenantId("tenant".into()),
    )
    .unwrap();
    writer
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::Notice {
                text: "actual host publication".into(),
            },
        })
        .unwrap();
    let mut context = NativeChildContextV1 {
        version: 1,
        generation_sha256: String::new(),
        base_sha256: format!("sha256:{}", "a".repeat(64)),
        publication_sequence: writer.next_sequence().0,
        tenant: "tenant".into(),
        run: "native-source".into(),
        scope_sha256: iteron_protocol::agent_cohort::provider_scope(
            &TenantId("tenant".into()),
            &RunId("native-source".into()),
        ),
        route: PricingRoute {
            provider_id: "fixture".into(),
            model_id: "model".into(),
            catalog_digest: String::new(),
            capability_digest: String::new(),
        },
        context_window: Some(100_000),
        output_cap: Some(1000),
        permission_mode: PermissionMode::default(),
        permission_rules: PermissionRules::new(),
        authority_ceiling: CapabilitySet::none(),
        policy_capabilities: CapabilitySet::none(),
        bypass_permissions: false,
        default_effort: Default::default(),
    };
    context.generation_sha256 = context.digest().unwrap();
    let seq = writer
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::NativeChildContextCapturedV1 {
                context: context.clone(),
            },
        })
        .unwrap();
    let reference = NativeChildContextRefV1 {
        generation_sha256: context.generation_sha256.clone(),
        tenant: "tenant".into(),
        run: "native-source".into(),
        sequence: seq.0,
    };
    let bytes = std::fs::read(writer.path()).unwrap();
    assert_eq!(read_reference(&bytes, &reference).unwrap(), context);
    let mut wrong = reference.clone();
    wrong.sequence = 0;
    assert!(read_reference(&bytes, &wrong).is_err());
    wrong = reference.clone();
    wrong.tenant = "foreign".into();
    assert!(read_reference(&bytes, &wrong).is_err());
    let mut tampered = bytes.clone();
    let offset = tampered.iter().position(|byte| *byte == b'a').unwrap();
    tampered[offset] = b'c';
    assert!(read_reference(&tampered, &reference).is_err());
    assert!(read_reference(&bytes[..bytes.len() - 1], &reference).is_err());
    drop(writer);
    std::fs::remove_dir_all(root).unwrap();
}
