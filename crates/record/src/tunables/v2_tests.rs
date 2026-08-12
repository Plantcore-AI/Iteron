use super::*;
use crate::{Rollout, replay};
use iteron_protocol::{Effort, Event, EventKind, RunId, Seq, TenantId, TurnId};
use iteron_tunables::{
    Adjustment, AdjustmentKind, CapabilityRequirement, DefaultResolver, EntryOutcome,
    EvidenceSubject, ExternalCeiling, FixedAuthorityAttestation, FixedAuthorityId, InactiveCause,
    InactiveReason, ResolutionProvenance, ResolutionReport, ResolutionSource, ResolutionValue,
    ResolvedEntry, RouteIdentity, SourceKind, SourceTrust, canonical_embedded_default, families,
    fixed_authority_value_digest_sha256,
};

fn report() -> ResolutionReport {
    let mut entries = families()
        .iter()
        .map(|family| ResolvedEntry {
            ordinal: family.ordinal,
            family_id: family.id,
            semantic_key: family.semantic_key,
            requested: None,
            effective: None,
            provenance: None,
            outcome: EntryOutcome::Unavailable,
            adjustments: Vec::new(),
            shadowed: Vec::new(),
            default: family.default,
            strategy_slots: family.strategy_slots,
            optimization: family.optimization,
            benchmark_relevance: family.benchmark_relevance,
        })
        .collect::<Vec<_>>();
    entries[4].requested = Some(ResolutionValue::Integer { value: 10 });
    entries[4].effective = Some(ResolutionValue::Integer { value: 5 });
    entries[4].provenance = Some(ResolutionProvenance {
        source: ResolutionSource::Profile {
            kind: SourceKind::UserConfig,
            trust: SourceTrust::Operator,
            declared_locator: "config.max_turns",
            profile_digest_sha256: "e".repeat(64),
        },
    });
    entries[4].adjustments.push(Adjustment {
        kind: AdjustmentKind::ClampMaximum,
        field: "$".to_owned(),
        requested: ResolutionValue::Integer { value: 10 },
        effective: ResolutionValue::Integer { value: 5 },
        ceiling: ExternalCeiling::ParentTurns,
        policy_id: "iteron://tunables/clamp/fixture-v1",
        evidence_digest_sha256: "a".repeat(64),
        subject: EvidenceSubject::Global,
    });
    entries[4].outcome = EntryOutcome::Effective;
    entries[1].outcome = EntryOutcome::Inactive {
        cause: InactiveCause::Activation {
            reason: InactiveReason::ConfigurationAbsent,
        },
    };
    let mut report = ResolutionReport {
        schema_version: iteron_tunables::RESOLUTION_SCHEMA_VERSION,
        registry_id: iteron_tunables::REGISTRY_ID,
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256,
        input_digest_sha256: "b".repeat(64),
        effective_digest_sha256: String::new(),
        resolution_digest_sha256: "c".repeat(64),
        profile_digest_sha256: Some("e".repeat(64)),
        fixed_authority_attestations: Vec::new(),
        entries,
    };
    report.effective_digest_sha256 = snapshot_v2::effective_digest_from_report(&report).unwrap();
    report
}

fn report_with_effective_fixed_authority() -> ResolutionReport {
    let mut report = report();
    let family = families()
        .iter()
        .find(|family| family.id == "provider_discovery_account_probe_cache_policy")
        .expect("fixed bootstrap family");
    let value = canonical_embedded_default(family.id).expect("embedded bootstrap value");
    let entry = report
        .entries
        .iter_mut()
        .find(|entry| entry.family_id == family.id)
        .expect("complete report entry");
    entry.requested = Some(value.clone());
    entry.effective = Some(value.clone());
    entry.provenance = Some(ResolutionProvenance {
        source: ResolutionSource::Default {
            resolver_id: "iteron://tunables/resolvers/literal-v1".to_owned(),
            evidence_digest_sha256: None,
            subject: None,
            fallback: false,
        },
    });
    entry.outcome = EntryOutcome::Effective;
    report.fixed_authority_attestations = vec![FixedAuthorityAttestation {
        family_id: family.id.to_owned(),
        authority: FixedAuthorityId::ProviderDiscoveryBootstrap,
        owner_value_digest_sha256: fixed_authority_value_digest_sha256(
            family.id,
            FixedAuthorityId::ProviderDiscoveryBootstrap,
            &value,
        )
        .expect("fixed authority digest"),
    }];
    report.effective_digest_sha256 = snapshot_v2::effective_digest_from_report(&report).unwrap();
    report
}

fn root_start(parent: Option<(&RunId, Seq, String)>) -> Event {
    let (parent_run, forked_at, parent_hash_at_seq) = match parent {
        Some((run, at, hash)) => (Some(run.0.clone()), Some(at.0), Some(hash)),
        None => (None, None, None),
    };
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::RunStart {
            cwd: "/repo".into(),
            model: "model".into(),
            effort: Effort::Medium,
            created_at: 1,
            environment: None,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            config_digest: "d".repeat(64),
            agent_definition_tag: None,
            max_usd: None,
        },
    }
}

#[test]
fn v2_reconstructs_effective_and_explanation_truth_and_fails_closed_on_tamper() {
    let snapshot = snapshot_v2::snapshot_v2_from_report(&report()).unwrap();
    validate_tunables_snapshot_v2(&snapshot).unwrap();
    assert_eq!(snapshot.entries.len(), 160);
    assert_eq!(
        snapshot.entries[4].effective_value,
        Some(serde_json::json!({"type": "integer", "value": 5}))
    );
    assert!(snapshot.entries[4].profile_applied);
    assert_eq!(snapshot.entries[4].ceiling_adjustments.len(), 1);
    assert_eq!(
        snapshot.entries[4]
            .provenance
            .as_ref()
            .and_then(|value| value.pointer("/source/type"))
            .and_then(serde_json::Value::as_str),
        Some("profile")
    );
    assert_eq!(
        snapshot.entries[1]
            .inactive_reason
            .as_ref()
            .and_then(|value| value.get("type"))
            .and_then(serde_json::Value::as_str),
        Some("activation")
    );

    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(snapshot, decoded);

    let mut changed = snapshot.clone();
    changed.entries[4].effective_value = Some(serde_json::json!({
        "type": "integer",
        "value": 4
    }));
    assert_eq!(
        validate_tunables_snapshot_v2(&changed),
        Err(TunablesSnapshotError::Invalid {
            reason: "V2 effective values do not match the effective digest"
        })
    );

    let mut credential = snapshot;
    credential.entries[4].effective_value = Some(serde_json::json!({
        "type": "text",
        "value": format!("sk-{}", "x".repeat(80))
    }));
    assert_eq!(
        validate_tunables_snapshot_v2(&credential),
        Err(TunablesSnapshotError::Invalid {
            reason: "a V2 projection contains unbounded, control, or credential-shaped text"
        })
    );
}

#[test]
fn v2_fixed_authority_binding_is_bijective_and_rejects_missing_duplicate_and_tamper() {
    let report = report_with_effective_fixed_authority();
    let snapshot = snapshot_v2::snapshot_v2_from_report(&report)
        .expect("exact fixed authority projects into V2");
    validate_tunables_snapshot_v2(&snapshot).expect("exact fixed binding validates");
    let fixed = snapshot
        .entries
        .iter()
        .find(|entry| entry.family_id == "provider_discovery_account_probe_cache_policy")
        .and_then(|entry| entry.fixed_authority_binding.as_ref())
        .expect("effective fixed family carries one binding");
    assert_eq!(fixed.owner_value_digest_sha256.len(), 64);

    let mut missing_report = report.clone();
    missing_report.fixed_authority_attestations.clear();
    assert!(snapshot_v2::snapshot_v2_from_report(&missing_report).is_err());

    let mut duplicate_report = report.clone();
    duplicate_report
        .fixed_authority_attestations
        .push(duplicate_report.fixed_authority_attestations[0].clone());
    assert!(snapshot_v2::snapshot_v2_from_report(&duplicate_report).is_err());

    let fixed_index = snapshot
        .entries
        .iter()
        .position(|entry| entry.family_id == "provider_discovery_account_probe_cache_policy")
        .expect("fixed entry index");
    let mut wrong_authority = snapshot.clone();
    wrong_authority.entries[fixed_index]
        .fixed_authority_binding
        .as_mut()
        .expect("binding")
        .authority = iteron_protocol::RunGenesisFixedAuthorityIdV2::RuntimeInvariant;
    assert!(validate_tunables_snapshot_v2(&wrong_authority).is_err());

    let mut tampered_digest = snapshot;
    tampered_digest.entries[fixed_index]
        .fixed_authority_binding
        .as_mut()
        .expect("binding")
        .owner_value_digest_sha256 = "f".repeat(64);
    assert!(validate_tunables_snapshot_v2(&tampered_digest).is_err());
}

#[test]
fn public_resolved_fixture_projects_to_a_content_free_v2_snapshot() {
    let resolved = crate::resolved_fixture::resolved();
    let snapshot = snapshot_v2::snapshot_v2_from_report(resolved.report())
        .expect("the public production fixture must project to V2");
    validate_tunables_snapshot_v2(&snapshot)
        .expect("the public production fixture must remain content-free");
}

#[test]
fn public_resolved_fixture_uses_the_exact_embedded_value_for_builtin_literals() {
    let input = crate::resolved_fixture::input();
    for declared in input.declared_values {
        let family = families()
            .iter()
            .find(|family| family.id == declared.family)
            .expect("fixture family is canonical");
        if declared.source == SourceKind::Builtin
            && matches!(family.default.resolver, DefaultResolver::Literal)
        {
            assert_eq!(
                declared.value,
                canonical_embedded_default(family.id)
                    .expect("a literal family has an embedded value"),
                "{} must not manufacture a second Builtin literal",
                family.id
            );
        }
    }
}

#[test]
fn typed_route_revision_content_address_survives_but_credential_text_does_not() {
    let mut report = report();
    report.entries[3].outcome = EntryOutcome::Inactive {
        cause: InactiveCause::CapabilitiesMissing {
            route: Some(RouteIdentity {
                provider_id: "provider".into(),
                model_id: "model".into(),
                route_revision: format!("sha256:{}", "a".repeat(64)),
                catalog_digest_sha256: "b".repeat(64),
            }),
            capabilities: vec![CapabilityRequirement::ProviderReasoningControl],
        },
    };
    report.effective_digest_sha256 = snapshot_v2::effective_digest_from_report(&report).unwrap();
    let snapshot = snapshot_v2::snapshot_v2_from_report(&report)
        .expect("a typed content-addressed route revision is content-free identity");
    validate_tunables_snapshot_v2(&snapshot).unwrap();

    let EntryOutcome::Inactive {
        cause: InactiveCause::CapabilitiesMissing {
            route: Some(route), ..
        },
    } = &mut report.entries[3].outcome
    else {
        unreachable!()
    };
    route.route_revision = format!("sk-{}", "x".repeat(80));
    report.effective_digest_sha256 = snapshot_v2::effective_digest_from_report(&report).unwrap();
    assert_eq!(
        snapshot_v2::snapshot_v2_from_report(&report),
        Err(TunablesSnapshotError::Invalid {
            reason: "a V2 projection contains unbounded, control, or credential-shaped text"
        })
    );
}

#[test]
fn v2_is_physical_seq_one_and_untyped_fork_copies_and_binds_it() {
    let dir = std::env::temp_dir().join(format!(
        "iteron-record-v2-genesis-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let parent = RunId("v2-parent".into());
    let tenant = TenantId::default();
    let checkpoint =
        TunablesCheckpoint::V2(snapshot_v2::snapshot_v2_from_report(&report()).unwrap());
    {
        let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
        assert_eq!(
            rollout
                .append_genesis_checkpoint(&root_start(None), checkpoint.clone(), None)
                .unwrap(),
            (Seq::ZERO, Seq(1))
        );
    }
    let events = replay(&dir.join("v2-parent.jsonl")).unwrap();
    assert!(matches!(
        events[1].kind,
        EventKind::TunablesSnapshotV2 { .. }
    ));
    assert_eq!(
        checkpoint_from_events(&events).unwrap(),
        Some(checkpoint.clone())
    );

    let child = crate::fork(&dir, &parent, Seq(1), &tenant).expect("V2 fork");
    let child_events = replay(&dir.join(format!("{child}.jsonl"))).unwrap();
    let EventKind::TunablesSnapshotV2 {
        snapshot,
        inherited_from: Some(inherited),
        ..
    } = &child_events[1].kind
    else {
        panic!("child did not inherit V2 checkpoint")
    };
    assert_eq!(
        snapshot.snapshot_digest_sha256,
        checkpoint.snapshot_digest_sha256()
    );
    assert_eq!(inherited.parent_run, parent.0);
    assert_eq!(
        inherited.parent_snapshot_digest_sha256,
        checkpoint.snapshot_digest_sha256()
    );
}
