use super::*;
use crate::config::ConfigOrigin;
use iteron_evolve::{PolicyBundle, PolicyRef, StrategySlot as EvolveSlot};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::SlotObservation;
use iteron_protocol::{Capability, Purity, ToolUse, Trust};
use serde::Serialize;
use serde_json::json;

fn alternative_id(slot: CoreSlot) -> &'static str {
    match slot {
        CoreSlot::Context => "minimal-context",
        CoreSlot::ToolPolicy => "read-only-tools",
        CoreSlot::Memory => "single-memory-recall",
        CoreSlot::Router => "direct-only",
        CoreSlot::Planner => "single-leaf",
        CoreSlot::Collaboration => "serial-collaboration",
        CoreSlot::Scheduler => "serial-scheduler",
        CoreSlot::Verifier => "workspace-gate",
        CoreSlot::ModelRouter => "bound-route-only",
    }
}

fn identity(slot: CoreSlot, policy_id: &str) -> ImplementationIdentity {
    registered_implementations()
        .unwrap()
        .into_iter()
        .find(|identity| identity.slot == slot.as_str() && identity.policy_id == policy_id)
        .expect("test identity is registered")
}

fn policy(slot: CoreSlot, policy_id: &str) -> PolicyRef {
    let identity = identity(slot, policy_id);
    PolicyRef {
        slot: EvolveSlot::new(slot.as_str()).unwrap(),
        policy_id: identity.policy_id,
        version: identity.version,
        digest: identity.digest,
    }
}

fn bundle(policies: Vec<PolicyRef>) -> PolicyBundle {
    PolicyBundle {
        bundle_id: "operator-active".into(),
        digest: "a".repeat(64),
        policies,
        rollback_to: None,
    }
}

fn all_alternatives() -> PolicyBundle {
    bundle(
        CoreSlot::ALL
            .into_iter()
            .map(|slot| policy(slot, alternative_id(slot)))
            .collect(),
    )
}

#[test]
fn registry_has_baseline_and_non_baseline_for_every_slot() {
    let catalog = registered_implementations().unwrap();
    assert!(catalog.len() <= schema::MAX_REGISTERED_IMPLEMENTATIONS);
    for slot in CoreSlot::ALL {
        let entries = catalog
            .iter()
            .filter(|entry| entry.slot == slot.as_str())
            .collect::<Vec<_>>();
        assert!(entries.iter().any(|entry| entry.baseline), "{slot:?}");
        assert!(entries.iter().any(|entry| !entry.baseline), "{slot:?}");
        assert!(entries.iter().all(|entry| {
            entry.artifact_bytes as usize <= schema::MAX_IMPLEMENTATION_ARTIFACT_BYTES
        }));
    }
}

#[test]
fn nine_requested_slots_compile_once_as_full_with_a_stable_receipt() {
    let first = compile_configured_bundle(Some(&all_alternatives()), ConfigOrigin::UserConfig)
        .expect("known operator bundle compiles");
    let mut reordered = all_alternatives();
    reordered.policies.reverse();
    let second = compile_configured_bundle(Some(&reordered), ConfigOrigin::UserConfig)
        .expect("input order does not change compilation");
    assert_eq!(first.receipt().coverage, BundleCoverage::Full);
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first.receipt().slots.len(), CoreSlot::ALL.len());
    assert!(first.receipt().rejected_requests.is_empty());
    assert!(
        first
            .receipt()
            .slots
            .iter()
            .all(|row| row.requested && row.status == SlotReceiptStatus::Applied)
    );
}

#[test]
fn absent_and_partial_bundles_are_never_reported_full() {
    let baseline = compile_configured_bundle(None, ConfigOrigin::UserConfig).unwrap();
    assert_eq!(baseline.receipt().coverage, BundleCoverage::Baseline);
    assert_eq!(
        baseline.policy_runtime_bindings().len(),
        CoreSlot::ALL.len()
    );
    let bundle_id = &baseline.policy_runtime_bindings()[0].policy.bundle_id;
    let bundle_digest = &baseline.policy_runtime_bindings()[0]
        .policy
        .bundle_digest_sha256;
    assert_eq!(bundle_id, registry::BASELINE_BUNDLE_ID);
    assert_eq!(bundle_digest.len(), 64);
    assert!(baseline.receipt().slots.iter().all(|row| {
        !row.requested
            && row.status == SlotReceiptStatus::Baseline
            && row.policy_id.as_deref() == Some("baseline")
            && row.version.as_deref() == Some("1")
            && row.digest.as_ref().is_some_and(|digest| digest.len() == 64)
    }));
    assert!(baseline.policy_runtime_bindings().iter().all(|binding| {
        binding.policy.bundle_id == *bundle_id
            && binding.policy.bundle_digest_sha256 == *bundle_digest
            && binding.policy.validate().is_ok()
    }));
    let one = bundle(vec![policy(CoreSlot::Router, "direct-only")]);
    let partial = compile_configured_bundle(Some(&one), ConfigOrigin::UserConfig).unwrap();
    assert_eq!(partial.receipt().coverage, BundleCoverage::Partial);
    assert_eq!(
        partial
            .receipt()
            .slots
            .iter()
            .filter(|row| row.requested)
            .count(),
        1
    );
}

#[test]
fn unknown_identity_version_and_digest_fail_closed() {
    let mut unknown = policy(CoreSlot::Context, "minimal-context");
    unknown.policy_id = "not-in-this-build".into();
    assert_rejected(bundle(vec![unknown]), RejectionCode::UnknownImplementation);

    let mut version = policy(CoreSlot::Context, "minimal-context");
    version.version = "2".into();
    assert_rejected(bundle(vec![version]), RejectionCode::UnknownVersion);

    let mut digest = policy(CoreSlot::Context, "minimal-context");
    digest.digest = "f".repeat(64);
    assert_rejected(bundle(vec![digest]), RejectionCode::DigestMismatch);
}

#[test]
fn malformed_duplicate_unknown_slot_and_project_selection_fail_closed() {
    let mut malformed = bundle(vec![policy(CoreSlot::Context, "minimal-context")]);
    malformed.bundle_id.clear();
    assert_rejected(malformed, RejectionCode::MalformedBundle);

    let duplicate = policy(CoreSlot::Context, "minimal-context");
    assert_rejected(
        bundle(vec![duplicate.clone(), duplicate]),
        RejectionCode::DuplicateSlot,
    );

    let future = PolicyRef {
        slot: EvolveSlot::new("core/future").unwrap(),
        policy_id: "future".into(),
        version: "1".into(),
        digest: "b".repeat(64),
    };
    assert_rejected(bundle(vec![future]), RejectionCode::UnknownSlot);

    let project = all_alternatives();
    let failure = compile_configured_bundle(Some(&project), ConfigOrigin::ProjectConfig)
        .expect_err("workspace config never selects executable policy");
    assert_eq!(failure.code, RejectionCode::ProjectSelectionForbidden);
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
}

#[test]
fn one_bad_request_atomically_rejects_the_other_valid_request() {
    let valid = policy(CoreSlot::Context, "minimal-context");
    let mut invalid = policy(CoreSlot::Router, "direct-only");
    invalid.version = "future".into();
    let failure = compile_operator_bundle(Some(&bundle(vec![valid, invalid]))).unwrap_err();
    assert_eq!(failure.code, RejectionCode::UnknownVersion);
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
    let context = &failure.receipt.slots[0];
    assert_eq!(context.status, SlotReceiptStatus::Rejected);
    assert_eq!(context.rejection, Some(RejectionCode::AtomicBundleRejected));
}

#[test]
fn every_registered_alternative_intersects_the_caller_ceiling() {
    let compiled = compile_operator_bundle(Some(&all_alternatives())).unwrap();
    let slots = compiled.slots();
    for (slot, implementation, payload) in [
        (
            CoreSlot::Context,
            &slots.context,
            value(iteron_ctx::ContextSlotObservation::baseline(
                iteron_protocol::context::RequestId(1),
                "task",
            )),
        ),
        (
            CoreSlot::ToolPolicy,
            &slots.tool_policy,
            value(tool_observation(Capability::ReadOnly)),
        ),
        (
            CoreSlot::Memory,
            &slots.memory,
            value(iteron_ctx::MemorySlotObservation::baseline(
                "task",
                Vec::new(),
                &iteron_ctx::MemBudget::default(),
            )),
        ),
        (
            CoreSlot::Router,
            &slots.router,
            value(iteron_agents::RouterSlotObservation::baseline(
                "audit every module",
                iteron_agents::RepoSignals::default(),
            )),
        ),
        (
            CoreSlot::Planner,
            &slots.planner,
            value(iteron_agents::PlannerObservation {
                version: iteron_agents::PLANNER_SLOT_VERSION,
                class: iteron_agents::TaskClass::MultiFile,
                leaves: vec!["a".into(), "b".into()],
                max_leaves: 2,
            }),
        ),
        (
            CoreSlot::Collaboration,
            &slots.collaboration,
            value(iteron_workflow::CollaborationObservation {
                version: iteron_workflow::COLLABORATION_SLOT_VERSION,
                active_workers: 4,
                max_concurrency: 4,
            }),
        ),
        (
            CoreSlot::Scheduler,
            &slots.scheduler,
            value(
                iteron_sched::SchedulerSlotObservation::baseline(
                    iteron_sched::BackoffPolicy::default(),
                    4,
                )
                .unwrap(),
            ),
        ),
        (
            CoreSlot::Verifier,
            &slots.verifier,
            value(iteron_verify::VerifierSlotObservation::advisory()),
        ),
        (
            CoreSlot::ModelRouter,
            &slots.model_router,
            value(
                iteron_provider::catalog::ModelRouterObservation::single_route(
                    "provider/model",
                    None,
                    None,
                ),
            ),
        ),
    ] {
        assert_eq!(implementation.slot().as_persisted_str(), slot.as_str());
        let outcome = implementation.decide(&SlotObservation {
            slot: implementation.slot().clone(),
            ceiling: CapabilitySet::none(),
            payload,
        });
        assert!(outcome.admitted.is_empty(), "{slot:?} widened authority");
    }
}

#[test]
fn alternatives_make_only_narrower_typed_decisions() {
    let compiled = compile_operator_bundle(Some(&all_alternatives())).unwrap();
    let baseline = compile_operator_bundle(None).unwrap();
    let ceiling = CapabilitySet::only(Capability::ReadOnly);
    let context = iteron_ctx::ContextStrategy::select_with(
        compiled.slots().context.as_ref(),
        &iteron_ctx::ContextSlotObservation::baseline(
            iteron_protocol::context::RequestId(1),
            "task",
        ),
        ceiling,
    )
    .unwrap();
    assert!(!context.recall_memory && !context.include_skills);

    let router_input = iteron_agents::RouterSlotObservation::baseline(
        "audit every module in this repository",
        iteron_agents::RepoSignals {
            has_test_command: true,
            file_count: 10_000,
        },
    );
    let route = iteron_agents::RouterStrategy::route_with(
        compiled.slots().router.as_ref(),
        &router_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(route.route.max_leaves, 0);

    let planner = iteron_agents::PlannerStrategy::plan_with(
        compiled.slots().planner.as_ref(),
        &iteron_agents::PlannerObservation {
            version: iteron_agents::PLANNER_SLOT_VERSION,
            class: iteron_agents::TaskClass::MultiFile,
            leaves: vec!["a".into(), "b".into()],
            max_leaves: 2,
        },
        ceiling,
    )
    .unwrap();
    assert_eq!(planner.plan.selected, vec![0]);

    assert_eq!(
        iteron_tools::ToolPolicy::propose_with(
            compiled.slots().tool_policy.as_ref(),
            &tool_observation(Capability::CodeExecuting),
            CapabilitySet::only(Capability::CodeExecuting),
        ),
        Err(iteron_tools::ToolPolicyError::NotEligible)
    );

    let memory_input = iteron_ctx::MemorySlotObservation {
        version: iteron_ctx::MEMORY_SLOT_VERSION,
        task: "alpha beta".into(),
        candidates: vec![
            iteron_ctx::MemoryCandidate {
                slug: "alpha".into(),
                text: "alpha beta first".into(),
                framed_bytes: 16,
                trust: Trust::Trusted,
                modified_unix_secs: None,
            },
            iteron_ctx::MemoryCandidate {
                slug: "beta".into(),
                text: "alpha beta second".into(),
                framed_bytes: 16,
                trust: Trust::Trusted,
                modified_unix_secs: None,
            },
        ],
        recall_bytes: 1_024,
        max_recalled: 2,
        trust_floor: Trust::Untrusted,
        reference_unix_secs: 0,
        retrieval_policy: iteron_ctx::MemoryRetrievalPolicy::default(),
        write: None,
    };
    let baseline_memory = iteron_ctx::MemoryRecallStrategy::select_with(
        baseline.slots().memory.as_ref(),
        &memory_input,
        ceiling,
    )
    .unwrap();
    let alternative_memory = iteron_ctx::MemoryRecallStrategy::select_with(
        compiled.slots().memory.as_ref(),
        &memory_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(baseline_memory.plan.recalled.len(), 2);
    assert_eq!(alternative_memory.plan.recalled.len(), 1);

    let collaboration_input = iteron_workflow::CollaborationObservation {
        version: iteron_workflow::COLLABORATION_SLOT_VERSION,
        active_workers: 4,
        max_concurrency: 4,
    };
    let baseline_collaboration = iteron_workflow::CollaborationStrategy::select_with(
        baseline.slots().collaboration.as_ref(),
        &collaboration_input,
        ceiling,
    )
    .unwrap();
    let alternative_collaboration = iteron_workflow::CollaborationStrategy::select_with(
        compiled.slots().collaboration.as_ref(),
        &collaboration_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(baseline_collaboration.concurrency, 4);
    assert_eq!(alternative_collaboration.concurrency, 1);

    let scheduler_input =
        iteron_sched::SchedulerSlotObservation::baseline(iteron_sched::BackoffPolicy::default(), 4)
            .unwrap();
    let baseline_scheduler = iteron_sched::SchedulerStrategy::plan_with(
        baseline.slots().scheduler.as_ref(),
        &scheduler_input,
        ceiling,
    )
    .unwrap();
    let alternative_scheduler = iteron_sched::SchedulerStrategy::plan_with(
        compiled.slots().scheduler.as_ref(),
        &scheduler_input,
        ceiling,
    )
    .unwrap();
    assert!(baseline_scheduler.plan.max_attempts > 1);
    assert_eq!(alternative_scheduler.plan.max_attempts, 1);
    assert_eq!(alternative_scheduler.plan.concurrency_permits, 1);

    let verifier_input = iteron_verify::VerifierSlotObservation::advisory();
    let baseline_verifier = iteron_verify::VerifierStrategy::plan_with(
        baseline.slots().verifier.as_ref(),
        &verifier_input,
        ceiling,
    )
    .unwrap();
    let alternative_verifier = iteron_verify::VerifierStrategy::plan_with(
        compiled.slots().verifier.as_ref(),
        &verifier_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(
        baseline_verifier.plan.scope,
        iteron_verify::VerifierScope::Lane
    );
    assert_eq!(
        alternative_verifier.plan.scope,
        iteron_verify::VerifierScope::Workspace
    );

    let model_router_input = iteron_provider::catalog::ModelRouterObservation {
        version: iteron_provider::catalog::MODEL_ROUTER_SLOT_VERSION,
        resolved_routes: vec!["provider/parent".into(), "provider/requested".into()],
        definition_model: Some("provider/requested".into()),
        call_model: None,
    };
    let baseline_route = iteron_provider::catalog::ModelRouterStrategy::route_with(
        baseline.slots().model_router.as_ref(),
        &model_router_input,
        ceiling,
    )
    .unwrap();
    let alternative_route = iteron_provider::catalog::ModelRouterStrategy::route_with(
        compiled.slots().model_router.as_ref(),
        &model_router_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(baseline_route.model, "provider/requested");
    assert_eq!(alternative_route.model, "provider/parent");
}

#[test]
fn recorded_genesis_reconstructs_the_exact_executable_generation() {
    for compiled in [
        compile_operator_bundle(None).unwrap(),
        compile_operator_bundle(Some(&all_alternatives())).unwrap(),
    ] {
        let reconstructed = compile_recorded_bundle(compiled.genesis_snapshot())
            .expect("a valid genesis checkpoint is independently executable");
        assert_eq!(reconstructed.receipt(), compiled.receipt());
        assert_eq!(
            reconstructed.policy_runtime_bindings(),
            compiled.policy_runtime_bindings()
        );
        assert_eq!(
            reconstructed.genesis_snapshot(),
            compiled.genesis_snapshot()
        );
    }
}

#[test]
fn recorded_genesis_fails_closed_when_a_known_bundle_names_an_unknown_version() {
    let compiled = compile_operator_bundle(Some(&all_alternatives())).unwrap();
    let mut snapshot = compiled.genesis_snapshot().clone();
    snapshot.slots[0].policy.policy_version = "future".into();
    let snapshot = iteron_record::policy_bundle::seal_policy_bundle_snapshot(snapshot)
        .expect("the tampered identity is structurally valid and self-consistent");
    let failure = compile_recorded_bundle(&snapshot)
        .expect_err("resume must require an implementation registered in this build");
    assert_eq!(failure.code, RejectionCode::UnknownVersion);
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
}

#[test]
fn recorded_external_genesis_requires_operator_candidate_again() {
    let compiled = compile_operator_bundle(None).unwrap();
    let mut snapshot = compiled.genesis_snapshot().clone();
    snapshot.coverage = iteron_protocol::PolicyBundleCoverage::Partial;
    snapshot.bundle_digest_sha256 = "d".repeat(64);
    for row in &mut snapshot.slots {
        row.policy.bundle_digest_sha256 = "d".repeat(64);
    }
    let row = &mut snapshot.slots[0];
    row.requested = true;
    row.status = iteron_protocol::PolicySlotApplicationStatus::Applied;
    row.implementation = "fixture.external".into();
    row.policy.policy_id = format!("external-manifest:{}", "a".repeat(64));
    row.policy.policy_version = format!("external-artifact:{}", "b".repeat(64));
    row.policy.policy_digest_sha256 = "c".repeat(64);
    let snapshot = iteron_record::policy_bundle::seal_policy_bundle_snapshot(snapshot).unwrap();

    let failure = compile_recorded_bundle(&snapshot)
        .expect_err("resume without the exact external candidate must fail closed");
    assert_eq!(failure.code, RejectionCode::ExternalOperatorIntentRequired);
}

#[test]
fn every_optimization_module_has_a_production_consumer() {
    let mapped = iteron_tunables::ModuleId::ALL
        .into_iter()
        .filter(|module| super::external::module_has_production_consumer(*module))
        .collect::<Vec<_>>();
    assert_eq!(mapped, iteron_tunables::ModuleId::ALL);
}

#[cfg(unix)]
fn external_fixture_body(
    implementation_id: &str,
    module: iteron_tunables::ModuleId,
    decision: &serde_json::Value,
    require_prior: bool,
) -> String {
    let wire_module = serde_json::to_string(&module).unwrap();
    let wire_module = wire_module.trim_matches('"');
    let guard = if require_prior {
        r#"printf '%s\n' "$start" > "$1""#
    } else {
        ""
    };
    r#"#!/bin/sh
set -eu
read -r _
printf '%s\n' '{"protocol":"iteron-implementation/1","request_id":"host-1","implementation_id":"__ID__","module":"__WIRE_MODULE__","payload":{"result":"loaded","provider_contract":{"id":"iteron/__CONTRACT_MODULE__/provider@v1","version":1},"observation_schema":{"id":"iteron/__CONTRACT_MODULE__/observation@v1","version":1}}}'
read -r start
__GUARD__
run_id=$(printf '%s\n' "$start" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
printf '%s' '{"protocol":"iteron-implementation/1","request_id":"host-2","implementation_id":"__ID__","module":"__WIRE_MODULE__","payload":{"result":"started","run_id":"'
printf '%s' "$run_id"
printf '%s\n' '"}}'
printf '%s' '{"protocol":"iteron-implementation/1","implementation_id":"__ID__","module":"__WIRE_MODULE__","run_id":"'
printf '%s' "$run_id"
printf '%s' '","sequence":0,"schema":{"id":"iteron/__CONTRACT_MODULE__/observation@v1","version":1},"terminal":true,"observation":__DECISION__}'
printf '\n'
read -r _
printf '%s\n' '{"protocol":"iteron-implementation/1","request_id":"host-3","implementation_id":"__ID__","module":"__WIRE_MODULE__","payload":{"result":"stopped"}}'
"#
    .replace("__ID__", implementation_id)
    .replace("__WIRE_MODULE__", wire_module)
    .replace("__CONTRACT_MODULE__", module.as_str())
    .replace("__GUARD__", guard)
    .replace("__DECISION__", &serde_json::to_string(decision).unwrap())
}

#[cfg(unix)]
#[test]
fn same_slot_provider_chain_runs_every_module_and_threads_the_prior_outcome() {
    use iteron_marketplace::{
        EvidenceLimits, ImplementationActivationDocument, ImplementationCatalog,
        ImplementationFailurePolicy, ImplementationManifest, ImplementationSource, Version,
    };
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::env::temp_dir().join(format!(
        "iteron-cli-external-provider-chain-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let host =
        CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::CodeExecuting]);

    let prior_decision = json!({
        "admitted": CapabilitySet::only(Capability::ReadOnly),
        "decision": {"kind": "route", "model": "provider/prior"}
    });
    let final_decision = json!({
        "admitted": CapabilitySet::only(Capability::ReadOnly),
        "decision": {"kind": "route", "model": "provider/final"}
    });
    let fixtures = [
        (
            iteron_tunables::ModuleId::ProviderRouting,
            "fixture.provider-routing",
            "provider-routing.sh",
            external_fixture_body(
                "fixture.provider-routing",
                iteron_tunables::ModuleId::ProviderRouting,
                &prior_decision,
                false,
            ),
        ),
        (
            iteron_tunables::ModuleId::ProviderSampling,
            "fixture.provider-sampling",
            "provider-sampling.sh",
            external_fixture_body(
                "fixture.provider-sampling",
                iteron_tunables::ModuleId::ProviderSampling,
                &final_decision,
                true,
            ),
        ),
    ];
    let mut manifests = Vec::new();
    for (module, implementation_id, executable_name, body) in &fixtures {
        let executable = root.join(executable_name);
        std::fs::write(&executable, body.as_bytes()).unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).unwrap();
        manifests.push(ImplementationManifest {
            implementation_id: (*implementation_id).into(),
            implementation_version: Version(1, 0, 0),
            module: *module,
            artifact_sha256: hex::encode(sha2::Sha256::digest(body.as_bytes())),
            executable: (*executable_name).into(),
            argv: if *module == iteron_tunables::ModuleId::ProviderSampling {
                vec![
                    root.join("provider-sampling-start.json")
                        .display()
                        .to_string(),
                ]
            } else {
                Vec::new()
            },
            protocol_version: 1,
            requested_capabilities: host,
            dependencies: Vec::new(),
            runtime_deadline_ms: 30_000,
            cancellation_deadline_ms: 2_000,
            evidence_limits: EvidenceLimits {
                stdout_bytes: 16 * 1024,
                stderr_bytes: 4 * 1024,
                observations: 4,
            },
            failure_policy: ImplementationFailurePolicy::FailClosed,
        });
    }
    let catalog_path = root.join("catalog.json");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec(&ImplementationCatalog {
            schema_version: 1,
            implementations: manifests.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    let sources = manifests
        .iter()
        .map(|manifest| ImplementationSource {
            module: manifest.module,
            implementation_id: manifest.implementation_id.clone(),
            catalog_path: catalog_path.display().to_string(),
            artifact_root: root.display().to_string(),
            manifest_sha256: format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(serde_json::to_vec(manifest).unwrap()))
            ),
            artifact_sha256: format!("sha256:{}", manifest.artifact_sha256),
        })
        .collect();
    let activation_bytes = serde_json::to_vec(&ImplementationActivationDocument {
        schema_version: 1,
        candidate_sha256: format!("sha256:{}", "7".repeat(64)),
        sources,
    })
    .unwrap();
    let activation_digest = hex::encode(sha2::Sha256::digest(&activation_bytes));
    let activation_path = root.join("research-activation.json");
    std::fs::write(&activation_path, &activation_bytes).unwrap();
    let candidate =
        crate::plugin_runtime::CandidateFile::read(&activation_path, &activation_digest).unwrap();
    let research = crate::plugin_runtime::RuntimePlugins::research(candidate, host)
        .expect("the universal research activation is independently marketplace-verified");
    let compiled = compile_configured_bundle_with_external(
        None,
        ConfigOrigin::UserConfig,
        research.implementation.as_ref().unwrap(),
        &root,
        "provider-chain-run",
    )
    .expect("ProviderSampling and ProviderRouting both map to the production model-router chain");
    let slot = compiled.slots().model_router.clone();
    let input = iteron_provider::catalog::ModelRouterObservation {
        version: iteron_provider::catalog::MODEL_ROUTER_SLOT_VERSION,
        resolved_routes: vec![
            "provider/parent".into(),
            "provider/prior".into(),
            "provider/final".into(),
        ],
        definition_model: None,
        call_model: None,
    };
    let baseline = iteron_provider::catalog::ModelRouterStrategy::route_with(
        &iteron_provider::catalog::ModelRouterStrategy::default(),
        &input,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .unwrap();
    let external = iteron_provider::catalog::ModelRouterStrategy::route_with(
        slot.as_ref(),
        &input,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .unwrap();
    assert_eq!(baseline.model, "provider/parent");
    assert_eq!(external.model, "provider/final");

    let start: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("provider-sampling-start.json")).unwrap())
            .unwrap();
    let chained = &start["payload"]["input"];
    assert_eq!(chained["schema_id"], "iteron-module-observation/1");
    assert_eq!(chained["module"], "provider_sampling");
    assert_eq!(chained["core_slot"], "model_router");
    assert_eq!(chained["prior"]["decision"]["model"], "provider/prior");

    let sidecar = root.join(format!(
        ".iteron-implementation-{activation_digest}-consumption.json"
    ));
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sidecar).unwrap()).unwrap();
    assert_eq!(document["cli_run_id"], "provider-chain-run");
    let rows = document["implementations"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["module"], "provider_routing");
    assert_eq!(rows[1]["module"], "provider_sampling");
    for row in rows {
        for field in ["loaded", "started", "terminal", "stopped"] {
            assert_eq!(row[field], true, "{field}: {row}");
        }
    }
    drop(slot);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn external_process_observation_changes_the_production_scheduler_decision() {
    use iteron_marketplace::{
        EvidenceLimits, ImplementationActivation, ImplementationActivationDocument,
        ImplementationCatalog, ImplementationFailurePolicy, ImplementationManifest,
        ImplementationSource, Version,
    };
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;

    let root =
        std::env::temp_dir().join(format!("iteron-cli-external-slot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let decision = serde_json::to_string(&json!({
        "admitted": CapabilitySet::only(Capability::ReadOnly),
        "decision": {
            "kind": "plan",
            "plan": {
                "retry_base_ms": 500,
                "retry_cap_ms": 10_000,
                "max_attempts": 1,
                "concurrency_permits": 1
            }
        }
    }))
    .unwrap();
    let body = r#"#!/bin/sh
set -eu
read -r _
printf '%s\n' '{"protocol":"iteron-implementation/1","request_id":"host-1","implementation_id":"fixture.scheduler","module":"scheduler_parallelism","payload":{"result":"loaded","provider_contract":{"id":"iteron/scheduler.parallelism/provider@v1","version":1},"observation_schema":{"id":"iteron/scheduler.parallelism/observation@v1","version":1}}}'
read -r start
run_id=$(printf '%s\n' "$start" | sed -n 's/.*"run_id":"\([^"]*\)".*/\1/p')
printf '%s' '{"protocol":"iteron-implementation/1","request_id":"host-2","implementation_id":"fixture.scheduler","module":"scheduler_parallelism","payload":{"result":"started","run_id":"'
printf '%s' "$run_id"
printf '%s\n' '"}}'
printf '%s' '{"protocol":"iteron-implementation/1","implementation_id":"fixture.scheduler","module":"scheduler_parallelism","run_id":"'
printf '%s' "$run_id"
printf '%s' '","sequence":0,"schema":{"id":"iteron/scheduler.parallelism/observation@v1","version":1},"terminal":true,"observation":'
printf '%s' '__DECISION__'
printf '%s\n' '}'
read -r _
printf '%s\n' '{"protocol":"iteron-implementation/1","request_id":"host-3","implementation_id":"fixture.scheduler","module":"scheduler_parallelism","payload":{"result":"stopped"}}'
"#
    .replace("__DECISION__", &decision);
    let executable = root.join("provider.sh");
    std::fs::write(&executable, body.as_bytes()).unwrap();
    let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&executable, permissions).unwrap();
    let artifact = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    let host =
        CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::CodeExecuting]);
    let manifest = ImplementationManifest {
        implementation_id: "fixture.scheduler".into(),
        implementation_version: Version(1, 0, 0),
        module: iteron_tunables::ModuleId::SchedulerParallelism,
        artifact_sha256: artifact.clone(),
        executable: "provider.sh".into(),
        argv: Vec::new(),
        protocol_version: 1,
        requested_capabilities: host,
        dependencies: Vec::new(),
        // This fixture exercises spawn + four durable consumption-ledger writes + stop/reap.
        // A two-second whole-process budget flakes under the full suite's scheduler and disk
        // pressure, turning the adapter's intentional fail-closed `Unknown` into a misleading
        // `UnsupportedVersion`. Keep the production bounds, but do not make this a latency test.
        runtime_deadline_ms: 30_000,
        cancellation_deadline_ms: 2_000,
        evidence_limits: EvidenceLimits {
            stdout_bytes: 16 * 1024,
            stderr_bytes: 4 * 1024,
            observations: 4,
        },
        failure_policy: ImplementationFailurePolicy::FailClosed,
    };
    let mut weak_manifest = manifest.clone();
    weak_manifest.requested_capabilities = CapabilitySet::only(Capability::ReadOnly);
    let weak_catalog_path = root.join("weak-catalog.json");
    std::fs::write(
        &weak_catalog_path,
        serde_json::to_vec(&ImplementationCatalog {
            schema_version: 1,
            implementations: vec![weak_manifest.clone()],
        })
        .unwrap(),
    )
    .unwrap();
    let weak_manifest_digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&weak_manifest).unwrap(),
    ));
    let weak_bytes = serde_json::to_vec(&ImplementationActivationDocument {
        schema_version: 1,
        candidate_sha256: format!("sha256:{}", "f".repeat(64)),
        sources: vec![ImplementationSource {
            module: iteron_tunables::ModuleId::SchedulerParallelism,
            implementation_id: "fixture.scheduler".into(),
            catalog_path: weak_catalog_path.display().to_string(),
            artifact_root: root.display().to_string(),
            manifest_sha256: format!("sha256:{weak_manifest_digest}"),
            artifact_sha256: format!("sha256:{artifact}"),
        }],
    })
    .unwrap();
    let weak = crate::plugin_runtime::VerifiedImplementationActivation::for_test(
        ImplementationActivation::from_json(&weak_bytes, host).unwrap(),
        hex::encode(sha2::Sha256::digest(&weak_bytes)),
    );
    let weak_failure = compile_configured_bundle_with_external(
        None,
        ConfigOrigin::UserConfig,
        &weak,
        &root,
        "fixture-run",
    )
    .expect_err("an external process without code_executing admission must be rejected");
    assert_eq!(weak_failure.code, RejectionCode::ExternalIdentityMismatch);

    let weak_digest = hex::encode(sha2::Sha256::digest(&weak_bytes));
    let weak_activation_path = root.join("standalone-weak-research-activation.json");
    std::fs::write(&weak_activation_path, &weak_bytes).unwrap();
    let weak_candidate =
        crate::plugin_runtime::CandidateFile::read(&weak_activation_path, &weak_digest).unwrap();
    let weak_research = crate::plugin_runtime::RuntimePlugins::research(weak_candidate, host)
        .expect("CandidateValidate-compatible activation is accepted without a plugin winner");
    compile_configured_bundle_with_external(
        None,
        ConfigOrigin::UserConfig,
        weak_research.implementation.as_ref().unwrap(),
        &root,
        "fixture-run-weak",
    )
    .expect("the explicit research candidate pair authorizes process activation");

    let catalog_path = root.join("catalog.json");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec(&ImplementationCatalog {
            schema_version: 1,
            implementations: vec![manifest.clone()],
        })
        .unwrap(),
    )
    .unwrap();
    let manifest_digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
    let activation_bytes = serde_json::to_vec(&ImplementationActivationDocument {
        schema_version: 1,
        candidate_sha256: format!("sha256:{}", "c".repeat(64)),
        sources: vec![ImplementationSource {
            module: iteron_tunables::ModuleId::SchedulerParallelism,
            implementation_id: "fixture.scheduler".into(),
            catalog_path: catalog_path.display().to_string(),
            artifact_root: root.display().to_string(),
            manifest_sha256: format!("sha256:{manifest_digest}"),
            artifact_sha256: format!("sha256:{artifact}"),
        }],
    })
    .unwrap();
    let activation_digest = hex::encode(sha2::Sha256::digest(&activation_bytes));
    let activation_path = root.join("standalone-research-activation.json");
    std::fs::write(&activation_path, &activation_bytes).unwrap();
    let candidate =
        crate::plugin_runtime::CandidateFile::read(&activation_path, &activation_digest).unwrap();
    let research_plugins = crate::plugin_runtime::RuntimePlugins::research(candidate, host)
        .expect("standalone research activation does not require an installed plugin winner");
    assert!(research_plugins.agents.is_empty());
    assert!(research_plugins.mcp_servers.is_empty());
    let external = research_plugins.implementation.unwrap();
    let compiled = compile_configured_bundle_with_external(
        None,
        ConfigOrigin::UserConfig,
        &external,
        &root,
        "fixture-run",
    )
    .unwrap();
    let scheduler_row = &compiled.genesis_snapshot().slots[6];
    assert_eq!(scheduler_row.implementation, "fixture.scheduler");
    assert_eq!(
        scheduler_row.policy.policy_id,
        format!("external-manifest:{manifest_digest}")
    );
    assert_eq!(
        scheduler_row.policy.policy_version,
        format!("external-artifact:{artifact}")
    );
    assert_eq!(scheduler_row.policy.policy_digest_sha256, "c".repeat(64));

    let drift = crate::plugin_runtime::VerifiedImplementationActivation::for_test(
        ImplementationActivation::from_json(&activation_bytes, host).unwrap(),
        "e".repeat(64),
    );
    assert!(
        compile_recorded_bundle_with_external(
            compiled.genesis_snapshot(),
            Some(&drift),
            &root,
            "fixture-run",
        )
        .is_err(),
        "resume must reject activation-byte drift"
    );
    let reconstructed = compile_recorded_bundle_with_external(
        compiled.genesis_snapshot(),
        Some(&external),
        &root,
        "fixture-run",
    )
    .unwrap();
    let slot = reconstructed.slots().scheduler.clone();
    let input =
        iteron_sched::SchedulerSlotObservation::baseline(iteron_sched::BackoffPolicy::default(), 4)
            .unwrap();
    let baseline = iteron_sched::SchedulerStrategy::plan_with(
        &iteron_sched::SchedulerStrategy::default(),
        &input,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .unwrap();
    let external = iteron_sched::SchedulerStrategy::plan_with(
        slot.as_ref(),
        &input,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .unwrap();
    assert!(baseline.plan.max_attempts > external.plan.max_attempts);
    assert_eq!(external.plan.max_attempts, 1);
    assert_eq!(external.plan.concurrency_permits, 1);

    let sidecar = root.join(format!(
        ".iteron-implementation-{}-consumption.json",
        activation_digest
    ));
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sidecar).unwrap()).unwrap();
    assert_eq!(document["schema_id"], "iteron-implementation-consumption/1");
    assert_eq!(document["cli_run_id"], "fixture-run");
    let row = &document["implementations"][0];
    for field in ["loaded", "started", "terminal", "stopped"] {
        assert_eq!(row[field], true, "{field}");
    }
    drop(slot);
    std::fs::remove_dir_all(root).unwrap();
}

fn assert_rejected(bundle: PolicyBundle, expected: RejectionCode) {
    let failure = compile_operator_bundle(Some(&bundle)).expect_err("bundle must fail closed");
    assert_eq!(failure.code, expected, "{failure:#?}");
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
    assert!(!failure.receipt.rejected_requests.is_empty());
}

fn tool_observation(capability: Capability) -> iteron_tools::ToolPolicyObservation {
    iteron_tools::ToolPolicyObservation {
        version: iteron_tools::TOOL_POLICY_SLOT_VERSION,
        call: ToolUse {
            id: "tool-1".into(),
            name: "sample".into(),
            input: json!({}),
        },
        registered: iteron_tools::RegisteredToolPolicy {
            name: "sample".into(),
            purity: if capability == Capability::ReadOnly {
                Purity::Pure
            } else {
                Purity::Effecting
            },
            capability,
        },
        argument_trust: Trust::Trusted,
    }
}

fn value(value: impl Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}
