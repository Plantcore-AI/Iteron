use super::*;
use crate::config::ConfigOrigin;
use core_evolve::{PolicyBundle, PolicyRef, StrategySlot as EvolveSlot};
use core_protocol::capability_set::CapabilitySet;
use core_protocol::slot::SlotObservation;
use core_protocol::{Capability, Purity, ToolUse, Trust};
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
            value(core_ctx::ContextSlotObservation::baseline(
                core_protocol::context::RequestId(1),
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
            value(core_ctx::MemorySlotObservation::baseline(
                "task",
                Vec::new(),
                &core_ctx::MemBudget::default(),
            )),
        ),
        (
            CoreSlot::Router,
            &slots.router,
            value(core_agents::RouterSlotObservation::baseline(
                "audit every module",
                core_agents::RepoSignals::default(),
            )),
        ),
        (
            CoreSlot::Planner,
            &slots.planner,
            value(core_agents::PlannerObservation {
                version: core_agents::PLANNER_SLOT_VERSION,
                class: core_agents::TaskClass::MultiFile,
                leaves: vec!["a".into(), "b".into()],
                max_leaves: 2,
            }),
        ),
        (
            CoreSlot::Collaboration,
            &slots.collaboration,
            value(core_workflow::CollaborationObservation {
                version: core_workflow::COLLABORATION_SLOT_VERSION,
                active_workers: 4,
                max_concurrency: 4,
            }),
        ),
        (
            CoreSlot::Scheduler,
            &slots.scheduler,
            value(
                core_sched::SchedulerSlotObservation::baseline(
                    core_sched::BackoffPolicy::default(),
                    4,
                )
                .unwrap(),
            ),
        ),
        (
            CoreSlot::Verifier,
            &slots.verifier,
            value(core_verify::VerifierSlotObservation::advisory()),
        ),
        (
            CoreSlot::ModelRouter,
            &slots.model_router,
            value(
                core_provider::catalog::ModelRouterObservation::single_route(
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
    let context = core_ctx::ContextStrategy::select_with(
        compiled.slots().context.as_ref(),
        &core_ctx::ContextSlotObservation::baseline(core_protocol::context::RequestId(1), "task"),
        ceiling,
    )
    .unwrap();
    assert!(!context.recall_memory && !context.include_skills);

    let router_input = core_agents::RouterSlotObservation::baseline(
        "audit every module in this repository",
        core_agents::RepoSignals {
            has_test_command: true,
            file_count: 10_000,
        },
    );
    let route = core_agents::RouterStrategy::route_with(
        compiled.slots().router.as_ref(),
        &router_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(route.route.max_leaves, 0);

    let planner = core_agents::PlannerStrategy::plan_with(
        compiled.slots().planner.as_ref(),
        &core_agents::PlannerObservation {
            version: core_agents::PLANNER_SLOT_VERSION,
            class: core_agents::TaskClass::MultiFile,
            leaves: vec!["a".into(), "b".into()],
            max_leaves: 2,
        },
        ceiling,
    )
    .unwrap();
    assert_eq!(planner.plan.selected, vec![0]);

    assert_eq!(
        core_tools::ToolPolicy::propose_with(
            compiled.slots().tool_policy.as_ref(),
            &tool_observation(Capability::CodeExecuting),
            CapabilitySet::only(Capability::CodeExecuting),
        ),
        Err(core_tools::ToolPolicyError::NotEligible)
    );

    let memory_input = core_ctx::MemorySlotObservation {
        version: core_ctx::MEMORY_SLOT_VERSION,
        task: "alpha beta".into(),
        candidates: vec![
            core_ctx::MemoryCandidate {
                slug: "alpha".into(),
                text: "alpha beta".into(),
                framed_bytes: 16,
                trust: Trust::Trusted,
                modified_unix_secs: None,
            },
            core_ctx::MemoryCandidate {
                slug: "beta".into(),
                text: "alpha beta".into(),
                framed_bytes: 16,
                trust: Trust::Trusted,
                modified_unix_secs: None,
            },
        ],
        recall_bytes: 1_024,
        max_recalled: 2,
        trust_floor: Trust::Untrusted,
        reference_unix_secs: 0,
        retrieval_policy: core_ctx::MemoryRetrievalPolicy::default(),
        write: None,
    };
    let baseline_memory = core_ctx::MemoryRecallStrategy::select_with(
        baseline.slots().memory.as_ref(),
        &memory_input,
        ceiling,
    )
    .unwrap();
    let alternative_memory = core_ctx::MemoryRecallStrategy::select_with(
        compiled.slots().memory.as_ref(),
        &memory_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(baseline_memory.plan.recalled.len(), 2);
    assert_eq!(alternative_memory.plan.recalled.len(), 1);

    let collaboration_input = core_workflow::CollaborationObservation {
        version: core_workflow::COLLABORATION_SLOT_VERSION,
        active_workers: 4,
        max_concurrency: 4,
    };
    let baseline_collaboration = core_workflow::CollaborationStrategy::select_with(
        baseline.slots().collaboration.as_ref(),
        &collaboration_input,
        ceiling,
    )
    .unwrap();
    let alternative_collaboration = core_workflow::CollaborationStrategy::select_with(
        compiled.slots().collaboration.as_ref(),
        &collaboration_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(baseline_collaboration.concurrency, 4);
    assert_eq!(alternative_collaboration.concurrency, 1);

    let scheduler_input =
        core_sched::SchedulerSlotObservation::baseline(core_sched::BackoffPolicy::default(), 4)
            .unwrap();
    let baseline_scheduler = core_sched::SchedulerStrategy::plan_with(
        baseline.slots().scheduler.as_ref(),
        &scheduler_input,
        ceiling,
    )
    .unwrap();
    let alternative_scheduler = core_sched::SchedulerStrategy::plan_with(
        compiled.slots().scheduler.as_ref(),
        &scheduler_input,
        ceiling,
    )
    .unwrap();
    assert!(baseline_scheduler.plan.max_attempts > 1);
    assert_eq!(alternative_scheduler.plan.max_attempts, 1);
    assert_eq!(alternative_scheduler.plan.concurrency_permits, 1);

    let verifier_input = core_verify::VerifierSlotObservation::advisory();
    let baseline_verifier = core_verify::VerifierStrategy::plan_with(
        baseline.slots().verifier.as_ref(),
        &verifier_input,
        ceiling,
    )
    .unwrap();
    let alternative_verifier = core_verify::VerifierStrategy::plan_with(
        compiled.slots().verifier.as_ref(),
        &verifier_input,
        ceiling,
    )
    .unwrap();
    assert_eq!(
        baseline_verifier.plan.scope,
        core_verify::VerifierScope::Lane
    );
    assert_eq!(
        alternative_verifier.plan.scope,
        core_verify::VerifierScope::Workspace
    );

    let model_router_input = core_provider::catalog::ModelRouterObservation {
        version: core_provider::catalog::MODEL_ROUTER_SLOT_VERSION,
        resolved_routes: vec!["provider/parent".into(), "provider/requested".into()],
        definition_model: Some("provider/requested".into()),
        call_model: None,
    };
    let baseline_route = core_provider::catalog::ModelRouterStrategy::route_with(
        baseline.slots().model_router.as_ref(),
        &model_router_input,
        ceiling,
    )
    .unwrap();
    let alternative_route = core_provider::catalog::ModelRouterStrategy::route_with(
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
    let snapshot = core_record::seal_policy_bundle_snapshot(snapshot)
        .expect("the tampered identity is structurally valid and self-consistent");
    let failure = compile_recorded_bundle(&snapshot)
        .expect_err("resume must require an implementation registered in this build");
    assert_eq!(failure.code, RejectionCode::UnknownVersion);
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
}

fn assert_rejected(bundle: PolicyBundle, expected: RejectionCode) {
    let failure = compile_operator_bundle(Some(&bundle)).expect_err("bundle must fail closed");
    assert_eq!(failure.code, expected, "{failure:#?}");
    assert_eq!(failure.receipt.coverage, BundleCoverage::Rejected);
    assert!(!failure.receipt.rejected_requests.is_empty());
}

fn tool_observation(capability: Capability) -> core_tools::ToolPolicyObservation {
    core_tools::ToolPolicyObservation {
        version: core_tools::TOOL_POLICY_SLOT_VERSION,
        call: ToolUse {
            id: "tool-1".into(),
            name: "sample".into(),
            input: json!({}),
        },
        registered: core_tools::RegisteredToolPolicy {
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
