//! D11-13 oracle — API/build honesty for the ultracode workflow topology.
//!
//! The gap: the pre-fix crate shipped `WorkflowPlan` with a `pub aggregate: Budget` field, so
//! every planner call had to invent a *placeholder* shared ceiling before the real admitted-task
//! count was known, and a crate-wide `#![allow(dead_code)]` hid that the budgeted/finalized
//! surface was never actually wired. The honest design this locks in:
//!
//!   1. `WorkflowPlan` carries NO budget of any kind — a topology record must never imply that a
//!      finalized run budget already exists.
//!   2. A budget only materializes at the explicit `with_aggregate` finalization boundary, which
//!      *validates* the monetary ceiling (a NaN/negative ceiling is refused, never stored as a
//!      placeholder that lies about enforcing a dollar cap).
//!   3. That finalization surface (`with_aggregate` / `BudgetedWorkflowPlan` / `aggregate`) is
//!      reachable through the crate's public API end-to-end — it is not dead code hidden behind a
//!      crate-wide allow.
//!
//! These are exercised through the real public router+planner path (`route` -> `plan` ->
//! `with_aggregate`), not by hand-constructing internal structs.

use core_agents::{
    BudgetedWorkflowPlan, Decomposer, RepoSignals, Stage, TaskClass, WorkflowPlan, FAN_CAP,
    INVESTIGATOR_SCOPE,
};
use core_protocol::Budget;

/// Build a real, *unbudgeted* plan by driving the deterministic router and planner — the same
/// path the executor uses. A broad cross-file ask on a large tree routes to `MultiFile`, which
/// fans out.
fn real_unbudgeted_plan() -> WorkflowPlan {
    let repo = RepoSignals {
        has_test_command: false,
        file_count: 5_000,
    };
    let class = Decomposer::route("rename the config field everywhere", &repo);
    assert_eq!(
        class,
        TaskClass::MultiFile,
        "precondition: a broad cross-file ask must route to a fan-out class"
    );
    Decomposer::plan(
        class,
        vec![
            "find all callers".into(),
            "find the schema".into(),
            "find the tests".into(),
        ],
    )
    .expect("a fan-out class with valid leaves must yield a plan")
}

#[test]
fn unbudgeted_plan_never_serializes_a_placeholder_budget() {
    let plan = real_unbudgeted_plan();
    let json = serde_json::to_value(&plan).expect("WorkflowPlan serializes");
    let obj = json
        .as_object()
        .expect("WorkflowPlan serializes to a JSON object");

    // The pre-fix `WorkflowPlan` exposed `pub aggregate: Budget`; the honest record must not.
    assert!(
        !obj.contains_key("aggregate"),
        "topology record must not imply a finalized budget exists: {obj:?}"
    );
    assert!(
        !obj.contains_key("budget"),
        "no budget field under any name may leak onto the unbudgeted topology: {obj:?}"
    );

    // The provenance the record IS allowed to carry stays present — proves we serialized a real,
    // fully-populated plan and not an empty object that trivially lacks `aggregate`.
    assert!(obj.contains_key("stages"), "stages provenance must remain");
    assert!(obj.contains_key("class"), "routing class must remain");
    assert!(
        obj.contains_key("truncated"),
        "truncation honesty field must remain"
    );
}

#[test]
fn budget_only_materializes_at_the_validated_finalization_boundary() {
    let plan = real_unbudgeted_plan();

    // A well-formed shared ceiling is accepted and preserved verbatim behind the accessor.
    let budget = Budget {
        max_turns: 12,
        max_usd: Some(3.5),
        max_wall_secs: 90,
        max_consecutive_tool_errors: 2,
    };
    let budgeted: BudgetedWorkflowPlan = plan
        .clone()
        .with_aggregate(budget)
        .expect("a valid ceiling finalizes");
    assert_eq!(budgeted.aggregate().max_turns, 12);
    assert_eq!(budgeted.aggregate().max_usd, Some(3.5));
    assert_eq!(budgeted.aggregate().max_wall_secs, 90);
    assert_eq!(budgeted.aggregate().max_consecutive_tool_errors, 2);

    // NaN would make every `cost >= max_usd` comparison false and silently disable the monetary
    // ceiling — the boundary must reject it rather than store a lying placeholder.
    let nan = Budget {
        max_usd: Some(f64::NAN),
        ..Budget::default()
    };
    assert_eq!(
        plan.clone().with_aggregate(nan).unwrap_err(),
        "max_usd must be finite"
    );

    // A negative ceiling is likewise refused at the boundary.
    let negative = Budget {
        max_usd: Some(-1.0),
        ..Budget::default()
    };
    assert_eq!(
        plan.with_aggregate(negative).unwrap_err(),
        "max_usd must be non-negative"
    );
}

#[test]
fn finalization_surface_is_wired_end_to_end_not_dead_code() {
    // Drive the whole public path: route -> plan (unbudgeted) -> with_aggregate -> budgeted. If
    // this surface were the dead, allow(dead_code)-hidden API the pre-fix crate shipped, it could
    // not be exercised through `core_agents`' public exports at all.
    let plan = real_unbudgeted_plan();

    // The unbudgeted plan already exposes the ordered fan leaves and the fixed Fan -> Reduce shape.
    let leaves = plan.fan_tasks();
    assert_eq!(leaves.len(), 3);
    assert!(leaves.len() <= FAN_CAP);
    assert!(matches!(plan.stages.first(), Some(Stage::Fan { .. })));
    assert!(matches!(plan.stages.get(1), Some(Stage::Reduce)));
    for (i, task) in leaves.iter().enumerate() {
        assert_eq!(
            task.id, i,
            "fan ids are declaration-ordered join keys, never completion order"
        );
        assert_eq!(
            task.scope, INVESTIGATOR_SCOPE,
            "every fan leaf is read-only by contract"
        );
    }

    // Finalizing preserves the topology + leaves behind the immutable aggregate accessor.
    let budgeted = plan
        .with_aggregate(Budget::default())
        .expect("the default ceiling is valid");
    assert_eq!(budgeted.topology().class, TaskClass::MultiFile);
    assert_eq!(budgeted.fan_tasks().len(), 3);
    assert_eq!(budgeted.fan_tasks()[0].objective, "find all callers");
    assert_eq!(budgeted.fan_tasks()[0].id, 0);

    // The aggregate is only reachable through the finalized type — the raw topology exposes none.
    assert_eq!(
        budgeted.aggregate().max_turns,
        Budget::default().max_turns,
        "the finalized ceiling is exactly the one supplied at the boundary"
    );
}
