//! D14-04 oracle: an "unknown" provider cost is NEVER silently converted to `$0` anywhere in the
//! `core-eval` measurement pipeline — not when the Core CLI final result is decoded, not when a
//! configuration's cells are aggregated, and not when two arms are compared.
//!
//! The gap under closure is "Unknown cost silently converted to $0". A dollar figure that cannot be
//! established from durable, route-bound rate-card evidence is monetary truth, not a free run: the
//! honest report of such a cell is `unknown`, and it must be EXCLUDED from every priced statistic
//! rather than folded in as a `0.0` that drags an average down or manufactures a bogus cost delta.
//! Observability (`crates/obs/src/lib.rs`) already models this as `CostState::Unknown` whose
//! `usd()` is `None`; this oracle pins the consuming half of the contract in the evaluation harness,
//! which is where a silent `$0` would first become visible to an operator (the summary the
//! `crates/eval/src/main.rs` binary prints and the machine artifact it persists).
//!
//! Two deterministic, network-free contrasts:
//!
//!   1. DECODE. The Core CLI process contract carries `cost_status` + `cost_usd`. A `known` cost is
//!      admitted only with a finite, non-negative amount; a `known` cost missing its amount is a
//!      hard contract error (NOT a silent `$0`); an `unknown` cost decodes to a cost observation
//!      whose dollar value is absent (`None`), never `Some(0.0)`.
//!
//!   2. AGGREGATE + COMPARE. A configuration mixing one priced cell with one unknown-cost cell must
//!      report the unknown cell in `unknown_cost_cells`, keep the priced average equal to the mean
//!      of the PRICED cells only (an unknown coerced to `0.0` would halve it), and disable the
//!      cross-arm cost delta with an explicit reason rather than emit a fabricated dollar figure.

use core_eval::report::{aggregate, compare};
use core_eval::{
    CellResult, ContractError, CostStatus, OracleStatus, Partition, RunStatus, SamplingControl,
    parse_final_result,
};

/// A Core CLI terminal `result` record with the given cost fields. Every other field is fixed to a
/// clean, self-consistent `done` run so that `parse_final_result`'s exit-code / outcome invariants
/// pass and only the cost decoding is under test.
fn final_result_json(cost_status: &str, cost_usd_json: &str, cost_reason_json: &str) -> Vec<u8> {
    format!(
        r#"{{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"run-d14-04","cost_usd":{cost_usd_json},"cost_status":"{cost_status}","cost_reason":{cost_reason_json},"turns":2,"exit_code":0,"error":null}}"#
    )
    .into_bytes()
}

/// A completed, resolved cell carrying an explicit cost observation.
fn cell(config: &str, seed: u64, cost_status: CostStatus, cost_usd: Option<f64>) -> CellResult {
    CellResult {
        task: "task-a".into(),
        config: config.into(),
        seed,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: Some(true),
        run_status: RunStatus::Completed,
        failure_phase: None,
        exit_code: Some(0),
        terminal_outcome: Some("done".into()),
        cost_status,
        cost_usd,
        cost_reason: (cost_status == CostStatus::Unknown)
            .then(|| "no_verified_rate_card".to_owned()),
        turns: Some(1),
        oracle_status: OracleStatus::Passed,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "fixed".into(),
            reason: None,
        },
        elapsed_ms: 1,
        error: None,
        candidate_diff: None,
    }
}

#[test]
fn core_cli_unknown_cost_is_never_coerced_to_zero_dollars() {
    // A verified `known` cost decodes to exactly its stated amount.
    let known = parse_final_result(&final_result_json("known", "0.125000", "null"), 0)
        .expect("a well-formed known-cost result parses")
        .cost()
        .expect("known cost with a finite amount is admitted");
    assert_eq!(known.status, CostStatus::Known);
    assert_eq!(
        known.usd,
        Some(0.125),
        "a priced cell keeps its real dollar amount"
    );

    // An `unknown` cost decodes WITHOUT a dollar value — the whole point of the gap. If it were
    // silently coerced to `$0`, `usd` would be `Some(0.0)` and this would fail.
    let unknown = parse_final_result(
        &final_result_json("unknown", "null", "\"no_verified_rate_card\""),
        0,
    )
    .expect("a well-formed unknown-cost result parses")
    .cost()
    .expect("an unknown cost is a valid, honest observation");
    assert_eq!(unknown.status, CostStatus::Unknown);
    assert_eq!(
        unknown.usd, None,
        "an unknown cost must not be reported as a dollar amount (not even $0)"
    );
    assert_eq!(unknown.reason.as_deref(), Some("no_verified_rate_card"));

    // A `known` cost that is missing its amount is a hard contract error, never a fabricated $0.
    let missing = parse_final_result(&final_result_json("known", "null", "null"), 0);
    assert_eq!(
        missing.err(),
        Some(ContractError::KnownCostMissing),
        "a `known` cost with no amount must be rejected, not defaulted to $0"
    );
}

#[test]
fn aggregate_and_compare_reject_unknown_cost_and_disable_delta() {
    // Baseline arm: fully priced (mean of 2.0 and 4.0 == 3.0).
    // Treatment arm: one priced cell at 10.0 plus one UNKNOWN-cost cell. If the unknown cell were
    // coerced to $0 the treatment average would be (10.0 + 0.0) / 2 == 5.0.
    let cells = vec![
        cell("verify_OFF", 0, CostStatus::Known, Some(2.0)),
        cell("verify_OFF", 1, CostStatus::Known, Some(4.0)),
        cell("verify_ON", 0, CostStatus::Known, Some(10.0)),
        cell("verify_ON", 1, CostStatus::Unknown, None),
    ];
    let stats = aggregate(&cells, 1);

    let baseline = stats
        .configs
        .iter()
        .find(|item| item.config == "verify_OFF")
        .expect("baseline aggregate present");
    assert_eq!(baseline.known_cost_cells, 2);
    assert_eq!(baseline.unknown_cost_cells, 0);
    assert_eq!(baseline.average_known_cost_usd, Some(3.0));

    let treatment = stats
        .configs
        .iter()
        .find(|item| item.config == "verify_ON")
        .expect("treatment aggregate present");
    assert_eq!(
        treatment.unknown_cost_cells, 1,
        "the unknown-cost cell is counted as unknown, not as a priced cell"
    );
    assert_eq!(treatment.known_cost_cells, 1);
    assert_eq!(
        treatment.average_known_cost_usd,
        Some(10.0),
        "the priced average must be the mean of PRICED cells only; a coerced $0 would make it 5.0"
    );

    // The cross-arm cost delta is refused (with a reason) because one arm has an unknown cell.
    // A silent $0 would instead produce a concrete, and dishonest, delta.
    let comparison = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(
        comparison.cost_delta_usd, None,
        "an unknown-cost cell in either arm must disable the cost delta, not fabricate one"
    );
    assert!(
        comparison
            .cost_delta_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("unknown")),
        "the disabled delta must name the unknown/non-numeric cause"
    );
}
