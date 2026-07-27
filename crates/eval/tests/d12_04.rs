//! D12-04 oracle: `core-eval` never silently converts an unknown cost into a numeric $0.
//!
//! The gap under closure is "Eval silently converts unknown cost to $0". A run whose Core process
//! could not establish a dollar amount (no verified rate card) must stay *typed* as unknown from
//! the moment its JSON contract is read, through per-cell accounting, into aggregation and the
//! cross-config comparison. The dishonest behaviour would coerce that absent amount into a concrete
//! `$0.0000`: a priced-zero cell that then drags a config's average toward zero and makes an
//! unpriced comparison look "fully priced" with a fabricated $0 delta.
//!
//! These tests pin the honest-cost invariant at every layer core-eval owns:
//!   * the contract reader ([`parse_final_result`] -> [`CliFinalResult::cost`]) yields
//!     `usd == None` for an unknown cost, while a genuine `known` `$0.00` is preserved as
//!     `Some(0.0)` — proving the fix distinguishes "no amount" from "an amount that is zero";
//!   * [`aggregate`] excludes an unknown-cost cell from `average_known_cost_usd` (it is NOT
//!     averaged in as a zero) and counts it as `unknown_cost_cells`, never `zero_cost_cells`;
//!   * [`compare`] refuses to emit a `cost_delta_usd` when either arm carries an unknown cell,
//!     reporting the disabling reason instead of a fabricated $0.00 delta.
//!
//! The whole target is a new file, absent on the INTEG base, so acceptance is RED there and GREEN
//! once this oracle runs against the honest-cost runner. Every assertion below would FAIL under the
//! "unknown -> $0" coercion, so the oracle is non-vacuous.

use core_eval::types::CostObservation;
use core_eval::{
    CellResult, CostStatus, OracleStatus, Partition, RunStatus, SamplingControl, aggregate,
    compare, parse_final_result,
};

/// A valid, `deny_unknown_fields`-strict Core final-result JSON whose cost is UNKNOWN: the amount is
/// `null` and the status names it as unpriced. A successful `done` outcome so the cell is a real
/// completion, not a censored/errored one — the unknown cost must survive a *clean* completion.
const UNKNOWN_COST_RESULT: &[u8] = br#"{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"run-d12-04-unknown","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":2,"exit_code":0,"error":null}"#;

/// The contrast: a genuinely `known` cost that happens to be exactly `$0.00`. This is an *amount*
/// (Some(0.0)), categorically different from "no amount established". A blanket coercion in either
/// direction would collapse this distinction.
const KNOWN_ZERO_COST_RESULT: &[u8] = br#"{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"run-d12-04-known-zero","cost_usd":0.0,"cost_status":"known","cost_reason":null,"turns":1,"exit_code":0,"error":null}"#;

fn priced_cell(config: &str, seed: u64, status: CostStatus, usd: Option<f64>) -> CellResult {
    CellResult {
        task: "task".into(),
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
        cost_status: status,
        cost_usd: usd,
        cost_reason: (status == CostStatus::Unknown).then(|| "no_verified_rate_card".into()),
        turns: Some(2),
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
fn unknown_cost_from_core_contract_is_none_not_zero() {
    // The FRONT DOOR: whatever the runner later does, it must first read an honest cost off the
    // versioned contract. An unknown cost decodes to `None`, never `Some(0.0)`.
    let result = parse_final_result(UNKNOWN_COST_RESULT, 0)
        .expect("a valid done result with an unknown cost is a well-formed contract");
    // The raw decoded field is null -> None, not a silent zero.
    assert_eq!(
        result.cost_usd, None,
        "unknown cost_usd must decode to None"
    );
    assert_eq!(result.cost_status, "unknown");

    let observation: CostObservation = result.cost().expect("cost projection is valid");
    assert_eq!(observation.status, CostStatus::Unknown);
    assert_eq!(
        observation.usd, None,
        "an unknown cost must never be projected to a numeric $0"
    );
    assert_eq!(observation.reason.as_deref(), Some("no_verified_rate_card"));
}

#[test]
fn known_zero_cost_is_preserved_and_distinct_from_unknown() {
    // The fix must not overreach: a genuinely-priced $0.00 is an amount and stays `Some(0.0)`,
    // categorically distinct from the unknown case above.
    let result = parse_final_result(KNOWN_ZERO_COST_RESULT, 0)
        .expect("a valid done result with a known $0 cost is a well-formed contract");
    assert_eq!(result.cost_usd, Some(0.0));

    let observation = result.cost().expect("cost projection is valid");
    assert_eq!(observation.status, CostStatus::Known);
    assert_eq!(
        observation.usd,
        Some(0.0),
        "a verified $0.00 rate is a real amount and must be preserved"
    );

    // The two must not be conflated: unknown.usd() is None while known-zero.usd() is Some(0.0).
    let unknown = parse_final_result(UNKNOWN_COST_RESULT, 0)
        .expect("unknown contract parses")
        .cost()
        .expect("unknown cost projects");
    assert_ne!(
        observation.usd, unknown.usd,
        "known $0 and unknown must remain distinguishable, not both collapsed to a number"
    );
}

#[test]
fn unknown_cost_cell_is_excluded_from_average_not_counted_as_zero_dollars() {
    // One priced cell at $4.00 and one unknown-cost cell. Honest accounting averages ONLY the
    // priced cell ($4.00). The "unknown -> $0" bug would instead average (4.0 + 0.0)/2 == $2.00 and
    // miscount the unknown cell as a zero-cost cell.
    let cells = vec![
        priced_cell("verify_ON", 0, CostStatus::Known, Some(4.0)),
        priced_cell("verify_ON", 1, CostStatus::Unknown, None),
    ];
    let agg = aggregate(&cells, 1);
    let treated = agg
        .configs
        .iter()
        .find(|c| c.config == "verify_ON")
        .expect("treatment config is aggregated");

    assert_eq!(
        treated.average_known_cost_usd,
        Some(4.0),
        "the average must reflect only the priced cell, not a phantom $0 for the unknown one"
    );
    assert_eq!(treated.known_cost_cells, 1);
    assert_eq!(
        treated.unknown_cost_cells, 1,
        "the unpriced cell must be typed as unknown"
    );
    assert_eq!(
        treated.zero_cost_cells, 0,
        "an unknown cost is not a zero cost and must never be counted as one"
    );

    // The cell itself carries no fabricated amount.
    let unknown_cell = cells
        .iter()
        .find(|c| c.cost_status == CostStatus::Unknown)
        .expect("the unknown cell is present");
    assert_eq!(
        unknown_cell.cost_usd, None,
        "the persisted cell must keep an absent amount, not a coerced $0"
    );
}

#[test]
fn unknown_cost_disables_cost_delta_rather_than_reporting_zero_delta() {
    // A fully-priced baseline ($2.00 average) versus a treatment arm that contains one unknown-cost
    // cell. Because the treatment is not fully priced, the cost delta is DISABLED with a reason.
    // The "unknown -> $0" bug would make the treatment look fully priced ($2.00 average) and emit a
    // fabricated $0.00 cost delta.
    let cells = vec![
        priced_cell("verify_OFF", 0, CostStatus::Known, Some(2.0)),
        priced_cell("verify_OFF", 1, CostStatus::Known, Some(2.0)),
        priced_cell("verify_ON", 0, CostStatus::Known, Some(4.0)),
        priced_cell("verify_ON", 1, CostStatus::Unknown, None),
    ];
    let agg = aggregate(&cells, 1);

    let baseline = agg
        .configs
        .iter()
        .find(|c| c.config == "verify_OFF")
        .expect("baseline aggregated");
    assert_eq!(
        baseline.average_known_cost_usd,
        Some(2.0),
        "the fully-priced baseline reports a real average"
    );
    assert_eq!(baseline.unknown_cost_cells, 0);

    let comparison = compare(&agg, "verify_OFF", "verify_ON");
    assert_eq!(
        comparison.cost_delta_usd, None,
        "an unpriced arm must disable the cost delta, not report a fabricated $0.00 delta"
    );
    assert_eq!(
        comparison.cost_delta_reason.as_deref(),
        Some("unknown_or_non_numeric_cost_cells_present"),
        "the disabled delta must name why it is unavailable"
    );
}
