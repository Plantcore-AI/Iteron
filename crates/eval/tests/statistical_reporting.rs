use iteron_eval::{
    CellResult, CostStatus, InsufficientPowerReason, OracleStatus, Partition, RunStatus,
    SamplingControl, StatisticalConclusion, aggregate, compare,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedSeedFixture {
    minimum_seeds: u64,
    baseline: String,
    treatment: String,
    outcomes: Vec<FixedOutcome>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedOutcome {
    task: String,
    config: String,
    seed: u64,
    resolved: bool,
}

fn load_fixture() -> FixedSeedFixture {
    serde_json::from_str(include_str!("fixtures/d14_07_fixed_seed_outcomes.json"))
        .expect("D14-07 fixed-seed fixture is valid JSON")
}

fn cell(outcome: &FixedOutcome) -> CellResult {
    CellResult {
        task: outcome.task.clone(),
        config: outcome.config.clone(),
        seed: outcome.seed,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/fixed-seed-fixture.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: Some(outcome.resolved),
        run_status: RunStatus::Completed,
        failure_phase: None,
        exit_code: Some(0),
        terminal_outcome: Some("done".into()),
        cost_status: CostStatus::Zero,
        cost_usd: None,
        cost_reason: None,
        turns: Some(1),
        kernel_tax: None,
        oracle_status: OracleStatus::Passed,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: outcome.seed,
            enforcement: "fixed_fixture".into(),
            reason: None,
        },
        elapsed_ms: 1,
        error: None,
        candidate_diff: None,
    }
}

#[test]
fn d14_07_variance_floor_fixture_reports_typed_not_significant_conclusion() {
    let fixture = load_fixture();
    let cells: Vec<_> = fixture.outcomes.iter().map(cell).collect();
    let summary = aggregate(&cells, fixture.minimum_seeds);
    let comparison = compare(&summary, &fixture.baseline, &fixture.treatment);

    assert!(!summary.underpowered);
    assert!((comparison.resolved_rate_delta - 1.0 / 6.0).abs() < f64::EPSILON);
    assert_eq!(
        comparison.statistical_conclusion,
        StatisticalConclusion::NotSignificant
    );
    assert!(!comparison.statistically_significant);
    assert!(comparison.delta_ci95[0] <= 0.0);
    assert!(comparison.delta_ci95[1] >= 0.0);
    let machine_report = serde_json::to_value(&comparison).unwrap();
    assert_eq!(
        machine_report["statistical_conclusion"]["status"],
        "not_significant"
    );
}

#[test]
fn d14_07_identical_fixed_seed_inputs_report_byte_identical_confidence_intervals() {
    let fixture = load_fixture();
    let cells: Vec<_> = fixture.outcomes.iter().map(cell).collect();
    let first = compare(
        &aggregate(&cells, fixture.minimum_seeds),
        &fixture.baseline,
        &fixture.treatment,
    );

    let repeated = compare(
        &aggregate(&cells, fixture.minimum_seeds),
        &fixture.baseline,
        &fixture.treatment,
    );
    assert_eq!(
        first.delta_ci95.map(f64::to_bits),
        repeated.delta_ci95.map(f64::to_bits)
    );
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );

    let reversed: Vec<_> = cells.into_iter().rev().collect();
    let reordered = compare(
        &aggregate(&reversed, fixture.minimum_seeds),
        &fixture.baseline,
        &fixture.treatment,
    );
    assert_eq!(
        first.delta_ci95.map(f64::to_bits),
        reordered.delta_ci95.map(f64::to_bits),
        "aggregation order must not perturb the reported confidence interval"
    );
}

#[test]
fn d14_07_below_seed_floor_cannot_be_promoted_to_significant() {
    let outcomes: Vec<_> = ["alpha", "beta"]
        .into_iter()
        .flat_map(|task| {
            [1, 2].into_iter().flat_map(move |seed| {
                [
                    FixedOutcome {
                        task: task.into(),
                        config: "verify_OFF".into(),
                        seed,
                        resolved: false,
                    },
                    FixedOutcome {
                        task: task.into(),
                        config: "verify_ON".into(),
                        seed,
                        resolved: true,
                    },
                ]
            })
        })
        .collect();
    let cells: Vec<_> = outcomes.iter().map(cell).collect();
    let summary = aggregate(&cells, 3);
    let comparison = compare(&summary, "verify_OFF", "verify_ON");

    assert!(summary.underpowered);
    assert!(comparison.delta_ci95[0] > 0.0);
    assert_eq!(
        comparison.statistical_conclusion,
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::BelowMinimumSeeds)
    );
    assert!(!comparison.statistically_significant);
    let machine_report = serde_json::to_value(&comparison).unwrap();
    assert_eq!(
        machine_report["statistical_conclusion"]["status"],
        "insufficient_power"
    );
    assert_eq!(
        machine_report["statistical_conclusion"]["reason"],
        "below_minimum_seeds"
    );
}
