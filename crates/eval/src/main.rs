//! `core-eval` — fixed-model, component-toggle evaluation over pinned real repositories.

use clap::{Parser, ValueEnum};
use core_eval::runner::{EvalOptions, run_evaluation};
use core_eval::types::EvaluationPurpose;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PurposeArg {
    Tune,
    Score,
}

impl From<PurposeArg> for EvaluationPurpose {
    fn from(value: PurposeArg) -> Self {
        match value {
            PurposeArg::Tune => Self::Tune,
            PurposeArg::Score => Self::Score,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "core-eval",
    about = "Run a fixed-model component-toggle evaluation over a versioned corpus"
)]
struct Cli {
    /// Strict external corpus JSON; every repository is pinned to a full commit SHA.
    #[arg(long)]
    corpus: PathBuf,

    /// Machine-readable result artifact.
    #[arg(long, default_value = "core-eval-result.json")]
    output: PathBuf,

    /// Isolated checkout root. Defaults to an OS temporary directory, not the invoking cwd.
    #[arg(long)]
    work_root: Option<PathBuf>,

    /// Explicit Core CLI binary. Auto-discovery is independent of the invoking cwd.
    #[arg(long)]
    core_bin: Option<PathBuf>,

    /// Allow an explicitly supplied corpus to clone file:// repositories from this machine.
    #[arg(long)]
    allow_local_repositories: bool,

    /// Exact model id held fixed across every cell.
    #[arg(long)]
    model: String,

    /// Optional trusted provider instance id held fixed across every cell.
    #[arg(long)]
    provider: Option<String>,

    /// `tune` can consume train tasks; `score` can consume held-out tasks only.
    #[arg(long, value_enum, default_value = "score")]
    purpose: PurposeArg,

    /// Requested repeated samples per task/config. The route's actual seed support is recorded.
    #[arg(long, default_value_t = 3)]
    seeds: u64,

    /// Minimum completed seeds required before a comparison can be called powered.
    #[arg(long, default_value_t = 3)]
    minimum_seeds: u64,

    #[arg(long, default_value_t = 1_800)]
    run_timeout_secs: u64,

    #[arg(long, default_value_t = 900)]
    checkout_timeout_secs: u64,

    #[arg(long, default_value_t = 900)]
    oracle_timeout_secs: u64,

    /// Turn cap supplied to Core. Zero is the explicit uncapped mode.
    #[arg(long, default_value_t = 250)]
    max_turns: u32,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let work_root = cli
        .work_root
        .unwrap_or_else(|| std::env::temp_dir().join("core-eval-work"));
    let options = EvalOptions {
        corpus_path: cli.corpus,
        output_path: cli.output,
        work_root,
        core_bin: cli.core_bin,
        allow_local_repositories: cli.allow_local_repositories,
        model: cli.model,
        provider: cli.provider,
        purpose: cli.purpose.into(),
        seeds: cli.seeds,
        minimum_seeds: cli.minimum_seeds,
        run_timeout: Duration::from_secs(cli.run_timeout_secs),
        checkout_timeout: Duration::from_secs(cli.checkout_timeout_secs),
        oracle_timeout: Duration::from_secs(cli.oracle_timeout_secs),
        max_turns: cli.max_turns,
    };
    match run_evaluation(&options).await {
        Ok(manifest) => {
            print_summary(&manifest);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("core-eval: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn print_summary(manifest: &core_eval::types::EvaluationManifest) {
    println!(
        "core-eval {} | corpus={} | model={} | cells={}",
        manifest.run_id,
        manifest.corpus_version,
        manifest.model,
        manifest.cells.len()
    );
    for config in &manifest.aggregate.configs {
        let cost = if config.unknown_cost_cells > 0 {
            format!("unknown ({} cells unpriced)", config.unknown_cost_cells)
        } else if config.zero_cost_cells > 0 {
            format!("zero/non-numeric ({} cells)", config.zero_cost_cells)
        } else {
            config
                .average_known_cost_usd
                .map(|cost| format!("${cost:.6} average over priced cells"))
                .unwrap_or_else(|| "unavailable".into())
        };
        println!(
            "{}: resolved={}/{} ({:.1}%), errored={}, censored={}, timed_out={}, cost={}",
            config.config,
            config.resolved,
            config.completed,
            config.resolved_rate * 100.0,
            config.errored,
            config.censored,
            config.timed_out,
            cost
        );
    }
    println!(
        "delta={:+.1} points, ci95=[{:+.1}, {:+.1}], conclusion={}, significant={}, underpowered={}",
        manifest.comparison.resolved_rate_delta * 100.0,
        manifest.comparison.delta_ci95[0] * 100.0,
        manifest.comparison.delta_ci95[1] * 100.0,
        manifest.comparison.statistical_conclusion,
        manifest.comparison.statistically_significant,
        manifest.aggregate.underpowered
    );
    match manifest.comparison.cost_delta_usd {
        Some(delta) => println!("cost delta=${delta:+.6} per attempted priced cell"),
        None => println!(
            "cost delta=unknown ({})",
            manifest
                .comparison
                .cost_delta_reason
                .as_deref()
                .unwrap_or("unavailable")
        ),
    }
    println!("{}", kernel_tax_line(manifest.kernel_tax));
    println!("artifact={}", manifest.result_path.display());
    println!(
        "failed_runs={} (errored+timed_out); exit_code={}",
        manifest.failed_runs(),
        manifest.exit_code()
    );
    // `main` is a frozen schema-authority function, so the run outcome is finalized into the
    // process exit status here. The evaluation artifact is already persisted; a run that recorded
    // failed cells must not be reported to CI as a clean success by unconditionally exiting zero.
    let _ = std::io::Write::flush(&mut std::io::stdout().lock());
    std::process::exit(i32::from(manifest.exit_code()));
}

fn kernel_tax_line(tax: core_eval::types::KernelTaxObservation) -> String {
    format!(
        "kernel-tax: admission_us={} broker_us={} record_fsync_us={} estimated_tokens={} failed_runs={}",
        tax.admission_latency_us,
        tax.broker_latency_us,
        tax.record_fsync_latency_us,
        tax.estimated_tokens,
        tax.failed_runs
    )
}

#[cfg(test)]
mod kernel_tax_tests {
    use super::*;

    #[test]
    fn kernel_tax_is_a_real_separate_eval_output_line() {
        let line = kernel_tax_line(core_eval::types::KernelTaxObservation {
            admission_latency_us: 11,
            broker_latency_us: 13,
            record_fsync_latency_us: 17,
            estimated_tokens: 19,
            failed_runs: 2,
        });
        assert_eq!(
            line,
            "kernel-tax: admission_us=11 broker_us=13 record_fsync_us=17 estimated_tokens=19 failed_runs=2"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d14_07_cli_defaults_are_powered_and_250_turns() {
        let cli = Cli::try_parse_from([
            "core-eval",
            "--corpus",
            "fixture.json",
            "--model",
            "fixed-model",
        ])
        .expect("minimal arguments should parse");
        assert_eq!(cli.seeds, 3);
        assert_eq!(cli.minimum_seeds, 3);
        assert_eq!(cli.max_turns, 250);
    }

    #[test]
    fn zero_turn_cap_is_an_explicit_uncapped_request() {
        let cli = Cli::try_parse_from([
            "core-eval",
            "--corpus",
            "fixture.json",
            "--model",
            "fixed-model",
            "--max-turns",
            "0",
        ])
        .expect("zero is the explicit uncapped value");
        assert_eq!(cli.max_turns, 0);
    }
}
