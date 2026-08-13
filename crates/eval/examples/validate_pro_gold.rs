use clap::Parser;
use iteron_eval::{
    BenchmarkReference, CorpusManifest, EvaluationPurpose, Partition, ProvisioningBackend,
    RunStatus, TestSetReceipt, TwoSidedOracleReceipt,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_GOLD_PATCH_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Validate one withheld SWE-bench Pro gold patch and emit a bound receipt")]
struct Args {
    #[arg(long)]
    corpus: PathBuf,
    #[arg(long)]
    task: String,
    #[arg(long)]
    gold_patch: PathBuf,
    #[arg(long)]
    oracle_workspace: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    source: String,
    #[arg(long)]
    source_revision: String,
    #[arg(long)]
    recorded_at: String,
    #[arg(long)]
    executor: String,
    #[arg(long, default_value_t = 900)]
    checkout_timeout_secs: u64,
    #[arg(long, default_value_t = 900)]
    oracle_timeout_secs: u64,
}

#[derive(Debug, Serialize)]
struct GoldValidationRecord {
    schema_version: u32,
    record_type: &'static str,
    corpus_version: String,
    dataset_digest: String,
    source_evaluation: SourceEvaluation,
    cells: Vec<GoldValidationCell>,
}

#[derive(Debug, Serialize)]
struct SourceEvaluation {
    kind: &'static str,
    source: String,
    source_revision: String,
    recorded_at: String,
    executor: String,
    target_arch: &'static str,
    gold_patch_sha256: String,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct GoldValidationCell {
    task: String,
    partition: Partition,
    benchmark: BenchmarkReference,
    run_status: RunStatus,
    resolved: bool,
    evidence: GoldValidationEvidence,
}

#[derive(Debug, Serialize)]
struct GoldValidationEvidence {
    two_sided_oracle: TwoSidedOracleReceipt,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.source_revision.len() != 40
        || !args
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--source-revision must be a full lowercase Git SHA-1".into());
    }
    if args.recorded_at.trim().is_empty() || args.executor.trim().is_empty() {
        return Err("--recorded-at and --executor must be non-empty".into());
    }
    if args.output.exists() {
        return Err(format!("refusing to overwrite `{}`", args.output.display()).into());
    }

    let corpus = CorpusManifest::load(&args.corpus)?;
    let task = corpus
        .task_for(&args.task, EvaluationPurpose::Score)?
        .ok_or_else(|| format!("task `{}` is not present in the corpus", args.task))?
        .clone();
    let benchmark = task
        .benchmark
        .as_ref()
        .ok_or("selected task does not carry a benchmark binding")?
        .reference
        .clone();
    if benchmark.dataset_revision != args.source_revision {
        return Err("receipt source revision does not match the corpus binding".into());
    }
    if task.provenance.source != args.source {
        return Err("receipt source URL does not match the corpus provenance binding".into());
    }

    let gold_patch = read_bounded(&args.gold_patch)?;
    let gold_patch_sha256 = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(gold_patch.as_bytes()))
    );
    let receipt = iteron_eval::runner::score_candidate_diff(
        &task,
        &gold_patch,
        &args.oracle_workspace,
        Duration::from_secs(args.checkout_timeout_secs),
        Duration::from_secs(args.oracle_timeout_secs),
    )
    .await
    .map_err(|error| format!("gold-patch oracle failed: {error}"))?;
    if !receipt.resolved {
        return Err(
            format!("gold patch did not resolve under the two-sided oracle: {receipt:#?}").into(),
        );
    }
    require_docker(&receipt.fail_to_pass_before)?;
    require_docker(&receipt.fail_to_pass_after)?;
    require_docker(&receipt.pass_to_pass_before)?;
    require_docker(&receipt.pass_to_pass_after)?;

    let record = GoldValidationRecord {
        schema_version: 1,
        record_type: "live_gold_patch_validation",
        corpus_version: corpus.corpus_version,
        dataset_digest: corpus.dataset_digest,
        source_evaluation: SourceEvaluation {
            kind: "swe-bench-pro-os-gold-validation",
            source: args.source,
            source_revision: args.source_revision,
            recorded_at: args.recorded_at,
            executor: args.executor,
            target_arch: std::env::consts::ARCH,
            gold_patch_sha256,
            note: "Live gold-patch oracle run; the upstream solution patch is deliberately not stored in the corpus.",
        },
        cells: vec![GoldValidationCell {
            task: task.id,
            partition: task.partition,
            benchmark,
            run_status: RunStatus::Completed,
            resolved: receipt.resolved,
            evidence: GoldValidationEvidence {
                two_sided_oracle: receipt,
            },
        }],
    };
    write_fresh(&args.output, &serde_json::to_vec_pretty(&record)?)?;
    println!("{}", args.output.display());
    Ok(())
}

fn read_bounded(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(
        iteron_tunables::param_integer(
            "eval.crates.eval.examples.validate_pro_gold.max_gold_patch_bytes",
            MAX_GOLD_PATCH_BYTES,
        ) + 1,
    )
    .read_to_end(&mut bytes)?;
    if bytes.len() as u64
        > iteron_tunables::param_integer(
            "eval.crates.eval.examples.validate_pro_gold.max_gold_patch_bytes",
            MAX_GOLD_PATCH_BYTES,
        )
    {
        return Err("gold patch exceeds 8 MiB".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn require_docker(receipt: &TestSetReceipt) -> Result<(), Box<dyn std::error::Error>> {
    if receipt
        .commands
        .iter()
        .any(|command| command.backend != ProvisioningBackend::Docker || !command.egress_disabled)
    {
        return Err("gold receipt requires the Docker backend with egress disabled".into());
    }
    Ok(())
}

fn write_fresh(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
