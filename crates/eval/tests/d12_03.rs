//! D12-03 oracle: `core-eval` reads the versioned JSON contract, never the human stderr ledger.
//!
//! The gap under closure is "Eval parses the human stderr ledger line instead of the versioned JSON
//! contract": a consumer that scraped the CLI's human ledger on stderr (`turns=... | cost=$...`)
//! would believe whatever number that prose carried, and it threw the stderr away on a contract
//! failure — leaving a broken run undebuggable.
//!
//! The fix keeps every terminal metric sourced from [`core_eval::parse_final_result`] over stdout and
//! the OS exit code alone, and adds [`core_eval::contract::contract_failure_detail`], which — only on
//! a contract failure — retains the human stderr as *labelled diagnostics*, never as a metric.
//! `contract_failure_detail` is absent on the base branch, so this whole test target does not compile
//! there (RED); with the fix in place every assertion below holds (GREEN).

use core_eval::contract::contract_failure_detail;
use core_eval::{ContractError, RunStatus, parse_final_result};

const VALID_BUDGET_RESULT: &[u8] = br#"{"schema_version":4,"type":"result","outcome":"budget_exhausted","reason":"max_turns","success":false,"assistant_text":"partial","run_id":"run-d12-03","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":2,"exit_code":3,"error":null}"#;

// The human ledger the CLI prints to stderr, deliberately disagreeing with the stdout JSON on every
// metric a naive scraper would read: it screams turns=999999 and a $9.99 cost.
const CONFLICTING_STDERR: &[u8] =
    b"core run LEDGER turns=999999 | cost=$9.99 | tokens in=123 out=456 | D12_03_STDERR_MARKER\n";

#[test]
fn terminal_metrics_come_from_stdout_json_not_the_stderr_ledger() {
    // Authoritative parse of a valid stdout contract; exit code matches the JSON exit_code.
    let result = parse_final_result(VALID_BUDGET_RESULT, 3).expect("valid stdout contract parses");

    // The stdout JSON is authoritative. A stderr scraper would have read 999999 / $9.99.
    assert_eq!(result.turns, 2, "turns must come from the stdout JSON, not stderr");
    assert_ne!(result.turns, 999_999, "the stderr ledger must never reach a metric");
    assert_eq!(result.outcome, "budget_exhausted");
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.run_status(), RunStatus::Censored);
    assert!(
        result.cost().unwrap().usd.is_none(),
        "cost is unknown per the JSON; the stderr $9.99 must not become a number"
    );
}

#[test]
fn a_malformed_stdout_contract_keeps_stderr_as_diagnostics_only() {
    // A truncated stdout object cannot be parsed. A scraper of the stderr `turns=999999` line would
    // have wrongly "succeeded"; the contract fails closed instead, and the human stderr is retained
    // ONLY as labelled diagnostic evidence so the failure is debuggable.
    let error: ContractError = parse_final_result(br#"{"schema_version":4,"#, 2)
        .expect_err("a malformed stdout contract must fail closed, never fall back to stderr");
    assert!(
        matches!(error, ContractError::MalformedJson(_)),
        "the authoritative failure is the stdout contract error, got {error:?}"
    );

    let contract_message = error.to_string();
    let detail = contract_failure_detail(&error, CONFLICTING_STDERR);
    assert!(
        detail.contains(contract_message.as_str()),
        "the authoritative contract error must lead the detail: {detail}"
    );
    assert!(
        detail.contains("D12_03_STDERR_MARKER"),
        "the human stderr must be retained as failure evidence: {detail}"
    );
    assert!(
        detail.contains("diagnostic only"),
        "the stderr must be labelled diagnostics, never adopted as a metric: {detail}"
    );
}

#[test]
fn empty_stderr_yields_a_clean_contract_error_with_no_diagnostic_tail() {
    let error = parse_final_result(br#"turns=9 cost=$0.00"#, 0)
        .expect_err("a non-JSON stdout must fail the contract, not be scraped as a ledger");
    // With no stderr evidence the detail is exactly the contract error — no dangling label.
    assert_eq!(contract_failure_detail(&error, b""), error.to_string());
    assert!(!contract_failure_detail(&error, b"").contains("core stderr"));
}

#[test]
fn oversized_stderr_diagnostics_are_bounded_and_marked() {
    let error = parse_final_result(br#"{"schema_version":4,"#, 0).expect_err("malformed contract");
    let flood = vec![b'x'; 200_000];
    let detail = contract_failure_detail(&error, &flood);
    assert!(
        detail.ends_with("[stderr truncated]"),
        "an unbounded stderr flood must be truncated with a marker"
    );
    assert!(
        detail.matches('x').count() <= 4 * 1024,
        "the retained stderr diagnostic must be bounded, got {} chars",
        detail.matches('x').count()
    );
}

/// End-to-end proof through the real runner: even when the Core process floods stderr with a
/// conflicting human ledger, the persisted cells take their metrics from the stdout JSON contract,
/// and a cell whose stdout contract is malformed records the human stderr only as failure evidence.
#[cfg(unix)]
mod pipeline {
    use core_eval::corpus::{
        CORPUS_SCHEMA_VERSION, CorpusManifest, CorpusTask, Provenance, digest_tasks,
    };
    use core_eval::{EvalOptions, EvaluationPurpose, Partition, RunStatus, run_evaluation};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("core-eval-d12-03-{}-{nonce:x}", std::process::id()));
            std::fs::create_dir(&path).expect("create isolated D12-03 root");
            Self(path)
        }

        fn join(&self, path: impl AsRef<Path>) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(cwd: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("spawn git fixture command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output is UTF-8")
            .trim()
            .to_owned()
    }

    fn real_repository(root: &TempRoot) -> (String, String) {
        let repo = root.join("source-repo");
        std::fs::create_dir(&repo).expect("create source repository");
        git(&repo, &["init", "--quiet"]);
        std::fs::write(repo.join("README.md"), "fixture\n").expect("write fixture state");
        git(&repo, &["add", "README.md"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=core-eval",
                "-c",
                "user.email=core-eval@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        );
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        let canonical = repo.canonicalize().expect("canonical source repository");
        let url = url::Url::from_file_path(canonical)
            .expect("file URL")
            .to_string();
        (url, commit)
    }

    /// A stand-in Core CLI that always floods stderr with a conflicting human ledger, then — keyed by
    /// the task prompt — emits either a VALID `budget_exhausted` stdout contract (turns=2, exit 3) or
    /// a truncated/malformed stdout object (exit 2). No cell completes, so the egress-off oracle and
    /// the platform sandbox are never entered — the test stays deterministic on the Linux merge gate.
    fn fake_core(root: &TempRoot) -> PathBuf {
        let path = root.join("fake-core");
        let script = "#!/bin/sh\n\
printf 'core run LEDGER turns=999999 | cost=$9.99 | tokens in=123 out=456 | D12_03_STDERR_MARKER\\n' 1>&2\n\
case \"$*\" in\n\
  *malformed*)\n\
    printf '%s' '{\"schema_version\":4,'\n\
    exit 2\n\
    ;;\n\
  *)\n\
    printf '%s' '{\"schema_version\":4,\"type\":\"result\",\"outcome\":\"budget_exhausted\",\"reason\":\"max_turns\",\"success\":false,\"assistant_text\":\"partial\",\"run_id\":\"run-d12-03\",\"cost_usd\":null,\"cost_status\":\"unknown\",\"cost_reason\":\"no_verified_rate_card\",\"turns\":2,\"exit_code\":3,\"error\":null}'\n\
    exit 3\n\
    ;;\n\
esac\n";
        std::fs::write(&path, script).expect("write fake core");
        let mut permissions = std::fs::metadata(&path).expect("stat fake core").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("make fake core executable");
        path
    }

    fn task(id: &str, repo_url: &str, commit: &str) -> CorpusTask {
        CorpusTask {
            id: id.to_owned(),
            repo_url: repo_url.to_owned(),
            commit: commit.to_owned(),
            prompt: format!("resolve {id}"),
            verify_command: "true".into(),
            ground_truth_command: "true".into(),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "d12-03-stdout-contract-not-stderr".into(),
                task_id: id.to_owned(),
                license: Some("test-fixture-only".into()),
            },
            benchmark: None,
        }
    }

    #[tokio::test]
    async fn cells_take_metrics_from_stdout_and_keep_stderr_only_as_diagnostics() {
        let root = TempRoot::new();
        let (repo_url, commit) = real_repository(&root);
        let tasks = vec![
            task("valid-budget", &repo_url, &commit),
            task("malformed-contract", &repo_url, &commit),
        ];
        let corpus = CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            corpus_version: "d12-03-v1".into(),
            dataset_digest: digest_tasks(&tasks).expect("digest tasks"),
            tasks,
        };
        corpus.validate().expect("corpus is valid");
        let corpus_path = root.join("corpus.json");
        std::fs::write(
            &corpus_path,
            serde_json::to_vec_pretty(&corpus).expect("encode corpus"),
        )
        .expect("write corpus");

        let options = EvalOptions {
            corpus_path,
            output_path: root.join("out/evaluation.json"),
            work_root: root.join("work"),
            core_bin: Some(fake_core(&root)),
            allow_local_repositories: true,
            model: "fixture/model".into(),
            provider: None,
            purpose: EvaluationPurpose::Score,
            seeds: 1,
            minimum_seeds: 1,
            run_timeout: Duration::from_secs(30),
            checkout_timeout: Duration::from_secs(60),
            oracle_timeout: Duration::from_secs(5),
            max_turns: 4,
        };

        let manifest = tokio::time::timeout(Duration::from_secs(120), run_evaluation(&options))
            .await
            .expect("evaluation stays bounded")
            .expect("per-cell faults belong in the artifact, not the top-level error");

        // 2 tasks x 2 configs x 1 seed.
        assert_eq!(manifest.cells.len(), 4);

        // The valid-budget cells parse their metrics from the stdout JSON contract. The stderr ledger
        // shouted turns=999999; a scraper would have recorded that. The JSON (turns=2) wins.
        let valid: Vec<_> = manifest
            .cells
            .iter()
            .filter(|cell| cell.task == "valid-budget")
            .collect();
        assert_eq!(valid.len(), 2);
        for cell in &valid {
            assert_eq!(cell.run_status, RunStatus::Censored, "budget_exhausted is censored");
            assert_eq!(cell.turns, Some(2), "turns must come from stdout JSON, not stderr");
            assert_ne!(cell.turns, Some(999_999), "the stderr ledger must never reach a metric");
            assert_eq!(cell.terminal_outcome.as_deref(), Some("budget_exhausted"));
            assert_eq!(cell.exit_code, Some(3));
        }

        // The malformed-contract cells fail the stdout contract (never fall back to the stderr
        // number) and retain the human stderr ONLY as labelled failure evidence.
        let malformed: Vec<_> = manifest
            .cells
            .iter()
            .filter(|cell| cell.task == "malformed-contract")
            .collect();
        assert_eq!(malformed.len(), 2);
        for cell in &malformed {
            assert_eq!(cell.run_status, RunStatus::Errored);
            assert_eq!(cell.failure_phase.as_deref(), Some("core_contract"));
            assert_eq!(cell.exit_code, Some(2));
            let error = cell.error.as_deref().expect("an errored cell records an error");
            assert!(
                error.contains("D12_03_STDERR_MARKER"),
                "the human stderr must be retained as failure evidence, got {error:?}"
            );
            assert!(
                error.contains("diagnostic only"),
                "any stderr text must be labelled diagnostic, never adopted as a metric: {error:?}"
            );
        }
    }
}
