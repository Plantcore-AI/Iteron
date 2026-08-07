//! D12-03 oracle: `core-eval` reads the versioned JSON contract, never the human stderr ledger.
//!
//! The gap under closure is "Eval parses the human stderr ledger line instead of the versioned JSON
//! contract". A consumer that scraped the CLI's human ledger on stderr (`turns=... | cost=$...`)
//! would believe whatever number that prose carried; the trustworthy consumer derives every terminal
//! metric from the versioned machine JSON on **stdout** plus the OS **exit code**, and treats stderr
//! as opaque diagnostics only.
//!
//! These tests pin that invariant end to end:
//!   * [`core_eval::parse_final_result`] takes ONLY stdout bytes and the process exit code — stderr is
//!     not even an input — and a human ledger line fed where the JSON belongs is rejected, never
//!     scraped into a result;
//!   * driven through the real [`core_eval::run_evaluation`] pipeline, a Core process that floods
//!     stderr with a conflicting ledger (`turns=999999 | cost=$9.99`) yields cells whose metrics come
//!     from the stdout JSON (`turns=2`), and the stderr number never reaches any metric.
//!
//! The whole target is a new file, absent on the base branch, so acceptance is RED there and GREEN
//! once this oracle is present against the trustworthy runner.

use core_eval::{ContractError, RunStatus, parse_final_result};

// A valid versioned result on stdout. Its authoritative metrics (turns=2, budget_exhausted, unknown
// cost) deliberately disagree with the conflicting human ledger the producer would print to stderr.
const VALID_BUDGET_RESULT: &[u8] = br#"{"schema_version":4,"type":"result","outcome":"budget_exhausted","reason":"max_turns","success":false,"assistant_text":"partial","run_id":"run-d12-03","cost_usd":null,"cost_status":"unknown","cost_reason":"no_verified_rate_card","turns":2,"exit_code":3,"error":null}"#;

#[test]
fn terminal_metrics_come_from_the_stdout_json_contract() {
    // The parse seam consumes stdout bytes and the OS exit code — nothing else. There is no stderr
    // parameter, so a human ledger on stderr is structurally incapable of altering a metric.
    let result = parse_final_result(VALID_BUDGET_RESULT, 3).expect("valid stdout contract parses");

    assert_eq!(
        result.turns, 2,
        "turns are read from the versioned stdout JSON"
    );
    assert_ne!(
        result.turns, 999_999,
        "no stderr ledger number can reach a metric"
    );
    assert_eq!(result.outcome, "budget_exhausted");
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.run_status(), RunStatus::Censored);
    assert!(
        result.cost().unwrap().usd.is_none(),
        "cost is unknown per the JSON; a human `$9.99` on stderr must not become a number"
    );
}

#[test]
fn a_human_ledger_line_is_rejected_and_never_scraped_as_a_result() {
    // This is exactly the kind of prose the CLI prints to stderr. Fed where the versioned JSON is
    // expected, it fails the contract closed — it is never re-interpreted into turns/cost.
    let error: ContractError =
        parse_final_result(b"turns=999999 | cost=$9.99 | tokens in=1 out=2", 0)
            .expect_err("a human ledger line is not a versioned result and must be rejected");
    assert!(
        matches!(error, ContractError::MalformedJson(_)),
        "a ledger line must fail as malformed JSON, not be scraped, got {error:?}"
    );

    // A truncated JSON object is likewise rejected rather than partially believed.
    assert!(matches!(
        parse_final_result(br#"{"schema_version":4,"#, 2),
        Err(ContractError::MalformedJson(_))
    ));
}

#[test]
fn a_process_exit_that_disagrees_with_the_json_is_a_contract_error() {
    // The OS exit code is authoritative alongside stdout: a result claiming exit 3 while the process
    // exited 0 is a contract violation, not something reconciled from a human summary line.
    assert!(matches!(
        parse_final_result(VALID_BUDGET_RESULT, 0),
        Err(ContractError::ExitMismatch {
            process: 0,
            result: 3
        })
    ));
}

/// End-to-end proof through the real runner: even when the Core process floods stderr with a
/// conflicting human ledger, the persisted cells take every metric from the stdout JSON contract, and
/// the stderr `turns=999999` never reaches a metric on any cell.
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
        let mut permissions = std::fs::metadata(&path)
            .expect("stat fake core")
            .permissions();
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
            dockerhub_tag: None,
            fail_to_pass: vec!["legacy::true".into()],
            pass_to_pass: Vec::new(),
            test_cmd: std::collections::BTreeMap::from([("legacy".into(), "true".into())]),
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
    async fn cells_take_metrics_from_stdout_and_ignore_the_conflicting_stderr_ledger() {
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
            max_attempts: 1,
        };

        let manifest = tokio::time::timeout(Duration::from_secs(120), run_evaluation(&options))
            .await
            .expect("evaluation stays bounded")
            .expect("per-cell faults belong in the artifact, not the top-level error");

        // 2 tasks x 2 configs x 1 seed.
        assert_eq!(manifest.cells.len(), 4);

        // The stderr ledger shouted turns=999999 on EVERY invocation. It must never reach a metric.
        assert!(
            manifest
                .cells
                .iter()
                .all(|cell| cell.turns != Some(999_999)),
            "the human stderr ledger number must never become a cell metric"
        );

        // The valid-budget cells parse their metrics from the stdout JSON contract (turns=2).
        let valid: Vec<_> = manifest
            .cells
            .iter()
            .filter(|cell| cell.task == "valid-budget")
            .collect();
        assert_eq!(valid.len(), 2);
        for cell in &valid {
            assert_eq!(
                cell.run_status,
                RunStatus::Censored,
                "budget_exhausted is censored"
            );
            assert_eq!(
                cell.turns,
                Some(2),
                "turns come from the stdout JSON, not stderr"
            );
            assert_eq!(cell.terminal_outcome.as_deref(), Some("budget_exhausted"));
            assert_eq!(cell.exit_code, Some(3));
        }

        // The malformed-contract cells fail the stdout JSON contract rather than adopting the stderr
        // `turns=999999` number — the stdout contract is authoritative, and it fails closed.
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
            assert_eq!(
                cell.turns, None,
                "a failed contract yields no scraped turn count"
            );
        }
    }
}
