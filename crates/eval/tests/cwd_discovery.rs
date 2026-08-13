use iteron_eval::corpus::{CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
use iteron_eval::process::{ProcessSpec, run_process};
use iteron_eval::{CorpusManifest, CorpusTask, EvaluationManifest, Partition, RunStatus};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iteron-eval-non-workspace-cwd-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create isolated cwd-discovery root");
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

fn write_valid_corpus(root: &TempRoot) -> PathBuf {
    let missing_source = root.join("deliberately-missing-source-repository");
    let task = CorpusTask {
        id: "cwd-discovery".into(),
        repo_url: url::Url::from_file_path(&missing_source)
            .expect("absolute fixture path converts to a file URL")
            .to_string(),
        commit: "0".repeat(40),
        prompt: "the checkout intentionally fails before Core is invoked".into(),
        verify_command: "true".into(),
        ground_truth_command: "true".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["legacy::true".into()],
        pass_to_pass: Vec::new(),
        test_cmd: std::collections::BTreeMap::from([("legacy".into(), "true".into())]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "cwd-discovery-integration-v1".into(),
            task_id: "cwd-discovery".into(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    };
    let tasks = vec![task];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "cwd-discovery-v1".into(),
        dataset_digest: digest_tasks(&tasks).expect("digest valid fixture tasks"),
        tasks,
    };
    let path = root.join("corpus.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&manifest).expect("encode valid fixture corpus"),
    )
    .expect("write valid fixture corpus");
    path
}

#[cfg(unix)]
fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .expect("spawn git fixture command");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim()
        .to_owned()
}

#[cfg(unix)]
fn write_success_corpus(root: &TempRoot) -> PathBuf {
    let repo = root.join("source-repository");
    std::fs::create_dir(&repo).expect("create source repository");
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("status.txt"), "bad\n").expect("write source status");
    git(&repo, &["add", "status.txt"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=eval",
            "-c",
            "user.email=eval@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    );
    let commit = git(&repo, &["rev-parse", "HEAD"]);
    let task = CorpusTask {
        id: "relative-work-root".into(),
        repo_url: url::Url::from_file_path(repo.canonicalize().expect("canonical source"))
            .expect("source file URL")
            .to_string(),
        commit,
        prompt: "make status.txt contain good".into(),
        verify_command: "test \"$(cat status.txt)\" = good".into(),
        ground_truth_command: "test \"$(cat status.txt)\" = good".into(),
        dockerhub_tag: None,
        fail_to_pass: vec!["legacy::status".into()],
        pass_to_pass: Vec::new(),
        test_cmd: std::collections::BTreeMap::from([(
            "legacy".into(),
            "test \"$(cat status.txt)\" = good".into(),
        )]),
        partition: Partition::HeldOut,
        provenance: Provenance {
            source: "relative-work-root-integration-v1".into(),
            task_id: "relative-work-root".into(),
            license: Some("test-fixture-only".into()),
        },
        benchmark: None,
    };
    let tasks = vec![task];
    let manifest = CorpusManifest {
        schema_version: CORPUS_SCHEMA_VERSION,
        corpus_version: "relative-work-root-v1".into(),
        dataset_digest: digest_tasks(&tasks).expect("digest valid fixture tasks"),
        tasks,
    };
    let path = root.join("success-corpus.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&manifest).expect("encode successful fixture corpus"),
    )
    .expect("write successful fixture corpus");
    path
}

#[cfg(unix)]
fn write_boundary_checking_core(root: &TempRoot) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = root.join("boundary-checking-core");
    std::fs::write(
        &path,
        r#"#!/bin/sh
set -eu
workspace=
runs=
max_wall=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -C) shift; workspace=$1 ;;
    --runs-dir) shift; runs=$1 ;;
    --max-wall-secs) shift; max_wall=$1 ;;
  esac
  shift
done
test "$workspace" = .
test "$max_wall" = 1
case "$runs" in /*) ;; *) exit 81 ;; esac
for path in "$runs" "$HOME" "$ITERON_CONFIG_HOME" "$TMPDIR"; do
  case "$path" in /*) ;; *) exit 82 ;; esac
  test -d "$path"
  test "$(cd "$path" && pwd -P)" = "$path"
done
printf 'good\n' > ./status.txt
printf '%s\n' '{"schema_version":4,"type":"result","outcome":"done","reason":null,"success":true,"assistant_text":"done","run_id":"relative-work-root","cost_usd":null,"cost_status":"unknown","cost_reason":"fixture","turns":1,"exit_code":0,"error":null}'
"#,
    )
    .expect("write boundary-checking Core fixture");
    let mut permissions = path.metadata().expect("stat Core fixture").permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make Core fixture executable");
    path.canonicalize().expect("canonical Core fixture")
}

#[tokio::test]
async fn real_iteron_eval_from_non_workspace_cwd_discovers_core_or_errors_actionably() {
    let parent_cwd = std::env::current_dir().expect("read test-process cwd");
    let root = TempRoot::new();
    let outside_cwd = root.join("outside-workspace");
    std::fs::create_dir(&outside_cwd).expect("create non-workspace cwd");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical workspace");
    assert!(
        !outside_cwd
            .canonicalize()
            .expect("canonical test cwd")
            .starts_with(&workspace),
        "the child must genuinely start outside the Cargo workspace"
    );

    let corpus = write_valid_corpus(&root);
    let artifact = root.join("result.json");
    let work_root = root.join("work");
    let output = run_process(&ProcessSpec {
        program: PathBuf::from(env!("CARGO_BIN_EXE_iteron-eval")),
        args: vec![
            "--corpus".into(),
            corpus.into_os_string(),
            "--output".into(),
            artifact.as_os_str().to_owned(),
            "--work-root".into(),
            work_root.as_os_str().to_owned(),
            "--model".into(),
            "cwd-discovery-model".into(),
            "--purpose".into(),
            "score".into(),
            "--seeds".into(),
            "1".into(),
            "--minimum-seeds".into(),
            "1".into(),
            "--run-timeout-secs".into(),
            "1".into(),
            "--checkout-timeout-secs".into(),
            "1".into(),
            "--oracle-timeout-secs".into(),
            "1".into(),
            "--max-turns".into(),
            "1".into(),
            "--allow-local-repositories".into(),
        ],
        // `Command::current_dir` is local to the child; the test process cwd is never mutated, so
        // this remains race-free under the default parallel Rust test runner.
        cwd: Some(outside_cwd),
        clear_env: false,
        inherit_env: Vec::new(),
        env: Vec::new(),
        // The semantic child bounds above remain one second. This outer watchdog also covers the
        // evaluator's mandatory build-and-verify attestation passes over the real Cargo-built Core
        // binary, whose debug artifact is large and CPU scheduling is shared by all-target runs.
        timeout: Duration::from_secs(60),
        max_output_bytes: 128 * 1024,
    })
    .await
    .expect("launch the real Cargo-built iteron-eval binary");

    assert_eq!(
        std::env::current_dir().expect("re-read test-process cwd"),
        parent_cwd,
        "child-local current_dir must not mutate process-global cwd"
    );
    assert!(!output.timed_out, "cwd discovery has a hard process bound");
    assert!(!output.stdout_truncated);
    assert!(!output.stderr_truncated);
    // Gap D12-02 graded this binary's exit codes: 0 = every cell ran clean, 1 = the
    // evaluation ran but some cells errored or timed out, 2 = the harness itself could not run
    // (EVAL_EXIT_HARNESS), which is what a cwd-discovery failure reports. This fixture corpus
    // points at a deliberately missing source repository, so a successful discovery necessarily
    // produces errored cells and therefore exit 1, not 0. This test predates D12-02 and still
    // assumed the binary only ever returned 0 or 2.
    if output.exit_code == 0 || output.exit_code == 1 {
        let manifest: EvaluationManifest = serde_json::from_slice(
            &std::fs::read(&artifact).expect("successful evaluator writes its artifact"),
        )
        .expect("successful evaluator artifact follows its machine schema");
        assert_eq!(manifest.cells.len(), 2);
        assert!(manifest.cells.iter().all(|cell| {
            cell.run_status == RunStatus::Errored
                && cell.failure_phase.as_deref() == Some("checkout")
        }));
    } else {
        assert_eq!(
            output.exit_code,
            i32::from(iteron_eval::types::EVAL_EXIT_HARNESS),
            "discovery failures use the harness exit"
        );
        let stderr = output.stderr_lossy();
        assert!(stderr.contains("cannot locate the Core CLI independent of cwd"));
        assert!(stderr.contains("--core-bin /absolute/path/to/core"));
        assert!(stderr.contains("cargo build -p iteron-cli"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn relative_work_root_is_resolved_once_and_core_receives_canonical_paths() {
    let root = TempRoot::new();
    let outside_cwd = root.join("relative-root-cwd");
    std::fs::create_dir(&outside_cwd).expect("create child cwd");
    let corpus = write_success_corpus(&root);
    let iteron = write_boundary_checking_core(&root);
    let artifact = root.join("relative-result.json");
    let output = run_process(&ProcessSpec {
        program: PathBuf::from(env!("CARGO_BIN_EXE_iteron-eval")),
        args: vec![
            "--corpus".into(),
            corpus.into_os_string(),
            "--output".into(),
            artifact.as_os_str().to_owned(),
            "--work-root".into(),
            "relative-work".into(),
            "--core-bin".into(),
            iteron.into_os_string(),
            "--model".into(),
            "relative-root-model".into(),
            "--purpose".into(),
            "score".into(),
            "--seeds".into(),
            "1".into(),
            "--minimum-seeds".into(),
            "1".into(),
            "--run-timeout-secs".into(),
            "1".into(),
            "--checkout-timeout-secs".into(),
            "5".into(),
            "--oracle-timeout-secs".into(),
            "5".into(),
            "--max-turns".into(),
            "1".into(),
            "--allow-local-repositories".into(),
        ],
        cwd: Some(outside_cwd.clone()),
        clear_env: false,
        inherit_env: Vec::new(),
        env: Vec::new(),
        timeout: Duration::from_secs(30),
        max_output_bytes: 128 * 1024,
    })
    .await
    .expect("launch iteron-eval with a relative work root");

    assert!(!output.timed_out);
    assert_eq!(output.exit_code, 0, "stderr: {}", output.stderr_lossy());
    let manifest: EvaluationManifest =
        serde_json::from_slice(&std::fs::read(&artifact).expect("read result artifact"))
            .expect("decode result artifact");
    assert_eq!(manifest.core_agent_wall_secs, 1);
    assert_eq!(manifest.core_process_grace_secs, 1);
    assert_eq!(manifest.core_process_timeout_secs, 2);
    assert_eq!(manifest.cells.len(), 2);
    assert!(
        manifest
            .cells
            .iter()
            .all(|cell| cell.run_status == RunStatus::Completed)
    );
    let canonical_work = outside_cwd
        .join("relative-work")
        .canonicalize()
        .expect("relative work root was created below child cwd");
    assert!(canonical_work.starts_with(outside_cwd.canonicalize().unwrap()));
}
