//! D13-15 — process-level golden test for the one-shot machine-output contract.
//!
//! The `output.rs` unit tests freeze the pure producer functions, and `one_shot_output.rs`
//! freezes the provider-backed *success* path. What was missing is a PROCESS-level golden that
//! spawns the real `core` binary and pins the machine-output contract end to end for a fully
//! deterministic, provider-free run. This closes that gap using the `--max-usd 0` budget path,
//! which terminates at turn admission before any provider call, so the emitted terminal is
//! hermetic and byte-stable.
//!
//! Three checks, one per contract facet the gap spans:
//!   1. `cli-output`  — the `json` terminal equals a frozen schema-v4 golden object.
//!   2. `cli-tui`     — `stream-json` shares one authoritative terminal with `json` and every
//!                      streamed record is a versioned machine record.
//!   3. `evaluation`  — the terminal `exit_code` equals the real OS exit status and
//!                      `success == (outcome in {done, drained})`: the exact coherence the
//!                      `core-eval` consumer (`parse_final_result`) enforces at the process seam.

use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const PROVIDER_ID: &str = "golden";
const MODEL_ID: &str = "golden-model";
const TEST_KEY_ENV: &str = "CORE_GOLDEN_TEST_KEY";
const TEST_KEY: &str = "integration-test-placeholder";

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Isolated HOME + repo + rollout tree for one hermetic `core` invocation.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-cli-d13-15-{label}-{}-{id}",
            std::process::id()
        ));
        let scratch = Self { root };
        fs::create_dir_all(scratch.repo()).expect("create isolated repository");
        fs::create_dir_all(scratch.home().join(".core")).expect("create isolated Core home");
        fs::create_dir_all(scratch.runs()).expect("create isolated rollout directory");

        // The loopback discard port is never contacted: `--max-usd 0` exhausts the budget before
        // any provider request is admitted. The config still resolves a provider + model so the
        // run reaches turn admission (where the budget check fires) deterministically.
        let config = json!({
            "provider": PROVIDER_ID,
            "model": MODEL_ID,
            "effort": "low",
            "max_wall_secs": 10,
            "providers": [{
                "id": PROVIDER_ID,
                "display_name": "Golden fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": "http://127.0.0.1:9/v1",
                "key_env": TEST_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [MODEL_ID]
            }]
        });
        fs::write(
            scratch.home().join(".core/config.json"),
            serde_json::to_vec(&config).expect("encode test config"),
        )
        .expect("write isolated test config");
        scratch
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Spawn the real `core` binary on the deterministic budget path and collect its bounded output.
fn run_budget(scratch: &Scratch, format: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    // Never inherit a developer credential, proxy, or user config. The only credential visible to
    // the child is the inert placeholder, and no origin is ever contacted on the budget path.
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env(TEST_KEY_ENV, TEST_KEY)
        .current_dir(scratch.repo())
        .arg("-p")
        .arg("return the deterministic fixture response")
        .arg("--output-format")
        .arg(format)
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .arg("--provider")
        .arg(PROVIDER_ID)
        .arg("--model")
        .arg(MODEL_ID)
        .arg("--effort")
        .arg("low")
        .arg("--max-turns")
        .arg("1")
        .arg("--max-usd")
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn the real core binary");
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        match child.try_wait().expect("poll core child") {
            Some(_) => return child.wait_with_output().expect("collect core output"),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collect timed-out core output");
                panic!(
                    "core exceeded the {PROCESS_TIMEOUT:?} process bound; stderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

/// The strict machine-stdout framing the contract promises: UTF-8, LF, one JSON object per line,
/// a trailing newline, and no blank records.
fn json_lines(stdout: &[u8]) -> Vec<Value> {
    assert!(!stdout.is_empty(), "machine stdout must not be empty");
    assert_eq!(stdout.last(), Some(&b'\n'), "stdout needs a final newline");
    let text = std::str::from_utf8(stdout).expect("machine stdout is UTF-8");
    assert!(!text.contains('\r'), "machine stdout uses LF line endings");
    text.strip_suffix('\n')
        .expect("final newline already checked")
        .split('\n')
        .map(|line| {
            assert!(!line.is_empty(), "machine stdout has no blank JSONL records");
            serde_json::from_str(line).expect("every stdout line is one JSON object")
        })
        .collect()
}

fn normalized(mut value: Value) -> Value {
    if let Some(run_id) = value.get_mut("run_id") {
        assert!(
            run_id
                .as_str()
                .is_some_and(|id| id.starts_with("run-") && id.len() > 4),
            "the terminal carries the actual non-empty run id"
        );
        *run_id = json!("<RUN_ID>");
    }
    value
}

/// The frozen schema-v4 machine terminal for the deterministic `--max-usd 0` budget path.
///
/// Inlined (rather than a `golden/` file) so this test adds no entry to the CLI machine-golden
/// inventory the compatibility manifest governs; the object below IS the golden.
fn golden_terminal() -> Value {
    json!({
        "schema_version": 4,
        "type": "result",
        "outcome": "budget_exhausted",
        "reason": "max_usd",
        "success": false,
        "assistant_text": "",
        "run_id": "<RUN_ID>",
        "cost_usd": 0.0,
        "cost_status": "zero",
        "cost_reason": null,
        "turns": 0,
        "exit_code": 3,
        "error": null,
    })
}

#[test]
fn d13_15_json_budget_terminal_is_a_process_level_golden() {
    let scratch = Scratch::new("json-budget");
    let output = run_budget(&scratch, "json");

    assert_eq!(
        output.status.code(),
        Some(3),
        "the provider-free budget path is a stable exit 3"
    );
    let lines = json_lines(&output.stdout);
    assert_eq!(lines.len(), 1, "json mode emits exactly one terminal object");
    assert_eq!(
        normalized(lines[0].clone()),
        golden_terminal(),
        "the real one-shot budget terminal is a frozen schema-v4 machine contract"
    );

    // Machine records belong exclusively on stdout; stderr is human diagnostics only.
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        !stderr.contains("\"schema_version\":4"),
        "the machine result must never leak onto stderr"
    );
}

#[test]
fn d13_15_stream_json_shares_one_authoritative_terminal_with_json() {
    let scratch = Scratch::new("stream-budget");
    let output = run_budget(&scratch, "stream-json");

    assert_eq!(output.status.code(), Some(3));
    let lines = json_lines(&output.stdout);
    assert!(!lines.is_empty(), "stream-json emits at least the terminal");

    let results: Vec<&Value> = lines.iter().filter(|value| value["type"] == "result").collect();
    assert_eq!(results.len(), 1, "stream-json has exactly one terminal result");
    assert_eq!(
        lines.last().expect("terminal record")["type"],
        "result",
        "the authoritative result is the final streamed record"
    );

    // Every streamed record is a versioned machine record with a stable string discriminant.
    for record in &lines {
        assert_eq!(
            record["schema_version"], 4,
            "every streamed record is frozen at schema v4: {record}"
        );
        assert!(
            record["type"].as_str().is_some(),
            "every streamed record carries a string type: {record}"
        );
    }

    // The two machine surfaces converge on ONE authoritative terminal object.
    assert_eq!(
        normalized(lines.last().expect("terminal record").clone()),
        golden_terminal(),
        "json and stream-json must emit the identical authoritative terminal"
    );
}

#[test]
fn d13_15_process_exit_matches_the_machine_result_exit_code() {
    for format in ["json", "stream-json"] {
        let scratch = Scratch::new(&format!("exit-{format}"));
        let output = run_budget(&scratch, format);
        let process_exit = output
            .status
            .code()
            .expect("core exits with a numeric status");

        let terminal = json_lines(&output.stdout)
            .into_iter()
            .rev()
            .find(|value| value["type"] == "result")
            .expect("a terminal result record is present");

        // This is exactly the invariant the core-eval consumer enforces at the process seam:
        // the OS exit status and the embedded machine exit_code cannot disagree.
        assert_eq!(
            terminal["exit_code"].as_i64(),
            Some(i64::from(process_exit)),
            "the machine result exit_code must equal the real OS exit status ({format})"
        );

        let success = terminal["success"].as_bool().expect("bool success field");
        let outcome = terminal["outcome"].as_str().expect("string outcome field");
        assert_eq!(
            success,
            matches!(outcome, "done" | "drained"),
            "success must be exactly (outcome in done|drained) ({format})"
        );
    }
}
