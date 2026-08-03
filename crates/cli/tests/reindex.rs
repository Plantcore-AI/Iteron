use core_protocol::{Effort, Event, EventKind, Message, RunId, Seq, TenantId, TurnId};
use core_record::Rollout;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-cli-reindex-{}-{serial}", std::process::id()));
        std::fs::create_dir_all(root.join("repo")).unwrap();
        std::fs::create_dir_all(root.join("runs")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        Self(root)
    }

    fn repo(&self) -> PathBuf {
        self.0.join("repo")
    }

    fn runs(&self) -> PathBuf {
        self.0.join("runs")
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_core(home: &Path, repo: &Path, arguments: &[&str]) -> (ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    command
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env(
            "PATH",
            if cfg!(windows) {
                std::env::var_os("PATH").unwrap_or_default()
            } else {
                "/usr/bin:/bin".into()
            },
        )
        .env("LANG", "C.UTF-8")
        .current_dir(repo)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("core maintenance command exceeded {PROCESS_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status, stdout, stderr)
}

#[test]
fn d9_10_g1_reindex_subcommand_repairs_corrupt_cache_and_sessions_listing() {
    let scratch = Scratch::new();
    let run = RunId("repair-me".into());
    {
        let mut rollout = Rollout::open(&scratch.runs(), &run, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: scratch.repo().display().to_string(),
                    model: "fixture-model".into(),
                    effort: Effort::Low,
                    created_at: 123,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Message {
                    message: Message::user_text("repairable session title"),
                },
            })
            .unwrap();
    }

    std::fs::write(scratch.runs().join("sessions.index"), b"not-json\n").unwrap();
    std::fs::write(scratch.runs().join("repair-me.meta.json"), b"{torn-cache").unwrap();

    let repo_arg = scratch.repo().display().to_string();
    let runs_arg = scratch.runs().display().to_string();
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &["--repo", &repo_arg, "--runs-dir", &runs_arg, "reindex"],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("reindexed 1 session"), "{stdout}");

    let index = std::fs::read_to_string(scratch.runs().join("sessions.index")).unwrap();
    let index_entry: serde_json::Value = serde_json::from_str(index.trim()).unwrap();
    assert_eq!(index_entry["run_id"], "repair-me");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(scratch.runs().join("repair-me.meta.json")).unwrap())
            .unwrap();
    assert_eq!(meta["run_id"], "repair-me");
    assert_eq!(meta["title"], "repairable session title");

    let (status, sessions, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &["--repo", &repo_arg, "--runs-dir", &runs_arg, "--sessions"],
    );
    assert!(status.success(), "stdout={sessions}\nstderr={stderr}");
    assert!(sessions.contains("repair-me"), "{sessions}");
    assert!(sessions.contains("repairable session title"), "{sessions}");
}

#[test]
fn schema_v4_session_argv_is_typed_provider_free_and_tag_preserving() {
    let scratch = Scratch::new();
    let parent = RunId("tagged-parent".into());
    {
        let mut rollout = Rollout::open(&scratch.runs(), &parent, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: scratch.repo().display().to_string(),
                    model: "fixture-model".into(),
                    effort: Effort::Low,
                    created_at: 123,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: Some("reviewer-a".into()),
                    max_usd: None,
                },
            })
            .unwrap();
    }

    let (status, contract, stderr) = run_core(&scratch.home(), &scratch.repo(), &["--machine-contract"]);
    assert!(status.success(), "stdout={contract}\nstderr={stderr}");
    let contract: serde_json::Value = serde_json::from_str(contract.trim()).unwrap();
    assert_eq!(contract["cli_stream_versions"], serde_json::json!([4, 5]));
    assert_eq!(contract["resident_protocol_version"], 1);

    let repo_arg = scratch.repo().display().to_string();
    let runs_arg = scratch.runs().display().to_string();
    let (status, page, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &repo_arg,
            "--runs-dir",
            &runs_arg,
            "--sessions",
            "--output-format",
            "json",
            "--output-schema-version",
            "4",
            "--agent-definition-tag",
            "reviewer-a",
            "--session-limit",
            "1",
        ],
    );
    assert!(status.success(), "stdout={page}\nstderr={stderr}");
    let page: serde_json::Value = serde_json::from_str(page.trim()).unwrap();
    assert_eq!(page["schema_version"], 4);
    assert_eq!(page["type"], "session_list_page");
    assert_eq!(page["sessions"][0]["run_id"], "tagged-parent");
    assert_eq!(page["sessions"][0]["agent_definition_tag"], "reviewer-a");

    let (status, forked, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &repo_arg,
            "--runs-dir",
            &runs_arg,
            "--fork",
            "tagged-parent",
            "--output-format",
            "json",
            "--output-schema-version",
            "4",
        ],
    );
    assert!(status.success(), "stdout={forked}\nstderr={stderr}");
    let forked: serde_json::Value = serde_json::from_str(forked.trim()).unwrap();
    assert_eq!(forked["type"], "session_fork_result");
    assert_eq!(forked["parent_run_id"], "tagged-parent");
    assert_eq!(forked["status"], "created");
    let child = RunId(forked["child_run_id"].as_str().unwrap().to_owned());
    assert_eq!(
        core_record::meta(&scratch.runs(), &child)
            .unwrap()
            .agent_definition_tag
            .as_deref(),
        Some("reviewer-a")
    );
}
/// Write a complete, listable session whose genesis records `cwd`.
fn write_session(runs: &Path, run: &RunId, cwd: &Path, title: &str) {
    let mut rollout = Rollout::open(runs, run, TenantId::default()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: cwd.display().to_string(),
                model: "fixture-model".into(),
                effort: Effort::Low,
                created_at: 123,
                environment: None,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                agent_definition_tag: None,
                config_digest: String::new(),
                max_usd: None,
            },
        })
        .unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::Message {
                message: Message::user_text(title),
            },
        })
        .unwrap();
}

/// I-06. Nine call sites used the raw `.core/runs` default, so the audit record landed beside
/// whatever directory the process started in rather than under `-C`. An absolute `--runs-dir` is
/// still taken verbatim.
#[test]
fn d11_06_a_relative_runs_dir_resolves_against_dash_c_not_the_process_directory() {
    let scratch = Scratch::new();
    let repo_arg = scratch.repo().display().to_string();
    let canonical = scratch.repo().canonicalize().unwrap();

    // Invoked from the scratch ROOT, not from the repository.
    let (status, stdout, stderr) = run_core(&scratch.home(), &scratch.0, &["--repo", &repo_arg, "reindex"]);
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&canonical.join(".core/runs").display().to_string()),
        "{stdout}"
    );
    assert!(
        canonical.join(".core/runs").is_dir(),
        "the runs dir belongs to -C"
    );
    assert!(
        !scratch.0.join(".core").exists(),
        "nothing is written beside the process working directory"
    );

    let runs_arg = scratch.runs().display().to_string();
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.0,
        &["--repo", &repo_arg, "--runs-dir", &runs_arg, "reindex"],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&runs_arg),
        "an absolute --runs-dir is honoured verbatim: {stdout}"
    );
}

/// I-50. The failure used to propagate the bare `RecordError`, which anyhow's alternate Display
/// printed as `io: <errno>: <errno>` — the `#[from]` source repeated, with no run id and no path.
#[test]
fn d11_50_a_transcript_read_failure_names_the_run_and_the_file() {
    let scratch = Scratch::new();
    let repo_arg = scratch.repo().display().to_string();
    let runs_arg = scratch.runs().display().to_string();

    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &repo_arg,
            "--runs-dir",
            &runs_arg,
            "--transcript",
            "absent-run",
        ],
    );
    assert!(!status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stderr.contains("absent-run"), "the run id: {stderr}");
    assert!(
        stderr.contains(
            &scratch
                .runs()
                .join("absent-run.jsonl")
                .display()
                .to_string()
        ),
        "the file: {stderr}"
    );
    assert_eq!(
        stderr.matches("os error").count(),
        1,
        "the underlying error is reported once, not twice: {stderr}"
    );
}

/// I-51. `--sessions` documented "sessions in this repo" while listing every repository the runs
/// dir held; `--continue` filtered by the recorded cwd. Both now mean the same thing.
#[test]
fn d11_51_sessions_lists_only_the_repository_continue_would_select_from() {
    let scratch = Scratch::new();
    let elsewhere = scratch.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    write_session(
        &scratch.runs(),
        &RunId("in-this-repo".into()),
        &scratch.repo(),
        "belongs here",
    );
    write_session(
        &scratch.runs(),
        &RunId("in-another-repo".into()),
        &elsewhere,
        "belongs elsewhere",
    );

    let repo_arg = scratch.repo().display().to_string();
    let runs_arg = scratch.runs().display().to_string();
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &["--repo", &repo_arg, "--runs-dir", &runs_arg, "--sessions"],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("in-this-repo"), "{stdout}");
    assert!(
        !stdout.contains("in-another-repo"),
        "another repository's sessions are not in this repo: {stdout}"
    );

    let elsewhere_arg = elsewhere.display().to_string();
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &elsewhere_arg,
            "--runs-dir",
            &runs_arg,
            "--sessions",
        ],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("in-another-repo"), "{stdout}");
    assert!(!stdout.contains("in-this-repo"), "{stdout}");
}

/// I-46. The listing was linear and unpaged, and nothing ever removed a journal. The list is now
/// bounded, and `prune` deletes exactly what an explicit policy names.
#[test]
fn d11_46_the_session_list_is_paged_and_prune_enforces_an_explicit_policy() {
    let scratch = Scratch::new();
    for index in 0..3 {
        write_session(
            &scratch.runs(),
            &RunId(format!("session-{index}")),
            &scratch.repo(),
            "paged session",
        );
    }
    let repo_arg = scratch.repo().display().to_string();
    let runs_arg = scratch.runs().display().to_string();
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &repo_arg,
            "--runs-dir",
            &runs_arg,
            "--sessions",
            "--limit",
            "2",
        ],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        stdout.lines().count(),
        2,
        "the listing is a page, not a dump: {stdout}"
    );
    assert!(
        stderr.contains("showing the 2 most recent of 3 sessions"),
        "a page must say it is a page: {stderr}"
    );

    // A prune with no rule is a question, not a command.
    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &["--repo", &repo_arg, "--runs-dir", &runs_arg, "prune"],
    );
    assert!(!status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stderr.contains("explicit retention policy"), "{stderr}");
    assert_eq!(count_rollouts(&scratch.runs()), 3);

    let (status, stdout, stderr) = run_core(
        &scratch.home(),
        &scratch.repo(),
        &[
            "--repo",
            &repo_arg,
            "--runs-dir",
            &runs_arg,
            "prune",
            "--keep-last",
            "1",
        ],
    );
    assert!(status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("removed 2 sessions"), "{stdout}");
    assert_eq!(
        count_rollouts(&scratch.runs()),
        1,
        "prune removes exactly what the policy names"
    );
}

fn count_rollouts(runs: &Path) -> usize {
    std::fs::read_dir(runs)
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
        .count()
}
