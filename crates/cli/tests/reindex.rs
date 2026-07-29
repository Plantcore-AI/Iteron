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
