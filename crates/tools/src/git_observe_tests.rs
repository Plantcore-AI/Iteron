use super::*;
use crate::git_harness::{NULL_DEVICE, resolve_git_executable, shell_script_command};
use iteron_protocol::ToolUse;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "core-git-observe-{label}-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git_output(root: &Path, args: &[&OsStr]) -> Output {
    let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), root).unwrap();
    let mut command = Command::new(&git.executable);
    command.env_clear();
    if let Some(path) = git.safe_path {
        command.env("PATH", path);
    }
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn git_ok(root: &Path, args: &[&OsStr]) -> Output {
    let output = git_output(root, args);
    assert!(
        output.status.success(),
        "fixture Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn initialize_repo(root: &Path) {
    git_ok(root, &[OsStr::new("init"), OsStr::new("--quiet")]);
    for (key, value) in [
        ("user.name", "Core Test"),
        ("user.email", "core@test.invalid"),
    ] {
        git_ok(
            root,
            &[OsStr::new("config"), OsStr::new(key), OsStr::new(value)],
        );
    }
}

fn commit_all(root: &Path, subject: &str) {
    git_ok(root, &[OsStr::new("add"), OsStr::new("--all")]);
    git_ok(
        root,
        &[
            OsStr::new("-c"),
            OsStr::new("commit.gpgsign=false"),
            OsStr::new("commit"),
            OsStr::new("--quiet"),
            OsStr::new("-m"),
            OsStr::new(subject),
        ],
    );
}

#[cfg(unix)]
fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn d3_09_g1_status_and_log_are_correct_through_the_hardened_registry() {
    let temp = TestDir::new("normal");
    std::fs::write(temp.0.join("tracked.txt"), "before\n").unwrap();
    initialize_repo(&temp.0);
    commit_all(&temp.0, "known base subject");
    std::fs::write(temp.0.join("tracked.txt"), "after\n").unwrap();
    std::fs::write(temp.0.join("new.txt"), "new\n").unwrap();

    let registry = Registry::read_only(&temp.0).unwrap();
    let status = registry
        .run(ToolUse {
            id: "status".into(),
            name: "git_status".into(),
            input: serde_json::json!({}),
        })
        .await;
    assert!(!status.is_error, "{}", status.content);
    assert!(status.content.contains(" M tracked.txt"));
    assert!(status.content.contains("?? new.txt"));

    let log = registry
        .run(ToolUse {
            id: "log".into(),
            name: "git_log".into(),
            input: serde_json::json!({"max_count":1}),
        })
        .await;
    assert!(!log.is_error, "{}", log.content);
    assert!(log.content.contains("Core Test\tknown base subject"));
    let oid = log.content.split('\t').next().unwrap();
    assert!(matches!(oid.len(), 40 | 64));
    assert!(oid.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn d3_09_g2_every_observation_neutralizes_all_filter_entry_points() {
    let drivers = ["filter.Evil".to_owned()];
    for args in [
        status_args(&drivers),
        environment_status_args(&drivers),
        log_args(&drivers, 1),
    ] {
        let args: Vec<String> = args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        for expected in [
            "filter.Evil.clean=",
            "filter.Evil.smudge=",
            "filter.Evil.process=",
            "filter.Evil.required=false",
        ] {
            assert!(
                args.windows(2).any(|pair| pair == ["-c", expected]),
                "missing hardened setting {expected:?} in {args:?}"
            );
        }
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "core.fsmonitor=false"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "credential.helper="])
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn d3_09_g2_clean_filter_cannot_execute_from_status_or_log() {
    let temp = TestDir::new("filter");
    initialize_repo(&temp.0);
    let marker = temp.0.join("filter-ran");
    let filter = temp.0.join("evil-filter");
    script(
        &filter,
        &format!("printf hit > \"{}\"\n/bin/cat", marker.display()),
    );
    git_ok(
        &temp.0,
        &[
            OsStr::new("config"),
            OsStr::new("filter.evil.clean"),
            shell_script_command(&filter).as_os_str(),
        ],
    );
    std::fs::write(temp.0.join(".gitattributes"), "* filter=evil\n").unwrap();
    std::fs::write(temp.0.join("tracked"), "before\n").unwrap();
    commit_all(&temp.0, "filtered base");
    assert!(marker.exists(), "fixture did not activate its clean filter");
    std::fs::remove_file(&marker).unwrap();
    std::fs::write(temp.0.join("tracked"), "after\n").unwrap();

    let registry = Registry::read_only(&temp.0).unwrap();
    for (name, input) in [
        ("git_status", serde_json::json!({})),
        ("git_log", serde_json::json!({"max_count":1})),
    ] {
        let result = registry
            .run(ToolUse {
                id: name.into(),
                name: name.into(),
                input,
            })
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(
            !marker.exists(),
            "{name} executed a repository clean filter"
        );
    }
}

#[tokio::test]
async fn d3_09_g2_malicious_core_worktree_cannot_disclose_an_outside_name() {
    let temp = TestDir::new("worktree");
    let workspace = temp.0.join("workspace");
    let outside = temp.0.join("outside");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    initialize_repo(&workspace);
    std::fs::write(workspace.join("tracked"), "safe\n").unwrap();
    commit_all(&workspace, "safe history");

    std::fs::write(outside.join("tracked"), "different\n").unwrap();
    let outside_name = "ITERON_OUTSIDE_SECRET_FILENAME";
    std::fs::write(outside.join(outside_name), "secret\n").unwrap();
    git_ok(
        &workspace,
        &[
            OsStr::new("config"),
            OsStr::new("core.worktree"),
            outside.as_os_str(),
        ],
    );
    let vulnerable = git_ok(
        &workspace,
        &[
            OsStr::new("status"),
            OsStr::new("--porcelain=v1"),
            OsStr::new("--untracked-files=normal"),
        ],
    );
    assert!(String::from_utf8_lossy(&vulnerable.stdout).contains(outside_name));

    let registry = Registry::read_only(&workspace).unwrap();
    for (name, input) in [
        ("git_status", serde_json::json!({})),
        ("git_log", serde_json::json!({"max_count":1})),
    ] {
        let result = registry
            .run(ToolUse {
                id: name.into(),
                name: name.into(),
                input,
            })
            .await;
        assert!(!result.is_error, "{}", result.content);
        assert!(!result.content.contains(outside_name));
    }
}

#[tokio::test]
async fn d3_09_g3_linked_or_submodule_worktree_fails_closed_for_both_tools() {
    let temp = TestDir::new("git-file");
    std::fs::write(
        temp.0.join(".git"),
        "gitdir: /outside/shared/.git/worktrees/w1\n",
    )
    .unwrap();
    let registry = Registry::read_only(&temp.0).unwrap();
    for (name, input) in [
        ("git_status", serde_json::json!({})),
        ("git_log", serde_json::json!({"max_count":1})),
    ] {
        let result = registry
            .run(ToolUse {
                id: name.into(),
                name: name.into(),
                input,
            })
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("linked worktrees"));
    }
}

#[test]
fn d3_09_g4_status_and_log_are_effecting_readonly_not_code_executing() {
    let registry = Registry::read_only(std::env::temp_dir()).unwrap();
    for name in ["git_status", "git_log"] {
        assert_eq!(registry.purity_of(name), Some(Purity::Effecting));
        assert_eq!(registry.capability_of(name), Some(Capability::ReadOnly));
        assert_ne!(
            registry.capability_of(name),
            Some(Capability::CodeExecuting)
        );
    }
}

#[test]
fn status_escapes_deceptive_unicode_and_discloses_the_rewrite() {
    let output = render_status(b"?? visible\xe2\x80\xaehidden.rs\0").unwrap();
    assert!(output.contains("visible\\u{202e}hidden.rs"));
    assert!(output.contains("Git output safety"));
}

#[test]
fn status_record_count_and_log_count_are_fixed_bounded() {
    let mut status = Vec::new();
    for _ in 0..=MAX_STATUS_RECORDS {
        status.extend_from_slice(b"?? x\0");
    }
    let error = render_status(&status).unwrap_err();
    assert!(error.contains("record limit"));
    for input in [
        serde_json::json!({"max_count":0}),
        serde_json::json!({"max_count":MAX_LOG_COUNT + 1}),
        serde_json::json!({"max_count":"many"}),
        serde_json::json!({"unexpected":1}),
    ] {
        assert!(parse_log_count(&input).is_err());
    }
}

#[test]
fn environment_status_reports_only_branch_and_bounded_counts() {
    let rendered = render_environment_status(
        b"## feature/safe...origin/feature/safe\0M  staged-secret-name\0 M changed-secret-name\0?? untracked-secret-name\0UU conflict-secret-name\0",
    )
    .unwrap();
    assert_eq!(
        rendered,
        "branch=feature/safe; status=staged:1,modified:1,untracked:1,conflicts:1"
    );
    for hidden_path in [
        "staged-secret-name",
        "changed-secret-name",
        "untracked-secret-name",
        "conflict-secret-name",
    ] {
        assert!(!rendered.contains(hidden_path));
    }
    assert_eq!(
        render_environment_status(b"## No commits yet on main\0").unwrap(),
        "branch=unborn:main; status=clean"
    );
    assert_eq!(
        render_environment_status(b"## HEAD (no branch)\0").unwrap(),
        "branch=detached; status=clean"
    );

    let escaped =
        render_environment_status(b"## visible\xe2\x80\xaehidden\0?? never-render-this-name\0")
            .unwrap();
    assert!(escaped.contains("branch=visible\\u{202e}hidden"));
    assert!(escaped.contains("branch_encoding=escaped"));
    assert!(!escaped.contains("never-render-this-name"));
}

#[test]
fn environment_status_fails_closed_when_branch_escaping_expands_past_render_bound() {
    // Git accepts this ref shape: each path component stays below 255 bytes while the complete
    // raw branch remains below our 512-byte input cap. Escaping each bidi scalar expands it enough
    // to cross the rendered cap; this must be an error, never a debug-only panic.
    let component = "\u{202e}".repeat(80);
    let snapshot = format!("## {component}/{component}\0");
    assert!(snapshot.len() < MAX_ENVIRONMENT_BRANCH_BYTES + 4);
    let error = render_environment_status(snapshot.as_bytes()).unwrap_err();
    assert!(error.contains("rendered bound"));
}

#[cfg(unix)]
#[tokio::test]
async fn environment_observation_uses_the_hardened_repo_and_returns_no_paths() {
    let temp = TestDir::new("environment-summary");
    initialize_repo(&temp.0);
    std::fs::write(temp.0.join("tracked-private-name"), "base\n").unwrap();
    commit_all(&temp.0, "base");
    git_ok(
        &temp.0,
        &[
            OsStr::new("branch"),
            OsStr::new("-M"),
            OsStr::new("facts-original"),
        ],
    );

    std::fs::write(temp.0.join("tracked-private-name"), "changed\n").unwrap();
    std::fs::write(temp.0.join("staged-private-name"), "staged\n").unwrap();
    git_ok(
        &temp.0,
        &[OsStr::new("add"), OsStr::new("staged-private-name")],
    );
    std::fs::write(temp.0.join("untracked-private-name"), "untracked\n").unwrap();

    let rendered = run_git_environment(&temp.0).await.unwrap();
    assert_eq!(
        rendered,
        "branch=facts-original; status=staged:1,modified:1,untracked:1,conflicts:0"
    );
    for hidden_path in [
        "tracked-private-name",
        "staged-private-name",
        "untracked-private-name",
    ] {
        assert!(!rendered.contains(hidden_path));
    }
    assert!(rendered.len() < 1_024);
}
