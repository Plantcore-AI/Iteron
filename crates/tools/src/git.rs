//! `git_diff` — a bounded, read-only view of the working tree's uncommitted changes.
//!
//! Starting a process is an observable effect even when the Git operation itself is read-only, so
//! this tool is deliberately `Effecting`/`ReadOnly`: it remains available to read-only subagents,
//! but the kernel must defer it until after the provider turn and route it through the effect WAL.
//! Git is resolved to an absolute executable outside the workspace before `current_dir` changes,
//! the repository is required to have a contained `.git` directory, every invocation pins both
//! `--git-dir` and `--work-tree`, ambient Git configuration is removed, repository executable
//! extension points are disabled, dirty submodules are not descended into, and the child is
//! supervised with bounded output, a deadline, and process-group teardown. Linked worktrees and
//! submodule worktrees use an external git-dir through a `.git` file and currently fail closed.

use crate::git_filters::discover_filter_drivers;
#[cfg(test)]
use crate::git_filters::{MAX_FILTER_DRIVERS, parse_filter_drivers};
use crate::git_harness::{
    GIT_TIMEOUT, STDERR_LIMIT, hardened_args, hardened_git_command, resolve_git_executable,
    resolve_repository_layout, run_command_bounded,
};
#[cfg(test)]
use crate::git_harness::{NULL_DEVICE, ResolvedGit, shell_script_command};
use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use core_protocol::{Capability, Purity, ToolSpec};
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::{io, process::Stdio, time::Duration};

const STDOUT_LIMIT: usize = 40_000;

fn git_diff_args(stat: bool, path: Option<&Path>, filter_drivers: &[String]) -> Vec<OsString> {
    let mut operation: Vec<OsString> = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        // Inspecting a dirty submodule runs another Git against submodule-controlled config;
        // that nested status can execute the submodule's own clean/process filter. Keep the
        // safe superproject boundary explicit and render gitlinks only in short form.
        "--ignore-submodules=dirty",
        "--submodule=short",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if stat {
        operation.push("--stat".into());
    }
    if let Some(path) = path {
        operation.push("--".into());
        operation.push(path.as_os_str().to_owned());
    }
    hardened_args(filter_drivers, operation)
}

async fn run_git_diff_inner(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    let relative_path = requested_path
        .map(|path| {
            resolve_in_root(&root, path).and_then(|resolved| {
                resolved
                    .strip_prefix(&root)
                    .map(|relative| {
                        if relative.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            relative.to_path_buf()
                        }
                    })
                    // NOT a policy boundary: `git diff -- <path>` takes a repository-relative
                    // pathspec, and a path outside this repository has no such form. The fs tools
                    // address the whole host now; this one refusal is what `git` itself can mean.
                    .map_err(|_| format!("path is outside the repository being diffed: {path}"))
            })
        })
        .transpose()?;
    let repository = resolve_repository_layout(&root)?;
    let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &root)
        .map_err(|error| format!("could not resolve trusted Git: {error}"))?;
    let filter_drivers = discover_filter_drivers(&git, &repository).await?;
    let args = git_diff_args(stat, relative_path.as_deref(), &filter_drivers);
    let mut command = hardened_git_command(&git, &repository, &args);
    let captured = run_command_bounded(&mut command, GIT_TIMEOUT, STDOUT_LIMIT, STDERR_LIMIT)
        .await
        .map_err(|error| format!("could not run bounded Git diff: {error}"))?;

    if !captured.status.success() {
        let stderr = captured.stderr.render("Git stderr");
        return Err(format!(
            "Git diff failed (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    let output = captured.stdout.render("Git diff output");
    Ok(if output.trim().is_empty() {
        "(no uncommitted changes)".into()
    } else {
        output
    })
}

pub(crate) async fn run_git_diff(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    // The filter-config inspection and diff share one end-to-end deadline. Dropping either active
    // command invokes `ProcessGroupGuard`, so outer timeout/caller cancellation tears down the
    // whole Unix process group rather than leaking a repository-triggered descendant.
    tokio::time::timeout(GIT_TIMEOUT, run_git_diff_inner(root, stat, requested_path))
        .await
        .map_err(|_| format!("Git diff exceeded {} seconds", GIT_TIMEOUT.as_secs()))?
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "git_diff".into(),
            description: "Show uncommitted changes in the working tree (git diff). Optional \
                          `stat` for a summary, or `path` to limit to one file/dir. Runs a fixed, \
                          bounded, hook/filter-disabled Git command after the model turn; dirty \
                          submodule worktrees are intentionally not descended into."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "stat":{"type":"boolean","description":"summary (--stat) instead of full diff"},
                    "path":{"type":"string","description":"limit to this path (relative to repo root)"}
                }
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let stat = call
                    .input
                    .get("stat")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                let path = call
                    .input
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
                match run_git_diff(&root, stat, path.as_deref()).await {
                    Ok(output) => ok_result(id, output),
                    Err(error) => err_result(id, error),
                }
            })
        },
    )?;
    crate::git_observe::register(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::ToolUse;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestDir(PathBuf);

    static NEXT_TEST_DIR: AtomicUsize = AtomicUsize::new(0);

    impl TestDir {
        /// The label alone does not make this unique: `no-lazy-fetch` is used by two tests, and the
        /// nanosecond nonce it used to rely on is microsecond-granular on macOS -- consecutive
        /// calls return the same value. Two tests sharing a directory do not merely litter; they
        /// read each other's repositories. A process-wide counter cannot collide with itself.
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "core-git-diff-{label}-{}-{sequence}",
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

    #[cfg(unix)]
    fn script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    fn fixture_path(workspace: &Path) -> Option<OsString> {
        let workspace = workspace.canonicalize().ok()?;
        let path = std::env::var_os("PATH")?;
        let directories = std::env::split_paths(&path)
            .filter(|directory| directory.is_absolute())
            .filter_map(|directory| directory.canonicalize().ok())
            .filter(|directory| !directory.starts_with(&workspace));
        std::env::join_paths(directories).ok()
    }

    /// Serialise the fixture tests that drive real `git` porcelain.
    ///
    /// These four build repositories with dozens of real `git` subprocesses, and `git submodule`
    /// is itself a shell script that spawns more. Run concurrently on a loaded box they compete
    /// for the same 5-second per-command deadline in `setup_git`, which is the shape of the
    /// second, macOS-side flake in #55 — a failure nobody can reproduce on demand and which
    /// teaches readers to re-run a red CI instead of reading it.
    ///
    /// The issue admits an explicit serialisation in place of a diagnosis, and that is what this
    /// is: not a claim about the mechanism, but a refusal to let these four overlap. It costs a
    /// few seconds of wall clock in one crate and buys a deterministic suite.
    ///
    /// The guard is held across `await`, so it has to be the futures-aware lock: a
    /// `std::sync::MutexGuard` parked across a suspension point is what `clippy::await_holding_lock`
    /// exists to stop.
    #[cfg(unix)]
    fn git_fixture_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        &LOCK
    }

    #[cfg(unix)]
    async fn setup_git(git: &ResolvedGit, workspace: &Path, args: &[&OsStr]) {
        let args: Vec<OsString> = args.iter().map(|arg| (*arg).to_owned()).collect();
        // Fixtures need to run `git init` before a RepositoryLayout exists and deliberately need
        // to activate dangerous repository settings to prove the production boundary. This raw
        // command builder is therefore test-only; production Git always uses
        // `hardened_git_command` with an already-validated layout.
        let mut command = tokio::process::Command::new(&git.executable);
        command.env_clear();
        // Git porcelain such as `submodule` is a shell script on macOS and needs platform tools
        // including `basename`, `sed`, and `uname`. The production command intentionally keeps
        // its narrower PATH; this test-only builder runs against fixtures created by this test and
        // admits every absolute ambient PATH directory except the fixture workspace itself.
        if let Some(path) = fixture_path(workspace) {
            command.env("PATH", path);
        }
        command
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
            .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 4096, 4096)
            .await
            .unwrap();
        assert!(
            captured.status.success(),
            "setup Git failed: {}",
            captured.stderr.render("setup stderr")
        );
    }

    #[test]
    fn git_diff_is_effecting_readonly_and_cannot_early_dispatch() {
        let dir = std::env::temp_dir();
        let registry = Registry::read_only(&dir).unwrap();
        assert_eq!(registry.purity_of("git_diff"), Some(Purity::Effecting));
        assert_eq!(
            registry.capability_of("git_diff"),
            Some(Capability::ReadOnly)
        );
    }

    #[test]
    fn fixed_arguments_disable_extension_points_and_guard_paths() {
        let args = git_diff_args(
            true,
            Some(Path::new("-looks-like-an-option")),
            &["filter.Evil".to_owned()],
        );
        let args: Vec<String> = args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "core.fsmonitor=false"])
        );
        assert!(args.windows(2).any(|pair| pair == ["-c", "diff.external="]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.clean="])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.process="])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.required=false"])
        );
        assert!(args.iter().any(|argument| argument == "--no-ext-diff"));
        assert!(args.iter().any(|argument| argument == "--no-textconv"));
        assert!(args.iter().any(|argument| argument == "--no-color"));
        assert!(
            args.iter()
                .any(|argument| argument == "--ignore-submodules=dirty")
        );
        assert!(args.iter().any(|argument| argument == "--submodule=short"));
        assert!(args.iter().any(|argument| argument == "--stat"));
        let separator = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(args[separator + 1], "-looks-like-an-option");
    }

    #[test]
    fn filter_driver_parser_is_nul_safe_deduplicated_and_bounded() {
        let parsed =
            parse_filter_drivers(b"filter.alpha.clean\0filter.alpha.process\0filter.Case.smudge\0")
                .unwrap();
        assert_eq!(parsed, ["filter.Case", "filter.alpha"]);
        assert!(parse_filter_drivers(b"filter.bad.clean\nkey\0").is_err());

        let too_many = (0..=MAX_FILTER_DRIVERS)
            .map(|index| format!("filter.f{index}.clean\0"))
            .collect::<String>();
        assert!(parse_filter_drivers(too_many.as_bytes()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_ignores_relative_and_workspace_git_entries() {
        let temp = TestDir::new("resolver");
        let workspace = temp.0.join("workspace");
        let trusted = temp.0.join("trusted-bin");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&trusted).unwrap();
        script(&workspace.join("git"), "exit 99");
        script(&trusted.join("git"), "exit 0");
        let path =
            std::env::join_paths([Path::new("."), workspace.as_path(), trusted.as_path()]).unwrap();

        let resolved = resolve_git_executable(Some(&path), &workspace).unwrap();
        assert_eq!(
            resolved.executable,
            trusted.join("git").canonicalize().unwrap()
        );
        assert!(resolved.executable.is_absolute());
        assert!(
            !resolved
                .executable
                .starts_with(workspace.canonicalize().unwrap())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_bounds_both_output_streams() {
        let temp = TestDir::new("bounded");
        let executable = temp.0.join("flood");
        script(
            &executable,
            "i=0; while [ \"$i\" -lt 5000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i + 1)); done",
        );
        // Invoke the freshly written fixture through the stable system shell. Linux may
        // transiently report ETXTBSY when a just-created script is executed directly on a busy
        // CI filesystem; this test exercises bounded pipe draining, not executable resolution.
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg(&executable);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 1024, 512)
            .await
            .unwrap();
        assert!(captured.status.success());
        assert!(captured.stdout.truncated());
        assert!(captured.stderr.truncated());
        assert_eq!(
            captured.stdout.head.len() + captured.stdout.tail.len(),
            1024
        );
        assert_eq!(captured.stderr.head.len() + captured.stderr.tail.len(), 512);
        assert!(
            captured
                .stdout
                .render("stdout")
                .contains("stdout truncated")
        );
        assert!(
            captured
                .stderr
                .render("stderr")
                .contains("stderr truncated")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_the_process_group_and_waits() {
        let temp = TestDir::new("timeout");
        let executable = temp.0.join("linger");
        let marker = temp.0.join("escaped-descendant");
        script(
            &executable,
            "(/bin/sleep 1; printf escaped > \"$1\") & wait",
        );
        // Keep the fixture launch independent of Linux's transient ETXTBSY handling for a
        // just-created script. The process-group timeout contract remains unchanged because the
        // shell becomes the new process-group leader before it starts the descendant.
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg(&executable);
        command
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let error = run_command_bounded(&mut command, Duration::from_millis(50), 1024, 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            !marker.exists(),
            "a timed-out descendant survived its process group"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn repository_clean_filter_is_neutralized_before_diff() {
        let _serial = git_fixture_lock().lock().await;
        let temp = TestDir::new("clean-filter");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();
        let filter = temp.0.join("filter");
        let marker = temp.0.join("filter-ran");
        script(
            &filter,
            &format!("printf hit > \"{}\"\n/bin/cat", marker.display()),
        );

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("config"),
                OsStr::new("filter.evil.clean"),
                shell_script_command(&filter).as_os_str(),
            ],
        )
        .await;
        std::fs::write(workspace.join(".gitattributes"), "* filter=evil\n").unwrap();
        std::fs::write(workspace.join("tracked"), "before\n").unwrap();
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("add"),
                OsStr::new("--"),
                OsStr::new(".gitattributes"),
                OsStr::new("tracked"),
            ],
        )
        .await;
        assert!(
            marker.exists(),
            "test setup did not activate the clean filter"
        );
        std::fs::remove_file(&marker).unwrap();
        std::fs::write(workspace.join("tracked"), "after\n").unwrap();

        let output = run_git_diff(&workspace, false, None).await.unwrap();
        assert!(output.contains("tracked"));
        assert!(
            !marker.exists(),
            "git_diff executed a repository-configured clean filter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malicious_core_worktree_cannot_leak_an_outside_file() {
        let _serial = git_fixture_lock().lock().await;
        let temp = TestDir::new("core-worktree-escape");
        let workspace = temp.0.join("workspace");
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        std::fs::write(workspace.join("tracked"), "safe workspace contents\n").unwrap();
        setup_git(
            &git,
            &workspace,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new("tracked")],
        )
        .await;

        let outside_marker = "CORE_OUTSIDE_WORKTREE_SECRET_MARKER";
        std::fs::write(outside.join("tracked"), format!("{outside_marker}\n")).unwrap();
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("config"),
                OsStr::new("core.worktree"),
                outside.as_os_str(),
            ],
        )
        .await;

        // Prove the fixture reaches the vulnerable behavior: an unpinned Git invocation honors
        // local core.worktree and emits contents read from outside the workspace.
        let raw_args = [
            OsStr::new("--no-pager"),
            OsStr::new("diff"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new("--no-color"),
        ];
        let raw_args: Vec<OsString> = raw_args.iter().map(|arg| (*arg).to_owned()).collect();
        let mut raw_command = tokio::process::Command::new(&git.executable);
        raw_command
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
            .args(raw_args)
            .current_dir(&workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let vulnerable = run_command_bounded(
            &mut raw_command,
            Duration::from_secs(5),
            STDOUT_LIMIT,
            STDERR_LIMIT,
        )
        .await
        .unwrap();
        assert!(vulnerable.status.success());
        assert!(
            vulnerable
                .stdout
                .render("raw Git output")
                .contains(outside_marker),
            "test setup did not reproduce the unpinned core.worktree disclosure"
        );

        let output = run_git_diff(&workspace, false, None).await.unwrap();
        assert_eq!(output, "(no uncommitted changes)");
        assert!(
            !output.contains(outside_marker),
            "confined git_diff disclosed contents from core.worktree outside the workspace"
        );
    }

    #[test]
    fn linked_worktree_git_file_fails_closed() {
        let temp = TestDir::new("linked-worktree");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join(".git"),
            "gitdir: /outside/shared/.git/worktrees/w1\n",
        )
        .unwrap();

        let error = resolve_repository_layout(&workspace).unwrap_err();
        assert!(error.contains("linked worktrees"));
    }

    #[test]
    fn alternate_git_common_directory_fails_closed() {
        let temp = TestDir::new("common-dir");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        std::fs::write(workspace.join(".git/commondir"), "/outside/shared/.git\n").unwrap();

        let error = resolve_repository_layout(&workspace).unwrap_err();
        assert!(error.contains("common-directory"));
    }

    #[test]
    fn hardened_command_environment_disables_partial_clone_lazy_fetch() {
        let temp = TestDir::new("no-lazy-fetch");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        let git = ResolvedGit {
            executable: std::env::current_exe().unwrap(),
            safe_path: None,
        };
        let repository = resolve_repository_layout(&workspace).unwrap();

        // Inspect the exact child environment instead of execing a just-written probe script:
        // busy Linux CI filesystems can transiently reject that fixture with ETXTBSY.
        let command = hardened_git_command(&git, &repository, &[]);
        let lazy_fetch = command
            .as_std()
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("GIT_NO_LAZY_FETCH"))
            .and_then(|(_, value)| value);

        assert_eq!(lazy_fetch, Some(OsStr::new("1")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hardened_git_invocation_disables_partial_clone_lazy_fetch() {
        // This test used to fabricate a synthetic Git binary, so it never paid the cost of real
        // Git. Driving the resolved system Git through `setup_git` makes it a fourth real-Git
        // fixture, and it holds a five-second deadline while doing so, which is exactly the
        // contention the lock below was introduced to remove. Take the lock too.
        let _serial = git_fixture_lock().lock().await;
        let temp = TestDir::new("no-lazy-fetch");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();
        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        let repository = resolve_repository_layout(&workspace).unwrap();

        // Use the stable system Git binary rather than directly executing a freshly written
        // script. On Linux another test thread can fork while that script still has a writer;
        // the child briefly inherits the descriptor and execve then returns ETXTBSY. A shell Git
        // alias observes the same command environment without creating that unrelated race.
        let args = hardened_args(
            &[],
            [
                OsString::from("-c"),
                OsString::from("alias.print-env=!printf '%s' \"$GIT_NO_LAZY_FETCH\""),
                OsString::from("print-env"),
            ],
        );
        let mut command = hardened_git_command(&git, &repository, &args);
        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 128, 128)
            .await
            .unwrap();
        assert!(captured.status.success());
        assert_eq!(captured.stdout.render("probe stdout"), "1");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dirty_submodule_filter_is_not_descended_into() {
        let _serial = git_fixture_lock().lock().await;
        let temp = TestDir::new("submodule-filter");
        let source = temp.0.join("source");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();

        setup_git(&git, &source, &[OsStr::new("init"), OsStr::new("--quiet")]).await;
        for (key, value) in [("user.name", "core-test"), ("user.email", "core@test")] {
            setup_git(
                &git,
                &source,
                &[OsStr::new("config"), OsStr::new(key), OsStr::new(value)],
            )
            .await;
        }
        std::fs::write(source.join(".gitattributes"), "* filter=evil\n").unwrap();
        std::fs::write(source.join("tracked"), "before\n").unwrap();
        setup_git(
            &git,
            &source,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new(".")],
        )
        .await;
        setup_git(
            &git,
            &source,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("base"),
            ],
        )
        .await;

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        for (key, value) in [("user.name", "core-test"), ("user.email", "core@test")] {
            setup_git(
                &git,
                &workspace,
                &[OsStr::new("config"), OsStr::new(key), OsStr::new(value)],
            )
            .await;
        }
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("-c"),
                OsStr::new("protocol.file.allow=always"),
                OsStr::new("submodule"),
                OsStr::new("add"),
                OsStr::new("--quiet"),
                source.as_os_str(),
                OsStr::new("sub"),
            ],
        )
        .await;
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("submodule"),
            ],
        )
        .await;

        let filter = temp.0.join("submodule-filter");
        let marker = temp.0.join("submodule-filter-ran");
        script(
            &filter,
            &format!("printf hit > \"{}\"\n/bin/cat", marker.display()),
        );
        let submodule = workspace.join("sub");
        setup_git(
            &git,
            &submodule,
            &[
                OsStr::new("config"),
                OsStr::new("filter.evil.clean"),
                shell_script_command(&filter).as_os_str(),
            ],
        )
        .await;
        std::fs::write(submodule.join("tracked"), "after\n").unwrap();

        // Prove this fixture reaches the dangerous nested-status path without the production
        // submodule guard; otherwise a passing marker assertion below would be vacuous.
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("--no-pager"),
                OsStr::new("diff"),
                OsStr::new("--no-ext-diff"),
                OsStr::new("--no-textconv"),
            ],
        )
        .await;
        assert!(
            marker.exists(),
            "test setup did not activate the submodule clean filter"
        );
        std::fs::remove_file(&marker).unwrap();

        run_git_diff(&workspace, false, None).await.unwrap();
        assert!(
            !marker.exists(),
            "git_diff descended into a dirty submodule and executed its filter"
        );
    }

    #[tokio::test]
    async fn registry_rejects_an_undiffable_path_before_spawning_git() {
        // The fs tools address the host, but a pathspec still has to name something this
        // repository can diff. That refusal is structural, not a confinement policy.
        let temp = TestDir::new("path-escape");
        let registry = Registry::read_only(&temp.0).unwrap();
        let result = registry
            .run(ToolUse {
                id: "git-path-escape".into(),
                name: "git_diff".into(),
                input: serde_json::json!({"path":"../outside"}),
            })
            .await;
        assert!(result.is_error);
        assert!(
            result
                .content
                .contains("outside the repository being diffed"),
            "{}",
            result.content
        );
    }
}
