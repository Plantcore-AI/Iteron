//! Linux backend: **bubblewrap** (`bwrap`) for filesystem confinement + `unshare` of the
//! network namespace for egress-off. This is ADR-007's designed Linux path, and it is what
//! makes core deployable on a Linux server (the #1 production blocker without it).
//!
//! Posture (deny-by-default, matching the Seatbelt backend):
//!   - a fresh mount namespace: read-only bind of the host's system dirs (so toolchains work),
//!     a read-WRITE bind of ONLY the workspace + a private /tmp, and nothing else writable.
//!   - `--unshare-net` when egress is off: the process gets an empty network namespace with no
//!     interfaces, so it physically cannot reach the network (the kernel-level denial, not a
//!     prompt). When egress is escalated, the net namespace is shared.
//!   - `--die-with-parent`, `--new-session`, dropped ambient caps.
//!
//! Honest limits: bwrap must be present (it is on most modern distros / CI images; if absent we
//! refuse rather than run unconfined). This is a namespace boundary, not a VM; a kernel bug can
//! still escape. It is the same primitive Codex uses on Linux, and a real blast-radius reduction.

use crate::{Confinement, RunOutput, Sandbox, SandboxError};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const BWRAP_PROBE_POLL: Duration = Duration::from_millis(10);
const BWRAP_PROBE_MAX_POLLS: usize = 500;
const BWRAP_PROBE_REAP_POLLS: usize = 100;
static USABLE_BWRAP: OnceLock<PathBuf> = OnceLock::new();

/// Credential-free, user-scoped toolchain roots that may be exposed read-only inside the Linux
/// namespace. Keep these narrower than their parent configuration directories: for example,
/// binding all of `.cargo` would also expose `credentials.toml`, and binding all of HOME would
/// defeat the sandbox's default-deny filesystem posture.
const TOOLCHAIN_HOME_READ_SUBPATHS: &[&str] = &[
    ".cargo/bin",
    ".cargo/git",
    ".cargo/registry",
    ".rustup",
    ".pyenv",
    ".nvm/versions",
    ".local/bin",
    ".local/lib",
    ".npm/_cacache",
    ".cache/pip",
    ".cache/uv",
    ".gradle/caches",
    ".gradle/wrapper",
    ".m2/repository",
    "go",
];

const MAX_HOME_COMPONENTS: usize = 64;

// `bwrap --version` only proves that the executable can start. In particular, Ubuntu 24.04 can
// install a perfectly valid bwrap while AppArmor still refuses the unprivileged user namespace
// needed to create a sandbox. Probe the namespace and mount operations that carry our security
// contract before advertising this backend as usable. The fixed `/bin/true` cannot observe or
// mutate caller-controlled state; the host root is mounted read-only solely so its loader exists.
const BWRAP_PROBE_ARGS: &[&str] = &[
    "--ro-bind",
    "/",
    "/",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
    "--die-with-parent",
    "--new-session",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-net",
    "/bin/true",
];

fn trusted_bwrap() -> Option<PathBuf> {
    BWRAP_CANDIDATES.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // A namespace boundary cannot start by executing a binary writable by an untrusted
            // user/group. Root-owned, non-group/world-writable is the trusted system contract.
            if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
                return None;
            }
        }
        Some(path.to_path_buf())
    })
}

fn usable_bwrap() -> Option<PathBuf> {
    let binary = trusted_bwrap()?;
    if USABLE_BWRAP.get().is_some_and(|probed| probed == &binary) {
        // Keep revalidating ownership and mode through `trusted_bwrap`; cache only the expensive
        // successful namespace process, never the executable's trust decision.
        return Some(binary);
    }
    let mut child = std::process::Command::new(&binary)
        .args(BWRAP_PROBE_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + BWRAP_PROBE_TIMEOUT;
    let mut success = false;
    let mut completed = false;
    for _ in 0..BWRAP_PROBE_MAX_POLLS {
        match child.try_wait() {
            Ok(Some(status)) => {
                success = status.success();
                completed = true;
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(BWRAP_PROBE_POLL),
            Ok(None) | Err(_) => break,
        }
    }
    if !completed {
        let _ = child.kill();
        for _ in 0..BWRAP_PROBE_REAP_POLLS {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(BWRAP_PROBE_POLL),
                Err(_) => break,
            }
        }
    }
    if !success {
        // Do not cache a negative result: an operator may install an AppArmor profile or enable
        // user namespaces while a long-lived harness process is still running.
        return None;
    }
    let _ = USABLE_BWRAP.set(binary.clone());
    Some(binary)
}

pub struct Bubblewrap;

impl Bubblewrap {
    pub fn new() -> Self {
        Bubblewrap
    }
    /// Can a fixed, root-owned system `bwrap` create the namespaces and mounts required by this
    /// backend? PATH is intentionally ignored: a cloned repository must not substitute the
    /// executable that is supposed to create its sandbox.
    pub fn available() -> bool {
        usable_bwrap().is_some()
    }

    async fn run_inner(
        &self,
        command: &str,
        conf: &Confinement,
        pre_sanitization_env: &[(&str, &str)],
    ) -> Result<RunOutput, SandboxError> {
        let Some(binary) = usable_bwrap() else {
            // Deny-by-default: missing *or unusable* bwrap means we refuse, never run unconfined.
            // This covers hosts where an LSM/kernel policy permits `--version` but rejects the
            // user namespace that actually provides confinement.
            return Err(SandboxError::Unsupported);
        };
        let synthetic_home = pre_sanitization_env
            .iter()
            .rev()
            .find_map(|(name, value)| (*name == "HOME").then(|| PathBuf::from(value)));
        let inherited_home = std::env::var_os("HOME").map(PathBuf::from);
        let args = bwrap_args_with_home(
            conf,
            command,
            synthetic_home.as_deref().or(inherited_home.as_deref()),
        );
        let mut cmd = tokio::process::Command::new(binary);
        cmd.args(&args);
        // Tests inject only synthetic values here so exact-name removal is exercised without
        // mutating the test runner's process-global environment. Production always passes an
        // empty slice and therefore grants no additional environment authority.
        for (name, value) in pre_sanitization_env {
            cmd.env(name, value);
        }
        // Inherit the operator's real toolchain env but strip every secret-shaped var
        // (ANTHROPIC_API_KEY, *_TOKEN, AWS_*, …). The egress-off network denial is the real
        // containment; this restores venvs/PATH/HOME so real build/test commands run
        // (live-e2e review: env_clear + HOME=/tmp broke Python user site-packages).
        crate::confine_env_with_exact(&mut cmd, &conf.sensitive_env_names);
        cmd.env("TERM", "dumb")
            .env("PAGER", "cat")
            .env("MANPAGER", "cat")
            .env("GIT_PAGER", "cat")
            .env("PIP_PROGRESS_BAR", "off")
            .env("TQDM_DISABLE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true); // code review F4: never leak a running process on timeout/return
        crate::configure_process_group(&mut cmd);
        let mut child = cmd
            .spawn()
            .map_err(|e| SandboxError::Spawn(e.to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Spawn("child stdout was not piped".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Spawn("child stderr was not piped".into()))?;
        crate::collect_child_output(child, stdout, stderr, conf).await
    }

    #[cfg(all(test, target_os = "linux"))]
    async fn run_with_synthetic_parent_env(
        &self,
        command: &str,
        conf: &Confinement,
        env: &[(&str, &str)],
    ) -> Result<RunOutput, SandboxError> {
        self.run_inner(command, conf, env).await
    }
}

impl Default for Bubblewrap {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the bwrap argument vector for a confinement. The only ambient input is the operator's
/// HOME path, whose existing allowlisted toolchain roots are resolved into read-only mounts.
pub fn bwrap_args(conf: &Confinement, command: &str) -> Vec<String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    bwrap_args_with_home(conf, command, home.as_deref())
}

fn bwrap_args_with_home(conf: &Confinement, command: &str, home: Option<&Path>) -> Vec<String> {
    let ws = conf.workspace.display().to_string();
    let mut a: Vec<String> = Vec::new();
    let (home_dirs, home_mounts) = toolchain_home_mount_plan(home);
    // Read-only system so compilers/interpreters work; nothing here is writable.
    for ro in ["/usr", "/bin", "/lib", "/lib64", "/etc", "/opt"] {
        if std::path::Path::new(ro).exists() {
            a.push("--ro-bind".into());
            a.push(ro.into());
            a.push(ro.into());
        }
    }
    // Writable: ONLY the workspace and a private tmp. Mount private tmp first so a workspace
    // underneath the host's /tmp can be bound back into the namespace instead of being masked.
    a.push("--tmpfs".into());
    a.push("/tmp".into());
    for directory in home_dirs {
        a.push("--dir".into());
        a.push(directory.display().to_string());
    }
    a.push("--bind".into());
    a.push(ws.clone());
    a.push(ws.clone());
    for (source, destination) in home_mounts {
        a.push("--ro-bind".into());
        a.push(source.display().to_string());
        a.push(destination.display().to_string());
    }
    // Minimal /dev and /proc.
    a.push("--dev".into());
    a.push("/dev".into());
    a.push("--proc".into());
    a.push("/proc".into());
    // Make the namespace root read-only.
    //
    // This is the line that turns "nothing else is bound" into "nothing else is writable". bwrap's
    // root is a fresh tmpfs, and it *creates the parent directories of every mount point on it* —
    // so binding `<root>/workspace` silently materialises a writable `<root>/` beside it. A write
    // to a sibling path like `<root>/outside-write` then succeeds: it lands in the disposable root
    // tmpfs rather than on the host, so nothing escapes, but the write syscall is not denied and
    // the process cannot tell the difference. That is the gap `d4_13_d5_14_linux_live_...` probes,
    // and why the sandbox could not be described as a write-containment boundary.
    //
    // `--remount-ro /` remounts only the root mount. The workspace bind, the private `/tmp` tmpfs,
    // `/dev` and `/proc` are each their own mount, so they keep the access they were given. It has
    // to come after every bind, because bwrap applies these in order.
    a.push("--remount-ro".into());
    a.push("/".into());
    // Hardening.
    a.push("--die-with-parent".into());
    a.push("--new-session".into());
    a.push("--unshare-pid".into());
    a.push("--unshare-ipc".into());
    a.push("--unshare-uts".into());
    // Network: the load-bearing denial. Empty net namespace unless egress is escalated.
    if !conf.allow_egress {
        a.push("--unshare-net".into());
    }
    // Working directory inside the sandbox = the workspace.
    a.push("--chdir".into());
    a.push(ws);
    // The command.
    a.push("/bin/bash".into());
    a.push("-c".into());
    a.push(command.into());
    a
}

/// Plan mounts only for existing toolchain/cache roots below a canonical HOME. Symlinks that
/// resolve outside HOME are ignored rather than turning a seemingly safe allowlist entry into an
/// arbitrary host read. Namespace parent directories are empty scaffolding; HOME itself is never
/// host-bound.
fn toolchain_home_mount_plan(home: Option<&Path>) -> (Vec<PathBuf>, Vec<(PathBuf, PathBuf)>) {
    let Some(home) = home.filter(|path| path.is_absolute()) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(canonical_home) = std::fs::canonicalize(home) else {
        return (Vec::new(), Vec::new());
    };

    let component_count = home.components().count();
    if component_count == 0 || component_count > MAX_HOME_COMPONENTS {
        return (Vec::new(), Vec::new());
    }

    let mut namespace_dirs = BTreeSet::new();
    let mut ancestor = PathBuf::new();
    for component in home.components() {
        ancestor.push(component.as_os_str());
        if ancestor != Path::new("/") {
            namespace_dirs.insert(ancestor.clone());
        }
    }

    let mut mounts = Vec::with_capacity(TOOLCHAIN_HOME_READ_SUBPATHS.len());
    for relative in TOOLCHAIN_HOME_READ_SUBPATHS {
        let destination = home.join(relative);
        let Ok(source) = std::fs::canonicalize(&destination) else {
            continue;
        };
        if !source.starts_with(&canonical_home) {
            continue;
        }
        if !source.is_dir() && !source.is_file() {
            continue;
        }

        if let Some(parent) = destination.parent() {
            let Ok(relative_parent) = parent.strip_prefix(home) else {
                continue;
            };
            let mut namespace_parent = home.to_path_buf();
            for component in relative_parent.components() {
                namespace_parent.push(component.as_os_str());
                namespace_dirs.insert(namespace_parent.clone());
            }
        }
        mounts.push((source, destination));
    }

    if mounts.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Bubblewrap starts with an empty namespace root. These directories merely host the narrow
    // mounts and expose none of their corresponding host contents.
    (namespace_dirs.into_iter().collect(), mounts)
}

#[async_trait::async_trait]
impl Sandbox for Bubblewrap {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
        self.run_inner(command, conf, &[]).await
    }
}

#[cfg(test)]
#[path = "bubblewrap_tests.rs"]
mod tests;
