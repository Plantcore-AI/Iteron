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
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
static USABLE_BWRAP: OnceLock<PathBuf> = OnceLock::new();

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
    let status = std::process::Command::new(&binary)
        .args(BWRAP_PROBE_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
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
}

impl Default for Bubblewrap {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the bwrap argument vector for a confinement. Pure function so the policy is
/// unit-testable (we assert net is unshared by default and only the workspace is writable).
pub fn bwrap_args(conf: &Confinement, command: &str) -> Vec<String> {
    let ws = conf.workspace.display().to_string();
    let mut a: Vec<String> = Vec::new();
    // Read-only system so compilers/interpreters work; nothing here is writable.
    for ro in ["/usr", "/bin", "/lib", "/lib64", "/etc", "/opt"] {
        if std::path::Path::new(ro).exists() {
            a.push("--ro-bind".into());
            a.push(ro.into());
            a.push(ro.into());
        }
    }
    // Writable: ONLY the workspace and a private tmp. This is the containment that matters.
    a.push("--bind".into());
    a.push(ws.clone());
    a.push(ws.clone());
    a.push("--tmpfs".into());
    a.push("/tmp".into());
    // Minimal /dev and /proc.
    a.push("--dev".into());
    a.push("/dev".into());
    a.push("--proc".into());
    a.push("/proc".into());
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

#[async_trait::async_trait]
impl Sandbox for Bubblewrap {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
        let Some(binary) = usable_bwrap() else {
            // Deny-by-default: missing *or unusable* bwrap means we refuse, never run unconfined.
            // This covers hosts where an LSM/kernel policy permits `--version` but rejects the
            // user namespace that actually provides confinement.
            return Err(SandboxError::Unsupported);
        };
        let args = bwrap_args(conf, command);
        let mut cmd = tokio::process::Command::new(binary);
        cmd.args(&args);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn args_unshare_net_by_default_and_bind_only_workspace() {
        let conf = Confinement::egress_off(PathBuf::from("/work/repo"));
        let a = bwrap_args(&conf, "make test");
        assert!(
            a.iter().any(|x| x == "--unshare-net"),
            "network must be unshared by default"
        );
        // the workspace is bound read-write; system dirs are ro-bind
        let joined = a.join(" ");
        assert!(
            joined.contains("--bind /work/repo /work/repo"),
            "workspace writable"
        );
        assert!(joined.contains("--ro-bind /usr /usr"), "system read-only");
        assert!(
            a.last().map(|s| s == "make test").unwrap_or(false),
            "command is last"
        );
        assert_eq!(&a[a.len() - 3..], ["/bin/bash", "-c", "make test"]);
        assert!(
            BWRAP_CANDIDATES
                .iter()
                .all(|candidate| Path::new(candidate).is_absolute())
        );
        assert!(
            BWRAP_PROBE_ARGS
                .windows(3)
                .any(|args| args == ["--ro-bind", "/", "/"]),
            "the capability probe must not grant host writes"
        );
        assert!(
            BWRAP_PROBE_ARGS.contains(&"--unshare-net"),
            "the capability probe must exercise the load-bearing network namespace"
        );
    }

    #[test]
    fn egress_escalation_shares_the_network() {
        let mut conf = Confinement::egress_off(PathBuf::from("/work/repo"));
        conf.allow_egress = true;
        let a = bwrap_args(&conf, "curl x");
        assert!(
            !a.iter().any(|x| x == "--unshare-net"),
            "escalated egress must not unshare net"
        );
    }

    // Live confinement test: only where bwrap actually exists (Linux CI). Asserts the kernel
    // blocks the network, mirroring the Seatbelt live test.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn code_runs_but_network_is_blocked_when_bwrap_present() {
        if trusted_bwrap().is_none() {
            eprintln!("skipping: bwrap not installed");
            return;
        }
        assert!(
            Bubblewrap::available(),
            "trusted bwrap is installed but cannot create the required namespace/mount boundary"
        );
        let dir = std::env::temp_dir();
        let sb = Bubblewrap::new();
        let conf = Confinement::egress_off(&dir);
        let ok = sb.run("echo confined", &conf).await.unwrap();
        assert_eq!(
            ok.exit_code, 0,
            "the functional probe passed but the real sandbox failed: {}",
            ok.stderr
        );
        assert!(ok.stdout.contains("confined"));
        // With --unshare-net there are no interfaces; a connect must fail.
        let net = sb
            .run(
                "if bash -c 'exec 3<>/dev/tcp/1.1.1.1/80' 2>/dev/null; then echo network-open; exit 97; else echo network-blocked; fi",
                &conf,
            )
            .await
            .unwrap();
        assert_eq!(
            net.exit_code, 0,
            "network unexpectedly reachable: {}",
            net.stderr
        );
        assert!(
            net.stdout.contains("network-blocked"),
            "the connect inside was refused by the empty net namespace"
        );

        let mut flood_conf = Confinement::egress_off(&dir);
        flood_conf.max_output_bytes = 4 * 1024;
        flood_conf.timeout_secs = 5;
        let flood = sb
            .run(
                "(yes O | head -c 1048576) & (yes E | head -c 1048576 >&2) & wait",
                &flood_conf,
            )
            .await
            .unwrap();
        assert!(flood.stdout_truncated && flood.stderr_truncated);
    }
}
