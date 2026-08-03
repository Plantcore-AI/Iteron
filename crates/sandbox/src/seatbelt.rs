//! macOS Seatbelt backend: `sandbox-exec` with an SBPL profile.
//!
//! The profile is deny-by-default. Reads are allowlisted to the workspace, system runtime/toolchain
//! roots, and explicit user toolchain/cache roots; writes are confined to the workspace + per-run
//! temp dir. It **denies all network** unless egress is explicitly granted. This is not a complete
//! information-flow or provider taint boundary, but it does not expose ambient HOME by default.
//!
//! Honest limits (stated, per the truth gate): Seatbelt is a capability boundary, not a VM; a
//! kernel bug or an approved-but-malicious toolchain can still do harm, and Apple has signaled
//! SBPL is not forever. It is the same primitive the reference implementations use, and it is a
//! real reduction of blast radius, not a solution.

use crate::{Confinement, RunOutput, Sandbox, SandboxError};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// High-value user directories that build toolchains do not need to read. This is deliberately
/// explicit rather than denying all of HOME: language runtimes commonly live in `.cargo`,
/// `.rustup`, `.nvm`, virtualenvs, etc. A denylist cannot prove absence of every secret, but these
/// entries close the common credential and agent-state paths without making compilers unusable.
const PROTECTED_HOME_SUBPATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".oci",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".config/glab-cli",
    ".config/doctl",
    ".config/op",
    ".cache/git/credential",
    ".git-credential-cache",
    ".claude",
    ".config/claude",
    ".codex",
    ".config/codex",
    ".core",
    ".config/core",
    ".cursor",
    ".continue",
    ".gemini",
    ".config/opencode",
    "Library/Keychains",
    "Library/Application Support/Claude",
    "Library/Application Support/Codex",
    "Library/Application Support/1Password",
];

/// Credential-bearing files inside otherwise useful HOME subtrees. In particular, denying all of
/// `.cargo`, `.gradle`, or `.m2` would hide installed toolchains and dependency caches.
const PROTECTED_HOME_FILES: &[&str] = &[
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".config/git/credentials",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".config/pip/pip.conf",
    ".gradle/gradle.properties",
    ".m2/settings.xml",
    ".terraformrc",
    ".terraform.d/credentials.tfrc.json",
    ".vault-token",
    ".claude.json",
    ".mcp.json",
    ".zsh_history",
    ".bash_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
];

/// User-keychain services observed on current macOS releases. `com.apple.SecurityServer` is the
/// load-bearing service used by `/usr/bin/security`; the other names are denied defensively so a
/// child cannot switch to a lower-level securityd endpoint.
const PROTECTED_MACH_SERVICES: &[&str] = &[
    "com.apple.SecurityServer",
    "com.apple.securityd",
    "com.apple.securityd.xpc",
    "com.apple.securityd.general",
    "com.apple.securityd.systemkeychain",
    // DNS resolution crosses Mach to mDNSResponder and can otherwise bypass `(deny network*)`
    // as a DNS exfiltration channel. Keep these explicit denies even while ordinary toolchain
    // services remain under the broad compatibility grant below.
    "com.apple.mDNSResponder",
    "com.apple.mDNSResponder_Helper",
    "com.apple.dnssd.service",
    // GUI and clipboard brokers are unnecessary for headless build/test commands and would turn
    // the sandbox into an ambient desktop-data reader if blanket Mach lookup returned.
    "com.apple.pboard",
    "com.apple.pasteboard.1",
    "com.apple.WindowServer",
    "com.apple.windowserver.active",
];

/// Narrow Mach services used by ordinary non-interactive shells and toolchains. Everything else
/// remains denied by `(deny default)`. Keep this list evidence-driven: additions expand ambient
/// host authority and require a live build regression test.
const ALLOWED_MACH_SERVICES: &[&str] = &[
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
    "com.apple.system.logger",
    "com.apple.logd",
    "com.apple.system.opendirectoryd.libinfo",
];

/// Host roots required by ordinary macOS shells, compilers, SDKs, Homebrew, and dynamic linking.
/// This is deliberately an allowlist: arbitrary `/Users`, `/Volumes`, and machine-private data are
/// absent. The workspace is added separately.
const READABLE_SYSTEM_SUBPATHS: &[&str] = &[
    "/System",
    "/Library",
    "/usr",
    "/bin",
    "/sbin",
    "/opt",
    "/Applications",
    "/private/etc",
    // xcrun/xcode-select resolves the active developer directory through this system-owned
    // symlink. Without it Rust/C/C++ compilation can start but cannot link against the macOS SDK.
    "/private/var/select",
    "/dev",
];

/// Root-level macOS aliases that may appear in an operator/workspace path. Reading the literal
/// symlink is necessary before Seatbelt can match the separately allowlisted resolved target; it
/// does not grant recursive access through the alias.
const READABLE_ROOT_ALIASES: &[&str] = &["/var", "/tmp", "/etc", "/home"];

/// User-scoped build/runtime roots commonly needed for offline coding-agent commands. Do not add
/// broad `.cache`, `.config`, `Library`, or HOME grants here; each addition expands the data that
/// repo-controlled code can observe and later place in tool output.
const READABLE_HOME_SUBPATHS: &[&str] = &[
    ".cargo",
    ".rustup",
    ".pyenv",
    ".nvm",
    ".local",
    ".npm/_cacache",
    ".cache/pip",
    ".cache/uv",
    ".gradle/caches",
    ".gradle/wrapper",
    ".m2/repository",
    "go",
    "Library/Caches/Homebrew",
    "Library/Caches/go-build",
    "Library/Developer",
    "Library/Python",
];

pub struct Seatbelt;

impl Seatbelt {
    pub fn new() -> Self {
        Seatbelt
    }
}

impl Default for Seatbelt {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape a path for an SBPL double-quoted string literal (code review SEC-2: a path containing
/// `"` or `\` would otherwise break out of the literal and could disable confinement). Control
/// characters are rejected rather than lossy-replaced: a deny rule that names a different path is
/// a fail-open. Inside a properly escaped literal, `(` `)` `*` and spaces are ordinary bytes.
fn sbpl_escape(s: &str) -> Result<String, SandboxError> {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                return Err(SandboxError::Profile(
                    "policy path contains a control character; refusing to build a lossy SBPL rule"
                        .into(),
                ));
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Render an exact filesystem path into an SBPL literal. Relative or non-UTF-8 paths cannot be
/// represented without ambiguity, so policy construction refuses them (fail closed).
fn sbpl_path(path: &Path, label: &str) -> Result<String, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::Profile(format!(
            "{label} must be an absolute path"
        )));
    }
    let raw = path
        .to_str()
        .ok_or_else(|| SandboxError::Profile(format!("{label} is not valid UTF-8")))?;
    sbpl_escape(raw)
}

/// Return both the declared path and, when it currently exists, its resolved target. Seatbelt
/// checks the resolved vnode path, so a credential directory symlinked outside HOME must carve out
/// the target as well. Missing paths retain their declared deny so later ordinary creation remains
/// protected.
fn sbpl_path_variants(path: &Path, label: &str) -> Result<Vec<String>, SandboxError> {
    let declared = sbpl_path(path, label)?;
    let mut paths = vec![declared];
    if let Ok(resolved) = std::fs::canonicalize(path) {
        let resolved = sbpl_path(&resolved, label)?;
        if !paths.contains(&resolved) {
            paths.push(resolved);
        }
    }
    Ok(paths)
}

fn operator_home() -> Result<PathBuf, SandboxError> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        SandboxError::Profile("HOME is unset; refusing a profile without user-secret denies".into())
    })?;
    canonical_home(PathBuf::from(home))
}

fn canonical_home(home: PathBuf) -> Result<PathBuf, SandboxError> {
    if !home.is_absolute() {
        return Err(SandboxError::Profile(
            "HOME is not absolute; refusing a profile without reliable user-secret denies".into(),
        ));
    }
    // Seatbelt evaluates the resolved vnode path. macOS aliases such as `/var` -> `/private/var`
    // would otherwise let a textual deny miss its target. HOME must exist for a usable toolchain,
    // so failure to canonicalize is a policy-construction error, not a reason to omit the denies.
    std::fs::canonicalize(&home).map_err(|e| {
        SandboxError::Profile(format!("cannot canonicalize HOME for secret denies: {e}"))
    })
}

/// Build the SBPL profile text for a confinement. Kept a pure function so the policy is
/// unit-testable (we assert network is denied, secret reads are denied, and the workspace is the
/// only writable root). Production resolves the protected HOME from the parent process; tests use
/// `profile_for_home` to exercise the same builder deterministically.
pub fn profile(conf: &Confinement) -> Result<String, SandboxError> {
    let home = operator_home()?;
    profile_for_home(conf, &home)
}

/// The profile fragments that depend only on the operator's HOME. Building them canonicalizes
/// close to ninety paths, measured at about 7.5ms over a bare shell, and the strictly serial
/// effecting-tool loop paid that on every single shell and git call. HOME does not change inside a
/// session, so the fragments are built once and spliced into each rendered profile in their
/// original order (SBPL is order-sensitive: the denies must stay after the workspace grants).
///
/// Honest limit: a memoized fragment is a snapshot of the filesystem at first use. A credential
/// directory that becomes a symlink *after* the first profile was built keeps its declared deny but
/// does not gain a deny on the newly resolved target until the process restarts. The declared path
/// stays denied either way and no allow rule is ever widened by the memo.
struct HomeRules {
    read_metadata: String,
    read_roots: String,
    denies: String,
}

fn build_home_rules(home: &Path) -> Result<HomeRules, SandboxError> {
    let mut read_metadata = String::new();
    if let Some(parent) = home.parent() {
        let parent = sbpl_path(parent, "HOME parent")?;
        read_metadata.push_str(&format!(
            "(allow file-read-metadata (literal \"{parent}\"))\n"
        ));
    }
    let home_literal = sbpl_path(home, "HOME")?;
    read_metadata.push_str(&format!(
        "(allow file-read-metadata (literal \"{home_literal}\"))\n"
    ));

    let mut read_roots = String::new();
    for relative in READABLE_HOME_SUBPATHS {
        for path in sbpl_path_variants(&home.join(relative), "user toolchain read root")? {
            read_roots.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
        }
    }

    // Credential and agent-state carve-outs. Deny writes too: if an operator accidentally points
    // the workspace inside one of these trees, the workspace grant must not authorize mutation.
    let mut denies = String::new();
    for relative in PROTECTED_HOME_SUBPATHS {
        for path in sbpl_path_variants(&home.join(relative), "protected HOME subpath")? {
            denies.push_str(&format!("(deny file-read* (subpath \"{path}\"))\n"));
            denies.push_str(&format!("(deny file-write* (subpath \"{path}\"))\n"));
        }
    }
    for relative in PROTECTED_HOME_FILES {
        for path in sbpl_path_variants(&home.join(relative), "protected HOME file")? {
            denies.push_str(&format!("(deny file-read* (literal \"{path}\"))\n"));
            denies.push_str(&format!("(deny file-write* (literal \"{path}\"))\n"));
        }
    }
    Ok(HomeRules {
        read_metadata,
        read_roots,
        denies,
    })
}

/// Everything the rendered profile text depends on. Nothing else in `Confinement` reaches SBPL.
#[derive(PartialEq, Eq)]
struct ProfileKey {
    workspace: PathBuf,
    scratch: PathBuf,
    home: PathBuf,
    allow_egress: bool,
}

impl ProfileKey {
    fn of(conf: &Confinement, home: &Path) -> Self {
        Self {
            workspace: conf.workspace.clone(),
            scratch: conf.scratch.clone(),
            home: home.to_path_buf(),
            allow_egress: conf.allow_egress,
        }
    }
}

/// Per-process profile memo. One slot each is enough and keeps the memo bounded: a session runs one
/// workspace under one HOME, while `Confinement::egress_off` mints a fresh scratch path per call, so
/// retaining more than the last rendered profile would grow without limit across a long run.
struct ProfileCache {
    profile: Mutex<Option<(ProfileKey, Arc<str>)>>,
    home_rules: Mutex<Option<(PathBuf, Arc<HomeRules>)>>,
    renders: AtomicUsize,
    home_builds: AtomicUsize,
}

impl ProfileCache {
    const fn new() -> Self {
        Self {
            profile: Mutex::new(None),
            home_rules: Mutex::new(None),
            renders: AtomicUsize::new(0),
            home_builds: AtomicUsize::new(0),
        }
    }

    fn home_rules(&self, home: &Path) -> Result<Arc<HomeRules>, SandboxError> {
        if let Ok(slot) = self.home_rules.lock()
            && let Some((cached, rules)) = slot.as_ref()
            && cached == home
        {
            return Ok(Arc::clone(rules));
        }
        self.home_builds.fetch_add(1, Ordering::Relaxed);
        let rules = Arc::new(build_home_rules(home)?);
        if let Ok(mut slot) = self.home_rules.lock() {
            *slot = Some((home.to_path_buf(), Arc::clone(&rules)));
        }
        Ok(rules)
    }
}

static PROFILE_CACHE: ProfileCache = ProfileCache::new();

fn profile_for_home(conf: &Confinement, home: &Path) -> Result<String, SandboxError> {
    profile_with_cache(&PROFILE_CACHE, conf, home)
}

fn profile_with_cache(
    cache: &ProfileCache,
    conf: &Confinement,
    home: &Path,
) -> Result<String, SandboxError> {
    if !home.is_absolute() {
        return Err(SandboxError::Profile(
            "HOME must be an absolute path".into(),
        ));
    }
    let key = ProfileKey::of(conf, home);
    if let Ok(slot) = cache.profile.lock()
        && let Some((cached, profile)) = slot.as_ref()
        && *cached == key
    {
        return Ok(profile.to_string());
    }
    let rules = cache.home_rules(home)?;
    let profile = render_profile(conf, &rules)?;
    cache.renders.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut slot) = cache.profile.lock() {
        *slot = Some((key, Arc::from(profile.as_str())));
    }
    Ok(profile)
}

fn render_profile(conf: &Confinement, home_rules: &HomeRules) -> Result<String, SandboxError> {
    let workspaces = sbpl_path_variants(&conf.workspace, "workspace")?;
    let scratch_paths = sbpl_path_variants(&conf.scratch, "private scratch")?;
    let mut p = String::new();
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");
    // Process machinery the shell + toolchain need.
    p.push_str("(allow process-exec)\n");
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow signal (target self))\n");
    p.push_str("(allow sysctl-read)\n");
    for service in ALLOWED_MACH_SERVICES {
        p.push_str(&format!(
            "(allow mach-lookup (global-name \"{service}\"))\n"
        ));
    }
    // Read allowlist. Parent literals grant only traversal/metadata needed to reach named roots;
    // their contents are not readable. There is intentionally no ambient `(allow file-read*)`.
    // Seatbelt requires opening the root directory while resolving every absolute path. A literal
    // grant exposes only that one directory object, not recursive file contents.
    p.push_str("(allow file-read* (literal \"/\"))\n");
    for alias in READABLE_ROOT_ALIASES {
        let alias = sbpl_path(Path::new(alias), "system root alias")?;
        p.push_str(&format!("(allow file-read* (literal \"{alias}\"))\n"));
    }
    p.push_str(&home_rules.read_metadata);
    for workspace in &workspaces {
        p.push_str(&format!("(allow file-read* (subpath \"{workspace}\"))\n"));
    }
    for scratch in &scratch_paths {
        p.push_str(&format!("(allow file-read* (subpath \"{scratch}\"))\n"));
    }
    for root in READABLE_SYSTEM_SUBPATHS {
        let root = sbpl_path(Path::new(root), "system read root")?;
        p.push_str(&format!("(allow file-read* (subpath \"{root}\"))\n"));
    }
    p.push_str(&home_rules.read_roots);
    // Writes: confined to the workspace and temp only.
    for workspace in &workspaces {
        p.push_str(&format!("(allow file-write* (subpath \"{workspace}\"))\n"));
    }
    for scratch in &scratch_paths {
        p.push_str(&format!("(allow file-write* (subpath \"{scratch}\"))\n"));
    }
    p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    p.push_str("(allow file-write-data (literal \"/dev/stdout\"))\n");
    p.push_str("(allow file-write-data (literal \"/dev/stderr\"))\n");

    p.push_str(&home_rules.denies);
    // File rules alone do not protect Keychain: `/usr/bin/security` talks to securityd over Mach.
    for service in PROTECTED_MACH_SERVICES {
        p.push_str(&format!("(deny mach-lookup (global-name \"{service}\"))\n"));
    }

    // Network: the load-bearing denial. Off unless explicitly escalated (ADR-007 R13).
    if conf.allow_egress {
        p.push_str("(allow network*)\n");
    } else {
        p.push_str("(deny network*)\n");
    }
    Ok(p)
}

#[async_trait::async_trait]
impl Sandbox for Seatbelt {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
        prepare_private_scratch(&conf.scratch)?;
        let _scratch_cleanup = ScratchCleanup(conf.scratch.clone());
        let prof = profile(conf)?;
        // sandbox-exec -p <profile> /bin/bash -c <command>, cwd = workspace, pagers disabled.
        // `-c` intentionally avoids login/profile startup files from ambient HOME.
        let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-p")
            .arg(&prof)
            .arg("/bin/bash")
            .arg("-c")
            .arg(command)
            .current_dir(&conf.workspace);
        // Confine the environment: inherit the operator's real toolchain env but strip every
        // secret-shaped var (ANTHROPIC_API_KEY, *_TOKEN, AWS_*, …). The egress-off network denial
        // is the real containment; this restores venvs/PATH/HOME so real build/test commands run
        // (live-e2e review: env_clear + HOME=/tmp broke Python user site-packages).
        crate::confine_env_with_exact(&mut cmd, &conf.sensitive_env_names);
        cmd.env("TERM", "dumb")
            .env("TMPDIR", &conf.scratch)
            .env("TMP", &conf.scratch)
            .env("TEMP", &conf.scratch)
            .env("PAGER", "cat")
            .env("MANPAGER", "cat")
            .env("GIT_PAGER", "cat")
            .env("PIP_PROGRESS_BAR", "off")
            .env("TQDM_DISABLE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Kill the child if this future is dropped (code review F4: a timed-out or
            // early-returned run must not leak a running process).
            .kill_on_drop(true);
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

fn prepare_private_scratch(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::Profile(
            "private scratch path must be absolute".into(),
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(SandboxError::Profile(
            "private scratch path already exists; refusing to reuse or remove it".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(path)
            .map_err(|error| SandboxError::Spawn(format!("create private scratch: {error}"))),
        Err(error) => Err(SandboxError::Spawn(format!(
            "inspect private scratch: {error}"
        ))),
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

fn cleanup_private_scratch(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let _ = std::fs::remove_file(path);
        }
        Ok(metadata) if metadata.file_type().is_dir() => {
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}

struct ScratchCleanup(PathBuf);

impl Drop for ScratchCleanup {
    fn drop(&mut self) {
        cleanup_private_scratch(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(target_os = "macos")]
    async fn bounded_command_output(mut command: tokio::process::Command) -> std::process::Output {
        command.kill_on_drop(true);
        tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
            .await
            .expect("live sandbox-exec probe exceeded ten seconds")
            .unwrap()
    }

    #[test]
    fn profile_denies_network_by_default_and_confines_writes() {
        let conf = Confinement::egress_off(PathBuf::from("/repo"));
        let p = profile_for_home(&conf, Path::new("/Users/tester")).unwrap();
        assert!(p.contains("(deny default)"), "must be deny-by-default");
        assert!(
            p.contains("(deny network*)"),
            "network must be denied by default"
        );
        assert!(!p.contains("(allow network*)"));
        assert!(
            !p.lines().any(|line| line == "(allow mach-lookup)"),
            "Mach lookup must be a named allowlist, never an ambient grant"
        );
        for service in ALLOWED_MACH_SERVICES {
            assert!(
                p.contains(&format!("(allow mach-lookup (global-name \"{service}\"))")),
                "required toolchain service must be explicitly named"
            );
        }
        for service in [
            "com.apple.mDNSResponder",
            "com.apple.pboard",
            "com.apple.WindowServer",
        ] {
            assert!(
                p.contains(&format!("(deny mach-lookup (global-name \"{service}\"))")),
                "DNS, clipboard, and GUI services stay explicitly denied"
            );
        }
        assert!(
            p.contains("(allow file-write* (subpath \"/repo\"))"),
            "workspace writable"
        );
        assert!(
            p.contains(&format!(
                "(allow file-write* (subpath \"{}\"))",
                conf.scratch.display()
            )),
            "only the capability-private scratch is writable"
        );
        assert!(!p.contains("(allow file-write* (subpath \"/private/tmp\"))"));
        assert!(!p.contains("(allow file-write* (subpath \"/private/var/folders\"))"));
    }

    #[test]
    fn existing_scratch_is_refused_and_preserved() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "core-seatbelt-existing-scratch-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        let marker = path.join("owner-data");
        std::fs::write(&marker, "preserve").unwrap();

        let error = prepare_private_scratch(&path).unwrap_err();
        assert!(error.to_string().contains("refusing to reuse or remove"));
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "preserve");

        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn workspace_path_with_quote_is_escaped_not_injectable() {
        // SEC-2: a path containing a double-quote must not break out of the SBPL literal.
        let conf = Confinement::egress_off(PathBuf::from("/tmp/ev\"il)/repo"));
        let p = profile_for_home(&conf, Path::new("/Users/tester")).unwrap();
        // The quote is backslash-escaped, so the literal stays closed and network stays denied.
        assert!(
            p.contains("(deny network*)"),
            "confinement must survive a hostile path"
        );
        assert!(p.contains("ev\\\"il"), "the quote must be escaped");
        // No stray unescaped quote that would prematurely close the write-subpath literal.
        assert!(!p.contains("\"/tmp/ev\"il"));

        let quoted_home = Path::new("/Users/ev\"il");
        let p = profile_for_home(
            &Confinement::egress_off(PathBuf::from("/repo")),
            quoted_home,
        )
        .unwrap();
        assert!(
            p.contains("/Users/ev\\\"il/.ssh"),
            "protected HOME paths must use the same escaping"
        );
        assert!(!p.contains("\"/Users/ev\"il/.ssh"));
    }

    #[test]
    fn profile_allows_network_only_when_egress_escalated() {
        let mut conf = Confinement::egress_off(PathBuf::from("/repo"));
        conf.allow_egress = true;
        let p = profile_for_home(&conf, Path::new("/Users/tester")).unwrap();
        assert!(
            p.contains("(allow network*)"),
            "egress escalation must open the network"
        );
    }

    #[test]
    fn profile_allowlists_toolchains_without_ambient_home_reads() {
        let home = Path::new("/Users/tester");
        let conf = Confinement::egress_off(PathBuf::from("/Users/tester/project"));
        let p = profile_for_home(&conf, home).unwrap();

        assert!(!p.lines().any(|line| line == "(allow file-read*)"));
        assert!(p.contains("(allow file-read* (subpath \"/Users/tester/.cargo\"))"));
        assert!(p.contains("(allow file-read* (subpath \"/Users/tester/project\"))"));
        assert!(
            p.contains("(allow file-write* (subpath \"/Users/tester/project\"))"),
            "the workspace stays writable"
        );
        for relative in PROTECTED_HOME_SUBPATHS {
            let path = home.join(relative);
            let path = path.to_str().unwrap();
            assert!(
                p.contains(&format!("(deny file-read* (subpath \"{path}\"))")),
                "missing read deny for {path}"
            );
            assert!(
                p.contains(&format!("(deny file-write* (subpath \"{path}\"))")),
                "missing write deny for {path}"
            );
        }
        for relative in PROTECTED_HOME_FILES {
            let path = home.join(relative);
            let path = path.to_str().unwrap();
            assert!(
                p.contains(&format!("(deny file-read* (literal \"{path}\"))")),
                "missing read deny for {path}"
            );
        }
        for service in PROTECTED_MACH_SERVICES {
            assert!(
                p.contains(&format!("(deny mach-lookup (global-name \"{service}\"))")),
                "missing Keychain IPC deny for {service}"
            );
        }
    }

    #[test]
    fn profile_is_memoized_per_session_and_rebuilt_when_a_key_changes() {
        // I-59: the profile was rebuilt for every shell and git call, including ~90 path
        // canonicalisations measured at about 7.5ms, multiplied by the serial effecting-tool loop.
        let cache = ProfileCache::new();
        let home = Path::new("/Users/tester");
        let conf = Confinement::egress_off(PathBuf::from("/repo"));

        let first = profile_with_cache(&cache, &conf, home).unwrap();
        let second = profile_with_cache(&cache, &conf, home).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            cache.renders.load(Ordering::Relaxed),
            1,
            "repeated calls with the same key must build the profile once"
        );
        assert_eq!(
            first,
            profile_with_cache(&ProfileCache::new(), &conf, home).unwrap(),
            "a memoized profile must be byte-identical to a freshly built one"
        );

        // A changed egress decision is a changed key and must rebuild.
        let mut escalated = conf.clone();
        escalated.allow_egress = true;
        let escalated_profile = profile_with_cache(&cache, &escalated, home).unwrap();
        assert!(escalated_profile.contains("(allow network*)"));
        assert!(!escalated_profile.contains("(deny network*)"));
        assert_eq!(cache.renders.load(Ordering::Relaxed), 2);

        // A changed workspace is a changed key and must rebuild.
        let elsewhere = Confinement::egress_off(PathBuf::from("/other-repo"));
        let elsewhere_profile = profile_with_cache(&cache, &elsewhere, home).unwrap();
        assert!(elsewhere_profile.contains("(allow file-write* (subpath \"/other-repo\"))"));
        assert!(!elsewhere_profile.contains("(allow file-write* (subpath \"/repo\"))"));
        assert_eq!(cache.renders.load(Ordering::Relaxed), 3);

        // Every `Confinement` mints a fresh scratch path, so the rendered text must follow it while
        // the HOME canonicalisations — the actual cost — stay paid exactly once per session.
        let rotated = Confinement::egress_off(PathBuf::from("/repo"));
        assert_ne!(rotated.scratch, conf.scratch);
        let rotated_profile = profile_with_cache(&cache, &rotated, home).unwrap();
        assert!(rotated_profile.contains(&format!(
            "(allow file-write* (subpath \"{}\"))",
            rotated.scratch.display()
        )));
        assert_eq!(
            cache.home_builds.load(Ordering::Relaxed),
            1,
            "the HOME canonicalisations must not be repeated for a rotated scratch or egress flip"
        );

        // A changed HOME does rebuild them, and the new secret denies are present.
        let other_home = profile_with_cache(&cache, &conf, Path::new("/Users/other")).unwrap();
        assert!(other_home.contains("(deny file-read* (subpath \"/Users/other/.ssh\"))"));
        assert!(!other_home.contains("/Users/tester/.ssh"));
        assert_eq!(cache.home_builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn ambiguous_policy_paths_fail_closed() {
        let relative = Confinement::egress_off(PathBuf::from("relative/workspace"));
        assert!(profile_for_home(&relative, Path::new("/Users/tester")).is_err());

        let control = Confinement::egress_off(PathBuf::from("/tmp/workspace\nrule"));
        assert!(profile_for_home(&control, Path::new("/Users/tester")).is_err());

        let conf = Confinement::egress_off(PathBuf::from("/repo"));
        assert!(profile_for_home(&conf, Path::new("relative/home")).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn home_alias_is_canonicalized_and_missing_home_fails_closed() {
        use std::os::unix::fs::symlink;

        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("core-seatbelt-home-{pid}-{nonce:x}"));
        let real_home = root.join("real-home");
        let home_alias = root.join("home-alias");
        std::fs::create_dir_all(&real_home).unwrap();
        symlink(&real_home, &home_alias).unwrap();

        assert_eq!(
            canonical_home(home_alias).unwrap(),
            std::fs::canonicalize(&real_home).unwrap()
        );
        assert!(canonical_home(root.join("missing-home")).is_err());
        assert!(canonical_home(PathBuf::from("relative-home")).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    // Live confinement tests: only run on macOS where sandbox-exec exists.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn d4_13_d5_14_macos_live_network_is_actually_blocked() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "core-seatbelt-build-{}-{nonce:x}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("hello.rs"),
            "fn main() { println!(\"compiled-inside-seatbelt\"); }\n",
        )
        .unwrap();
        let sb = Seatbelt::new();
        let conf = Confinement::egress_off(&dir);

        // Benign code runs and its output is captured.
        let ok = sb.run("echo confined && exit 0", &conf).await.unwrap();
        assert!(ok.stdout.contains("confined"), "sandbox failed: {ok:?}");
        assert_eq!(ok.exit_code, 0);

        // Compile and execute a real source file. This catches an over-narrow Mach or filesystem
        // allowlist that would pass `rustc --version` while breaking ordinary builds.
        let rustc = sb
            .run("rustc hello.rs -o hello && ./hello", &conf)
            .await
            .unwrap();
        assert_eq!(rustc.exit_code, 0, "confined rustc failed: {rustc:?}");
        assert!(rustc.stdout.contains("compiled-inside-seatbelt"));

        // Bind a loopback listener that is provably reachable from the host, then require the same
        // connect to fail inside Seatbelt. This assertion fails if `(deny network*)` regresses;
        // it cannot pass merely because an external address happened to be down.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let host_probe =
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1))
                .expect("the host-side loopback precondition must be reachable");
        drop(host_probe);
        let port = address.port();
        let net = sb
            .run(
                &format!(
                    "if bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; then echo network-open; exit 97; else echo network-blocked; fi"
                ),
                &conf,
            )
            .await
            .unwrap();
        assert_eq!(
            net.exit_code, 0,
            "loopback unexpectedly reachable from the sandbox: {net:?}"
        );
        assert!(net.stdout.contains("network-blocked"));
        assert!(!net.stdout.contains("network-open"));

        // `dns-sd` talks to mDNSResponder over Mach rather than opening the caller's own socket.
        // Resolving localhost is a deterministic host precondition and would return both loopback
        // addresses under the former blanket mach-lookup grant. The explicit DNS-service denials
        // must instead fail fast, closing that proxy/exfiltration path as well as direct sockets.
        let dns = sb
            .run("/usr/bin/dns-sd -G v4v6 localhost", &conf)
            .await
            .unwrap();
        assert!(!dns.timed_out, "denied DNS service lookup must fail fast");
        assert_ne!(dns.exit_code, 0, "mDNSResponder must be unreachable");
        assert!(
            !dns.stdout.contains("127.0.0.1") && !dns.stdout.contains("0000:0000:0000:0000"),
            "DNS resolution escaped through mDNSResponder: {dns:?}"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn sibling_in_host_temp_is_not_readable_or_writable() {
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("core-seatbelt-sibling-{pid}-{nonce:x}"));
        let workspace = root.join("workspace");
        let sibling_read = root.join("outside-read");
        let sibling_write = root.join("outside-write");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(&sibling_read, "must-not-be-readable").unwrap();
        let confinement = Confinement::egress_off(&workspace);
        let command = format!(
            "cat '{}' 2>/dev/null || true; printf escaped > '{}'",
            sibling_read.display(),
            sibling_write.display()
        );
        let output = Seatbelt::new().run(&command, &confinement).await.unwrap();
        assert_ne!(output.exit_code, 0);
        assert!(
            !output.stdout.contains("must-not-be-readable"),
            "a sandbox command must not read a sibling host-temp path"
        );
        assert!(
            !sibling_write.exists(),
            "a sandbox command must not write to a sibling host-temp path"
        );
        assert!(
            !confinement.scratch.exists(),
            "capability-private scratch is removed after the command"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn simultaneous_stdout_and_stderr_floods_are_live_bounded() {
        let dir = std::env::temp_dir();
        let sb = Seatbelt::new();
        let mut conf = Confinement::egress_off(&dir);
        conf.max_output_bytes = 4 * 1024;
        conf.timeout_secs = 5;

        let output = sb
            .run(
                "(yes O | head -c 1048576) & (yes E | head -c 1048576 >&2) & wait",
                &conf,
            )
            .await
            .unwrap();

        assert!(!output.timed_out);
        assert!(output.stdout_truncated);
        assert!(output.stderr_truncated);
        assert!(output.stdout.contains("[stdout truncated after 4096 bytes"));
        assert!(output.stderr.contains("[stderr truncated after 4096 bytes"));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn timeout_kills_live_sandbox_descendants_and_preserves_partial_output() {
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let workspace = std::env::temp_dir().join(format!("core-seatbelt-timeout-{pid}-{nonce:x}"));
        std::fs::create_dir_all(&workspace).unwrap();
        let marker = workspace.join("escaped-descendant");
        let sb = Seatbelt::new();
        let mut conf = Confinement::egress_off(&workspace);
        conf.timeout_secs = 1;
        conf.max_output_bytes = 1024;

        let output = sb
            .run(
                "(sleep 2; printf leaked > escaped-descendant) & echo child-started; wait",
                &conf,
            )
            .await
            .unwrap();

        assert!(output.timed_out);
        assert!(output.stdout.contains("child-started"));
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            !marker.exists(),
            "a Seatbelt descendant must not survive the timeout"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn workspace_reads_work_but_secret_paths_and_keychain_are_live_denied() {
        use std::os::unix::fs::symlink;

        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("core-seatbelt-secrets-{pid}-{nonce:x}"));
        let home = root.join("home");
        let workspace = root.join("workspace");
        let ssh_target = root.join("external-ssh-store");
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ssh_target).unwrap();
        symlink(&ssh_target, &ssh).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let visible = workspace.join("visible.txt");
        let secret = ssh.join("id_test");
        std::fs::write(&visible, "workspace-visible").unwrap();
        std::fs::write(&secret, "must-not-be-readable").unwrap();
        symlink(&secret, workspace.join("secret-link")).unwrap();

        let conf = Confinement::egress_off(workspace.clone());
        let canonical_home = std::fs::canonicalize(&home).unwrap();
        let prof = profile_for_home(&conf, &canonical_home).unwrap();
        let run = |program: &str, args: &[&str]| {
            let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");
            cmd.arg("-p")
                .arg(&prof)
                .arg(program)
                .args(args)
                .current_dir(&workspace);
            cmd
        };

        let allowed = bounded_command_output(run("/bin/cat", &[visible.to_str().unwrap()])).await;
        assert!(
            allowed.status.success(),
            "workspace read must remain available: {allowed:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&allowed.stdout),
            "workspace-visible"
        );

        let denied = bounded_command_output(run("/bin/cat", &[secret.to_str().unwrap()])).await;
        assert!(
            !denied.status.success(),
            "direct secret read must be denied"
        );
        assert!(!String::from_utf8_lossy(&denied.stdout).contains("must-not-be-readable"));

        let via_link = bounded_command_output(run("/bin/cat", &["secret-link"])).await;
        assert!(
            !via_link.status.success(),
            "a workspace symlink must not bypass the secret deny"
        );
        assert!(!String::from_utf8_lossy(&via_link.stdout).contains("must-not-be-readable"));

        let keychain = bounded_command_output(run("/usr/bin/security", &["list-keychains"])).await;
        assert!(
            !keychain.status.success(),
            "Keychain IPC must be denied, not merely its files"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
