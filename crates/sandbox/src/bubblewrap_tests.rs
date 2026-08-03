use super::*;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
const LIVE_TEST_TIMEOUT_SECS: u64 = 10;

#[cfg(target_os = "linux")]
struct LiveFixture {
    root: PathBuf,
    workspace: PathBuf,
    fake_home: PathBuf,
    outside_write: PathBuf,
}

#[cfg(target_os = "linux")]
impl LiveFixture {
    fn new(label: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Keep the host fixture outside bwrap's deliberately writable private `/tmp`; otherwise
        // an outside path could succeed only inside the disposable tmpfs and fail to prove the
        // write syscall itself was denied.
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "core-bwrap-{label}-{}-{nonce:x}",
                std::process::id()
            ));
        let workspace = root.join("workspace");
        let fake_home = root.join("synthetic-home");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(fake_home.join(".ssh")).unwrap();
        std::fs::create_dir_all(fake_home.join(".cargo/registry")).unwrap();
        std::fs::write(
            fake_home.join(".ssh/id_fixture"),
            "synthetic-secret-must-not-leak",
        )
        .unwrap();
        std::fs::write(
            fake_home.join(".cargo/registry/cache_fixture"),
            "synthetic-toolchain-cache-readable",
        )
        .unwrap();
        let outside_write = root.join("outside-write");
        std::fs::write(&outside_write, "host-outside-preserved").unwrap();
        Self {
            root,
            workspace,
            fake_home,
            outside_write,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn args_unshare_net_by_default_and_make_only_workspace_writable() {
    let conf = Confinement::egress_off(PathBuf::from("/work/repo"));
    let args = bwrap_args(&conf, "make test");
    assert!(
        args.iter().any(|arg| arg == "--unshare-net"),
        "network must be unshared by default"
    );
    let joined = args.join(" ");
    assert!(
        joined.contains("--bind /work/repo /work/repo"),
        "workspace writable"
    );
    assert!(joined.contains("--ro-bind /usr /usr"), "system read-only");
    let tmpfs_position = args.iter().position(|arg| arg == "--tmpfs").unwrap();
    let workspace_position = args
        .windows(3)
        .position(|window| window == ["--bind", "/work/repo", "/work/repo"])
        .unwrap();
    assert!(
        tmpfs_position < workspace_position,
        "a workspace below host /tmp must be mounted after the private tmpfs"
    );
    assert_eq!(
        &args[args.len() - 3..],
        [crate::confined_shell(), "-c", "make test"]
    );
    assert!(
        BWRAP_CANDIDATES
            .iter()
            .all(|candidate| Path::new(candidate).is_absolute())
    );
    assert!(
        BWRAP_PROBE_ARGS
            .windows(3)
            .any(|probe| probe == ["--ro-bind", "/", "/"]),
        "the capability probe must not grant host writes"
    );
    assert!(
        BWRAP_PROBE_ARGS.contains(&"--unshare-net"),
        "the capability probe must exercise the load-bearing network namespace"
    );
    assert_eq!(
        BWRAP_PROBE_POLL * u32::try_from(BWRAP_PROBE_MAX_POLLS).unwrap(),
        BWRAP_PROBE_TIMEOUT,
        "the synchronous capability probe has one fixed wall-clock ceiling"
    );
}

#[test]
fn egress_escalation_shares_the_network() {
    let mut conf = Confinement::egress_off(PathBuf::from("/work/repo"));
    conf.allow_egress = true;
    let args = bwrap_args(&conf, "curl x");
    assert!(
        !args.iter().any(|arg| arg == "--unshare-net"),
        "escalated egress must not unshare net"
    );
}

#[test]
fn a_refused_probe_is_cached_for_a_bounded_ttl_then_retried() {
    // Before this, `usable_bwrap` explicitly refused to cache a failure, so a host with restricted
    // user namespaces re-ran a process probe with a 5s ceiling on EVERY bash call.
    let binary = PathBuf::from("/usr/bin/bwrap");
    let refused = ProbeOutcome {
        binary: binary.clone(),
        usable: false,
        at: std::time::Instant::now(),
    };
    assert_eq!(
        cached_probe(Some(&refused), &binary, refused.at),
        Some(false),
        "a fresh refusal must answer from cache instead of re-probing"
    );
    assert_eq!(
        cached_probe(
            Some(&refused),
            &binary,
            refused.at + BWRAP_PROBE_NEGATIVE_TTL - std::time::Duration::from_millis(1),
        ),
        Some(false),
    );
    assert_eq!(
        cached_probe(
            Some(&refused),
            &binary,
            refused.at + BWRAP_PROBE_NEGATIVE_TTL,
        ),
        None,
        "the refusal must expire so an operator who fixes the host is picked up"
    );
    assert!(
        BWRAP_PROBE_NEGATIVE_TTL >= BWRAP_PROBE_TIMEOUT,
        "a TTL below the probe's own ceiling would not bound the cost at all"
    );
}

#[test]
fn a_successful_probe_is_kept_and_a_different_executable_is_not() {
    let binary = PathBuf::from("/usr/bin/bwrap");
    let usable = ProbeOutcome {
        binary: binary.clone(),
        usable: true,
        at: std::time::Instant::now(),
    };
    assert_eq!(
        cached_probe(
            Some(&usable),
            &binary,
            usable.at + BWRAP_PROBE_NEGATIVE_TTL * 1000,
        ),
        Some(true),
        "a proven namespace capability does not need re-proving"
    );
    assert_eq!(
        cached_probe(Some(&usable), Path::new("/usr/local/bin/bwrap"), usable.at),
        None,
        "a different executable is a different trust decision"
    );
    assert_eq!(cached_probe(None, &binary, usable.at), None);
}

#[tokio::test]
async fn resolving_the_backend_does_not_park_the_async_worker() {
    // `usable_bwrap` spawns a child and `std::thread::sleep`s while polling it. Called inline from
    // this single-threaded runtime it would hold the only worker for the whole probe, so nothing
    // else — timers, streaming, cancellation — could run. It must go through the blocking pool.
    let ticked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = ticked.clone();
    let ticker = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let resolved = Bubblewrap::usable_bwrap_off_worker().await;
    ticker.await.unwrap();
    assert!(
        ticked.load(std::sync::atomic::Ordering::SeqCst),
        "a concurrent task must still be scheduled while the backend is probed"
    );
    assert_eq!(resolved.is_some(), Bubblewrap::available());
}

#[test]
fn toolchain_mounts_are_narrow_read_only_and_exclude_credentials() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!("core-bwrap-args-{}-{nonce:x}", std::process::id()));
    let home = root.join("home");
    std::fs::create_dir_all(home.join(".cargo/registry")).unwrap();
    std::fs::create_dir_all(home.join(".npm/_cacache")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join(".aws")).unwrap();
    std::fs::create_dir_all(home.join(".config/core")).unwrap();
    std::fs::write(home.join(".cargo/credentials.toml"), "secret").unwrap();
    std::fs::write(home.join(".npmrc"), "secret").unwrap();

    let conf = Confinement::egress_off(root.join("workspace"));
    let args = bwrap_args_with_home(&conf, "true", Some(&home));
    let canonical_home = std::fs::canonicalize(&home).unwrap();
    let joined = args.join("\n");

    for relative in [".cargo/registry", ".npm/_cacache"] {
        let source = canonical_home.join(relative).display().to_string();
        let destination = home.join(relative).display().to_string();
        assert!(
            args.windows(3).any(|window| {
                window[0] == "--ro-bind" && window[1] == source && window[2] == destination
            }),
            "missing narrow read-only mount for {relative}: {args:?}"
        );
    }
    let home_dir_position = args
        .windows(2)
        .position(|window| window[0] == "--dir" && window[1] == home.display().to_string())
        .unwrap();
    let workspace_position = args
        .windows(3)
        .position(|window| {
            window[0] == "--bind" && window[2] == conf.workspace.display().to_string()
        })
        .unwrap();
    let first_cache_position = args
        .windows(3)
        .position(|window| {
            window[0] == "--ro-bind"
                && window[2] == home.join(".cargo/registry").display().to_string()
        })
        .unwrap();
    assert!(home_dir_position < workspace_position);
    assert!(workspace_position < first_cache_position);
    assert!(
        !args
            .windows(3)
            .any(|window| { window[0] == "--ro-bind" && window[2] == home.display().to_string() }),
        "HOME itself must never be host-bound"
    );
    for forbidden in [
        ".ssh",
        ".aws",
        ".config",
        ".cargo/credentials",
        ".cargo/credentials.toml",
        ".npmrc",
        ".netrc",
    ] {
        assert!(
            !joined.contains(&home.join(forbidden).display().to_string()),
            "credential path leaked into bwrap arguments: {forbidden}"
        );
    }

    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn toolchain_mount_ignores_an_allowlisted_symlink_that_escapes_home() {
    use std::os::unix::fs::symlink;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "core-bwrap-symlink-{}-{nonce:x}",
            std::process::id()
        ));
    let home = root.join("home");
    let outside = root.join("outside");
    std::fs::create_dir_all(home.join(".cargo")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("credential"), "must-stay-hidden").unwrap();
    symlink(&outside, home.join(".cargo/registry")).unwrap();

    let conf = Confinement::egress_off(root.join("workspace"));
    let args = bwrap_args_with_home(&conf, "true", Some(&home));
    let joined = args.join("\n");
    assert!(!joined.contains(&outside.display().to_string()));
    assert!(!joined.contains("must-stay-hidden"));

    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(target_os = "linux")]
enum LiveBackend {
    Ready(Bubblewrap, Confinement),
    Refused(SandboxError),
}

#[cfg(target_os = "linux")]
async fn live_backend(workspace: &Path) -> LiveBackend {
    let sandbox = Bubblewrap::new();
    let mut confinement = Confinement::egress_off(workspace);
    confinement.timeout_secs = LIVE_TEST_TIMEOUT_SECS;
    match sandbox.run("printf live-backend-ready", &confinement).await {
        Ok(output) => {
            assert_eq!(output.exit_code, 0, "live bwrap probe failed: {output:?}");
            assert!(!output.timed_out);
            assert!(output.stdout.contains("live-backend-ready"));
            LiveBackend::Ready(sandbox, confinement)
        }
        Err(error @ SandboxError::Unsupported) => LiveBackend::Refused(error),
        Err(error) => panic!("live bwrap probe returned a non-refusal error: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn record_typed_refusal(error: SandboxError) {
    assert!(matches!(&error, SandboxError::Unsupported));
    assert_ne!(
        std::env::var("GITHUB_ACTIONS").ok().as_deref(),
        Some("true"),
        "GitHub's Linux job installs and authorizes bwrap, so live confinement must run there"
    );
    eprintln!("typed live-test refusal (not an unconfined fallback): {error}");
}

// Live confinement test: on Linux CI the configured bwrap boundary is mandatory. A local Linux
// host without that capability exercises and records the typed Unsupported refusal instead of
// silently returning before any assertion.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn d4_13_d5_14_linux_live_network_is_blocked_when_bwrap_present() {
    let fixture = LiveFixture::new("network");
    let (sandbox, confinement) = match live_backend(&fixture.workspace).await {
        LiveBackend::Ready(sandbox, confinement) => (sandbox, confinement),
        LiveBackend::Refused(error) => {
            record_typed_refusal(error);
            return;
        }
    };

    // First establish that this exact local endpoint accepts a bounded host connection. The same
    // connect must then fail inside the empty network namespace; an unavailable public endpoint
    // cannot make this assertion pass accidentally.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let host_probe = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1))
        .expect("the host-side loopback precondition must be reachable");
    drop(host_probe);
    let network = sandbox
        .run(
            &format!(
                "if bash -c 'exec 3<>/dev/tcp/127.0.0.1/{}' 2>/dev/null; then echo network-open; exit 97; else echo network-blocked; fi",
                address.port()
            ),
            &confinement,
        )
        .await
        .unwrap();
    assert_eq!(
        network.exit_code, 0,
        "loopback unexpectedly reachable from bwrap: {network:?}"
    );
    assert!(network.stdout.contains("network-blocked"));
    assert!(!network.stdout.contains("network-open"));

    let mut flood_confinement = Confinement::egress_off(&fixture.workspace);
    flood_confinement.max_output_bytes = 4 * 1024;
    flood_confinement.timeout_secs = 5;
    let flood = sandbox
        .run(
            "(yes O | head -c 1048576) & (yes E | head -c 1048576 >&2) & wait",
            &flood_confinement,
        )
        .await
        .unwrap();
    assert!(!flood.timed_out);
    assert!(flood.stdout_truncated && flood.stderr_truncated);
}

#[cfg(target_os = "linux")]
#[tokio::test]
// KNOWN FAILING BOUNDARY - the assertion is correct, the confinement is not finished.
//
// This probe writes to a path outside the bound workspace and requires the write to be refused.
// On a real Linux runner bwrap starts cleanly (`live_backend` returns Ready) and the write
// SUCCEEDS, so the filesystem boundary this test describes is not actually enforced yet.
//
// It arrived with the un-gated `close-all-gaps progress checkpoint (M0-M2 substrate)` commit while
// both of its gaps, D4-13 and D5-14, were still `todo` and had never been verified. It is
// `cfg(linux)`, so it never compiles on macOS and no local run could have caught it; the first
// execution anywhere was CI on the pull request that promoted this line to main.
//
// Do NOT delete this test and do NOT weaken its assertions.
//
// The gap is closed: `bwrap_args` now ends its mount plan with `--remount-ro /`. bwrap creates
// the parent directories of every mount point on its root tmpfs, so binding the workspace was
// materialising a writable directory beside it, and a write to a sibling path succeeded into
// that disposable tmpfs. Nothing escaped to the host, but the syscall was not denied, which is
// not the same thing and is not what this probe asserts. Every assertion below is unchanged.
async fn d4_13_d5_14_linux_live_enforces_writes_home_secret_and_exact_env_name() {
    let fixture = LiveFixture::new("filesystem-env");
    let (sandbox, mut confinement) = match live_backend(&fixture.workspace).await {
        LiveBackend::Ready(sandbox, confinement) => (sandbox, confinement),
        LiveBackend::Refused(error) => {
            record_typed_refusal(error);
            return;
        }
    };
    confinement
        .sensitive_env_names
        .push("CORE_SANDBOX_ROUTE".into());
    let fake_home = fixture.fake_home.to_str().unwrap();
    let outside_write = fixture.outside_write.to_str().unwrap();
    let output = sandbox
        .run_with_synthetic_parent_env(
            "printf workspace-write-allowed > inside-write || exit 91; \
             if printf escaped > \"$CORE_TEST_OUTSIDE_WRITE\"; then echo outside-write-open; exit 97; else echo outside-write-blocked; fi; \
             if cat \"$HOME/.ssh/id_fixture\" 2>/dev/null; then echo home-secret-open; exit 98; else echo home-secret-blocked; fi; \
             if ! cat \"$HOME/.cargo/registry/cache_fixture\"; then echo toolchain-cache-blocked; exit 96; else echo toolchain-cache-readable; fi; \
             if [ -n \"${CORE_SANDBOX_ROUTE+x}\" ]; then echo exact-env-open; exit 99; else echo exact-env-cleared; fi",
            &confinement,
            &[
                ("HOME", fake_home),
                ("CORE_TEST_OUTSIDE_WRITE", outside_write),
                ("CORE_SANDBOX_ROUTE", "synthetic-exact-must-not-leak"),
            ],
        )
        .await
        .unwrap();

    assert_eq!(output.exit_code, 0, "boundary probe failed: {output:?}");
    assert!(!output.timed_out);
    assert!(output.stdout.contains("outside-write-blocked"));
    assert!(output.stdout.contains("home-secret-blocked"));
    assert!(output.stdout.contains("synthetic-toolchain-cache-readable"));
    assert!(output.stdout.contains("toolchain-cache-readable"));
    assert!(output.stdout.contains("exact-env-cleared"));
    assert!(!output.stdout.contains("outside-write-open"));
    assert!(!output.stdout.contains("home-secret-open"));
    assert!(!output.stdout.contains("toolchain-cache-blocked"));
    assert!(!output.stdout.contains("exact-env-open"));
    assert!(!output.stdout.contains("synthetic-secret-must-not-leak"));
    assert!(!output.stderr.contains("synthetic-secret-must-not-leak"));
    assert!(!output.stdout.contains("synthetic-exact-must-not-leak"));
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("inside-write")).unwrap(),
        "workspace-write-allowed"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.outside_write).unwrap(),
        "host-outside-preserved",
        "the confined command changed a host file outside its workspace"
    );
}
