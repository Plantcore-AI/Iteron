use super::*;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt as _;

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
                "iteron-bwrap-{label}-{}-{nonce:x}",
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
    assert!(
        args.iter().any(|argument| argument == "--new-session"),
        "bounded one-shot children must not inherit the caller's controlling session"
    );
    assert!(
        !args
            .windows(3)
            .any(|window| window == ["--ro-bind", "/dev/null", "/dev/tty"]),
        "the tty mask is the persistent-mode substitute for a new session"
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
        BWRAP_PROBE_RUN_TIMEOUT,
        "the active probe phase has one fixed wall-clock ceiling"
    );
    assert_eq!(
        BWRAP_PROBE_POLL * u32::try_from(BWRAP_PROBE_REAP_POLLS).unwrap(),
        BWRAP_PROBE_REAP_TIMEOUT,
        "probe cleanup has one fixed wall-clock ceiling"
    );
    assert_eq!(
        BWRAP_PROBE_RUN_TIMEOUT + BWRAP_PROBE_REAP_TIMEOUT,
        BWRAP_PROBE_TIMEOUT,
        "probe plus cleanup has one aggregate wall-clock ceiling"
    );
}

#[test]
fn descriptor_workspace_source_is_distinct_from_namespace_destination() {
    let conf = Confinement::egress_off(PathBuf::from("/work/repo"));
    let args = bwrap_args_with_workspace_fd(&conf, "rust-analyzer", 10);
    assert!(
        args.windows(3)
            .any(|window| { window == ["--bind-fd", "10", "/work/repo"] })
    );
    assert_eq!(
        &args[args.len() - 3..],
        [crate::confined_shell(), "-c", "rust-analyzer"]
    );
    assert!(
        !args.iter().any(|argument| argument == "--new-session"),
        "persistent children must remain in the outer cleanup group during setup"
    );
    assert_persistent_tty_mask(&args);
}

#[test]
fn path_backed_persistent_args_inherit_cleanup_group_and_mask_tty() {
    let conf = Confinement::egress_off(PathBuf::from("/work/repo"));
    let args = bwrap_args_for_persistent(&conf, "rust-analyzer");
    assert!(
        args.windows(3)
            .any(|window| window == ["--bind", "/work/repo", "/work/repo"])
    );
    assert!(
        !args.iter().any(|argument| argument == "--new-session"),
        "persistent children must remain reachable by the outer cleanup group during setup"
    );
    assert_persistent_tty_mask(&args);
}

fn assert_persistent_tty_mask(args: &[String]) {
    let dev_position = args
        .windows(2)
        .position(|window| window == ["--dev", "/dev"])
        .unwrap();
    let mask_position = args
        .windows(3)
        .position(|window| window == ["--ro-bind", "/dev/null", "/dev/tty"])
        .expect("persistent children must not be able to reopen the host controlling terminal");
    let remount_position = args
        .windows(2)
        .position(|window| window == ["--remount-ro", "/"])
        .unwrap();
    assert!(
        dev_position < mask_position && mask_position < remount_position,
        "the tty mask must overlay the private device mount before the namespace root is sealed"
    );
}

#[test]
fn capability_probe_requires_native_descriptor_binding() {
    let args = bwrap_probe_args(11);
    assert!(
        args.windows(3)
            .any(|window| window == ["--bind-fd", "11", "/tmp/iteron-bwrap-fd-probe"]),
        "an older bwrap without --bind-fd must fail the executable capability probe"
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
    let fingerprint = test_fingerprint(1);
    let refused = ProbeOutcome {
        binary: binary.clone(),
        fingerprint,
        usable: false,
        at: std::time::Instant::now(),
    };
    assert_eq!(
        cached_probe(Some(&refused), &binary, fingerprint, refused.at),
        Some(false),
        "a fresh refusal must answer from cache instead of re-probing"
    );
    assert_eq!(
        cached_probe(
            Some(&refused),
            &binary,
            fingerprint,
            refused.at + BWRAP_PROBE_NEGATIVE_TTL - std::time::Duration::from_millis(1),
        ),
        Some(false),
    );
    assert_eq!(
        cached_probe(
            Some(&refused),
            &binary,
            fingerprint,
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
    let fingerprint = test_fingerprint(1);
    let usable = ProbeOutcome {
        binary: binary.clone(),
        fingerprint,
        usable: true,
        at: std::time::Instant::now(),
    };
    assert_eq!(
        cached_probe(
            Some(&usable),
            &binary,
            fingerprint,
            usable.at + BWRAP_PROBE_POSITIVE_TTL - std::time::Duration::from_millis(1),
        ),
        Some(true),
        "a recent fingerprint-matched capability proof is reusable"
    );
    assert_eq!(
        cached_probe(
            Some(&usable),
            &binary,
            fingerprint,
            usable.at + BWRAP_PROBE_POSITIVE_TTL,
        ),
        None,
        "host namespace policy can change without replacing the executable"
    );
    assert_eq!(
        cached_probe(
            Some(&usable),
            Path::new("/usr/local/bin/bwrap"),
            fingerprint,
            usable.at,
        ),
        None,
        "a different executable is a different trust decision"
    );
    assert_eq!(
        cached_probe(Some(&usable), &binary, test_fingerprint(2), usable.at),
        None,
        "an in-place executable replacement invalidates a successful probe"
    );
    assert_eq!(cached_probe(None, &binary, fingerprint, usable.at), None);
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
        .join(format!(
            "iteron-bwrap-args-{}-{nonce:x}",
            std::process::id()
        ));
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
            "iteron-bwrap-symlink-{}-{nonce:x}",
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
async fn linux_live_descriptor_mount_survives_path_replacement_and_closes_the_bind_fd() {
    let fixture = LiveFixture::new("descriptor-rebind");
    std::fs::write(fixture.workspace.join("marker"), "retained-capability").unwrap();
    let workspace_fd = std::fs::File::open(&fixture.workspace).unwrap();
    let detached = fixture.root.join("detached-workspace");
    std::fs::rename(&fixture.workspace, &detached).unwrap();
    std::fs::create_dir(&fixture.workspace).unwrap();
    std::fs::write(fixture.workspace.join("marker"), "replacement-path").unwrap();

    let mut confinement = Confinement::egress_off(&fixture.workspace);
    confinement.timeout_secs = LIVE_TEST_TIMEOUT_SECS;
    let mut process = match crate::spawn_confined_process_from_workspace(
        "cat marker; for fd in /proc/self/fd/[1-9][0-9]*; do [ ! -e \"$fd\" ] || exit 91; done",
        &confinement,
        &workspace_fd,
    )
    .await
    {
        Ok(process) => process,
        Err(error @ SandboxError::Unsupported) => {
            record_typed_refusal(error);
            return;
        }
        Err(error) => panic!("descriptor-bound spawn failed: {error}"),
    };
    drop(process.take_stdin());
    let mut stdout = process.take_stdout().unwrap();
    let mut stderr = process.take_stderr().unwrap();
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let (outcome, stdout_result, stderr_result) =
        tokio::time::timeout(Duration::from_secs(LIVE_TEST_TIMEOUT_SECS), async {
            tokio::join!(
                process.wait(),
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors)
            )
        })
        .await
        .expect("descriptor-bound process exceeded its live-test budget");
    assert!(
        outcome.unwrap().success(),
        "stderr={}",
        String::from_utf8_lossy(&errors)
    );
    stdout_result.unwrap();
    stderr_result.unwrap();
    assert_eq!(output, b"retained-capability");
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("marker")).unwrap(),
        "replacement-path"
    );
}

#[cfg(target_os = "linux")]
fn read_bounded_proc_record(path: &str) -> std::io::Result<String> {
    const MAX_PROC_RECORD_BYTES: u64 = 16 * 1024;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_PROC_RECORD_BYTES as usize + 1);
    let mut limited = std::io::Read::take(file, MAX_PROC_RECORD_BYTES + 1);
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() > MAX_PROC_RECORD_BYTES as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proc record exceeded the live-test byte ceiling",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(target_os = "linux")]
fn bounded_host_descendants(root: u32) -> Vec<u32> {
    const MAX_DESCENDANTS: usize = 64;
    let mut pending = vec![root];
    let mut seen = std::collections::BTreeSet::from([root]);
    let mut descendants = Vec::new();
    while let Some(parent) = pending.pop() {
        let children_path = format!("/proc/{parent}/task/{parent}/children");
        let children = match read_bounded_proc_record(&children_path) {
            Ok(children) => children,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("cannot inspect {children_path}: {error}"),
        };
        for child in children.split_whitespace() {
            let child = child.parse::<u32>().unwrap();
            if seen.insert(child) {
                descendants.push(child);
                assert!(
                    descendants.len() <= MAX_DESCENDANTS,
                    "persistent setup exceeded the bounded process-tree inventory"
                );
                pending.push(child);
            }
        }
    }
    descendants
}

#[cfg(target_os = "linux")]
fn host_process_group(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/stat");
    let stat = match read_bounded_proc_record(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("cannot inspect host process {pid}: {error}"),
    };
    let (_, fields) = stat.rsplit_once(") ").expect("malformed /proc stat record");
    let mut fields = fields.split_whitespace();
    let _state = fields.next().expect("missing process state");
    let _parent = fields.next().expect("missing parent pid");
    Some(
        fields
            .next()
            .expect("missing process group")
            .parse()
            .expect("non-numeric process group"),
    )
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_live_path_persistent_setup_stays_reachable_and_masks_the_host_tty() {
    let fixture = LiveFixture::new("path-persistent-session");
    let mut confinement = Confinement::egress_off(&fixture.workspace);
    confinement.timeout_secs = LIVE_TEST_TIMEOUT_SECS;
    let mut process = match crate::spawn_confined_process(
        "[ /dev/tty -ef /dev/null ] || exit 91; printf ready; sleep 30",
        &confinement,
    )
    .await
    {
        Ok(process) => process,
        Err(error @ SandboxError::Unsupported) => {
            record_typed_refusal(error);
            return;
        }
        Err(error) => panic!("path-backed persistent spawn failed: {error}"),
    };
    let direct_pid = process.direct_pid().expect("spawned child lost its pid");
    drop(process.take_stdin());
    let mut stdout = process.take_stdout().unwrap();
    let mut ready = [0_u8; 5];
    tokio::time::timeout(
        Duration::from_secs(LIVE_TEST_TIMEOUT_SECS),
        stdout.read_exact(&mut ready),
    )
    .await
    .expect("server never reached the post-admission marker")
    .expect("server exited before proving its tty mask");
    assert_eq!(&ready, b"ready");

    assert_eq!(host_process_group(direct_pid), Some(direct_pid));
    let descendants = bounded_host_descendants(direct_pid);
    assert!(
        !descendants.is_empty(),
        "a live bubblewrap setup must expose at least one host descendant"
    );
    for descendant in descendants {
        if let Some(group) = host_process_group(descendant) {
            assert_eq!(
                group, direct_pid,
                "persistent setup descendant {descendant} escaped the owned cleanup group"
            );
        }
    }
    assert!(process.terminate_and_reap().await.is_some());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_live_forced_cleanup_prevents_a_setsid_descendant_late_write() {
    let fixture = LiveFixture::new("persistent-descendant");
    let workspace_fd = std::fs::File::open(&fixture.workspace).unwrap();
    let mut confinement = Confinement::egress_off(&fixture.workspace);
    confinement.timeout_secs = LIVE_TEST_TIMEOUT_SECS;
    let mut process = match crate::spawn_confined_process_from_workspace(
        "setsid sh -c 'sleep 2; printf survived > late-write' & printf ready; sleep 30",
        &confinement,
        &workspace_fd,
    )
    .await
    {
        Ok(process) => process,
        Err(error @ SandboxError::Unsupported) => {
            record_typed_refusal(error);
            return;
        }
        Err(error) => panic!("persistent descendant spawn failed: {error}"),
    };
    drop(process.take_stdin());
    let mut stdout = process.take_stdout().unwrap();
    let mut ready = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stdout.read_exact(&mut ready))
        .await
        .expect("server never reached the post-descendant marker")
        .unwrap();
    assert_eq!(&ready, b"ready");
    assert!(process.terminate_and_reap().await.is_some());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !fixture.workspace.join("late-write").exists(),
        "a detached descendant survived the owned process cleanup"
    );
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
        .push("ITERON_SANDBOX_ROUTE".into());
    let fake_home = fixture.fake_home.to_str().unwrap();
    let outside_write = fixture.outside_write.to_str().unwrap();
    let output = sandbox
        .run_with_synthetic_parent_env(
            "printf workspace-write-allowed > inside-write || exit 91; \
             if printf escaped > \"$ITERON_TEST_OUTSIDE_WRITE\"; then echo outside-write-open; exit 97; else echo outside-write-blocked; fi; \
             if cat \"$HOME/.ssh/id_fixture\" 2>/dev/null; then echo home-secret-open; exit 98; else echo home-secret-blocked; fi; \
             if ! cat \"$HOME/.cargo/registry/cache_fixture\"; then echo toolchain-cache-blocked; exit 96; else echo toolchain-cache-readable; fi; \
             if [ -n \"${ITERON_SANDBOX_ROUTE+x}\" ]; then echo exact-env-open; exit 99; else echo exact-env-cleared; fi",
            &confinement,
            &[
                ("HOME", fake_home),
                ("ITERON_TEST_OUTSIDE_WRITE", outside_write),
                ("ITERON_SANDBOX_ROUTE", "synthetic-exact-must-not-leak"),
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
