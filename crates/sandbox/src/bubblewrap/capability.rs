use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const BWRAP_CANDIDATES: &[&str] =
    &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
pub(super) const BWRAP_PROBE_RUN_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const BWRAP_PROBE_REAP_TIMEOUT: Duration = Duration::from_secs(1);
pub(super) const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(6);
pub(super) const BWRAP_PROBE_POLL: Duration = Duration::from_millis(10);
pub(super) const BWRAP_PROBE_MAX_POLLS: usize = 500;
pub(super) const BWRAP_PROBE_REAP_POLLS: usize = 100;
pub(super) const BWRAP_PROBE_POSITIVE_TTL: Duration = Duration::from_secs(5 * 60);
pub(super) const BWRAP_PROBE_NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// Lowest descriptor number a workspace handed to a child may occupy. Kept clear of the standard
/// streams and of the few descriptors the spawn path itself moves around.
pub(crate) const CHILD_INHERITED_FD_FLOOR: libc::c_int = 10;
static PROBE_CACHE: Mutex<Option<ProbeOutcome>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BinaryFingerprint {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Clone)]
pub(super) struct ProbeOutcome {
    pub(super) binary: PathBuf,
    pub(super) fingerprint: BinaryFingerprint,
    pub(super) usable: bool,
    pub(super) at: Instant,
}

pub(super) fn cached_probe(
    entry: Option<&ProbeOutcome>,
    binary: &Path,
    fingerprint: BinaryFingerprint,
    now: Instant,
) -> Option<bool> {
    let entry = entry?;
    if entry.binary != binary || entry.fingerprint != fingerprint {
        return None;
    }
    let ttl = if entry.usable {
        // Host policy (AppArmor, user-namespace controls) can revoke capability without replacing
        // the binary, so even a fingerprint-matched success receives a bounded lifetime.
        BWRAP_PROBE_POSITIVE_TTL
    } else {
        BWRAP_PROBE_NEGATIVE_TTL
    };
    (now.duration_since(entry.at) < ttl).then_some(entry.usable)
}

#[cfg(test)]
pub(super) const fn test_fingerprint(serial: u64) -> BinaryFingerprint {
    BinaryFingerprint {
        device: serial,
        inode: serial,
        size: serial,
        modified_seconds: serial as i64,
        modified_nanoseconds: 0,
        changed_seconds: serial as i64,
        changed_nanoseconds: 0,
    }
}

// `bwrap --version` does not prove that AppArmor/user-namespace policy permits the operations
// carrying the confinement contract. The probe also requires native descriptor binding.
pub(super) const BWRAP_PROBE_ARGS: &[&str] = &[
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
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-net",
    "/bin/true",
];

#[cfg(target_os = "linux")]
fn trusted_bwrap() -> Option<(PathBuf, BinaryFingerprint)> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    BWRAP_CANDIDATES.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return None;
        }
        let fingerprint = BinaryFingerprint {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        };
        Some((path.to_path_buf(), fingerprint))
    })
}

/// Resolve and capability-probe the trusted binary. The mutex is deliberately retained during a
/// cold probe: callers execute this on Tokio's blocking pool, and one bounded single-flight probe
/// is cheaper and safer than N concurrent namespace launches.
#[cfg(target_os = "linux")]
pub(super) fn usable_bwrap() -> Option<PathBuf> {
    let (binary, fingerprint) = trusted_bwrap()?;
    let mut cache = PROBE_CACHE.lock().ok()?;
    if let Some(decision) = cached_probe(cache.as_ref(), &binary, fingerprint, Instant::now()) {
        return decision.then_some(binary);
    }
    let usable = probe_binary(&binary);
    *cache = Some(ProbeOutcome {
        binary: binary.clone(),
        fingerprint,
        usable,
        at: Instant::now(),
    });
    usable.then_some(binary)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn usable_bwrap() -> Option<PathBuf> {
    None
}

#[cfg(target_os = "linux")]
fn probe_binary(binary: &Path) -> bool {
    use std::fs::File;
    use std::os::fd::AsRawFd as _;

    let Ok(workspace) = File::open("/tmp") else {
        return false;
    };
    let Ok(inherited) = duplicate_for_child(&workspace, CHILD_INHERITED_FD_FLOOR) else {
        return false;
    };
    let descriptor = inherited.as_raw_fd();
    let mut command = std::process::Command::new(binary);
    command
        .args(bwrap_probe_args(descriptor))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    inherit_fd_in_std_command(&mut command, descriptor);
    let child = command.spawn();
    drop(inherited);
    let Ok(mut child) = child else {
        return false;
    };
    let started = Instant::now();
    let run_deadline = started + BWRAP_PROBE_RUN_TIMEOUT;
    let total_deadline = run_deadline + BWRAP_PROBE_REAP_TIMEOUT;
    debug_assert_eq!(total_deadline, started + BWRAP_PROBE_TIMEOUT);
    for _ in 0..BWRAP_PROBE_MAX_POLLS {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < run_deadline => std::thread::sleep(BWRAP_PROBE_POLL),
            Ok(None) | Err(_) => break,
        }
    }
    let _ = child.kill();
    for _ in 0..BWRAP_PROBE_REAP_POLLS {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < total_deadline => std::thread::sleep(BWRAP_PROBE_POLL),
            Ok(None) | Err(_) => break,
        }
    }
    false
}

#[cfg(target_os = "linux")]
pub(crate) fn duplicate_for_child(
    file: &std::fs::File,
    minimum: libc::c_int,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    // SAFETY: `file` owns a live descriptor; a successful fcntl returns one newly owned fd.
    let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful F_DUPFD_CLOEXEC result is newly owned here.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn inherit_fd_in_std_command(command: &mut std::process::Command, descriptor: libc::c_int) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the child-only closure calls async-signal-safe fcntl before exec.
    unsafe {
        command.pre_exec(move || clear_cloexec(descriptor));
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn inherit_fd_in_tokio_command(
    command: &mut tokio::process::Command,
    descriptor: libc::c_int,
) {
    // SAFETY: identical child-only boundary to the std Command helper.
    unsafe {
        command.pre_exec(move || clear_cloexec(descriptor));
    }
}

#[cfg(target_os = "linux")]
fn clear_cloexec(descriptor: libc::c_int) -> std::io::Result<()> {
    // SAFETY: fcntl addresses the inherited exact descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `flags` came from F_GETFD for this live descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn bwrap_probe_args(workspace_fd: libc::c_int) -> Vec<String> {
    let mut arguments = BWRAP_PROBE_ARGS[..BWRAP_PROBE_ARGS.len() - 1]
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    arguments.extend([
        "--dir".to_owned(),
        "/tmp/iteron-bwrap-fd-probe".to_owned(),
        "--bind-fd".to_owned(),
        workspace_fd.to_string(),
        "/tmp/iteron-bwrap-fd-probe".to_owned(),
        BWRAP_PROBE_ARGS[BWRAP_PROBE_ARGS.len() - 1].to_owned(),
    ]);
    arguments
}
