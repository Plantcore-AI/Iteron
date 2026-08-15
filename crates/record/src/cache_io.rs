//! Crash-atomic writes for rebuildable session-cache projections.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_TEMP_ATTEMPTS: u64 = 16;
const SESSION_INDEX_LOCK_FILE: &str = ".sessions-index.lock";
const SESSION_INDEX_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_INDEX_LOCK_RETRY_DELAY: Duration = Duration::from_millis(5);
// One immediate attempt followed by at most 400 five-millisecond waits.
const MAX_SESSION_INDEX_LOCK_ATTEMPTS: usize = 401;
/// A session-index entry consists only of bounded identifiers, a platform path, and the compact
/// session projection. Keeping a separate outer cap means a corrupt cache cannot force an
/// unbounded allocation before JSON decoding. The cache is rebuildable, so an oversized line is
/// treated exactly like a torn one: callers discard the scan and replay authoritative rollouts.
pub(crate) const MAX_INDEX_LINE_BYTES: usize = 256 * 1024;
/// Per-run metadata carries the same bounded projection as one index line. A corrupt sidecar must
/// never make the cache fast path allocate in proportion to attacker-controlled file length.
pub(crate) const MAX_SESSION_META_BYTES: usize = MAX_INDEX_LINE_BYTES;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Result of a bounded physical-line scan. `complete == false` deliberately carries no prefix:
/// using an early prefix of an append-era index could select an older, still-parseable projection.
pub(crate) struct BoundedLineScan {
    pub(crate) lines: Vec<Vec<u8>>,
    pub(crate) complete: bool,
    pub(crate) lines_examined: usize,
}

impl BoundedLineScan {
    fn degraded(lines_examined: usize) -> Self {
        Self {
            lines: Vec::new(),
            complete: false,
            lines_examined,
        }
    }
}

/// Read no more than `max_lines + 1` physical lines and no more than
/// [`MAX_INDEX_LINE_BYTES`] for any one line. The extra line detects an over-limit append-era
/// index without scanning its remaining K historical writes. Missing files are an empty, complete
/// cache; I/O errors remain distinguishable so callers can degrade without mutating anything.
pub(crate) fn scan_index_lines(path: &Path, max_lines: usize) -> io::Result<BoundedLineScan> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(BoundedLineScan {
                lines: Vec::new(),
                complete: true,
                lines_examined: 0,
            });
        }
        Err(error) => return Err(error),
    };
    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut lines_examined = 0usize;

    loop {
        let mut bytes = Vec::new();
        let mut bounded = (&mut reader).take(
            (iteron_tunables::param_integer(
                "record.cache_io.max_index_line_bytes",
                MAX_INDEX_LINE_BYTES,
            ) + 1) as u64,
        );
        let consumed = bounded.read_until(b'\n', &mut bytes)?;
        if consumed == 0 {
            return Ok(BoundedLineScan {
                lines,
                complete: true,
                lines_examined,
            });
        }
        lines_examined = lines_examined.saturating_add(1);
        if consumed
            > iteron_tunables::param_integer(
                "record.cache_io.max_index_line_bytes",
                MAX_INDEX_LINE_BYTES,
            )
            || bytes.last() != Some(&b'\n')
        {
            return Ok(BoundedLineScan::degraded(lines_examined));
        }
        if lines.len() == max_lines {
            return Ok(BoundedLineScan::degraded(lines_examined));
        }
        bytes.pop();
        lines.push(bytes);
    }
}

/// Read one rebuildable cache object under an exact outer byte ceiling. Oversized and missing
/// sidecars are ordinary cache misses to callers; authoritative rollout replay remains available.
pub(crate) fn read_session_meta(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_SESSION_META_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SESSION_META_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session metadata exceeds the cache byte limit",
        ));
    }
    Ok(bytes)
}

/// Serialize read-modify-replace updates to `sessions.index` across Core processes.
///
/// The lock inode is deliberately stable: callers must never remove the lock file, because
/// replacing it while another process still holds the old inode would create two independent
/// lock domains. Waiting is capped by both elapsed time and an explicit attempt count so a
/// crashed or wedged peer degrades the rebuildable cache instead of stalling the runtime.
pub(crate) fn with_session_index_lock<T, F>(runs_dir: &Path, operation: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    with_session_index_lock_timeout(
        runs_dir,
        iteron_tunables::param_duration(
            "record.cache_io.session_index_lock_timeout",
            SESSION_INDEX_LOCK_TIMEOUT,
        ),
        operation,
    )
}

fn with_session_index_lock_timeout<T, F>(
    runs_dir: &Path,
    timeout: Duration,
    operation: F,
) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    crate::create_state_dir(runs_dir)?;
    let lock_path = runs_dir.join(SESSION_INDEX_LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    let started = Instant::now();

    for attempt in 0..iteron_tunables::param_integer(
        "record.cache_io.max_session_index_lock_attempts",
        MAX_SESSION_INDEX_LOCK_ATTEMPTS,
    ) {
        match file.try_lock() {
            Ok(()) => {
                let _lock = SessionIndexLock(file);
                return operation();
            }
            Err(TryLockError::WouldBlock) => {
                let elapsed = started.elapsed();
                if elapsed >= timeout
                    || attempt + 1
                        == iteron_tunables::param_integer(
                            "record.cache_io.max_session_index_lock_attempts",
                            MAX_SESSION_INDEX_LOCK_ATTEMPTS,
                        )
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "timed out waiting for the session-index lock at {}",
                            lock_path.display()
                        ),
                    ));
                }
                std::thread::sleep(
                    iteron_tunables::param_duration(
                        "record.cache_io.session_index_lock_retry_delay",
                        SESSION_INDEX_LOCK_RETRY_DELAY,
                    )
                    .min(timeout - elapsed),
                );
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }

    unreachable!("the bounded session-index lock loop always returns")
}

struct SessionIndexLock(File);

impl Drop for SessionIndexLock {
    fn drop(&mut self) {
        // Descriptor close is the final RAII fallback if this best-effort explicit unlock fails.
        let _ = self.0.unlock();
    }
}

pub(crate) fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_with(path, bytes, true, |_| Ok(()))
}

/// Crash-atomic private replacement. Permissions are applied to the fsynced temporary inode
/// before publication, eliminating both the public-mode rename window and the second open/fsync
/// cycle that callers previously paid after [`atomic_replace`].
pub(crate) fn atomic_replace_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_with(path, bytes, true, |temporary| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    })
}

/// [`atomic_replace`] for one member of a batch: the file's own bytes are still fsynced before the
/// rename, but the containing directory is not. The caller MUST call [`sync_dir`] once after the
/// batch, or a crash can leave the renames undurable. Rewriting N sidecars one directory sync at a
/// time is what made a full reindex 91% blocking fsync.
pub(crate) fn atomic_replace_deferring_dir_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_with(path, bytes, false, |_| Ok(()))
}

/// Make every rename performed in `dir` durable. The batch counterpart of the per-write directory
/// sync [`atomic_replace`] does inline.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    sync_directory(dir)
}

#[cfg(test)]
pub(crate) fn fail_before_rename(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_with(path, bytes, true, |_| {
        Err(io::Error::other("injected crash before rename"))
    })
}

fn atomic_replace_with<F>(
    path: &Path,
    bytes: &[u8],
    sync_parent: bool,
    before_rename: F,
) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    // Declare cleanup before the descriptor so Rust drops the open file first on every `?` path;
    // this also makes temp cleanup work on platforms that cannot unlink an open file.
    let mut cleanup = TempCleanup(None);
    let (mut file, temp_path) = create_temp(parent)?;
    cleanup.0 = Some(temp_path.clone());

    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    before_rename(&temp_path)?;
    drop(file);
    std::fs::rename(&temp_path, path)?;
    cleanup.0 = None;
    if sync_parent {
        sync_directory(parent)?;
    }
    Ok(())
}

fn create_temp(parent: &Path) -> io::Result<(File, PathBuf)> {
    let first = NEXT_TEMP.fetch_add(
        iteron_tunables::param_integer("record.cache_io.max_temp_attempts", MAX_TEMP_ATTEMPTS),
        Ordering::Relaxed,
    );
    let mut last_collision = None;
    for offset in
        0..iteron_tunables::param_integer("record.cache_io.max_temp_attempts", MAX_TEMP_ATTEMPTS)
    {
        let path = parent.join(format!(
            ".core-session-cache-{}-{}.tmp",
            std::process::id(),
            first.saturating_add(offset)
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "session cache temp-name attempts exhausted",
        )
    }))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

struct TempCleanup(Option<PathBuf>);

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "iteron-record-atomic-cache-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn d9_10_g2_failure_after_synced_temp_preserves_complete_old_projection() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("run.meta.json");
        let old = br#"{"version":"old","complete":true}"#;
        let new = br#"{"version":"new","complete":true}"#;
        atomic_replace(&target, old).unwrap();

        let error = fail_before_rename(&target, new).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read(&target).unwrap(), old);
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(parsed["complete"], true);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        atomic_replace(&target, new).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), new);
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(parsed["version"], "new");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_01_session_meta_read_accepts_exact_limit_and_rejects_one_more_byte() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("run.meta.json");
        let exact = vec![b'x'; MAX_SESSION_META_BYTES];
        std::fs::write(&target, &exact).unwrap();
        assert_eq!(read_session_meta(&target).unwrap(), exact);

        std::fs::write(&target, vec![b'x'; MAX_SESSION_META_BYTES + 1]).unwrap();
        let error = read_session_meta(&target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_01_session_index_line_accepts_exact_limit_and_rejects_one_more_byte() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("sessions.index");
        let mut exact = vec![b'x'; MAX_INDEX_LINE_BYTES - 1];
        exact.push(b'\n');
        std::fs::write(&target, &exact).unwrap();
        let scan = scan_index_lines(&target, 1).unwrap();
        assert!(scan.complete);
        assert_eq!(scan.lines_examined, 1);
        assert_eq!(scan.lines, vec![vec![b'x'; MAX_INDEX_LINE_BYTES - 1]]);

        let mut oversized = vec![b'x'; MAX_INDEX_LINE_BYTES];
        oversized.push(b'\n');
        std::fs::write(&target, oversized).unwrap();
        let scan = scan_index_lines(&target, 1).unwrap();
        assert!(!scan.complete);
        assert_eq!(scan.lines_examined, 1);
        assert!(scan.lines.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_01_session_index_lock_wait_is_bounded_and_file_is_stable() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let lock_path = dir.join(SESSION_INDEX_LOCK_FILE);
        let held = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        held.lock().unwrap();

        let started = Instant::now();
        let error = with_session_index_lock_timeout(&dir, Duration::from_millis(20), || Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        held.unlock().unwrap();

        with_session_index_lock(&dir, || Ok(())).unwrap();
        assert!(lock_path.is_file());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn d9_01_session_index_lock_is_released_when_operation_panics() {
        let dir = test_dir();
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _: io::Result<()> = with_session_index_lock(&dir, || {
                panic!("injected index-update panic");
            });
        }));
        assert!(panicked.is_err());

        let mut entered = false;
        with_session_index_lock(&dir, || {
            entered = true;
            Ok(())
        })
        .unwrap();
        assert!(entered);
        let _ = std::fs::remove_dir_all(dir);
    }
}
