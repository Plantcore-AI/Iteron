//! Bounded derivative publication. The journal remains authoritative.

use crate::{RecordError, session};
use iteron_protocol::RunId;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

const PENDING_DIR: &str = ".session-pending";
const WAIT_LIMIT: Duration = Duration::from_secs(10);
type Work = (PathBuf, session::SessionMeta);

enum Command {
    Publish(Box<Work>),
    Flush(mpsc::Sender<()>),
}

static WORKER: OnceLock<Option<mpsc::SyncSender<Command>>> = OnceLock::new();

fn worker() -> Option<&'static mpsc::SyncSender<Command>> {
    WORKER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel(64);
            std::thread::Builder::new()
                .name("iteron-session-publication".into())
                .spawn(move || {
                    for command in receiver {
                        match command {
                            Command::Publish(work) => {
                                let (runs, meta) = *work;
                                // A durable pending marker survives any publication failure. Readers
                                // validate its record tail and rebuild instead of trusting stale rows.
                                let _ = session::write_meta_if_current(&runs, &meta);
                            }
                            Command::Flush(reply) => {
                                let _ = reply.send(());
                            }
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

pub(crate) fn enqueue(runs: PathBuf, meta: session::SessionMeta) -> bool {
    worker().is_some_and(|sender| {
        sender
            .try_send(Command::Publish(Box::new((runs, meta))))
            .is_ok()
    })
}

/// Read/maintenance rendezvous, never used by ordinary turn completion.
pub(crate) fn flush() -> Result<(), RecordError> {
    let Some(Some(sender)) = WORKER.get() else {
        return Ok(());
    };
    let start = Instant::now();
    let wait_limit =
        iteron_tunables::param_duration("record.session_maintenance.wait_limit", WAIT_LIMIT);
    let (reply, receipt) = mpsc::channel();
    let mut command = Command::Flush(reply);
    loop {
        match sender.try_send(command) {
            Ok(()) => break,
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(unavailable()),
            Err(mpsc::TrySendError::Full(returned)) => {
                command = returned;
                if start.elapsed() >= wait_limit {
                    return Err(unavailable());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    receipt
        .recv_timeout(wait_limit.saturating_sub(start.elapsed()))
        .map_err(|_| unavailable())
}

fn unavailable() -> RecordError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "session publication worker unavailable",
    )
    .into()
}

/// Created once before a writer can append, retained until its final derivative is published.
/// A crash cannot erase the fact that a new or updated run needs discovery/index repair.
pub(crate) struct PendingPublication {
    runs: PathBuf,
    marker: PathBuf,
    run: RunId,
}

impl PendingPublication {
    pub(crate) fn open(runs: &Path, run: &RunId) -> Result<Self, RecordError> {
        crate::validate_run_id(run)?;
        let directory = runs.join(PENDING_DIR);
        let created = !directory.exists();
        std::fs::create_dir_all(&directory)?;
        if created {
            crate::cache_io::sync_dir(runs)?;
        }
        let marker = directory.join(&run.0);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&marker)?;
        if !file.metadata()?.is_file() {
            return Err(unavailable());
        }
        file.sync_all()?;
        crate::cache_io::sync_dir(&directory)?;
        Ok(Self {
            runs: runs.to_owned(),
            marker,
            run: run.clone(),
        })
    }
}

impl Drop for PendingPublication {
    fn drop(&mut self) {
        if flush().is_ok() && session::cached_projection_is_current(&self.runs, &self.run) {
            let _ = std::fs::remove_file(&self.marker);
            if let Some(parent) = self.marker.parent() {
                let _ = crate::cache_io::sync_dir(parent);
            }
        }
    }
}

/// Only active/crashed writers are inspected, not the entire session history. A durable marker
/// with no current sidecar forces verified reindex, including in a different process after crash.
pub(crate) fn marked_projections_current(runs: &Path) -> bool {
    let entries = match std::fs::read_dir(runs.join(PENDING_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return false;
        };
        let run = RunId(name);
        if crate::validate_run_id(&run).is_err() {
            return false;
        }
        match std::fs::metadata(runs.join(format!("{}.jsonl", run.0))) {
            Ok(metadata) if metadata.len() == 0 => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return false,
            _ => {}
        }
        if !session::cached_projection_is_current(runs, &run) {
            return false;
        }
    }
    true
}

/// Keep inactive writers excluded until verified reindex has published the complete snapshot.
/// Successful recovery can retire an orphan marker even when that run is malformed and skipped,
/// so one crashed journal cannot make every other session permanently unavailable.
pub(crate) struct ReindexRecovery {
    directory: PathBuf,
    locked: Vec<(std::fs::File, PathBuf)>,
}

impl ReindexRecovery {
    pub(crate) fn acquire(runs: &Path) -> Result<Self, RecordError> {
        let directory = runs.join(PENDING_DIR);
        let mut recovery = Self {
            directory: directory.clone(),
            locked: Vec::new(),
        };
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(recovery),
            Err(error) => return Err(error.into()),
        };
        for (index, entry) in entries.enumerate() {
            if index >= 4096 {
                return Err(unavailable());
            }
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let run = RunId(name);
            if crate::validate_run_id(&run).is_err() {
                continue;
            }
            let path = runs.join(format!("{}.jsonl", run.0));
            #[cfg(windows)]
            let path = path.with_extension("jsonl.lock");
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true);
            #[cfg(windows)]
            options.create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let Ok(file) = options.open(path) else {
                continue;
            };
            if file.try_lock().is_ok() {
                recovery.locked.push((file, entry.path()));
            }
        }
        Ok(recovery)
    }

    pub(crate) fn complete(self) -> Result<(), RecordError> {
        let mut removed = false;
        for (_, marker) in &self.locked {
            match std::fs::remove_file(marker) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if removed {
            crate::cache_io::sync_dir(&self.directory)?;
        }
        Ok(())
    }
}
