use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::DagError;
use super::hash::config_digest;
use super::reducer::{ApplyReceipt, LogEntry, Prepared, TaskDag};
use super::types::{Command, CommandId, Config, max_log_bytes};

const STORE_VERSION: u32 = 1;
const MAX_LOG_LINE_BYTES: usize = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
enum StoredLine {
    Genesis {
        version: u32,
        config: Config,
        config_digest: String,
    },
    Command {
        entry: LogEntry,
    },
}

/// Exclusive, append-only durable owner for one [`TaskDag`].
///
/// A command is validated first, then appended and `sync_data`ed, then projected into memory. If
/// any post-append operation fails the store is poisoned and reports [`DagError::DurabilityUnknown`]
/// because the command may already be durable. Reopening and retrying the same `CommandId` is the
/// only safe recovery path.
///
/// The final path component is opened without following a symlink. Its parent directory remains a
/// composition-root trust boundary and must be a durably pre-provisioned, application-owned state
/// directory, not an untrusted workspace path. For a new file, genesis is synced before the parent
/// directory entry is synced; failure of either operation is reported as durability-unknown.
/// This namespace-durability contract currently has a supported implementation only on Unix. For
/// a regular target, other platforms fail with [`DagError::UnsupportedPlatform`] before creating
/// or opening the log; unsafe file types are still rejected first.
pub struct TaskDagStore {
    path: PathBuf,
    file: File,
    dag: TaskDag,
    bytes: u64,
    recovered_torn_bytes: u64,
    poisoned: Option<String>,
    #[cfg(all(test, unix))]
    next_append_fault: Option<TestAppendFault>,
}

#[cfg(all(test, unix))]
#[derive(Debug, Clone, Copy)]
pub(super) enum TestAppendFault {
    PartialWrite(usize),
    AfterFullWriteBeforeSync,
}

impl TaskDagStore {
    pub fn open(path: impl Into<PathBuf>, config: Config) -> Result<Self, DagError> {
        Self::open_inner(path.into(), config, false)
    }

    #[cfg(all(test, unix))]
    pub(super) fn open_with_parent_sync_failure(
        path: impl Into<PathBuf>,
        config: Config,
    ) -> Result<Self, DagError> {
        Self::open_inner(path.into(), config, true)
    }

    fn open_inner(
        path: PathBuf,
        config: Config,
        inject_parent_sync_failure: bool,
    ) -> Result<Self, DagError> {
        config.validate().map_err(DagError::InvalidConfig)?;
        let parent = durable_parent(&path)?;
        reject_non_regular_target(&path)?;
        require_namespace_durability_support()?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(&path)?;
        let opened = file.metadata()?;
        #[cfg(windows)]
        if is_windows_reparse_point(&opened) {
            return Err(DagError::Io(std::io::Error::other(
                "task-DAG store target must not be a reparse point",
            )));
        }
        if opened.file_type().is_symlink() || !opened.is_file() {
            return Err(DagError::Io(std::io::Error::other(
                "task-DAG store target must be a regular non-symlink file",
            )));
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(DagError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "task-DAG store already has an active writer",
                )));
            }
            Err(TryLockError::Error(error)) => return Err(DagError::Io(error)),
        }

        // One read of the ceiling for the whole open: the size check, the bounded read and the
        // post-read check have to agree about the same number, and three independent lookups could
        // not be made to disagree today but would be a trap for a later edit.
        let log_ceiling = max_log_bytes();
        let length = file.metadata()?.len();
        if length > log_ceiling {
            return Err(DagError::Corrupt(format!(
                "log is {length} bytes, over the {log_ceiling}-byte ceiling"
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        std::io::Read::by_ref(&mut file)
            .take(log_ceiling + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > log_ceiling {
            return Err(DagError::Corrupt("log exceeded its read ceiling".into()));
        }

        let retained = complete_prefix_len(&bytes);
        let recovered_torn_bytes = (bytes.len() - retained) as u64;
        if !bytes.is_empty() && retained == 0 {
            return Err(DagError::Corrupt(
                "log has no durable newline-terminated genesis".into(),
            ));
        }

        let mut dag = TaskDag::new(config.clone())?;
        if bytes.is_empty() {
            let genesis = StoredLine::Genesis {
                version: STORE_VERSION,
                config,
                config_digest: dag.head_digest().to_string(),
            };
            let encoded = encode_line(&genesis)?;
            append_synced(&mut file, &encoded).map_err(|error| {
                DagError::DurabilityUnknown(format!("genesis append failed: {error}"))
            })?;
            // Syncing the parent unconditionally also recovers an empty file whose creator could
            // not prove that its namespace update reached stable storage.
            sync_parent_entry(parent, inject_parent_sync_failure).map_err(|error| {
                DagError::DurabilityUnknown(format!(
                    "store namespace sync failed after genesis: {error}"
                ))
            })?;
            return Ok(Self {
                path,
                file,
                dag,
                bytes: encoded.len() as u64,
                recovered_torn_bytes,
                poisoned: None,
                #[cfg(all(test, unix))]
                next_append_fault: None,
            });
        }

        // Validate the entire durable prefix, including immutable genesis, before repairing a torn
        // tail. A wrong config or corrupt prefix must never gain permission to mutate this file.
        let mut lines = bytes[..retained]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty());
        let first = lines
            .next()
            .ok_or_else(|| DagError::Corrupt("log has no genesis".into()))?;
        if first.len()
            > iteron_tunables::param_integer(
                "workflow.task_dag.store.max_log_line_bytes",
                MAX_LOG_LINE_BYTES,
            )
        {
            return Err(DagError::Corrupt(
                "genesis line exceeds its byte ceiling".into(),
            ));
        }
        match serde_json::from_slice::<StoredLine>(first)? {
            StoredLine::Genesis {
                version,
                config: stored,
                config_digest: stored_digest,
            } => {
                if version != STORE_VERSION {
                    return Err(DagError::Corrupt(format!(
                        "unsupported store version {version}"
                    )));
                }
                if stored != config {
                    return Err(DagError::Corrupt(
                        "requested config differs from immutable genesis".into(),
                    ));
                }
                if config_digest(&stored)? != stored_digest || stored_digest != dag.head_digest() {
                    return Err(DagError::Corrupt("genesis digest mismatch".into()));
                }
            }
            StoredLine::Command { .. } => {
                return Err(DagError::Corrupt("first record is not genesis".into()));
            }
        }

        for raw in lines {
            if raw.len()
                > iteron_tunables::param_integer(
                    "workflow.task_dag.store.max_log_line_bytes",
                    MAX_LOG_LINE_BYTES,
                )
            {
                return Err(DagError::Corrupt(
                    "command line exceeds its byte ceiling".into(),
                ));
            }
            match serde_json::from_slice::<StoredLine>(raw)? {
                StoredLine::Command { entry } => dag.replay(entry)?,
                StoredLine::Genesis { .. } => {
                    return Err(DagError::Corrupt("duplicate genesis record".into()));
                }
            }
        }
        if retained != bytes.len() {
            file.set_len(retained as u64)?;
        }
        // Reopening is the recovery boundary for an earlier sync-unknown append. Re-sync the
        // validated prefix and directory before reporting an exact replay; otherwise a later
        // crash could lose a command that this process had already treated as durable.
        file.sync_data().map_err(|error| {
            DagError::DurabilityUnknown(format!("validated log sync failed on reopen: {error}"))
        })?;
        sync_parent_entry(parent, inject_parent_sync_failure).map_err(|error| {
            DagError::DurabilityUnknown(format!("store namespace sync failed on reopen: {error}"))
        })?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            dag,
            bytes: retained as u64,
            recovered_torn_bytes,
            poisoned: None,
            #[cfg(all(test, unix))]
            next_append_fault: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dag(&self) -> &TaskDag {
        &self.dag
    }

    /// Bytes removed from one non-newline-terminated tail while reopening. A non-zero value is
    /// recovery evidence for support/telemetry; valid newline-terminated records are never repaired.
    pub fn recovered_torn_bytes(&self) -> u64 {
        self.recovered_torn_bytes
    }

    pub fn submit(
        &mut self,
        command_id: CommandId,
        command: Command,
    ) -> Result<ApplyReceipt, DagError> {
        if let Some(reason) = &self.poisoned {
            return Err(DagError::Poisoned(reason.clone()));
        }
        let entry = match self.dag.prepare(command_id, command)? {
            Prepared::Replay(receipt) => return Ok(receipt),
            Prepared::New(entry) => *entry,
        };
        let encoded = encode_line(&StoredLine::Command {
            entry: entry.clone(),
        })?;
        if self.bytes.saturating_add(encoded.len() as u64) > max_log_bytes() {
            return Err(DagError::Capacity { kind: "log bytes" });
        }
        #[cfg(all(test, unix))]
        let append_result = match self.next_append_fault.take() {
            Some(fault) => append_synced_with_fault(&mut self.file, &encoded, fault),
            None => append_synced(&mut self.file, &encoded),
        };
        #[cfg(any(not(test), not(unix)))]
        let append_result = append_synced(&mut self.file, &encoded);
        if let Err(error) = append_result {
            let reason = error.to_string();
            self.poisoned = Some(reason.clone());
            return Err(DagError::DurabilityUnknown(reason));
        }
        self.bytes += encoded.len() as u64;
        let receipt = ApplyReceipt {
            sequence: entry.sequence,
            replayed: false,
        };
        self.dag.commit(entry);
        Ok(receipt)
    }

    /// Validate and publish one small semantic command group with one durability barrier. A cloned
    /// reducer applies each command in order before any byte is written, so failure leaves both
    /// disk and the live projection unchanged; success appends all newline-delimited entries,
    /// syncs once, then swaps in the staged projection.
    pub fn submit_batch(
        &mut self,
        commands: Vec<(CommandId, Command)>,
    ) -> Result<Vec<ApplyReceipt>, DagError> {
        if commands.is_empty() || commands.len() > 16 {
            return Err(DagError::Invalid(
                "command batch must contain 1..=16 entries",
            ));
        }
        if let Some(reason) = &self.poisoned {
            return Err(DagError::Poisoned(reason.clone()));
        }
        let mut staged_dag = self.dag.clone();
        let mut encoded = Vec::new();
        let mut receipts = Vec::with_capacity(commands.len());
        for (command_id, command) in commands {
            match staged_dag.prepare(command_id, command)? {
                Prepared::Replay(receipt) => receipts.push(receipt),
                Prepared::New(entry) => {
                    let entry = *entry;
                    let line = encode_line(&StoredLine::Command {
                        entry: entry.clone(),
                    })?;
                    encoded.extend_from_slice(&line);
                    receipts.push(ApplyReceipt {
                        sequence: entry.sequence,
                        replayed: false,
                    });
                    staged_dag.commit(entry);
                }
            }
        }
        if encoded.is_empty() {
            return Ok(receipts);
        }
        if self.bytes.saturating_add(encoded.len() as u64) > max_log_bytes() {
            return Err(DagError::Capacity { kind: "log bytes" });
        }
        if let Err(error) = append_synced(&mut self.file, &encoded) {
            let reason = error.to_string();
            self.poisoned = Some(reason.clone());
            return Err(DagError::DurabilityUnknown(reason));
        }
        self.bytes = self.bytes.saturating_add(encoded.len() as u64);
        self.dag = staged_dag;
        Ok(receipts)
    }

    #[cfg(all(test, unix))]
    pub(super) fn inject_next_append_fault(&mut self, fault: TestAppendFault) {
        self.next_append_fault = Some(fault);
    }
}

fn durable_parent(path: &Path) -> Result<&Path, DagError> {
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            DagError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "task-DAG store parent must be pre-provisioned",
            ))
        } else {
            DagError::Io(error)
        }
    })?;
    if !metadata.is_dir() {
        return Err(DagError::Io(std::io::Error::other(
            "task-DAG store parent must be a directory",
        )));
    }
    Ok(parent)
}

#[cfg(unix)]
fn require_namespace_durability_support() -> Result<(), DagError> {
    Ok(())
}

#[cfg(not(unix))]
fn require_namespace_durability_support() -> Result<(), DagError> {
    Err(DagError::UnsupportedPlatform {
        capability: "durable append-only store namespace synchronization",
    })
}

fn reject_non_regular_target(path: &Path) -> Result<(), DagError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DagError::Io(
            std::io::Error::other("task-DAG store target must not be a symlink"),
        )),
        #[cfg(windows)]
        Ok(metadata) if is_windows_reparse_point(&metadata) => Err(DagError::Io(
            std::io::Error::other("task-DAG store target must not be a reparse point"),
        )),
        Ok(metadata) if !metadata.is_file() => Err(DagError::Io(std::io::Error::other(
            "task-DAG store target must be a regular file",
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DagError::Io(error)),
    }
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn complete_prefix_len(bytes: &[u8]) -> usize {
    if bytes.last() == Some(&b'\n') {
        bytes.len()
    } else {
        bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1)
    }
}

fn encode_line(line: &StoredLine) -> Result<Vec<u8>, DagError> {
    let mut encoded = serde_json::to_vec(line)?;
    encoded.push(b'\n');
    if encoded.len()
        > iteron_tunables::param_integer(
            "workflow.task_dag.store.max_log_line_bytes",
            MAX_LOG_LINE_BYTES,
        )
    {
        return Err(DagError::Capacity { kind: "log line" });
    }
    Ok(encoded)
}

fn append_synced(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_data()
}

#[cfg(all(test, unix))]
fn append_synced_with_fault(
    file: &mut File,
    bytes: &[u8],
    fault: TestAppendFault,
) -> std::io::Result<()> {
    match fault {
        TestAppendFault::PartialWrite(requested) => {
            let length = requested.min(bytes.len().saturating_sub(1));
            file.write_all(&bytes[..length])?;
            file.flush()?;
            Err(std::io::Error::other("injected partial append failure"))
        }
        TestAppendFault::AfterFullWriteBeforeSync => {
            file.write_all(bytes)?;
            file.flush()?;
            Err(std::io::Error::other(
                "injected sync failure after a full append",
            ))
        }
    }
}

#[cfg(unix)]
fn sync_parent_entry(parent: &Path, inject_failure: bool) -> std::io::Result<()> {
    if inject_failure {
        return Err(std::io::Error::other(
            "injected parent-directory sync failure",
        ));
    }
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_entry(_parent: &Path, _inject_failure: bool) -> std::io::Result<()> {
    // `open_inner` refuses before touching the log on these platforms. Keep this defensive branch
    // fall-closed as well in case that ordering is refactored.
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "durable parent-namespace synchronization is unsupported on this platform",
    ))
}
