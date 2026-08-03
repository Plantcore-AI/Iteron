use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::DagError;
use super::hash::config_digest;
use super::reducer::{ApplyReceipt, LogEntry, Prepared, TaskDag};
use super::types::{Command, CommandId, Config, MAX_LOG_BYTES};

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
/// composition-root trust boundary and must be an application-owned state directory, not an
/// untrusted workspace path.
pub struct TaskDagStore {
    path: PathBuf,
    file: File,
    dag: TaskDag,
    bytes: u64,
    recovered_torn_bytes: u64,
    poisoned: Option<String>,
}

impl TaskDagStore {
    pub fn open(path: impl Into<PathBuf>, config: Config) -> Result<Self, DagError> {
        config.validate().map_err(DagError::InvalidConfig)?;
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        reject_non_regular_target(&path)?;
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

        let length = file.metadata()?.len();
        if length > MAX_LOG_BYTES {
            return Err(DagError::Corrupt(format!(
                "log is {length} bytes, over the {MAX_LOG_BYTES}-byte ceiling"
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(length as usize);
        std::io::Read::by_ref(&mut file)
            .take(MAX_LOG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LOG_BYTES {
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
            return Ok(Self {
                path,
                file,
                dag,
                bytes: encoded.len() as u64,
                recovered_torn_bytes,
                poisoned: None,
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
        if first.len() > MAX_LOG_LINE_BYTES {
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
            if raw.len() > MAX_LOG_LINE_BYTES {
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
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            dag,
            bytes: retained as u64,
            recovered_torn_bytes,
            poisoned: None,
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
        if self.bytes.saturating_add(encoded.len() as u64) > MAX_LOG_BYTES {
            return Err(DagError::Capacity { kind: "log bytes" });
        }
        if let Err(error) = append_synced(&mut self.file, &encoded) {
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
}

fn reject_non_regular_target(path: &Path) -> Result<(), DagError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DagError::Io(
            std::io::Error::other("task-DAG store target must not be a symlink"),
        )),
        Ok(metadata) if !metadata.is_file() => Err(DagError::Io(std::io::Error::other(
            "task-DAG store target must be a regular file",
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DagError::Io(error)),
    }
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
    if encoded.len() > MAX_LOG_LINE_BYTES {
        return Err(DagError::Capacity { kind: "log line" });
    }
    Ok(encoded)
}

fn append_synced(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_data()
}
