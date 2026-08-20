use super::{
    MAX_TRAJECTORY_REGISTRY_BYTES, MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES,
    MAX_TRAJECTORY_REGISTRY_RECORD_BYTES, TrajectoryEnvelope, TrajectoryRegistryError,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[derive(Clone, Copy)]
pub(super) struct FileIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
}

pub(super) fn prepare_directory(directory: &Path) -> Result<PathBuf, TrajectoryRegistryError> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(TrajectoryRegistryError::SymlinkRefused {
                path: directory.to_path_buf(),
            });
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(TrajectoryRegistryError::InvalidPathKind {
                path: directory.to_path_buf(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(directory)?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() {
        return Err(TrajectoryRegistryError::SymlinkRefused {
            path: directory.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(TrajectoryRegistryError::InvalidPathKind {
            path: directory.to_path_buf(),
        });
    }
    Ok(std::fs::canonicalize(directory)?)
}

pub(super) fn reject_existing_symlink(path: &Path) -> Result<(), TrajectoryRegistryError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(TrajectoryRegistryError::SymlinkRefused {
                path: path.to_path_buf(),
            })
        }
        Ok(metadata) if !metadata.is_file() => Err(TrajectoryRegistryError::InvalidPathKind {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
pub(super) fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
pub(super) fn sync_directory(directory: &Path) -> io::Result<()> {
    use std::fs::File;
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
pub(super) fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

pub(super) fn read_bounded_line<R: BufRead>(
    reader: &mut R,
) -> Result<Option<(Vec<u8>, bool, usize)>, TrajectoryRegistryError> {
    let mut bytes = Vec::new();
    let mut bounded = reader.take(
        (iteron_tunables::param_integer(
            "evolve.registry.max_trajectory_registry_record_bytes",
            MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
        ) + 1) as u64,
    );
    let consumed = bounded.read_until(b'\n', &mut bytes)?;
    if consumed == 0 {
        return Ok(None);
    }
    if consumed
        > iteron_tunables::param_integer(
            "evolve.registry.max_trajectory_registry_record_bytes",
            MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
        )
    {
        return Err(TrajectoryRegistryError::RecordTooLarge {
            bytes: consumed,
            limit: iteron_tunables::param_integer(
                "evolve.registry.max_trajectory_registry_record_bytes",
                MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
            ),
        });
    }
    let terminated = bytes.last() == Some(&b'\n');
    if terminated {
        bytes.pop();
    }
    Ok(Some((bytes, terminated, consumed)))
}

pub(super) fn ensure_registry_size(bytes: u64) -> Result<(), TrajectoryRegistryError> {
    if bytes > MAX_TRAJECTORY_REGISTRY_BYTES {
        Err(TrajectoryRegistryError::RegistryTooLarge {
            bytes,
            limit: MAX_TRAJECTORY_REGISTRY_BYTES,
        })
    } else {
        Ok(())
    }
}

struct CappedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON writer limit reached"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum BoundedJsonError {
    TooLarge,
    Json(serde_json::Error),
}

fn bounded_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, BoundedJsonError> {
    let mut writer = CappedWriter {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(BoundedJsonError::TooLarge);
    }
    result.map_err(BoundedJsonError::Json)?;
    Ok(writer.bytes)
}

pub(super) fn encode_envelope(
    envelope: &TrajectoryEnvelope,
) -> Result<Vec<u8>, TrajectoryRegistryError> {
    match bounded_json(envelope, MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(BoundedJsonError::TooLarge) => Err(TrajectoryRegistryError::EnvelopeTooLarge {
            limit: MAX_TRAJECTORY_REGISTRY_ENVELOPE_BYTES,
        }),
        Err(BoundedJsonError::Json(error)) => Err(error.into()),
    }
}

pub(super) fn encode_record<T: Serialize>(record: &T) -> Result<Vec<u8>, TrajectoryRegistryError> {
    match bounded_json(
        record,
        iteron_tunables::param_integer(
            "evolve.registry.max_trajectory_registry_record_bytes",
            MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
        )
        .saturating_sub(1),
    ) {
        Ok(bytes) => Ok(bytes),
        Err(BoundedJsonError::TooLarge) => Err(TrajectoryRegistryError::RecordTooLarge {
            bytes: iteron_tunables::param_integer(
                "evolve.registry.max_trajectory_registry_record_bytes",
                MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
            )
            .saturating_add(1),
            limit: iteron_tunables::param_integer(
                "evolve.registry.max_trajectory_registry_record_bytes",
                MAX_TRAJECTORY_REGISTRY_RECORD_BYTES,
            ),
        }),
        Err(BoundedJsonError::Json(error)) => Err(error.into()),
    }
}

pub(super) fn digest_bytes(bytes: &[u8]) -> String {
    encode_hex(Sha256::digest(bytes))
}

pub(super) fn hash_record(previous_hash: &str, sequence: u64, content_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"iteron-evolve/trajectory-registry/v1\0");
    hasher.update(previous_hash.as_bytes());
    hasher.update(sequence.to_le_bytes());
    hasher.update(content_digest.as_bytes());
    encode_hex(hasher.finalize())
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
