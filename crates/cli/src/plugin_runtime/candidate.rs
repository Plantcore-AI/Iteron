use iteron_marketplace::MAX_IMPLEMENTATION_ACTIVATION_BYTES;
use sha2::Digest as _;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

const MAX_CANDIDATE_PATH_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct CandidateFile {
    path: PathBuf,
    bytes: Vec<u8>,
    digest_sha256: String,
}

impl CandidateFile {
    pub(crate) fn read(path: &Path, expected_digest: &str) -> anyhow::Result<Self> {
        let expected_digest = validate_digest(expected_digest)?;
        let absolute = checked_absolute_path(path)?;
        reject_symlink_components(&absolute)?;
        let path = absolute.canonicalize().map_err(|error| {
            anyhow::anyhow!("implementation candidate {}: {error}", absolute.display())
        })?;
        let before = std::fs::symlink_metadata(&path).map_err(|error| {
            anyhow::anyhow!("implementation candidate {}: {error}", path.display())
        })?;
        if !before.file_type().is_file() {
            anyhow::bail!("implementation candidate must be a regular file");
        }
        let declared_len = usize::try_from(before.len()).unwrap_or(usize::MAX);
        if declared_len > MAX_IMPLEMENTATION_ACTIVATION_BYTES {
            anyhow::bail!(
                "implementation candidate is {declared_len} bytes; maximum is {MAX_IMPLEMENTATION_ACTIVATION_BYTES}"
            );
        }

        let file = open_no_follow(&path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || !same_file(&before, &opened) {
            anyhow::bail!("implementation candidate changed while it was being opened");
        }
        let mut bytes = Vec::with_capacity(declared_len);
        file.take((MAX_IMPLEMENTATION_ACTIVATION_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_IMPLEMENTATION_ACTIVATION_BYTES {
            anyhow::bail!(
                "implementation candidate exceeds the {MAX_IMPLEMENTATION_ACTIVATION_BYTES}-byte limit"
            );
        }
        let actual = hex::encode(sha2::Sha256::digest(&bytes));
        if actual != expected_digest {
            anyhow::bail!(
                "implementation candidate digest mismatch: expected {expected_digest}, got {actual}"
            );
        }
        Ok(Self {
            path,
            bytes,
            digest_sha256: actual,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn digest_sha256(&self) -> &str {
        &self.digest_sha256
    }
}

fn validate_digest(value: &str) -> anyhow::Result<String> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        anyhow::bail!("--implementation-candidate-digest must be 64 lowercase hexadecimal bytes");
    }
    Ok(value.to_owned())
}

fn checked_absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_CANDIDATE_PATH_BYTES
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        anyhow::bail!("implementation candidate path is invalid or exceeds its bound");
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(absolute)
}

fn reject_symlink_components(path: &Path) -> anyhow::Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&prefix).map_err(|error| {
            anyhow::anyhow!(
                "implementation candidate path {}: {error}",
                prefix.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "implementation candidate path contains a symlink: {}",
                prefix.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> (PathBuf, String) {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "iteron-cli-implementation-candidate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("activation.json");
        std::fs::write(&path, b"{}").unwrap();
        let digest = hex::encode(sha2::Sha256::digest(b"{}"));
        (path, digest)
    }

    #[test]
    fn exact_digest_is_required() {
        let (path, digest) = fixture();
        assert!(CandidateFile::read(&path, &digest).is_ok());
        assert!(CandidateFile::read(&path, &"0".repeat(64)).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_candidate_is_rejected() {
        let (path, digest) = fixture();
        let link = path.parent().unwrap().join("linked.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(CandidateFile::read(&link, &digest).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
