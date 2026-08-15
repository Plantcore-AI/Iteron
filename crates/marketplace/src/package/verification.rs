//! Byte-level verification and private filesystem primitives for plugin packages.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::PackageError;
use crate::{Manifest, valid_name};

pub(super) const SIGNATURE_FILE: &str = "signature.json";
pub(super) const MANIFEST_FILE: &str = "manifest.json";
pub(super) const DOMAIN: &[u8] = b"plantcore.core.plugin-package.v1\0";
pub(super) const MAX_PACKAGE_FILES: usize = 4096;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
/// Heap-backed so verification does not add a quarter-megabyte stack frame. Read granularity is
/// deliberately outside the signed representation, so changing it cannot alter the tree digest.
const TREE_DIGEST_BUFFER_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignatureEnvelope {
    pub(super) key_id: String,
    pub(super) signature: String,
}

pub(super) struct VerifiedPackage {
    pub(super) manifest: Manifest,
    pub(super) digest: String,
    pub(super) key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerificationCacheEntry {
    schema_version: u8,
    pub(super) artifact_digest: String,
    pub(super) metadata_digest: String,
    pub(super) manifest: Manifest,
    pub(super) key_id: String,
}

impl VerificationCacheEntry {
    pub(super) fn from_verified(verified: &VerifiedPackage, metadata_digest: String) -> Self {
        Self {
            schema_version: 1,
            artifact_digest: verified.digest.clone(),
            metadata_digest,
            manifest: verified.manifest.clone(),
            key_id: verified.key_id.clone(),
        }
    }

    pub(super) fn valid_schema(&self) -> bool {
        self.schema_version == 1
    }
}

pub(super) fn verify_package<F>(path: &Path, key: F) -> Result<VerifiedPackage, PackageError>
where
    F: FnOnce(&str) -> Result<[u8; 32], PackageError>,
{
    if !path.is_dir() {
        return Err(PackageError::InvalidPackage {
            path: path.to_path_buf(),
            reason: "not a directory".into(),
        });
    }
    let manifest_bytes = read_bounded(&path.join(MANIFEST_FILE), crate::MAX_PLUGIN_MANIFEST_BYTES)
        .map_err(|error| PackageError::InvalidPackage {
            path: path.join(MANIFEST_FILE),
            reason: error.to_string(),
        })?;
    let manifest =
        Manifest::parse_json(&manifest_bytes).map_err(|error| PackageError::InvalidPackage {
            path: path.join(MANIFEST_FILE),
            reason: error.to_string(),
        })?;
    let signature_bytes = read_bounded(
        &path.join(SIGNATURE_FILE),
        iteron_tunables::param_integer(
            "marketplace.package.verification.max_signature_bytes",
            MAX_SIGNATURE_BYTES,
        ),
    )
    .map_err(|_| PackageError::MalformedSignature)?;
    let envelope: SignatureEnvelope =
        serde_json::from_slice(&signature_bytes).map_err(|_| PackageError::MalformedSignature)?;
    if !valid_name(&envelope.key_id) {
        return Err(PackageError::MalformedSignature);
    }
    let raw_signature = base64::engine::general_purpose::STANDARD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| PackageError::MalformedSignature)?;
    let signature = Ed25519Signature::from_slice(&raw_signature)
        .map_err(|_| PackageError::MalformedSignature)?;
    let digest = tree_digest(path)?;
    let public_key = key(&envelope.key_id)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| PackageError::MalformedKey(envelope.key_id.clone()))?;
    let mut message = Vec::with_capacity(DOMAIN.len() + digest.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&digest);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| PackageError::BadSignature(envelope.key_id.clone()))?;
    Ok(VerifiedPackage {
        manifest,
        digest: hex::encode(digest),
        key_id: envelope.key_id,
    })
}

pub(super) fn tree_digest(root: &Path) -> Result<[u8; 32], PackageError> {
    tree_digest_with_buffer(root, TREE_DIGEST_BUFFER_BYTES)
}

fn tree_digest_with_buffer(root: &Path, buffer_bytes: usize) -> Result<[u8; 32], PackageError> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.len()
        > iteron_tunables::param_integer(
            "marketplace.package.verification.max_package_files",
            MAX_PACKAGE_FILES,
        )
    {
        return Err(invalid(root, "too many files"));
    }
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; buffer_bytes.max(1)].into_boxed_slice();
    for (relative, absolute, size) in files {
        total = total
            .checked_add(size)
            .ok_or_else(|| invalid(root, "package byte count overflow"))?;
        if total
            > iteron_tunables::param_integer(
                "marketplace.package.verification.max_package_bytes",
                MAX_PACKAGE_BYTES,
            )
        {
            return Err(invalid(root, "package exceeds the total byte limit"));
        }
        hash.update((relative.len() as u64).to_be_bytes());
        hash.update(relative.as_bytes());
        hash.update(size.to_be_bytes());
        let mut file = File::open(absolute)?;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
    }
    Ok(hash.finalize().into())
}

/// Content-free change detector for an already signature-verified immutable artifact. This walks
/// the bounded file table but does not reopen every body. Any path, type, size, or mtime change
/// invalidates the cache and forces the full signed tree verification path.
pub(super) fn metadata_digest(root: &Path) -> Result<String, PackageError> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.len()
        > iteron_tunables::param_usize(
            "marketplace.package.verification.max_package_files",
            MAX_PACKAGE_FILES,
        )
    {
        return Err(invalid(root, "too many files"));
    }
    let mut digest = Sha256::new();
    for (relative, absolute, size) in files {
        let metadata = fs::metadata(&absolute)?;
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update(size.to_be_bytes());
        match metadata.modified()?.duration_since(std::time::UNIX_EPOCH) {
            Ok(modified) => {
                digest.update(modified.as_secs().to_be_bytes());
                digest.update(modified.subsec_nanos().to_be_bytes());
            }
            Err(_) => return Err(invalid(&absolute, "file mtime predates the Unix epoch")),
        }
        // ctime/inode make a same-size rewrite followed by mtime restoration observable on Unix.
        // These fields are a change detector only; the signed content digest remains authority.
        #[cfg(unix)]
        {
            digest.update(metadata.dev().to_be_bytes());
            digest.update(metadata.ino().to_be_bytes());
            digest.update(metadata.ctime().to_be_bytes());
            digest.update(metadata.ctime_nsec().to_be_bytes());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> Result<(), PackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        let path = entry.path();
        if metadata.is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(invalid(
                &path,
                "symlinks and special files are not admitted",
            ));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .ok_or_else(|| invalid(&path, "path is not portable UTF-8"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if relative == SIGNATURE_FILE {
            continue;
        }
        let size = entry.metadata()?.len();
        if size
            > iteron_tunables::param_integer(
                "marketplace.package.verification.max_package_file_bytes",
                MAX_PACKAGE_FILE_BYTES,
            )
        {
            return Err(invalid(&path, "file exceeds the per-file byte limit"));
        }
        files.push((relative, path, size));
        if files.len()
            > iteron_tunables::param_integer(
                "marketplace.package.verification.max_package_files",
                MAX_PACKAGE_FILES,
            )
        {
            return Err(invalid(root, "too many files"));
        }
    }
    Ok(())
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<(), PackageError> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            fs::create_dir(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)?;
        } else {
            return Err(invalid(
                &entry.path(),
                "symlinks and special files are not admitted",
            ));
        }
    }
    Ok(())
}

pub(super) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, std::io::Error> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), PackageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn sync_dir(path: &Path) -> Result<(), PackageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn invalid(path: &Path, reason: impl Into<String>) -> PackageError {
    PackageError::InvalidPackage {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn tree_digest_is_independent_of_read_chunk_size() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "iteron-tree-digest-buffer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("manifest.json"), b"manifest").unwrap();
        std::fs::write(root.join("nested/body.bin"), vec![7u8; 300_001]).unwrap();

        let tiny = tree_digest_with_buffer(&root, 17).unwrap();
        let production = tree_digest(&root).unwrap();
        assert_eq!(tiny, production);
        std::fs::remove_dir_all(root).unwrap();
    }
}
