//! Bounded reads for filesystem-discovered prompt sources.
//!
//! Repository content is adversarial input.  A source beneath a repository root is accepted only
//! when every component below that root is a real directory/file (never a symlink), the leaf is a
//! regular file, and the bytes actually read fit the caller's declared ceiling.  User-owned
//! sources intentionally retain dotfiles-style symlink support, but are still regular-file and
//! byte bounded.

use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Filesystem provenance determines whether an intentional user symlink is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceScope {
    /// Tree-discovered repository content: no symlink below `root` may be followed.
    Repository,
    /// Operator-owned content: symlinks are allowed, matching common dotfiles layouts.
    User,
    /// Operator-owned content whose resolved target must remain below `root`.
    UserContained,
}

/// The no-follow type of a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// One entry returned by a bounded directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub path: PathBuf,
    pub kind: SourceEntryKind,
}

/// A directory listing that explicitly reports when its entry ceiling was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceListing {
    pub entries: Vec<SourceEntry>,
    pub truncated: bool,
}

struct ResolvedSource {
    path: PathBuf,
    metadata: Metadata,
}

/// A surfaced refusal or I/O failure while opening a discovered source.
#[derive(Debug)]
pub struct SourceError {
    path: PathBuf,
    reason: String,
}

impl SourceError {
    fn new(path: &Path, reason: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

impl std::error::Error for SourceError {}

/// Read an optional UTF-8 source through a descriptor capped at `max_bytes + 1`.
///
/// The metadata length check rejects obviously oversized files before allocation; the bounded
/// descriptor read remains authoritative if a file grows after that check.
pub fn read_bounded_utf8(
    root: &Path,
    path: &Path,
    max_bytes: usize,
    scope: SourceScope,
) -> Result<Option<String>, SourceError> {
    let Some(resolved) = resolve_file(root, path, scope)? else {
        return Ok(None);
    };

    let before = resolved.metadata;
    if !before.is_file() {
        return Err(SourceError::new(path, "source is not a regular file"));
    }
    if before.len() > max_bytes as u64 {
        return Err(SourceError::new(
            path,
            format!("source exceeds the {max_bytes} byte limit"),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if scope == SourceScope::Repository {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = match options.open(&resolved.path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SourceError::new(
                path,
                format!("cannot open source: {error}"),
            ));
        }
    };
    let opened = file
        .metadata()
        .map_err(|error| SourceError::new(path, format!("cannot inspect open source: {error}")))?;
    if !opened.is_file() {
        return Err(SourceError::new(path, "source is not a regular file"));
    }
    ensure_same_file(path, &before, &opened)?;
    if opened.len() > max_bytes as u64 {
        return Err(SourceError::new(
            path,
            format!("source exceeds the {max_bytes} byte limit"),
        ));
    }

    let capacity = usize::try_from(opened.len())
        .unwrap_or(max_bytes)
        .min(max_bytes)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| SourceError::new(path, format!("cannot read source: {error}")))?;
    if bytes.len() > max_bytes {
        return Err(SourceError::new(
            path,
            format!("source exceeds the {max_bytes} byte limit"),
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| SourceError::new(path, "source is not valid UTF-8"))
}

/// List at most `max_entries` entries without following entry symlinks.
pub fn list_directory_bounded(
    root: &Path,
    dir: &Path,
    max_entries: usize,
    scope: SourceScope,
) -> Result<Option<SourceListing>, SourceError> {
    let Some(resolved) = resolve_directory(root, dir, scope)? else {
        return Ok(None);
    };
    let before = resolved.metadata;
    if !before.is_dir() {
        return Err(SourceError::new(dir, "source root is not a directory"));
    }
    let read_dir = match fs::read_dir(&resolved.path) {
        Ok(read_dir) => read_dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SourceError::new(
                dir,
                format!("cannot list source directory: {error}"),
            ));
        }
    };

    let mut entries = Vec::with_capacity(max_entries.min(256));
    let mut truncated = false;
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            SourceError::new(dir, format!("cannot inspect directory entry: {error}"))
        })?;
        if entries.len() == max_entries {
            truncated = true;
            break;
        }
        let entry_path = dir.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            SourceError::new(
                &entry_path,
                format!("cannot inspect directory entry type: {error}"),
            )
        })?;
        let kind = if file_type.is_symlink() {
            SourceEntryKind::Symlink
        } else if file_type.is_file() {
            SourceEntryKind::File
        } else if file_type.is_dir() {
            SourceEntryKind::Directory
        } else {
            SourceEntryKind::Other
        };
        entries.push(SourceEntry {
            // Keep the caller's lexical root (which may itself be an explicitly selected symlink)
            // rather than leaking the canonical enumeration path into the next confined descent.
            path: entry_path,
            kind,
        });
    }

    // Detect replacement of the named directory while it was being enumerated.  This cannot make
    // path-based `read_dir` perfectly race-free, but it closes the common swap and keeps unsafe
    // results out of callers; every subsequent descent/read repeats the no-follow validation.
    let after = metadata_for_open(&resolved.path, scope)?;
    ensure_same_file(dir, &before, &after)?;
    if !after.is_dir() {
        return Err(SourceError::new(dir, "source root is not a directory"));
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Some(SourceListing { entries, truncated }))
}

fn resolve_file(
    root: &Path,
    path: &Path,
    scope: SourceScope,
) -> Result<Option<ResolvedSource>, SourceError> {
    match scope {
        SourceScope::Repository => resolve_repository_path(root, path, false),
        SourceScope::User => match fs::metadata(path) {
            Ok(metadata) => Ok(Some(ResolvedSource {
                path: path.to_path_buf(),
                metadata,
            })),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SourceError::new(
                path,
                format!("cannot inspect source: {error}"),
            )),
        },
        SourceScope::UserContained => {
            let Some(path) = resolve_user_contained(root, path)? else {
                return Ok(None);
            };
            let metadata = fs::metadata(&path).map_err(|error| {
                SourceError::new(&path, format!("cannot inspect source: {error}"))
            })?;
            Ok(Some(ResolvedSource { path, metadata }))
        }
    }
}

fn resolve_directory(
    root: &Path,
    path: &Path,
    scope: SourceScope,
) -> Result<Option<ResolvedSource>, SourceError> {
    match scope {
        SourceScope::Repository => resolve_repository_path(root, path, true),
        SourceScope::User => match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(Some(ResolvedSource {
                path: path.to_path_buf(),
                metadata,
            })),
            Ok(_) => Err(SourceError::new(path, "source root is not a directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(SourceError::new(
                path,
                format!("cannot inspect source directory: {error}"),
            )),
        },
        SourceScope::UserContained => {
            let resolved = resolve_user_contained(root, path)?;
            match resolved {
                Some(resolved) => {
                    let metadata = fs::metadata(&resolved).map_err(|error| {
                        SourceError::new(
                            &resolved,
                            format!("cannot inspect source directory: {error}"),
                        )
                    })?;
                    if !metadata.is_dir() {
                        return Err(SourceError::new(path, "source root is not a directory"));
                    }
                    Ok(Some(ResolvedSource {
                        path: resolved,
                        metadata,
                    }))
                }
                None => Ok(None),
            }
        }
    }
}

/// Resolve a path lexically below `root`, then reject every symlink component below the canonical
/// root.  Canonicalizing only the caller-selected root preserves explicit workspace symlinks while
/// preventing repository content from redirecting discovery elsewhere.
fn resolve_repository_path(
    root: &Path,
    path: &Path,
    want_directory: bool,
) -> Result<Option<ResolvedSource>, SourceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SourceError::new(path, format!("source escapes root {}", root.display())))?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err(SourceError::new(
                path,
                format!("source escapes root {}", root.display()),
            ));
        }
    }

    let root_canonical = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SourceError::new(
                root,
                format!("cannot resolve source root: {error}"),
            ));
        }
    };
    let root_metadata = fs::metadata(&root_canonical)
        .map_err(|error| SourceError::new(root, format!("cannot inspect source root: {error}")))?;
    if !root_metadata.is_dir() {
        return Err(SourceError::new(root, "source root is not a directory"));
    }

    let normals: Vec<_> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            Component::CurDir => None,
            _ => unreachable!("validated above"),
        })
        .collect();
    let mut current = root_canonical;
    let mut leaf_metadata = root_metadata;
    for (index, name) in normals.iter().enumerate() {
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(SourceError::new(
                    path,
                    format!("cannot inspect source component: {error}"),
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(SourceError::new(
                path,
                format!(
                    "repository source contains symlink component {}",
                    current.display()
                ),
            ));
        }
        let is_leaf = index + 1 == normals.len();
        if !is_leaf && !metadata.is_dir() {
            return Err(SourceError::new(
                path,
                format!("source parent {} is not a directory", current.display()),
            ));
        }
        if is_leaf && want_directory && !metadata.is_dir() {
            return Err(SourceError::new(path, "source root is not a directory"));
        }
        if is_leaf && !want_directory && !metadata.is_file() {
            return Err(SourceError::new(path, "source is not a regular file"));
        }
        leaf_metadata = metadata;
    }
    if normals.is_empty() && !want_directory {
        return Err(SourceError::new(path, "source is not a regular file"));
    }
    Ok(Some(ResolvedSource {
        path: current,
        metadata: leaf_metadata,
    }))
}

fn resolve_user_contained(root: &Path, path: &Path) -> Result<Option<PathBuf>, SourceError> {
    let root_canonical = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SourceError::new(
                root,
                format!("cannot resolve source root: {error}"),
            ));
        }
    };
    let resolved = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SourceError::new(
                path,
                format!("cannot resolve source: {error}"),
            ));
        }
    };
    if !resolved.starts_with(&root_canonical) {
        return Err(SourceError::new(
            path,
            format!("resolved source escapes root {}", root.display()),
        ));
    }
    Ok(Some(resolved))
}

fn metadata_for_open(path: &Path, scope: SourceScope) -> Result<Metadata, SourceError> {
    let result = if scope == SourceScope::Repository {
        fs::symlink_metadata(path)
    } else {
        fs::metadata(path)
    };
    result.map_err(|error| SourceError::new(path, format!("cannot inspect source: {error}")))
}

fn ensure_same_file(path: &Path, before: &Metadata, after: &Metadata) -> Result<(), SourceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(SourceError::new(
                path,
                "source identity changed while it was being opened",
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, before, after);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "core-source-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn actual_read_is_bounded_and_regular_only() {
        let root = scratch("bounded");
        fs::write(root.join("small.md"), "1234").unwrap();
        fs::write(root.join("large.md"), "12345").unwrap();
        assert_eq!(
            read_bounded_utf8(&root, &root.join("small.md"), 4, SourceScope::Repository)
                .unwrap()
                .as_deref(),
            Some("1234")
        );
        let error = read_bounded_utf8(&root, &root.join("large.md"), 4, SourceScope::Repository)
            .unwrap_err();
        assert!(error.reason().contains("4 byte limit"));
        assert!(read_bounded_utf8(&root, &root, 4, SourceScope::Repository).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn directory_listing_reports_its_ceiling() {
        let root = scratch("listing");
        for name in ["a", "b", "c"] {
            fs::write(root.join(name), name).unwrap();
        }
        let listing = list_directory_bounded(&root, &root, 2, SourceScope::Repository)
            .unwrap()
            .unwrap();
        assert_eq!(listing.entries.len(), 2);
        assert!(listing.truncated);
        fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn repository_refuses_symlinks_but_user_source_allows_them() {
        let root = scratch("symlink");
        let outside = scratch("outside");
        fs::write(outside.join("source.md"), "operator source").unwrap();
        std::os::unix::fs::symlink(outside.join("source.md"), root.join("source.md")).unwrap();

        let error = read_bounded_utf8(&root, &root.join("source.md"), 64, SourceScope::Repository)
            .unwrap_err();
        assert!(error.reason().contains("symlink"));
        assert_eq!(
            read_bounded_utf8(&root, &root.join("source.md"), 64, SourceScope::User)
                .unwrap()
                .as_deref(),
            Some("operator source")
        );
        assert!(
            read_bounded_utf8(
                &root,
                &root.join("source.md"),
                64,
                SourceScope::UserContained
            )
            .is_err(),
            "contained user source cannot escape its root"
        );
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn repository_refuses_a_symlinked_parent_directory() {
        let root = scratch("parent-link");
        let outside = scratch("parent-outside");
        fs::write(outside.join("source.md"), "outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
        let error = read_bounded_utf8(
            &root,
            &root.join("linked/source.md"),
            64,
            SourceScope::Repository,
        )
        .unwrap_err();
        assert!(error.reason().contains("symlink"));
        fs::remove_dir_all(root).ok();
        fs::remove_dir_all(outside).ok();
    }
}
