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

/// Shared discovery prune vocabulary. Filesystem tools, context outline, and agent discovery use
/// one list so a build/vendor tree cannot be skipped by one startup path and scanned by another.
pub const DEFAULT_PRUNED_COMPONENTS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
];

/// Coverage is diagnostic evidence, not an unbounded mirror of a repository tree. Incomplete
/// strata sort first, so this fixed cap retains the paths that can drive a narrower follow-up.
pub const MAX_FAIR_PATH_COVERAGE_STRATA: usize = 32;

fn max_fair_path_coverage_strata() -> usize {
    iteron_tunables::param_usize(
        "ctx.source.max_fair_path_coverage_strata",
        MAX_FAIR_PATH_COVERAGE_STRATA,
    )
}

/// Per-first-component accounting for a deterministic fair path admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStratumCoverage {
    pub path: PathBuf,
    pub eligible_files: usize,
    pub eligible_bytes: usize,
    pub admitted_files: usize,
    pub admitted_bytes: usize,
}

impl PathStratumCoverage {
    pub fn is_complete(&self) -> bool {
        self.eligible_files == self.admitted_files
    }
}

/// Result of admitting an already-discovered `(path, bytes)` corpus under hard file/byte limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairPathAdmission {
    pub admitted: Vec<PathBuf>,
    pub eligible_files: usize,
    pub eligible_bytes: usize,
    pub admitted_bytes: usize,
    pub coverage: Vec<PathStratumCoverage>,
    pub incomplete_strata: usize,
    pub coverage_truncated: bool,
}

/// Deterministically admit paths without letting one lexically early top-level subtree consume the
/// complete byte budget.
///
/// Candidates are stratified by their first normal component relative to `base`. Each stratum is
/// ordered by `(bytes, path)`. Admission repeatedly serves the stratum with the fewest admitted
/// bytes, then files, breaking ties by its smallest remaining file. Feasible strata therefore
/// receive max-min byte fairness while small files remain preferred. The caller's byte and file
/// ceilings remain hard limits; this function performs no filesystem I/O.
pub fn admit_paths_fair(
    base: &Path,
    candidates: Vec<(PathBuf, usize)>,
    max_files: usize,
    max_bytes: usize,
) -> FairPathAdmission {
    #[derive(Default)]
    struct Stratum {
        candidates: Vec<(PathBuf, usize)>,
        next: usize,
        eligible_bytes: usize,
        admitted_files: usize,
        admitted_bytes: usize,
    }

    fn stratum_path(base: &Path, path: &Path) -> PathBuf {
        path.strip_prefix(base)
            .ok()
            .and_then(|relative| {
                relative.components().find_map(|component| match component {
                    Component::Normal(name) => Some(base.join(name)),
                    Component::CurDir => None,
                    _ => None,
                })
            })
            .unwrap_or_else(|| base.to_path_buf())
    }

    let mut strata = std::collections::BTreeMap::<PathBuf, Stratum>::new();
    let mut eligible_bytes = 0usize;
    for (path, bytes) in candidates {
        eligible_bytes = eligible_bytes.saturating_add(bytes);
        let stratum = strata.entry(stratum_path(base, &path)).or_default();
        stratum.eligible_bytes = stratum.eligible_bytes.saturating_add(bytes);
        stratum.candidates.push((path, bytes));
    }
    for stratum in strata.values_mut() {
        stratum
            .candidates
            .sort_by(|(left_path, left_bytes), (right_path, right_bytes)| {
                left_bytes
                    .cmp(right_bytes)
                    .then_with(|| left_path.cmp(right_path))
            });
    }

    let eligible_files = strata
        .values()
        .map(|stratum| stratum.candidates.len())
        .sum();
    let mut strata = strata.into_iter().collect::<Vec<_>>();
    let mut next = std::collections::BinaryHeap::new();
    for (index, (path, stratum)) in strata.iter().enumerate() {
        if let Some((candidate, bytes)) = stratum.candidates.first() {
            next.push(std::cmp::Reverse((
                0usize,
                0usize,
                *bytes,
                path.clone(),
                candidate.clone(),
                index,
            )));
        }
    }
    let mut admitted = Vec::with_capacity(max_files.min(eligible_files));
    let mut admitted_bytes = 0usize;
    while admitted.len() < max_files && admitted_bytes < max_bytes {
        let remaining = max_bytes.saturating_sub(admitted_bytes);
        let Some(std::cmp::Reverse((_, _, bytes, _, path, index))) = next.pop() else {
            break;
        };
        // Remaining budget only decreases, so an infeasible head can never become feasible later.
        // Since each stratum is byte-sorted, neither can any of that stratum's later candidates.
        if bytes > remaining {
            continue;
        }
        let (stratum_path, stratum) = &mut strata[index];
        stratum.next = stratum.next.saturating_add(1);
        stratum.admitted_files = stratum.admitted_files.saturating_add(1);
        stratum.admitted_bytes = stratum.admitted_bytes.saturating_add(bytes);
        admitted_bytes = admitted_bytes.saturating_add(bytes);
        admitted.push(path);
        if let Some((candidate, bytes)) = stratum.candidates.get(stratum.next) {
            next.push(std::cmp::Reverse((
                stratum.admitted_bytes,
                stratum.admitted_files,
                *bytes,
                stratum_path.clone(),
                candidate.clone(),
                index,
            )));
        }
    }

    let mut coverage = strata
        .into_iter()
        .map(|(path, stratum)| PathStratumCoverage {
            path,
            eligible_files: stratum.candidates.len(),
            eligible_bytes: stratum.eligible_bytes,
            admitted_files: stratum.admitted_files,
            admitted_bytes: stratum.admitted_bytes,
        })
        .collect::<Vec<_>>();
    coverage.sort_by(|left, right| {
        left.is_complete()
            .cmp(&right.is_complete())
            .then_with(|| left.path.cmp(&right.path))
    });
    let incomplete_strata = coverage
        .iter()
        .filter(|stratum| !stratum.is_complete())
        .count();
    let coverage_truncated = coverage.len() > max_fair_path_coverage_strata();
    coverage.truncate(max_fair_path_coverage_strata());

    FairPathAdmission {
        admitted,
        eligible_files,
        eligible_bytes,
        admitted_bytes,
        coverage,
        incomplete_strata,
        coverage_truncated,
    }
}

pub fn is_default_pruned_component(name: &str) -> bool {
    iteron_tunables::param_str_list(
        "ctx.source.default_pruned_components",
        DEFAULT_PRUNED_COMPONENTS,
    )
    .contains(&name)
}

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

/// A descriptor-bounded UTF-8 prefix. `truncated` means the source contains more bytes; callers
/// must refuse an unterminated grammar rather than treating that prefix as a complete document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePrefix {
    pub text: String,
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
    let mut limited = file.take(max_bytes.saturating_add(1) as u64);
    let mut prefix = vec![0_u8; max_bytes.saturating_add(1).min(8 * 1024)];
    let prefix_bytes = limited
        .read(&mut prefix)
        .map_err(|error| SourceError::new(path, format!("cannot read source: {error}")))?;
    if prefix[..prefix_bytes].contains(&0) {
        return Err(SourceError::new(path, "source has a binary NUL prefix"));
    }
    bytes.extend_from_slice(&prefix[..prefix_bytes]);
    limited
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

/// Read only the first `max_bytes` of an optional source through the same no-follow boundary as
/// [`read_bounded_utf8`]. This is for metadata-first formats whose body is deliberately lazy. A
/// valid file may be larger than the prefix ceiling; the returned `truncated` bit makes that fact
/// explicit. An UTF-8 code point split exactly at the ceiling is refused rather than repaired.
pub fn read_bounded_utf8_prefix(
    root: &Path,
    path: &Path,
    max_bytes: usize,
    scope: SourceScope,
) -> Result<Option<SourcePrefix>, SourceError> {
    let Some(resolved) = resolve_file(root, path, scope)? else {
        return Ok(None);
    };
    let before = resolved.metadata;
    if !before.is_file() {
        return Err(SourceError::new(path, "source is not a regular file"));
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

    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1).min(16 * 1024));
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| SourceError::new(path, format!("cannot read source prefix: {error}")))?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    if bytes.contains(&0) {
        return Err(SourceError::new(path, "source has a binary NUL prefix"));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| SourceError::new(path, "source prefix is not valid UTF-8"))?;
    Ok(Some(SourcePrefix { text, truncated }))
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

    #[test]
    fn fair_path_admission_reaches_late_strata_and_prefers_small_files() {
        let base = PathBuf::from("repo");
        let candidates = vec![
            (base.join("a-early/large.rs"), 5),
            (base.join("a-early/small.rs"), 2),
            (base.join("b-middle/only.rs"), 2),
            (base.join("z-late/only.rs"), 2),
        ];
        let admitted = admit_paths_fair(&base, candidates.clone(), 3, 6);

        assert_eq!(
            admitted.admitted,
            vec![
                base.join("a-early/small.rs"),
                base.join("b-middle/only.rs"),
                base.join("z-late/only.rs"),
            ]
        );
        assert_eq!(admitted.eligible_files, 4);
        assert_eq!(admitted.eligible_bytes, 11);
        assert_eq!(admitted.admitted_bytes, 6);
        assert_eq!(admitted.coverage[0].path, base.join("a-early"));
        assert!(!admitted.coverage[0].is_complete());
        assert!(!admitted.coverage_truncated);

        let mut reversed = candidates;
        reversed.reverse();
        assert_eq!(
            admit_paths_fair(&base, reversed, 3, 6),
            admitted,
            "candidate enumeration order must not affect admission"
        );

        let unequal = (0..9)
            .map(|index| (base.join(format!("light/{index}.rs")), 1))
            .chain([(base.join("heavy/0.rs"), 6), (base.join("heavy/1.rs"), 6)])
            .collect();
        let unequal = admit_paths_fair(&base, unequal, 20, 15);
        let light = unequal
            .coverage
            .iter()
            .find(|coverage| coverage.path == base.join("light"))
            .unwrap();
        let heavy = unequal
            .coverage
            .iter()
            .find(|coverage| coverage.path == base.join("heavy"))
            .unwrap();
        assert_eq!((light.admitted_files, light.admitted_bytes), (9, 9));
        assert_eq!((heavy.admitted_files, heavy.admitted_bytes), (1, 6));
        assert_eq!(unequal.admitted_bytes, 15);
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
