//! Compact authoritative reference/lineage storage. All access is protected by the tenant's
//! store lock. Complete checksummed frames are the commit unit; only an incomplete final frame
//! is discarded. A successful append acknowledges OS writes, not survival of power loss.
//!
//! Keys and ciphertext deliberately remain separate: an append log must never retain an erased
//! encryption key. Legacy metadata files are merged on read and overridden by logged mutations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

const LOG_NAME: &str = "metadata-v2.log";
const MAGIC: &[u8; 8] = b"ITMETA02";
const HEADER_BYTES: usize = 44;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_INDEX_ENTRIES: usize = 500_000;
const MAX_CACHED_STORES: usize = 4;
const MAX_DIRECTORY_ENTRIES: usize = 100_001;
const MAX_LEASE_DIRECTORY_FACTS: usize = 128;
const COMPACT_LOG_BYTES: u64 = 8 * 1024 * 1024;
const COMPACT_DELETED_ENTRIES: usize = 4_096;

mod counts;
mod snapshot;
pub(super) use counts::reference_count;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    paths: Vec<String>,
    value: Option<Vec<u8>>,
}

#[derive(Default)]
struct Index {
    entries: BTreeMap<String, Option<Arc<[u8]>>>,
    reference_counts: std::collections::HashMap<String, counts::ReferenceCount>,
    lease_directories: std::collections::HashMap<String, bool>,
    bytes: usize,
    offset: u64,
    observed: Option<(u64, std::time::SystemTime)>,
    initialized: bool,
    write_lease: bool,
    writer: Option<File>,
    deleted: usize,
    #[cfg(unix)]
    identity: Option<(u64, u64)>,
}

type CachedIndexes = BTreeMap<PathBuf, Arc<Mutex<Index>>>;
static INDEXES: OnceLock<Mutex<CachedIndexes>> = OnceLock::new();

#[cfg(test)]
std::thread_local! {
    static FAIL_COMMITTED_STAMP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LOG_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DIRECTORY_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LEGACY_MEMBER_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn missing() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "private content metadata missing")
}

fn open_log(scope: &Path, writable: bool, create: bool) -> io::Result<(File, std::fs::Metadata)> {
    #[cfg(test)]
    LOG_OPENS.with(|opens| opens.set(opens.get() + 1));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(scope.join(LOG_NAME))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "private content metadata log is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("private content metadata log has multiple links"));
        }
    }
    Ok((file, metadata))
}

fn acquire_index(scope: &Path) -> io::Result<(Arc<Mutex<Index>>, bool)> {
    let index = {
        let mut stores = INDEXES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invalid("private content metadata cache poisoned"))?;
        if !stores.contains_key(scope) {
            if stores.len() >= MAX_CACHED_STORES {
                let evict = stores
                    .iter()
                    .find(|(_, index)| Arc::strong_count(index) == 1)
                    .map(|(path, _)| path.clone());
                if let Some(evict) = evict {
                    stores.remove(&evict);
                }
            }
            if stores.len() < MAX_CACHED_STORES {
                stores.insert(scope.to_path_buf(), Arc::new(Mutex::new(Index::default())));
            }
        }
        // Cache pressure must not reject an otherwise valid write. An uncached index is bounded
        // by the same per-store limits and this synchronous caller's lifetime. The actual OS
        // store lock still excludes competing writers; concurrent shared readers may each replay
        // a private index safely. Existing registered indexes always reuse their one Arc.
        match stores.get(scope) {
            Some(index) => (index.clone(), true),
            None => (Arc::new(Mutex::new(Index::default())), false),
        }
    };
    Ok(index)
}

fn with_index<T>(scope: &Path, f: impl FnOnce(&mut Index) -> io::Result<T>) -> io::Result<T> {
    let (index, _) = acquire_index(scope)?;
    let mut index = index
        .lock()
        .map_err(|_| invalid("private content metadata index poisoned"))?;
    if !index.initialized {
        index.refresh(scope, false)?;
        index.initialized = true;
    }
    f(&mut index)
}

/// Pins the optional cache and writable descriptor for exactly one exclusive OS store lease.
/// Under cache pressure path-based operations retain their existing uncached fallback rather
/// than retaining an unused index or rejecting a valid store operation.
pub(super) struct WriteLease {
    index: Option<Arc<Mutex<Index>>>,
}

pub(super) fn write_lease(scope: &Path) -> io::Result<WriteLease> {
    let (index, cached) = acquire_index(scope)?;
    {
        let mut value = index
            .lock()
            .map_err(|_| invalid("private content metadata index poisoned"))?;
        if value.write_lease {
            return Err(invalid("private content metadata writer already leased"));
        }
        let writer = value.refresh_open(scope, true)?;
        value.initialized = true;
        if cached {
            value.lease_directories.clear();
            value.writer = writer;
            value.write_lease = true;
        }
    }
    // Uncached path-based operations replay privately as before. Do not retain an unused second
    // bounded index for their full operation lifetime under cache pressure.
    Ok(WriteLease {
        index: cached.then_some(index),
    })
}

impl Drop for WriteLease {
    fn drop(&mut self) {
        let Some(index) = &self.index else {
            return;
        };
        let mut index = index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(file) = index.writer.take() {
            // A committed append remains successful if this optional cache observation fails.
            // The next lease then replays the full prefix before trusting any cached member.
            index.observed = committed_stamp(&file);
        }
        index.write_lease = false;
        index.lease_directories.clear();
    }
}

/// Called after acquiring the actual process-shared store lock, before observing any index.
pub(super) fn refresh(scope: &Path, writable: bool) -> io::Result<()> {
    let (index, _) = acquire_index(scope)?;
    let mut index = index
        .lock()
        .map_err(|_| invalid("private content metadata index poisoned"))?;
    index.refresh(scope, writable)?;
    index.initialized = true;
    Ok(())
}

impl Index {
    fn refresh(&mut self, scope: &Path, writable: bool) -> io::Result<()> {
        self.refresh_open(scope, writable).map(drop)
    }

    fn refresh_open(&mut self, scope: &Path, writable: bool) -> io::Result<Option<File>> {
        // Platforms without the Unix device/inode identity replay instead of trusting equal
        // length/timestamp metadata after an external file replacement.
        #[cfg(not(unix))]
        {
            *self = Self::default();
        }
        let (mut file, metadata) = match open_log(scope, writable, false) {
            Ok(opened) => opened,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                *self = Self::default();
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(unix)]
        {
            if self.identity.is_some_and(|old| old != identity) {
                *self = Self::default();
            }
            self.identity = Some(identity);
        }
        let stamp = (metadata.len(), metadata.modified()?);
        if stamp.0 > MAX_LOG_BYTES {
            return Err(invalid("private content metadata log exceeds its bound"));
        }
        if self.observed == Some(stamp) && self.offset == stamp.0 {
            if writable {
                file.seek(SeekFrom::Start(self.offset))?;
            }
            return Ok(Some(file));
        }
        // No production operation rewrites the prefix. A shrink or same-length replacement is
        // nevertheless replayed from scratch, so eviction/restart and maintenance agree.
        if (self.observed.is_none() && self.offset != 0)
            || stamp.0 < self.offset
            || self
                .observed
                .is_some_and(|old| old.0 == stamp.0 && old.1 != stamp.1)
        {
            *self = Self::default();
        }
        #[cfg(unix)]
        {
            self.identity = Some(identity);
        }
        file.seek(SeekFrom::Start(self.offset))?;
        while self.offset < stamp.0 {
            if stamp.0 - self.offset < HEADER_BYTES as u64 {
                break;
            }
            let mut header = [0u8; HEADER_BYTES];
            file.read_exact(&mut header)?;
            if &header[..8] != MAGIC {
                return Err(invalid("invalid private content metadata frame"));
            }
            let length = u32::from_le_bytes(header[8..12].try_into().expect("four bytes")) as usize;
            if length > MAX_FRAME_BYTES {
                return Err(invalid("private content metadata frame exceeds its bound"));
            }
            if stamp.0 - self.offset - (HEADER_BYTES as u64) < length as u64 {
                break;
            }
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes)?;
            if Sha256::digest(&bytes)[..] != header[12..] {
                return Err(invalid("private content metadata checksum mismatch"));
            }
            let mutations: Vec<Mutation> =
                serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            self.preflight(&mutations)?;
            self.apply(scope, mutations);
            self.offset += (HEADER_BYTES + length) as u64;
        }
        self.observed = Some(stamp);
        if writable {
            if self.offset < stamp.0 {
                file.set_len(self.offset)?;
                self.observed = committed_stamp(&file);
            }
            file.seek(SeekFrom::Start(self.offset))?;
        }
        Ok(Some(file))
    }

    fn preflight(&self, mutations: &[Mutation]) -> io::Result<()> {
        validate_mutations(mutations)?;
        let mut changed = BTreeMap::<&str, Option<&[u8]>>::new();
        for mutation in mutations {
            for path in &mutation.paths {
                changed.insert(path, mutation.value.as_deref());
            }
        }
        let mut bytes = self.bytes;
        let mut entries = self.entries.len();
        for (path, value) in changed {
            if let Some(previous) = self.entries.get(path) {
                bytes = bytes.saturating_sub(previous.as_ref().map_or(0, |v| v.len()));
            } else {
                entries += 1;
                // Include map nodes, path storage, and allocation overhead in the bound.
                bytes = bytes.saturating_add(path.len().saturating_mul(2) + 128);
            }
            bytes = bytes.saturating_add(value.map_or(0, <[u8]>::len));
        }
        if bytes > MAX_INDEX_BYTES || entries > MAX_INDEX_ENTRIES {
            return Err(invalid("private content metadata index exceeds its bound"));
        }
        Ok(())
    }

    fn apply(&mut self, scope: &Path, mutations: Vec<Mutation>) {
        for mutation in mutations {
            let value = mutation.value.map(Arc::<[u8]>::from);
            for path in mutation.paths {
                self.update_reference_count(scope, &path, value.is_some());
                let previous = self.entries.insert(path.clone(), value.clone());
                if previous.as_ref().is_some_and(Option::is_none) {
                    self.deleted = self.deleted.saturating_sub(1);
                }
                if value.is_none() {
                    self.deleted += 1;
                }
                if let Some(previous) = previous {
                    self.bytes = self
                        .bytes
                        .saturating_sub(previous.as_ref().map_or(0, |v| v.len()));
                } else {
                    self.bytes += path.len().saturating_mul(2) + 128;
                }
                self.bytes += value.as_ref().map_or(0, |v| v.len());
            }
        }
    }
}

fn validate_mutations(mutations: &[Mutation]) -> io::Result<()> {
    for mutation in mutations {
        if mutation.paths.is_empty()
            || mutation
                .value
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
        {
            return Err(invalid("invalid private content metadata mutation"));
        }
        for path in &mutation.paths {
            validate_relative(path)?;
        }
    }
    Ok(())
}

fn validate_relative(path: &str) -> io::Result<()> {
    let mut parts = path.split('/');
    let (Some(family), Some(owner), Some(member), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("invalid private content metadata path"));
    };
    if !matches!(
        family,
        "refs" | "run-refs" | "run-ref-lookup" | "lineage-from" | "lineage-to"
    ) || [owner, member].iter().any(|part| {
        part.is_empty()
            || part.len() > 128
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            || *part == "."
            || *part == ".."
    }) {
        return Err(invalid("invalid private content metadata path"));
    }
    Ok(())
}

pub(super) fn location(path: &Path) -> Option<(PathBuf, String)> {
    let mut components = path.components();
    // Normal metadata paths contain only the family, owner and member after the scope. Keep
    // those borrowed names on the stack, and walk the original path only once from its end.
    // Physical keys, blobs and state files allocate nothing while being ruled out here.
    let mut suffix = [""; 3];
    let mut suffix_len = 0;
    while let Some(component) = components.next_back() {
        let Component::Normal(name) = component else {
            return None;
        };
        let name = name.to_str()?;
        if suffix_len < suffix.len() {
            suffix[suffix_len] = name;
        }
        suffix_len += 1;
        if !matches!(
            name,
            "refs" | "run-refs" | "run-ref-lookup" | "lineage-from" | "lineage-to"
        ) {
            continue;
        }
        let scope = components.as_path();
        if scope.parent()?.file_name()? != "v1"
            || scope.parent()?.parent()?.file_name()? != ".content"
        {
            continue;
        }
        if suffix_len <= suffix.len() {
            let names = &suffix[..suffix_len];
            let capacity = names.iter().map(|name| name.len()).sum::<usize>() + suffix_len - 1;
            let mut relative = String::with_capacity(capacity);
            for name in names.iter().rev() {
                if !relative.is_empty() {
                    relative.push('/');
                }
                relative.push_str(name);
            }
            return Some((scope.to_path_buf(), relative));
        }
        // Preserve the generic directory-reader behavior for deeper paths, including the
        // original component normalization and rejection of non-normal relative components.
        let relative = path.strip_prefix(scope).ok()?;
        let parts = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        return Some((scope.to_path_buf(), parts.join("/")));
    }
    None
}

/// Publish several logical index members in one atomic frame. The caller holds the exclusive
/// store lease. No filesystem projection is needed before a reference can be served or revoked.
pub(super) fn replace_batch(changes: &[(PathBuf, Option<Vec<u8>>)]) -> io::Result<()> {
    let Some((first, remaining)) = changes.split_first() else {
        return Ok(());
    };
    let (scope, relative) =
        location(&first.0).ok_or_else(|| invalid("metadata path missing scope"))?;
    let mut mutations = vec![Mutation {
        paths: vec![relative],
        value: first.1.clone(),
    }];
    for (path, value) in remaining {
        let (candidate, relative) =
            location(path).ok_or_else(|| invalid("metadata path missing scope"))?;
        if candidate != scope {
            return Err(invalid("cross-tenant metadata mutation"));
        }
        if let Some(last) = mutations.last_mut()
            && last.value == *value
        {
            last.paths.push(relative);
        } else {
            mutations.push(Mutation {
                paths: vec![relative],
                value: value.clone(),
            });
        }
    }
    validate_mutations(&mutations)?;
    with_index(&scope, |index| {
        let payload = serde_json::to_vec(&mutations).map_err(io::Error::other)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(invalid("private content metadata append exceeds its bound"));
        }
        let append_bytes = (HEADER_BYTES + payload.len()) as u64;
        let needs_reclaim = (index.offset >= COMPACT_LOG_BYTES
            && index.offset > (index.bytes as u64).saturating_mul(4))
            || (index.deleted >= COMPACT_DELETED_ENTRIES
                && index.deleted > index.entries.len() / 2);
        if needs_reclaim
            || index.preflight(&mutations).is_err()
            || index.offset.saturating_add(append_bytes) > MAX_LOG_BYTES
        {
            index.compact(&scope)?;
        }
        index.preflight(&mutations)?;
        if index.offset.saturating_add(append_bytes) > MAX_LOG_BYTES {
            return Err(invalid("private content metadata append exceeds its bound"));
        }
        let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&Sha256::digest(&payload));
        frame.extend_from_slice(&payload);
        let mut file = match index.writer.take() {
            Some(file) => file,
            None => {
                let (mut file, metadata) = open_log(&scope, true, true)?;
                // The exclusive acquisition already established the complete valid prefix.
                if metadata.len() != index.offset {
                    file.set_len(index.offset)?;
                }
                file.seek(SeekFrom::Start(index.offset))?;
                file
            }
        };
        index.observed = None;
        if let Err(error) = file.write_all(&frame) {
            // Discard the descriptor on failure. A later append reopens at the repaired prefix;
            // a failed repair remains an error and is reconciled on the next actual lease.
            file.set_len(index.offset)?;
            return Err(error);
        }
        index.apply(&scope, mutations);
        index.offset += frame.len() as u64;
        if index.write_lease {
            index.writer = Some(file);
        } else {
            // A complete frame is committed even if its optional cache stamp is unavailable.
            index.observed = committed_stamp(&file);
        }
        Ok(())
    })
}

fn committed_stamp(file: &File) -> Option<(u64, std::time::SystemTime)> {
    #[cfg(test)]
    if FAIL_COMMITTED_STAMP.with(std::cell::Cell::get) {
        return None;
    }
    let metadata = file.metadata().ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
}

pub(super) fn read(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    if let Some((scope, relative)) = location(path) {
        let value = with_index(&scope, |index| Ok(index.entries.get(&relative).cloned()))?;
        if let Some(value) = value {
            let value = value.ok_or_else(missing)?;
            if value.len() > max {
                return Err(invalid("private content metadata exceeds its bound"));
            }
            return Ok(value.to_vec());
        }
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(invalid("private content object exceeds its bound"));
    }
    Ok(bytes)
}

pub(super) fn is_file(path: &Path) -> io::Result<bool> {
    if let Some((scope, relative)) = location(path)
        && let Some(present) = with_index(&scope, |index| {
            if let Some(value) = index.entries.get(&relative) {
                return Ok(Some(value.is_some()));
            }
            // Log members override legacy files. For a missing member, one observation of its
            // absent legacy parent proves all child paths absent during this exclusive lease.
            if index.write_lease && validate_relative(&relative).is_ok() {
                let (directory, _) = relative.rsplit_once('/').expect("validated member path");
                let parent = path.parent().expect("validated member parent");
                if index.legacy_directory_absent(parent, directory)? {
                    return Ok(Some(false));
                }
            }
            Ok(None)
        })?
    {
        return Ok(present);
    }
    #[cfg(test)]
    LEGACY_MEMBER_PROBES.with(|probes| probes.set(probes.get() + 1));
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

impl Index {
    fn remember_legacy_directory(&mut self, relative: &str, absent: bool) {
        if self.write_lease
            && (self.lease_directories.len() < MAX_LEASE_DIRECTORY_FACTS
                || self.lease_directories.contains_key(relative))
        {
            self.lease_directories.insert(relative.to_owned(), absent);
        }
    }

    fn legacy_directory_absent(&mut self, path: &Path, relative: &str) -> io::Result<bool> {
        if let Some(absent) = self.lease_directories.get(relative) {
            return Ok(*absent);
        }
        #[cfg(test)]
        DIRECTORY_PROBES.with(|probes| probes.set(probes.get() + 1));
        let absent = match std::fs::metadata(path) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        self.remember_legacy_directory(relative, absent);
        Ok(absent)
    }
}

pub(super) struct Entry {
    path: PathBuf,
    kind: EntryKind,
}

#[derive(Clone, Copy)]
pub(super) enum EntryKind {
    File,
    Directory,
    Other,
}

impl EntryKind {
    pub(super) fn is_file(self) -> bool {
        matches!(self, Self::File)
    }
    pub(super) fn is_dir(self) -> bool {
        matches!(self, Self::Directory)
    }
}

impl Entry {
    pub(super) fn path(&self) -> PathBuf {
        self.path.clone()
    }
    pub(super) fn file_name(&self) -> OsString {
        self.path.file_name().unwrap_or_default().to_owned()
    }
    pub(super) fn file_type(&self) -> io::Result<EntryKind> {
        Ok(self.kind)
    }
}

pub(super) fn read_dir(
    path: impl AsRef<Path>,
) -> io::Result<std::vec::IntoIter<io::Result<Entry>>> {
    let path = path.as_ref();
    let mut entries = BTreeMap::new();
    let mut existed = false;
    match std::fs::read_dir(path) {
        Ok(physical) => {
            existed = true;
            for entry in physical.take(MAX_DIRECTORY_ENTRIES + 1) {
                let entry = entry?;
                let kind = entry.file_type()?;
                entries.insert(
                    entry.file_name(),
                    Entry {
                        path: entry.path(),
                        kind: if kind.is_file() {
                            EntryKind::File
                        } else if kind.is_dir() {
                            EntryKind::Directory
                        } else {
                            EntryKind::Other
                        },
                    },
                );
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(invalid("metadata directory exceeds its bound"));
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some((scope, relative)) = location(path) {
        let prefix = format!("{relative}/");
        with_index(&scope, |index| {
            for (key, value) in index.entries.range(prefix.clone()..) {
                let Some(suffix) = key.strip_prefix(&prefix) else {
                    break;
                };
                if let Some((directory, _)) = suffix.split_once('/') {
                    if value.is_some() {
                        existed = true;
                        entries.entry(OsString::from(directory)).or_insert(Entry {
                            path: path.join(directory),
                            kind: EntryKind::Directory,
                        });
                    }
                } else if value.is_some() {
                    existed = true;
                    entries.insert(
                        OsString::from(suffix),
                        Entry {
                            path: path.join(suffix),
                            kind: EntryKind::File,
                        },
                    );
                } else {
                    existed = true;
                    entries.remove(&OsString::from(suffix));
                }
                if entries.len() > MAX_DIRECTORY_ENTRIES {
                    return Err(invalid("metadata directory exceeds its bound"));
                }
            }
            Ok(())
        })?;
    }
    if !existed {
        return Err(missing());
    }
    Ok(entries
        .into_values()
        .map(Ok)
        .collect::<Vec<_>>()
        .into_iter())
}

pub(super) fn remove_empty_dir(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
