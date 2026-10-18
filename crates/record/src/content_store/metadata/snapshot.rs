//! Reclaim overwritten metadata and deletion history without weakening the committed prefix.

use super::*;

const SNAPSHOT_FRAME_BYTES: usize = 1024 * 1024;

#[cfg(test)]
std::thread_local! {
    pub(super) static EXIT_AT_REPLACE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

impl Index {
    pub(super) fn compact(&mut self, scope: &Path) -> io::Result<()> {
        // Atomic replacement changes the log identity. Never append through the old descriptor.
        self.writer = None;
        self.lease_directories.clear();
        // Compaction may remove physical orphan lookups and replace the complete log. Counts
        // are projections: rebuild them from the resulting merged membership after this pass.
        self.reference_counts.clear();
        let mut retained = BTreeMap::new();
        let mut bytes = 0usize;
        let mut deleted = 0usize;
        for (relative, value) in &self.entries {
            let path = scope.join(relative);
            if value.is_none() && !physical_exists(&path)? {
                continue;
            }
            // Reclaim old direct lookups left by earlier writers only after proving the exact
            // reverse edge absent. A still-present legacy lookup is unlinked before omitting it.
            if let Some(value) = value
                && orphaned_lookup(scope, &self.entries, relative, value)?
            {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                continue;
            }
            bytes += relative.len().saturating_mul(2)
                + 128
                + value.as_ref().map_or(0, |value| value.len());
            deleted += usize::from(value.is_none());
            retained.insert(relative.clone(), value.clone());
        }
        let (scratch, mut file) = scratch_file(scope)?;
        let result = (|| {
            let written = write_snapshot(&mut file, &retained)?;
            let metadata = file.metadata()?;
            let observed = (metadata.len(), metadata.modified()?);
            drop(file);
            #[cfg(test)]
            EXIT_AT_REPLACE.with(|exit| {
                if exit.get() == Some(false) {
                    std::process::exit(77);
                }
            });
            // Every snapshot frame has reached the OS before rename. A process crash before
            // rename leaves the old log authoritative; a crash after it exposes the whole new
            // snapshot. Power-loss survival is deliberately outside ordinary publication.
            std::fs::rename(&scratch, scope.join(LOG_NAME))?;
            #[cfg(test)]
            EXIT_AT_REPLACE.with(|exit| {
                if exit.get() == Some(true) {
                    std::process::exit(78);
                }
            });
            self.entries = retained;
            self.bytes = bytes;
            self.deleted = deleted;
            self.offset = written;
            self.observed = Some(observed);
            self.initialized = true;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                self.identity = Some((metadata.dev(), metadata.ino()));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(scratch);
        }
        result
    }
}

fn physical_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn orphaned_lookup(
    scope: &Path,
    entries: &BTreeMap<String, Option<Arc<[u8]>>>,
    relative: &str,
    value: &[u8],
) -> io::Result<bool> {
    let Some(suffix) = relative.strip_prefix("run-ref-lookup/") else {
        return Ok(false);
    };
    let Some((owner, _)) = suffix.split_once('/') else {
        return Err(invalid("invalid metadata lookup path"));
    };
    if value.len() != 64 || !value.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("invalid metadata lookup value"));
    }
    let id = std::str::from_utf8(value).map_err(io::Error::other)?;
    let reverse = format!("run-refs/{owner}/{id}.json");
    match entries.get(&reverse) {
        Some(value) => Ok(value.is_none()),
        None => Ok(!physical_exists(&scope.join(reverse))?),
    }
}

fn scratch_file(scope: &Path) -> io::Result<(PathBuf, File)> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..16 {
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scratch = scope.join(format!(
            ".metadata-snapshot-{}-{serial}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&scratch) {
            Ok(file) => return Ok((scratch, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "metadata snapshot scratch paths exhausted",
    ))
}

fn write_snapshot(
    file: &mut File,
    entries: &BTreeMap<String, Option<Arc<[u8]>>>,
) -> io::Result<u64> {
    let mut payload = vec![b'['];
    let mut written = 0u64;
    for (path, value) in entries {
        let mutation = Mutation {
            paths: vec![path.clone()],
            value: value.as_ref().map(|value| value.to_vec()),
        };
        let encoded = serde_json::to_vec(&mutation).map_err(io::Error::other)?;
        if payload.len() + encoded.len() + 2 > SNAPSHOT_FRAME_BYTES {
            payload.push(b']');
            written += write_frame(file, &payload)?;
            payload.clear();
            payload.push(b'[');
        }
        if payload.len() > 1 {
            payload.push(b',');
        }
        payload.extend_from_slice(&encoded);
    }
    if payload.len() > 1 {
        payload.push(b']');
        written += write_frame(file, &payload)?;
    }
    if written > MAX_LOG_BYTES {
        return Err(invalid("metadata snapshot exceeds its bound"));
    }
    Ok(written)
}

fn write_frame(file: &mut File, payload: &[u8]) -> io::Result<u64> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(invalid("metadata snapshot frame exceeds its bound"));
    }
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    header.extend_from_slice(&Sha256::digest(payload));
    file.write_all(&header)?;
    file.write_all(payload)?;
    Ok((header.len() + payload.len()) as u64)
}
