use super::{
    ManagedToolResult, ToolOutputSpillCleanup, ToolOutputSpillError, ToolOutputSpillPolicy,
};
use core_protocol::ToolResult;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const SHA256_BYTES: usize = 32;
const MAX_TEMP_CREATE_ATTEMPTS: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ToolOutputSpillHandle([u8; SHA256_BYTES]);

impl ToolOutputSpillHandle {
    fn for_content(content: &[u8]) -> Self {
        Self(Sha256::digest(content).into())
    }

    fn parse(value: &str) -> Option<Self> {
        let hex = value.strip_prefix("sha256:")?;
        if hex.len() != SHA256_BYTES * 2 {
            return None;
        }
        let mut bytes = [0_u8; SHA256_BYTES];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Some(Self(bytes))
    }

    fn file_name(self) -> String {
        let mut name = String::with_capacity("spill-".len() + (SHA256_BYTES * 2) + ".bin".len());
        name.push_str("spill-");
        push_hex(&mut name, &self.0);
        name.push_str(".bin");
        name
    }
}

impl fmt::Display for ToolOutputSpillHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
}

#[derive(Debug)]
struct SpillEntry {
    path: PathBuf,
    bytes: usize,
    leases: usize,
}

#[derive(Debug, Default)]
struct SpillState {
    retained_bytes: usize,
    files: BTreeMap<ToolOutputSpillHandle, SpillEntry>,
}

/// Opaque ownership token for one retained result. It never contains or exposes a filesystem path.
#[derive(Debug)]
pub(crate) struct ToolOutputSpillLease {
    handle: ToolOutputSpillHandle,
}

enum RetainOutcome {
    Retained(ToolOutputSpillLease),
    CapacityExceeded,
}

/// A run/session-private store. The only public locator is a content digest; path construction and
/// dereference remain inside this owner.
pub(crate) struct ToolOutputSpillStore {
    policy: ToolOutputSpillPolicy,
    root: PathBuf,
    next_temporary: AtomicU64,
    state: Mutex<SpillState>,
}

impl ToolOutputSpillStore {
    pub(crate) fn create(policy: ToolOutputSpillPolicy) -> Result<Self, ToolOutputSpillError> {
        static STORE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..MAX_TEMP_CREATE_ATTEMPTS {
            let sequence = STORE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let root = base.join(format!(
                "core-tool-output-spill-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    if sync_directory(&base).is_err() {
                        let _ = std::fs::remove_dir(&root);
                        return Err(ToolOutputSpillError::StorageUnavailable);
                    }
                    return Ok(Self {
                        policy,
                        root,
                        next_temporary: AtomicU64::new(1),
                        state: Mutex::new(SpillState::default()),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ToolOutputSpillError::StorageUnavailable),
            }
        }
        Err(ToolOutputSpillError::StorageUnavailable)
    }

    /// Replace an oversized result with a bounded prefix and opaque durable handle. Storage
    /// failures become a fixed, content-free tool error so neither an I/O path nor the discarded
    /// raw result can leak into the record/model boundary.
    pub(crate) fn apply(&self, mut result: ToolResult) -> ManagedToolResult {
        if result.content.len() <= self.policy.memory_threshold_bytes() {
            return ManagedToolResult::unspilled(result);
        }

        let original_bytes = result.content.len();
        match self.retain(result.content.as_bytes()) {
            Ok(RetainOutcome::Retained(lease)) => {
                let marker = format!(
                    "\n[tool output spill {} bytes={original_bytes} cleanup={}]",
                    lease.handle,
                    self.policy.cleanup().label(),
                );
                result.content = bounded_preview(
                    &result.content,
                    &marker,
                    self.policy.memory_threshold_bytes(),
                );
                ManagedToolResult {
                    result,
                    lease: Some(lease),
                    spilled: true,
                }
            }
            Ok(RetainOutcome::CapacityExceeded) => {
                let marker = format!(
                    "\n[tool output omitted bytes={original_bytes}: private spill capacity exhausted; cleanup={}]",
                    self.policy.cleanup().label(),
                );
                result.content = bounded_preview(
                    &result.content,
                    &marker,
                    self.policy.memory_threshold_bytes(),
                );
                ManagedToolResult::unspilled(result)
            }
            Err(_) => {
                result.content = bounded_control_text(
                    "[tool output withheld: private spill storage unavailable]",
                    self.policy.memory_threshold_bytes(),
                );
                result.is_error = true;
                ManagedToolResult::unspilled(result)
            }
        }
    }

    /// Remove the artifact owned by one completed tool when the policy is `tool_end`. Identical
    /// concurrent outputs share a file and hold separate leases, so the first completion cannot
    /// delete bytes still owned by the second.
    pub(crate) fn cleanup_tool(
        &self,
        lease: &mut Option<ToolOutputSpillLease>,
    ) -> Result<(), ToolOutputSpillError> {
        if self.policy.cleanup() != ToolOutputSpillCleanup::ToolEnd {
            return Ok(());
        }
        let Some(lease) = lease.take() else {
            return Ok(());
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        let Some(entry) = state.files.get_mut(&lease.handle) else {
            return Ok(());
        };
        if entry.leases > 1 {
            entry.leases -= 1;
            return Ok(());
        }
        remove_entry(&self.root, &mut state, lease.handle)
    }

    /// Later lifecycle boundaries also clean an earlier configured scope. This is the fail-closed
    /// crash/recovery rule: a missed `turn_end` never permits retention past `run_end` or Drop.
    pub(crate) fn cleanup(
        &self,
        boundary: ToolOutputSpillCleanup,
    ) -> Result<(), ToolOutputSpillError> {
        if !self.policy.cleanup().reached_by(boundary) {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        let handles = state.files.keys().copied().collect::<Vec<_>>();
        let mut failed = false;
        for handle in handles {
            if remove_entry(&self.root, &mut state, handle).is_err() {
                failed = true;
            }
        }
        if failed {
            Err(ToolOutputSpillError::StorageUnavailable)
        } else {
            Ok(())
        }
    }

    /// Resolve an opaque handle only against this exact session owner. The caller receives bounded
    /// bytes, never the backing path, and a handle minted by another store is simply absent.
    #[allow(
        dead_code,
        reason = "private handle retrieval is the production artifact seam"
    )]
    pub(crate) fn read_private(&self, handle: &str) -> Result<Vec<u8>, ToolOutputSpillError> {
        let handle =
            ToolOutputSpillHandle::parse(handle).ok_or(ToolOutputSpillError::UnknownHandle)?;
        let state = self
            .state
            .lock()
            .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        let entry = state
            .files
            .get(&handle)
            .ok_or(ToolOutputSpillError::UnknownHandle)?;
        std::fs::read(&entry.path).map_err(|_| ToolOutputSpillError::StorageUnavailable)
    }

    fn retain(&self, content: &[u8]) -> Result<RetainOutcome, ToolOutputSpillError> {
        let handle = ToolOutputSpillHandle::for_content(content);
        let mut state = self
            .state
            .lock()
            .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        if let Some(entry) = state.files.get_mut(&handle) {
            entry.leases = entry
                .leases
                .checked_add(1)
                .ok_or(ToolOutputSpillError::StorageUnavailable)?;
            return Ok(RetainOutcome::Retained(ToolOutputSpillLease { handle }));
        }
        let Some(next_bytes) = state.retained_bytes.checked_add(content.len()) else {
            return Ok(RetainOutcome::CapacityExceeded);
        };
        if next_bytes > self.policy.spill_max_bytes() {
            return Ok(RetainOutcome::CapacityExceeded);
        }

        let path = self.root.join(handle.file_name());
        let (temporary_path, mut temporary) = self.create_temporary()?;
        let publish = (|| -> std::io::Result<()> {
            temporary.write_all(content)?;
            temporary.flush()?;
            temporary.sync_all()?;
            drop(temporary);
            std::fs::hard_link(&temporary_path, &path)?;
            std::fs::remove_file(&temporary_path)?;
            sync_directory(&self.root)
        })();
        if publish.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
            let _ = std::fs::remove_file(&path);
            let _ = sync_directory(&self.root);
            return Err(ToolOutputSpillError::StorageUnavailable);
        }

        state.retained_bytes = next_bytes;
        state.files.insert(
            handle,
            SpillEntry {
                path,
                bytes: content.len(),
                leases: 1,
            },
        );
        Ok(RetainOutcome::Retained(ToolOutputSpillLease { handle }))
    }

    fn create_temporary(&self) -> Result<(PathBuf, File), ToolOutputSpillError> {
        let first = self
            .next_temporary
            .fetch_add(MAX_TEMP_CREATE_ATTEMPTS, Ordering::Relaxed);
        for offset in 0..MAX_TEMP_CREATE_ATTEMPTS {
            let path = self.root.join(format!(
                ".spill-{}-{}.tmp",
                std::process::id(),
                first.saturating_add(offset)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ToolOutputSpillError::StorageUnavailable),
            }
        }
        Err(ToolOutputSpillError::StorageUnavailable)
    }

    #[cfg(test)]
    pub(super) fn retained_bytes(&self) -> usize {
        self.state.lock().unwrap().retained_bytes
    }

    #[cfg(test)]
    pub(super) fn retained_count(&self) -> usize {
        self.state.lock().unwrap().files.len()
    }

    #[cfg(test)]
    pub(super) fn root(&self) -> PathBuf {
        self.root.clone()
    }

    #[cfg(all(test, unix))]
    pub(super) fn artifact_path(&self, handle: &str) -> Option<PathBuf> {
        let handle = ToolOutputSpillHandle::parse(handle)?;
        self.state
            .lock()
            .ok()?
            .files
            .get(&handle)
            .map(|entry| entry.path.clone())
    }
}

fn remove_entry(
    root: &std::path::Path,
    state: &mut SpillState,
    handle: ToolOutputSpillHandle,
) -> Result<(), ToolOutputSpillError> {
    let Some(entry) = state.files.get(&handle) else {
        return Ok(());
    };
    match std::fs::remove_file(&entry.path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ToolOutputSpillError::StorageUnavailable),
    }
    let bytes = entry.bytes;
    state.files.remove(&handle);
    state.retained_bytes = state.retained_bytes.saturating_sub(bytes);
    sync_directory(root).map_err(|_| ToolOutputSpillError::StorageUnavailable)
}

impl Drop for ToolOutputSpillStore {
    fn drop(&mut self) {
        let parent = self.root.parent().map(std::path::Path::to_path_buf);
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, entry) in std::mem::take(&mut state.files) {
            let _ = std::fs::remove_file(entry.path);
        }
        if std::fs::remove_dir(&self.root).is_ok()
            && let Some(parent) = parent
        {
            let _ = sync_directory(&parent);
        }
    }
}

fn bounded_preview(content: &str, marker: &str, maximum_bytes: usize) -> String {
    if marker.len() >= maximum_bytes {
        return utf8_prefix(marker, maximum_bytes).to_owned();
    }
    let prefix = utf8_prefix(content, maximum_bytes - marker.len());
    format!("{prefix}{marker}")
}

fn bounded_control_text(content: &str, maximum_bytes: usize) -> String {
    utf8_prefix(content, maximum_bytes).to_owned()
}

fn utf8_prefix(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(unix)]
fn sync_directory(path: &std::path::Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}
