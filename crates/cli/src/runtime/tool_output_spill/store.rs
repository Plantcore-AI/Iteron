use super::{
    ManagedToolResult, ToolOutputSpillCleanup, ToolOutputSpillError, ToolOutputSpillPolicy,
};
use iteron_protocol::{RunId, Seq, TenantId, ToolResult};
use iteron_record::{
    MAX_PRIVATE_CONTENT_BYTES, PrivateContentClass, PrivateContentDerivativeStore,
    PrivateContentHandle, PrivateContentNamespace, PrivateContentRetention,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const SHA256_BYTES: usize = 32;
const SPILL_SEQUENCE_BASE: u64 = 1_u64 << 63;

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

#[derive(Debug)]
struct SpillEntry {
    chunks: Vec<(Seq, PrivateContentHandle)>,
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
    private: PrivateContentDerivativeStore,
    next_sequence: AtomicU64,
    state: Mutex<SpillState>,
    cleanup_on_drop: bool,
    #[cfg(test)]
    test_root: Option<PathBuf>,
}

impl ToolOutputSpillStore {
    /// Open the spill owner on the same tenant/run content graph as the durable record.
    ///
    /// Raw oversized output is one bounded primary private artifact behind the record CAS, and
    /// the preview marker exposes that exact whole-value digest. Exact-session deletion and
    /// content revocation therefore share the same owner lock and tombstone authority instead of
    /// leaving an unrelated plaintext file in the system temporary directory.
    pub(crate) fn create_for_run(
        policy: ToolOutputSpillPolicy,
        runs_dir: &Path,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Self, ToolOutputSpillError> {
        let private = PrivateContentDerivativeStore::open_registered(
            runs_dir,
            tenant,
            run,
            PrivateContentNamespace::ToolArtifact,
            PrivateContentClass::ToolOutput,
            PrivateContentRetention::Session,
            MAX_PRIVATE_CONTENT_BYTES,
        )
        .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        Ok(Self {
            policy,
            private,
            next_sequence: AtomicU64::new(SPILL_SEQUENCE_BASE),
            state: Mutex::new(SpillState::default()),
            cleanup_on_drop: true,
            #[cfg(test)]
            test_root: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn create(policy: ToolOutputSpillPolicy) -> Result<Self, ToolOutputSpillError> {
        static STORE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = STORE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "core-tool-output-spill-test-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&root).map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
        }
        let mut store = Self::create_for_run(
            policy,
            &root,
            TenantId::default(),
            RunId(format!("tool-output-spill-test-{sequence}")),
        )?;
        store.test_root = Some(root);
        Ok(store)
    }

    /// Replace an oversized result with a bounded prefix and opaque durable handle. Storage
    /// failures become a fixed, content-free tool error so neither an I/O path nor the discarded
    /// raw result can leak into the record/model boundary.
    pub(crate) fn apply(&self, mut result: ToolResult) -> ManagedToolResult {
        if result.content.len() <= self.policy.memory_threshold_bytes() {
            return ManagedToolResult::unspilled(result);
        }

        let original_bytes = result.content.len();
        let advertised = ToolOutputSpillHandle::for_content(result.content.as_bytes());
        let marker = format!(
            "\n[tool output spill {advertised} bytes={original_bytes} cleanup={}]",
            self.policy.cleanup().label(),
        );
        if marker.len() > self.policy.memory_threshold_bytes() {
            // A truncated digest is not an opaque handle: it cannot be dereferenced or revoked.
            // Refuse publication before writing the CAS rather than emitting a marker that names
            // no durable target.
            result.content = bounded_control_text(
                "[tool output withheld: spill handle exceeds preview bound]",
                self.policy.memory_threshold_bytes(),
            );
            result.is_error = true;
            return ManagedToolResult::unspilled(result);
        }
        match self.retain(result.content.as_bytes()) {
            Ok(RetainOutcome::Retained(lease)) => {
                debug_assert_eq!(lease.handle, advertised);
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
                let notice = format!(
                    "[tool output withheld bytes={original_bytes}: private spill capacity exhausted; cleanup={}]",
                    self.policy.cleanup().label(),
                );
                // The store cannot retain the exact bytes, so no portion of the untrusted raw
                // value may cross the model/record boundary. A prefix would be irreversible and
                // would have neither a dereferenceable handle nor a revocation target.
                result.content =
                    bounded_control_text(&notice, self.policy.memory_threshold_bytes());
                result.is_error = true;
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
        remove_entry(&self.private, &mut state, lease.handle)
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
            if remove_entry(&self.private, &mut state, handle).is_err() {
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
        let mut bytes = Vec::with_capacity(entry.bytes);
        for (seq, chunk) in &entry.chunks {
            let next = self
                .private
                .read_at(*seq, chunk)
                .map_err(|_| ToolOutputSpillError::StorageUnavailable)?;
            bytes.extend_from_slice(&next);
        }
        if bytes.len() != entry.bytes || ToolOutputSpillHandle::for_content(&bytes) != handle {
            return Err(ToolOutputSpillError::StorageUnavailable);
        }
        Ok(bytes)
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
        if content.len() > MAX_PRIVATE_CONTENT_BYTES || next_bytes > self.policy.spill_max_bytes() {
            return Ok(RetainOutcome::CapacityExceeded);
        }

        // One marker must name one durable revocation target. Never advertise a digest for a
        // virtual concatenation whose actual CAS references are unrelated chunk digests: a caller
        // revoking the visible marker would otherwise receive TargetNotFound. Values beyond the
        // record CAS bound are withheld instead of being published under a misleading handle.
        let seq = Seq(self.next_sequence.fetch_add(1, Ordering::Relaxed));
        let chunk = match self.private.put(seq, content) {
            Ok(chunk) => chunk,
            Err(_) => return Err(ToolOutputSpillError::StorageUnavailable),
        };
        if chunk.digest.as_str() != handle.to_string() {
            let _ = self.private.release(seq, &chunk.digest);
            return Err(ToolOutputSpillError::StorageUnavailable);
        }
        match self.private.read_at(seq, &chunk) {
            Ok(published) if published == content => {}
            _ => {
                let _ = self.private.release(seq, &chunk.digest);
                return Err(ToolOutputSpillError::StorageUnavailable);
            }
        }

        state.retained_bytes = next_bytes;
        state.files.insert(
            handle,
            SpillEntry {
                chunks: vec![(seq, chunk)],
                bytes: content.len(),
                leases: 1,
            },
        );
        Ok(RetainOutcome::Retained(ToolOutputSpillLease { handle }))
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
        self.private.runs_dir().to_path_buf()
    }

    #[cfg(all(test, unix))]
    pub(super) fn artifact_path(&self, handle: &str) -> Option<PathBuf> {
        let _ = ToolOutputSpillHandle::parse(handle)?;
        None
    }

    #[cfg(test)]
    pub(super) fn abandon_for_recovery(mut self) -> Option<PathBuf> {
        self.cleanup_on_drop = false;
        self.test_root.take()
    }
}

fn remove_entry(
    private: &PrivateContentDerivativeStore,
    state: &mut SpillState,
    handle: ToolOutputSpillHandle,
) -> Result<(), ToolOutputSpillError> {
    let Some(entry) = state.files.remove(&handle) else {
        return Ok(());
    };
    let bytes = entry.bytes;
    state.retained_bytes = state.retained_bytes.saturating_sub(bytes);
    let mut failed = false;
    for (seq, chunk) in entry.chunks {
        if private.release(seq, &chunk.digest).is_err() {
            failed = true;
        }
    }
    if failed {
        return Err(ToolOutputSpillError::StorageUnavailable);
    }
    Ok(())
}

impl Drop for ToolOutputSpillStore {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let files = std::mem::take(&mut state.files);
        state.retained_bytes = 0;
        for (_, entry) in files {
            for (seq, chunk) in entry.chunks {
                let _ = self.private.release(seq, &chunk.digest);
            }
        }
        #[cfg(test)]
        if let Some(root) = self.test_root.take() {
            let _ = std::fs::remove_dir_all(root);
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
