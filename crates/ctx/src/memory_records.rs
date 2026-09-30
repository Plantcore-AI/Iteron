//! Versioned reference facts. Location and relevance never confer instruction authority.
//! One bounded snapshot publishes body, provenance, scope and tombstones atomically.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io, path::Path};

mod file;
#[cfg(test)]
mod tests;

pub const MAX_RECORDS: usize = 1_024;
pub const MAX_RECORD_BODY_BYTES: usize = 8 * 1024;
pub const MAX_RECORD_SNAPSHOT_BYTES: usize = 12 * 1024 * 1024;
pub const DEFAULT_CONFIDENCE_PPM: u32 = 500_000;
pub const LEGACY_CONFIDENCE_PPM: u32 = 250_000;
const DEFAULT_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySourceKind {
    Operator,
    ToolResult,
    Imported,
    LegacyUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProvenance {
    pub kind: MemorySourceKind,
    /// A bounded source label/receipt, never an authorization statement.
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum MemoryRecordScope {
    Workspace {
        workspace_sha256: String,
    },
    /// This explicit write choice is required for cross-workspace visibility.
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPathEvidence {
    pub relative_path: String,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum MemoryInvalidation {
    ExpiresAt {
        unix_seconds: u64,
    },
    /// Operator explicitly retains the fact until a reviewed update/delete.
    ManualReview,
    UntilPathChanges,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecordDraft {
    pub provenance: MemoryProvenance,
    pub scope: MemoryRecordScope,
    pub confidence_ppm: u32,
    pub invalidation: MemoryInvalidation,
    pub path_evidence: Vec<MemoryPathEvidence>,
    pub created_unix_seconds: u64,
}

impl MemoryRecordDraft {
    pub fn workspace(workspace: &Path, source: &str, now: u64) -> io::Result<Self> {
        Ok(Self {
            provenance: MemoryProvenance {
                kind: MemorySourceKind::Operator,
                reference: source.into(),
            },
            scope: MemoryRecordScope::Workspace {
                workspace_sha256: workspace_digest(workspace)?,
            },
            confidence_ppm: DEFAULT_CONFIDENCE_PPM,
            invalidation: MemoryInvalidation::ExpiresAt {
                unix_seconds: now
                    .checked_add(DEFAULT_LIFETIME_SECONDS)
                    .ok_or_else(invalid)?,
            },
            path_evidence: Vec::new(),
            created_unix_seconds: now,
        })
    }
    /// Call only for an explicit global-memory write; the ordinary Add API uses workspace().
    pub fn explicit_global(source: &str, now: u64) -> io::Result<Self> {
        let mut draft = Self::workspace(Path::new("."), source, now)?;
        draft.scope = MemoryRecordScope::Global;
        Ok(draft)
    }
    pub fn bind_path(&mut self, workspace: &Path, relative_path: &str) -> io::Result<()> {
        if self.path_evidence.len() >= 8 {
            return Err(invalid());
        }
        let content_sha256 = path_digest(workspace, relative_path)?;
        self.path_evidence.push(MemoryPathEvidence {
            relative_path: relative_path.into(),
            content_sha256,
        });
        Ok(())
    }
    fn validate(&self) -> io::Result<()> {
        if self.provenance.reference.is_empty()
            || self.provenance.reference.len() > 512
            || crate::memory::suspicious_unicode(&self.provenance.reference)
            || self.confidence_ppm > 1_000_000
            || self.path_evidence.len() > 8
            || matches!(&self.scope, MemoryRecordScope::Workspace { workspace_sha256 } if !valid_digest(workspace_sha256))
            || matches!(self.invalidation, MemoryInvalidation::ExpiresAt { unix_seconds } if unix_seconds <= self.created_unix_seconds)
            || matches!(self.invalidation, MemoryInvalidation::UntilPathChanges)
                && self.path_evidence.is_empty()
        {
            return Err(invalid());
        }
        for path in &self.path_evidence {
            if !safe_relative(&path.relative_path) || !valid_digest(&path.content_sha256) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRecord {
    pub id: String,
    pub revision: u64,
    pub body: String,
    pub metadata: MemoryRecordDraft,
    pub deleted: bool,
}

/// Sealed host receipt: clients cannot deserialize or construct a record admission identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRecordReceipt {
    id: String,
    revision: u64,
    record_sha256: String,
    store_sha256: String,
    workspace_sha256: String,
}
impl MemoryRecordReceipt {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn record_sha256(&self) -> &str {
        &self.record_sha256
    }
    pub fn workspace_sha256(&self) -> &str {
        &self.workspace_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRecordExclusion {
    Deleted,
    Expired,
    ScopeDenied,
    StalePath,
    Invalid,
}

impl MemoryRecord {
    pub fn eligibility(
        &self,
        workspace: Option<&Path>,
        now: u64,
    ) -> Result<(), MemoryRecordExclusion> {
        if self.deleted {
            return Err(MemoryRecordExclusion::Deleted);
        }
        self.metadata
            .validate()
            .map_err(|_| MemoryRecordExclusion::Invalid)?;
        if let MemoryRecordScope::Workspace { workspace_sha256 } = &self.metadata.scope {
            if workspace
                .and_then(|root| workspace_digest(root).ok())
                .as_ref()
                != Some(workspace_sha256)
            {
                return Err(MemoryRecordExclusion::ScopeDenied);
            }
        }
        if matches!(self.metadata.invalidation, MemoryInvalidation::ExpiresAt { unix_seconds } if now >= unix_seconds)
        {
            return Err(MemoryRecordExclusion::Expired);
        }
        for evidence in &self.metadata.path_evidence {
            if workspace
                .and_then(|root| path_digest(root, &evidence.relative_path).ok())
                .as_ref()
                != Some(&evidence.content_sha256)
            {
                return Err(MemoryRecordExclusion::StalePath);
            }
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    revision: u64,
    records: BTreeMap<String, MemoryRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    snapshot: Snapshot,
}

/// Writer lease is acquired without waiting. Failed publication is unknown and never reported
/// as success. Reads take a bounded single snapshot and never need a writer lease.
pub struct MemoryRecordOwner {
    journal: file::Journal,
    snapshot: Snapshot,
}
impl MemoryRecordOwner {
    pub fn open(store_root: &Path) -> io::Result<Self> {
        let mut journal = file::Journal::open(store_root)?;
        let snapshot = decode(journal.load()?)?;
        Ok(Self { journal, snapshot })
    }
    pub fn read(store_root: &Path) -> io::Result<Vec<MemoryRecord>> {
        Ok(decode(file::read(store_root)?)?
            .records
            .into_values()
            .collect())
    }
    pub fn capture_receipt(
        store_root: &Path,
        workspace: &Path,
        id: &str,
        expected_body: &str,
    ) -> io::Result<MemoryRecordReceipt> {
        let record = Self::read(store_root)?
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(missing)?;
        record
            .eligibility(Some(workspace), now_unix_seconds())
            .map_err(|_| invalid())?;
        if record.body != expected_body.trim() {
            return Err(conflict());
        }
        Ok(MemoryRecordReceipt {
            id: id.into(),
            revision: record.revision,
            record_sha256: digest(&serde_json::to_vec(&record).map_err(|_| invalid())?),
            store_sha256: workspace_digest(store_root)?,
            workspace_sha256: workspace_digest(workspace)?,
        })
    }
    pub fn resolve_receipt(
        store_root: &Path,
        workspace: &Path,
        receipt: &MemoryRecordReceipt,
    ) -> io::Result<MemoryRecord> {
        if workspace_digest(store_root)? != receipt.store_sha256
            || workspace_digest(workspace)? != receipt.workspace_sha256
        {
            return Err(invalid());
        }
        let record = Self::read(store_root)?
            .into_iter()
            .find(|record| record.id == receipt.id)
            .ok_or_else(missing)?;
        record
            .eligibility(Some(workspace), now_unix_seconds())
            .map_err(|_| invalid())?;
        if record.revision != receipt.revision
            || digest(&serde_json::to_vec(&record).map_err(|_| invalid())?) != receipt.record_sha256
        {
            return Err(conflict());
        }
        Ok(record)
    }
    pub fn revision(&self) -> u64 {
        self.snapshot.revision
    }
    pub fn records(&self) -> impl Iterator<Item = &MemoryRecord> {
        self.snapshot.records.values()
    }
    pub fn add(&mut self, body: &str, metadata: MemoryRecordDraft) -> io::Result<String> {
        validate_body(body)?;
        metadata.validate()?;
        let body = body.trim();
        let id = format!("m-{}", digest(body.as_bytes()));
        if let Some(existing) = self.snapshot.records.get(&id) {
            if !existing.deleted
                && existing.body == body
                && existing.metadata.scope == metadata.scope
                && existing.metadata.provenance == metadata.provenance
            {
                // An idempotent add never refreshes age, confidence or expiry.
                return Ok(id);
            }
            return Err(conflict());
        }
        if self.snapshot.records.len() >= MAX_RECORDS {
            return Err(invalid());
        }
        let record = MemoryRecord {
            id: id.clone(),
            revision: 1,
            body: body.into(),
            metadata,
            deleted: false,
        };
        self.change(move |snapshot| {
            snapshot.records.insert(id.clone(), record);
            Ok(id)
        })
    }
    /// Exact record revision, rather than global snapshot revision, prevents lost updates.
    pub fn update(
        &mut self,
        id: &str,
        expected: u64,
        body: &str,
        metadata: MemoryRecordDraft,
    ) -> io::Result<()> {
        validate_body(body)?;
        metadata.validate()?;
        let old = self.snapshot.records.get(id).ok_or_else(missing)?;
        if old.deleted || old.revision != expected {
            return Err(conflict());
        }
        let next = MemoryRecord {
            id: id.into(),
            revision: expected.checked_add(1).ok_or_else(invalid)?,
            body: body.trim().into(),
            metadata,
            deleted: false,
        };
        self.change(|snapshot| {
            snapshot.records.insert(id.into(), next);
            Ok(())
        })
    }
    pub fn delete(&mut self, id: &str, expected: u64) -> io::Result<()> {
        let old = self.snapshot.records.get(id).ok_or_else(missing)?;
        if old.deleted || old.revision != expected {
            return Err(conflict());
        }
        let mut next = old.clone();
        next.deleted = true;
        next.body.clear();
        next.revision = expected.checked_add(1).ok_or_else(invalid)?;
        self.change(|snapshot| {
            snapshot.records.insert(id.into(), next);
            Ok(())
        })
    }
    /// Atomically migrate/delete an exact legacy body, retaining a tombstone that prevents a
    /// still-present Markdown file from resurrecting after restart. No old trust is inherited.
    pub fn replace_legacy(
        &mut self,
        id: &str,
        old_body: &str,
        replacement: Option<(&str, MemoryRecordDraft)>,
    ) -> io::Result<()> {
        if !safe_id(id)
            || self.snapshot.records.contains_key(id)
            || self.snapshot.records.len() >= MAX_RECORDS
        {
            return Err(conflict());
        }
        validate_body(old_body)?;
        let (body, metadata, deleted) = match replacement {
            Some((body, metadata)) => {
                validate_body(body)?;
                metadata.validate()?;
                (body.trim().into(), metadata, false)
            }
            None => {
                let metadata = MemoryRecordDraft {
                    provenance: MemoryProvenance {
                        kind: MemorySourceKind::LegacyUnknown,
                        reference: "legacy-delete".into(),
                    },
                    scope: MemoryRecordScope::Global,
                    confidence_ppm: 0,
                    invalidation: MemoryInvalidation::ManualReview,
                    path_evidence: Vec::new(),
                    created_unix_seconds: 0,
                };
                (String::new(), metadata, true)
            }
        };
        let record = MemoryRecord {
            id: id.into(),
            revision: 1,
            body,
            metadata,
            deleted,
        };
        self.change(|snapshot| {
            snapshot.records.insert(id.into(), record);
            Ok(())
        })
    }
    fn change<T>(&mut self, change: impl FnOnce(&mut Snapshot) -> io::Result<T>) -> io::Result<T> {
        let mut next = Snapshot {
            revision: self.snapshot.revision.checked_add(1).ok_or_else(invalid)?,
            records: self.snapshot.records.clone(),
        };
        let result = change(&mut next)?;
        let payload = serde_json::to_vec(&next).map_err(|_| invalid())?;
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            sha256: digest(&payload),
            snapshot: next,
        })
        .map_err(|_| invalid())?;
        if bytes.len() > MAX_RECORD_SNAPSHOT_BYTES {
            return Err(invalid());
        }
        self.journal.publish(&bytes, self.snapshot.revision == 0)?;
        self.snapshot = decode(Some(bytes))?;
        Ok(result)
    }
}

fn decode(bytes: Option<Vec<u8>>) -> io::Result<Snapshot> {
    let Some(bytes) = bytes else {
        return Ok(Snapshot::default());
    };
    if bytes.len() > MAX_RECORD_SNAPSHOT_BYTES {
        return Err(invalid());
    }
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::to_vec(&envelope.snapshot).map_err(|_| invalid())?;
    if envelope.version != 1
        || envelope.sha256 != digest(&payload)
        || envelope.snapshot.revision == 0
        || envelope.snapshot.records.len() > MAX_RECORDS
    {
        return Err(invalid());
    }
    for (id, record) in &envelope.snapshot.records {
        if id != &record.id
            || !safe_id(id)
            || record.revision == 0
            || record.revision > envelope.snapshot.revision
        {
            return Err(invalid());
        }
        record.metadata.validate()?;
        if !record.deleted {
            validate_body(&record.body)?;
        } else if !record.body.is_empty() {
            return Err(invalid());
        }
    }
    Ok(envelope.snapshot)
}

pub fn workspace_digest(workspace: &Path) -> io::Result<String> {
    let root = workspace.canonicalize()?;
    Ok(digest(root.as_os_str().as_encoded_bytes()))
}
pub fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
fn path_digest(workspace: &Path, relative: &str) -> io::Result<String> {
    if !safe_relative(relative) {
        return Err(invalid());
    }
    let bytes = crate::source::read_bounded_utf8(
        workspace,
        &workspace.join(relative),
        256 * 1024,
        crate::source::SourceScope::Repository,
    )
    .map_err(|_| invalid())?
    .ok_or_else(missing)?;
    Ok(digest(bytes.as_bytes()))
}
fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}
pub(super) fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn validate_body(body: &str) -> io::Result<()> {
    if body.trim().is_empty()
        || body.len() > MAX_RECORD_BODY_BYTES
        || crate::memory::suspicious_unicode(body)
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unbounded memory record",
    )
}
fn conflict() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "memory record conflict; inspect exact revision before updating",
    )
}
fn missing() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "memory record is absent")
}
