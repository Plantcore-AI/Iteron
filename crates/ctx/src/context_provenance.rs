//! Actual owner bytes and renderer ranges. No path is a reconstruction capability;
//! retained locators are minted later by the durable artifact owner from publication receipts.
use crate::{ContextDecision, ContextSourceClass};
use iteron_protocol::Trust;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    path::{Component, Path},
    sync::Arc,
};

#[cfg(test)]
mod tests;

pub const MAX_CONTEXT_MATERIALS: usize = 512;
pub const MAX_CONTEXT_MATERIAL_BYTES: usize = 256 * 1024;
pub const MAX_CONTEXT_PROVENANCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMaterialRootV1 {
    Workspace,
    Operator,
    Dependency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextMaterialPathV1 {
    pub root: ContextMaterialRootV1,
    /// Identity of the actual declared source-owner boundary, not an absolute public path.
    pub declared_root_path_sha256: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextMaterialVersionV1 {
    CompleteFile {
        sha256: String,
        bytes: u64,
    },
    ReadPrefix {
        sha256: String,
        bytes: u64,
        unread_tail: bool,
    },
    MemoryRecord {
        sha256: String,
        bytes: u64,
        record_revision: u64,
    },
    GatheredBytes {
        sha256: String,
        bytes: u64,
    },
    JournalRecord {
        sha256: String,
        bytes: u64,
        run_scope_sha256: String,
        source_event_seq: u64,
        record_revision: u64,
        observation_event_seq: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextMaterialUnavailableV1 {
    Missing,
    SourceReadRefused { reason: String },
    SourceOwnerDidNotCapture,
    HistoricalSourceNotRetained,
    RetentionBound,
    InvalidSourceIdentity,
    NotAFileSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMaterialRendererV1 {
    ContextGrant,
    FrontendInstructions,
    HistoricalInjection,
    JournalReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextMaterialViewV1 {
    pub version: u32,
    pub material_id_sha256: String,
    pub segment_ordinal: u32,
    pub renderer: ContextMaterialRendererV1,
    pub source_class: ContextSourceClass,
    pub path: Option<ContextMaterialPathV1>,
    pub path_unavailable: Option<ContextMaterialUnavailableV1>,
    pub source_key_sha256: Option<String>,
    pub source_version: Option<ContextMaterialVersionV1>,
    pub source_unavailable: Option<ContextMaterialUnavailableV1>,
    pub source_truncated: bool,
    pub rendered_before_sha256: String,
    pub rendered_sha256: String,
    pub rendered_bytes_before: u64,
    pub rendered_bytes: u64,
    /// Byte range inside the admitted aggregate segment. A rejected item has an empty range.
    pub segment_byte_start: u64,
    pub segment_byte_end: u64,
    pub decision: ContextDecision,
    pub trust: Trust,
}

/// Opaque immutable capture. Debug exposes metadata only; no deserialization or raw-body fields.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedContextMaterial {
    view: ContextMaterialViewV1,
    source: Option<Arc<str>>,
    rendered: Arc<str>,
}
impl fmt::Debug for CapturedContextMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedContextMaterial")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}
impl CapturedContextMaterial {
    pub fn view(&self) -> &ContextMaterialViewV1 {
        &self.view
    }
    pub fn source_bytes(&self) -> Option<&str> {
        self.source.as_deref()
    }
    pub fn rendered_bytes(&self) -> &str {
        &self.rendered
    }
    pub fn captured_bytes(&self) -> usize {
        self.source
            .as_ref()
            .map_or(0, |s| s.len())
            .saturating_add(self.rendered.len())
    }
    pub fn without_retained_source(&self) -> Self {
        let mut result = self.clone();
        result.source = None;
        result
            .view
            .source_unavailable
            .get_or_insert(ContextMaterialUnavailableV1::RetentionBound);
        result
    }
    pub fn with_journal_observation(mut self, source_event_seq: u64) -> Self {
        if let Some(ContextMaterialVersionV1::JournalRecord {
            observation_event_seq,
            ..
        }) = &mut self.view.source_version
            && source_event_seq > 0
        {
            *observation_event_seq = Some(source_event_seq);
            self.view.material_id_sha256 = digest(
                &serde_json::to_vec(&(
                    "iteron-context-journal-observation-v1",
                    &self.view.material_id_sha256,
                    source_event_seq,
                ))
                .unwrap_or_default(),
            );
        }
        self
    }
    fn bound_rendered(&mut self) {
        if self.rendered.len() > MAX_CONTEXT_MATERIAL_BYTES {
            self.rendered = Arc::from("");
            self.view
                .source_unavailable
                .get_or_insert(ContextMaterialUnavailableV1::RetentionBound);
        }
    }
    pub(crate) fn with_renderer(mut self, renderer: ContextMaterialRendererV1) -> Self {
        if self.view.renderer != renderer {
            self.view.material_id_sha256 = digest(
                &serde_json::to_vec(&(
                    "iteron-context-renderer-scope-v1",
                    &self.view.material_id_sha256,
                    renderer,
                ))
                .unwrap_or_default(),
            );
            self.view.renderer = renderer;
        }
        self
    }
    /// Caller supplies the exact host-owned journal scope and durable receipt. This records
    /// immutable reference evidence only; it grants no execution authority.
    pub fn journal_record(
        source_class: ContextSourceClass,
        run_scope_sha256: &str,
        source_event_seq: u64,
        revision: u64,
        record: &str,
        rendered: &str,
        trust: Trust,
    ) -> Self {
        let valid = source_event_seq > 0
            && revision > 0
            && run_scope_sha256.len() == 64
            && run_scope_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'));
        let mut source = MaterialSource::gathered(source_class, record);
        if valid {
            source.version = Some(ContextMaterialVersionV1::JournalRecord {
                sha256: digest(record.as_bytes()),
                bytes: record.len() as u64,
                run_scope_sha256: run_scope_sha256.into(),
                source_event_seq,
                record_revision: revision,
                observation_event_seq: None,
            });
        } else {
            source = MaterialSource::unavailable(
                source_class,
                ContextMaterialUnavailableV1::InvalidSourceIdentity,
            );
        }
        let mut render = MaterialRender::default();
        render.append(source, rendered);
        let mut captured = render.admit(0, rendered, rendered.len(), trust).remove(0);
        captured = captured.with_renderer(ContextMaterialRendererV1::JournalReference);
        captured.bound_rendered();
        captured
    }

    /// Frozen recorded context has actual rendered bytes but no recovered original-file owner.
    pub fn historical(text: &str, trust: Trust) -> Self {
        Self::historical_source(ContextSourceClass::CompactionSummary, text, trust)
    }
    pub fn historical_source(source_class: ContextSourceClass, text: &str, trust: Trust) -> Self {
        let mut render = MaterialRender::default();
        render.append(
            MaterialSource::unavailable(
                source_class,
                ContextMaterialUnavailableV1::HistoricalSourceNotRetained,
            ),
            text,
        );
        let mut captured = render.admit(0, text, text.len(), trust).remove(0);
        captured = captured.with_renderer(ContextMaterialRendererV1::HistoricalInjection);
        captured.bound_rendered();
        captured
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaterialSource {
    class: ContextSourceClass,
    path: Option<ContextMaterialPathV1>,
    key: Option<String>,
    version: Option<ContextMaterialVersionV1>,
    unavailable: Option<ContextMaterialUnavailableV1>,
    truncated: bool,
    bytes: Option<Arc<str>>,
}
impl fmt::Debug for MaterialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaterialSource")
            .field("class", &self.class)
            .field("path", &self.path)
            .field("version", &self.version)
            .field("unavailable", &self.unavailable)
            .finish_non_exhaustive()
    }
}
impl MaterialSource {
    pub(crate) fn unavailable(
        class: ContextSourceClass,
        reason: ContextMaterialUnavailableV1,
    ) -> Self {
        Self {
            class,
            path: None,
            key: None,
            version: None,
            unavailable: Some(reason),
            truncated: false,
            bytes: None,
        }
    }
    pub(crate) fn file(
        class: ContextSourceClass,
        root_kind: ContextMaterialRootV1,
        root: &Path,
        path: &Path,
        bytes: &str,
        unread_tail: bool,
    ) -> Self {
        let identity = source_path(root_kind, root, path);
        let version = if unread_tail {
            ContextMaterialVersionV1::ReadPrefix {
                sha256: digest(bytes.as_bytes()),
                bytes: bytes.len() as u64,
                unread_tail,
            }
        } else {
            ContextMaterialVersionV1::CompleteFile {
                sha256: digest(bytes.as_bytes()),
                bytes: bytes.len() as u64,
            }
        };
        let mut result =
            Self::unavailable(class, ContextMaterialUnavailableV1::InvalidSourceIdentity);
        result.path = identity;
        result.version = Some(version);
        result.truncated = unread_tail;
        if result.path.is_some() {
            result.unavailable = None;
            result.retain(bytes);
        }
        result
    }
    pub(crate) fn record(
        root_kind: ContextMaterialRootV1,
        root: &Path,
        snapshot_path: &Path,
        key: &str,
        revision: u64,
        serialized_record: &str,
    ) -> Self {
        let mut result = Self::file(
            ContextSourceClass::WorkspaceMemory,
            root_kind,
            root,
            snapshot_path,
            serialized_record,
            false,
        );
        result.key = Some(digest(key.as_bytes()));
        result.version = Some(ContextMaterialVersionV1::MemoryRecord {
            sha256: digest(serialized_record.as_bytes()),
            bytes: serialized_record.len() as u64,
            record_revision: revision,
        });
        result
    }
    pub(crate) fn gathered(class: ContextSourceClass, bytes: &str) -> Self {
        let mut result = Self::unavailable(
            class,
            ContextMaterialUnavailableV1::SourceOwnerDidNotCapture,
        );
        result.version = Some(ContextMaterialVersionV1::GatheredBytes {
            sha256: digest(bytes.as_bytes()),
            bytes: bytes.len() as u64,
        });
        result.unavailable = None;
        result.retain(bytes);
        result
    }
    pub(crate) fn refused(
        class: ContextSourceClass,
        root_kind: ContextMaterialRootV1,
        root: &Path,
        path: &Path,
        reason: ContextMaterialUnavailableV1,
    ) -> Self {
        let mut result = Self::unavailable(class, reason);
        result.path = source_path(root_kind, root, path);
        result
    }
    fn retain(&mut self, bytes: &str) {
        if bytes.len() <= MAX_CONTEXT_MATERIAL_BYTES {
            self.bytes = Some(Arc::from(bytes));
        } else {
            self.unavailable = Some(ContextMaterialUnavailableV1::RetentionBound);
        }
    }
    pub(crate) fn with_key(mut self, key: &str) -> Self {
        self.key = Some(digest(key.as_bytes()));
        self
    }
    pub(crate) fn mark_truncated(mut self, truncated: bool) -> Self {
        self.truncated |= truncated;
        self
    }
    pub(crate) fn without_bytes(mut self) -> Self {
        self.bytes = None;
        self.unavailable = Some(ContextMaterialUnavailableV1::RetentionBound);
        self
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        self.bytes.as_ref().map_or(0, |s| s.len())
    }
}

fn source_path(
    root_kind: ContextMaterialRootV1,
    root: &Path,
    target: &Path,
) -> Option<ContextMaterialPathV1> {
    let path = target.strip_prefix(root).ok()?;
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return None;
    }
    let relative = path.to_str()?;
    if relative.len() > 1024
        || relative.chars().any(char::is_control)
        || crate::instructions::suspicious_unicode(relative).is_some()
    {
        return None;
    }
    Some(ContextMaterialPathV1 {
        root: root_kind,
        declared_root_path_sha256: digest(root.as_os_str().as_encoded_bytes()),
        relative_path: relative.into(),
    })
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MaterialRender {
    pub(crate) text: String,
    contributions: Vec<(MaterialSource, usize, usize)>,
    pub(crate) dropped: u32,
    retained_bytes: usize,
}
impl MaterialRender {
    pub(crate) fn append(&mut self, source: MaterialSource, text: &str) {
        let start = self.text.len();
        self.text.push_str(text);
        self.contribution(source, start, self.text.len());
    }
    pub(crate) fn contribution(&mut self, mut source: MaterialSource, start: usize, end: usize) {
        if self.contributions.len() == MAX_CONTEXT_MATERIALS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if source.retained_bytes()
            > MAX_CONTEXT_PROVENANCE_BYTES.saturating_sub(self.retained_bytes)
        {
            source = source.without_bytes();
        }
        self.retained_bytes += source.retained_bytes();
        self.contributions.push((source, start, end));
    }
    pub(crate) fn append_materialized(&mut self, other: MaterialRender) {
        let offset = self.text.len();
        self.text.push_str(&other.text);
        self.dropped = self.dropped.saturating_add(other.dropped);
        for (source, start, end) in other.contributions {
            self.contribution(source, offset + start, offset + end);
        }
    }
    pub(crate) fn refuse(&mut self, source: MaterialSource) {
        self.contribution(source, self.text.len(), self.text.len());
    }
    pub(crate) fn admit(
        &self,
        ordinal: u32,
        admitted: &str,
        retained_prefix_bytes: usize,
        trust: Trust,
    ) -> Vec<CapturedContextMaterial> {
        let mut output = Vec::with_capacity(self.contributions.len());
        for (source, start, end) in &self.contributions {
            let Some(before) = self.text.get(*start..*end) else {
                continue;
            };
            let after_start = (*start).min(retained_prefix_bytes);
            let after_end = (*end).min(retained_prefix_bytes);
            let Some(after) = admitted.get(after_start..after_end) else {
                continue;
            };
            let decision = if after.is_empty() {
                ContextDecision::Rejected
            } else if after.len() < before.len() {
                ContextDecision::Truncated
            } else {
                ContextDecision::Selected
            };
            let identity = serde_json::to_vec(&(
                ordinal,
                source.class,
                &source.path,
                &source.key,
                &source.version,
                start,
                end,
                digest(before.as_bytes()),
            ))
            .unwrap_or_default();
            output.push(CapturedContextMaterial {
                view: ContextMaterialViewV1 {
                    version: 1,
                    material_id_sha256: digest(&identity),
                    segment_ordinal: ordinal,
                    renderer: ContextMaterialRendererV1::ContextGrant,
                    source_class: source.class,
                    path: source.path.clone(),
                    path_unavailable: source.path.is_none().then(|| {
                        source
                            .unavailable
                            .clone()
                            .unwrap_or(ContextMaterialUnavailableV1::NotAFileSource)
                    }),
                    source_key_sha256: source.key.clone(),
                    source_version: source.version.clone(),
                    source_unavailable: source.unavailable.clone(),
                    source_truncated: source.truncated,
                    rendered_before_sha256: digest(before.as_bytes()),
                    rendered_sha256: digest(after.as_bytes()),
                    rendered_bytes_before: before.len() as u64,
                    rendered_bytes: after.len() as u64,
                    segment_byte_start: after_start as u64,
                    segment_byte_end: after_end as u64,
                    decision,
                    trust,
                },
                source: source.bytes.clone(),
                rendered: Arc::from(after),
            });
        }
        output
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
