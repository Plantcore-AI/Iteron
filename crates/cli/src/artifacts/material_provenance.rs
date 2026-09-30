//! Bounded reconstruction locators minted only from actual same-owner CAS receipts.
//! Filesystem labels are provenance displays, never read paths or artifact capabilities.
use super::{ArtifactSchema, ArtifactStoreError, DurableArtifactStore};
use iteron_ctx::context_provenance::{
    CapturedContextMaterial, ContextMaterialUnavailableV1, ContextMaterialVersionV1,
    ContextMaterialViewV1, MAX_CONTEXT_MATERIALS, MAX_CONTEXT_PROVENANCE_BYTES,
};
use iteron_protocol::client_artifact::ClientArtifactDescriptorV1;
use iteron_provider::{AdapterKind, request_capture::ProviderWireRequest};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_WIRE_TEXT_FIELDS: usize = 4096;
const MAX_WIRE_CONTEXT_VERIFY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MaterialRetentionUnavailableV1 {
    SourceUnavailable {
        reason: ContextMaterialUnavailableV1,
    },
    CaptureNotRetained,
    RetentionBound,
    NotSelected,
    CaptureCommitmentMismatch,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaterialRetainedRepresentationV1 {
    ExactCapturedBytes,
    ScrubbedDerivative,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MaterialRetainedLocatorV1 {
    pub(crate) artifact: ClientArtifactDescriptorV1,
    pub(crate) offset: u64,
    pub(crate) bytes: u64,
    /// Commitment to the exact bytes read from this retained offset, after redaction if any.
    pub(crate) sha256: String,
    pub(crate) representation: MaterialRetainedRepresentationV1,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MaterialRetainedResolutionV1 {
    Retained {
        locator: MaterialRetainedLocatorV1,
    },
    Unavailable {
        reason: MaterialRetentionUnavailableV1,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MaterialPreparedInclusionV1 {
    CapturedRendering { sha256: String },
    ScrubbedRendering { sha256: String },
    Unconfirmed { reason_code: &'static str },
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MaterialResolutionV1 {
    pub(crate) material: ContextMaterialViewV1,
    /// Public path/reason displays may be scrubbed; original commitments remain computed evidence.
    pub(crate) metadata_scrubbed: bool,
    pub(crate) source: MaterialRetainedResolutionV1,
    pub(crate) rendered: MaterialRetainedResolutionV1,
    /// Exact actual native prepared text only; no socket dispatch or model consumption claim.
    pub(crate) prepared_request_inclusion: MaterialPreparedInclusionV1,
}

pub(crate) struct MaterialProvenancePublication {
    pub(crate) resolutions: Vec<MaterialResolutionV1>,
    pub(crate) archive: Option<ClientArtifactDescriptorV1>,
}

enum PendingResolution {
    Retained {
        offset: u64,
        bytes: u64,
        sha256: String,
        representation: MaterialRetainedRepresentationV1,
    },
    Unavailable(MaterialRetentionUnavailableV1),
}
impl PendingResolution {
    fn resolve(
        self,
        receipt: Option<&ClientArtifactDescriptorV1>,
    ) -> Result<MaterialRetainedResolutionV1, ArtifactStoreError> {
        Ok(match self {
            Self::Unavailable(reason) => MaterialRetainedResolutionV1::Unavailable { reason },
            Self::Retained {
                offset,
                bytes,
                sha256,
                representation,
            } => {
                let artifact = receipt.ok_or(ArtifactStoreError::Corrupt)?;
                if !artifact.complete
                    || offset
                        .checked_add(bytes)
                        .is_none_or(|end| end > artifact.bytes)
                {
                    return Err(ArtifactStoreError::Corrupt);
                }
                MaterialRetainedResolutionV1::Retained {
                    locator: MaterialRetainedLocatorV1 {
                        artifact: artifact.clone(),
                        offset,
                        bytes,
                        sha256,
                        representation,
                    },
                }
            }
        })
    }
}

struct MaterialArchive {
    text: String,
    positions: BTreeMap<String, (u64, u64)>,
}
impl MaterialArchive {
    fn new() -> Self {
        Self {
            text: "iteron-context-material-archive-v1\n".into(),
            positions: BTreeMap::new(),
        }
    }
    fn retain(&mut self, original: &str, expected: &str) -> PendingResolution {
        if digest(original.as_bytes()) != expected {
            return PendingResolution::Unavailable(
                MaterialRetentionUnavailableV1::CaptureCommitmentMismatch,
            );
        }
        // Scrub a complete captured field before concatenation. No raw source is serialized in
        // the manifest or split across a redaction boundary; the receipt names these served bytes.
        let served = iteron_record::redact::scrub(original);
        let commitment = digest(served.as_bytes());
        let representation = if served == original {
            MaterialRetainedRepresentationV1::ExactCapturedBytes
        } else {
            MaterialRetainedRepresentationV1::ScrubbedDerivative
        };
        if let Some((offset, bytes)) = self.positions.get(&commitment) {
            let end = (*offset + *bytes) as usize;
            if self.text.get(*offset as usize..end) == Some(served.as_str()) {
                return PendingResolution::Retained {
                    offset: *offset,
                    bytes: *bytes,
                    sha256: commitment,
                    representation,
                };
            }
            return PendingResolution::Unavailable(
                MaterialRetentionUnavailableV1::CaptureCommitmentMismatch,
            );
        }
        const BOUNDARY: &str = "\n--- retained material boundary ---\n";
        if self.positions.len() >= MAX_CONTEXT_MATERIALS * 2
            || served
                .len()
                .checked_add(BOUNDARY.len())
                .is_none_or(|bytes| {
                    bytes
                        > MAX_ARCHIVE_BYTES
                            .min(super::MAX_PRIVATE_CONTENT_BYTES)
                            .saturating_sub(self.text.len())
                })
        {
            return PendingResolution::Unavailable(MaterialRetentionUnavailableV1::RetentionBound);
        }
        let offset = self.text.len() as u64;
        self.text.push_str(&served);
        self.text.push_str(BOUNDARY);
        let bytes = served.len() as u64;
        self.positions.insert(commitment.clone(), (offset, bytes));
        PendingResolution::Retained {
            offset,
            bytes,
            sha256: commitment,
            representation,
        }
    }
}

impl DurableArtifactStore {
    pub(crate) fn publish_material_provenance(
        &self,
        source_event_seq: u64,
        materials: &[CapturedContextMaterial],
        wire: &ProviderWireRequest<'_>,
    ) -> Result<MaterialProvenancePublication, ArtifactStoreError> {
        if materials.len() > MAX_CONTEXT_MATERIALS
            || materials
                .iter()
                .try_fold(0usize, |sum, item| sum.checked_add(item.captured_bytes()))
                .is_none_or(|bytes| bytes > MAX_CONTEXT_PROVENANCE_BYTES)
        {
            return Err(ArtifactStoreError::Capacity);
        }
        if materials.is_empty() {
            return Ok(MaterialProvenancePublication {
                resolutions: Vec::new(),
                archive: None,
            });
        }
        let fields = PreparedContextFields::capture(wire);
        let mut archive = MaterialArchive::new();
        let mut pending = Vec::with_capacity(materials.len());
        for material in materials {
            let (view, metadata_scrubbed) = scrub_metadata(material.view());
            let source = match (
                material.source_bytes(),
                source_commitment(&view.source_version),
            ) {
                (Some(bytes), Some(expected)) => archive.retain(bytes, expected),
                _ => PendingResolution::Unavailable(
                    view.source_unavailable
                        .clone()
                        .map(|reason| MaterialRetentionUnavailableV1::SourceUnavailable { reason })
                        .unwrap_or(MaterialRetentionUnavailableV1::CaptureNotRetained),
                ),
            };
            let rendered = if view.rendered_bytes == 0 {
                PendingResolution::Unavailable(MaterialRetentionUnavailableV1::NotSelected)
            } else if material.rendered_bytes().is_empty() {
                PendingResolution::Unavailable(MaterialRetentionUnavailableV1::CaptureNotRetained)
            } else {
                archive.retain(material.rendered_bytes(), &view.rendered_sha256)
            };
            let inclusion = fields.inclusion(material);
            pending.push((view, metadata_scrubbed, source, rendered, inclusion));
        }
        let receipt = if archive.positions.is_empty() {
            None
        } else {
            Some(self.publish_served(
                source_event_seq,
                ArtifactSchema::ContextMaterialArchive,
                &archive.text,
                &[],
                &[],
            )?)
        };
        let resolutions = pending
            .into_iter()
            .map(
                |(material, metadata_scrubbed, source, rendered, prepared_request_inclusion)| {
                    Ok(MaterialResolutionV1 {
                        material,
                        metadata_scrubbed,
                        source: source.resolve(receipt.as_ref())?,
                        rendered: rendered.resolve(receipt.as_ref())?,
                        prepared_request_inclusion,
                    })
                },
            )
            .collect::<Result<Vec<_>, ArtifactStoreError>>()?;
        Ok(MaterialProvenancePublication {
            resolutions,
            archive: receipt,
        })
    }
}

fn source_commitment(version: &Option<ContextMaterialVersionV1>) -> Option<&str> {
    match version.as_ref()? {
        ContextMaterialVersionV1::CompleteFile { sha256, .. }
        | ContextMaterialVersionV1::ReadPrefix { sha256, .. }
        | ContextMaterialVersionV1::MemoryRecord { sha256, .. }
        | ContextMaterialVersionV1::GatheredBytes { sha256, .. }
        | ContextMaterialVersionV1::JournalRecord { sha256, .. } => Some(sha256),
    }
}
fn scrub_metadata(original: &ContextMaterialViewV1) -> (ContextMaterialViewV1, bool) {
    let mut view = original.clone();
    let mut scrubbed = false;
    if let Some(path) = &mut view.path {
        let served = iteron_record::redact::scrub(&path.relative_path);
        scrubbed |= served != path.relative_path;
        path.relative_path = served;
    }
    for reason in [&mut view.source_unavailable, &mut view.path_unavailable] {
        if let Some(ContextMaterialUnavailableV1::SourceReadRefused { reason }) = reason {
            let served = iteron_record::redact::scrub(reason);
            scrubbed |= served != *reason;
            *reason = served;
        }
    }
    (view, scrubbed)
}

struct PreparedContextFields {
    texts: Vec<String>,
    bytes: usize,
    unavailable: Option<&'static str>,
}
impl PreparedContextFields {
    fn capture(wire: &ProviderWireRequest<'_>) -> Self {
        let unavailable = |reason| Self {
            texts: Vec::new(),
            bytes: 0,
            unavailable: Some(reason),
        };
        if wire.body.len() > 32 * 1024 * 1024 {
            return unavailable("prepared_body_bounds");
        }
        let Ok(body) = serde_json::from_slice::<Value>(wire.body) else {
            return unavailable("prepared_body_not_json");
        };
        let mut result = Self {
            texts: Vec::new(),
            bytes: 0,
            unavailable: None,
        };
        match wire.adapter {
            AdapterKind::AnthropicMessages => {
                if let Some(system) = body.get("system") {
                    result.push(system);
                }
            }
            AdapterKind::OpenAiResponses => {
                if let Some(system) = body.get("instructions") {
                    result.push(system);
                }
            }
            AdapterKind::OpenAiCompatibleChat => {
                if let Some(messages) = body.get("messages").and_then(Value::as_array) {
                    if messages.len() > MAX_WIRE_TEXT_FIELDS {
                        return unavailable("prepared_text_field_bounds");
                    }
                    for message in messages {
                        if message.get("role").and_then(Value::as_str) == Some("system")
                            && let Some(content) = message.get("content")
                        {
                            result.push(content);
                        }
                    }
                }
            }
        }
        result
    }
    fn push(&mut self, value: &Value) {
        if self.unavailable.is_some() {
            return;
        }
        match value {
            Value::String(text) => self.push_text(text),
            Value::Array(blocks) if blocks.len() <= MAX_WIRE_TEXT_FIELDS => {
                for block in blocks {
                    if matches!(
                        block.get("type").and_then(Value::as_str),
                        Some("text" | "input_text")
                    ) {
                        if let Some(text) = block.get("text").and_then(Value::as_str) {
                            self.push_text(text);
                        } else {
                            self.unavailable = Some("prepared_context_field_shape");
                        }
                    }
                }
            }
            _ => self.unavailable = Some("prepared_context_field_shape"),
        }
    }
    fn push_text(&mut self, text: &str) {
        if self.unavailable.is_some() {
            return;
        }
        if self.texts.len() >= MAX_WIRE_TEXT_FIELDS
            || text.len() > MAX_WIRE_CONTEXT_VERIFY_BYTES.saturating_sub(self.bytes)
        {
            self.texts.clear();
            self.unavailable = Some("prepared_context_verification_bound");
            return;
        }
        self.bytes += text.len();
        self.texts.push(text.into());
    }
    fn inclusion(&self, material: &CapturedContextMaterial) -> MaterialPreparedInclusionV1 {
        let unconfirmed = |reason_code| MaterialPreparedInclusionV1::Unconfirmed { reason_code };
        if let Some(reason) = self.unavailable {
            return unconfirmed(reason);
        }
        let fragment = material.rendered_bytes();
        if fragment.is_empty() {
            return unconfirmed("material_not_rendered_or_capture_unavailable");
        }
        if self.texts.iter().any(|text| text.contains(fragment)) {
            return MaterialPreparedInclusionV1::CapturedRendering {
                sha256: digest(fragment.as_bytes()),
            };
        }
        let served = iteron_record::redact::scrub(fragment);
        if !served.is_empty() && self.texts.iter().any(|text| text.contains(&served)) {
            return MaterialPreparedInclusionV1::ScrubbedRendering {
                sha256: digest(served.as_bytes()),
            };
        }
        unconfirmed("material_not_confirmed_in_actual_prepared_context")
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
#[path = "material_provenance/tests.rs"]
mod tests;
