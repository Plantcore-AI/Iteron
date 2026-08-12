use iteron_protocol::{ErasureAuthorityId, ErasureContentDigest, ErasureOperationId, RunId};
use serde::{Deserialize, Serialize};

pub(super) const STORE_VERSION: u16 = 1;
pub(super) const CONTENT_ROOT: &str = ".content";
pub const MAX_PRIVATE_CONTENT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_CONTENT_JSON_BYTES: usize = MAX_PRIVATE_CONTENT_BYTES;
pub(super) const MAX_CONTENT_REFERENCES: usize = 100_000;
pub(super) const MAX_CONTENT_RUNS: usize = 100_000;
pub(super) const MAX_CONTENT_REVOCATIONS: usize = 4_096;
pub(super) const MAX_REFERENCE_EDGE_BYTES: usize = 4 * 1024;
pub(super) const MAX_LINEAGE_EDGE_BYTES: usize = 4 * 1024;
pub(super) const MAX_CONTENT_LINEAGE_EDGES: usize = 100_000;
pub(super) const MAX_REVOCATION_STATE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PRIVATE_CONTENT_PREVIEW_BYTES: usize = 4 * 1024;
pub(super) const MARKER_PREFIX: &str = "core-private-ref:v1:";
pub(super) const ENVELOPE_FIELD: &str = "_core_private_content_version";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceEdge {
    pub version: u16,
    pub digest: ErasureContentDigest,
    pub run_id: RunId,
    pub seq: u64,
    pub ordinal: u16,
    pub field_class: String,
    pub surface: ContentReferenceSurface,
    pub retention: PrivateContentRetention,
}

/// One durable source-to-derivative dependency.
///
/// The edge is stored in both directions, outside either manifest. That lets content revocation
/// walk descendants and lets every derivative read re-check all of its sources without embedding
/// an unbounded source list in a handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LineageEdge {
    pub version: u16,
    pub source_owner: RunId,
    pub source_digest: ErasureContentDigest,
    pub derivative_owner: RunId,
    pub derivative_digest: ErasureContentDigest,
    pub derivative_seq: u64,
    pub surface: ContentReferenceSurface,
}

/// A bounded source identity supplied when materializing a private derivative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateContentSource {
    pub owner: RunId,
    pub digest: ErasureContentDigest,
}

impl PartialOrd for PrivateContentSource {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrivateContentSource {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.owner.0, &self.digest).cmp(&(&other.owner.0, &other.digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContentTombstone {
    pub version: u16,
    pub digest: ErasureContentDigest,
    pub operation_id: ErasureOperationId,
    pub authority_id: ErasureAuthorityId,
    pub revoked_at_unix_ms: u64,
    pub reason: ContentTombstoneReason,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ContentTombstoneReason {
    AuthorityRevoked,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevocationState {
    pub version: u16,
    pub generation: u64,
    pub tombstones: Vec<ContentTombstone>,
}

impl RevocationState {
    pub(super) fn empty() -> Self {
        Self {
            version: STORE_VERSION,
            generation: 0,
            tombstones: Vec::new(),
        }
    }

    pub(super) fn tombstone(&self, digest: &ErasureContentDigest) -> Option<&ContentTombstone> {
        self.tombstones
            .binary_search_by(|entry| entry.digest.cmp(digest))
            .ok()
            .map(|index| &self.tombstones[index])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContentClass {
    Transcript,
    SessionProjection,
    SessionIndex,
    ModelThinking,
    ToolOutput,
    ToolArguments,
    Attachment,
    Context,
    Memory,
    Artifact,
    Checkpoint,
    Export,
    TelemetryDebug,
    Trajectory,
    Dataset,
    EvaluatorInput,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateContentRetention {
    Session,
    UntilUnixSecs { expires_at: u64 },
    ExplicitRevocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateContentHandle {
    pub digest: ErasureContentDigest,
    pub byte_len: u32,
    pub class: PrivateContentClass,
    /// Bounded live convenience only. Callers must never persist this beside the handle.
    #[serde(skip)]
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentReferenceSurface {
    RecordField,
    SessionProjection,
    SessionIndex,
    PromptHistory,
    Attachment,
    ToolArtifact,
    Checkpoint,
    MemoryContext,
    Export,
    TelemetryDebug,
    Trajectory,
    Dataset,
    EvaluatorInput,
    CandidateStore,
}

/// Closed production namespace registry for content-bearing mutable/semantic surfaces.
///
/// Production derivative writers receive one of these values instead of an arbitrary surface.
/// That makes coverage an executable registration contract: a new surface cannot be written via
/// [`crate::PrivateContentDerivativeStore`] until it is added here and to the revocation verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContentNamespace {
    SessionProjection,
    SessionIndex,
    PromptHistory,
    Attachment,
    ToolArtifact,
    Checkpoint,
    MemoryContext,
    Export,
    Trajectory,
    Dataset,
    EvaluatorInput,
    CandidateStore,
}

impl PrivateContentNamespace {
    pub const ALL: [Self; 12] = [
        Self::SessionProjection,
        Self::SessionIndex,
        Self::PromptHistory,
        Self::Attachment,
        Self::ToolArtifact,
        Self::Checkpoint,
        Self::MemoryContext,
        Self::Export,
        Self::Trajectory,
        Self::Dataset,
        Self::EvaluatorInput,
        Self::CandidateStore,
    ];

    pub const fn surface(self) -> ContentReferenceSurface {
        match self {
            Self::SessionProjection => ContentReferenceSurface::SessionProjection,
            Self::SessionIndex => ContentReferenceSurface::SessionIndex,
            Self::PromptHistory => ContentReferenceSurface::PromptHistory,
            Self::Attachment => ContentReferenceSurface::Attachment,
            Self::ToolArtifact => ContentReferenceSurface::ToolArtifact,
            Self::Checkpoint => ContentReferenceSurface::Checkpoint,
            Self::MemoryContext => ContentReferenceSurface::MemoryContext,
            Self::Export => ContentReferenceSurface::Export,
            Self::Trajectory => ContentReferenceSurface::Trajectory,
            Self::Dataset => ContentReferenceSurface::Dataset,
            Self::EvaluatorInput => ContentReferenceSurface::EvaluatorInput,
            Self::CandidateStore => ContentReferenceSurface::CandidateStore,
        }
    }

    pub const fn from_surface(surface: ContentReferenceSurface) -> Option<Self> {
        Some(match surface {
            ContentReferenceSurface::SessionProjection => Self::SessionProjection,
            ContentReferenceSurface::SessionIndex => Self::SessionIndex,
            ContentReferenceSurface::PromptHistory => Self::PromptHistory,
            ContentReferenceSurface::Attachment => Self::Attachment,
            ContentReferenceSurface::ToolArtifact => Self::ToolArtifact,
            ContentReferenceSurface::Checkpoint => Self::Checkpoint,
            ContentReferenceSurface::MemoryContext => Self::MemoryContext,
            ContentReferenceSurface::Export => Self::Export,
            ContentReferenceSurface::Trajectory => Self::Trajectory,
            ContentReferenceSurface::Dataset => Self::Dataset,
            ContentReferenceSurface::EvaluatorInput => Self::EvaluatorInput,
            ContentReferenceSurface::CandidateStore => Self::CandidateStore,
            ContentReferenceSurface::RecordField | ContentReferenceSurface::TelemetryDebug => {
                return None;
            }
        })
    }
}

impl ContentReferenceSurface {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::RecordField => "record_field",
            Self::SessionProjection => "session_projection",
            Self::SessionIndex => "session_index",
            Self::PromptHistory => "prompt_history",
            Self::Attachment => "attachment",
            Self::ToolArtifact => "tool_artifact",
            Self::Checkpoint => "checkpoint",
            Self::MemoryContext => "memory_context",
            Self::Export => "export",
            Self::TelemetryDebug => "telemetry_debug",
            Self::Trajectory => "trajectory",
            Self::Dataset => "dataset",
            Self::EvaluatorInput => "evaluator_input",
            Self::CandidateStore => "candidate_store",
        }
    }
}
