//! Content-free evidence explaining how a provider request's context was assembled.

use core_protocol::{Trust, TurnId};
use serde::{Deserialize, Serialize};

pub const MAX_CONTEXT_LEDGER_SEGMENTS: usize = 512;
pub const MAX_CONTEXT_LEDGER_TRANSFORMS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContextSegmentId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSourceClass {
    KernelSystem,
    OperatorInstructions,
    ProjectInstructions,
    DirectoryInstructions,
    Environment,
    WorkspaceOutline,
    UserMemory,
    WorkspaceMemory,
    SessionMemory,
    SkillIndex,
    SkillReference,
    ToolSchema,
    TaskPrompt,
    TranscriptUser,
    TranscriptAssistant,
    TranscriptTool,
    CompactionSummary,
    ImageAttachment,
    FileAttachment,
    WorkflowEvidence,
    SubagentEvidence,
    Steering,
    QueuedSubmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDecision {
    Selected,
    Rejected,
    Deduplicated,
    Truncated,
    Compacted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDecisionReason {
    Required,
    WithinBudget,
    TrustCeiling,
    Duplicate,
    SourceDisabled,
    BudgetExhausted,
    WindowOverflow,
    Unsupported,
    Superseded,
    CompactionRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheClass {
    StablePrefix,
    CacheRead,
    CacheWrite,
    Uncached,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenizerIdentity {
    pub catalog_id: String,
    pub version: u16,
    pub exact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSegmentEvidence {
    pub segment_id: ContextSegmentId,
    pub parent_segment_id: Option<ContextSegmentId>,
    pub source_class: ContextSourceClass,
    pub source_digest_sha256: [u8; 32],
    pub trust: Trust,
    pub ordinal: u32,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub estimated_tokens: u64,
    pub actual_tokens: Option<u64>,
    pub token_range: Option<TokenRange>,
    pub cache_class: CacheClass,
    pub decision: ContextDecision,
    pub reason: ContextDecisionReason,
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextTransformKind {
    Classify,
    Select,
    Deduplicate,
    Budget,
    Serialize,
    Tokenize,
    Submit,
    ReconcileUsage,
    Cache,
    Compact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTransformEvidence {
    pub kind: ContextTransformKind,
    pub policy_id: String,
    pub input_segments: u32,
    pub output_segments: u32,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub elapsed_us: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextTotals {
    pub selected_segments: u32,
    pub rejected_segments: u32,
    pub bytes: u64,
    pub estimated_tokens: u64,
    pub actual_input_tokens: Option<u64>,
    pub duplicate_tokens: u64,
    pub reclaimable_tokens: u64,
    pub tool_schema_tokens: u64,
    pub attachment_tokens: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEvidence {
    pub stable_prefix_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub uncached_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionEvidence {
    pub trigger_tokens: u64,
    pub before_tokens: u64,
    pub after_tokens: u64,
    pub obligations_preserved: u32,
    pub obligations_lost: u32,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextLedger {
    pub turn_id: TurnId,
    pub model_context_window: Option<u64>,
    pub usable_window: Option<u64>,
    pub output_reserved_tokens: u64,
    pub estimator: TokenizerIdentity,
    pub segments: Vec<ContextSegmentEvidence>,
    pub transforms: Vec<ContextTransformEvidence>,
    pub totals: ContextTotals,
    pub cache: CacheEvidence,
    pub compaction: Option<CompactionEvidence>,
    pub dropped: u32,
}

impl ContextLedger {
    pub fn new(turn_id: TurnId, estimator: TokenizerIdentity) -> Self {
        Self {
            turn_id,
            model_context_window: None,
            usable_window: None,
            output_reserved_tokens: 0,
            estimator,
            segments: Vec::new(),
            transforms: Vec::new(),
            totals: ContextTotals::default(),
            cache: CacheEvidence::default(),
            compaction: None,
            dropped: 0,
        }
    }

    pub fn record_segment(&mut self, evidence: ContextSegmentEvidence) {
        if self.segments.len() == MAX_CONTEXT_LEDGER_SEGMENTS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        match evidence.decision {
            ContextDecision::Selected | ContextDecision::Truncated | ContextDecision::Compacted => {
                self.totals.selected_segments = self.totals.selected_segments.saturating_add(1);
                self.totals.bytes = self.totals.bytes.saturating_add(evidence.bytes_after);
                self.totals.estimated_tokens = self
                    .totals
                    .estimated_tokens
                    .saturating_add(evidence.estimated_tokens);
            }
            ContextDecision::Rejected | ContextDecision::Deduplicated => {
                self.totals.rejected_segments = self.totals.rejected_segments.saturating_add(1);
            }
        }
        self.segments.push(evidence);
    }

    pub fn record_transform(&mut self, evidence: ContextTransformEvidence) {
        if self.transforms.len() == MAX_CONTEXT_LEDGER_TRANSFORMS {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.transforms.push(evidence);
        }
    }

    pub fn headroom_tokens(&self) -> Option<u64> {
        self.usable_window.map(|window| {
            window.saturating_sub(
                self.totals
                    .actual_input_tokens
                    .unwrap_or(self.totals.estimated_tokens),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextObservation {
    Segment(ContextSegmentEvidence),
    Transform(ContextTransformEvidence),
    Compaction(CompactionEvidence),
    ProviderUsage { actual_input_tokens: u64 },
}

pub trait ContextObserver: Send + Sync {
    fn observe(&self, turn_id: TurnId, observation: ContextObservation);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NullContextObserver;

impl ContextObserver for NullContextObserver {
    fn observe(&self, _turn_id: TurnId, _observation: ContextObservation) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_is_counted_instead_of_growing_unbounded() {
        let mut ledger = ContextLedger::new(
            TurnId(1),
            TokenizerIdentity {
                catalog_id: "heuristic".into(),
                version: 1,
                exact: false,
            },
        );
        let segment = ContextSegmentEvidence {
            segment_id: ContextSegmentId(1),
            parent_segment_id: None,
            source_class: ContextSourceClass::KernelSystem,
            source_digest_sha256: [0; 32],
            trust: Trust::Trusted,
            ordinal: 0,
            bytes_before: 1,
            bytes_after: 1,
            estimated_tokens: 1,
            actual_tokens: None,
            token_range: None,
            cache_class: CacheClass::StablePrefix,
            decision: ContextDecision::Selected,
            reason: ContextDecisionReason::Required,
            elapsed_us: 0,
        };
        for _ in 0..=MAX_CONTEXT_LEDGER_SEGMENTS {
            ledger.record_segment(segment.clone());
        }
        assert_eq!(ledger.segments.len(), MAX_CONTEXT_LEDGER_SEGMENTS);
        assert_eq!(ledger.dropped, 1);
    }
}
