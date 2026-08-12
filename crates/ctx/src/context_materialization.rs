//! Content-free audit of the world port's bounded context materialization.

use crate::context_ledger::MAX_CONTEXT_LEDGER_SEGMENTS;
use crate::{
    CacheClass, ContextDecision, ContextDecisionReason, ContextSegmentEvidence, ContextSegmentId,
    ContextSourceClass,
};
use iteron_protocol::Trust;
use iteron_protocol::context::{
    ContextGrant, ContextRequest, ContextSegment, ContextSource, MAX_CONTEXT_SEGMENTS,
};
use sha2::{Digest, Sha256};

/// Exact bounded decisions made while turning gathered sources into a context grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextMaterializationAudit {
    pub segments: Vec<ContextSegmentEvidence>,
    pub dropped: u32,
}

pub(crate) struct AuditedGrantBuilder<'a> {
    request: &'a ContextRequest,
    segments: Vec<ContextSegment>,
    audit: ContextMaterializationAudit,
    bytes: usize,
    next_ordinal: u32,
}

impl<'a> AuditedGrantBuilder<'a> {
    pub(crate) fn new(request: &'a ContextRequest) -> Self {
        Self {
            request,
            segments: Vec::new(),
            audit: ContextMaterializationAudit::default(),
            bytes: 0,
            next_ordinal: 0,
        }
    }

    pub(crate) fn remaining_bytes(&self) -> usize {
        (self.request.max_bytes as usize).saturating_sub(self.bytes)
    }

    pub(crate) fn push(&mut self, text: String, trust: Trust, source: ContextSource) {
        if text.is_empty() {
            return;
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        let bytes_before = text.len();
        let admitted = if self.segments.len() == MAX_CONTEXT_SEGMENTS {
            String::new()
        } else {
            bounded_text(&text, self.remaining_bytes())
        };
        let decision = if admitted.is_empty() {
            ContextDecision::Rejected
        } else if admitted.len() < bytes_before {
            ContextDecision::Truncated
        } else {
            ContextDecision::Selected
        };
        let reason = match decision {
            ContextDecision::Selected => ContextDecisionReason::WithinBudget,
            ContextDecision::Truncated | ContextDecision::Rejected => {
                ContextDecisionReason::BudgetExhausted
            }
            ContextDecision::Deduplicated | ContextDecision::Compacted => {
                ContextDecisionReason::Required
            }
        };
        let effective_trust = trust.min(self.request.trust_ceiling);
        if self.audit.segments.len() == MAX_CONTEXT_LEDGER_SEGMENTS {
            self.audit.dropped = self.audit.dropped.saturating_add(1);
        } else {
            self.audit.segments.push(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: source_class(source),
                source_digest_sha256: Sha256::digest(text.as_bytes()).into(),
                trust: effective_trust,
                ordinal,
                bytes_before: u64::try_from(bytes_before).unwrap_or(u64::MAX),
                bytes_after: u64::try_from(admitted.len()).unwrap_or(u64::MAX),
                estimated_tokens: u64::try_from(crate::estimate_tokens(&admitted))
                    .unwrap_or(u64::MAX),
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::StablePrefix,
                decision,
                reason,
                elapsed_us: 0,
            });
        }
        if admitted.is_empty() {
            return;
        }
        self.bytes = self.bytes.saturating_add(admitted.len());
        self.segments.push(ContextSegment {
            text: admitted,
            trust: effective_trust,
            source,
        });
    }

    pub(crate) fn finish(self) -> (ContextGrant, ContextMaterializationAudit) {
        (
            ContextGrant {
                request_id: self.request.request_id,
                segments: self.segments,
                bytes: u32::try_from(self.bytes).unwrap_or(u32::MAX),
            },
            self.audit,
        )
    }
}

fn bounded_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    const MARKER: &str = "\n… (truncated)";
    if max_bytes <= MARKER.len() {
        return String::new();
    }
    let mut end = max_bytes - MARKER.len();
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = String::with_capacity(max_bytes);
    output.push_str(&text[..end]);
    output.push_str(MARKER);
    output
}

fn source_class(source: ContextSource) -> ContextSourceClass {
    match source {
        ContextSource::RepoOutline => ContextSourceClass::WorkspaceOutline,
        ContextSource::Instructions => ContextSourceClass::ProjectInstructions,
        ContextSource::Memory => ContextSourceClass::WorkspaceMemory,
        ContextSource::Transcript => ContextSourceClass::TranscriptUser,
        ContextSource::Environment => ContextSourceClass::Environment,
        ContextSource::Skills => ContextSourceClass::SkillIndex,
        ContextSource::Unknown => ContextSourceClass::Environment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::context::RequestId;

    fn request(max_bytes: u32) -> ContextRequest {
        let mut request = ContextRequest::new(
            RequestId(1),
            iteron_protocol::slot::SlotId("core/context".into()),
            max_bytes,
        );
        request.trust_ceiling = Trust::Trusted;
        request
    }

    #[test]
    fn truncation_and_budget_rejection_are_explicit() {
        let request = request(32);
        let mut builder = AuditedGrantBuilder::new(&request);
        builder.push(
            "a".repeat(64),
            Trust::Workspace,
            ContextSource::Instructions,
        );
        builder.push("second".into(), Trust::Workspace, ContextSource::Memory);
        let (grant, audit) = builder.finish();
        assert_eq!(grant.bytes, 32);
        assert_eq!(audit.segments.len(), 2);
        assert_eq!(audit.segments[0].decision, ContextDecision::Truncated);
        assert_eq!(audit.segments[0].bytes_before, 64);
        assert_eq!(audit.segments[0].bytes_after, 32);
        assert_eq!(audit.segments[1].decision, ContextDecision::Rejected);
        assert_eq!(audit.segments[1].bytes_after, 0);
    }
}
