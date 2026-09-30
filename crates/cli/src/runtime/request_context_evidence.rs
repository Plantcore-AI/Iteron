//! Bounded source state and exact prepared-request evidence. This owner receives immutable
//! request values and estimator policy; it owns no Agent, filesystem or provider authority.
//! Source classifications may overlap; admission's actual request estimate owns aggregate tokens.
use super::context_runtime::InputImageEvidence;
use super::file_submission::InputFileEvidence;
use iteron_ctx::{
    CacheClass, ContextDecision, ContextDecisionReason, ContextLedger, ContextMaterializationAudit,
    ContextSegmentEvidence, ContextSegmentId, ContextSourceClass, ContextTransformEvidence,
    ContextTransformKind, MAX_CONTEXT_LEDGER_SEGMENTS, RequestEstimator, TokenRange,
};
use iteron_protocol::{Block, LifecyclePayload, Message, Role, ToolSpec, Trust, TurnId};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "request_context_evidence_tests.rs"]
mod tests;

pub(super) struct ContextRequestObservation<'a> {
    pub(super) system: &'a str,
    pub(super) messages: &'a [Message],
    pub(super) tools: &'a [ToolSpec],
    pub(super) images: &'a [iteron_protocol::ImageContent],
    pub(super) estimate: iteron_ctx::ContextEstimate,
    pub(super) output_reserved_tokens: u32,
    pub(super) elapsed_us: u64,
}

pub(super) struct RequestContextScope<'a> {
    pub(super) execution_window: Option<u64>,
    pub(super) request_trust: Trust,
    pub(super) estimator: &'a RequestEstimator,
    pub(super) file: Option<InputFileEvidence>,
    pub(super) image: Option<InputImageEvidence>,
}

pub(super) struct RequestContextReport {
    pub(super) ledger: ContextLedger,
    pub(super) observations: Vec<(&'static str, LifecyclePayload)>,
}

#[derive(Default)]
pub(super) struct RequestContextEvidenceOwner {
    sources: Vec<ContextSegmentEvidence>,
    dropped: u32,
}

impl RequestContextEvidenceOwner {
    pub(super) fn clear(&mut self) {
        self.sources.clear();
        self.dropped = 0;
    }
    pub(super) fn segments(&self) -> &[ContextSegmentEvidence] {
        &self.sources
    }
    pub(super) fn replace_materialized(
        &mut self,
        materialization: &ContextMaterializationAudit,
        elapsed_us: u64,
    ) -> u64 {
        self.clear();
        self.dropped = materialization.dropped.saturating_add(
            u32::try_from(
                materialization
                    .segments
                    .len()
                    .saturating_sub(MAX_CONTEXT_LEDGER_SEGMENTS),
            )
            .unwrap_or(u32::MAX),
        );
        let mut token_cursor = 0u64;
        for evidence in materialization
            .segments
            .iter()
            .take(MAX_CONTEXT_LEDGER_SEGMENTS)
        {
            let mut evidence = evidence.clone();
            evidence.elapsed_us = elapsed_us;
            if matches!(
                evidence.decision,
                ContextDecision::Selected | ContextDecision::Truncated | ContextDecision::Compacted
            ) {
                let end = token_cursor.saturating_add(evidence.estimated_tokens);
                evidence.token_range = Some(TokenRange {
                    start: token_cursor,
                    end,
                });
                token_cursor = end;
            }
            self.sources.push(evidence);
        }
        token_cursor
    }
    pub(super) fn replace_recorded(
        &mut self,
        text: &str,
        trust: Trust,
        estimator: &RequestEstimator,
    ) -> u64 {
        self.clear();
        let tokens = u64::try_from(estimator.estimate_text(text)).unwrap_or(u64::MAX);
        self.sources = vec![ContextSegmentEvidence {
            segment_id: ContextSegmentId(0),
            parent_segment_id: None,
            source_class: ContextSourceClass::CompactionSummary,
            source_digest_sha256: digest(text.as_bytes()),
            trust,
            ordinal: 0,
            bytes_before: u64::try_from(text.len()).unwrap_or(u64::MAX),
            bytes_after: u64::try_from(text.len()).unwrap_or(u64::MAX),
            estimated_tokens: tokens,
            actual_tokens: None,
            token_range: Some(TokenRange {
                start: 0,
                end: tokens,
            }),
            cache_class: CacheClass::StablePrefix,
            decision: ContextDecision::Selected,
            reason: ContextDecisionReason::Required,
            elapsed_us: 0,
        }];
        tokens
    }

    pub(super) fn build_request(
        &self,
        turn: TurnId,
        scope: RequestContextScope<'_>,
        observation: ContextRequestObservation<'_>,
    ) -> RequestContextReport {
        let estimator = scope.estimator;
        let ContextRequestObservation {
            system,
            messages,
            tools,
            images,
            estimate,
            output_reserved_tokens,
            elapsed_us,
        } = observation;
        let mut observations = Vec::with_capacity(2);
        let mut ledger = ContextLedger::new(turn, estimator.tokenizer_identity());
        let execution_window = scope.execution_window;
        ledger.dropped = self.dropped;
        ledger.model_context_window = execution_window;
        ledger.output_reserved_tokens = u64::from(output_reserved_tokens);
        ledger.usable_window =
            execution_window.map(|window| window.saturating_sub(u64::from(output_reserved_tokens)));
        for segment in &self.sources {
            ledger.record_segment(segment.clone());
        }
        let mut ordinal = u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX);
        record_segment(
            &mut ledger,
            ordinal,
            ContextSourceClass::KernelSystem,
            system.as_bytes(),
            scope.request_trust,
            u64::try_from(estimator.estimate_text(system)).unwrap_or(u64::MAX),
            CacheClass::StablePrefix,
        );
        ordinal = ordinal.saturating_add(1);
        if !tools.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(b"iteron-request-tool-schemas-v1\0");
            hasher.update((tools.len() as u64).to_le_bytes());
            let mut bytes = 0u64;
            for tool in tools {
                let schema = tool.input_schema.to_string();
                for field in [&tool.name, &tool.description, &schema] {
                    hasher.update((field.len() as u64).to_le_bytes());
                    hasher.update(field.as_bytes());
                }
                bytes = bytes
                    .saturating_add(u64::try_from(tool.name.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(tool.description.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(schema.len()).unwrap_or(u64::MAX));
            }
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::ToolSchema,
                source_digest_sha256: hasher.finalize().into(),
                trust: Trust::Trusted,
                ordinal,
                bytes_before: bytes,
                bytes_after: bytes,
                estimated_tokens: u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX),
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::StablePrefix,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            ledger.totals.tool_schema_tokens =
                u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX);
            ordinal = ordinal.saturating_add(1);
        }
        let active_task_index = messages.iter().rposition(|message| {
            message.role == Role::User
                && message
                    .content
                    .iter()
                    .any(|block| matches!(block, Block::Text { .. }))
        });
        let mut lsp_tool_use_ids = std::collections::BTreeSet::new();
        for (index, message) in messages.iter().enumerate() {
            // Tool-result messages can contain the results of several parallel calls. Record each
            // result as its own source so an LSP result never disappears into an ordinary mixed
            // tool message. The exact tool-use identity, learned from the preceding request block,
            // is the classification authority shared with RequestEstimator.
            for block in &message.content {
                if let Block::ToolUse(tool) = block
                    && tool.name == "lsp_query"
                {
                    lsp_tool_use_ids.insert(tool.id.clone());
                }
            }
            let has_tool_results = message
                .content
                .iter()
                .any(|block| matches!(block, Block::ToolResult(_)));
            if !has_tool_results {
                let bytes = serde_json::to_vec(message).unwrap_or_default();
                let source = if Some(index) == active_task_index {
                    ContextSourceClass::TaskPrompt
                } else {
                    match message.role {
                        Role::User => ContextSourceClass::TranscriptUser,
                        Role::Assistant => ContextSourceClass::TranscriptAssistant,
                    }
                };
                record_segment(
                    &mut ledger,
                    ordinal,
                    source,
                    &bytes,
                    scope.request_trust,
                    u64::try_from(estimator.estimate_text(&String::from_utf8_lossy(&bytes)))
                        .unwrap_or(u64::MAX),
                    CacheClass::Uncached,
                );
                ordinal = ordinal.saturating_add(1);
                continue;
            }

            let non_results = message
                .content
                .iter()
                .filter(|block| !matches!(block, Block::ToolResult(_)))
                .collect::<Vec<_>>();
            if !non_results.is_empty() {
                let bytes = serde_json::to_vec(&(message.role, non_results)).unwrap_or_default();
                let source = if Some(index) == active_task_index {
                    ContextSourceClass::TaskPrompt
                } else {
                    match message.role {
                        Role::User => ContextSourceClass::TranscriptUser,
                        Role::Assistant => ContextSourceClass::TranscriptAssistant,
                    }
                };
                record_segment(
                    &mut ledger,
                    ordinal,
                    source,
                    &bytes,
                    scope.request_trust,
                    u64::try_from(estimator.estimate_text(&String::from_utf8_lossy(&bytes)))
                        .unwrap_or(u64::MAX),
                    CacheClass::Uncached,
                );
                ordinal = ordinal.saturating_add(1);
            }
            for block in &message.content {
                let Block::ToolResult(result) = block else {
                    continue;
                };
                let bytes = serde_json::to_vec(block).unwrap_or_default();
                let source = if lsp_tool_use_ids.contains(&result.tool_use_id) {
                    ContextSourceClass::LspResult
                } else {
                    ContextSourceClass::TranscriptTool
                };
                record_segment(
                    &mut ledger,
                    ordinal,
                    source,
                    &bytes,
                    result.trust,
                    u64::try_from(estimator.estimate_text(&result.content).saturating_add(8))
                        .unwrap_or(u64::MAX),
                    CacheClass::Uncached,
                );
                ordinal = ordinal.saturating_add(1);
            }
        }
        ledger.totals.tool_result_tokens =
            u64::try_from(estimate.tool_result_tokens).unwrap_or(u64::MAX);
        ledger.totals.lsp_result_tokens =
            u64::try_from(estimate.lsp_result_tokens).unwrap_or(u64::MAX);
        if let Some(file) = scope.file {
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::FileAttachment,
                source_digest_sha256: file.digest_sha256,
                trust: Trust::Trusted,
                ordinal,
                bytes_before: file.bytes,
                bytes_after: file.bytes,
                estimated_tokens: file.estimated_tokens,
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::Uncached,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            ledger.totals.attachment_tokens = ledger
                .totals
                .attachment_tokens
                .saturating_add(file.estimated_tokens);
            ordinal = ordinal.saturating_add(1);
            observations.push((
                "context.source.classified",
                LifecyclePayload {
                    count: Some(u64::from(file.count)),
                    magnitude: Some(file.bytes),
                    reason_code: Some("file_attachment".into()),
                    ..LifecyclePayload::default()
                },
            ));
        }
        if !images.is_empty() {
            let fallback = || {
                let encoded_bytes = images.iter().fold(0u64, |total, image| {
                    total
                        .saturating_add(u64::try_from(image.data.encoded_len()).unwrap_or(u64::MAX))
                });
                let estimated_tokens = images.iter().fold(0u64, |total, image| {
                    total.saturating_add(
                        u64::try_from(
                            estimator
                                .estimate_image_with_provenance(image.data.encoded_len())
                                .tokens,
                        )
                        .unwrap_or(u64::MAX),
                    )
                });
                InputImageEvidence {
                    count: u32::try_from(images.len()).unwrap_or(u32::MAX),
                    encoded_bytes,
                    raw_bytes: encoded_bytes.saturating_mul(3) / 4,
                    estimated_tokens,
                    provenance:
                        iteron_ctx::ImageTokenEstimateProvenance::EncodedBytesConservativeFallback,
                }
            };
            let image = scope.image.unwrap_or_else(fallback);
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::ImageAttachment,
                source_digest_sha256: image_attachment_digest(images),
                trust: Trust::Trusted,
                ordinal,
                bytes_before: image.encoded_bytes,
                bytes_after: image.encoded_bytes,
                estimated_tokens: image.estimated_tokens,
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::Unknown,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            ledger.totals.attachment_tokens = ledger
                .totals
                .attachment_tokens
                .saturating_add(image.estimated_tokens);
            ledger.record_transform(ContextTransformEvidence {
                kind: ContextTransformKind::Tokenize,
                policy_id: image.provenance.policy_id().into(),
                input_segments: image.count,
                output_segments: image.count,
                input_bytes: image.raw_bytes,
                output_bytes: image.raw_bytes,
                input_tokens: 0,
                output_tokens: image.estimated_tokens,
                elapsed_us: 0,
            });
            observations.push((
                "context.source.classified",
                LifecyclePayload {
                    count: Some(u64::from(image.count)),
                    magnitude: Some(image.encoded_bytes),
                    reason_code: Some("image_attachment".into()),
                    ..LifecyclePayload::default()
                },
            ));
        }
        ledger.record_transform(ContextTransformEvidence {
            kind: ContextTransformKind::Serialize,
            policy_id: "core/context@1".into(),
            input_segments: u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX),
            output_segments: u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX),
            input_bytes: ledger.totals.bytes,
            output_bytes: ledger.totals.bytes,
            input_tokens: u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX),
            output_tokens: u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX),
            elapsed_us,
        });
        ledger.cache.stable_prefix_tokens =
            u64::try_from(estimate.system_tokens.saturating_add(estimate.tool_tokens))
                .unwrap_or(u64::MAX);
        ledger.cache.uncached_tokens = u64::try_from(estimate.total_tokens)
            .unwrap_or(u64::MAX)
            .saturating_sub(ledger.cache.stable_prefix_tokens);
        // The request estimator is the single accounting pass used for admission. Segment-level
        // classification may overlap (a file is also serialized inside a transcript message), so
        // the aggregate must remain that authoritative request estimate rather than their sum.
        ledger.totals.estimated_tokens = u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX);
        RequestContextReport {
            ledger,
            observations,
        }
    }
}

fn record_segment(
    ledger: &mut ContextLedger,
    ordinal: u32,
    source_class: ContextSourceClass,
    bytes: &[u8],
    trust: Trust,
    estimated_tokens: u64,
    cache_class: CacheClass,
) {
    ledger.record_segment(ContextSegmentEvidence {
        segment_id: ContextSegmentId(u64::from(ordinal)),
        parent_segment_id: None,
        source_class,
        source_digest_sha256: digest(bytes),
        trust,
        ordinal,
        bytes_before: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes_after: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        estimated_tokens,
        actual_tokens: None,
        token_range: None,
        cache_class,
        decision: ContextDecision::Selected,
        reason: ContextDecisionReason::Required,
        elapsed_us: 0,
    });
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Ordered, content-addressed identity for the exact neutral image payloads sent on this turn.
/// The media type and explicit lengths make the framing unambiguous; hashing only aggregate byte
/// length would make unrelated same-size images indistinguishable in the context ledger.
fn image_attachment_digest(images: &[iteron_protocol::ImageContent]) -> [u8; 32] {
    const DOMAIN: &[u8] = b"iteron-context-image-attachments-v1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update((images.len() as u64).to_le_bytes());
    for image in images {
        let media_type = image.media_type.as_str().as_bytes();
        let encoded = image.data.as_str().as_bytes();
        hasher.update((media_type.len() as u64).to_le_bytes());
        hasher.update(media_type);
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(encoded);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod image_digest_tests {
    use super::image_attachment_digest;
    use iteron_protocol::{ImageContent, ImageMediaType};

    #[test]
    fn image_attachment_commitment_distinguishes_same_size_content_and_order() {
        let first = ImageContent::new(ImageMediaType::Png, "AAAA").unwrap();
        let second = ImageContent::new(ImageMediaType::Png, "AQID").unwrap();
        assert_eq!(first.data.encoded_len(), second.data.encoded_len());
        assert_ne!(
            image_attachment_digest(std::slice::from_ref(&first)),
            image_attachment_digest(std::slice::from_ref(&second)),
        );
        assert_ne!(
            image_attachment_digest(&[first.clone(), second.clone()]),
            image_attachment_digest(&[second, first]),
        );
    }
}
