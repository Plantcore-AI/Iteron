//! Source-separated request accounting over real immutable context evidence. Provider usage
//! calibration remains owned by TokenCalibrationStore; this adapter never fabricates usage.
use super::context_runtime::{ContextBudgetInspection, InputImageEvidence};
use super::file_submission::InputFileEvidence;
use iteron_ctx::{
    ContextBudgetPolicy, ContextComponentUsage, ContextDecision, ContextEstimate,
    ContextSegmentEvidence, ContextSourceClass, RequestEstimator, TokenCalibrationStore,
};
use iteron_protocol::{Block, Message, Role};

// Compiled fallbacks keep their existing profile addresses at this actual accounting owner.
const NO_ACTIVE_TASK_TOKENS: usize = 0;
const NO_ATTACHMENT_TOKENS: usize = 0;

#[derive(Default)]
struct SourcePartition {
    instructions: usize,
    memory: usize,
    task: usize,
}

pub(super) struct RequestAccounting {
    sources: SourcePartition,
    policy: ContextBudgetPolicy,
    calibration: TokenCalibrationStore,
    provider: String,
    model: String,
    file: Option<InputFileEvidence>,
    image: Option<InputImageEvidence>,
}

#[derive(Clone, Copy)]
pub(super) struct AccountedRequest {
    pub(super) baseline: usize,
    pub(super) estimate: ContextEstimate,
    pub(super) inspection: ContextBudgetInspection,
}

impl RequestAccounting {
    pub(super) fn new(
        sources: &[ContextSegmentEvidence],
        policy: ContextBudgetPolicy,
        calibration: TokenCalibrationStore,
        route: (&str, &str),
        file: Option<InputFileEvidence>,
        image: Option<InputImageEvidence>,
    ) -> Self {
        let mut partition = SourcePartition::default();
        for source in sources {
            if !matches!(
                source.decision,
                ContextDecision::Selected | ContextDecision::Truncated | ContextDecision::Compacted
            ) {
                continue;
            }
            let tokens = usize::try_from(source.estimated_tokens).unwrap_or(usize::MAX);
            let target = match source.source_class {
                ContextSourceClass::OperatorInstructions
                | ContextSourceClass::ProjectInstructions
                | ContextSourceClass::DirectoryInstructions => &mut partition.instructions,
                ContextSourceClass::UserMemory
                | ContextSourceClass::WorkspaceMemory
                | ContextSourceClass::SessionMemory => &mut partition.memory,
                ContextSourceClass::Environment
                | ContextSourceClass::WorkspaceOutline
                | ContextSourceClass::SkillIndex
                | ContextSourceClass::SkillReference
                | ContextSourceClass::WorkflowEvidence
                | ContextSourceClass::SubagentEvidence
                | ContextSourceClass::Steering
                | ContextSourceClass::QueuedSubmission => &mut partition.task,
                _ => continue,
            };
            *target = target.saturating_add(tokens);
        }
        Self {
            sources: partition,
            policy,
            calibration,
            provider: route.0.to_owned(),
            model: route.1.to_owned(),
            file,
            image,
        }
    }

    pub(super) fn project(
        &self,
        estimator: &RequestEstimator,
        messages: &[Message],
        raw: ContextEstimate,
    ) -> AccountedRequest {
        let baseline = self.with_images(raw).total_tokens;
        let estimate = self.with_images(self.calibrate(raw));
        let usage = self.components(estimator, messages, &estimate);
        let inspection = ContextBudgetInspection::from_policy(usage, self.policy);
        AccountedRequest {
            baseline,
            estimate,
            inspection,
        }
    }

    pub(super) fn clear_file(&mut self) {
        self.file = None;
    }

    fn with_images(&self, mut estimate: ContextEstimate) -> ContextEstimate {
        if let Some(image) = self.image {
            estimate.total_tokens = estimate
                .total_tokens
                .saturating_add(usize::try_from(image.estimated_tokens).unwrap_or(usize::MAX));
        }
        estimate
    }

    pub(super) fn calibrate(&self, estimate: ContextEstimate) -> ContextEstimate {
        calibrated_estimate(&self.calibration, (&self.provider, &self.model), estimate)
    }

    pub(super) fn components(
        &self,
        estimator: &RequestEstimator,
        messages: &[Message],
        estimate: &ContextEstimate,
    ) -> ContextComponentUsage {
        let active = messages
            .iter()
            .rfind(|message| {
                message.role == Role::User
                    && message
                        .content
                        .iter()
                        .any(|block| matches!(block, Block::Text { .. }))
            })
            .map(|message| {
                message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        Block::Text { text } => Some(estimator.estimate_text(text)),
                        _ => None,
                    })
                    .fold(0usize, usize::saturating_add)
            })
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.context_runtime.no_active_task_tokens",
                NO_ACTIVE_TASK_TOKENS,
            ));
        let file = self
            .file
            .map(|file| usize::try_from(file.estimated_tokens).unwrap_or(usize::MAX))
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.context_runtime.no_attachment_tokens",
                NO_ATTACHMENT_TOKENS,
            ))
            .min(active);
        let images = self
            .image
            .map(|image| usize::try_from(image.estimated_tokens).unwrap_or(usize::MAX))
            .unwrap_or(0);
        let classified = self
            .sources
            .instructions
            .saturating_add(self.sources.memory)
            .saturating_add(self.sources.task);
        ContextComponentUsage {
            stable_prefix_tokens: estimate.system_tokens.saturating_sub(classified),
            instruction_tokens: self.sources.instructions,
            memory_tokens: self.sources.memory,
            task_context_tokens: self
                .sources
                .task
                .saturating_add(active.saturating_sub(file)),
            transcript_tokens: estimate.conversation_tokens.saturating_sub(active),
            attachment_tokens: file.saturating_add(images),
            tool_schema_tokens: estimate.tool_tokens,
            tool_result_tokens: estimate.tool_result_tokens,
            lsp_result_tokens: estimate.lsp_result_tokens,
        }
    }
}

pub(super) fn calibrated_estimate(
    calibration: &TokenCalibrationStore,
    route: (&str, &str),
    mut estimate: ContextEstimate,
) -> ContextEstimate {
    let conservative = u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX);
    let calibrated = calibration.calibrated_estimate(route.0, route.1, conservative);
    let calibrated = usize::try_from(calibrated).unwrap_or(usize::MAX);
    let baseline = estimate.total_tokens;
    if baseline == 0 || calibrated == baseline {
        return estimate;
    }
    let scale = |value: usize| {
        value
            .saturating_mul(calibrated)
            .saturating_add(baseline.saturating_sub(1))
            / baseline
    };
    estimate.system_tokens = scale(estimate.system_tokens);
    estimate.tool_tokens = scale(estimate.tool_tokens);
    estimate.conversation_tokens = scale(estimate.conversation_tokens);
    estimate.tool_result_tokens = scale(estimate.tool_result_tokens);
    estimate.lsp_result_tokens = scale(estimate.lsp_result_tokens);
    estimate.transcript_tokens = estimate
        .conversation_tokens
        .saturating_add(estimate.tool_result_tokens)
        .saturating_add(estimate.lsp_result_tokens);
    estimate.framing_tokens = scale(estimate.framing_tokens);
    estimate.total_tokens = estimate
        .system_tokens
        .saturating_add(estimate.tool_tokens)
        .saturating_add(estimate.transcript_tokens)
        .saturating_add(estimate.framing_tokens);
    estimate
}
