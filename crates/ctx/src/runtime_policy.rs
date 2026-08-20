//! Runtime-effective context and materialization ceilings.

use crate::MemBudget;
use serde::{Deserialize, Serialize};

/// Model window assumed by the default budget split when no route has been selected yet.
const DEFAULT_MODEL_WINDOW_TOKENS: usize = 120_000;
/// Output space held back from input budgeting so a full answer always fits.
const DEFAULT_OUTPUT_RESERVE_TOKENS: u32 = 8_192;
/// Additional space held back for the post-answer verification pass.
const DEFAULT_VERIFICATION_RESERVE_TOKENS: u32 = 4_096;

/// Separately-accounted request components. These are ceilings, not allocation targets: unused
/// budget in one class cannot silently widen another class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBudgetPolicy {
    /// The immutable kernel/system prefix, excluding discovered instructions and memory.
    pub stable_prefix_tokens: usize,
    /// Operator/project/directory instructions after bounded discovery and rendering.
    pub instruction_tokens: usize,
    /// The active task plus bounded environment/outline/skill evidence selected for that task.
    pub task_context_tokens: usize,
    /// Recalled/indexed memory admitted after trust and retrieval policy.
    pub memory_tokens: usize,
    /// Prior user/assistant conversation, excluding the active task and tool-result bodies.
    pub transcript_tokens: usize,
    /// File attachment text carried by the active submission. Image input has its own provider-
    /// specific multimodal ceiling below.
    pub attachment_tokens: usize,
    pub tool_schema_tokens: usize,
    pub tool_result_tokens: usize,
    pub lsp_result_tokens: usize,
    pub multimodal_tokens: usize,
    pub output_reserve_tokens: u32,
    pub verification_reserve_tokens: u32,
}

impl Default for ContextBudgetPolicy {
    fn default() -> Self {
        Self::for_usable_window(
            iteron_tunables::param_usize(
                "ctx.runtime_policy.default_model_window_tokens",
                iteron_tunables::param_integer(
                    "ctx.runtime_policy.default_model_window_tokens",
                    DEFAULT_MODEL_WINDOW_TOKENS,
                ),
            ),
            u32::try_from(iteron_tunables::param_i128(
                "ctx.runtime_policy.default_output_reserve_tokens",
                i128::from(iteron_tunables::param_integer(
                    "ctx.runtime_policy.default_output_reserve_tokens",
                    DEFAULT_OUTPUT_RESERVE_TOKENS,
                )),
            ))
            .unwrap_or(iteron_tunables::param_integer(
                "ctx.runtime_policy.default_output_reserve_tokens",
                DEFAULT_OUTPUT_RESERVE_TOKENS,
            )),
            u32::try_from(iteron_tunables::param_i128(
                "ctx.runtime_policy.default_verification_reserve_tokens",
                i128::from(iteron_tunables::param_integer(
                    "ctx.runtime_policy.default_verification_reserve_tokens",
                    DEFAULT_VERIFICATION_RESERVE_TOKENS,
                )),
            ))
            .unwrap_or(iteron_tunables::param_integer(
                "ctx.runtime_policy.default_verification_reserve_tokens",
                DEFAULT_VERIFICATION_RESERVE_TOKENS,
            )),
        )
    }
}

impl ContextBudgetPolicy {
    pub fn for_usable_window(
        model_window_tokens: usize,
        output_reserve_tokens: u32,
        verification_reserve_tokens: u32,
    ) -> Self {
        let reserves = usize::try_from(
            u64::from(output_reserve_tokens) + u64::from(verification_reserve_tokens),
        )
        .unwrap_or(usize::MAX);
        let usable = model_window_tokens.saturating_sub(reserves);
        Self {
            stable_prefix_tokens: usable.saturating_mul(10) / 100,
            instruction_tokens: usable.saturating_mul(5) / 100,
            task_context_tokens: usable.saturating_mul(10) / 100,
            memory_tokens: usable.saturating_mul(10) / 100,
            transcript_tokens: usable.saturating_mul(25) / 100,
            attachment_tokens: usable.saturating_mul(5) / 100,
            tool_schema_tokens: usable.saturating_mul(5) / 100,
            tool_result_tokens: usable.saturating_mul(15) / 100,
            lsp_result_tokens: usable.saturating_mul(5) / 100,
            multimodal_tokens: usable.saturating_mul(10) / 100,
            output_reserve_tokens,
            verification_reserve_tokens,
        }
    }

    /// Verify that the independently-owned component ceilings fit inside the request window.
    /// Component ceilings are deliberately non-transferable, but their aggregate still has to be
    /// physically possible on the selected route. Multimodal input consumes the same provider
    /// context window, so its ceiling participates in this bound as well.
    pub fn validate_for_window(&self, model_window_tokens: usize) -> Result<(), &'static str> {
        let reserves = usize::try_from(
            u64::from(self.output_reserve_tokens)
                .saturating_add(u64::from(self.verification_reserve_tokens)),
        )
        .unwrap_or(usize::MAX);
        if reserves > model_window_tokens {
            return Err("context reserves exceed the selected model window");
        }
        let component_ceiling = [
            self.stable_prefix_tokens,
            self.instruction_tokens,
            self.task_context_tokens,
            self.memory_tokens,
            self.transcript_tokens,
            self.attachment_tokens,
            self.tool_schema_tokens,
            self.tool_result_tokens,
            self.lsp_result_tokens,
            self.multimodal_tokens,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or("context component ceilings overflow")?;
        if component_ceiling > model_window_tokens.saturating_sub(reserves) {
            return Err("context component ceilings exceed the usable model window");
        }
        Ok(())
    }

    /// Admit the exact component projection assembled by the production request path. Keeping
    /// this separate from [`ContextEstimate`] is intentional: the provider wire estimate knows
    /// the aggregate serialized system/transcript cost, while the runtime owns the source
    /// boundaries needed to prevent unused memory or attachment budget from widening history.
    pub fn admit_components(
        &self,
        usage: &ContextComponentUsage,
    ) -> Result<(), ContextBudgetViolation> {
        for (class, used, ceiling) in [
            (
                ContextBudgetClass::StablePrefix,
                usage.stable_prefix_tokens,
                self.stable_prefix_tokens,
            ),
            (
                ContextBudgetClass::Instructions,
                usage.instruction_tokens,
                self.instruction_tokens,
            ),
            (
                ContextBudgetClass::TaskContext,
                usage.task_context_tokens,
                self.task_context_tokens,
            ),
            (
                ContextBudgetClass::Memory,
                usage.memory_tokens,
                self.memory_tokens,
            ),
            (
                ContextBudgetClass::Transcript,
                usage.transcript_tokens,
                self.transcript_tokens,
            ),
            (
                ContextBudgetClass::Attachments,
                usage.attachment_tokens,
                self.attachment_tokens,
            ),
            (
                ContextBudgetClass::ToolSchemas,
                usage.tool_schema_tokens,
                self.tool_schema_tokens,
            ),
            (
                ContextBudgetClass::ToolResults,
                usage.tool_result_tokens,
                self.tool_result_tokens,
            ),
            (
                ContextBudgetClass::LspResults,
                usage.lsp_result_tokens,
                self.lsp_result_tokens,
            ),
        ] {
            if used > ceiling {
                return Err(ContextBudgetViolation {
                    class,
                    used,
                    ceiling,
                });
            }
        }
        Ok(())
    }

    pub fn admit_multimodal(&self, estimated_tokens: usize) -> Result<(), ContextBudgetViolation> {
        if estimated_tokens > self.multimodal_tokens {
            return Err(ContextBudgetViolation {
                class: ContextBudgetClass::Multimodal,
                used: estimated_tokens,
                ceiling: self.multimodal_tokens,
            });
        }
        Ok(())
    }
}

/// Source-separated request usage. Every field is estimated with the same explicitly identified
/// estimator as the aggregate request, but none overlaps another field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextComponentUsage {
    pub stable_prefix_tokens: usize,
    pub instruction_tokens: usize,
    pub task_context_tokens: usize,
    pub memory_tokens: usize,
    pub transcript_tokens: usize,
    pub attachment_tokens: usize,
    pub tool_schema_tokens: usize,
    pub tool_result_tokens: usize,
    pub lsp_result_tokens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextBudgetClass {
    StablePrefix,
    Instructions,
    TaskContext,
    Memory,
    Transcript,
    Attachments,
    ToolSchemas,
    ToolResults,
    LspResults,
    Multimodal,
}

impl ContextBudgetClass {
    /// Whether compacting prior transcript entries can reduce this component's usage.
    ///
    /// Keep this exhaustive: budget classes outside transcript history must fail closed rather
    /// than enter a recovery path that cannot change their projection.
    pub const fn is_transcript_compaction_recoverable(self) -> bool {
        matches!(
            self,
            Self::Transcript | Self::ToolResults | Self::LspResults
        )
    }

    /// Stable, allocation-free reason code suitable for lifecycle event labels.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::StablePrefix => "context_budget_stable_prefix",
            Self::Instructions => "context_budget_instructions",
            Self::TaskContext => "context_budget_task_context",
            Self::Memory => "context_budget_memory",
            Self::Transcript => "context_budget_transcript",
            Self::Attachments => "context_budget_attachments",
            Self::ToolSchemas => "context_budget_tool_schemas",
            Self::ToolResults => "context_budget_tool_results",
            Self::LspResults => "context_budget_lsp_results",
            Self::Multimodal => "context_budget_multimodal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudgetViolation {
    pub class: ContextBudgetClass,
    pub used: usize,
    pub ceiling: usize,
}

impl ContextBudgetViolation {
    /// Whether transcript compaction can make a subsequent admission attempt succeed.
    pub const fn is_transcript_compaction_recoverable(&self) -> bool {
        self.class.is_transcript_compaction_recoverable()
    }

    /// Stable, allocation-free lifecycle reason code for the violated component.
    pub const fn reason_code(&self) -> &'static str {
        self.class.reason_code()
    }
}

impl std::fmt::Display for ContextBudgetViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?} context used {} tokens, exceeding its {}-token ceiling",
            self.class, self.used, self.ceiling
        )
    }
}

impl std::error::Error for ContextBudgetViolation {}

/// Limits used while materializing one immutable injected context segment.
#[derive(Debug, Clone, Copy)]
pub struct ContextMaterializationPolicy {
    pub max_bytes: u32,
    pub memory: MemBudget,
    pub memory_retrieval: crate::MemoryRetrievalPolicy,
    pub skill_listing_bytes: usize,
    /// Filesystem traversal and rendering limits pinned by family 29 at run genesis.
    pub instruction_discovery: crate::InstructionDiscoveryPolicy,
}

impl Default for ContextMaterializationPolicy {
    fn default() -> Self {
        Self {
            max_bytes: iteron_protocol::context::MAX_CONTEXT_GRANT_BYTES,
            memory: MemBudget::default(),
            memory_retrieval: crate::MemoryRetrievalPolicy::default(),
            skill_listing_bytes: iteron_tunables::param_usize(
                "ctx.runtime_policy.default_skill_listing_bytes",
                6_000,
            ),
            instruction_discovery: crate::InstructionDiscoveryPolicy::owner(),
        }
    }
}

impl ContextMaterializationPolicy {
    pub fn validate(self) -> Result<Self, &'static str> {
        self.memory_retrieval.validate()?;
        let memory_sum = self
            .memory
            .index_bytes
            .saturating_add(self.memory.recall_bytes)
            .saturating_add(self.memory.instr_bytes);
        if memory_sum > self.memory.total {
            return Err("memory component budgets exceed the total memory ceiling");
        }
        if usize::try_from(self.max_bytes).unwrap_or(usize::MAX) < self.memory.total {
            return Err("memory total exceeds the injected context byte ceiling");
        }
        crate::InstructionDiscoveryPolicy::try_new(
            self.instruction_discovery.max_depth,
            self.instruction_discovery.max_files,
            self.instruction_discovery.per_file_bytes,
            self.instruction_discovery.total_bytes,
        )?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_budget_is_not_transferable() {
        let policy = ContextBudgetPolicy::for_usable_window(100_000, 8_000, 2_000);
        let usage = ContextComponentUsage {
            stable_prefix_tokens: policy.stable_prefix_tokens + 1,
            ..ContextComponentUsage::default()
        };
        assert_eq!(
            policy.admit_components(&usage).unwrap_err().class,
            ContextBudgetClass::StablePrefix
        );
    }

    #[test]
    fn lsp_evidence_has_a_non_transferable_attributed_budget() {
        let policy = ContextBudgetPolicy::for_usable_window(100_000, 8_000, 2_000);
        let usage = ContextComponentUsage {
            lsp_result_tokens: policy.lsp_result_tokens + 1,
            tool_result_tokens: 0,
            ..ContextComponentUsage::default()
        };
        let violation = policy.admit_components(&usage).unwrap_err();
        assert_eq!(violation.class, ContextBudgetClass::LspResults);
        assert_eq!(violation.ceiling, policy.lsp_result_tokens);
    }

    #[test]
    fn only_transcript_owned_components_are_compaction_recoverable() {
        for class in [
            ContextBudgetClass::Transcript,
            ContextBudgetClass::ToolResults,
            ContextBudgetClass::LspResults,
        ] {
            assert!(class.is_transcript_compaction_recoverable());
            assert!(
                ContextBudgetViolation {
                    class,
                    used: 2,
                    ceiling: 1,
                }
                .is_transcript_compaction_recoverable()
            );
        }

        for class in [
            ContextBudgetClass::StablePrefix,
            ContextBudgetClass::Instructions,
            ContextBudgetClass::TaskContext,
            ContextBudgetClass::Memory,
            ContextBudgetClass::Attachments,
            ContextBudgetClass::ToolSchemas,
            ContextBudgetClass::Multimodal,
        ] {
            assert!(!class.is_transcript_compaction_recoverable());
        }
    }

    #[test]
    fn budget_reason_codes_are_stable_and_lifecycle_safe() {
        let expected = [
            (
                ContextBudgetClass::StablePrefix,
                "context_budget_stable_prefix",
            ),
            (
                ContextBudgetClass::Instructions,
                "context_budget_instructions",
            ),
            (
                ContextBudgetClass::TaskContext,
                "context_budget_task_context",
            ),
            (ContextBudgetClass::Memory, "context_budget_memory"),
            (ContextBudgetClass::Transcript, "context_budget_transcript"),
            (
                ContextBudgetClass::Attachments,
                "context_budget_attachments",
            ),
            (
                ContextBudgetClass::ToolSchemas,
                "context_budget_tool_schemas",
            ),
            (
                ContextBudgetClass::ToolResults,
                "context_budget_tool_results",
            ),
            (ContextBudgetClass::LspResults, "context_budget_lsp_results"),
            (ContextBudgetClass::Multimodal, "context_budget_multimodal"),
        ];

        for (class, expected_code) in expected {
            let violation = ContextBudgetViolation {
                class,
                used: 2,
                ceiling: 1,
            };
            assert_eq!(class.reason_code(), expected_code);
            assert_eq!(violation.reason_code(), expected_code);
            assert!(expected_code.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            }));
        }
    }
}
