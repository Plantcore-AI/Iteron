//! Runtime-effective context and materialization ceilings.

use crate::MemBudget;
use serde::{Deserialize, Serialize};

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
        Self::for_usable_window(120_000, 8_192, 4_096)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudgetViolation {
    pub class: ContextBudgetClass,
    pub used: usize,
    pub ceiling: usize,
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
            skill_listing_bytes: 2_000,
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
}
