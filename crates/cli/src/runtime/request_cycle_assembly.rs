//! Freeze current request inputs before recovery. This factory grants no IO authority; native
//! output/funding proof and actual context projection are still enforced by their single owners.
use super::context_runtime::ToolProjectionPosture;
use super::investigation_convergence::InvestigationConvergence;
use super::request_cycle::RequestCycleRecipe;
use super::request_preparation::RequestContent;
use super::request_recovery_driver::RequestRecoveryScope;
use super::{Agent, KernelError};
use iteron_protocol::{ImageContent, Message, TurnId};
use iteron_provider::output_ceiling::ProviderOutputBudget;
use std::time::Instant;

impl Agent {
    /// Capture fallible host evidence before moving the invocation working transcript.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn request_cycle_seed(
        &mut self,
        turn: TurnId,
        images: &[ImageContent],
        relevance: &str,
        convergence: &InvestigationConvergence,
        started: Instant,
    ) -> Result<RequestCycleRecipe<'static>, KernelError> {
        let mut placeholder = Vec::new();
        let recipe = self.request_cycle_recipe(
            turn,
            &mut placeholder,
            images,
            relevance,
            convergence,
            started,
        )?;
        let RequestCycleRecipe {
            content,
            requested_output,
            window,
            accounting,
            recovery,
            started,
        } = recipe;
        let RequestContent {
            system,
            messages: _,
            input_images,
            tools,
            max_tokens,
        } = content;
        Ok(RequestCycleRecipe {
            content: RequestContent {
                system,
                messages: super::request_preparation::RequestMessages::Owned(Vec::new()),
                input_images,
                tools,
                max_tokens,
            },
            requested_output,
            window,
            accounting,
            recovery,
            started,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn request_cycle_recipe<'a>(
        &mut self,
        turn: TurnId,
        messages: &'a mut Vec<Message>,
        images: &[ImageContent],
        relevance: &str,
        convergence: &InvestigationConvergence,
        started: Instant,
    ) -> Result<RequestCycleRecipe<'a>, KernelError> {
        let system = self.effective_system();
        let posture = if convergence.enabled() {
            ToolProjectionPosture {
                patch_trial: convergence.patch_trial_active(),
                candidate_change_required: convergence.candidate_change_required(),
                candidate_revision_required: convergence.candidate_revision_required(),
                candidate_owner_evidence_required: convergence.candidate_owner_evidence_required(),
                structural_repair_read_required: convergence.structural_repair_read_required(),
                behavior_counterexample_read_required: convergence
                    .behavior_counterexample_read_required(),
                localized_closure_active: convergence.localized_closure_active(),
                candidate_review_active: convergence.candidate_review_active()
                    || convergence.localization_plateau_active(),
                evidence_insufficient_terminal: convergence.evidence_insufficient_terminal(),
                candidate_handoff_terminal: convergence.candidate_handoff_terminal(),
            }
        } else {
            ToolProjectionPosture::default()
        };
        let tools = self.advertised_tool_specs_for_task_with_patch_trial(relevance, posture);
        let requested_output = self
            .model_max_output_tokens
            .unwrap_or(crate::runtime_tunables::core_facts::DEFAULT_REQUEST_OUTPUT_TOKENS);
        let max_tokens = self.funded_provider_output_ceiling(ProviderOutputBudget {
            model: &self.model,
            requested_max_tokens: requested_output,
            thinking_budget: self.effort_thinking_budget(self.effort),
        })?;
        Ok(RequestCycleRecipe {
            content: RequestContent {
                system,
                messages: super::request_preparation::RequestMessages::Borrowed(messages),
                input_images: images.to_vec(),
                tools,
                max_tokens,
            },
            requested_output,
            window: self.execution_context_window(),
            accounting: self.request_accounting(),
            recovery: RequestRecoveryScope {
                turn,
                policy: self.compaction,
                compacted: self.compaction_state.compacted(),
                events: self.context_preparation_events(),
            },
            started,
        })
    }
}
