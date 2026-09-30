//! Composition-only port factories for the independent model-turn driver. All stateful policy,
//! execution, journal and pricing behavior belongs to its concrete owners.
use super::permission_policy::OperationPolicy;
use super::provider_execution_scope::ProviderExecutionEvidence;
use super::provider_route_binding::{
    ProviderRouteBindingJournal, ProviderRouteBindingOwner, ProviderRouteBindingScope,
};
use super::provider_selection_journal::ProviderSelectionJournal;
use super::provider_turn_driver::{
    ProviderTurnEnvironment, ProviderTurnJournal, ProviderTurnResident,
};
use super::submitted_turn_state::SubmittedTurnState;
use super::{Agent, KernelError};
use iteron_protocol::{Trust, TurnId};

impl Agent {
    pub(super) fn provider_turn_ports(
        &mut self,
        context_tokens: u64,
    ) -> (
        ProviderTurnJournal<'_>,
        ProviderTurnEnvironment<'_>,
        ProviderTurnResident<'_>,
        &mut super::plantcore::PlantcoreRuntime,
    ) {
        let strict_controls = self.plantcore_runtime_enabled();
        let output_proof_required = self.provider_output_proof_required();
        (
            ProviderTurnJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                policy: self.policy_evidence.as_mut(),
                terminal: &mut self.terminal_record,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            ProviderTurnEnvironment {
                workspace: &self.workspace,
                routes: &self.fallback_provider_routes,
                governor: self.provider_governor.as_ref(),
                control: &self.control,
                router: self.model_router.as_ref(),
                authority: self.authority_ceiling,
                controls: self.provider_controls,
                strict_controls,
                require_fallback_pricing: self.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0),
                output_proof_required,
                context_tokens,
                run_deadline: self.run_deadline,
                #[cfg(test)]
                pricing_now_unix_secs: self.pricing_now_unix_secs,
            },
            ProviderTurnResident {
                selection: &mut self.provider_selection,
                provider: &mut self.provider,
                model: &mut self.model,
                context_window: &mut self.model_context_window,
                max_output: &mut self.model_max_output_tokens,
            },
            &mut self.plantcore,
        )
    }

    pub(super) fn provider_turn_execution_ports<'a>(
        &'a mut self,
        trust: Trust,
        submitted: &'a SubmittedTurnState,
    ) -> (ProviderTurnJournal<'a>, ProviderExecutionEvidence<'a>) {
        let authority = self.operator_authority();
        let requested_control = self.requested_control() != super::InboundControl::None;
        let publication = self.tool_output_publication_factory();
        (
            ProviderTurnJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                policy: self.policy_evidence.as_mut(),
                terminal: &mut self.terminal_record,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            ProviderExecutionEvidence {
                workspace: &self.workspace,
                registry: &self.registry,
                operation: OperationPolicy {
                    mode: self.permission_mode,
                    rules: &self.permission_rules,
                    bypass: self.bypass_permissions,
                    task_ceiling: self.authority_ceiling,
                    policy_capabilities: self.policy_capabilities,
                    governing_trust: trust,
                    authority,
                },
                failed_actions: &self.failed_actions,
                recovered: submitted,
                requested_control,
                publication,
                spill: self.tool_output_spill.clone(),
            },
        )
    }

    pub(super) fn provider_route_binding(
        &mut self,
        turn: TurnId,
    ) -> Result<ProviderRouteBindingOwner<'_>, KernelError> {
        self.ensure_policy_evidence()?;
        let strict_controls = self.plantcore_runtime_enabled();
        Ok(ProviderRouteBindingOwner {
            selected: &mut self.provider_selection,
            provider: &mut self.provider,
            model: &mut self.model,
            journal: ProviderRouteBindingJournal {
                selection: ProviderSelectionJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                policy: self.policy_evidence.as_mut(),
            },
            scope: ProviderRouteBindingScope {
                turn,
                router: self.model_router.as_ref(),
                authority: self.authority_ceiling,
                controls: self.provider_controls,
                strict_controls,
                governor: self.provider_governor.as_ref(),
            },
        })
    }
}
