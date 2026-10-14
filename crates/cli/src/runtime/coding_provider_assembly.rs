//! Captures concrete resident slots and invocation journals for the independent provider pump.
use super::Agent;
use super::coding_execution_journal::CodingExecutionJournal;
use super::coding_provider_session::{CodingProviderEvidence, CodingProviderSession};
use super::permission_policy::OperationPolicy;
use super::provider_turn_driver::{ProviderTurnEnvironment, ProviderTurnResident};
use iteron_protocol::{Trust, TurnId};
impl Agent {
    pub(super) fn coding_provider_session(
        &mut self,
        context_tokens: u64,
        trust: Trust,
    ) -> CodingProviderSession<'_> {
        let strict_controls = self.provider_extension_enabled();
        let output_proof_required = self.provider_output_proof_required();
        let authority = self.operator_authority();
        let requested_control = self.requested_control() != super::InboundControl::None;
        let publication = self.tool_output_publication_factory();
        let turn = TurnId(self.seq_turn);
        let memory_events = super::provider_route_events::ProviderRouteEvents {
            turn,
            lifecycle: self.lifecycle_emitter.clone(),
            hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
            activity: self.activity.clone(),
        };
        CodingProviderSession {
            journal: CodingExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                failed_actions: &mut self.failed_actions,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                policy: &mut self.policy_evidence,
                terminal: &mut self.terminal_record,
                publications: &mut self.turn_publications,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            environment: ProviderTurnEnvironment {
                workspace: &self.workspace,
                routes: &self.fallback_provider_routes,
                governor: self.provider_governor.as_ref(),
                control: &self.control,
                router: self.compiled_policy_bundle.slots().model_router.as_ref(),
                authority: self.authority_ceiling,
                controls: self.provider_controls,
                strict_controls,
                require_fallback_pricing: self.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0),
                output_proof_required,
                context_tokens,
                run_deadline: self.run_deadline.current(),
                #[cfg(test)]
                pricing_now_unix_secs: self.pricing_now_unix_secs,
            },
            resident: ProviderTurnResident {
                selection: &mut self.provider_selection,
                provider: &mut self.provider,
                model: &mut self.model,
                context_window: &mut self.model_context_window,
                max_output: &mut self.model_max_output_tokens,
            },
            extension: {
                #[cfg(feature = "legacy-plantcore")]
                {
                    super::provider_extension::ProviderExtensionPort::installed(&mut self.plantcore)
                }
                #[cfg(not(feature = "legacy-plantcore"))]
                {
                    super::provider_extension::ProviderExtensionPort::none()
                }
            },
            evidence: CodingProviderEvidence {
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
                requested_control,
                publication,
                spill: self.tool_output_spill.clone(),
            },
            memory: super::memory_request_exposure::MemoryRequestExposure {
                visibility: &mut self.session_memory_visibility,
                memory_traces: &self.memory_traces,
                events: memory_events,
            },
        }
    }
}
