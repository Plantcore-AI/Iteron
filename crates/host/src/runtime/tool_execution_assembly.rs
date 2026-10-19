//! Capture only actual completed-response tool ports. No Agent or provider loop reaches the
//! executable session; ordinary schema/effect dispatch reads the same mutable permission owner.
use super::Agent;
use super::context_runtime::TurnResultProjectionBudget;
use super::permission_transaction::PermissionTransaction;
use super::tool_declaration_admission::ToolAdmissionScope;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_execution_session::{
    ToolExecutionControl, ToolExecutionOutput, ToolExecutionSchedule, ToolExecutionSession,
};
use iteron_protocol::{Message, TurnId};

impl Agent {
    pub(super) fn tool_execution_session(
        &mut self,
        turn: TurnId,
        messages: &[Message],
        projection: TurnResultProjectionBudget,
    ) -> ToolExecutionSession<'_> {
        let events = self.tool_events(turn);
        let trust = self.governing_turn_trust(messages);
        let authority = self.operator_authority();
        let publication = self.tool_output_publication_factory();
        let gate = self.provider_dispatch_gate();
        let artifact_enabled = self.provider_extension_enabled();
        let additional_external_tool = {
            #[cfg(feature = "legacy-plantcore")]
            {
                artifact_enabled.then_some("plantcore-run-gateway__tool_search")
            }
            #[cfg(not(feature = "legacy-plantcore"))]
            {
                None
            }
        };
        ToolExecutionSession {
            journal: ToolExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                failed_actions: &mut self.failed_actions,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            control: ToolExecutionControl {
                inbox: &mut self.inbox,
                state: &mut self.control,
                force_cancel: self.force_cancel_seam.as_mut(),
                approval_sequence: &mut self.approval_seq,
            },
            permission: PermissionTransaction {
                mode: &mut self.permission_mode,
                rules: &mut self.permission_rules,
                provenance: &mut self.runtime_policy_provenance,
                effort: self.effort,
                max_turns: self.budget.max_turns,
            },
            scope: ToolAdmissionScope {
                turn,
                registry: &self.registry,
                workspace: &self.workspace,
                hooks: &self.hooks,
                hook_journal: self.hook_effect_journal.clone(),
                trust,
                authority,
                ceiling: self.authority_ceiling,
                policy_capabilities: self.policy_capabilities,
                bypass: self.bypass_permissions,
                ordinary_extensions: self.ordinary_extensions.is_some(),
                interactive: self.interactive_approvals,
                deadline: self.run_deadline.current(),
                activity: self.activity.clone(),
                events,
            },
            output: ToolExecutionOutput {
                publication,
                spill: self.tool_output_spill.clone(),
                projection,
                external_gate: gate,
                additional_external_tool,
                artifact_enabled,
            },
            schedule: ToolExecutionSchedule {
                concurrency: self
                    .execution_policy
                    .effecting_tool_admission
                    .max_concurrency,
                declared_set_required: self
                    .execution_policy
                    .effecting_tool_admission
                    .declared_set_required,
            },
        }
    }
}
