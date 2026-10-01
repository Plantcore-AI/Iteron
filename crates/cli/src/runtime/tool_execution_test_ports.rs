//! Test-only trusted port conveniences for the existing physical admission/executor fixtures.
//! Production whole-round composition lives in ToolExecutionSession, not these Agent helpers.
use super::Agent;
use super::{
    context_runtime, hook_execution, ordered_tool_call, permission_transaction,
    tool_declaration_admission, tool_execution_journal,
};
use iteron_protocol::{Trust, TurnId};

impl Agent {
    /// Assemble the ordered effect owner from real disjoint state ports. No permission or
    /// provider authority reaches its executor, and the external permit remains with this loop.
    fn tool_declaration_admission(
        &mut self,
        turn: TurnId,
        trust: Trust,
    ) -> tool_declaration_admission::ToolDeclarationAdmission<'_> {
        let events = self.tool_events(turn);
        let authority = self.operator_authority();
        tool_declaration_admission::ToolDeclarationAdmission {
            journal: tool_execution_journal::ToolExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                failed_actions: &mut self.failed_actions,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            inbox: &mut self.inbox,
            control: &mut self.control,
            force_cancel: self.force_cancel_seam.as_mut(),
            approval_sequence: &mut self.approval_seq,
            permission: permission_transaction::PermissionTransaction {
                mode: &mut self.permission_mode,
                rules: &mut self.permission_rules,
                provenance: &mut self.runtime_policy_provenance,
                effort: self.effort,
                max_turns: self.budget.max_turns,
            },
            scope: tool_declaration_admission::ToolAdmissionScope {
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
        }
    }

    fn ordered_tool_call(
        &mut self,
        turn: TurnId,
        tool: &str,
        settle_on_drain: bool,
        projection: context_runtime::TurnResultProjectionBudget,
    ) -> ordered_tool_call::OrderedToolCall<'_> {
        let events = self.tool_events(turn);
        let publication = self.tool_output_publication_factory();
        let spill = self.ordinary_tool_spill_store(tool);
        let hooks = hook_execution::HookExecutionScope {
            turn,
            workspace: self.workspace.as_path(),
            hooks: &self.hooks,
            command_journal: self.hook_effect_journal.clone(),
            interrupt: self.control.interrupt().cloned(),
            drain: self.control.drain().clone(),
            activity: self.activity.clone(),
            emitter: self.lifecycle_emitter.clone(),
            dispatcher: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        ordered_tool_call::OrderedToolCall {
            journal: tool_execution_journal::ToolExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                failed_actions: &mut self.failed_actions,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            scope: ordered_tool_call::OrderedToolScope {
                registry: &self.registry,
                interrupt: self.control.interrupt().cloned(),
                force_cancel: self.control.force_cancel().clone(),
                drain: self.control.drain().clone(),
                settle_on_drain,
                spill,
                projection,
                publication,
                hooks,
                events,
            },
        }
    }
}
