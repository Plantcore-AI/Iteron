//! Concrete batch composition. Pure prefix policy and disjoint actual owner borrowing carry
//! no receiver, hook, journal or physical execution algorithms.
use super::context_runtime::TurnResultProjectionBudget;
use super::deferred_batch_admission::DeferredBatchAdmission;
use super::deferred_tool_batch::DeferredToolScope;
use super::deferred_tools::DeferredBatchPolicy;
use super::hook_execution::HookExecutionScope;
use super::tool_execution_journal::ToolExecutionJournal;
use super::{Agent, permission_policy};
use iteron_protocol::{Message, TurnId};
use iteron_sched::Governor;
impl Agent {
    pub(super) fn deferred_batch_policy<'a>(
        &'a self,
        messages: &[Message],
    ) -> DeferredBatchPolicy<'a> {
        DeferredBatchPolicy {
            registry: &self.registry,
            operation: permission_policy::OperationPolicy {
                mode: self.permission_mode,
                rules: &self.permission_rules,
                bypass: self.bypass_permissions,
                task_ceiling: self.authority_ceiling,
                policy_capabilities: self.policy_capabilities,
                governing_trust: self.governing_turn_trust(messages),
                authority: self.operator_authority(),
            },
            failed_actions: &self.failed_actions,
            declared_set_required: self
                .execution_policy
                .effecting_tool_admission
                .declared_set_required,
            external_dispatch_gate: self.plantcore_dispatch_gate().is_some(),
            plantcore_gateway_enabled: self.plantcore_runtime_enabled(),
        }
    }
    pub(super) fn deferred_batch_admission<'a>(
        &'a mut self,
        turn: TurnId,
        governor: &'a Governor,
        projection: TurnResultProjectionBudget,
    ) -> DeferredBatchAdmission<'a> {
        let events = self.tool_events(turn);
        let publication = self.tool_output_publication_factory();
        let hooks = HookExecutionScope {
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
        let interrupt = self.control.interrupt().cloned();
        let force_cancel = self.control.force_cancel().clone();
        let drain = self.control.drain().clone();
        DeferredBatchAdmission {
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
            scope: DeferredToolScope {
                turn,
                registry: &self.registry,
                governor,
                spill_owner: self.tool_output_spill.clone(),
                interrupt,
                force_cancel,
                drain,
                projection,
                publication,
                hooks,
                events,
            },
            inbox: &mut self.inbox,
            control: &mut self.control,
            force_cancel: self.force_cancel_seam.as_mut(),
            deadline: self.run_deadline,
        }
    }
}
