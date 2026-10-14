//! Concrete ports for one completed-response tool phase. The same journal/control/permission
//! owners are reborrowed for early collection, batch admission and ordered effects.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::artifact_publication::ToolOutputPublicationFactory;
use super::context_runtime::TurnResultProjectionBudget;
use super::control_ingress::ControlIngress;
use super::deferred_batch_admission::DeferredBatchAdmission;
use super::deferred_tool_batch::DeferredToolScope;
use super::deferred_tools::DeferredBatchPolicy;
use super::early_tool_collection::{EarlyToolCollection, EarlyToolCollectionScope};
use super::force_cancel::ForceCancelSeam;
use super::hook_execution::HookExecutionScope;
use super::ordered_tool_call::{OrderedToolCall, OrderedToolScope};
use super::permission_policy::OperationPolicy;
use super::permission_transaction::PermissionTransaction;
use super::provider_extension::{ProviderDispatchGate, ProviderExtensionPermit, enter_owned_gate};
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::tool_declaration_admission::{ToolAdmissionScope, ToolDeclarationAdmission};
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_output_spill::ToolOutputSpillStore;
use super::tool_presentation::tool_end_ui;
use iteron_protocol::{ToolResult, ToolUse, Trust};
use iteron_sched::Governor;
use std::sync::Arc;

pub(super) struct ToolExecutionControl<'a> {
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) state: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) approval_sequence: &'a mut u64,
}
pub(super) struct ToolExecutionOutput {
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
    pub(super) projection: TurnResultProjectionBudget,
    pub(super) external_gate: Option<Arc<dyn ProviderDispatchGate>>,
    pub(super) additional_external_tool: Option<&'static str>,
    pub(super) artifact_enabled: bool,
}
pub(super) struct ToolExecutionSchedule {
    pub(super) concurrency: usize,
    pub(super) declared_set_required: bool,
}
pub(super) struct ToolExecutionSession<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) control: ToolExecutionControl<'a>,
    pub(super) permission: PermissionTransaction<'a>,
    pub(super) scope: ToolAdmissionScope<'a>,
    pub(super) output: ToolExecutionOutput,
    pub(super) schedule: ToolExecutionSchedule,
}

impl<'scope> ToolExecutionSession<'scope> {
    fn journal(&mut self) -> ToolExecutionJournal<'_> {
        ToolExecutionJournal {
            rollout: &mut *self.journal.rollout,
            effects: &mut *self.journal.effects,
            ledger: &mut *self.journal.ledger,
            failed_actions: &mut *self.journal.failed_actions,
            record_failed: &mut *self.journal.record_failed,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: &mut *self.journal.fault,
        }
    }
    fn hooks(&self) -> HookExecutionScope<'scope> {
        HookExecutionScope {
            turn: self.scope.turn,
            workspace: self.scope.workspace,
            hooks: self.scope.hooks,
            command_journal: self.scope.hook_journal.clone(),
            interrupt: self.control.state.interrupt().cloned(),
            drain: self.control.state.drain().clone(),
            activity: self.scope.activity.clone(),
            emitter: self.scope.events.lifecycle.clone(),
            dispatcher: self.scope.events.lifecycle_hooks.clone(),
            correlation: self.scope.events.correlation.clone(),
        }
    }
    pub(super) fn early(&mut self) -> EarlyToolCollection<'_> {
        let hooks = self.hooks();
        EarlyToolCollection {
            journal: ToolExecutionJournal {
                rollout: &mut *self.journal.rollout,
                effects: &mut *self.journal.effects,
                ledger: &mut *self.journal.ledger,
                failed_actions: &mut *self.journal.failed_actions,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            scope: EarlyToolCollectionScope {
                turn: self.scope.turn,
                registry: self.scope.registry,
                hooks,
                events: self.scope.events.clone(),
                deadline: self.scope.deadline,
            },
        }
    }
    pub(super) fn batch_policy(&self) -> DeferredBatchPolicy<'_> {
        DeferredBatchPolicy {
            registry: self.scope.registry,
            operation: OperationPolicy {
                mode: *self.permission.mode,
                rules: self.permission.rules,
                bypass: self.scope.bypass,
                task_ceiling: self.scope.ceiling,
                policy_capabilities: self.scope.policy_capabilities,
                governing_trust: self.scope.trust,
                authority: self.scope.authority,
            },
            failed_actions: self.journal.failed_actions,
            declared_set_required: self.schedule.declared_set_required,
            external_dispatch_gate: self.output.external_gate.is_some(),
            plantcore_gateway_enabled: self.output.additional_external_tool.is_some(),
        }
    }
    pub(super) fn batch<'a>(&'a mut self, governor: &'a Governor) -> DeferredBatchAdmission<'a> {
        let hooks = self.hooks();
        let scope = DeferredToolScope {
            turn: self.scope.turn,
            registry: self.scope.registry,
            governor,
            spill_owner: self.output.spill.clone(),
            interrupt: self.control.state.interrupt().cloned(),
            force_cancel: self.control.state.force_cancel().clone(),
            drain: self.control.state.drain().clone(),
            projection: self.output.projection,
            publication: self.output.publication.clone(),
            hooks,
            events: self.scope.events.clone(),
        };
        DeferredBatchAdmission {
            journal: ToolExecutionJournal {
                rollout: &mut *self.journal.rollout,
                effects: &mut *self.journal.effects,
                ledger: &mut *self.journal.ledger,
                failed_actions: &mut *self.journal.failed_actions,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            scope,
            inbox: &mut *self.control.inbox,
            control: &mut *self.control.state,
            force_cancel: self.control.force_cancel.as_deref_mut(),
            deadline: self.scope.deadline,
        }
    }
    pub(super) fn admission(&mut self) -> ToolDeclarationAdmission<'_> {
        ToolDeclarationAdmission {
            journal: ToolExecutionJournal {
                rollout: &mut *self.journal.rollout,
                effects: &mut *self.journal.effects,
                ledger: &mut *self.journal.ledger,
                failed_actions: &mut *self.journal.failed_actions,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            inbox: &mut *self.control.inbox,
            control: &mut *self.control.state,
            force_cancel: self.control.force_cancel.as_deref_mut(),
            approval_sequence: &mut *self.control.approval_sequence,
            permission: PermissionTransaction {
                mode: &mut *self.permission.mode,
                rules: &mut *self.permission.rules,
                provenance: &mut *self.permission.provenance,
                effort: self.permission.effort,
                max_turns: self.permission.max_turns,
            },
            scope: ToolAdmissionScope {
                turn: self.scope.turn,
                registry: self.scope.registry,
                workspace: self.scope.workspace,
                hooks: self.scope.hooks,
                hook_journal: self.scope.hook_journal.clone(),
                trust: self.scope.trust,
                authority: self.scope.authority,
                ceiling: self.scope.ceiling,
                policy_capabilities: self.scope.policy_capabilities,
                bypass: self.scope.bypass,
                ordinary_extensions: self.scope.ordinary_extensions,
                interactive: self.scope.interactive,
                deadline: self.scope.deadline,
                activity: self.scope.activity.clone(),
                events: self.scope.events.clone(),
            },
        }
    }
    pub(super) fn ordered(
        &mut self,
        call: &ToolUse,
        settling_external: bool,
    ) -> OrderedToolCall<'_> {
        let hooks = self.hooks();
        OrderedToolCall {
            journal: ToolExecutionJournal {
                rollout: &mut *self.journal.rollout,
                effects: &mut *self.journal.effects,
                ledger: &mut *self.journal.ledger,
                failed_actions: &mut *self.journal.failed_actions,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            scope: OrderedToolScope {
                registry: self.scope.registry,
                interrupt: self.control.state.interrupt().cloned(),
                force_cancel: self.control.state.force_cancel().clone(),
                drain: self.control.state.drain().clone(),
                settle_on_drain: settling_external,
                spill: if self.scope.registry.is_mcp_effect(&call.name) {
                    None
                } else {
                    self.output.spill.clone()
                },
                projection: self.output.projection,
                publication: self.output.publication.clone(),
                hooks,
                events: self.scope.events.clone(),
            },
        }
    }
    pub(super) async fn external_permit(
        &mut self,
        call: &ToolUse,
    ) -> Result<Option<ProviderExtensionPermit>, ()> {
        if !self.scope.registry.is_mcp_effect(&call.name)
            && self.output.additional_external_tool != Some(call.name.as_str())
        {
            return Ok(None);
        }
        enter_owned_gate(self.output.external_gate.as_ref()).await
    }
    pub(super) fn external_refusal(&mut self, call: &ToolUse) -> Result<ToolResult, KernelError> {
        ControlIngress {
            journal: ApprovalJournal {
                rollout: &mut *self.journal.rollout,
                ledger: &mut *self.journal.ledger,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            inbox: &mut *self.control.inbox,
            control: &mut *self.control.state,
            force_cancel: self.control.force_cancel.as_deref_mut(),
            events: self.scope.events.clone(),
        }
        .poll(
            self.scope.turn,
            super::inbound_control::inbound_poll_limit(),
        );
        let control = self.control.state.requested();
        let result = if control == InboundControl::None {
            ToolResult {
                tool_use_id: call.id.clone(),
                content: "MCP dispatch refused because the resident Run is terminal".into(),
                is_error: true,
                trust: Trust::Workspace,
                latency_ms: 0,
            }
        } else {
            super::control_refusal(call, control)
        };
        self.refuse(call, result)
    }
    pub(super) fn refuse(
        &mut self,
        call: &ToolUse,
        result: ToolResult,
    ) -> Result<ToolResult, KernelError> {
        let events = self.scope.events.clone();
        let turn = self.scope.turn;
        self.journal().refused_result(
            turn,
            &call.name,
            &result,
            "refused_before_dispatch",
            &events,
        )?;
        events.present(tool_end_ui(call, &result));
        Ok(result)
    }
}
