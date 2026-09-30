//! One actual ordered declaration admission lifetime. Policy, hook and approval barriers precede
//! the permit; execution and physical tool intents remain separate and cannot re-enter this owner.
use super::KernelError;
use super::approval_wait::{ApprovalJournal, ApprovalRequest, ApprovalWait};
use super::control_ingress::ControlIngress;
use super::control_refusal;
use super::force_cancel::ForceCancelSeam;
use super::hook_execution::{HookExecution, HookExecutionScope};
use super::hooks::{HookDecision, HookEvent, Hooks, journal::HookEffectJournal};
use super::inbound_control::inbound_poll_limit;
use super::permission_policy::{OperationAdmission, OperationPolicy, evaluate_operation};
use super::permission_transaction::PermissionTransaction;
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_presentation::{strict_utf8_head, tool_end_ui, ui_approval_arguments};
use super::turn_activity::{ActivitySink, ActivityStage};
use super::{INBOUND_DRAIN_POLL_INTERVAL, UI_PROJECTION_TRUNCATED_WHEN_UNMARKED};
use iteron_kernel::admission::OperatorAuthority;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{
    Capability, LifecyclePayload, PermissionMode, SubmissionId, ToolResult, ToolUse, Trust, TurnId,
    Verdict,
};
use iteron_tools::{Registry, ToolPolicyError, ToolPolicyProposal};
use std::{path::Path, time::Instant};

#[cfg(all(test, unix))]
#[path = "tool_declaration_admission_tests.rs"]
mod tests;

pub(super) struct ToolAdmissionScope<'a> {
    pub(super) turn: TurnId,
    pub(super) registry: &'a Registry,
    pub(super) workspace: &'a Path,
    pub(super) hooks: &'a Hooks,
    pub(super) hook_journal: Option<HookEffectJournal>,
    pub(super) trust: Trust,
    pub(super) authority: OperatorAuthority,
    pub(super) ceiling: CapabilitySet,
    pub(super) policy_capabilities: CapabilitySet,
    pub(super) bypass: bool,
    pub(super) ordinary_extensions: bool,
    pub(super) interactive: bool,
    pub(super) deadline: Option<Instant>,
    pub(super) activity: ActivitySink,
    pub(super) events: StreamToolEvents,
}
pub(super) struct ToolDeclarationAdmission<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) approval_sequence: &'a mut u64,
    pub(super) permission: PermissionTransaction<'a>,
    pub(super) scope: ToolAdmissionScope<'a>,
}
pub(super) enum ToolAdmissionDecision {
    Permitted {
        proposal: ToolPolicyProposal,
        capability: Capability,
        action_signature: String,
    },
    Refused(ToolResult),
}
impl ToolDeclarationAdmission<'_> {
    pub(super) async fn run(
        mut self,
        call: &ToolUse,
        proposal: Result<ToolPolicyProposal, ToolPolicyError>,
    ) -> Result<ToolAdmissionDecision, KernelError> {
        self.poll();
        let control = self.control.requested();
        if control != InboundControl::None {
            return self.refused(call, control_refusal(call, control), true);
        }
        if self
            .scope
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return self.refuse(
                call,
                "refused: run wall deadline exhausted before this effecting tool".into(),
                Trust::Workspace,
                true,
            );
        }
        if *self.journal.record_failed {
            return self.refuse(call, "refused: the durable record failed mid-turn; halting before side effects (audit integrity, ADR-008).".into(), Trust::Workspace, false);
        }
        let proposal = match proposal {
            Ok(proposal) => proposal,
            Err(error) => {
                return self.refuse(
                    call,
                    format!("tool policy refused `{}`: {error}", call.name),
                    Trust::Trusted,
                    true,
                );
            }
        };
        if proposal.intent.call != *call {
            return Err(KernelError::EffectBoundary(
                "tool proposal differs from the admitted declaration".into(),
            ));
        }
        let signature = format!("{}::{}", call.name, call.input);
        if let Some(prior) = self.journal.failed_actions.get(&signature) {
            let reason = format!(
                "This exact `{}` call already failed earlier in this run and was not \
                re-run (ADR-003 dedup). Do NOT repeat it — change your approach. The \
                earlier error was:\n{}",
                call.name,
                iteron_protocol::text::tail(prior, 800)
            );
            return self.refuse(call, reason, Trust::Workspace, true);
        }
        if proposal.eligible.iter().next().is_none() {
            return self.refuse(
                call,
                format!(
                    "tool policy refused `{}`: no capability survived the run ceiling",
                    call.name
                ),
                Trust::Trusted,
                true,
            );
        }
        let effects = self.scope.registry.operation_effects(call).ok_or_else(|| {
            KernelError::EffectBoundary(
                "registered tool proposal lost its operation evidence".into(),
            )
        })?;
        let admission = evaluate_operation(
            &call.name,
            &effects,
            OperationPolicy {
                mode: *self.permission.mode,
                rules: self.permission.rules,
                bypass: self.scope.bypass,
                task_ceiling: self.scope.ceiling,
                policy_capabilities: self.scope.policy_capabilities,
                governing_trust: self.scope.trust,
                authority: self.scope.authority,
            },
        );
        self.scope
            .activity
            .span(ActivityStage::ToolProposed, Some(self.scope.turn))
            .complete();
        let hook_activity = self
            .scope
            .activity
            .span(ActivityStage::ToolHook, Some(self.scope.turn));
        if !self.scope.registry.is_mcp_effect(&call.name) {
            let context =
                serde_json::json!({"event":"PreToolUse","tool":call.name,"input":call.input})
                    .to_string();
            if let HookDecision::Deny(reason) = self
                .hooks()
                .compatibility(HookEvent::PreToolUse, &context)
                .await?
            {
                hook_activity.complete();
                self.notice(format!(
                    "hook: PreToolUse DENIED `{}`: {}",
                    call.name,
                    iteron_protocol::text::head(&reason, 200)
                ))?;
                return self.refuse(
                    call,
                    format!(
                        "tool `{}` blocked by a PreToolUse hook: {reason}",
                        call.name
                    ),
                    Trust::Workspace,
                    true,
                );
            }
        }
        self.scope.events.emit(
            "tool.call_proposed",
            None,
            LifecyclePayload {
                reason_code: Some(call.name.clone()),
                ..LifecyclePayload::default()
            },
        );
        let lifecycle = self.hooks().lifecycle("tool.call_proposed").await?;
        if let HookDecision::Deny(reason) = lifecycle.decision {
            hook_activity.complete();
            return self.refuse(
                call,
                format!("tool `{}` blocked by lifecycle hook: {reason}", call.name),
                Trust::Workspace,
                true,
            );
        }
        hook_activity.complete();
        let arguments = if admission.verdict == Verdict::Ask {
            Some(self.approval_arguments(call))
        } else {
            None
        };
        let incomplete = arguments.as_ref().is_some_and(|value| {
            value
                .get("_truncated_for_ui")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(iteron_tunables::param_bool(
                    "cli.runtime.ui_projection_truncated_when_unmarked",
                    UI_PROJECTION_TRUNCATED_WHEN_UNMARKED,
                ))
        });
        let approved = match admission.verdict {
            Verdict::Auto => true,
            Verdict::Deny => false,
            Verdict::Ask if incomplete => false,
            Verdict::Ask => {
                self.approve(
                    call,
                    admission.capability,
                    arguments.expect("Ask projected its arguments"),
                )
                .await?
            }
        };
        if approved && *self.journal.record_failed {
            return self.refuse(call, "refused: the durable record failed; halting before this side effect (audit integrity, ADR-008).".into(), Trust::Workspace, false);
        }
        if !approved {
            let reason = self.permission_refusal(call, &admission, incomplete);
            return self.refuse(call, reason, Trust::Workspace, true);
        }
        // A configured hook and a waited approval are physical external activity. Consume only
        // the actual ingress now visible before returning the permit to the separate executor.
        self.poll();
        let control = self.control.requested();
        if control != InboundControl::None {
            return self.refused(call, control_refusal(call, control), true);
        }
        Ok(ToolAdmissionDecision::Permitted {
            proposal,
            capability: admission.capability,
            action_signature: signature,
        })
    }
    fn approval_arguments(&self, call: &ToolUse) -> serde_json::Value {
        match if self.scope.ordinary_extensions {
            self.scope.registry.ordinary_call_projection(call)
        } else {
            Ok(None)
        } {
            Ok(Some(physical)) => ui_approval_arguments(&physical.input),
            Ok(None) => ui_approval_arguments(&call.input),
            Err(_) => serde_json::json!({"_truncated_for_ui":true}),
        }
    }
    async fn approve(
        &mut self,
        call: &ToolUse,
        capability: Capability,
        arguments: serde_json::Value,
    ) -> Result<bool, KernelError> {
        *self.approval_sequence = self
            .approval_sequence
            .checked_add(1)
            .ok_or(KernelError::IdentityExhausted("approval"))?;
        let request = ApprovalRequest {
            turn: self.scope.turn,
            id: SubmissionId(*self.approval_sequence),
            call_id: strict_utf8_head(&call.id, 2048),
            tool: call.name.clone(),
            capability,
            arguments,
            workspace: strict_utf8_head(
                &iteron_record::redact::scrub(&self.scope.workspace.display().to_string()),
                2048,
            ),
            reason: self.scope.registry.operation_effects(call).map_or_else(
                || {
                    "session policy requires an explicit operator decision before this effect"
                        .into()
                },
                |effects| {
                    format!(
                        "{}; required authority: {:?}",
                        effects.reason,
                        effects.required.iter().collect::<Vec<_>>()
                    )
                },
            ),
            interactive: self.scope.interactive,
            deadline: self.scope.deadline,
            poll: iteron_tunables::param_duration(
                "cli.runtime.inbound_drain_poll_interval",
                INBOUND_DRAIN_POLL_INTERVAL,
            ),
        };
        let decision = ApprovalWait {
            journal: ApprovalJournal {
                rollout: self.journal.rollout,
                ledger: self.journal.ledger,
                record_failed: self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: self.journal.fault,
            },
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            activity: self.scope.activity.clone(),
            events: self.scope.events.clone(),
        }
        .run(request)
        .await?;
        if decision.remember {
            let result = self.permission.remember(
                &mut ApprovalJournal {
                    rollout: self.journal.rollout,
                    ledger: self.journal.ledger,
                    record_failed: self.journal.record_failed,
                    diagnostics: self.journal.diagnostics,
                    #[cfg(test)]
                    fault: self.journal.fault,
                },
                self.scope.turn,
                capability,
            );
            if let Err(error) = result {
                decision.policy_persist_failed(&self.scope.events);
                return Err(error);
            }
        }
        decision.publish(&self.scope.events)
    }
    fn permission_refusal(
        &self,
        call: &ToolUse,
        admission: &OperationAdmission,
        incomplete: bool,
    ) -> String {
        let cap = admission.capability;
        if admission.ceiling_blocks {
            format!(
                "tool `{}` ({cap:?}) refused: the capability is outside the intersection \
                of the admitted task ceiling and selected immutable policy manifest",
                call.name
            )
        } else if admission.taint_blocks {
            format!(
                "tool `{}` ({cap:?}) refused: this turn's governing context trust is {:?}, \
                while external effects require Trusted context (ADR-007). Approval \
                cannot silently clear taint; use a fresh trusted-context phase until \
                scoped provenance escalation exists.",
                call.name, self.scope.trust
            )
        } else if incomplete {
            format!(
                "tool `{}` ({cap:?}) refused: the complete operation exceeds the bounded approval surface, so Iteron will not ask the operator to approve a hidden suffix",
                call.name
            )
        } else if *self.permission.mode == PermissionMode::Plan {
            format!(
                "tool `{}` ({cap:?}) refused: you are in read-only PLAN mode. Do not edit or \
                run anything — investigate with read-only tools and write the plan as \
                text. The operator will switch out of plan mode to execute it.",
                call.name
            )
        } else {
            format!(
                "tool `{}` ({cap:?}) refused by the permission gate (mode={}). This \
                capability needs operator approval or an allow rule (ADR-007). Code, \
                when allowed, runs in an egress-off sandbox.",
                call.name,
                self.permission.mode.label()
            )
        }
    }
    fn hooks(&mut self) -> HookExecution<'_> {
        HookExecution {
            rollout: self.journal.rollout,
            effects: self.journal.effects,
            record_failed: self.journal.record_failed,
            ledger: self.journal.ledger,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
            scope: HookExecutionScope {
                turn: self.scope.turn,
                workspace: self.scope.workspace,
                hooks: self.scope.hooks,
                command_journal: self.scope.hook_journal.clone(),
                interrupt: self.control.interrupt().cloned(),
                drain: self.control.drain().clone(),
                activity: self.scope.activity.clone(),
                emitter: self.scope.events.lifecycle.clone(),
                dispatcher: self.scope.events.lifecycle_hooks.clone(),
                correlation: self.scope.events.correlation.clone(),
            },
        }
    }
    fn poll(&mut self) {
        ControlIngress {
            journal: ApprovalJournal {
                rollout: self.journal.rollout,
                ledger: self.journal.ledger,
                record_failed: self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: self.journal.fault,
            },
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            events: self.scope.events.clone(),
        }
        .poll(self.scope.turn, inbound_poll_limit());
    }
    fn notice(&mut self, text: String) -> Result<(), KernelError> {
        ApprovalJournal {
            rollout: self.journal.rollout,
            ledger: self.journal.ledger,
            record_failed: self.journal.record_failed,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
        }
        .append(self.scope.turn, iteron_protocol::EventKind::Notice { text })
    }
    fn refuse(
        &mut self,
        call: &ToolUse,
        reason: String,
        trust: Trust,
        durable: bool,
    ) -> Result<ToolAdmissionDecision, KernelError> {
        self.refused(
            call,
            ToolResult {
                tool_use_id: call.id.clone(),
                content: reason,
                is_error: true,
                trust,
                latency_ms: 0,
            },
            durable,
        )
    }
    fn refused(
        &mut self,
        call: &ToolUse,
        result: ToolResult,
        durable: bool,
    ) -> Result<ToolAdmissionDecision, KernelError> {
        if durable {
            self.journal.refused_result(
                self.scope.turn,
                &call.name,
                &result,
                "refused_before_dispatch",
                &self.scope.events,
            )?;
        }
        self.scope.events.present(tool_end_ui(call, &result));
        Ok(ToolAdmissionDecision::Refused(result))
    }
}
