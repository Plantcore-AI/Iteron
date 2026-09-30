//! Actual configured-hook execution and universal-ticket settlement coordinator. Concrete journal
//! and hook owners are borrowed independently; this owner never receives mutable Agent state.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::deferred_tools::AutoApprovedCall;
use super::effect_descriptor::{
    effect_class_label, effect_done_terminal, effect_failed_terminal, effect_workspace,
};
use super::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use super::hooks::{
    CompatibilityHookReport, HookDecision, HookEvent, Hooks, LifecycleHookReport,
    journal::HookEffectJournal,
};
use super::lifecycle_hooks::LifecycleHookDispatcher;
use super::turn_activity::{ActivitySink, ActivityStage};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::Ledger;
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{
    ActivityDetailCode, Capability, LifecyclePayload, ToolResult, ToolUse, TurnId,
};
use iteron_record::Rollout;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};

pub(super) struct HookExecutionScope<'a> {
    pub(super) turn: TurnId,
    pub(super) workspace: &'a Path,
    pub(super) hooks: &'a Hooks,
    pub(super) command_journal: Option<HookEffectJournal>,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) drain: Arc<AtomicBool>,
    pub(super) activity: ActivitySink,
    pub(super) emitter: Option<LifecycleEmitter>,
    pub(super) dispatcher: Option<LifecycleHookDispatcher>,
    pub(super) correlation: LifecycleCorrelation,
}

pub(super) struct HookExecution<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) record_failed: &'a mut bool,
    pub(super) ledger: &'a mut Ledger,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
    pub(super) scope: HookExecutionScope<'a>,
}

pub(super) struct HookDeniedCall {
    pub(super) admitted: AutoApprovedCall,
    pub(super) reason: String,
}
pub(super) struct HookBatchAdmission {
    pub(super) allowed: Vec<AutoApprovedCall>,
    pub(super) denied: Vec<HookDeniedCall>,
}
struct HookTickets {
    compatibility: Option<(usize, effects::EffectTicket)>,
    lifecycle: Option<(usize, effects::EffectTicket)>,
}

impl HookExecution<'_> {
    pub(super) async fn compatibility(
        &mut self,
        event: HookEvent,
        context: &str,
    ) -> Result<HookDecision, KernelError> {
        if self.scope.hooks.is_empty_for(event) {
            return Ok(HookDecision::Allow);
        }
        let journal = self.command_journal()?;
        let matched = u64::try_from(self.scope.hooks.commands(event).len()).unwrap_or(u64::MAX);
        for event in ["hook.matched", "hook.started"] {
            self.emit(
                event,
                LifecyclePayload {
                    count: Some(matched),
                    ..LifecyclePayload::default()
                },
            );
        }
        let activity = self
            .scope
            .activity
            .span(ActivityStage::Hook, Some(self.scope.turn));
        let (ordinal, ticket) = match self.open(event.key(), None) {
            Ok(opened) => opened,
            Err(error) => {
                activity.fail(ActivityDetailCode::HookGate);
                return Err(error);
            }
        };
        let report = self
            .scope
            .hooks
            .run_cancellable_journaled_report(
                event,
                context,
                self.scope.interrupt.as_deref(),
                Some(self.scope.drain.as_ref()),
                &journal,
            )
            .await;
        if let Err(error) = self.settle(ordinal, ticket, None) {
            activity.fail(ActivityDetailCode::HookGate);
            return Err(error);
        }
        self.observe_report(&report);
        if report.failed > 0 || report.timed_out > 0 {
            activity.fail(ActivityDetailCode::HookGate);
        } else {
            activity.complete();
        }
        Ok(report.decision)
    }

    /// The caller projects the protected source with its exact optional child/effect correlation.
    /// This method executes the configured gate and returns only its actual journaled report.
    pub(super) async fn lifecycle(
        &mut self,
        event: &'static str,
    ) -> Result<LifecycleHookReport, KernelError> {
        debug_assert_eq!(
            iteron_protocol::lifecycle::event_spec(event).map(|spec| spec.hook_capability),
            Some(iteron_protocol::HookCapability::Gate)
        );
        if self.scope.hooks.is_empty_for_lifecycle(event) {
            return Ok(LifecycleHookReport {
                decision: HookDecision::Allow,
                matched: 0,
                completed: 0,
                failed: 0,
                timed_out: 0,
                augmentations: Vec::new(),
            });
        }
        let journal = self.command_journal()?;
        let (ordinal, ticket) = self.open(event, None)?;
        self.emit("hook.matched", LifecyclePayload::default());
        self.emit("hook.started", LifecyclePayload::default());
        let activity = self
            .scope
            .activity
            .span(ActivityStage::Hook, Some(self.scope.turn));
        let context = lifecycle_context(event, self.scope.turn);
        let report = self
            .scope
            .hooks
            .run_lifecycle_cancellable_journaled(
                event,
                &context,
                self.scope.interrupt.as_deref(),
                Some(self.scope.drain.as_ref()),
                &journal,
            )
            .await;
        let failed = report.as_ref().err().copied();
        if let Err(error) = self.settle(ordinal, ticket, failed) {
            activity.fail(ActivityDetailCode::HookGate);
            return Err(error);
        }
        let report = match report {
            Ok(report) => report,
            Err(reason) => {
                activity.fail(ActivityDetailCode::HookGate);
                return Err(KernelError::ContextResolution(reason.into()));
            }
        };
        self.emit(
            report_event(&report.decision, report.failed, report.timed_out),
            LifecyclePayload {
                count: Some(u64::from(report.completed)),
                ..LifecyclePayload::default()
            },
        );
        if report.failed > 0 || report.timed_out > 0 {
            activity.fail(ActivityDetailCode::HookGate);
        } else {
            activity.complete();
        }
        Ok(report)
    }

    /// Every universal intent is durable before any configured command is polled. Shared Hooks
    /// semaphore bounds physical commands; joining retains ownership and settles in declaration
    /// order. Domain denials return typed calls for the caller's durable ToolDone/UI projection.
    pub(super) async fn gate_batch(
        &mut self,
        batch: Vec<AutoApprovedCall>,
    ) -> Result<HookBatchAdmission, KernelError> {
        let compatibility = !self.scope.hooks.is_empty_for(HookEvent::PreToolUse);
        let lifecycle = !self
            .scope
            .hooks
            .is_empty_for_lifecycle("tool.call_proposed");
        if !compatibility && !lifecycle {
            return Ok(HookBatchAdmission {
                allowed: batch,
                denied: Vec::new(),
            });
        }
        bounded(batch.len())?;
        let journal = self.command_journal()?;
        self.effects.note_workspace_mutation();
        let activity = self
            .scope
            .activity
            .span(ActivityStage::ToolHook, Some(self.scope.turn));
        let mut prepared = Vec::with_capacity(batch.len());
        for admitted in batch {
            let tickets = HookTickets {
                compatibility: if compatibility {
                    Some(self.open(HookEvent::PreToolUse.key(), Some(admitted.index))?)
                } else {
                    None
                },
                lifecycle: if lifecycle {
                    Some(self.open("tool.call_proposed", Some(admitted.index))?)
                } else {
                    None
                },
            };
            prepared.push((admitted, tickets));
        }
        self.emit(
            "hook.started",
            LifecyclePayload {
                count: Some(u64::try_from(prepared.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        let hooks = self.scope.hooks;
        let interrupt = self.scope.interrupt.clone();
        let drain = self.scope.drain.clone();
        let turn = self.scope.turn;
        let reports = futures_util::future::join_all(prepared.iter().map(|(admitted, _)| {
            let compatibility_context = serde_json::json!({"event":"PreToolUse",
                "tool":admitted.call.name,"input":admitted.call.input})
            .to_string();
            let lifecycle_context = lifecycle_context("tool.call_proposed", turn);
            let journal = journal.clone();
            let interrupt = interrupt.clone();
            let drain = drain.clone();
            async move {
                let pre = if compatibility {
                    Some(
                        hooks
                            .run_cancellable_journaled_report(
                                HookEvent::PreToolUse,
                                &compatibility_context,
                                interrupt.as_deref(),
                                Some(drain.as_ref()),
                                &journal,
                            )
                            .await,
                    )
                } else {
                    None
                };
                let gate = if lifecycle {
                    Some(
                        hooks
                            .run_lifecycle_cancellable_journaled(
                                "tool.call_proposed",
                                &lifecycle_context,
                                interrupt.as_deref(),
                                Some(drain.as_ref()),
                                &journal,
                            )
                            .await,
                    )
                } else {
                    None
                };
                (pre, gate)
            }
        }))
        .await;
        let mut output = HookBatchAdmission {
            allowed: Vec::with_capacity(prepared.len()),
            denied: Vec::new(),
        };
        let mut dispatch_error = None;
        let mut failed = false;
        for ((admitted, tickets), (pre, gate)) in prepared.into_iter().zip(reports) {
            if let Some((ordinal, ticket)) = tickets.compatibility {
                self.settle(ordinal, ticket, None)?;
            }
            if let Some((ordinal, ticket)) = tickets.lifecycle {
                let reason = gate
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .copied();
                self.settle(ordinal, ticket, reason)?;
            }
            let gate = match gate {
                Some(Ok(report)) => Some(report),
                Some(Err(reason)) => {
                    self.emit(
                        "hook.failed",
                        LifecyclePayload {
                            reason_code: Some("tool_gate_dispatch_failed".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    dispatch_error.get_or_insert(reason);
                    failed = true;
                    continue;
                }
                None => None,
            };
            let denial = pre
                .as_ref()
                .and_then(|report| denied(&report.decision))
                .or_else(|| gate.as_ref().and_then(|report| denied(&report.decision)));
            if let Some(reason) = denial {
                output.denied.push(HookDeniedCall { admitted, reason });
            } else {
                failed |= pre
                    .as_ref()
                    .is_some_and(|report| report.failed > 0 || report.timed_out > 0)
                    || gate
                        .as_ref()
                        .is_some_and(|report| report.failed > 0 || report.timed_out > 0);
                output.allowed.push(admitted);
            }
        }
        if failed {
            activity.fail(ActivityDetailCode::HookGate);
        } else {
            activity.complete();
        }
        if let Some(reason) = dispatch_error {
            return Err(KernelError::ContextResolution(reason.into()));
        }
        Ok(output)
    }

    /// Actual tools are terminal before observers start; the caller keeps ToolEnd behind this
    /// method. Post observers remain advisory, while every started command owes a real terminal.
    pub(super) async fn post_tools(
        &mut self,
        completed: &[(ToolUse, ToolResult)],
    ) -> Result<(), KernelError> {
        if self.scope.hooks.is_empty_for(HookEvent::PostToolUse) || completed.is_empty() {
            return Ok(());
        }
        bounded(completed.len())?;
        let journal = self.command_journal()?;
        self.effects.note_workspace_mutation();
        let mut tickets = Vec::with_capacity(completed.len());
        for index in 0..completed.len() {
            tickets.push(self.open(HookEvent::PostToolUse.key(), Some(index))?);
        }
        let hooks = self.scope.hooks;
        let interrupt = self.scope.interrupt.clone();
        let drain = self.scope.drain.clone();
        let reports = futures_util::future::join_all(completed.iter().map(|(call, result)| {
            let context = serde_json::json!({"event":"PostToolUse","tool":call.name,
                "tool_use_id":result.tool_use_id,"is_error":result.is_error,
                "content":iteron_protocol::text::head(&result.content,2000)})
            .to_string();
            let journal = journal.clone();
            let interrupt = interrupt.clone();
            let drain = drain.clone();
            async move {
                hooks
                    .run_cancellable_journaled_report(
                        HookEvent::PostToolUse,
                        &context,
                        interrupt.as_deref(),
                        Some(drain.as_ref()),
                        &journal,
                    )
                    .await
            }
        }))
        .await;
        for ((ordinal, ticket), report) in tickets.into_iter().zip(reports) {
            self.settle(ordinal, ticket, None)?;
            self.emit(
                if report.timed_out > 0 {
                    "hook.timed_out"
                } else if report.failed > 0 {
                    "hook.failed"
                } else {
                    "hook.completed"
                },
                LifecyclePayload {
                    count: Some(u64::from(report.completed)),
                    magnitude: Some(u64::from(report.timed_out)),
                    ..LifecyclePayload::default()
                },
            );
        }
        Ok(())
    }

    fn command_journal(&self) -> Result<HookEffectJournal, KernelError> {
        self.scope.command_journal.clone().ok_or_else(|| {
            KernelError::ContextResolution(
                "hook command journal is unavailable; command was not started".into(),
            )
        })
    }
    fn open(
        &mut self,
        event: &'static str,
        index: Option<usize>,
    ) -> Result<(usize, effects::EffectTicket), KernelError> {
        let class = effect_class::EffectClass::Hook;
        let ordinal = self.effects.next_ordinal(self.scope.turn, class);
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::EffectIntent) {
            *self.fault = None;
            *self.record_failed = true;
            self.diagnostics
                .emit(KernelDiagnostic::RecordAppendFailed {});
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other("injected durable effect-intent append failure"),
            )));
        }
        let mut arguments = serde_json::json!({"event":event});
        if let Some(index) = index {
            arguments["tool_index"] = index.into();
        }
        let started = Instant::now();
        let result = self.effects.open(
            self.rollout,
            effects::BrokeredEffect {
                turn: self.scope.turn,
                effect_id: effect_class::effect_id(self.scope.turn, class, ordinal),
                tool_use_id: effect_class::harness_correlation_id(self.scope.turn, class, ordinal),
                kind: effect_class_label(class).into(),
                capability: Capability::CodeExecuting,
                audit_arguments: arguments,
                workspace: effect_workspace(self.scope.workspace),
                provider_route_attempt: None,
            },
        );
        self.measure(started);
        result
            .map(|ticket| (ordinal, ticket))
            .map_err(|error| self.boundary_error(error))
    }
    fn settle(
        &mut self,
        ordinal: usize,
        ticket: effects::EffectTicket,
        failed: Option<&str>,
    ) -> Result<(), KernelError> {
        let class = effect_class::EffectClass::Hook;
        let terminal = failed.map_or_else(
            || effect_done_terminal(self.scope.turn, class, ordinal),
            |reason| effect_failed_terminal(self.scope.turn, class, ordinal, reason),
        );
        let started = Instant::now();
        let result = self.effects.settle(
            self.rollout,
            ticket,
            effects::Settlement::Definite(terminal),
            UnknownCause::Unobserved,
        );
        self.measure(started);
        result.map_err(|error| self.boundary_error(error))
    }
    fn boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => {
                *self.record_failed = true;
                self.diagnostics
                    .emit(KernelDiagnostic::RecordAppendFailed {});
                KernelError::Record(error)
            }
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
    fn observe_report(&self, report: &CompatibilityHookReport) {
        self.emit(
            report_event(&report.decision, report.failed, report.timed_out),
            LifecyclePayload {
                count: Some(u64::from(report.completed)),
                magnitude: Some(u64::from(report.timed_out)),
                ..LifecyclePayload::default()
            },
        );
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
    fn emit(&self, event: &str, payload: LifecyclePayload) {
        if let Some(emitter) = &self.scope.emitter
            && let Ok(event) = emitter.emit(event, self.scope.correlation.clone(), payload)
            && let Some(dispatcher) = &self.scope.dispatcher
        {
            dispatcher.dispatch(event);
        }
    }
}
fn report_event(decision: &HookDecision, failed: u32, timed_out: u32) -> &'static str {
    if matches!(decision, HookDecision::Deny(_)) {
        "hook.blocked"
    } else if timed_out > 0 {
        "hook.timed_out"
    } else if failed > 0 {
        "hook.failed"
    } else {
        "hook.completed"
    }
}
fn denied(decision: &HookDecision) -> Option<String> {
    match decision {
        HookDecision::Allow => None,
        HookDecision::Deny(reason) => Some(reason.clone()),
    }
}
fn lifecycle_context(event: &str, turn: TurnId) -> String {
    serde_json::json!({
    "catalog_version":iteron_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION.0,"event_id":event,"turn_id":turn.0,
}).to_string()
}
fn bounded(count: usize) -> Result<(), KernelError> {
    if count > effects::MAX_TOOL_CALLS_PER_TURN {
        Err(KernelError::ContextResolution(
            "hook batch exceeds the admitted tool-call envelope".into(),
        ))
    } else {
        Ok(())
    }
}
