//! Actual running early-tool handle, reap and ordered journal settlement owner. Frozen execution
//! observations never grant authority; managed results survive through real post-hook settlement.
use super::KernelError;
use super::artifact_publication::PUBLICATION_UNAVAILABLE;
use super::context_runtime::TurnResultProjectionBudget;
use super::early_tool_executor::EarlyToolOutcome;
use super::early_tool_gate::EarlyHookSummary;
use super::effect_descriptor::{effect_done_terminal, effect_failed_terminal};
use super::effect_journal_owner::UnknownCause;
use super::frontend_events::UiEvent;
use super::hook_execution::{HookExecution, HookExecutionScope};
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_output_spill;
use super::tool_presentation::tool_end_ui;
use super::tool_turn::{EarlyHookEffectTickets, EarlyToolInFlight};
use iteron_kernel::{effect_class, effects};
use iteron_protocol::{Capability, LifecyclePayload, ToolResult, Trust, TurnId};
use iteron_tools::Registry;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

pub(super) struct EarlyToolCollectionScope<'a> {
    pub(super) turn: TurnId,
    pub(super) registry: &'a Registry,
    pub(super) hooks: HookExecutionScope<'a>,
    pub(super) events: StreamToolEvents,
    pub(super) deadline: Option<Instant>,
}

pub(super) struct EarlyToolWindow {
    pub(super) stream_start: Instant,
    pub(super) stream_elapsed: Duration,
    pub(super) hook_gates_reads: bool,
    pub(super) queued: Arc<AtomicUsize>,
    pub(super) projection: TurnResultProjectionBudget,
}

pub(super) struct EarlyToolCollection<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) scope: EarlyToolCollectionScope<'a>,
}
impl EarlyToolCollection<'_> {
    pub(super) async fn collect(
        mut self,
        early: Vec<EarlyToolInFlight>,
        window: EarlyToolWindow,
        results: &mut [Option<ToolResult>],
        any_error: &mut bool,
    ) -> Result<usize, KernelError> {
        if early.len() > effects::MAX_TOOL_CALLS_PER_TURN
            || early.iter().any(|(index, ..)| *index >= results.len())
        {
            return Err(KernelError::EffectBoundary(
                "early tool results exceed their admitted envelope".into(),
            ));
        }
        let mut completed = Vec::with_capacity(early.len());
        let mut unknown = 0usize;
        for (index, call, mut handle, dispatched_at, mut tickets) in early {
            let tool_ticket = tickets.tool.take();
            let was_effecting = tool_ticket.is_some();
            let since_dispatch = dispatched_at.saturating_duration_since(window.stream_start);
            let overlap_ms = u64::try_from(
                window
                    .stream_elapsed
                    .saturating_sub(since_dispatch)
                    .as_millis(),
            )
            .unwrap_or(u64::MAX);
            let remaining = self
                .scope
                .deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()));
            let joined = match remaining {
                Some(remaining) if remaining.is_zero() => {
                    handle.abort();
                    let _ = handle.await;
                    None
                }
                Some(remaining) => match tokio::time::timeout(remaining, &mut handle).await {
                    Ok(joined) => Some(joined),
                    Err(_) => {
                        handle.abort();
                        let _ = handle.await;
                        None
                    }
                },
                None => Some(handle.await),
            };
            let summary = match joined.as_ref() {
                Some(Ok(EarlyToolOutcome::Completed { hook, .. })) => *hook,
                Some(Ok(EarlyToolOutcome::Refused { hook, .. })) => Some(*hook),
                Some(Err(_)) | None => None,
            };
            self.settle_hooks(tickets, summary)?;
            match joined {
                Some(Ok(EarlyToolOutcome::Completed {
                    mut managed,
                    spill_store,
                    hook,
                    effect_unknown,
                    operator_interrupted,
                    publication_error,
                })) => {
                    if let Some(hook) = hook {
                        self.observe_hook(hook, false);
                    }
                    if managed.project_visible(window.projection.visible_bytes_for(&call.name)) {
                        self.scope.events.projected(managed.result.content.len());
                    }
                    // Pure contract reads may be journaled after their non-effecting overlap;
                    // effecting calls already hold the intent written before task retention.
                    let ticket = match tool_ticket {
                        Some(ticket) => ticket,
                        None => self.journal.open_tool(
                            self.scope.hooks.workspace,
                            self.scope.turn,
                            index,
                            &call,
                            Capability::ReadOnly,
                            &self.scope.events,
                        )?,
                    };
                    let result = &managed.result;
                    if effect_unknown {
                        let cause = if operator_interrupted {
                            UnknownCause::OperatorCancelled
                        } else {
                            UnknownCause::Unobserved
                        };
                        self.journal.settle(ticket,effects::Settlement::Unknown(
                            "streaming tool did not report an authoritative terminal; automatic retry is forbidden".into(),
                        ),cause)?;
                        self.journal.ledger.tool(
                            result.latency_ms,
                            overlap_ms.min(result.latency_ms),
                            true,
                        );
                        unknown = unknown.saturating_add(1);
                    } else {
                        self.journal.known_result(
                            ticket,
                            &call.name,
                            result,
                            overlap_ms.min(result.latency_ms),
                            &self.scope.events,
                        )?;
                        if was_effecting && result.is_error {
                            self.journal.failed_actions.insert(
                                format!("{}::{}", call.name, call.input),
                                result.content.clone(),
                            );
                        }
                    }
                    *any_error |= result.is_error || effect_unknown;
                    if managed.spilled {
                        self.scope.registry.invalidate_pure_cache();
                    }
                    // A known physical effect is already terminal before retention refusal.
                    if publication_error.is_some() {
                        self.scope
                            .events
                            .present(UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
                    }
                    completed.push((index, call, managed, spill_store));
                }
                Some(Ok(EarlyToolOutcome::Refused { reason, hook })) => {
                    self.observe_hook(hook, true);
                    let result = ToolResult {
                        tool_use_id: call.id.clone(),
                        content: format!(
                            "tool `{}` blocked by a tool gate hook: {reason}",
                            call.name
                        ),
                        is_error: true,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    };
                    if let Some(ticket) = tool_ticket {
                        self.journal.known_result(
                            ticket,
                            &call.name,
                            &result,
                            0,
                            &self.scope.events,
                        )?;
                    } else {
                        self.journal.refused_result(
                            self.scope.turn,
                            &call.name,
                            &result,
                            "refused_before_dispatch",
                            &self.scope.events,
                        )?;
                    }
                    self.scope.events.present(tool_end_ui(&call, &result));
                    results[index] = Some(result);
                    *any_error = true;
                }
                Some(Err(_)) | None => {
                    let result=ToolResult {
                        tool_use_id:call.id.clone(),
                        content:"tool task failed, was cancelled, or exceeded the run wall deadline before producing a result".into(),
                        is_error:true,trust:Trust::Workspace,latency_ms:0,
                    };
                    if let Some(ticket) = tool_ticket {
                        self.journal.settle(
                            ticket,
                            effects::Settlement::Unknown(
                                "streaming tool task was lost before an authoritative terminal"
                                    .into(),
                            ),
                            UnknownCause::Unobserved,
                        )?;
                        self.journal.ledger.tool(0, 0, true);
                        unknown = unknown.saturating_add(1);
                    } else {
                        self.journal.refused_result(
                            self.scope.turn,
                            &call.name,
                            &result,
                            "refused_before_dispatch",
                            &self.scope.events,
                        )?;
                    }
                    if window.hook_gates_reads {
                        self.scope.events.emit(
                            "hook.failed",
                            None,
                            LifecyclePayload {
                                count: Some(0),
                                reason_code: Some("early_tool_task_lost".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                    }
                    *any_error = true;
                    self.scope.events.present(tool_end_ui(&call, &result));
                    results[index] = Some(result);
                }
            }
        }
        self.journal
            .ledger
            .tool_inline_overflow(window.queued.load(Ordering::Relaxed));
        let post_inputs = completed
            .iter()
            .map(|(_, call, managed, _)| (call.clone(), managed.result.clone()))
            .collect::<Vec<_>>();
        let post_result = HookExecution {
            rollout: self.journal.rollout,
            effects: self.journal.effects,
            record_failed: self.journal.record_failed,
            ledger: self.journal.ledger,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
            scope: self.scope.hooks.clone(),
        }
        .post_tools(&post_inputs)
        .await;
        for (index, call, mut managed, spill_store) in completed {
            let terminal_ui = tool_end_ui(&call, &managed.result);
            tool_output_spill::cleanup_managed_result(spill_store.as_deref(), &mut managed)?;
            self.scope.events.present(terminal_ui);
            results[index] = Some(managed.result);
        }
        post_result?;
        Ok(unknown)
    }

    pub(super) fn settle_hooks(
        &mut self,
        tickets: EarlyHookEffectTickets,
        summary: Option<EarlyHookSummary>,
    ) -> Result<(), KernelError> {
        let turn = self.scope.turn;
        let class = effect_class::EffectClass::Hook;
        if let Some((ordinal, ticket)) = tickets.compatibility {
            let settlement = summary.map_or_else(
                || {
                    effects::Settlement::Unknown(
                        "early compatibility hook task ended without an observable terminal".into(),
                    )
                },
                |_| effects::Settlement::Definite(effect_done_terminal(turn, class, ordinal)),
            );
            self.journal
                .settle(ticket, settlement, UnknownCause::Unobserved)?;
        }
        if let Some((ordinal, ticket)) = tickets.lifecycle {
            let settlement = match summary {
                None => effects::Settlement::Unknown(
                    "early lifecycle hook task ended without an observable terminal".into(),
                ),
                Some(summary) if summary.lifecycle_dispatch_failed => {
                    effects::Settlement::Definite(effect_failed_terminal(
                        turn,
                        class,
                        ordinal,
                        "lifecycle hook dispatch failed before a valid report",
                    ))
                }
                Some(_) => {
                    effects::Settlement::Definite(effect_done_terminal(turn, class, ordinal))
                }
            };
            self.journal
                .settle(ticket, settlement, UnknownCause::Unobserved)?;
        }
        Ok(())
    }
    fn observe_hook(&self, report: EarlyHookSummary, blocked: bool) {
        let event = if blocked {
            "hook.blocked"
        } else if report.timed_out > 0 {
            "hook.timed_out"
        } else if report.failed > 0 {
            "hook.failed"
        } else {
            "hook.completed"
        };
        self.scope.events.emit(
            event,
            None,
            LifecyclePayload {
                count: Some(u64::from(report.completed)),
                magnitude: Some(u64::from(report.timed_out)),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) async fn abort_all(
        &mut self,
        early: &mut Vec<EarlyToolInFlight>,
    ) -> Result<(), KernelError> {
        // Abort every task before awaiting a receipt. A barrier failure cannot leave later handles
        // running. Join cancellation only proves reap of the task; physical effects stay Unknown.
        for (_, _, handle, _, _) in early.iter() {
            handle.abort();
        }
        let mut first_error = None;
        for (_, _, handle, _, mut tickets) in early.drain(..) {
            let _ = handle.await;
            if let Some(ticket) = tickets.tool.take() {
                match self.journal.settle(
                    ticket,
                    effects::Settlement::Unknown(
                        "provider stream stopped before the streaming tool terminal was collected"
                            .into(),
                    ),
                    UnknownCause::Unobserved,
                ) {
                    Ok(()) => self.journal.ledger.tool(0, 0, true),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if let Err(error) = self.settle_hooks(tickets, None) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
