//! Physical task owner for one already-admitted streamed tool call.
//! Journal tickets and permission admission stay with the caller. This owner retains lock queue
//! position, governor permits, cancellation and raw-output publication until its real terminal.
use super::artifact_publication::ToolOutputPublicationPort;
use super::early_tool_gate::{EarlyHookGateContext, EarlyHookSummary, run_lifecycle_gate};
use super::hooks::{Hooks, journal::HookEffectJournal};
use super::tool_interrupt::{ToolInterruption, await_tool_or_interrupt};
use super::tool_output_spill::{self, ManagedToolResult, ToolOutputSpillStore};
use iteron_protocol::{ToolResult, ToolUse, Trust};
use iteron_sched::Governor;
use iteron_tools::{ToolExecution, effectfut};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

pub(super) enum EarlyToolOutcome {
    Completed {
        managed: ManagedToolResult,
        spill_store: Option<Arc<ToolOutputSpillStore>>,
        hook: Option<EarlyHookSummary>,
        effect_unknown: bool,
        operator_interrupted: bool,
        publication_error: Option<String>,
    },
    Refused {
        reason: String,
        hook: EarlyHookSummary,
    },
}

/// Host-only execution context; it contains no journal mutation or permission escalation port.
pub(super) struct EarlyToolExecutionScope {
    pub(super) governor: Governor,
    pub(super) queued: Arc<AtomicUsize>,
    pub(super) execution_gate: Arc<tokio::sync::RwLock<()>>,
    pub(super) hooks: Hooks,
    pub(super) hook_journal: Option<HookEffectJournal>,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
    pub(super) publication: Arc<dyn ToolOutputPublicationPort>,
}

/// Every field is derived from the already-admitted call and immutable operator hook policy.
pub(super) struct AdmittedEarlyTool {
    pub(super) call: ToolUse,
    pub(super) is_pure: bool,
    pub(super) supports_parallel: bool,
    pub(super) compatibility_pre_hook: bool,
    pub(super) lifecycle_pre_hook: bool,
    pub(super) compatibility_context: String,
    pub(super) lifecycle_context: String,
    pub(super) spill_store: Option<Arc<ToolOutputSpillStore>>,
}

pub(super) struct EarlyToolExecutor {
    scope: EarlyToolExecutionScope,
}

impl EarlyToolExecutor {
    pub(super) fn new(scope: EarlyToolExecutionScope) -> Self {
        Self { scope }
    }

    /// Reserve the fair execution lock synchronously before the task is spawned: model call order
    /// remains the ordering authority even if Tokio first polls tasks in a different order.
    pub(super) fn spawn(
        self,
        admitted: AdmittedEarlyTool,
        future: effectfut::BoxFut,
    ) -> EarlyToolTask {
        let execution_guard = reserve_execution(
            self.scope.execution_gate.clone(),
            admitted.supports_parallel,
        );
        let handle = tokio::spawn(async move {
            let _execution_guard = execution_guard.await;
            // The exclusive predecessor may itself need a permit. Never acquire one while still
            // waiting behind that predecessor's lock queue position.
            let _permit = match self.scope.governor.try_acquire() {
                Some(permit) => permit,
                None => {
                    self.scope.queued.fetch_add(1, Ordering::Relaxed);
                    self.scope.governor.acquire().await
                }
            };
            let hook = match run_lifecycle_gate(
                &self.scope.hooks,
                EarlyHookGateContext {
                    journal: self.scope.hook_journal.as_ref(),
                    compatibility_enabled: admitted.compatibility_pre_hook,
                    lifecycle_enabled: admitted.lifecycle_pre_hook,
                    compatibility_json: &admitted.compatibility_context,
                    lifecycle_json: &admitted.lifecycle_context,
                    interrupt: self.scope.interrupt.as_deref(),
                    drain: self.scope.drain.as_ref(),
                },
            )
            .await
            {
                Ok(summary) => summary,
                Err(refusal) => {
                    return EarlyToolOutcome::Refused {
                        reason: refusal.reason,
                        hook: refusal.summary,
                    };
                }
            };
            let (execution, operator_interrupted) = match await_tool_or_interrupt(
                future,
                self.scope.interrupt.as_deref(),
                Some(self.scope.force_cancel.as_ref()),
                Some(self.scope.drain.as_ref()),
            )
            .await
            {
                Ok(execution) => (execution, false),
                Err(interruption) => {
                    let result = ToolResult {
                        tool_use_id: admitted.call.id.clone(),
                        content: match interruption {
                            ToolInterruption::Forced => {
                                "operator force-cancelled the read before it completed"
                            }
                            ToolInterruption::Drain => {
                                "operator drained the read before it completed"
                            }
                            ToolInterruption::Cooperative => {
                                "operator interrupted the read before it completed"
                            }
                        }
                        .into(),
                        is_error: true,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    };
                    // A pure read has no external effect by its frozen registry contract. An
                    // interrupted effecting call remains unknown until the journal owner settles.
                    (
                        if admitted.is_pure {
                            ToolExecution::Definite(result)
                        } else {
                            ToolExecution::Unknown(result)
                        },
                        true,
                    )
                }
            };
            let effect_unknown = matches!(&execution, ToolExecution::Unknown(_));
            let mut result = execution.into_result();
            result.tool_use_id = admitted.call.id.clone();
            let publication_error = self
                .scope
                .publication
                .publish(&admitted.call, &result, !effect_unknown)
                .err();
            let managed = tool_output_spill::manage_result(admitted.spill_store.as_deref(), result);
            EarlyToolOutcome::Completed {
                managed,
                spill_store: admitted.spill_store,
                hook,
                effect_unknown,
                operator_interrupted,
                publication_error,
            }
        });
        EarlyToolTask(handle)
    }
}

pub(super) struct ExecutionGuard {
    _shared: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
    _exclusive: Option<tokio::sync::OwnedRwLockWriteGuard<()>>,
}

pub(super) async fn execution_guard(
    gate: Arc<tokio::sync::RwLock<()>>,
    supports_parallel: bool,
) -> ExecutionGuard {
    if supports_parallel {
        ExecutionGuard {
            _shared: Some(gate.read_owned().await),
            _exclusive: None,
        }
    } else {
        ExecutionGuard {
            _shared: None,
            _exclusive: Some(gate.write_owned().await),
        }
    }
}

fn reserve_execution(
    gate: Arc<tokio::sync::RwLock<()>>,
    supports_parallel: bool,
) -> Pin<Box<dyn Future<Output = ExecutionGuard> + Send>> {
    let mut future = Box::pin(execution_guard(gate, supports_parallel));
    let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(guard) => Box::pin(std::future::ready(guard)),
        Poll::Pending => future,
    }
}

/// A failed record/projection path cannot detach an already-admitted tool. Drop revokes this
/// task; the caller's durable effect intent remains unresolved until an actual terminal is known.
pub(super) struct EarlyToolTask(tokio::task::JoinHandle<EarlyToolOutcome>);
impl EarlyToolTask {
    pub(super) fn abort(&self) {
        self.0.abort();
    }
}
impl Future for EarlyToolTask {
    type Output = Result<EarlyToolOutcome, tokio::task::JoinError>;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(context)
    }
}
impl Drop for EarlyToolTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
