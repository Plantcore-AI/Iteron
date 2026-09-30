//! Logical streamed-response recovery after the physical round is closed. Partial text and
//! complete declarations may continue a transcript; they never change physical usage/cost truth.
#[cfg(test)]
use super::DurableAppendFault;
use super::early_tool_collection::{EarlyToolCollection, EarlyToolCollectionScope};
use super::plantcore::PlantcoreTerminal;
use super::pricing::SharedUsdBudget;
use super::provider_round::ProviderRoundOwner;
use super::provider_route;
use super::provider_route_turn::ProviderRouteTurn;
use super::provider_turn_driver::CompletedProviderTurn;
use super::session_control::SessionControlState;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_presentation::strict_utf8_head;
use super::turn_publication::TurnPublicationOwner;
use super::{
    INTERRUPTED_STREAM_MARKER, INTERRUPTED_STREAM_MAX_BYTES, KernelError, Outcome,
    PROVIDER_INTERRUPT_POLL_INTERVAL,
};
use iteron_kernel::diagnostics::KernelDiagnostic;
use iteron_protocol::{Block, Event, EventKind, Message, Role, Seq, StopReason, ToolUse, TurnId};
use iteron_provider::{ProviderError, TurnResult, UsageReport};
use iteron_sched::BackoffPolicy;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct ProviderResponseJournal<'a> {
    pub(super) tools: ToolExecutionJournal<'a>,
    pub(super) publications: &'a mut TurnPublicationOwner,
    pub(super) assistant_source: &'a mut Option<Seq>,
}
pub(super) struct ProviderResponseScope<'a> {
    pub(super) early: EarlyToolCollectionScope<'a>,
    pub(super) control: &'a SessionControlState,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) plantcore: bool,
    pub(super) terminal: Option<PlantcoreTerminal>,
    pub(super) retry: BackoffPolicy,
}

pub(super) struct AcceptedProviderResponse {
    pub(super) route: ProviderRouteTurn,
    pub(super) round: ProviderRoundOwner,
    pub(super) execution: super::provider_execution_scope::ProviderExecutionScope,
    pub(super) result: TurnResult,
    pub(super) recovered: bool,
    pub(super) tools: Vec<ToolUse>,
}
pub(super) struct FailedProviderResponse {
    pub(super) error: KernelError,
    pub(super) observe_physical_usage: bool,
    pub(super) terminal: Option<Outcome>,
}
pub(super) enum ProviderResponseResolution {
    Accepted(Box<AcceptedProviderResponse>),
    Failed(FailedProviderResponse),
}

pub(super) struct ProviderResponseRecoveryOwner {
    completed: CompletedProviderTurn,
}
impl ProviderResponseRecoveryOwner {
    pub(super) fn new(completed: CompletedProviderTurn) -> Self {
        Self { completed }
    }

    pub(super) async fn resolve(
        self,
        mut journal: ProviderResponseJournal<'_>,
        scope: ProviderResponseScope<'_>,
        submitted: &mut SubmittedTurnState,
        messages: &mut Vec<Message>,
    ) -> Result<ProviderResponseResolution, KernelError> {
        let CompletedProviderTurn {
            mut route,
            mut round,
            execution,
            result,
        } = self.completed;
        let turn = scope.early.turn;
        let mut recovered = false;
        let retry_exhausted = provider_route::retryable_before_semantic_output_provider_error(
            &result,
            round.observations().semantic_output_observed(),
        )
        .is_some();
        let result = match result {
            Ok(result) => result,
            Err(ref error)
                if !scope.plantcore
                    && !round.tools().has_contract_error()
                    && !retry_exhausted
                    && submitted.stream_recoveries().saturating_add(1)
                        < scope.retry.max_attempts
                    && provider_route::recoverable_response_stream_error(error) =>
            {
                let delay = iteron_sched::full_jitter(
                    &scope.retry,
                    submitted.stream_recoveries(),
                    route.continuation_random(),
                );
                let delay = match error {
                    KernelError::Provider(error) => {
                        error.retry_after().map_or(delay, |hint| hint.max(delay))
                    }
                    _ => delay,
                };
                submitted.note_stream_recovery();
                scope.early.hooks.activity.retry(
                    turn,
                    submitted.stream_recoveries(),
                    scope.retry.max_attempts,
                    delay,
                );
                let recovery = journal.prepare_recovery(&scope, delay).await;
                if let Err(error) = recovery {
                    journal.abort(scope.early, &mut round).await?;
                    journal.preserve(
                        turn,
                        messages,
                        round.observations().text(),
                        round.observations().thinking(),
                    );
                    return Err(error);
                }
                journal.tools.ledger.record_provider_retries(
                    1,
                    u64::try_from(delay.as_millis().max(1)).unwrap_or(u64::MAX),
                );
                let calls = round.declared_calls();
                let stop_reason = if calls.is_empty() {
                    StopReason::PauseTurn
                } else {
                    StopReason::ToolUse
                };
                let mut blocks = Vec::new();
                if !round.observations().text().is_empty() {
                    blocks.push(Block::Text {
                        text: format!(
                            "{}\n\n{INTERRUPTED_STREAM_MARKER}",
                            round.observations().text()
                        ),
                    });
                }
                blocks.extend(calls.into_iter().map(Block::ToolUse));
                recovered = true;
                TurnResult {
                    blocks,
                    stop_reason,
                    usage: UsageReport::provider_omitted(),
                }
            }
            Err(error) => {
                let terminal = physical_terminal(&error, scope.terminal);
                journal.abort(scope.early, &mut round).await?;
                journal.preserve(
                    turn,
                    messages,
                    round.observations().text(),
                    round.observations().thinking(),
                );
                return Ok(ProviderResponseResolution::Failed(FailedProviderResponse {
                    error,
                    observe_physical_usage: true,
                    terminal,
                }));
            }
        };
        if let Some(error) = round.take_contract_error() {
            journal.abort(scope.early, &mut round).await?;
            return Ok(ProviderResponseResolution::Failed(FailedProviderResponse {
                error: ProviderError::Decode(error.to_string()).into(),
                observe_physical_usage: false,
                terminal: None,
            }));
        }
        let tools = match round.validated_tools(&result) {
            Ok(tools) => tools,
            Err(error) => {
                journal.abort(scope.early, &mut round).await?;
                return Ok(ProviderResponseResolution::Failed(FailedProviderResponse {
                    error,
                    observe_physical_usage: false,
                    terminal: None,
                }));
            }
        };
        Ok(ProviderResponseResolution::Accepted(
            AcceptedProviderResponse {
                route,
                round,
                execution,
                result,
                recovered,
                tools,
            },
        ))
    }
}

impl ProviderResponseJournal<'_> {
    async fn prepare_recovery(
        &mut self,
        scope: &ProviderResponseScope<'_>,
        delay: Duration,
    ) -> Result<(), KernelError> {
        if let Some(terminal) = scope.terminal {
            return Err(KernelError::InferenceBudgetExhausted(match terminal {
                PlantcoreTerminal::Budget(reason) => reason,
                PlantcoreTerminal::UsageUnavailable => "usage_unavailable",
            }));
        }
        if let Some(usd) = &scope.usd {
            if usd.requires_pricing() {
                usd.mark_unknown();
                return Err(KernelError::UnpricedUsdCeiling);
            }
            if usd.exhausted() {
                return Err(KernelError::InferenceBudgetExhausted("max_usd"));
            }
        }
        self.append(scope.early.turn, EventKind::Notice {
            text:"provider stream disconnected; continuing from completed output and tool calls; interrupted usage remains unknown".into(),
        })?;
        scope
            .control
            .wait_retry(
                delay,
                scope.early.deadline,
                iteron_tunables::param_duration(
                    "cli.runtime.provider_interrupt_poll_interval",
                    PROVIDER_INTERRUPT_POLL_INTERVAL,
                ),
            )
            .await
    }
    async fn abort(
        &mut self,
        scope: EarlyToolCollectionScope<'_>,
        round: &mut ProviderRoundOwner,
    ) -> Result<(), KernelError> {
        let mut collection = EarlyToolCollection {
            journal: ToolExecutionJournal {
                rollout: &mut *self.tools.rollout,
                effects: &mut *self.tools.effects,
                ledger: &mut *self.tools.ledger,
                failed_actions: &mut *self.tools.failed_actions,
                record_failed: &mut *self.tools.record_failed,
                diagnostics: self.tools.diagnostics,
                #[cfg(test)]
                fault: &mut *self.tools.fault,
            },
            scope,
        };
        collection
            .abort_all(&mut round.take_early_for_cleanup())
            .await
    }
    fn preserve(&mut self, turn: TurnId, messages: &mut Vec<Message>, text: &str, thinking: &str) {
        let limit = iteron_tunables::param_integer(
            "cli.runtime.interrupted_stream_max_bytes",
            INTERRUPTED_STREAM_MAX_BYTES,
        )
        .min(INTERRUPTED_STREAM_MAX_BYTES);
        if !thinking.is_empty() {
            let _ = self.append(
                turn,
                EventKind::Thinking {
                    delta: strict_utf8_head(thinking, limit),
                },
            );
        }
        if text.is_empty() {
            return;
        }
        let delta = strict_utf8_head(text, limit);
        let _ = self.append(
            turn,
            EventKind::Text {
                delta: delta.clone(),
            },
        );
        let message = Message {
            role: Role::Assistant,
            content: vec![Block::Text {
                text: format!("{delta}\n\n{INTERRUPTED_STREAM_MARKER}"),
            }],
        };
        if let Ok(source) = self.append(
            turn,
            EventKind::Message {
                message: message.clone(),
            },
        ) {
            *self.assistant_source = Some(source);
            messages.push(message);
        }
    }
    /// The closed producer calls only Notice/Text/Thinking/assistant-text Message. No policy,
    /// financial or terminal event is admitted by this journal.
    fn append(&mut self, turn: TurnId, kind: EventKind) -> Result<Seq, KernelError> {
        #[cfg(test)]
        if matches!(
            (*self.tools.fault, &kind),
            (Some(DurableAppendFault::Notice), EventKind::Notice { .. })
                | (
                    Some(DurableAppendFault::SteerMessage),
                    EventKind::Message { .. }
                )
        ) {
            *self.tools.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected response recovery append refusal",
                ))),
            );
        }
        let mut event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let started = Instant::now();
        let appended = self.tools.rollout.append(&event);
        self.tools.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        match appended {
            Ok(sequence) => {
                event.seq = sequence;
                self.publications.observe_committed(&event);
                Ok(sequence)
            }
            Err(error) => Err(self.record_error(error)),
        }
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.tools.record_failed = true;
        self.tools
            .diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
fn physical_terminal(error: &KernelError, plantcore: Option<PlantcoreTerminal>) -> Option<Outcome> {
    if let Some(terminal) = plantcore {
        return Some(match terminal {
            PlantcoreTerminal::Budget(reason) => Outcome::BudgetExhausted(reason),
            PlantcoreTerminal::UsageUnavailable => Outcome::HarnessError,
        });
    }
    match error {
        KernelError::Provider(ProviderError::DeadlineExceeded) => {
            Some(Outcome::BudgetExhausted("max_wall_secs"))
        }
        KernelError::InferenceBudgetExhausted("usage_unavailable") => Some(Outcome::HarnessError),
        KernelError::InferenceBudgetExhausted(reason) => Some(Outcome::BudgetExhausted(reason)),
        _ => None,
    }
}
