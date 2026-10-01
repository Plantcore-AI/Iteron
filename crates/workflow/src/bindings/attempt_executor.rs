//! Physical child execution/cleanup adapter and durable attempt settlement coordinator.
//!
//! This module has no JavaScript interpreter dependency. It observes immutable host ports and
//! publishes attempt commands only through the task ledger; run admission stays in RunState.

use super::run_state::AgentEnv;
use crate::events::ProgressEvent;
use crate::spawner::{AgentActivityReporter, AgentCall, AgentInvocationIdentity, AgentOutcome};
use crate::task_dag::runtime::{AttemptRetryLink, AttemptTerminal, digest_bytes};
use crate::task_dag::{
    AttemptAssignment, AttemptDisposition, AttemptId, AttemptRetryCause, TaskId,
};
use std::time::{Duration, Instant};

/// Token-only activity is coalesced at 250ms. State transitions remain immediate, while four hertz
/// keeps counters feeling live without turning decode tokens into an unbounded event stream.
const AGENT_ACTIVITY_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_CANCEL_ACK_TIMEOUT: Duration = Duration::from_millis(300);
const HARD_CANCEL_ACK_TIMEOUT: Duration = Duration::from_secs(1);

fn cancel_ack_timeout() -> Duration {
    let hard = iteron_tunables::param_duration(
        "workflow.bindings.hard_cancel_ack_timeout",
        HARD_CANCEL_ACK_TIMEOUT,
    )
    .clamp(Duration::from_millis(1), HARD_CANCEL_ACK_TIMEOUT);
    iteron_tunables::param_duration(
        "workflow.bindings.default_cancel_ack_timeout",
        DEFAULT_CANCEL_ACK_TIMEOUT,
    )
    .clamp(Duration::from_millis(1), hard)
}

#[derive(Debug)]
enum AttemptExecution {
    Settled(AgentOutcome),
    Failed(String),
    UnknownEffect(String),
}

#[derive(Debug)]
struct AttemptRun {
    id: AttemptId,
    elapsed_ms: u64,
    execution: AttemptExecution,
}

#[derive(Debug, Clone)]
pub(super) struct AttemptLineage {
    assignment: AttemptAssignment,
    retry_of: Option<AttemptId>,
    retry_cause: Option<AttemptRetryCause>,
}

impl AttemptLineage {
    pub(super) fn initial() -> Self {
        Self {
            assignment: AttemptAssignment::Initial,
            retry_of: None,
            retry_cause: None,
        }
    }

    pub(super) fn retry(
        assignment: AttemptAssignment,
        retry_of: AttemptId,
        retry_cause: AttemptRetryCause,
    ) -> Self {
        debug_assert!(assignment != AttemptAssignment::Initial);
        Self {
            assignment,
            retry_of: Some(retry_of),
            retry_cause: Some(retry_cause),
        }
    }
}

#[derive(Debug)]
pub(super) struct CandidateSelection {
    pub(super) outcome: AgentOutcome,
    pub(super) evidence_attempt: AttemptId,
    pub(super) retry_cause: Option<AttemptRetryCause>,
}

/// Reserve one physical-dispatch identity before its external effect begins. A pre-dispatch ceiling
/// refusal creates no attempt because no child effect crossed the broker boundary.
async fn prepare_attempt(
    env: &AgentEnv,
    task: TaskId,
    call: &AgentCall,
    retry_ordinal: usize,
    sibling_ordinal: usize,
    lineage: &AttemptLineage,
) -> Result<AttemptId, String> {
    if !env.state.admit_agent_call() {
        return Err(format!(
            "agent call ceiling {} reached",
            env.state.max_agent_calls
        ));
    }
    let input_digest = digest_bytes(call.prompt.as_bytes());
    env.task_dag
        .begin_attempt(
            task,
            retry_ordinal,
            sibling_ordinal,
            lineage.assignment,
            AttemptRetryLink::new(lineage.retry_of, lineage.retry_cause),
            &input_digest,
        )
        .await
}

/// Run one already-journaled SEND child. Cancellation first asks the spawner to settle through its
/// token; only an elapsed cleanup bound aborts the exact task handle and records UnknownEffect.
async fn spawn_child(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    attempt_id: AttemptId,
    cleanup_timeout: Duration,
) -> AttemptRun {
    let spawner = env.spawner.clone();
    let call = call.clone();
    let call_cancel = call.cancel.clone();
    let (activity, activity_rx) = AgentActivityReporter::channel();
    let mut child = tokio::spawn(async move {
        let Some(identity) = AgentInvocationIdentity::admitted(idx, attempt_id) else {
            return AgentOutcome::null(
                "actual engine attempt identity exceeds its bounded envelope",
            );
        };
        spawner.spawn_with_identity(call, identity, activity).await
    });
    let started = Instant::now();
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now()
            + iteron_tunables::param_duration(
                "workflow.bindings.agent_activity_interval",
                AGENT_ACTIVITY_INTERVAL,
            ),
        iteron_tunables::param_duration(
            "workflow.bindings.agent_activity_interval",
            AGENT_ACTIVITY_INTERVAL,
        ),
    );
    let mut last_emitted = None;
    loop {
        tokio::select! {
            biased;
            _ = call_cancel.cancelled() => {
                env.sink.emit(ProgressEvent::AgentCancelling {
                    index: idx,
                    cleanup_deadline_ms: cleanup_timeout.as_millis().min(u128::from(u64::MAX)) as u64,
                });
                let execution = match tokio::time::timeout(
                    cleanup_timeout,
                    &mut child,
                ).await {
                    Ok(Ok(outcome)) => AttemptExecution::Settled(outcome),
                    Ok(Err(error)) => AttemptExecution::Failed(format!("agent task failed: {error}")),
                    Err(_) => {
                        child.abort();
                        let _ = child.await;
                        AttemptExecution::UnknownEffect(
                            "child did not acknowledge cancellation before cleanup deadline".into(),
                        )
                    }
                };
                return AttemptRun {
                    id: attempt_id,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    execution,
                };
            }
            res = &mut child => {
                let execution = match res {
                    Ok(outcome) => AttemptExecution::Settled(outcome),
                    Err(error) => AttemptExecution::Failed(format!("agent task failed: {error}")),
                };
                return AttemptRun {
                    id: attempt_id,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    execution,
                };
            }
            _ = interval.tick() => {
                let latest = activity_rx.borrow().clone();
                if latest.is_some() && latest != last_emitted {
                    let snapshot = latest.clone().expect("checked as some");
                    env.sink.emit(ProgressEvent::AgentActivity {
                        index: idx,
                        tokens: snapshot.tokens,
                        tool_calls: snapshot.tool_calls,
                        last_tool_summary: snapshot.last_tool_summary,
                    });
                    last_emitted = latest;
                }
            }
        }
    }
}

/// Run one explicit read-only speculative group and return the first positive terminal. Every
/// loser receives a sibling-only cancellation token; cleanup is joined for a finite policy-owned
/// interval before any task is aborted as an exact-handle backstop.
pub(super) async fn spawn_candidate(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    task: TaskId,
    retry_ordinal: usize,
    speculative_siblings: usize,
    lineage: &AttemptLineage,
) -> Result<CandidateSelection, String> {
    if speculative_siblings == 0 {
        let attempt = prepare_attempt(env, task, call, retry_ordinal, 0, lineage).await?;
        let run = spawn_child(env, call, idx, attempt, cancel_ack_timeout()).await;
        return settle_sole_attempt(env, task, run).await;
    }
    if env.spawner.execution_class(call) != crate::AgentExecutionClass::ReadOnly {
        return Err(
            "speculative siblings are read-only; isolated writer authority cannot be duplicated"
                .into(),
        );
    }

    let group = call.cancel.child_token();
    let mut tasks = tokio::task::JoinSet::new();
    let mut pending = std::collections::BTreeSet::new();
    let mut first_negative: Option<(AgentOutcome, AttemptId, AttemptRetryCause)> = None;
    let mut first_refusal = None;
    for sibling_ordinal in 0..=speculative_siblings {
        let attempt =
            match prepare_attempt(env, task, call, retry_ordinal, sibling_ordinal, lineage).await {
                Ok(attempt) => attempt,
                Err(reason) => {
                    first_refusal.get_or_insert(reason);
                    continue;
                }
            };
        pending.insert(attempt);
        let env = env.clone();
        let mut sibling = call.clone();
        sibling.cancel = group.child_token();
        tasks.spawn(async move {
            let cleanup_timeout = env.speculative_siblings.cleanup_timeout();
            (
                attempt,
                spawn_child(&env, &sibling, idx, attempt, cleanup_timeout).await,
            )
        });
    }

    let mut runs = Vec::new();
    let mut winner_id = None;
    let mut winner_outcome = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((attempt, run)) => {
                pending.remove(&attempt);
                let positive = match &run.execution {
                    AttemptExecution::Settled(outcome @ AgentOutcome::Text { text, .. })
                        if winner_id.is_none() =>
                    {
                        Some((outcome.clone(), digest_bytes(text.as_bytes())))
                    }
                    _ => None,
                };
                if let Some((outcome, result_digest)) = positive {
                    winner_id = Some(run.id);
                    winner_outcome = Some(outcome);
                    match env
                        .task_dag
                        .record_speculative_winner(task, run.id, &result_digest)
                        .await
                    {
                        Ok(()) if env.speculative_siblings.cancel_losers() => group.cancel(),
                        Ok(()) => {}
                        Err(error) => env.sink.emit(ProgressEvent::Log {
                            message: format!(
                                "workflow: speculative winner receipt unavailable; siblings were not cancelled early: {error}"
                            ),
                        }),
                    }
                }
                if let AttemptExecution::Settled(AgentOutcome::Null { reason }) = &run.execution {
                    first_negative.get_or_insert_with(|| {
                        (
                            AgentOutcome::Null {
                                reason: reason.clone(),
                            },
                            run.id,
                            AttemptRetryCause::NegativeTerminal,
                        )
                    });
                } else if let AttemptExecution::Failed(reason) = &run.execution {
                    first_negative.get_or_insert_with(|| {
                        (
                            AgentOutcome::null(reason.clone()),
                            run.id,
                            AttemptRetryCause::ChildFailure,
                        )
                    });
                }
                runs.push(run);
            }
            Err(error) => {
                first_refusal
                    .get_or_insert_with(|| format!("agent task failed without identity: {error}"));
            }
        }
    }

    // A JoinSet panic/abort loses its returned identity, but not the controller's pre-dispatch WAL.
    // Those exact ids are terminalized as unknown and the selected result is refused below.
    for attempt in pending {
        runs.push(AttemptRun {
            id: attempt,
            elapsed_ms: 0,
            execution: AttemptExecution::UnknownEffect(
                "attempt task ended without a reconciliation receipt".into(),
            ),
        });
    }

    let mut unknown = false;
    for run in runs {
        let is_winner = winner_id == Some(run.id);
        match settle_group_attempt(env, task, run, is_winner, winner_id.is_some()).await {
            Ok(run_unknown) => unknown |= run_unknown,
            Err(error) => {
                env.cancel.cancel();
                return Err(format!("task DAG durability failed: {error}"));
            }
        }
    }
    if unknown {
        return Err(
            "speculative sibling effect outcome is unknown; selected result refused".into(),
        );
    }
    if let (Some(outcome), Some(evidence_attempt)) = (winner_outcome, winner_id) {
        return Ok(CandidateSelection {
            outcome,
            evidence_attempt,
            retry_cause: None,
        });
    }
    if let Some((outcome, evidence_attempt, retry_cause)) = first_negative {
        return Ok(CandidateSelection {
            outcome,
            evidence_attempt,
            retry_cause: Some(retry_cause),
        });
    }
    Err(first_refusal.unwrap_or_else(|| "speculative group produced no terminal".into()))
}

async fn settle_sole_attempt(
    env: &AgentEnv,
    task: TaskId,
    run: AttemptRun,
) -> Result<CandidateSelection, String> {
    let AttemptRun {
        id,
        elapsed_ms,
        execution,
    } = run;
    match execution {
        AttemptExecution::Settled(AgentOutcome::Text {
            text,
            tokens,
            tool_calls,
            last_tool_summary,
        }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    tokens,
                    elapsed_ms,
                    AttemptTerminal::Succeeded {
                        result_digest: digest_bytes(text.as_bytes()),
                        disposition: AttemptDisposition::Sole,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::Text {
                    text,
                    tokens,
                    tool_calls,
                    last_tool_summary,
                },
                evidence_attempt: id,
                retry_cause: None,
            })
        }
        AttemptExecution::Settled(AgentOutcome::Null { reason }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "negative_terminal",
                        detail: reason
                            .clone()
                            .unwrap_or_else(|| "agent returned null".into()),
                        disposition: AttemptDisposition::Negative,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                evidence_attempt: id,
                retry_cause: Some(AttemptRetryCause::NegativeTerminal),
            })
        }
        AttemptExecution::Failed(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "child_task_failed",
                        detail: reason.clone(),
                        disposition: AttemptDisposition::Negative,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::null(reason),
                evidence_attempt: id,
                retry_cause: Some(AttemptRetryCause::ChildFailure),
            })
        }
        AttemptExecution::UnknownEffect(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::UnknownEffect {
                        reason: reason.clone(),
                    },
                )
                .await?;
            Err(format!("unknown child effect: {reason}"))
        }
    }
}

async fn settle_group_attempt(
    env: &AgentEnv,
    task: TaskId,
    run: AttemptRun,
    winner: bool,
    group_has_winner: bool,
) -> Result<bool, String> {
    let AttemptRun {
        id,
        elapsed_ms,
        execution,
    } = run;
    match execution {
        AttemptExecution::Settled(AgentOutcome::Text { text, tokens, .. }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    tokens,
                    elapsed_ms,
                    AttemptTerminal::Succeeded {
                        result_digest: digest_bytes(text.as_bytes()),
                        disposition: if winner {
                            AttemptDisposition::Winner
                        } else {
                            AttemptDisposition::Loser
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::Settled(AgentOutcome::Null { reason }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "negative_terminal",
                        detail: reason.unwrap_or_else(|| "agent returned null".into()),
                        disposition: if group_has_winner {
                            AttemptDisposition::Loser
                        } else {
                            AttemptDisposition::Negative
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::Failed(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "child_task_failed",
                        detail: reason,
                        disposition: if group_has_winner {
                            AttemptDisposition::Loser
                        } else {
                            AttemptDisposition::Negative
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::UnknownEffect(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::UnknownEffect { reason },
                )
                .await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn ordinary_cancel_ack_is_not_the_speculative_cleanup_tail() {
        assert!(cancel_ack_timeout() <= Duration::from_millis(300));
        assert!(
            cancel_ack_timeout() < crate::SpeculativeSiblingPolicy::default().cleanup_timeout()
        );
    }
}
