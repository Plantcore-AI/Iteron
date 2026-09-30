//! The Rust host primitives behind the JS prelude: `__agent`, `__phase`, `__log`.
//!
//! `__agent` is the load-bearing bridge (proven in the B4 spike): it assigns a declaration-order
//! index synchronously, then — for a live call — acquires a [`iteron_sched::Governor`] permit (the one global slot
//! pool), `tokio::spawn`s a SEND child running the injected [`crate::spawner::AgentSpawner`], and awaits it (racing
//! the run's [`tokio_util::sync::CancellationToken`]), resolving the JS Promise back on the runtime thread.
//!
//! Three engine-depth behaviors live here (design §2.5/§2.6 + review B2/B3):
//!   * **Journal short-circuit (B2):** on a journal hit `__agent` replays the cached OUTCOME —
//!     including `null` — BEFORE touching the Governor, budget, or lifetime cap, so
//!     `parallel(...).filter(Boolean)` is deterministic across a resume.
//!   * **Schema-forced structured output (§2.5):** when `opts.schema` is set, the model's text is
//!     parsed + validated against the JSON Schema; on failure the spawner is re-called with the
//!     errors appended, up to the run's pinned schema-retry ceiling, then degrades to `null`.
//!   * **Cancellation (B3):** each child races the cancel token and is aborted on cancel.
//!
//! Per-run state lives in [`RunState`]/[`AgentEnv`] (owned, never a static — a `OnceLock` silently
//! no-ops on the 2nd run and masks concurrency, per the spike's watch-out).

use crate::cachekey;
use crate::events::{
    PREVIEW_MAX, ProgressEvent, TOOL_SUMMARY_MAX, WorkflowState, truncate_preview,
};
use crate::journal::{Outcome, Record};
use crate::schema::{self, SchemaValidator};
use crate::spawner::{AgentCall, AgentOutcome};
use crate::task_dag::runtime::{TaskAdmission, digest_bytes};
use crate::task_dag::{AttemptAssignment, AttemptRetryCause, TaskId};
use iteron_sched::backoff::{Jitter, full_jitter};
use rquickjs::function::Async;
use rquickjs::{Ctx, Function};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

mod attempt_executor;
mod quorum;
mod run_state;
use attempt_executor::{AttemptLineage, CandidateSelection, spawn_candidate};
use run_state::TrackedPermit;
pub(crate) use run_state::{AgentEnv, RunState};

/// Speculation is never implicit: a call that omits `speculativeSiblings` requests no duplicate
/// workers at all.
const BINDING_ABSENT_SPECULATIVE_SIBLINGS: usize = 0;

/// Width of a progress-row label derived from a prompt: a few words, short enough that the row
/// stays on one line in a narrow terminal beside the counters that share it.
const AGENT_LABEL_PREVIEW_MAX: usize = 40;

/// Width of the retained failure text on a retried attempt. Long enough to keep the model's stated
/// reason usable as retry evidence, bounded so a verbose terminal cannot inflate the durable log.
const RETRY_EVIDENCE_PREVIEW_MAX: usize = 512;

/// Attempt floor applied to the retry policy. A policy of zero attempts would silently skip the
/// assigned worker, so the call is still made once and the policy only ever adds reassignments.
const MIN_TASK_ATTEMPTS: usize = 1;

/// The escalation text handed to a fresh assignee after a read-only predecessor settled without
/// usable evidence. This is the compiled default behind the `prompt/recovery@v1` artifact: an
/// operator profile may replace the whole template, and with no profile the rendered bytes are
/// exactly what the previous inline `format!` produced.
///
/// `{prompt}` is the original assignment text and `{evidence}` the bounded predecessor reason.
/// Substitution is one left-to-right pass over the TEMPLATE only, so neither spliced value can be
/// rescanned for placeholders; an unknown `{...}` is copied through verbatim.
pub const RECOVERY_ESCALATION_PROMPT: &str = "{prompt}\n\nA prior read-only assignee ended without usable evidence: {evidence}\nIndependently complete the original task.";
/// Render [`RECOVERY_ESCALATION_PROMPT`] (or its profile replacement) against one attempt.
fn render_recovery_escalation(template: &str, prompt: &str, evidence: &str) -> String {
    let mut rendered = String::with_capacity(template.len() + prompt.len() + evidence.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let tail = &rest[open..];
        if let Some(remainder) = tail.strip_prefix("{prompt}") {
            rendered.push_str(prompt);
            rest = remainder;
        } else if let Some(remainder) = tail.strip_prefix("{evidence}") {
            rendered.push_str(evidence);
            rest = remainder;
        } else {
            rendered.push('{');
            rest = &tail['{'.len_utf8()..];
        }
    }
    rendered.push_str(rest);
    rendered
}

// ---- JS <-> Rust envelopes -----------------------------------------------------------------------

/// The prelude's `agent()` parses one of these. `ok:false` -> JS `null`; `kind:"structured"` ->
/// return `value` (an object) directly; `kind:"text"` -> return the string.
fn text_envelope(text: &str) -> String {
    serde_json::json!({ "ok": true, "kind": "text", "text": text }).to_string()
}
fn structured_envelope(value: &Value) -> String {
    serde_json::json!({ "ok": true, "kind": "structured", "value": value }).to_string()
}
fn null_envelope(reason: &str) -> String {
    serde_json::json!({ "ok": false, "kind": "null", "reason": reason }).to_string()
}

/// The envelope + progress state for a replayed/finished [`Record`].
fn envelope_for(record: &Record) -> String {
    match &record.outcome {
        Outcome::Structured { value } => structured_envelope(value),
        Outcome::Text { text } => text_envelope(text),
        Outcome::Null { reason } => null_envelope(reason.as_deref().unwrap_or("null")),
        Outcome::Unknown => null_envelope("unknown journal outcome"),
    }
}

/// The wire shape the prelude's `agent()` marshals into `__agent`.
#[derive(serde::Deserialize)]
struct RawCall {
    prompt: String,
    label: Option<String>,
    phase: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    #[serde(rename = "agentType")]
    agent_type: Option<String>,
    #[serde(default)]
    schema: Option<Value>,
    #[serde(default, rename = "quorumGroup")]
    quorum_group: Option<u64>,
    #[serde(default, rename = "speculativeSiblings")]
    speculative_siblings: Option<usize>,
    #[serde(default, rename = "dependsOn")]
    depends_on: Option<Vec<usize>>,
}

/// A short human label for the progress row when the caller gave none: the prompt's first words.
fn label_for(prompt: &str, idx: usize) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return format!("agent {idx}");
    }
    truncate_preview(
        trimmed,
        iteron_tunables::param_integer(
            "workflow.bindings.agent_label_preview_max",
            AGENT_LABEL_PREVIEW_MAX,
        ),
    )
}

/// Keep a refused call identifiable without allowing its label to become a multi-line or terminal
/// control surface. Empty labels fall back to the same prompt-derived identity as admitted calls.
fn refusal_label(label: Option<&str>, prompt: &str, idx: usize) -> String {
    label
        .map(|label| {
            truncate_preview(
                label,
                iteron_tunables::param_integer(
                    "workflow.bindings.agent_label_preview_max",
                    AGENT_LABEL_PREVIEW_MAX,
                ),
            )
        })
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| label_for(prompt, idx))
}

/// A requested model id is untrusted routing metadata and may itself be credential-shaped. The
/// engine cannot prove the selected route (that belongs to the spawner), so progress reports only
/// the presence of an override and never reflects the raw id to a terminal sink.
fn progress_model(model: Option<&str>) -> Option<String> {
    model.map(|_| "requested model override".to_string())
}

/// Emit a finished row derived from a [`Record`] (used by both the live path and cache replay).
fn emit_finished(env: &AgentEnv, idx: usize, label: String, record: &Record, duration_ms: u64) {
    let (state, result_preview, error) = match &record.outcome {
        Outcome::Structured { value } => (
            WorkflowState::Done,
            Some(truncate_preview(
                &value.to_string(),
                iteron_tunables::param_integer("workflow.events.preview_max", PREVIEW_MAX),
            )),
            None,
        ),
        Outcome::Text { text } => (
            WorkflowState::Done,
            Some(truncate_preview(
                text,
                iteron_tunables::param_integer("workflow.events.preview_max", PREVIEW_MAX),
            )),
            None,
        ),
        Outcome::Null { reason } => (
            WorkflowState::Error,
            None,
            Some(
                reason
                    .clone()
                    .unwrap_or_else(|| "agent returned null".into()),
            ),
        ),
        Outcome::Unknown => (
            WorkflowState::Error,
            None,
            Some("unknown journal outcome".into()),
        ),
    };
    env.state.observe(state, record.tokens, record.tool_calls);
    env.sink.emit(ProgressEvent::AgentFinished {
        index: idx,
        label,
        state,
        tokens: record.tokens,
        tool_calls: record.tool_calls,
        duration_ms,
        result_preview,
        last_tool_summary: record.last_tool_summary.as_deref().map(|s| {
            truncate_preview(
                s,
                iteron_tunables::param_integer(
                    "workflow.events.tool_summary_max",
                    TOOL_SUMMARY_MAX,
                ),
            )
        }),
        error,
    });
}

/// Terminalize a request-metadata refusal without acquiring a Governor permit or calling the
/// spawner. Negative outcomes remain journaled for deterministic resume. The record reflects no
/// rejected routing metadata: it carries one static bounded reason. The progress row retains the
/// separately-sanitized display label so the operator can identify which agent was refused.
async fn settle_metadata_refusal(
    env: &AgentEnv,
    idx: usize,
    task: TaskId,
    label: String,
    key: &str,
    reason: &'static str,
    journal_miss: bool,
) -> String {
    env.sink.emit(ProgressEvent::AgentQueued {
        index: idx,
        label: label.clone(),
        phase: None,
        model: None,
    });
    let record = Record::null(Some(reason.to_owned()));
    if journal_miss
        && env
            .journal
            .record(key, &cachekey::agent_id(key), record.clone())
            .is_err()
    {
        env.sink.emit(ProgressEvent::Log {
            message: "workflow: journal durability failed".into(),
        });
        env.cancel.cancel();
        let _ = env
            .task_dag
            .finish_task_failure(
                task,
                "journal_durability_failed",
                "journal durability failed",
            )
            .await;
        return null_envelope("journal durability failed");
    }
    if env
        .task_dag
        .finish_task_failure(task, "invalid_request_metadata", reason)
        .await
        .is_err()
    {
        env.cancel.cancel();
        return null_envelope("task DAG durability failed");
    }
    emit_finished(env, idx, label, &record, 0);
    null_envelope(reason)
}

async fn finish_task_for_record(
    env: &AgentEnv,
    task: TaskId,
    record: &Record,
) -> Result<(), String> {
    match &record.outcome {
        Outcome::Text { .. } | Outcome::Structured { .. } => {
            let encoded = serde_json::to_vec(record)
                .map_err(|error| format!("record digest serialization failed: {error}"))?;
            env.task_dag
                .finish_task_success(task, digest_bytes(&encoded))
                .await
        }
        Outcome::Null { reason } => {
            env.task_dag
                .finish_task_failure(
                    task,
                    "negative_terminal",
                    reason.as_deref().unwrap_or("agent returned null"),
                )
                .await
        }
        Outcome::Unknown => {
            env.task_dag
                .finish_task_failure(task, "unknown_journal_outcome", "unknown journal outcome")
                .await
        }
    }
}

/// The no-schema path: one child call -> a `Text`/`Null` record + its envelope.
async fn run_plain(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    task: TaskId,
    speculative_siblings: usize,
) -> (Record, String) {
    let attempts = env
        .task_retry
        .max_attempts()
        .max(iteron_tunables::param_usize(
            "workflow.bindings.min_task_attempts",
            iteron_tunables::param_integer(
                "workflow.bindings.min_task_attempts",
                MIN_TASK_ATTEMPTS,
            ),
        ));
    let mut assigned = call.clone();
    let mut lineage = AttemptLineage::initial();
    for attempt in 0..attempts {
        match spawn_candidate(
            env,
            &assigned,
            idx,
            task,
            attempt,
            speculative_siblings,
            &lineage,
        )
        .await
        {
            Ok(CandidateSelection {
                outcome:
                    AgentOutcome::Text {
                        text,
                        tokens,
                        tool_calls,
                        last_tool_summary,
                    },
                ..
            }) => {
                let record = Record::text(text.clone(), tokens, tool_calls, last_tool_summary);
                let envelope = text_envelope(&text);
                return (record, envelope);
            }
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                evidence_attempt,
                retry_cause,
            }) => {
                let exhausted = attempt + 1 >= attempts
                    || env.task_retry.on_failure() == crate::TaskFailureAction::Stop;
                if exhausted {
                    let envelope = null_envelope(reason.as_deref().unwrap_or("null"));
                    return (Record::null(reason), envelope);
                }
                let evidence = reason
                    .as_deref()
                    .map(|value| {
                        truncate_preview(
                            value,
                            iteron_tunables::param_usize(
                                "workflow.bindings.retry_evidence_preview_max",
                                iteron_tunables::param_integer(
                                    "workflow.bindings.retry_evidence_preview_max",
                                    RETRY_EVIDENCE_PREVIEW_MAX,
                                ),
                            ),
                        )
                    })
                    .unwrap_or_else(|| "definite negative terminal".into());
                let assignment = match env.task_retry.on_failure() {
                    crate::TaskFailureAction::RetrySame => AttemptAssignment::RetrySame,
                    crate::TaskFailureAction::Reassign => AttemptAssignment::Reassigned,
                    crate::TaskFailureAction::Stop => unreachable!("handled as exhausted"),
                };
                let retry_cause = retry_cause
                    .expect("a definite negative candidate must retain its durable terminal cause");
                lineage = AttemptLineage::retry(assignment, evidence_attempt, retry_cause);
                if env.task_retry.on_failure() == crate::TaskFailureAction::Reassign
                    && env.task_retry.preserve_evidence()
                {
                    let template = env
                        .tunables_profile
                        .as_deref()
                        .and_then(|document| {
                            iteron_tunables::artifact_override(document, "prompt/recovery@v1")
                        })
                        .unwrap_or(iteron_tunables::param_str(
                            "workflow.bindings.recovery_escalation_prompt",
                            RECOVERY_ESCALATION_PROMPT,
                        ));
                    assigned.prompt = render_recovery_escalation(template, &call.prompt, &evidence);
                }
            }
            Err(reason) => {
                let envelope = null_envelope(&reason);
                return (Record::null(Some(reason)), envelope);
            }
        }
    }
    let reason = "task retry policy exhausted without a terminal";
    (Record::null(Some(reason.into())), null_envelope(reason))
}

/// The schema-forced path (design §2.5): parse+validate the output; on failure re-call the spawner
/// with the errors appended, up to the pinned attempt ceiling (spaced by full-jitter backoff); return the
/// validated object as a `Structured` record, or `Null` on exhaustion / a degraded child.
async fn run_with_schema(
    env: &AgentEnv,
    base_call: &AgentCall,
    schema_value: &Value,
    idx: usize,
    task: TaskId,
    speculative_siblings: usize,
) -> (Record, String) {
    let validator = match SchemaValidator::compile(schema_value) {
        Ok(v) => v,
        Err(error) => {
            let reason = format!("invalid schema: {error}");
            env.sink.emit(ProgressEvent::Log {
                message: format!("workflow: agent #{idx} {reason}"),
            });
            let envelope = null_envelope(&reason);
            return (Record::null(Some(reason)), envelope);
        }
    };

    let policy = env.schema_retry.backoff();
    let mut jitter = Jitter::new();
    let mut last_errors: Vec<String> = Vec::new();
    let mut lineage = AttemptLineage::initial();

    for attempt in 0..env.schema_retry.max_attempts() {
        let mut call = base_call.clone();
        if attempt > 0 {
            call.prompt = schema::augment_prompt(&base_call.prompt, &last_errors);
            let delay = full_jitter(&policy, attempt - 1, jitter.next01());
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        match spawn_candidate(
            env,
            &call,
            idx,
            task,
            attempt as usize,
            speculative_siblings,
            &lineage,
        )
        .await
        {
            Ok(CandidateSelection {
                outcome:
                    AgentOutcome::Text {
                        text,
                        tokens,
                        tool_calls,
                        ..
                    },
                evidence_attempt,
                ..
            }) => {
                match schema::parse_json(&text) {
                    Ok(value) => match validator.validate(&value) {
                        Ok(()) => {
                            let record = Record::structured(value.clone(), tokens, tool_calls);
                            let envelope = structured_envelope(&value);
                            return (record, envelope);
                        }
                        Err(errors) => last_errors = errors,
                    },
                    Err(parse_error) => last_errors = vec![parse_error],
                }
                lineage = AttemptLineage::retry(
                    AttemptAssignment::RetrySame,
                    evidence_attempt,
                    AttemptRetryCause::SchemaValidation,
                );
            }
            // A degraded child or a cancel is terminal: no point retrying a deterministic null.
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                ..
            }) => {
                let envelope = null_envelope(reason.as_deref().unwrap_or("null"));
                return (Record::null(reason), envelope);
            }
            Err(reason) => {
                let envelope = null_envelope(&reason);
                return (Record::null(Some(reason)), envelope);
            }
        }
    }

    let reason = format!(
        "schema validation failed after {} attempts",
        env.schema_retry.max_attempts()
    );
    env.sink.emit(ProgressEvent::Log {
        message: format!("workflow: agent #{idx} {reason}"),
    });
    let envelope = null_envelope(&reason);
    (Record::null(Some(reason)), envelope)
}

/// The `__agent` body: cache short-circuit -> lifetime cap -> permit -> live run -> journal.
async fn run_agent(env: Arc<AgentEnv>, idx: usize, arg: String) -> String {
    let raw: RawCall = match serde_json::from_str(&arg) {
        Ok(call) => call,
        Err(_) => {
            let input_digest = digest_bytes(arg.as_bytes());
            let task = match env.task_dag.begin_task(idx, &input_digest, &[]).await {
                Ok(TaskAdmission::Ready(task)) => task,
                Ok(TaskAdmission::SkippedDependency { .. }) => {
                    unreachable!("a dependency-free task cannot be skipped")
                }
                Err(error) => {
                    env.sink.emit(ProgressEvent::Log {
                        message: format!("workflow: task DAG admission failed: {error}"),
                    });
                    env.cancel.cancel();
                    return null_envelope("task DAG admission failed");
                }
            };
            if env
                .task_dag
                .finish_task_failure(task, "malformed_agent_call", "malformed agent call")
                .await
                .is_err()
            {
                env.cancel.cancel();
                return null_envelope("task DAG durability failed");
            }
            return null_envelope("malformed agent() call");
        }
    };
    let dependencies = raw.depends_on.as_deref().unwrap_or(&[]);

    // Validate routing metadata before catalog lookup, rollout creation, provider dispatch, or a
    // Governor permit. The error type contains no caller text, so the same static reason is safe in
    // the envelope, progress row, and durable negative journal record.
    let metadata = AgentCall::validate_agent_type(raw.agent_type.as_deref())
        .and_then(|()| AgentCall::validate_model(raw.model.as_deref()));

    // --- content key over the CALLER's raw input (deterministic; §2.6) --------------------------
    let key = match metadata {
        Ok(()) => cachekey::agent_key_with_execution(
            &raw.prompt,
            raw.label.as_deref(),
            raw.phase.as_deref(),
            raw.schema.as_ref(),
            raw.model.as_deref(),
            raw.effort.as_deref(),
            raw.agent_type.as_deref(),
            raw.speculative_siblings,
            Some(dependencies),
        ),
        Err(error) => cachekey::rejected_agent_key(&arg, error.code()),
    };

    // Resume is a pure journal read: do not mint a new task, message, attempt, budget charge or
    // fsync for work whose durable terminal already exists. This is the first stateful lookup
    // after bounded parsing/key construction and remains before every live admission boundary.
    if let Some(record) = env.journal.get(&key) {
        let (label, visible_record) = match metadata {
            Ok(()) => (
                raw.label
                    .clone()
                    .unwrap_or_else(|| label_for(&raw.prompt, idx)),
                record,
            ),
            Err(error) => (
                refusal_label(raw.label.as_deref(), &raw.prompt, idx),
                Record::null(Some(error.public_reason().to_owned())),
            ),
        };
        env.sink.emit(ProgressEvent::AgentQueued {
            index: idx,
            label: label.clone(),
            phase: raw.phase.clone(),
            model: progress_model(raw.model.as_deref()),
        });
        env.sink.emit(ProgressEvent::AgentStarted {
            index: idx,
            label: label.clone(),
            phase: raw.phase.clone(),
            model: progress_model(raw.model.as_deref()),
            queued_ms: 0,
            available_permits: env.available_permits.load(Ordering::Acquire),
        });
        emit_finished(&env, idx, label, &visible_record, 0);
        env.state.observe_quorum(
            raw.quorum_group,
            raw.agent_type.as_deref().unwrap_or("generic"),
            matches!(
                &visible_record.outcome,
                Outcome::Text { .. } | Outcome::Structured { .. }
            ),
        );
        return envelope_for(&visible_record);
    }
    let input_digest = digest_bytes(arg.as_bytes());
    let task = match env
        .task_dag
        .begin_task(idx, &input_digest, dependencies)
        .await
    {
        Ok(TaskAdmission::Ready(task)) => task,
        Ok(TaskAdmission::SkippedDependency { task, dependency }) => {
            let reason = format!(
                "dependency task {} did not succeed; dependent task {task:?} was skipped",
                dependency.0
            );
            let record = Record::null(Some(reason.clone()));
            if env
                .journal
                .record(&key, &cachekey::agent_id(&key), record.clone())
                .is_err()
            {
                env.cancel.cancel();
                return null_envelope("journal durability failed");
            }
            let label = raw
                .label
                .clone()
                .unwrap_or_else(|| label_for(&raw.prompt, idx));
            emit_finished(&env, idx, label, &record, 0);
            return null_envelope(&reason);
        }
        Err(error) => {
            env.sink.emit(ProgressEvent::Log {
                message: format!("workflow: task DAG admission failed: {error}"),
            });
            env.cancel.cancel();
            return null_envelope("task DAG admission failed");
        }
    };
    let speculative_siblings = raw
        .speculative_siblings
        .unwrap_or(iteron_tunables::param_usize(
            "workflow.bindings.binding_absent_speculative_siblings",
            iteron_tunables::param_integer(
                "workflow.bindings.binding_absent_speculative_siblings",
                BINDING_ABSENT_SPECULATIVE_SIBLINGS,
            ),
        ));
    if speculative_siblings > env.speculative_siblings.max_siblings() {
        if env
            .task_dag
            .finish_task_failure(
                task,
                "speculative_sibling_ceiling",
                "speculative sibling request exceeds the host ceiling",
            )
            .await
            .is_err()
        {
            env.cancel.cancel();
            return null_envelope("task DAG durability failed");
        }
        return null_envelope("speculative sibling request exceeds the host ceiling");
    }
    if speculative_siblings > 0 && raw.schema.is_some() {
        // The winner must be selected from verified evidence. Schema validation currently occurs
        // after the physical child settles, so duplicating this call would otherwise cancel a
        // valid sibling merely because an earlier sibling returned invalid JSON.
        if env
            .task_dag
            .finish_task_failure(
                task,
                "speculative_schema_unsupported",
                "schema-validated calls cannot use speculative siblings",
            )
            .await
            .is_err()
        {
            env.cancel.cancel();
            return null_envelope("task DAG durability failed");
        }
        return null_envelope("schema-validated calls cannot use speculative siblings");
    }

    if let Err(error) = metadata {
        let label = refusal_label(raw.label.as_deref(), &raw.prompt, idx);
        let envelope =
            settle_metadata_refusal(&env, idx, task, label, &key, error.public_reason(), true)
                .await;
        env.state.observe_quorum(
            raw.quorum_group,
            raw.agent_type.as_deref().unwrap_or("generic"),
            false,
        );
        return envelope;
    }

    let label = raw
        .label
        .clone()
        .unwrap_or_else(|| label_for(&raw.prompt, idx));

    // --- (2) build the bounded live call ---------------------------------------------------------
    let call = AgentCall {
        prompt: raw.prompt.clone(),
        label: Some(label.clone()),
        phase: raw.phase.clone(),
        model: raw.model.clone(),
        effort: raw
            .effort
            .as_deref()
            .and_then(iteron_protocol::Effort::parse),
        agent_type: raw.agent_type.clone(),
        schema: raw.schema.clone(),
        cancel: env
            .state
            .quorum_token(raw.quorum_group)
            .unwrap_or_else(|| env.cancel.child_token()),
    };

    // --- (3) Governor permit — the one global slot pool, held for the whole call ----------------
    // The queued row is emitted BEFORE the permit is requested. `parallel()` marshals every
    // `agent()` call up front, so the whole fan appears at once and the run's denominator is fixed
    // from the first frame; emitting only on admission made the total climb as slots freed up.
    env.sink.emit(ProgressEvent::AgentQueued {
        index: idx,
        label: label.clone(),
        phase: raw.phase.clone(),
        model: progress_model(raw.model.as_deref()),
    });
    let queued_at = Instant::now();
    let permit = tokio::select! {
        biased;
        _ = call.cancel.cancelled() => {
            let record = Record::null(Some("quorum reached".into()));
            if env.journal.record(&key, &cachekey::agent_id(&key), record.clone()).is_err() {
                env.cancel.cancel();
                return null_envelope("journal durability failed");
            }
            if finish_task_for_record(&env, task, &record).await.is_err() {
                env.cancel.cancel();
                return null_envelope("task DAG durability failed");
            }
            emit_finished(&env, idx, label, &record, 0);
            return null_envelope("quorum reached");
        }
        permit = env.gov.acquire() => permit,
    };
    let permit = TrackedPermit::new(permit, env.available_permits.clone());
    let started = Instant::now();
    env.sink.emit(ProgressEvent::AgentStarted {
        index: idx,
        label: label.clone(),
        phase: raw.phase.clone(),
        model: progress_model(raw.model.as_deref()),
        queued_ms: queued_at.elapsed().as_millis() as u64,
        available_permits: env.available_permits.load(Ordering::Acquire),
    });

    // --- (4) run live (schema validate+retry when a schema was supplied) ------------------------
    let (record, envelope) = match &raw.schema {
        Some(schema_value) => {
            run_with_schema(&env, &call, schema_value, idx, task, speculative_siblings).await
        }
        None => run_plain(&env, &call, idx, task, speculative_siblings).await,
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    // --- (5) journal the outcome (positive AND negative — B2) -----------------------------------
    if let Err(error) = env
        .journal
        .record(&key, &cachekey::agent_id(&key), record.clone())
    {
        env.sink.emit(ProgressEvent::Log {
            message: format!("workflow: journal durability failed: {error}"),
        });
        env.cancel.cancel();
        let _ = env
            .task_dag
            .finish_task_failure(
                task,
                "journal_durability_failed",
                "journal durability failed",
            )
            .await;
        return null_envelope("journal durability failed");
    }
    if let Err(error) = finish_task_for_record(&env, task, &record).await {
        env.sink.emit(ProgressEvent::Log {
            message: format!("workflow: task DAG durability failed: {error}"),
        });
        env.cancel.cancel();
        return null_envelope("task DAG durability failed");
    }
    emit_finished(&env, idx, label, &record, duration_ms);
    env.state.observe_quorum(
        raw.quorum_group,
        raw.agent_type.as_deref().unwrap_or("generic"),
        matches!(
            &record.outcome,
            Outcome::Text { .. } | Outcome::Structured { .. }
        ),
    );
    // Quorum cancellation is evidence-driven. Keep the scarce permit until both durable stores
    // have accepted the selected terminal and `observe_quorum` has cancelled only this sibling
    // group; otherwise a queued sibling can acquire the released slot during the fsync window and
    // dispatch after the quorum was already logically satisfied.
    drop(permit);
    envelope
}

/// Register `__agent` / `__phase` / `__log` on the context's globals. Called once per run inside the
/// `AsyncContext::async_with` closure, before the prelude + script are evaluated.
pub fn install<'js>(ctx: &Ctx<'js>, env: &Arc<AgentEnv>) -> rquickjs::Result<()> {
    let globals = ctx.globals();

    // __agent — async. The closure body runs synchronously at call time (so `next_index()` yields
    // declaration order); it then returns the future rquickjs drives.
    {
        let env = env.clone();
        let f = Function::new(
            ctx.clone(),
            Async(move |arg: String| {
                let idx = env.state.next_index();
                let env = env.clone();
                async move { run_agent(env, idx, arg).await }
            }),
        )?;
        globals.set("__agent", f)?;
    }

    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |members: usize| -> u64 {
            env.state.begin_quorum(&env.cancel, members)
        })?;
        globals.set("__quorumBegin", f)?;
    }

    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |group_id: u64| {
            env.state.end_quorum(group_id);
        })?;
        globals.set("__quorumEnd", f)?;
    }

    // __phase — sync, returns the 1-based first-seen index.
    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |title: String| -> i32 {
            let Some((index, first_seen)) = env.state.phase_index(&title) else {
                return -1;
            };
            if first_seen {
                env.sink.emit(ProgressEvent::Phase { index, title });
            }
            index as i32
        })?;
        globals.set("__phase", f)?;
    }

    // __log — sync narrator.
    {
        let env = env.clone();
        let f = Function::new(
            ctx.clone(),
            move |message: String| -> rquickjs::Result<()> {
                if !env.state.admit_log_call() {
                    // Cancellation is an uncatchable QuickJS interrupt at the runtime boundary. A
                    // script cannot catch this error and continue consuming CPU with another 100k
                    // narrator calls.
                    env.cancel.cancel();
                    return Err(rquickjs::Error::new_from_js_message(
                        "workflow log",
                        "bounded narrator",
                        "workflow log-call ceiling reached",
                    ));
                }
                env.sink.emit(ProgressEvent::Log { message });
                Ok(())
            },
        )?;
        globals.set("__log", f)?;
    }

    Ok(())
}
