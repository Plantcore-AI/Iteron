//! The Rust host primitives behind the JS prelude: `__agent`, `__phase`, `__log`.
//!
//! `__agent` is the load-bearing bridge (proven in the B4 spike): it assigns a declaration-order
//! index synchronously, then — for a live call — acquires a [`Governor`] permit (the one global slot
//! pool), `tokio::spawn`s a SEND child running the injected [`AgentSpawner`], and awaits it (racing
//! the run's [`CancellationToken`]), resolving the JS Promise back on the runtime thread.
//!
//! Three engine-depth behaviors live here (design §2.5/§2.6 + review B2/B3):
//!   * **Journal short-circuit (B2):** on a journal hit `__agent` replays the cached OUTCOME —
//!     including `null` — BEFORE touching the Governor, budget, or lifetime cap, so
//!     `parallel(...).filter(Boolean)` is deterministic across a resume.
//!   * **Schema-forced structured output (§2.5):** when `opts.schema` is set, the model's text is
//!     parsed + validated against the JSON Schema; on failure the spawner is re-called with the
//!     errors appended, up to [`schema::RETRY_MAX`] times, then degrades to `null`.
//!   * **Cancellation (B3):** each child races the cancel token and is aborted on cancel.
//!
//! Per-run state lives in [`RunState`]/[`AgentEnv`] (owned, never a static — a `OnceLock` silently
//! no-ops on the 2nd run and masks concurrency, per the spike's watch-out).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use rquickjs::function::Async;
use rquickjs::{Ctx, Function};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::cachekey;
use crate::events::{
    PREVIEW_MAX, ProgressEvent, ProgressSink, TOOL_SUMMARY_MAX, WorkflowState, truncate_preview,
};
use crate::journal::{Journal, Outcome, Record};
use crate::schema::{self, SchemaValidator};
use crate::spawner::{AgentCall, AgentOutcome, AgentSpawner};
use core_sched::Governor;
use core_sched::backoff::{BackoffPolicy, Jitter, full_jitter};

/// Backward-compatible default aggregate ceiling. A kernel-minted [`crate::RunLimits`] may narrow
/// it, and schema retries consume it one real spawn at a time.
pub const LIFETIME_CAP: usize = 1000;

/// Fresh-per-run engine state. All fields are interior-mutable so the `Fn` host closures can share
/// one `Arc<RunState>` without a `&mut`.
pub struct RunState {
    index: AtomicUsize,
    agent_calls: AtomicUsize,
    max_agent_calls: usize,
    phases: Mutex<Vec<String>>,
    errors: AtomicUsize,
    tokens: AtomicU64,
    tool_calls: AtomicU64,
}

impl RunState {
    pub fn new(max_agent_calls: usize) -> Self {
        debug_assert!(max_agent_calls > 0);
        RunState {
            index: AtomicUsize::new(0),
            agent_calls: AtomicUsize::new(0),
            max_agent_calls,
            phases: Mutex::new(Vec::new()),
            errors: AtomicUsize::new(0),
            tokens: AtomicU64::new(0),
            tool_calls: AtomicU64::new(0),
        }
    }

    /// Fold one settled agent's outcome and metrics into the run totals. Every finish event already
    /// carries them; without this they were reported per row and never summed for the run.
    fn observe(&self, state: WorkflowState, tokens: u64, tool_calls: u64) {
        if state == WorkflowState::Error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.tokens.fetch_add(tokens, Ordering::Relaxed);
        self.tool_calls.fetch_add(tool_calls, Ordering::Relaxed);
    }

    /// `(errors, tokens, tool_calls)` accumulated across every agent this run settled (cache
    /// replays included — a replayed outcome is still part of the run's result evidence).
    pub fn totals(&self) -> (usize, u64, u64) {
        (
            self.errors.load(Ordering::Relaxed),
            self.tokens.load(Ordering::Relaxed),
            self.tool_calls.load(Ordering::Relaxed),
        )
    }

    /// 1-based declaration-order index, assigned synchronously at `__agent` call time.
    fn next_index(&self) -> usize {
        self.index.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Admit one real child spawn. Journal hits do not consume the aggregate ceiling; every schema
    /// retry does. The compare-and-update keeps concurrent callers from overshooting it.
    fn admit_agent_call(&self) -> bool {
        self.agent_calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                (calls < self.max_agent_calls).then_some(calls + 1)
            })
            .is_ok()
    }

    /// 1-based first-seen phase index.
    fn phase_index(&self, title: &str) -> usize {
        let mut phases = self.phases.lock().unwrap();
        if let Some(pos) = phases.iter().position(|p| p == title) {
            return pos + 1;
        }
        phases.push(title.to_string());
        phases.len()
    }
}

impl Default for RunState {
    fn default() -> Self {
        Self::new(LIFETIME_CAP)
    }
}

/// Everything a live `__agent` call needs, shared by `Arc` across the host closures.
pub struct AgentEnv {
    pub state: Arc<RunState>,
    pub spawner: Arc<dyn AgentSpawner>,
    pub sink: Arc<dyn ProgressSink>,
    pub gov: Governor,
    pub cancel: CancellationToken,
    pub journal: Arc<Journal>,
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
}

/// A short human label for the progress row when the caller gave none: the prompt's first words.
fn label_for(prompt: &str, idx: usize) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return format!("agent {idx}");
    }
    truncate_preview(trimmed, 40)
}

/// Keep a refused call identifiable without allowing its label to become a multi-line or terminal
/// control surface. Empty labels fall back to the same prompt-derived identity as admitted calls.
fn refusal_label(label: Option<&str>, prompt: &str, idx: usize) -> String {
    label
        .map(|label| truncate_preview(label, 40))
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
            Some(truncate_preview(&value.to_string(), PREVIEW_MAX)),
            None,
        ),
        Outcome::Text { text } => (
            WorkflowState::Done,
            Some(truncate_preview(text, PREVIEW_MAX)),
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
        last_tool_summary: record
            .last_tool_summary
            .as_deref()
            .map(|s| truncate_preview(s, TOOL_SUMMARY_MAX)),
        error,
    });
}

/// Terminalize a request-metadata refusal without acquiring a Governor permit or calling the
/// spawner. Negative outcomes remain journaled for deterministic resume. The record reflects no
/// rejected routing metadata: it carries one static bounded reason. The progress row retains the
/// separately-sanitized display label so the operator can identify which agent was refused.
fn settle_metadata_refusal(
    env: &AgentEnv,
    idx: usize,
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
        return null_envelope("journal durability failed");
    }
    emit_finished(env, idx, label, &record, 0);
    null_envelope(reason)
}

/// Spawn one SEND child, racing the cancel token. `Err` = the child was cancelled (`"stopped"`) or
/// its task failed. The Governor permit is held by the caller for the whole call.
async fn spawn_child(env: &AgentEnv, call: &AgentCall) -> Result<AgentOutcome, String> {
    if !env.state.admit_agent_call() {
        return Err(format!(
            "agent call ceiling {} reached",
            env.state.max_agent_calls
        ));
    }
    let spawner = env.spawner.clone();
    let call = call.clone();
    let mut child = tokio::spawn(async move { spawner.spawn(call).await });
    tokio::select! {
        biased;
        _ = env.cancel.cancelled() => {
            child.abort();
            Err("stopped".to_string())
        }
        res = &mut child => res.map_err(|join_error| format!("agent task failed: {join_error}")),
    }
}

/// The no-schema path: one child call -> a `Text`/`Null` record + its envelope.
async fn run_plain(env: &AgentEnv, call: &AgentCall) -> (Record, String) {
    match spawn_child(env, call).await {
        Ok(AgentOutcome::Text {
            text,
            tokens,
            tool_calls,
            last_tool_summary,
        }) => {
            let record = Record::text(text.clone(), tokens, tool_calls, last_tool_summary);
            let envelope = text_envelope(&text);
            (record, envelope)
        }
        Ok(AgentOutcome::Null { reason }) => {
            let envelope = null_envelope(reason.as_deref().unwrap_or("null"));
            (Record::null(reason), envelope)
        }
        Err(reason) => {
            let envelope = null_envelope(&reason);
            (Record::null(Some(reason)), envelope)
        }
    }
}

/// The schema-forced path (design §2.5): parse+validate the output; on failure re-call the spawner
/// with the errors appended, up to `RETRY_MAX` times (spaced by full-jitter backoff); return the
/// validated object as a `Structured` record, or `Null` on exhaustion / a degraded child.
async fn run_with_schema(
    env: &AgentEnv,
    base_call: &AgentCall,
    schema_value: &Value,
    idx: usize,
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

    // Tiny backoff so 5 retries stay sub-100ms; jitter is timing, not a recorded decision (ADR-006).
    let policy = BackoffPolicy {
        base_ms: 2,
        cap_ms: 20,
        max_attempts: schema::RETRY_MAX,
    };
    let mut jitter = Jitter::new();
    let mut last_errors: Vec<String> = Vec::new();

    for attempt in 0..schema::RETRY_MAX {
        let mut call = base_call.clone();
        if attempt > 0 {
            call.prompt = schema::augment_prompt(&base_call.prompt, &last_errors);
            let delay = full_jitter(&policy, attempt - 1, jitter.next01());
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        match spawn_child(env, &call).await {
            Ok(AgentOutcome::Text {
                text,
                tokens,
                tool_calls,
                ..
            }) => match schema::parse_json(&text) {
                Ok(value) => match validator.validate(&value) {
                    Ok(()) => {
                        let record = Record::structured(value.clone(), tokens, tool_calls);
                        let envelope = structured_envelope(&value);
                        return (record, envelope);
                    }
                    Err(errors) => last_errors = errors,
                },
                Err(parse_error) => last_errors = vec![parse_error],
            },
            // A degraded child or a cancel is terminal: no point retrying a deterministic null.
            Ok(AgentOutcome::Null { reason }) => {
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
        schema::RETRY_MAX
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
        Err(_) => return null_envelope("malformed agent() call"),
    };

    // Validate routing metadata before catalog lookup, rollout creation, provider dispatch, or a
    // Governor permit. The error type contains no caller text, so the same static reason is safe in
    // the envelope, progress row, and durable negative journal record.
    let metadata = AgentCall::validate_agent_type(raw.agent_type.as_deref())
        .and_then(|()| AgentCall::validate_model(raw.model.as_deref()));

    // --- content key over the CALLER's raw input (deterministic; §2.6) --------------------------
    let key = match metadata {
        Ok(()) => cachekey::agent_key(
            &raw.prompt,
            raw.label.as_deref(),
            raw.phase.as_deref(),
            raw.schema.as_ref(),
            raw.model.as_deref(),
            raw.effort.as_deref(),
            raw.agent_type.as_deref(),
        ),
        Err(error) => cachekey::rejected_agent_key(&arg, error.code()),
    };

    // --- (1) JOURNAL HIT — before Governor / budget / lifetime cap (B2 invariant) ---------------
    if let Some(record) = env.journal.get(&key) {
        if let Err(error) = metadata {
            // Ignore the stored prose for a rejected request. Core wrote the same static outcome,
            // but reconstructing it from the validator also stays safe if a journal was replaced.
            let label = refusal_label(raw.label.as_deref(), &raw.prompt, idx);
            return settle_metadata_refusal(&env, idx, label, &key, error.public_reason(), false);
        }
        let label = raw
            .label
            .clone()
            .unwrap_or_else(|| label_for(&raw.prompt, idx));
        env.sink.emit(ProgressEvent::AgentStarted {
            index: idx,
            label: label.clone(),
            phase: raw.phase.clone(),
            model: progress_model(raw.model.as_deref()),
        });
        emit_finished(&env, idx, label, &record, 0);
        return envelope_for(&record);
    }

    if let Err(error) = metadata {
        let label = refusal_label(raw.label.as_deref(), &raw.prompt, idx);
        return settle_metadata_refusal(&env, idx, label, &key, error.public_reason(), true);
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
        effort: raw.effort.as_deref().and_then(core_protocol::Effort::parse),
        agent_type: raw.agent_type.clone(),
        schema: raw.schema.clone(),
        cancel: env.cancel.clone(),
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
    let permit = env.gov.acquire().await;
    let started = Instant::now();
    env.sink.emit(ProgressEvent::AgentStarted {
        index: idx,
        label: label.clone(),
        phase: raw.phase.clone(),
        model: progress_model(raw.model.as_deref()),
    });

    // --- (4) run live (schema validate+retry when a schema was supplied) ------------------------
    let (record, envelope) = match &raw.schema {
        Some(schema_value) => run_with_schema(&env, &call, schema_value, idx).await,
        None => run_plain(&env, &call).await,
    };
    drop(permit);
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
        return null_envelope("journal durability failed");
    }
    emit_finished(&env, idx, label, &record, duration_ms);
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

    // __phase — sync, returns the 1-based first-seen index.
    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |title: String| -> i32 {
            let index = env.state.phase_index(&title);
            env.sink.emit(ProgressEvent::Phase { index, title });
            index as i32
        })?;
        globals.set("__phase", f)?;
    }

    // __log — sync narrator.
    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |message: String| {
            env.sink.emit(ProgressEvent::Log { message });
        })?;
        globals.set("__log", f)?;
    }

    Ok(())
}
