//! Shared machine representation contract for runtime facts and public clients.
//! This owner holds schema compatibility and bounded streaming redaction. It does not parse CLI
//! options, write stdout/stderr, bind sockets, hold an Agent or query mutable session state.

use crate::runtime::{UiEvent, WorkflowUiEvent};
use iteron_obs::{CostState, KernelTax};
use iteron_protocol::{Outcome, Phase};
use iteron_provider::EffortApplication;
use serde_json::{Value, json};
use std::io;

mod v7;
pub(crate) type V7AssistantStream = v7::AssistantStream;

/// Current one-shot stream schema. Schema 7 belongs to the separate resident contract.
pub const SCHEMA_VERSION: u32 = 8;
pub const V7_SCHEMA_VERSION: u32 = 7;
pub const DEFAULT_SCHEMA_VERSION: u32 = SCHEMA_VERSION;
pub const PREVIOUS_SCHEMA_VERSION: u32 = 5;
pub const LEGACY_SCHEMA_VERSION: u32 = 4;
pub const SUPPORTED_SCHEMA_VERSIONS: [u32; 4] = [
    LEGACY_SCHEMA_VERSION,
    PREVIOUS_SCHEMA_VERSION,
    6,
    SCHEMA_VERSION,
];
pub const EXIT_SUCCESS: u8 = 0;
/// A workflow settled, but one or more fan-out agents failed. Kept distinct from cancellation 130.
pub const EXIT_WORKFLOW_FAILED: u8 = 1;
pub const EXIT_HARNESS: u8 = 2;
pub const EXIT_BUDGET: u8 = 3;
pub const EXIT_STUCK: u8 = 4;
pub const EXIT_INTERRUPTED: u8 = 130;

#[cfg(feature = "legacy-plantcore")]
pub(crate) fn canonical_v7_event_bytes(value: &Value) -> io::Result<Vec<u8>> {
    v7::canonical_bytes(value)
}
/// A provider can split one credential-shaped token across arbitrarily many deltas. Hold the
/// unfinished token until a delimiter arrives so per-delta scrubbing cannot leak its prefix. A
/// malicious delimiter-free token is replaced at this ceiling rather than growing without bound.
pub(crate) const MAX_PENDING_STREAM_TOKEN_BYTES: usize = 16 * 1024;
/// Keep text/thinking deltas comfortably below the canonical v7 event ceiling after JSON escaping,
/// envelope fields, and redaction markers are added.
pub(crate) const MAX_STREAM_UI_DELTA_BYTES: usize = 8 * 1024;

pub(crate) fn max_stream_ui_delta_bytes() -> usize {
    iteron_tunables::param_usize(
        "cli.output.max_stream_ui_delta_bytes",
        MAX_STREAM_UI_DELTA_BYTES,
    )
    .clamp(1, MAX_STREAM_UI_DELTA_BYTES)
}

/// Stable process exit status for a terminal agent outcome. Keep this pure so tests and embedders
/// never need to invoke `process::exit`.
pub fn outcome_exit_code(outcome: &Outcome) -> u8 {
    match outcome {
        Outcome::Done | Outcome::Drained => EXIT_SUCCESS,
        Outcome::HarnessError => EXIT_HARNESS,
        Outcome::BudgetExhausted(_) => EXIT_BUDGET,
        Outcome::Stuck => EXIT_STUCK,
        Outcome::Interrupted => EXIT_INTERRUPTED,
    }
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Done => "done",
        Outcome::Drained => "drained",
        Outcome::HarnessError => "harness_error",
        Outcome::BudgetExhausted(_) => "budget_exhausted",
        Outcome::Stuck => "stuck",
        Outcome::Interrupted => "interrupted",
    }
}

fn outcome_reason(outcome: &Outcome) -> Option<&str> {
    match outcome {
        Outcome::BudgetExhausted(reason) => Some(reason),
        _ => None,
    }
}

/// The concrete operator action that clears one budget ceiling.
///
/// A bare `budget_exhausted` is indistinguishable from a hang: the run stops, nothing is broken,
/// and nothing says what would make the next submission run. `max_turns` is the worst of the five
/// because it is *cumulative for the whole session* — subagent attempts are charged to the parent
/// and resume deliberately restores the count — so an operator who reaches it has no reason to
/// suspect the ceiling is raisable at all. Every reason therefore names a remedy, and the
/// unrecognized case still says which direction to move.
pub fn budget_remedy(reason: &str) -> &'static str {
    match reason {
        "max_turns" => {
            "the turn ceiling counts the whole session, not this submission: raise it in place \
             with `/budget <turns>`, or restart with --max-turns <turns>"
        }
        "max_wall_secs" => {
            "the wall-clock ceiling bounds one submission: restart with --max-wall-secs <seconds>"
        }
        "max_usd" => "raise the spend ceiling with --max-usd <dollars>",
        "max_tokens" => "raise the aggregate token ceiling with --max-tokens <tokens>",
        "verify_attempts" => {
            "the verification retry ceiling was reached: fix the failing check, or rerun without \
             --verify"
        }
        _ => "raise the ceiling named above and submit again",
    }
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Context => "context",
        Phase::Model => "model",
        Phase::Tools => "tools",
        Phase::Verify => "verify",
        Phase::Idle => "idle",
    }
}

fn effort_application_json(application: EffortApplication) -> Value {
    match application {
        EffortApplication::Exact { requested } => json!({
            "enforcement": "exact",
            "meaning": "semantic_value_sent_without_adapter_mapping",
            "capability_proven_by_catalog": false,
            "requested": requested.label(),
            "sent": requested.label(),
        }),
        EffortApplication::Mapped { requested, sent } => json!({
            "enforcement": "mapped",
            "capability_proven_by_catalog": false,
            "requested": requested.label(),
            "sent": sent.label(),
        }),
        EffortApplication::BudgetBased {
            requested,
            budget_tokens,
        } => json!({
            "enforcement": "budget_based",
            "capability_proven_by_catalog": false,
            "requested": requested.label(),
            "budget_tokens": budget_tokens,
        }),
        EffortApplication::ToggleOnly { requested, enabled } => json!({
            "enforcement": "toggle_only",
            "capability_proven_by_catalog": false,
            "requested": requested.label(),
            "enabled": enabled,
        }),
        EffortApplication::Unsupported { requested } => json!({
            "enforcement": "unsupported",
            "capability_proven_by_catalog": false,
            "requested": requested.label(),
        }),
    }
}

fn scrub(text: &str) -> String {
    iteron_record::redact::scrub(text)
}

/// Defense in depth at the machine-output boundary. Kernel UiEvents are already scrubbed, but the
/// JSON contract must remain safe if a future producer forgets to apply the UI-seam scrubber.
fn scrub_json(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(scrub(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(scrub_json).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, scrub_json(value)))
                .collect(),
        ),
        other => other,
    }
}

fn is_token_boundary(c: char) -> bool {
    // `:` can be part of both a URL scheme and userinfo. Emitting `https:` before later deltas
    // arrive makes the URL-password scrubber unable to recognize the complete credential.
    c.is_whitespace() || matches!(c, '"' | '\'' | '=' | ',' | '(' | ')' | ';')
}

fn approval_resolution_name(resolution: crate::runtime::ApprovalResolution) -> &'static str {
    match resolution {
        crate::runtime::ApprovalResolution::Approved => "approved",
        crate::runtime::ApprovalResolution::Denied => "denied",
        crate::runtime::ApprovalResolution::Cancelled => "cancelled",
        crate::runtime::ApprovalResolution::TimedOut => "timed_out",
    }
}

/// Stateful redaction for model deltas. The ordinary scrubber is token-oriented, so invoking it on
/// each transport chunk is unsafe: `sk-ant-...` may arrive as `"sk-an"`, `"t-..."`. This buffer
/// emits only complete tokens and preserves concatenated ordinary text exactly.
#[derive(Default)]
pub(crate) struct StreamingScrubber {
    pending: String,
}

impl StreamingScrubber {
    pub(crate) fn push(&mut self, delta: &str) -> Option<String> {
        self.pending.push_str(delta);
        let split = self
            .pending
            .char_indices()
            .filter(|(_, c)| is_token_boundary(*c))
            .map(|(index, c)| index + c.len_utf8())
            .next_back();

        let mut output = split.map(|split| {
            let complete = self.pending[..split].to_string();
            self.pending.drain(..split);
            scrub(&complete)
        });
        if self.pending.len() > MAX_PENDING_STREAM_TOKEN_BYTES {
            self.pending.clear();
            output
                .get_or_insert_with(String::new)
                .push_str("[REDACTED:oversized-stream-token]");
        }
        output.filter(|value| !value.is_empty())
    }

    pub(crate) fn finish(&mut self) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        let pending = std::mem::take(&mut self.pending);
        Some(scrub(&pending))
    }
}

/// Map a kernel UI event onto the stable stream-json vocabulary. The final authoritative outcome is
/// deliberately emitted by [`final_result`] rather than parsed from `UiEvent::Done`'s debug string.
pub fn stream_event(event: UiEvent, turn: &mut u32) -> Value {
    match event {
        UiEvent::Text(delta) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "assistant_text",
            "delta": scrub(&delta),
        }),
        UiEvent::Thinking(delta) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "thinking",
            "delta": scrub(&delta),
        }),
        UiEvent::ToolStart { id, name, args } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "tool_start",
            "tool_use_id": iteron_record::redact::scrub_correlation_identifier(&id),
            "name": scrub(&name),
            "args": scrub_json(args),
        }),
        UiEvent::ToolEnd {
            id,
            ok,
            exit_code,
            output,
            diff,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "tool_end",
            "tool_use_id": iteron_record::redact::scrub_correlation_identifier(&id),
            "ok": ok,
            "exit_code": exit_code,
            "output": scrub(&output),
            "diff": scrub_json(serde_json::to_value(diff).unwrap_or(Value::Null)),
        }),
        UiEvent::Phase(phase) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "phase",
            "phase": phase_name(phase),
        }),
        UiEvent::TurnEnd {
            cost,
            usage,
            context,
            model_context_window,
            reserved_output_tokens,
            compaction_trigger_tokens,
            effort,
        } => {
            *turn = turn.saturating_add(1);
            json!({
                "schema_version": SCHEMA_VERSION,
                "type": "turn_end",
                "turn": *turn,
                "cost_usd": cost.usd(),
                "cumulative_cost_usd": cost.usd(),
                "cost_status": cost.status(),
                "cost_reason": cost.reason().map(|reason| reason.code()),
                "usage": usage,
                "cache_hit": usage.cache_hit_ratio(),
                "context": {
                    "kind": "estimate",
                    "input_tokens": context.total_tokens,
                    "system_tokens": context.system_tokens,
                    "tool_tokens": context.tool_tokens,
                    "transcript_tokens": context.transcript_tokens,
                    "framing_tokens": context.framing_tokens,
                    "components": context.components,
                    "estimator": "heuristic_bytes_per_token_3_5",
                    "model_context_window": model_context_window,
                    "reserved_output_tokens": reserved_output_tokens,
                    "compaction_trigger_tokens": compaction_trigger_tokens,
                },
                "effort": effort_application_json(effort),
            })
        }
        UiEvent::Workflow(event) => match event {
            WorkflowUiEvent::RunStarted {
                run_id,
                name,
                class,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_start",
                "workflow_run_id": scrub(&run_id),
                "name": scrub(&name),
                "class": scrub(&class),
            }),
            WorkflowUiEvent::PlanReady {
                run_id,
                tasks,
                dropped,
                duplicates_removed,
                invalid_removed,
                execution_mode,
                fan_turn_budget,
                writer_turn_reserve,
                fan_wall_secs,
                writer_wall_reserve_secs,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_plan",
                "workflow_run_id": scrub(&run_id),
                "tasks": scrub_json(serde_json::to_value(tasks).unwrap_or(Value::Null)),
                "dropped": dropped,
                "duplicates_removed": duplicates_removed,
                "invalid_removed": invalid_removed,
                "execution_mode": execution_mode,
                "budget": {
                    "fan_turns": fan_turn_budget,
                    "writer_turns_reserved": writer_turn_reserve,
                    "fan_wall_secs": fan_wall_secs,
                    "writer_wall_secs_reserved": writer_wall_reserve_secs,
                },
            }),
            WorkflowUiEvent::PhaseChanged { run_id, phase } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_phase",
                "workflow_run_id": scrub(&run_id),
                "phase": phase,
            }),
            WorkflowUiEvent::AgentStarted {
                run_id,
                agent_id,
                sub_run,
                turn_budget,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_agent_start",
                "workflow_run_id": scrub(&run_id),
                "agent_id": agent_id,
                "sub_run_id": scrub(&sub_run),
                "turn_budget": turn_budget,
            }),
            WorkflowUiEvent::AgentActivity {
                run_id,
                agent_id,
                activity,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_agent_activity",
                "workflow_run_id": scrub(&run_id),
                "agent_id": agent_id,
                "activity": scrub(&activity),
            }),
            WorkflowUiEvent::AgentFinished {
                run_id,
                agent_id,
                outcome,
                turns,
                tokens,
                tool_calls,
                elapsed_ms,
                summary_preview,
                error_preview,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_agent_end",
                "workflow_run_id": scrub(&run_id),
                "agent_id": agent_id,
                "outcome": outcome,
                "turns": turns,
                "tokens": tokens,
                "tool_calls": tool_calls,
                "elapsed_ms": elapsed_ms,
                "summary_preview": summary_preview.map(|text| scrub(&text)),
                "error_preview": error_preview.map(|text| scrub(&text)),
            }),
            WorkflowUiEvent::RunFinished {
                run_id,
                outcome,
                reason,
                elapsed_ms,
                provider_attempts,
                turns,
                tokens,
                tool_calls,
                failed_tasks,
                skipped_tasks,
            } => json!({
                "schema_version": SCHEMA_VERSION,
                "type": "workflow_end",
                "workflow_run_id": scrub(&run_id),
                "outcome": outcome,
                "reason": reason.map(|text| scrub(&text)),
                "elapsed_ms": elapsed_ms,
                "provider_attempts": provider_attempts,
                "turns": turns,
                "tokens": tokens,
                "tool_calls": tool_calls,
                "failed_tasks": failed_tasks,
                "skipped_tasks": skipped_tasks,
            }),
        },
        UiEvent::SteerApplied { count } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "steer_applied",
            "count": count,
        }),
        UiEvent::SteerSubmissionApplied { id } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "steer_submission_applied",
            "submission_id": id.0,
        }),
        UiEvent::SubmissionRejected { id, reason_code } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "submission_rejected",
            "submission_id": id.0,
            "reason_code": reason_code,
        }),
        UiEvent::ControlSubmissionApplied { id, kind } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "control_submission_applied",
            "submission_id": id.0,
            "kind": kind.as_str(),
        }),
        UiEvent::Notice(message) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "notice",
            "message": scrub(&message),
        }),
        UiEvent::ApprovalRequest {
            id,
            tool,
            capability,
            reason,
            arguments,
            workspace,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "approval_request",
            "submission_id": id.0,
            "tool": scrub(&tool),
            "capability": capability,
            "reason": scrub(&reason),
            "arguments": scrub_json(arguments),
            "workspace": scrub(&workspace),
        }),
        UiEvent::ApprovalResolved {
            id,
            resolution,
            reason_code,
            response_submission_id,
        } => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "approval_resolved",
            "submission_id": id.0,
            "resolution": approval_resolution_name(resolution),
            "reason_code": reason_code,
            "response_submission_id": response_submission_id.map(|id| id.0),
        }),
        // The old UI event contains a Debug-formatted string, which is not a stable contract.
        // Preserve the lifecycle signal; the immediately-following result object is authoritative.
        UiEvent::Done(_) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "run_done",
        }),
    }
}

pub(crate) fn stream_event_for_schema(
    event: UiEvent,
    turn: &mut u32,
    schema_version: u32,
) -> io::Result<Value> {
    let value = stream_event(event, turn);
    if schema_version == V7_SCHEMA_VERSION {
        v7::opaque_value(value)
    } else {
        project_schema(value, schema_version)
    }
}

pub(crate) fn v7_result(outcome: &iteron_protocol::PlantcoreTerminalOutcome) -> io::Result<Value> {
    v7::result_value(outcome)
}

pub(crate) fn v7_usage(usage: &iteron_protocol::TurnUsage) -> io::Result<Value> {
    v7::usage_value(usage)
}

pub(crate) fn v7_plantcore_run_admitted(
    profile_digest_sha256: iteron_protocol::HexSha256,
) -> io::Result<Value> {
    v7::opaque_value(json!({
        "type": "plantcore_run_admitted",
        "profile_digest_sha256": format!("sha256:{profile_digest_sha256}"),
    }))
}

pub(crate) fn v7_plantcore_event(event: crate::runtime::PlantcoreUiEvent) -> io::Result<Value> {
    match event {
        crate::runtime::PlantcoreUiEvent::Usage(usage) => v7_usage(&usage),
        crate::runtime::PlantcoreUiEvent::RunAdmitted {
            profile_digest_sha256,
        } => v7_plantcore_run_admitted(profile_digest_sha256),
    }
}

/// Build the metadata-only record emitted immediately before a multimodal SQ submission.
///
/// Bounds are enforced by [`input_attachment_metadata`] before this producer is reached. Keeping
/// the producer separate from [`stream_event`] avoids pretending that local input metadata is a
/// kernel `UiEvent`.
fn input_attachment_event(
    ordinal: usize,
    media_type: iteron_protocol::ImageMediaType,
    encoded_bytes: usize,
) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "type": "input_attachment",
        "ordinal": ordinal,
        "media_type": media_type.as_str(),
        "encoded_bytes": encoded_bytes,
    })
}

pub(crate) fn input_attachment_metadata(
    ordinal: usize,
    media_type: iteron_protocol::ImageMediaType,
    encoded_bytes: usize,
) -> io::Result<Value> {
    if ordinal == 0
        || ordinal > iteron_protocol::input::MAX_INPUT_IMAGES
        || encoded_bytes == 0
        || encoded_bytes > iteron_protocol::input::MAX_IMAGE_BASE64_BYTES
        || !encoded_bytes.is_multiple_of(4)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bounded input attachment metadata",
        ));
    }
    Ok(input_attachment_event(ordinal, media_type, encoded_bytes))
}

/// Build the authoritative terminal object shared by `json` and `stream-json`.
pub fn final_result(
    outcome: &Outcome,
    assistant_text: &str,
    run_id: &str,
    cost: &CostState,
    turns: u32,
    kernel_tax: KernelTax,
    error: Option<&str>,
) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "type": "result",
        "outcome": outcome_name(outcome),
        "reason": outcome_reason(outcome),
        "success": matches!(outcome, Outcome::Done | Outcome::Drained),
        "assistant_text": scrub(assistant_text),
        "run_id": scrub(run_id),
        "cost_usd": cost.usd(),
        "cost_status": cost.status(),
        "cost_reason": cost.reason().map(|reason| reason.code()),
        "turns": turns,
        "kernel_tax": kernel_tax,
        "exit_code": outcome_exit_code(outcome),
        "error": error.map(scrub),
    })
}

/// Project a current machine record onto one explicitly selected public CLI schema.
///
/// Keeping compatibility projection at the final stdout seam lets the runtime produce one current
/// vocabulary while older clients receive the exact frozen bytes they already know how to parse.
/// V5 predates source-separated context components; v4 additionally predates `kernel_tax`.
pub(crate) fn project_schema(mut value: Value, schema_version: u32) -> io::Result<Value> {
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&schema_version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported CLI output schema version {schema_version}"),
        ));
    }
    let fields = value.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "machine output record must be a JSON object",
        )
    })?;
    if schema_version < SCHEMA_VERSION
        && matches!(
            fields.get("type").and_then(Value::as_str),
            Some(
                "approval_resolved"
                    | "control_submission_applied"
                    | "steer_submission_applied"
                    | "submission_rejected"
            )
        )
    {
        return Ok(json!({
            "schema_version": schema_version,
            "type": "notice",
            "message": scrub("Submission lifecycle detail requires output schema v8."),
        }));
    }
    fields.insert("schema_version".into(), Value::from(schema_version));
    if schema_version < 6
        && fields.get("type").and_then(Value::as_str) == Some("turn_end")
        && let Some(context) = fields.get_mut("context").and_then(Value::as_object_mut)
    {
        context.remove("components");
    }
    if schema_version == LEGACY_SCHEMA_VERSION
        && fields.get("type").and_then(Value::as_str) == Some("result")
    {
        fields.remove("kernel_tax");
    }
    Ok(value)
}
