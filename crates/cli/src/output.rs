//! Stable one-shot output contracts.
//!
//! Every format consumes frontend `UiEvent`s; the kernel never writes model content directly.
//! Human `text` remains streaming but passes through one bounded cross-delta scrubber:
//! - `json` emits exactly one final result object;
//! - `stream-json` emits one JSON object per UI event, followed by the same final result object.
//!
//! `schema_version` versions this CLI contract independently from Rust enum/debug formatting.

use clap::ValueEnum;
use core_kernel::{UiEvent, WorkflowUiEvent};
use core_obs::CostState;
use core_protocol::{Outcome, Phase};
use core_provider::EffortApplication;
use serde_json::{Value, json};
use std::io::{self, Write};

pub const SCHEMA_VERSION: u32 = 3;
pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_HARNESS: u8 = 2;
pub const EXIT_BUDGET: u8 = 3;
pub const EXIT_STUCK: u8 = 4;
pub const EXIT_INTERRUPTED: u8 = 130;
/// A provider can split one credential-shaped token across arbitrarily many deltas. Hold the
/// unfinished token until a delimiter arrives so per-delta scrubbing cannot leak its prefix. A
/// malicious delimiter-free token is replaced at this ceiling rather than growing without bound.
const MAX_PENDING_STREAM_TOKEN_BYTES: usize = 16 * 1024;

/// The stdout contract for a one-shot run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Existing human-readable behavior: assistant text streams directly to stdout.
    Text,
    /// One final JSON object on stdout.
    Json,
    /// Stable JSONL events, followed by a final result object.
    StreamJson,
}

impl OutputFormat {
    pub fn is_machine(self) -> bool {
        !matches!(self, Self::Text)
    }
}

/// Stable process exit status for a terminal agent outcome. Keep this pure so tests and embedders
/// never need to invoke `process::exit`.
pub fn outcome_exit_code(outcome: &Outcome) -> u8 {
    match outcome {
        Outcome::Done => EXIT_SUCCESS,
        Outcome::HarnessError => EXIT_HARNESS,
        Outcome::BudgetExhausted(_) => EXIT_BUDGET,
        Outcome::Stuck => EXIT_STUCK,
        Outcome::Interrupted => EXIT_INTERRUPTED,
    }
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Done => "done",
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
    core_record::redact::scrub(text)
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
    c.is_whitespace() || matches!(c, '"' | '\'' | '=' | ':' | ',' | '(' | ')' | ';')
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
            "tool_use_id": scrub(&id),
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
            "tool_use_id": scrub(&id),
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
        // The old UI event contains a Debug-formatted string, which is not a stable contract.
        // Preserve the lifecycle signal; the immediately-following result object is authoritative.
        UiEvent::Done(_) => json!({
            "schema_version": SCHEMA_VERSION,
            "type": "run_done",
        }),
    }
}

/// Build the authoritative terminal object shared by `json` and `stream-json`.
pub fn final_result(
    outcome: &Outcome,
    assistant_text: &str,
    run_id: &str,
    cost: &CostState,
    turns: u32,
    error: Option<&str>,
) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "type": "result",
        "outcome": outcome_name(outcome),
        "reason": outcome_reason(outcome),
        "success": matches!(outcome, Outcome::Done),
        "assistant_text": scrub(assistant_text),
        "run_id": scrub(run_id),
        "cost_usd": cost.usd(),
        "cost_status": cost.status(),
        "cost_reason": cost.reason().map(|reason| reason.code()),
        "turns": turns,
        "exit_code": outcome_exit_code(outcome),
        "error": error.map(scrub),
    })
}

fn write_json_line(mut writer: impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Stateful stdout writer for a single one-shot invocation.
pub struct Emitter {
    format: OutputFormat,
    stream_turn: u32,
    assistant_scrubber: StreamingScrubber,
    thinking_scrubber: StreamingScrubber,
    text_line_open: bool,
}

impl Emitter {
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            stream_turn: 0,
            assistant_scrubber: StreamingScrubber::default(),
            thinking_scrubber: StreamingScrubber::default(),
            text_line_open: false,
        }
    }

    fn write_text_delta(&mut self, delta: &str) -> io::Result<()> {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(delta.as_bytes())?;
        stdout.flush()?;
        self.text_line_open = true;
        Ok(())
    }

    fn flush_text_output(&mut self, end_line: bool) -> io::Result<()> {
        if let Some(delta) = self.assistant_scrubber.finish() {
            self.write_text_delta(&delta)?;
        }
        if end_line && self.text_line_open {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            self.text_line_open = false;
        }
        Ok(())
    }

    fn write_stream_event(&mut self, event: UiEvent) -> io::Result<()> {
        let value = stream_event(event, &mut self.stream_turn);
        write_json_line(std::io::stdout().lock(), &value)
    }

    fn flush_stream_text(&mut self) -> io::Result<()> {
        if let Some(delta) = self.assistant_scrubber.finish() {
            self.write_stream_event(UiEvent::Text(delta))?;
        }
        if let Some(delta) = self.thinking_scrubber.finish() {
            self.write_stream_event(UiEvent::Thinking(delta))?;
        }
        Ok(())
    }

    /// Consume an event. JSON mode drains without emitting so the kernel's unbounded UI channel
    /// cannot grow with the run; stream-json writes and flushes one JSON line immediately.
    pub fn event(&mut self, event: UiEvent) -> io::Result<()> {
        match self.format {
            OutputFormat::Text => match event {
                UiEvent::Text(delta) => {
                    if let Some(delta) = self.assistant_scrubber.push(&delta) {
                        self.write_text_delta(&delta)?;
                    }
                }
                UiEvent::TurnEnd { .. } | UiEvent::Done(_) => {
                    self.flush_text_output(true)?;
                }
                _ => {}
            },
            OutputFormat::StreamJson => match event {
                UiEvent::Text(delta) => {
                    if let Some(delta) = self.assistant_scrubber.push(&delta) {
                        self.write_stream_event(UiEvent::Text(delta))?;
                    }
                }
                UiEvent::Thinking(delta) => {
                    if let Some(delta) = self.thinking_scrubber.push(&delta) {
                        self.write_stream_event(UiEvent::Thinking(delta))?;
                    }
                }
                done @ UiEvent::Done(_) => {
                    self.flush_stream_text()?;
                    self.write_stream_event(done)?;
                }
                other => self.write_stream_event(other)?,
            },
            OutputFormat::Json => {}
        }
        Ok(())
    }

    pub fn result(&mut self, value: &Value) -> io::Result<()> {
        match self.format {
            OutputFormat::Text => {
                // Harness failures need not emit TurnEnd/Done, so never strand a safe tail.
                self.flush_text_output(true)?;
            }
            OutputFormat::StreamJson => {
                // Harness failures need not emit UiEvent::Done, so the result boundary is the
                // final mandatory flush for any held partial token.
                self.flush_stream_text()?;
            }
            OutputFormat::Json => {}
        }
        if self.format.is_machine() {
            write_json_line(std::io::stdout().lock(), value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_cost(microusd: u64) -> CostState {
        CostState::Known {
            amount_microusd: microusd,
            rate_card_digest: "sha256:test-rate-card".into(),
        }
    }
    use core_kernel::{
        WorkflowAgentOutcomeUi, WorkflowExecutionModeUi, WorkflowPhaseUi, WorkflowRunOutcomeUi,
        WorkflowTaskUi,
    };
    use core_protocol::{Capability, SubmissionId};

    #[test]
    fn outcome_exit_codes_are_stable() {
        assert_eq!(outcome_exit_code(&Outcome::Done), 0);
        assert_eq!(outcome_exit_code(&Outcome::HarnessError), 2);
        assert_eq!(outcome_exit_code(&Outcome::BudgetExhausted("max_turns")), 3);
        assert_eq!(outcome_exit_code(&Outcome::Stuck), 4);
        assert_eq!(outcome_exit_code(&Outcome::Interrupted), 130);
    }

    #[test]
    fn output_format_names_are_stable() {
        assert_eq!(
            OutputFormat::from_str("text", false).unwrap(),
            OutputFormat::Text
        );
        assert_eq!(
            OutputFormat::from_str("json", false).unwrap(),
            OutputFormat::Json
        );
        assert_eq!(
            OutputFormat::from_str("stream-json", false).unwrap(),
            OutputFormat::StreamJson
        );
        assert!(OutputFormat::from_str("jsonl", false).is_err());
    }

    #[test]
    fn final_result_has_the_machine_contract_fields() {
        let value = final_result(
            &Outcome::Done,
            "fixed it",
            "run-1",
            &known_cost(125_000),
            3,
            None,
        );
        assert_eq!(value["schema_version"], 3);
        assert_eq!(value["type"], "result");
        assert_eq!(value["outcome"], "done");
        assert_eq!(value["success"], true);
        assert_eq!(value["assistant_text"], "fixed it");
        assert_eq!(value["run_id"], "run-1");
        assert_eq!(value["cost_usd"], 0.125);
        assert_eq!(value["turns"], 3);
        assert_eq!(value["exit_code"], 0);
        assert!(value["reason"].is_null());
        assert!(value["error"].is_null());
    }

    #[test]
    fn unknown_cost_is_null_and_typed_in_result_and_turn_end() {
        let unknown = CostState::Unknown {
            reason: core_obs::CostUnknownReason::NoVerifiedRateCard,
        };
        let result = final_result(&Outcome::Done, "done", "run-unpriced", &unknown, 1, None);
        assert_eq!(result["schema_version"], 3);
        assert_eq!(result["cost_usd"], Value::Null);
        assert_eq!(result["cost_status"], "unknown");
        assert_eq!(result["cost_reason"], "no_verified_rate_card");

        let mut turn = 0;
        let event = stream_event(
            UiEvent::TurnEnd {
                cost: unknown,
                usage: core_protocol::Usage::default(),
                context: core_ctx::ContextEstimate {
                    system_tokens: 0,
                    tool_tokens: 0,
                    transcript_tokens: 0,
                    framing_tokens: 0,
                    total_tokens: 0,
                    provenance: core_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                },
                model_context_window: None,
                reserved_output_tokens: 8_192,
                compaction_trigger_tokens: 120_000,
                effort: EffortApplication::Unsupported {
                    requested: core_protocol::ReasoningEffort::Medium,
                },
            },
            &mut turn,
        );
        assert_eq!(event["schema_version"], 3);
        assert_eq!(event["cost_usd"], Value::Null);
        assert_eq!(event["cumulative_cost_usd"], Value::Null);
        assert_eq!(event["cost_status"], "unknown");
        assert_eq!(event["cost_reason"], "no_verified_rate_card");
    }

    #[test]
    fn budget_result_is_unsuccessful_and_carries_reason() {
        let value = final_result(
            &Outcome::BudgetExhausted("max_usd"),
            "",
            "run-2",
            &CostState::Unknown {
                reason: core_obs::CostUnknownReason::NoVerifiedRateCard,
            },
            8,
            None,
        );
        assert_eq!(value["outcome"], "budget_exhausted");
        assert_eq!(value["reason"], "max_usd");
        assert_eq!(value["success"], false);
        assert_eq!(value["exit_code"], 3);
    }

    #[test]
    fn stream_events_have_stable_names_and_correlations() {
        let mut turn = 0;
        let start = stream_event(
            UiEvent::ToolStart {
                id: "tool-1".into(),
                name: "read_file".into(),
                args: json!({"path": "a.rs"}),
            },
            &mut turn,
        );
        assert_eq!(start["type"], "tool_start");
        assert_eq!(start["tool_use_id"], "tool-1");
        assert_eq!(start["args"]["path"], "a.rs");

        let end = stream_event(
            UiEvent::ToolEnd {
                id: "tool-1".into(),
                ok: true,
                exit_code: None,
                output: "ok".into(),
                diff: None,
            },
            &mut turn,
        );
        assert_eq!(end["type"], "tool_end");
        assert_eq!(end["tool_use_id"], "tool-1");

        let turn_end = stream_event(
            UiEvent::TurnEnd {
                cost: known_cost(10_000),
                usage: core_protocol::Usage {
                    input: 50,
                    cache_read: 50,
                    ..core_protocol::Usage::default()
                },
                context: core_ctx::ContextEstimate {
                    system_tokens: 10,
                    tool_tokens: 20,
                    transcript_tokens: 30,
                    framing_tokens: 4,
                    total_tokens: 64,
                    provenance: core_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                },
                model_context_window: None,
                reserved_output_tokens: 8_192,
                compaction_trigger_tokens: 120_000,
                effort: EffortApplication::Exact {
                    requested: core_protocol::ReasoningEffort::Medium,
                },
            },
            &mut turn,
        );
        assert_eq!(turn_end["type"], "turn_end");
        assert_eq!(turn_end["turn"], 1);
        assert_eq!(turn_end["cost_usd"], 0.01);
        assert_eq!(turn_end["cumulative_cost_usd"], 0.01);
        assert_eq!(turn_end["cache_hit"], 0.5);
        assert_eq!(turn_end["context"]["input_tokens"], 64);
        assert_eq!(turn_end["context"]["model_context_window"], Value::Null);
        assert_eq!(turn_end["context"]["reserved_output_tokens"], 8_192);
        assert_eq!(turn_end["effort"]["enforcement"], "exact");

        let approval = stream_event(
            UiEvent::ApprovalRequest {
                id: SubmissionId(7),
                tool: "bash".into(),
                capability: Capability::CodeExecuting,
                reason: "approve?".into(),
                arguments: serde_json::json!({"command": "cargo test"}),
                workspace: "/tmp/project".into(),
            },
            &mut turn,
        );
        assert_eq!(approval["submission_id"], 7);
        assert_eq!(approval["capability"], "code_executing");
        assert_eq!(approval["arguments"]["command"], "cargo test");
        assert_eq!(approval["workspace"], "/tmp/project");
    }

    #[test]
    fn workflow_stream_events_keep_ids_state_and_metrics() {
        let mut turn = 0;
        let run_id = "workflow-3";
        let plan = stream_event(
            UiEvent::Workflow(WorkflowUiEvent::PlanReady {
                run_id: run_id.into(),
                tasks: vec![WorkflowTaskUi {
                    id: 0,
                    label: "inspect runtime".into(),
                }],
                dropped: 2,
                duplicates_removed: 1,
                invalid_removed: 0,
                execution_mode: WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 8,
                writer_turn_reserve: 24,
                fan_wall_secs: 120,
                writer_wall_reserve_secs: 240,
            }),
            &mut turn,
        );
        assert_eq!(plan["type"], "workflow_plan");
        assert_eq!(plan["workflow_run_id"], run_id);
        assert_eq!(plan["tasks"][0]["id"], 0);
        assert_eq!(plan["dropped"], 2);

        let phase = stream_event(
            UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                run_id: run_id.into(),
                phase: WorkflowPhaseUi::Exploring,
            }),
            &mut turn,
        );
        assert_eq!(phase["phase"], "exploring");

        let end = stream_event(
            UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                run_id: run_id.into(),
                agent_id: 0,
                outcome: WorkflowAgentOutcomeUi::Done,
                turns: 3,
                tokens: 1_234,
                tool_calls: 5,
                elapsed_ms: 900,
                summary_preview: Some("found runtime ownership".into()),
                error_preview: None,
            }),
            &mut turn,
        );
        assert_eq!(end["type"], "workflow_agent_end");
        assert_eq!(end["workflow_run_id"], run_id);
        assert_eq!(end["outcome"], "done");
        assert_eq!(end["tokens"], 1_234);

        let finished = stream_event(
            UiEvent::Workflow(WorkflowUiEvent::RunFinished {
                run_id: run_id.into(),
                outcome: WorkflowRunOutcomeUi::Done,
                reason: None,
                elapsed_ms: 1_200,
                provider_attempts: 4,
                turns: 4,
                tokens: 2_000,
                tool_calls: 5,
                failed_tasks: 0,
                skipped_tasks: 0,
            }),
            &mut turn,
        );
        assert_eq!(finished["type"], "workflow_end");
        assert_eq!(finished["outcome"], "done");

        let steered = stream_event(UiEvent::SteerApplied { count: 2 }, &mut turn);
        assert_eq!(steered["type"], "steer_applied");
        assert_eq!(steered["count"], 2);
    }

    #[test]
    fn machine_boundary_rescrubs_events_and_terminal_errors() {
        let secret = "sk-\
ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let mut turn = 0;
        let notice = stream_event(
            UiEvent::Notice(format!("provider body: {secret}")),
            &mut turn,
        );
        let tool_end = stream_event(
            UiEvent::ToolEnd {
                id: "tool-1".into(),
                ok: false,
                exit_code: None,
                output: format!("failed with {secret}"),
                diff: None,
            },
            &mut turn,
        );
        let result = final_result(
            &Outcome::HarnessError,
            &format!("assistant repeated {secret}"),
            "run-3",
            &CostState::Zero,
            0,
            Some(&format!("provider response: {secret}")),
        );
        let workflow = stream_event(
            UiEvent::Workflow(WorkflowUiEvent::PlanReady {
                run_id: "workflow-secret".into(),
                tasks: vec![WorkflowTaskUi {
                    id: 0,
                    label: format!("inspect {secret}"),
                }],
                dropped: 0,
                duplicates_removed: 0,
                invalid_removed: 0,
                execution_mode: WorkflowExecutionModeUi::Sequential,
                fan_turn_budget: 4,
                writer_turn_reserve: 20,
                fan_wall_secs: 60,
                writer_wall_reserve_secs: 120,
            }),
            &mut turn,
        );
        for value in [notice, tool_end, workflow, result] {
            let encoded = serde_json::to_string(&value).unwrap();
            assert!(
                !encoded.contains(secret),
                "secret crossed machine output: {encoded}"
            );
            assert!(encoded.contains("[REDACTED"));
        }
    }

    #[test]
    fn streaming_scrubber_holds_a_secret_split_across_deltas() {
        let mut stream = StreamingScrubber::default();
        assert!(stream.push("answer sk-ant-api03-AbCd").is_some());
        assert!(stream.push("EfGhIjKlMnOpQrStUvWx").is_none());
        let tail = stream.push(" done").expect("delimiter completes the token");
        assert!(!tail.contains("AbCdEfGhIjKlMnOpQrStUvWx"));
        assert!(tail.contains("[REDACTED"));
        assert_eq!(stream.finish(), Some("done".into()));
    }

    #[test]
    fn streaming_scrubber_bounds_a_delimiter_free_adversarial_token() {
        let mut stream = StreamingScrubber::default();
        let oversized = "A".repeat(MAX_PENDING_STREAM_TOKEN_BYTES + 1);
        let output = stream
            .push(&oversized)
            .expect("oversized token is replaced");
        assert_eq!(output, "[REDACTED:oversized-stream-token]");
        assert!(stream.finish().is_none());
    }

    #[test]
    fn json_line_is_one_object_and_newline() {
        let mut bytes = Vec::new();
        write_json_line(&mut bytes, &json!({"type": "result"})).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let lines: Vec<_> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 1);
        let parsed: Value = serde_json::from_slice(lines[0]).unwrap();
        assert_eq!(parsed["type"], "result");
    }
}
