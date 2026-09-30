//! CLI output adapter. The shared machine contract lives in `machine_projection`; this owner
//! handles selected stdout format, physical writes/flushes and bounded stderr notices.

use crate::runtime::UiEvent;
use clap::ValueEnum;
use serde_json::Value;
use std::io::{self, Write};

pub use crate::machine_projection::{
    DEFAULT_SCHEMA_VERSION, EXIT_HARNESS, EXIT_INTERRUPTED, EXIT_SUCCESS, EXIT_WORKFLOW_FAILED,
    SUPPORTED_SCHEMA_VERSIONS, budget_remedy, final_result, outcome_exit_code,
};
use crate::machine_projection::{
    LEGACY_SCHEMA_VERSION, StreamingScrubber, input_attachment_metadata, project_schema,
    stream_event,
};
#[cfg(test)]
use crate::machine_projection::{
    MAX_PENDING_STREAM_TOKEN_BYTES, PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION,
    stream_event_for_schema,
};
#[cfg(test)]
use crate::runtime::WorkflowUiEvent;
#[cfg(test)]
use iteron_obs::{CostState, KernelTax};
#[cfg(test)]
use iteron_protocol::{Outcome, Phase};
#[cfg(test)]
use iteron_provider::EffortApplication;
#[cfg(test)]
use serde_json::json;

const MAX_STDERR_NOTICE_BYTES: usize = 4 * 1024;

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

fn input_attachment_record(
    format: OutputFormat,
    ordinal: usize,
    media_type: iteron_protocol::ImageMediaType,
    encoded_bytes: usize,
) -> io::Result<Option<Value>> {
    if format != OutputFormat::StreamJson {
        return Ok(None);
    }
    Ok(Some(input_attachment_metadata(
        ordinal,
        media_type,
        encoded_bytes,
    )?))
}

fn write_json_line(mut writer: impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn display_notice_on_stderr(message: &str) {
    let message = iteron_protocol::text::head(
        &iteron_record::redact::scrub(message),
        iteron_tunables::param_integer(
            "cli.output.max_stderr_notice_bytes",
            MAX_STDERR_NOTICE_BYTES,
        ),
    );
    // Notices are observational. A closed stderr must not suppress the final JSON result or alter
    // provider dispatch; stdout failures remain separately tracked by the emitter contract.
    let _ = writeln!(std::io::stderr().lock(), "notice: {message}");
}

/// Stateful stdout writer for a single one-shot invocation.
pub struct Emitter {
    format: OutputFormat,
    schema_version: u32,
    stream_turn: u32,
    assistant_scrubber: StreamingScrubber,
    thinking_scrubber: StreamingScrubber,
    text_line_open: bool,
}

impl Emitter {
    pub fn new(format: OutputFormat, schema_version: u32) -> Self {
        Self {
            format,
            schema_version,
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
        let value = project_schema(value, self.schema_version)?;
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

    /// Emit metadata for one validated input image before its SQ submission.
    ///
    /// `ordinal` is one-based. Human `text` and terminal-only `json` formats intentionally do
    /// nothing, preserving their existing bytes. The API cannot receive image data or a path.
    pub fn input_attachment(
        &mut self,
        ordinal: usize,
        media_type: iteron_protocol::ImageMediaType,
        encoded_bytes: usize,
    ) -> io::Result<()> {
        // v4 predates this record type. Its frozen stream is preserved byte-for-byte; the image
        // remains part of the admitted task, but no unknown metadata frame is invented for v4.
        if self.schema_version == LEGACY_SCHEMA_VERSION {
            return Ok(());
        }
        if let Some(value) =
            input_attachment_record(self.format, ordinal, media_type, encoded_bytes)?
        {
            let value = project_schema(value, self.schema_version)?;
            write_json_line(std::io::stdout().lock(), &value)?;
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
                UiEvent::Notice(message) => display_notice_on_stderr(&message),
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
            OutputFormat::Json => {
                if let UiEvent::Notice(message) = event {
                    display_notice_on_stderr(&message);
                }
            }
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
            let value = project_schema(value.clone(), self.schema_version)?;
            write_json_line(std::io::stdout().lock(), &value)?;
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
    use crate::runtime::{
        ApprovalResolution, WorkflowAgentOutcomeUi, WorkflowExecutionModeUi, WorkflowPhaseUi,
        WorkflowRunOutcomeUi, WorkflowTaskUi,
    };
    use iteron_protocol::{Capability, DiffLine, DiffTag, FileDiff, Hunk, SubmissionId};

    #[test]
    fn outcome_exit_codes_are_stable() {
        assert_eq!(outcome_exit_code(&Outcome::Done), 0);
        assert_eq!(outcome_exit_code(&Outcome::Drained), 0);
        assert_eq!(outcome_exit_code(&Outcome::HarnessError), 2);
        assert_eq!(outcome_exit_code(&Outcome::BudgetExhausted("max_turns")), 3);
        assert_eq!(outcome_exit_code(&Outcome::Stuck), 4);
        assert_eq!(outcome_exit_code(&Outcome::Interrupted), 130);
    }

    /// Every budget stop used to print only its reason token, which told an operator that the run
    /// had ended but never that anything could be done about it.
    #[test]
    fn every_budget_stop_names_a_concrete_remedy() {
        for reason in [
            "max_turns",
            "max_wall_secs",
            "max_usd",
            "max_tokens",
            "verify_attempts",
        ] {
            let remedy = budget_remedy(reason);
            assert!(!remedy.is_empty(), "{reason} has no remedy");
            assert_ne!(
                remedy,
                budget_remedy("something-new"),
                "{reason} is generic"
            );
        }
        assert!(
            budget_remedy("max_turns").contains("/budget"),
            "the cumulative turn ceiling must name the in-session command that raises it"
        );
        assert!(
            budget_remedy("max_wall_secs").contains("--max-wall-secs"),
            "the wall-clock ceiling must name the flag that sets it"
        );
        assert!(
            !budget_remedy("unrecognized").is_empty(),
            "an unknown reason still points the operator somewhere"
        );
    }

    #[test]
    fn drained_is_a_versioned_clean_checkpoint_terminal() {
        let value = final_result(
            &Outcome::Drained,
            "state checkpointed",
            "run-drained",
            &CostState::Zero,
            1,
            KernelTax::default(),
            None,
        );
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["outcome"], "drained");
        assert_eq!(value["success"], true);
        assert_eq!(value["exit_code"], EXIT_SUCCESS);
        assert_eq!(
            value,
            serde_json::from_str::<Value>(include_str!(
                "../tests/golden/one_shot_json_drained_v8.json"
            ))
            .unwrap(),
            "the complete drained machine terminal is a frozen schema-v8 contract"
        );
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
            KernelTax::default(),
            None,
        );
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
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
    fn explicit_v4_projection_preserves_the_frozen_terminal_bytes() {
        let current = final_result(
            &Outcome::Done,
            "golden reply",
            "<RUN_ID>",
            &CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
            },
            1,
            KernelTax::default(),
            None,
        );
        let legacy = project_schema(current, LEGACY_SCHEMA_VERSION).unwrap();
        assert_eq!(
            legacy,
            serde_json::from_str::<Value>(include_str!(
                "../tests/golden/one_shot_json_success_v4.json"
            ))
            .unwrap()
        );
        assert!(legacy.get("kernel_tax").is_none());
    }

    #[test]
    fn unknown_cost_is_null_and_typed_in_result_and_turn_end() {
        let unknown = CostState::Unknown {
            reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
        };
        let result = final_result(
            &Outcome::Done,
            "done",
            "run-unpriced",
            &unknown,
            1,
            KernelTax::default(),
            None,
        );
        assert_eq!(result["schema_version"], SCHEMA_VERSION);
        assert_eq!(result["cost_usd"], Value::Null);
        assert_eq!(result["cost_status"], "unknown");
        assert_eq!(result["cost_reason"], "no_verified_rate_card");

        let mut turn = 0;
        let event = stream_event(
            UiEvent::TurnEnd {
                cost: unknown,
                usage: iteron_protocol::Usage::default(),
                context: iteron_ctx::ContextEstimate {
                    system_tokens: 0,
                    tool_tokens: 0,
                    conversation_tokens: 0,
                    tool_result_tokens: 0,
                    lsp_result_tokens: 0,
                    transcript_tokens: 0,
                    framing_tokens: 0,
                    total_tokens: 0,
                    provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                    components: Some(iteron_ctx::ContextComponentUsage::default()),
                },
                model_context_window: None,
                reserved_output_tokens: 8_192,
                compaction_trigger_tokens: 120_000,
                effort: EffortApplication::Unsupported {
                    requested: iteron_protocol::ReasoningEffort::Medium,
                },
            },
            &mut turn,
        );
        assert_eq!(event["schema_version"], SCHEMA_VERSION);
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
                reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
            },
            8,
            KernelTax::default(),
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
                usage: iteron_protocol::Usage {
                    input: 50,
                    cache_read: 50,
                    ..iteron_protocol::Usage::default()
                },
                context: iteron_ctx::ContextEstimate {
                    system_tokens: 10,
                    tool_tokens: 20,
                    conversation_tokens: 30,
                    tool_result_tokens: 0,
                    lsp_result_tokens: 0,
                    transcript_tokens: 30,
                    framing_tokens: 4,
                    total_tokens: 64,
                    provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                    components: Some(iteron_ctx::ContextComponentUsage {
                        stable_prefix_tokens: 1,
                        instruction_tokens: 2,
                        task_context_tokens: 3,
                        memory_tokens: 4,
                        transcript_tokens: 5,
                        attachment_tokens: 6,
                        tool_schema_tokens: 7,
                        tool_result_tokens: 8,
                        lsp_result_tokens: 9,
                    }),
                },
                model_context_window: None,
                reserved_output_tokens: 8_192,
                compaction_trigger_tokens: 120_000,
                effort: EffortApplication::Exact {
                    requested: iteron_protocol::ReasoningEffort::Medium,
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
        assert_eq!(turn_end["context"]["components"]["memory_tokens"], 4);
        assert_eq!(turn_end["effort"]["enforcement"], "exact");

        let previous = project_schema(turn_end.clone(), PREVIOUS_SCHEMA_VERSION).unwrap();
        assert!(previous["context"].get("components").is_none());
        assert_eq!(previous["schema_version"], PREVIOUS_SCHEMA_VERSION);

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
        let resolution = stream_event(
            UiEvent::ApprovalResolved {
                id: SubmissionId(7),
                resolution: ApprovalResolution::Approved,
                reason_code: "operator_approved",
                response_submission_id: Some(SubmissionId(19)),
            },
            &mut turn,
        );
        assert_eq!(resolution["type"], "approval_resolved");
        assert_eq!(resolution["submission_id"], 7);
        assert_eq!(resolution["resolution"], "approved");
        assert_eq!(resolution["reason_code"], "operator_approved");
        assert_eq!(resolution["response_submission_id"], 19);
        let stale = stream_event(
            UiEvent::SubmissionRejected {
                id: SubmissionId(20),
                reason_code: "turn_mismatch_or_terminal",
            },
            &mut turn,
        );
        assert_eq!(stale["submission_id"], 20);
        assert_eq!(stale["reason_code"], "turn_mismatch_or_terminal");
        let control = stream_event(
            UiEvent::ControlSubmissionApplied {
                id: SubmissionId(21),
                kind: crate::runtime::ControlSubmissionKind::Drain,
            },
            &mut turn,
        );
        assert_eq!(control["submission_id"], 21);
        assert_eq!(control["kind"], "drain");
    }

    #[test]
    fn machine_tool_events_preserve_call_ids_without_relaxing_secret_scrubbing() {
        let mut turn = 0;
        let id = "call_00_RFTSn3Qcw4Wu9i4Z276c9895";
        let credential_shape = concat!("sk-", "ant-api03-AbCdEfGhIjKlMnOpQrStUvWx");
        let start = stream_event(
            UiEvent::ToolStart {
                id: id.into(),
                name: "read_file".into(),
                args: json!({"token": credential_shape}),
            },
            &mut turn,
        );
        let end = stream_event(
            UiEvent::ToolEnd {
                id: id.into(),
                ok: true,
                exit_code: None,
                output: credential_shape.into(),
                diff: None,
            },
            &mut turn,
        );
        assert_eq!(start["tool_use_id"], id);
        assert_eq!(end["tool_use_id"], id);
        assert_ne!(start["args"]["token"], credential_shape);
        assert_ne!(end["output"], credential_shape);

        let suspicious = stream_event(
            UiEvent::ToolStart {
                id: credential_shape.into(),
                name: "read_file".into(),
                args: json!({}),
            },
            &mut turn,
        );
        assert_ne!(suspicious["tool_use_id"], credential_shape);
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
    fn d13_14_every_stream_record_type_matches_the_frozen_v8_corpus() {
        fn frozen_turn_end(effort: EffortApplication, turn: &mut u32) -> Value {
            stream_event(
                UiEvent::TurnEnd {
                    cost: CostState::Unknown {
                        reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard,
                    },
                    usage: iteron_protocol::Usage::default(),
                    context: iteron_ctx::ContextEstimate {
                        system_tokens: 0,
                        tool_tokens: 0,
                        conversation_tokens: 0,
                        tool_result_tokens: 0,
                        lsp_result_tokens: 0,
                        transcript_tokens: 0,
                        framing_tokens: 0,
                        total_tokens: 0,
                        provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                        components: Some(iteron_ctx::ContextComponentUsage::default()),
                    },
                    model_context_window: None,
                    reserved_output_tokens: 8_192,
                    compaction_trigger_tokens: 120_000,
                    effort,
                },
                turn,
            )
        }

        let mut turn = 0;
        let records = vec![
            input_attachment_event(1, iteron_protocol::ImageMediaType::Png, 12),
            stream_event(UiEvent::Text("answer".into()), &mut turn),
            stream_event(UiEvent::Thinking("plan".into()), &mut turn),
            stream_event(
                UiEvent::ToolStart {
                    id: "tool-1".into(),
                    name: "read_file".into(),
                    args: json!({"path": "src/lib.rs"}),
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::ToolEnd {
                    id: "tool-1".into(),
                    ok: true,
                    exit_code: None,
                    output: "ok".into(),
                    diff: Some(FileDiff {
                        path: "src/lib.rs".into(),
                        adds: 1,
                        dels: 1,
                        hunks: vec![Hunk {
                            header: "@@ -1,2 +1,2 @@".into(),
                            lines: vec![
                                DiffLine {
                                    tag: DiffTag::Del,
                                    text: "old".into(),
                                },
                                DiffLine {
                                    tag: DiffTag::Add,
                                    text: "new".into(),
                                },
                                DiffLine {
                                    tag: DiffTag::Ctx,
                                    text: "context".into(),
                                },
                            ],
                        }],
                    }),
                },
                &mut turn,
            ),
            stream_event(UiEvent::Phase(Phase::Context), &mut turn),
            frozen_turn_end(
                EffortApplication::Exact {
                    requested: iteron_protocol::ReasoningEffort::High,
                },
                &mut turn,
            ),
            frozen_turn_end(
                EffortApplication::Mapped {
                    requested: iteron_protocol::ReasoningEffort::XHigh,
                    sent: iteron_protocol::ReasoningEffort::High,
                },
                &mut turn,
            ),
            frozen_turn_end(
                EffortApplication::BudgetBased {
                    requested: iteron_protocol::ReasoningEffort::Max,
                    budget_tokens: 32_000,
                },
                &mut turn,
            ),
            frozen_turn_end(
                EffortApplication::ToggleOnly {
                    requested: iteron_protocol::ReasoningEffort::Low,
                    enabled: true,
                },
                &mut turn,
            ),
            frozen_turn_end(
                EffortApplication::Unsupported {
                    requested: iteron_protocol::ReasoningEffort::Medium,
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::RunStarted {
                    run_id: "workflow-1".into(),
                    name: "ultracode".into(),
                    class: "fan_reduce".into(),
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::PlanReady {
                    run_id: "workflow-1".into(),
                    tasks: vec![WorkflowTaskUi {
                        id: 0,
                        label: "inspect".into(),
                    }],
                    dropped: 0,
                    duplicates_removed: 0,
                    invalid_removed: 0,
                    execution_mode: WorkflowExecutionModeUi::Sequential,
                    fan_turn_budget: 4,
                    writer_turn_reserve: 12,
                    fan_wall_secs: 60,
                    writer_wall_reserve_secs: 120,
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::PhaseChanged {
                    run_id: "workflow-1".into(),
                    phase: WorkflowPhaseUi::Exploring,
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::AgentStarted {
                    run_id: "workflow-1".into(),
                    agent_id: 0,
                    sub_run: "child-1".into(),
                    turn_budget: 4,
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::AgentActivity {
                    run_id: "workflow-1".into(),
                    agent_id: 0,
                    activity: "reading".into(),
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                    run_id: "workflow-1".into(),
                    agent_id: 0,
                    outcome: WorkflowAgentOutcomeUi::Done,
                    turns: 1,
                    tokens: 20,
                    tool_calls: 1,
                    elapsed_ms: 30,
                    summary_preview: Some("done".into()),
                    error_preview: None,
                }),
                &mut turn,
            ),
            stream_event(
                UiEvent::Workflow(WorkflowUiEvent::RunFinished {
                    run_id: "workflow-1".into(),
                    outcome: WorkflowRunOutcomeUi::Done,
                    reason: None,
                    elapsed_ms: 40,
                    provider_attempts: 1,
                    turns: 1,
                    tokens: 20,
                    tool_calls: 1,
                    failed_tasks: 0,
                    skipped_tasks: 0,
                }),
                &mut turn,
            ),
            stream_event(UiEvent::SteerApplied { count: 1 }, &mut turn),
            stream_event(UiEvent::Notice("checkpoint".into()), &mut turn),
            stream_event(
                UiEvent::ApprovalRequest {
                    id: SubmissionId(7),
                    tool: "bash".into(),
                    capability: Capability::CodeExecuting,
                    reason: "approve?".into(),
                    arguments: json!({"command": "cargo test"}),
                    workspace: "/workspace".into(),
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::ApprovalResolved {
                    id: SubmissionId(7),
                    resolution: ApprovalResolution::Approved,
                    reason_code: "operator_approved",
                    response_submission_id: Some(SubmissionId(19)),
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::ControlSubmissionApplied {
                    id: SubmissionId(21),
                    kind: crate::runtime::ControlSubmissionKind::Drain,
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::SteerSubmissionApplied {
                    id: SubmissionId(19),
                },
                &mut turn,
            ),
            stream_event(
                UiEvent::SubmissionRejected {
                    id: SubmissionId(20),
                    reason_code: "turn_mismatch_or_terminal",
                },
                &mut turn,
            ),
            stream_event(UiEvent::Done("ignored debug text".into()), &mut turn),
            final_result(
                &Outcome::Done,
                "complete",
                "run-all-types",
                &CostState::Zero,
                5,
                KernelTax::default(),
                None,
            ),
        ];
        let frozen = include_str!("../tests/golden/input_attachment_stream_v8.jsonl")
            .lines()
            .chain(include_str!("../tests/golden/machine_stream_all_v8.jsonl").lines())
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records, frozen);
        // The new receipt vocabulary must not rewrite any published v6 event shape.
        // Its four events are tested separately as compatibility notices below.
        let legacy_records = records
            .iter()
            .filter(|record| {
                !matches!(
                    record["type"].as_str(),
                    Some(
                        "approval_resolved"
                            | "control_submission_applied"
                            | "steer_submission_applied"
                            | "submission_rejected"
                    )
                )
            })
            .map(|record| project_schema(record.clone(), 6).unwrap())
            .collect::<Vec<_>>();
        let legacy_frozen = include_str!("../tests/golden/input_attachment_stream_v6.jsonl")
            .lines()
            .chain(include_str!("../tests/golden/machine_stream_all_v6.jsonl").lines())
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(legacy_records, legacy_frozen);
        let kinds = records
            .iter()
            .map(|record| record["type"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(kinds.len(), 23, "every machine stream type is frozen once");
        let tool_end_diff = records
            .iter()
            .find(|record| record["type"] == "tool_end")
            .and_then(|record| record["diff"].as_object())
            .expect("the frozen tool_end must carry a non-null typed FileDiff");
        let diff_tags = tool_end_diff["hunks"]
            .as_array()
            .expect("diff hunks")
            .iter()
            .flat_map(|hunk| hunk["lines"].as_array().expect("diff lines"))
            .map(|line| line["tag"].as_str().expect("diff tag"))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            tool_end_diff["hunks"]
                .as_array()
                .expect("diff hunks")
                .iter()
                .map(|hunk| hunk["lines"].as_array().expect("diff lines").len())
                .sum::<usize>(),
            diff_tags.len(),
            "the exhaustive diff corpus must contain each tag exactly once"
        );
        assert_eq!(
            diff_tags,
            std::collections::BTreeSet::from(["Add", "Ctx", "Del"]),
            "the typed CLI corpus must freeze every DiffTag variant"
        );
        let effort_variants = records
            .iter()
            .filter(|record| record["type"] == "turn_end")
            .filter_map(|record| record["effort"]["enforcement"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            effort_variants,
            std::collections::BTreeSet::from([
                "budget_based",
                "exact",
                "mapped",
                "toggle_only",
                "unsupported",
            ]),
            "every nested machine effort shape is frozen"
        );
    }

    #[test]
    fn identified_receipt_machine_records_match_the_versioned_v8_fixture() {
        let mut turn = 0;
        let records = [
            UiEvent::ApprovalResolved {
                id: SubmissionId(7),
                resolution: ApprovalResolution::Approved,
                reason_code: "operator_approved",
                response_submission_id: Some(SubmissionId(19)),
            },
            UiEvent::ControlSubmissionApplied {
                id: SubmissionId(21),
                kind: crate::runtime::ControlSubmissionKind::Drain,
            },
            UiEvent::SteerSubmissionApplied {
                id: SubmissionId(19),
            },
            UiEvent::SubmissionRejected {
                id: SubmissionId(20),
                reason_code: "turn_mismatch_or_terminal",
            },
        ]
        .into_iter()
        .map(|event| stream_event_for_schema(event, &mut turn, SCHEMA_VERSION).unwrap())
        .collect::<Vec<_>>();
        let fixture = include_str!("../tests/golden/receipt_stream_v8.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records, fixture);
        for legacy_schema in [LEGACY_SCHEMA_VERSION, PREVIOUS_SCHEMA_VERSION, 6] {
            for record in &records {
                let projected = project_schema(record.clone(), legacy_schema).unwrap();
                let encoded = serde_json::to_string(&projected).unwrap();
                assert_eq!(projected["schema_version"], legacy_schema);
                assert_eq!(projected["type"], "notice");
                assert_eq!(projected.as_object().unwrap().len(), 3);
                assert!(projected["message"].as_str().unwrap().len() <= MAX_STDERR_NOTICE_BYTES);
                assert!(!encoded.contains("applied"), "{encoded}");
                assert!(!encoded.contains("submission_id"), "{encoded}");
            }
        }
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
            KernelTax::default(),
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
    fn streaming_scrubber_never_emits_a_split_url_password() {
        let mut stream = StreamingScrubber::default();
        assert!(stream.push("https:").is_none());
        assert!(stream.push("//user:plain").is_none());
        assert!(stream.push("password@host.example").is_none());
        let completed = stream.push("/path done ").unwrap();
        assert!(!completed.contains("plainpassword"), "{completed}");
        assert!(completed.contains("[REDACTED"), "{completed}");
        assert_eq!(stream.finish(), None);
    }

    #[test]
    fn legacy_stream_json_never_emits_split_url_userinfo() {
        for schema in SUPPORTED_SCHEMA_VERSIONS {
            let mut stream = StreamingScrubber::default();
            let mut turn = 0;
            let mut frames = Vec::new();
            for delta in [
                "link https:",
                "//user:plain",
                "password@host.example",
                "/path done ",
            ] {
                if let Some(safe) = stream.push(delta) {
                    frames.push(
                        stream_event_for_schema(UiEvent::Text(safe), &mut turn, schema).unwrap(),
                    );
                }
                if delta == "//user:plain" || delta == "password@host.example" {
                    assert_eq!(frames.len(), 1, "a credential prefix escaped early");
                }
                let emitted = serde_json::to_string(&frames).unwrap();
                assert!(!emitted.contains("plainpassword"), "{emitted}");
            }
            if let Some(safe) = stream.finish() {
                frames
                    .push(stream_event_for_schema(UiEvent::Text(safe), &mut turn, schema).unwrap());
            }
            let emitted = serde_json::to_string(&frames).unwrap();
            assert!(emitted.contains("REDACTED"), "{emitted}");
            assert!(!emitted.contains("plainpassword"), "{emitted}");
        }
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

    #[test]
    fn input_attachment_is_bounded_metadata_only_and_stream_json_only() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../tests/golden/input_attachment_stream_v8.jsonl"
        ))
        .unwrap();
        assert_eq!(
            input_attachment_record(
                OutputFormat::StreamJson,
                1,
                iteron_protocol::ImageMediaType::Png,
                12,
            )
            .unwrap(),
            Some(frozen.clone())
        );
        assert_eq!(frozen["schema_version"], SCHEMA_VERSION);
        assert_eq!(frozen["type"], "input_attachment");
        assert_eq!(frozen["ordinal"], 1);
        assert_eq!(frozen["media_type"], "image/png");
        assert_eq!(frozen["encoded_bytes"], 12);
        assert_eq!(frozen.as_object().unwrap().len(), 5);
        assert!(frozen.get("path").is_none());
        assert!(frozen.get("data").is_none());

        for format in [OutputFormat::Text, OutputFormat::Json] {
            assert_eq!(
                input_attachment_record(
                    format,
                    usize::MAX,
                    iteron_protocol::ImageMediaType::Png,
                    1
                )
                .unwrap(),
                None,
                "{format:?} must retain its existing bytes"
            );
        }
        for (ordinal, encoded_bytes) in [
            (0, 4),
            (iteron_protocol::input::MAX_INPUT_IMAGES + 1, 4),
            (1, 0),
            (1, 3),
            (1, iteron_protocol::input::MAX_IMAGE_BASE64_BYTES + 4),
        ] {
            assert_eq!(
                input_attachment_record(
                    OutputFormat::StreamJson,
                    ordinal,
                    iteron_protocol::ImageMediaType::Png,
                    encoded_bytes,
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn legacy_stream_reader_skips_v5_input_attachment_without_changing_v4_bytes() {
        let legacy = include_bytes!("../tests/golden/one_shot_stream_json_success_v4.jsonl");
        let attachment = include_bytes!("../tests/golden/input_attachment_stream_v5.jsonl");
        let first_line_end = legacy
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .expect("legacy JSONL has a first line");
        let mut interleaved = Vec::with_capacity(legacy.len() + attachment.len());
        interleaved.extend_from_slice(&legacy[..first_line_end]);
        interleaved.extend_from_slice(attachment);
        interleaved.extend_from_slice(&legacy[first_line_end..]);

        let known_legacy_types = legacy
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice::<Value>(line).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!known_legacy_types.contains("input_attachment"));

        let mut retained = Vec::with_capacity(legacy.len());
        for line in interleaved.split_inclusive(|byte| *byte == b'\n') {
            let record: Value = serde_json::from_slice(line).unwrap();
            if known_legacy_types.contains(record["type"].as_str().unwrap()) {
                retained.extend_from_slice(line);
            }
        }
        assert_eq!(
            retained, legacy,
            "an old unknown-tag-skipping reader must recover the frozen v4 stream byte-for-byte"
        );
    }
}
