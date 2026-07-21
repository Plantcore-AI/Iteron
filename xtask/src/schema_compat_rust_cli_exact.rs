use super::runtime::{require_function, require_method};
use anyhow::Result;

pub(super) fn validate(file: &syn::File) -> Result<()> {
    require_function(
        file,
        "outcome_exit_code",
        r#"pub fn outcome_exit_code(outcome: &Outcome) -> u8 {
            match outcome {
                Outcome::Done | Outcome::Drained => EXIT_SUCCESS,
                Outcome::HarnessError => EXIT_HARNESS,
                Outcome::BudgetExhausted(_) => EXIT_BUDGET,
                Outcome::Stuck => EXIT_STUCK,
                Outcome::Interrupted => EXIT_INTERRUPTED,
            }
        }"#,
    )?;
    require_function(
        file,
        "outcome_name",
        r#"fn outcome_name(outcome: &Outcome) -> &'static str {
            match outcome {
                Outcome::Done => "done",
                Outcome::Drained => "drained",
                Outcome::HarnessError => "harness_error",
                Outcome::BudgetExhausted(_) => "budget_exhausted",
                Outcome::Stuck => "stuck",
                Outcome::Interrupted => "interrupted",
            }
        }"#,
    )?;
    require_function(
        file,
        "outcome_reason",
        r#"fn outcome_reason(outcome: &Outcome) -> Option<&str> {
            match outcome {
                Outcome::BudgetExhausted(reason) => Some(reason),
                _ => None,
            }
        }"#,
    )?;
    require_method(
        file,
        "OutputFormat",
        "is_machine",
        r#"pub fn is_machine(self) -> bool {
            !matches!(self, Self::Text)
        }"#,
    )?;
    require_function(
        file,
        "phase_name",
        r#"fn phase_name(phase: Phase) -> &'static str {
            match phase {
                Phase::Context => "context",
                Phase::Model => "model",
                Phase::Tools => "tools",
                Phase::Verify => "verify",
                Phase::Idle => "idle",
            }
        }"#,
    )?;
    require_function(
        file,
        "effort_application_json",
        r#"fn effort_application_json(application: EffortApplication) -> Value {
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
                EffortApplication::BudgetBased { requested, budget_tokens, } => json!({
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
        }"#,
    )?;
    require_function(
        file,
        "final_result",
        r#"pub fn final_result(
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
                "success": matches!(outcome, Outcome::Done | Outcome::Drained),
                "assistant_text": scrub(assistant_text),
                "run_id": scrub(run_id),
                "cost_usd": cost.usd(),
                "cost_status": cost.status(),
                "cost_reason": cost.reason().map(|reason| reason.code()),
                "turns": turns,
                "exit_code": outcome_exit_code(outcome),
                "error": error.map(scrub),
            })
        }"#,
    )?;
    validate_emitter(file)
}

fn validate_emitter(file: &syn::File) -> Result<()> {
    require_method(
        file,
        "Emitter",
        "new",
        r#"pub fn new(format: OutputFormat) -> Self {
            Self {
                format,
                stream_turn: 0,
                assistant_scrubber: StreamingScrubber::default(),
                thinking_scrubber: StreamingScrubber::default(),
                text_line_open: false,
            }
        }"#,
    )?;
    require_method(
        file,
        "Emitter",
        "write_text_delta",
        r#"fn write_text_delta(&mut self, delta: &str) -> io::Result<()> {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(delta.as_bytes())?;
            stdout.flush()?;
            self.text_line_open = true;
            Ok(())
        }"#,
    )?;
    require_method(
        file,
        "Emitter",
        "flush_text_output",
        r#"fn flush_text_output(&mut self, end_line: bool) -> io::Result<()> {
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
        }"#,
    )?;
    require_method(
        file,
        "Emitter",
        "flush_stream_text",
        r#"fn flush_stream_text(&mut self) -> io::Result<()> {
            if let Some(delta) = self.assistant_scrubber.finish() {
                self.write_stream_event(UiEvent::Text(delta))?;
            }
            if let Some(delta) = self.thinking_scrubber.finish() {
                self.write_stream_event(UiEvent::Thinking(delta))?;
            }
            Ok(())
        }"#,
    )?;
    require_method(
        file,
        "Emitter",
        "event",
        r#"pub fn event(&mut self, event: UiEvent) -> io::Result<()> {
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
        }"#,
    )
}
