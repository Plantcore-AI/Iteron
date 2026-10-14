//! Cooperative byte-capped semantic text projection for the joinable viewer worker.

mod markdown;

use std::sync::atomic::{AtomicBool, Ordering};

use iteron_protocol::DiffTag;
use iteron_workflow::events::{self, WorkflowState};

use crate::block;
use crate::markdown::MarkdownDoc;

/// Ceiling on the buffer reserved before any block text is appended. The caller's byte cap can be
/// far larger than the block it bounds, so reserving the cap itself would charge every short block
/// for the longest one the viewer tolerates.
const TEXT_RESERVE_BYTES: usize = 64 * 1024;

pub(super) fn markdown_text(
    document: &MarkdownDoc,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Option<(String, bool)> {
    markdown::project(document, max_bytes, cancelled)
}

pub(super) fn block_text(
    block: &block::Block,
    max_bytes: usize,
    cancelled: &AtomicBool,
) -> Option<(String, bool)> {
    let mut out = BoundedText::new(max_bytes, cancelled);
    match &block.kind {
        block::BlockKind::User(text) => {
            out.push("### you\n");
            out.push(text);
            out.push("\n");
        }
        block::BlockKind::Assistant(document) => {
            out.push("### iteron\n");
            if out.active()
                && let Some((text, truncated)) =
                    markdown::project(document, out.remaining(), cancelled)
            {
                out.push(&text);
                out.truncated |= truncated;
            }
        }
        block::BlockKind::Thinking { text, .. } => {
            out.push("<thinking>\n");
            out.push(text);
            out.push("\n</thinking>\n");
        }
        block::BlockKind::Tool(card) => {
            out.push("$ ");
            out.push(&card.name);
            out.push(" ");
            if out.active() {
                let (arguments, truncated) =
                    super::projection::arguments_json(&card.args, out.remaining(), cancelled)
                        .ok()?;
                out.push(&arguments);
                out.truncated |= truncated;
            }
            out.push("\nstatus: ");
            out.push(block::tool_status_label(card));
            if let Some(code) = card.exit_code {
                out.push(" · exit ");
                out.number(code);
            }
            out.push("\n");
            if card.output.len() > out.remaining() {
                out.push(&card.output);
            } else if !card.output.is_empty() {
                out.push(&card.output);
                out.push("\n");
            }
            if let Some(diff) = &card.diff {
                append_diff(&mut out, diff);
            }
        }
        block::BlockKind::Workflow(card) => {
            out.push("## ");
            out.push(&card.name);
            out.push(" workflow ");
            out.push(&card.run_id);
            out.push(" (");
            out.push(&card.class);
            out.push(", ");
            out.push(block::workflow_status_label(card.status));
            out.push(")\n");
            for task in &card.tasks {
                if !out.active() {
                    break;
                }
                out.push("- [");
                out.number(task.id.saturating_add(1));
                out.push("] ");
                out.push(&task.label);
                out.push(" — ");
                out.push(task_status(task.status));
                if task.status != block::WorkflowTaskStatus::Queued {
                    out.push(" (");
                    out.number(task.turns);
                    out.push(" turns, ");
                    out.number(task.tokens);
                    out.push(" tokens, ");
                    out.number(task.tool_calls);
                    out.push(" tools)");
                }
                out.push("\n");
                if let Some(summary) = &task.summary_preview {
                    out.push("  evidence: ");
                    out.push(summary);
                    out.push("\n");
                }
                if let Some(error) = &task.error_preview {
                    out.push("  reason: ");
                    out.push(error);
                    out.push("\n");
                }
            }
            if card.dropped > 0 {
                out.push("- ");
                out.number(card.dropped);
                out.push(" tasks omitted by the fan limit\n");
            }
        }
        block::BlockKind::WorkflowRun(card) => {
            out.push("## workflow \"");
            out.push(&card.name);
            out.push("\" (");
            out.push(&card.run_id);
            out.push(")\n");
            for phase in &card.phases {
                if !out.active() {
                    break;
                }
                out.push("### ");
                out.push(&phase.title);
                out.push(" (");
                out.number(phase.index);
                out.push(")\n");
            }
            for agent in &card.agents {
                if !out.active() {
                    break;
                }
                let state = match agent.state {
                    WorkflowState::Queued => "queued",
                    WorkflowState::Running => "running",
                    WorkflowState::Done => "done",
                    WorkflowState::Error => "error",
                    WorkflowState::Skipped => "skipped",
                };
                out.push("- #");
                out.number(agent.index);
                out.push(" ");
                out.push(&agent.label);
                out.push(" — ");
                out.push(state);
                out.push(" (");
                out.push(&events::fmt_count(agent.tokens));
                out.push(" tok, ");
                out.number(agent.tool_calls);
                out.push(" tools, ");
                out.push(&events::fmt_duration(agent.duration_ms));
                out.push(")\n");
                if let Some(error) = &agent.error {
                    out.push("  reason: ");
                    out.push(error);
                    out.push("\n");
                }
            }
        }
        block::BlockKind::Notice { text, .. } => {
            out.push("[");
            out.push(text);
            out.push("]\n");
        }
        block::BlockKind::Error { title, detail, .. } => {
            out.push("[error] ");
            out.push(title);
            out.push("\n");
            out.push(detail);
            out.push("\n");
        }
        block::BlockKind::Diff(diff) => append_diff(&mut out, diff),
        block::BlockKind::Panel { title, rows } => {
            out.push("## ");
            out.push(title);
            out.push("\n");
            for row in rows {
                if !out.active() {
                    break;
                }
                match row {
                    block::PanelRow::KeyValue { key, value } => {
                        out.push("- ");
                        out.push(key);
                        out.push(": ");
                        out.push(value);
                        out.push("\n");
                    }
                    block::PanelRow::Item { label, hint } => {
                        out.push("- ");
                        out.push(label);
                        if !hint.is_empty() {
                            out.push("  (");
                            out.push(hint);
                            out.push(")");
                        }
                        out.push("\n");
                    }
                    block::PanelRow::Note(text) => {
                        out.push("  ");
                        out.push(text);
                        out.push("\n");
                    }
                }
            }
        }
        block::BlockKind::Welcome { tagline } => {
            out.push("start here — ");
            out.push(tagline);
            out.push("\n");
        }
    }
    out.finish()
}

fn task_status(status: block::WorkflowTaskStatus) -> &'static str {
    match status {
        block::WorkflowTaskStatus::Queued => "queued",
        block::WorkflowTaskStatus::Running => "running",
        block::WorkflowTaskStatus::Done => "done",
        block::WorkflowTaskStatus::Failed => "failed",
        block::WorkflowTaskStatus::Interrupted => "interrupted",
        block::WorkflowTaskStatus::SkippedBudget => "budget-skipped",
        block::WorkflowTaskStatus::NotStarted => "not started",
        block::WorkflowTaskStatus::Unknown => "status unknown",
    }
}

fn append_diff(out: &mut BoundedText<'_>, diff: &iteron_protocol::FileDiff) {
    out.push("--- ");
    out.push(&diff.path);
    out.push(" (+");
    out.number(diff.adds);
    out.push(" -");
    out.number(diff.dels);
    out.push(")\n");
    for hunk in &diff.hunks {
        if !out.active() {
            return;
        }
        out.push(&hunk.header);
        out.push("\n");
        for line in &hunk.lines {
            if !out.active() {
                return;
            }
            out.push(match line.tag {
                DiffTag::Add => "+",
                DiffTag::Del => "-",
                DiffTag::Ctx => " ",
            });
            out.push(&line.text);
            out.push("\n");
        }
    }
}

struct BoundedText<'a> {
    text: String,
    max_bytes: usize,
    truncated: bool,
    cancelled: &'a AtomicBool,
}

impl<'a> BoundedText<'a> {
    fn new(max_bytes: usize, cancelled: &'a AtomicBool) -> Self {
        Self {
            text: String::with_capacity(max_bytes.min(iteron_tunables::param_integer(
                "cli.tui.transcript_viewer.semantic_text.text_reserve_bytes",
                TEXT_RESERVE_BYTES,
            ))),
            max_bytes,
            truncated: false,
            cancelled,
        }
    }

    fn active(&self) -> bool {
        !self.truncated && !self.cancelled.load(Ordering::Relaxed)
    }

    fn remaining(&self) -> usize {
        self.max_bytes.saturating_sub(self.text.len())
    }

    fn push(&mut self, value: &str) {
        if !self.active() {
            return;
        }
        if value.len() > self.remaining() {
            self.truncated = true;
            return;
        }
        self.text.push_str(value);
    }

    fn number(&mut self, value: impl ToString) {
        if self.active() {
            self.push(&value.to_string());
        }
    }

    fn finish(self) -> Option<(String, bool)> {
        (!self.cancelled.load(Ordering::Relaxed)).then_some((self.text, self.truncated))
    }
}
