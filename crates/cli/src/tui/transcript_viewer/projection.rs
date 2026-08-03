//! Bounded viewer projection starts from the same semantic blocks as ordinary rendering/export.

use crate::block;

pub(super) fn block_label(kind: &block::BlockKind) -> &'static str {
    match kind {
        block::BlockKind::User(_) => "user",
        block::BlockKind::Assistant(_) => "assistant",
        block::BlockKind::Thinking { .. } => "thinking",
        block::BlockKind::Tool(_) => "tool",
        block::BlockKind::Workflow(_) => "workflow",
        block::BlockKind::WorkflowRun(_) => "workflow-run",
        block::BlockKind::Notice { .. } => "notice",
        block::BlockKind::Error { .. } => "error",
        block::BlockKind::Diff(_) => "diff",
        block::BlockKind::Panel { .. } => "panel",
        block::BlockKind::Welcome { .. } => "welcome",
    }
}

pub(super) fn raw_text(block: &block::Block) -> String {
    match &block.kind {
        block::BlockKind::User(text) => text.clone(),
        block::BlockKind::Assistant(document) => document.to_text(),
        block::BlockKind::Thinking { text, .. } => text.clone(),
        block::BlockKind::Tool(card) => serde_json::to_string_pretty(&serde_json::json!({
            "block_id": block.id,
            "kind": "tool",
            "name": card.name,
            "arguments": card.args,
            "status": match card.status {
                block::ToolStatus::Running => "running",
                block::ToolStatus::Ok => "ok",
                block::ToolStatus::Err => "error",
            },
            "exit_code": card.exit_code,
            "output": card.output,
        }))
        .unwrap_or_else(|_| "{\"kind\":\"tool\",\"error\":\"unavailable\"}".into()),
        block::BlockKind::Notice { text, .. } => text.clone(),
        block::BlockKind::Error { title, detail, .. } => format!("{title}\n{detail}"),
        block::BlockKind::Welcome { tagline } => tagline.clone(),
        _ => block.to_text(),
    }
}
