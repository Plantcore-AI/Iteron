//! Compaction policy. When the transcript approaches the context budget, summarize the older
//! turns so a long task does not overflow the window (ADR-002). This is the anti-overflow
//! mechanism that makes the agent usable past a few turns — table-stakes for production.
//!
//! The policy here decides WHEN to compact and WHAT to keep; the kernel performs the LLM
//! summarization (ctx must not depend on a provider). Compaction is honest about its cost: it
//! rewrites the prefix, which breaks the prompt cache from that point (ADR-002: a cache bomb).
//! So we compact rarely (only at the boundary) and keep the task + the most recent turns
//! verbatim, summarizing only the middle.

use core_protocol::{Block, Message, Role, ToolSpec};

/// Provenance for the request-size number. This is never labelled as provider tokenization: it is
/// a fast, deterministic admission estimate used before a request exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEstimateProvenance {
    /// UTF-8 bytes divided by 3.5, rounded up, plus explicit message/tool framing allowances.
    HeuristicBytesPerToken35,
}

/// Estimated input context for the exact request projection the kernel is about to send.
/// `total_tokens` includes the effective system prefix (memory/skills included by the caller),
/// tool schemas, transcript content, and conservative wire-framing allowances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextEstimate {
    pub system_tokens: usize,
    pub tool_tokens: usize,
    pub transcript_tokens: usize,
    pub framing_tokens: usize,
    pub total_tokens: usize,
    pub provenance: TokenEstimateProvenance,
}

/// Estimate the complete provider input projection. The model's actual context window is a
/// separate catalog capability and is intentionally absent here; a compaction trigger is not a
/// context-window claim.
pub fn estimate_request_context(
    system: &str,
    messages: &[Message],
    tools: &[ToolSpec],
) -> ContextEstimate {
    let system_tokens = crate::estimate_tokens(system);
    let transcript_tokens = messages.iter().map(message_content_tokens).sum();
    let tool_tokens = tools
        .iter()
        .map(|tool| {
            crate::estimate_tokens(&tool.name)
                + crate::estimate_tokens(&tool.description)
                + crate::estimate_tokens(&tool.input_schema.to_string())
        })
        .sum();
    // Provider encodings differ, so account for roles, content wrappers, tool declarations, and
    // the system envelope explicitly without pretending this is an exact tokenizer result.
    let framing_tokens = 4usize
        .saturating_add(messages.len().saturating_mul(4))
        .saturating_add(tools.len().saturating_mul(12));
    let total_tokens = system_tokens
        .saturating_add(tool_tokens)
        .saturating_add(transcript_tokens)
        .saturating_add(framing_tokens);
    ContextEstimate {
        system_tokens,
        tool_tokens,
        transcript_tokens,
        framing_tokens,
        total_tokens,
        provenance: TokenEstimateProvenance::HeuristicBytesPerToken35,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompactionPolicy {
    /// Compact when the estimated transcript tokens exceed this.
    pub trigger_tokens: usize,
    /// Always keep the last N messages verbatim (recent context is highest-signal).
    pub keep_recent: usize,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        // This is an operator-tunable admission trigger, not a model-window assertion. A catalog
        // without context metadata must report the window as unknown rather than reverse-engineer
        // one from this value.
        CompactionPolicy {
            trigger_tokens: 120_000,
            keep_recent: 6,
        }
    }
}

/// What the kernel should do to compact: summarize `to_summarize`, then rebuild the transcript
/// as [first user message (the task), <summary as a user message>, ...keep_verbatim].
pub struct CompactionPlan {
    /// The middle messages to fold into a summary (sent to the model for summarization).
    pub to_summarize: Vec<Message>,
    /// The messages kept verbatim after the summary (the recent tail).
    pub keep_verbatim: Vec<Message>,
    /// The very first message (the task) is always preserved as the anchor.
    pub task_anchor: Message,
}

impl CompactionPolicy {
    /// Estimate the transcript's token cost.
    pub fn transcript_tokens(&self, messages: &[Message]) -> usize {
        messages.iter().map(message_content_tokens).sum()
    }

    /// Should we compact this transcript?
    pub fn should_compact(&self, messages: &[Message]) -> bool {
        messages.len() > self.keep_recent + 2
            && self.transcript_tokens(messages) > self.trigger_tokens
    }

    /// Build the plan. Returns None if there is nothing worth compacting.
    pub fn plan(&self, messages: &[Message]) -> Option<CompactionPlan> {
        if !self.should_compact(messages) {
            return None;
        }
        self.plan_unconditional(messages)
    }

    /// Build a plan using the complete request projection: effective system, tool schemas, and
    /// transcript. This is the kernel path. `plan` remains for transcript-only callers/tests.
    pub fn plan_for_request(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Option<CompactionPlan> {
        let estimate = estimate_request_context(system, messages, tools);
        if messages.len() <= self.keep_recent + 2 || estimate.total_tokens <= self.trigger_tokens {
            return None;
        }
        self.plan_unconditional(messages)
    }

    /// Plan a compaction UNCONDITIONALLY, ignoring the token trigger — the operator `/compact`
    /// path (design r5-design-tui-commands §3.6). Same middle-selection + tool_result-boundary
    /// safety as `plan`.
    pub fn force_plan(&self, messages: &[Message]) -> Option<CompactionPlan> {
        self.plan_unconditional(messages)
    }

    fn plan_unconditional(&self, messages: &[Message]) -> Option<CompactionPlan> {
        let task_anchor = messages.first()?.clone();
        let n = messages.len();
        let mut keep_from = n.saturating_sub(self.keep_recent);
        // Do not begin the kept tail on a user message carrying tool_results — that would orphan
        // the assistant tool_use turn before it (which is now summarized away), producing an
        // API-invalid transcript (code review). Walk keep_from back past any such boundary.
        while keep_from > 1 {
            let m = &messages[keep_from];
            let starts_on_toolresult = matches!(m.role, Role::User)
                && m.content.iter().any(|b| matches!(b, Block::ToolResult(_)));
            if starts_on_toolresult {
                keep_from -= 1;
            } else {
                break;
            }
        }
        // middle = everything between the task anchor (index 0) and the recent tail.
        let to_summarize: Vec<Message> = messages[1..keep_from].to_vec();
        let keep_verbatim: Vec<Message> = messages[keep_from..].to_vec();
        if to_summarize.is_empty() {
            return None;
        }
        Some(CompactionPlan {
            to_summarize,
            keep_verbatim,
            task_anchor,
        })
    }

    /// The instruction to the summarizer. Cognition's warning: the compressor is lossy and
    /// hard to get right, so the prompt is explicit about preserving *decisions and state*,
    /// not prose.
    pub fn summary_prompt() -> &'static str {
        "Summarize the conversation so far into a compact hand-off note for continuing the task. \
         Preserve, as terse bullet points: the goal; files inspected and what was found; edits \
         already made; commands run and their outcomes; decisions taken and why; and what remains \
         to do. Omit pleasantries and reasoning that did not change the plan. This note replaces \
         the detailed history, so anything you drop is lost."
    }

    /// Rebuild the transcript from a produced summary string. The result is:
    /// [task_anchor, summary-as-user-message, ...keep_verbatim].
    pub fn rebuild(plan: &CompactionPlan, summary: String) -> Vec<Message> {
        let mut out = Vec::with_capacity(2 + plan.keep_verbatim.len());
        out.push(plan.task_anchor.clone());
        out.push(Message {
            role: Role::User,
            content: vec![Block::Text {
                text: format!("[Compacted history — earlier turns summarized]\n{summary}"),
            }],
        });
        out.extend(plan.keep_verbatim.iter().cloned());
        out
    }
}

fn message_content_tokens(m: &Message) -> usize {
    m.content
        .iter()
        .map(|b| match b {
            Block::Text { text } => crate::estimate_tokens(text),
            Block::Thinking { thinking } => crate::estimate_tokens(thinking),
            // Adapter-private state still consumes provider context when its route matches. The
            // producing adapter enforces a strict byte bound before this reaches the transcript.
            Block::ProviderState(state) => crate::estimate_tokens(&state.payload.to_string()) + 8,
            Block::ToolUse(t) => crate::estimate_tokens(&t.input.to_string()) + 8,
            Block::ToolResult(r) => crate::estimate_tokens(&r.content) + 8,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big_user(n: usize) -> Message {
        Message::user_text("x".repeat(n))
    }

    #[test]
    fn does_not_compact_a_short_transcript() {
        let policy = CompactionPolicy {
            trigger_tokens: 1000,
            keep_recent: 2,
        };
        let msgs = vec![big_user(100), big_user(100)];
        assert!(policy.plan(&msgs).is_none());
    }

    #[test]
    fn compacts_the_middle_keeps_task_and_tail() {
        let policy = CompactionPolicy {
            trigger_tokens: 100,
            keep_recent: 2,
        };
        let msgs = vec![
            Message::user_text("THE TASK"),
            big_user(500),
            big_user(500),
            big_user(500),
            Message::user_text("recent-1"),
            Message::user_text("recent-2"),
        ];
        let plan = policy.plan(&msgs).expect("should compact");
        assert!(
            plan.task_anchor
                .content
                .iter()
                .any(|b| matches!(b, Block::Text { text } if text == "THE TASK"))
        );
        assert_eq!(plan.keep_verbatim.len(), 2, "keeps the recent tail");
        assert_eq!(plan.to_summarize.len(), 3, "summarizes the middle");

        let rebuilt = CompactionPolicy::rebuild(&plan, "SUMMARY".into());
        // task + summary + 2 recent = 4 messages, down from 6.
        assert_eq!(rebuilt.len(), 4);
        assert!(matches!(&rebuilt[1].content[0], Block::Text { text } if text.contains("SUMMARY")));
    }

    #[test]
    fn request_estimate_counts_effective_system_tools_and_framing() {
        let messages = vec![Message::user_text("small"); 5];
        let tools = vec![ToolSpec {
            name: "read_file".into(),
            description: "x".repeat(350),
            input_schema: Default::default(),
            purity: core_protocol::Purity::Pure,
            capability: core_protocol::Capability::ReadOnly,
        }];
        let estimate = estimate_request_context(&"s".repeat(350), &messages, &tools);
        assert!(estimate.system_tokens >= 100);
        assert!(estimate.tool_tokens >= 100);
        assert!(estimate.framing_tokens >= 4 + messages.len() * 4 + 12);
        assert_eq!(
            estimate.total_tokens,
            estimate.system_tokens
                + estimate.tool_tokens
                + estimate.transcript_tokens
                + estimate.framing_tokens
        );
    }

    #[test]
    fn request_plan_can_trigger_on_stable_prefix_not_only_transcript() {
        let policy = CompactionPolicy {
            trigger_tokens: 100,
            keep_recent: 2,
        };
        let messages = vec![
            Message::user_text("task"),
            Message::user_text("old one"),
            Message::user_text("old two"),
            Message::user_text("tail one"),
            Message::user_text("tail two"),
        ];
        assert!(policy.plan(&messages).is_none());
        assert!(
            policy
                .plan_for_request(&"large prefix ".repeat(100), &messages, &[])
                .is_some()
        );
    }
}
