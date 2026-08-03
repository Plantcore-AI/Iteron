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
    assemble_estimate(
        crate::estimate_tokens(system),
        tool_set_tokens(tools),
        messages.iter().map(message_content_tokens).sum(),
        messages.len(),
        tools.len(),
    )
}

/// Serialising every `input_schema` is the expensive half of the estimate. Kept separate so the
/// one-shot and the cached paths cannot drift into disagreeing about what a tool set costs.
fn tool_set_tokens(tools: &[ToolSpec]) -> usize {
    tools
        .iter()
        .map(|tool| {
            crate::estimate_tokens(&tool.name)
                + crate::estimate_tokens(&tool.description)
                + crate::estimate_tokens(&tool.input_schema.to_string())
        })
        .sum()
}

fn assemble_estimate(
    system_tokens: usize,
    tool_tokens: usize,
    transcript_tokens: usize,
    message_count: usize,
    tool_count: usize,
) -> ContextEstimate {
    // Provider encodings differ, so account for roles, content wrappers, tool declarations, and
    // the system envelope explicitly without pretending this is an exact tokenizer result.
    let framing_tokens = 4usize
        .saturating_add(message_count.saturating_mul(4))
        .saturating_add(tool_count.saturating_mul(12));
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

/// Session-scoped context accounting.
///
/// [`estimate_request_context`] walks the whole transcript and re-serialises every tool schema, and
/// the kernel calls it more than once per turn. Both inputs are almost entirely stable between
/// turns: a message's token cost is a pure function of its content, and a registered tool's spec is
/// immutable once registered. This keeps a per-message estimate with a running total plus one
/// cached tool-set estimate, so an append-only turn walks only what is new.
///
/// A caller that REWRITES an already-counted message instead of appending — compaction's rebuild,
/// or steering merged into the trailing user message — must call [`Self::invalidate_transcript`].
/// A shortened transcript is detected here; an in-place edit is not observable from a slice.
#[derive(Debug, Clone, Default)]
pub struct RequestEstimator {
    per_message: Vec<usize>,
    transcript_tokens: usize,
    tools: Option<CachedToolEstimate>,
}

#[derive(Debug, Clone)]
struct CachedToolEstimate {
    /// Advertised tool names in order. A registry has no API that mutates an already-registered
    /// spec, so the name sequence is a complete key for the advertised set.
    names: Vec<String>,
    tokens: usize,
}

impl RequestEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget every cached message estimate. Cheap; the next estimate rebuilds the running total.
    pub fn invalidate_transcript(&mut self) {
        self.per_message.clear();
        self.transcript_tokens = 0;
    }

    /// The transcript's estimated tokens, walking only messages appended since the last call.
    pub fn transcript_tokens(&mut self, messages: &[Message]) -> usize {
        if messages.len() < self.per_message.len() {
            self.invalidate_transcript();
        }
        for message in &messages[self.per_message.len()..] {
            let tokens = message_content_tokens(message);
            self.per_message.push(tokens);
            self.transcript_tokens = self.transcript_tokens.saturating_add(tokens);
        }
        self.transcript_tokens
    }

    fn tool_tokens(&mut self, tools: &[ToolSpec]) -> usize {
        let reusable = self.tools.as_ref().is_some_and(|cached| {
            cached.names.len() == tools.len()
                && cached
                    .names
                    .iter()
                    .zip(tools)
                    .all(|(name, tool)| *name == tool.name)
        });
        if !reusable {
            self.tools = Some(CachedToolEstimate {
                names: tools.iter().map(|tool| tool.name.clone()).collect(),
                tokens: tool_set_tokens(tools),
            });
        }
        self.tools.as_ref().map_or(0, |cached| cached.tokens)
    }

    /// The same projection as [`estimate_request_context`], reusing the cached transcript and tool
    /// accounting. Constant time in history length for an append-only turn.
    pub fn estimate(
        &mut self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> ContextEstimate {
        let system_tokens = crate::estimate_tokens(system);
        let transcript_tokens = self.transcript_tokens(messages);
        let tool_tokens = self.tool_tokens(tools);
        assemble_estimate(
            system_tokens,
            tool_tokens,
            transcript_tokens,
            messages.len(),
            tools.len(),
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompactionPolicy {
    /// Compact when the estimated request tokens exceed this fallback. When model-window
    /// metadata is available the default policy derives a window-relative threshold instead.
    pub trigger_tokens: usize,
    /// Always keep the last N messages verbatim (recent context is highest-signal).
    pub keep_recent: usize,
    window_relative: bool,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        // This is an operator-tunable admission trigger, not a model-window assertion. A catalog
        // without context metadata must report the window as unknown rather than reverse-engineer
        // one from this value.
        CompactionPolicy {
            trigger_tokens: 120_000,
            keep_recent: 6,
            window_relative: true,
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
    /// Replace the adaptive default with an exact operator-authored trigger.
    pub fn set_fixed_trigger_tokens(&mut self, trigger_tokens: usize) {
        self.trigger_tokens = trigger_tokens;
        self.window_relative = false;
    }

    /// Resolve the actual trigger from durable policy plus the catalog-proven model window. The
    /// calculation is deliberately provider-free and integer-only so replaying the same facts
    /// produces the same threshold. Twenty percent of usable input space remains as compaction
    /// headroom; the provider output reservation is never counted as available input space.
    pub fn effective_trigger_tokens(
        &self,
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> usize {
        if !self.window_relative {
            return self.trigger_tokens;
        }
        let Some(window) = model_context_window.filter(|window| *window > 0) else {
            return self.trigger_tokens;
        };
        let usable = window.saturating_sub(u64::from(reserved_output_tokens));
        let derived = usable.saturating_mul(4) / 5;
        usize::try_from(derived).unwrap_or(usize::MAX).max(1)
    }

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

    /// Window-aware kernel path. A missing window uses the documented fallback; a known window
    /// scales the default trigger while preserving an explicit fixed operator override.
    pub fn plan_for_request_with_window(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> Option<CompactionPlan> {
        let estimate = estimate_request_context(system, messages, tools);
        self.plan_for_estimated_request_with_window(
            &estimate,
            messages,
            model_context_window,
            reserved_output_tokens,
        )
    }

    /// The same decision over an ALREADY-COMPUTED estimate. The kernel owns the estimate so one
    /// turn pays for one transcript accounting pass instead of one per consumer.
    pub fn plan_for_estimated_request_with_window(
        &self,
        estimate: &ContextEstimate,
        messages: &[Message],
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> Option<CompactionPlan> {
        let trigger = self.effective_trigger_tokens(model_context_window, reserved_output_tokens);
        if messages.len() <= self.keep_recent + 2 || estimate.total_tokens <= trigger {
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
        let mut policy = CompactionPolicy {
            keep_recent: 2,
            ..CompactionPolicy::default()
        };
        policy.set_fixed_trigger_tokens(1000);
        let msgs = vec![big_user(100), big_user(100)];
        assert!(policy.plan(&msgs).is_none());
    }

    #[test]
    fn compacts_the_middle_keeps_task_and_tail() {
        let mut policy = CompactionPolicy {
            keep_recent: 2,
            ..CompactionPolicy::default()
        };
        policy.set_fixed_trigger_tokens(100);
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
    fn cached_accounting_matches_the_one_shot_estimate_through_append_and_rewrite() {
        // I-60: the estimate re-serialised the whole transcript and every tool schema two or three
        // times per turn. The cache must stay byte-for-byte equal to the uncached projection.
        let tools = vec![
            ToolSpec {
                name: "read_file".into(),
                description: "x".repeat(350),
                input_schema: serde_json::json!({"type":"object","properties":{"path":{"type":"string"}}}),
                purity: core_protocol::Purity::Pure,
                capability: core_protocol::Capability::ReadOnly,
            },
            ToolSpec {
                name: "bash".into(),
                description: "y".repeat(120),
                input_schema: serde_json::json!({"type":"object","properties":{"command":{"type":"string"}}}),
                purity: core_protocol::Purity::Effecting,
                capability: core_protocol::Capability::CodeExecuting,
            },
        ];
        let mut estimator = RequestEstimator::new();
        let mut messages = vec![Message::user_text("THE TASK")];
        for turn in 0..8 {
            messages.push(big_user(400 + turn));
            assert_eq!(
                estimator.estimate("system prefix", &messages, &tools),
                estimate_request_context("system prefix", &messages, &tools),
                "appending must not drift from the uncached projection"
            );
            // A second consumer in the same turn must observe the identical number for free.
            assert_eq!(
                estimator.estimate("system prefix", &messages, &tools),
                estimate_request_context("system prefix", &messages, &tools)
            );
        }

        // A shortened transcript (the compaction rebuild) is detected without an explicit hint.
        messages.truncate(3);
        assert_eq!(
            estimator.estimate("system prefix", &messages, &tools),
            estimate_request_context("system prefix", &messages, &tools)
        );

        // An in-place rewrite of an already-counted message is NOT observable from a slice, so the
        // caller must invalidate — this is the contract the kernel's steering path depends on.
        messages[2] = big_user(9_000);
        estimator.invalidate_transcript();
        assert_eq!(
            estimator.estimate("system prefix", &messages, &tools),
            estimate_request_context("system prefix", &messages, &tools)
        );

        // A changed advertised tool set re-costs the schemas rather than reusing a stale total.
        let narrowed = vec![tools[0].clone()];
        assert_eq!(
            estimator.estimate("system prefix", &messages, &narrowed),
            estimate_request_context("system prefix", &messages, &narrowed)
        );
        assert_eq!(
            estimator.estimate("system prefix", &messages, &[]),
            estimate_request_context("system prefix", &messages, &[])
        );
    }

    #[test]
    fn estimated_and_uncached_window_plans_agree() {
        let policy = CompactionPolicy::default();
        let messages = vec![big_user(9_000); policy.keep_recent + 3];
        let estimate = estimate_request_context("system", &messages, &[]);
        assert_eq!(
            policy
                .plan_for_estimated_request_with_window(&estimate, &messages, Some(32_768), 8_192)
                .is_some(),
            policy
                .plan_for_request_with_window("system", &messages, &[], Some(32_768), 8_192)
                .is_some()
        );
        let short = vec![big_user(10); 2];
        let short_estimate = estimate_request_context("system", &short, &[]);
        assert!(
            policy
                .plan_for_estimated_request_with_window(
                    &short_estimate,
                    &short,
                    Some(32_768),
                    8_192
                )
                .is_none()
        );
    }

    #[test]
    fn request_plan_can_trigger_on_stable_prefix_not_only_transcript() {
        let mut policy = CompactionPolicy {
            keep_recent: 2,
            ..CompactionPolicy::default()
        };
        policy.set_fixed_trigger_tokens(100);
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

    #[test]
    fn adaptive_trigger_is_a_pure_function_of_window_and_output_reservation() {
        let policy = CompactionPolicy::default();
        assert_eq!(policy.effective_trigger_tokens(Some(32_768), 8_192), 19_660);
        assert_eq!(
            policy.effective_trigger_tokens(Some(1_000_000), 8_192),
            793_446
        );
        assert_eq!(policy.effective_trigger_tokens(None, 8_192), 120_000);
        assert_eq!(policy.effective_trigger_tokens(Some(32_768), 8_192), 19_660);
    }

    #[test]
    fn explicit_trigger_remains_fixed_across_model_windows() {
        let mut policy = CompactionPolicy::default();
        policy.set_fixed_trigger_tokens(42_000);
        assert_eq!(policy.effective_trigger_tokens(Some(32_768), 8_192), 42_000);
        assert_eq!(
            policy.effective_trigger_tokens(Some(1_000_000), 8_192),
            42_000
        );
    }

    #[test]
    fn large_window_does_not_compact_at_the_legacy_default() {
        let policy = CompactionPolicy::default();
        let messages = vec![big_user(53_000); policy.keep_recent + 3];
        let estimate = estimate_request_context("system", &messages, &[]);
        assert!(estimate.total_tokens > 120_000);
        assert!(
            policy
                .plan_for_request_with_window("system", &messages, &[], Some(1_000_000), 8_192,)
                .is_none()
        );
    }

    #[test]
    fn small_window_compacts_before_input_admission_boundary() {
        let policy = CompactionPolicy::default();
        let messages = vec![big_user(9_000); policy.keep_recent + 3];
        let estimate = estimate_request_context("system", &messages, &[]);
        let usable = 32_768usize - 8_192;
        assert!(estimate.total_tokens < usable);
        assert!(estimate.total_tokens > policy.effective_trigger_tokens(Some(32_768), 8_192));
        assert!(
            policy
                .plan_for_request_with_window("system", &messages, &[], Some(32_768), 8_192,)
                .is_some()
        );
    }
}
