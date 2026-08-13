//! Compaction policy. When the transcript approaches the context budget, summarize the older
//! turns so a long task does not overflow the window (ADR-002). This is the anti-overflow
//! mechanism that makes the agent usable past a few turns — table-stakes for production.
//!
//! The policy here decides WHEN to compact and WHAT to keep; the kernel performs the LLM
//! summarization (ctx must not depend on a provider). Compaction is honest about its cost: it
//! rewrites the prefix, which breaks the prompt cache from that point (ADR-002: a cache bomb).
//! So we compact rarely (only at the boundary) and keep the task + the most recent turns
//! verbatim, summarizing only the middle.
//!
//! WHEN has two answers, and only one of them is on the critical path. [`plan_at_turn_end`] is
//! the routine one: the turn is over, the operator is reading an answer they already have, and
//! the summary is paid out of their thinking time. [`plan_before_overflow`] is the emergency
//! valve: this request does not fit the proven window, so the alternative to compacting is a
//! refused request. Nothing compacts merely because the next request would be *large*.
//!
//! [`plan_at_turn_end`]: CompactionPolicy::plan_at_turn_end
//! [`plan_before_overflow`]: CompactionPolicy::plan_before_overflow

use iteron_protocol::{Block, Message, Role, ToolSpec};

/// Fallback admission trigger used when no model window is proven and no window-relative
/// threshold can be derived.
const DEFAULT_TRIGGER_TOKENS: usize = 120_000;
/// Trailing messages kept verbatim, so the turn in progress survives compaction intact.
const DEFAULT_KEEP_RECENT: usize = 6;

/// Provenance for the request-size number. This is never labelled as provider tokenization: it is
/// a fast, deterministic admission estimate used before a request exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEstimateProvenance {
    /// Legacy pre-v2 estimate retained so historical UI/test events remain representable.
    HeuristicBytesPerToken35,
    /// One token per UTF-8 byte: an explicitly identified upper-bound fallback for an unknown
    /// provider/model route. Provider-reported usage remains authoritative after the request.
    ConservativeByteUpperBound,
    /// Route-selected, content-aware approximation for OpenAI-compatible BPE tokenizers.
    OpenAiBpeApproximation,
    /// Route-selected, content-aware approximation for Anthropic tokenizers.
    AnthropicBpeApproximation,
    /// Route-selected, content-aware approximation for SentencePiece-like provider families.
    SentencePieceApproximation,
}

/// Estimated input context for the exact request projection the kernel is about to send.
/// `total_tokens` includes the effective system prefix (memory/skills included by the caller),
/// tool schemas, transcript content, and conservative wire-framing allowances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextEstimate {
    pub system_tokens: usize,
    pub tool_tokens: usize,
    /// User/assistant text, thinking, provider state, and tool-call envelopes.
    pub conversation_tokens: usize,
    /// Ordinary tool-result bodies retained in the transcript.
    pub tool_result_tokens: usize,
    /// Language-server result bodies, accounted separately from ordinary tools.
    pub lsp_result_tokens: usize,
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
    estimate_request_context_with_profile(
        crate::TokenEstimatorProfile::default(),
        system,
        messages,
        tools,
    )
}

pub fn estimate_request_context_with_profile(
    profile: crate::TokenEstimatorProfile,
    system: &str,
    messages: &[Message],
    tools: &[ToolSpec],
) -> ContextEstimate {
    let transcript = transcript_components(messages, profile);
    assemble_estimate(
        profile.estimate(system),
        tool_set_tokens(tools, profile),
        transcript,
        messages.len(),
        tools.len(),
        profile.provenance(),
    )
}

/// Serialising every `input_schema` is the expensive half of the estimate. Kept separate so the
/// one-shot and the cached paths cannot drift into disagreeing about what a tool set costs.
fn tool_set_tokens(tools: &[ToolSpec], profile: crate::TokenEstimatorProfile) -> usize {
    tools
        .iter()
        .map(|tool| {
            profile.estimate(&tool.name)
                + profile.estimate(&tool.description)
                + profile.estimate(&tool.input_schema.to_string())
        })
        .sum()
}

fn assemble_estimate(
    system_tokens: usize,
    tool_tokens: usize,
    transcript: TranscriptComponents,
    message_count: usize,
    tool_count: usize,
    provenance: TokenEstimateProvenance,
) -> ContextEstimate {
    // Provider encodings differ, so account for roles, content wrappers, tool declarations, and
    // the system envelope explicitly without pretending this is an exact tokenizer result.
    let framing_tokens = 4usize
        .saturating_add(message_count.saturating_mul(4))
        .saturating_add(tool_count.saturating_mul(12));
    let transcript_tokens = transcript.total();
    let total_tokens = system_tokens
        .saturating_add(tool_tokens)
        .saturating_add(transcript_tokens)
        .saturating_add(framing_tokens);
    ContextEstimate {
        system_tokens,
        tool_tokens,
        conversation_tokens: transcript.conversation,
        tool_result_tokens: transcript.tool_results,
        lsp_result_tokens: transcript.lsp_results,
        transcript_tokens,
        framing_tokens,
        total_tokens,
        provenance,
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
    profile: crate::TokenEstimatorProfile,
    policy: crate::TokenEstimatorPolicy,
    per_message: Vec<TranscriptComponents>,
    transcript: TranscriptComponents,
    lsp_tool_ids: std::collections::BTreeSet<String>,
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

    pub fn for_route(provider_id: Option<&str>, model_id: &str) -> Self {
        Self {
            profile: crate::TokenEstimatorProfile::for_route(provider_id, model_id),
            ..Self::default()
        }
    }

    pub fn set_route(&mut self, provider_id: Option<&str>, model_id: &str) {
        let profile = match self.policy {
            crate::TokenEstimatorPolicy::RouteAwareV2 => {
                crate::TokenEstimatorProfile::for_route(provider_id, model_id)
            }
        };
        if self.profile != profile {
            self.profile = profile;
            self.invalidate_transcript();
            self.tools = None;
        }
    }

    /// Pin the exact selector policy recovered from the immutable tunables checkpoint. Concrete
    /// profiles remain route-aware and every selected identity is exposed to ContextLedger.
    pub fn pin_policy(&mut self, policy: crate::TokenEstimatorPolicy) {
        self.policy = policy;
    }

    pub fn tokenizer_identity(&self) -> crate::TokenizerIdentity {
        self.profile.identity()
    }

    pub fn estimate_text(&self, text: &str) -> usize {
        self.profile.estimate(text)
    }

    pub fn estimate_image(&self, encoded_base64_bytes: usize) -> usize {
        self.profile.estimate_image(encoded_base64_bytes)
    }

    pub fn estimate_uncached(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> ContextEstimate {
        estimate_request_context_with_profile(self.profile, system, messages, tools)
    }

    /// Forget every cached message estimate. Cheap; the next estimate rebuilds the running total.
    pub fn invalidate_transcript(&mut self) {
        self.per_message.clear();
        self.transcript = TranscriptComponents::default();
        self.lsp_tool_ids.clear();
    }

    /// The transcript's estimated tokens, walking only messages appended since the last call.
    fn transcript_components(&mut self, messages: &[Message]) -> TranscriptComponents {
        if messages.len() < self.per_message.len() {
            self.invalidate_transcript();
        }
        for message in &messages[self.per_message.len()..] {
            let components = message_components(message, &mut self.lsp_tool_ids, self.profile);
            self.per_message.push(components);
            self.transcript = self.transcript.saturating_add(components);
        }
        self.transcript
    }

    pub fn transcript_tokens(&mut self, messages: &[Message]) -> usize {
        self.transcript_components(messages).total()
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
                tokens: tool_set_tokens(tools, self.profile),
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
        let system_tokens = self.profile.estimate(system);
        let transcript = self.transcript_components(messages);
        let tool_tokens = self.tool_tokens(tools);
        assemble_estimate(
            system_tokens,
            tool_tokens,
            transcript,
            messages.len(),
            tools.len(),
            self.profile.provenance(),
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
    /// Automatic compaction may be disabled without disabling the explicit `/compact` command.
    pub enabled: bool,
    pub hysteresis: crate::CompactionHysteresis,
    pub summary_topology: crate::SummaryTopology,
    pub summary_profile: crate::SummaryProfile,
    pub coverage_check: bool,
    window_relative: bool,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        // This is an operator-tunable admission trigger, not a model-window assertion. A catalog
        // without context metadata must report the window as unknown rather than reverse-engineer
        // one from this value.
        CompactionPolicy {
            trigger_tokens: DEFAULT_TRIGGER_TOKENS,
            keep_recent: DEFAULT_KEEP_RECENT,
            enabled: true,
            hysteresis: crate::CompactionHysteresis::default(),
            summary_topology: crate::SummaryTopology::SingleStage,
            summary_profile: crate::SummaryProfile::default(),
            coverage_check: true,
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
    obligations: crate::compact_obligations::CompactionObligations,
}

impl CompactionPlan {
    pub fn obligations_preserved(&self) -> u32 {
        self.obligations.preserved_count()
    }

    pub fn obligations_lost(&self) -> u32 {
        self.obligations.lost_count()
    }
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
        self.enabled
            && messages.len() > self.keep_recent + 2
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
        if !self.enabled {
            return None;
        }
        let estimate = estimate_request_context(system, messages, tools);
        if messages.len() <= self.keep_recent + 2 || estimate.total_tokens <= self.trigger_tokens {
            return None;
        }
        self.plan_unconditional(messages)
    }

    /// The end-of-turn trigger: close enough to the real trigger that the next submission would
    /// otherwise have to pay for the summary before its own request could be built. Three
    /// quarters, integer-only, so a replay derives the same number from the same facts.
    pub fn approaching_trigger_tokens(
        &self,
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> usize {
        self.hysteresis.enter_threshold(
            self.effective_trigger_tokens(model_context_window, reserved_output_tokens),
        )
    }

    /// The routine path: plan a compaction to run AFTER the turn the operator was waiting on,
    /// while they read the answer. Triggered early (at [`Self::approaching_trigger_tokens`]) on
    /// purpose — being a little eager here is free, because nobody is blocked on it.
    pub fn plan_at_turn_end(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> Option<CompactionPlan> {
        if !self.enabled {
            return None;
        }
        let estimate = estimate_request_context(system, messages, tools);
        let trigger = self.approaching_trigger_tokens(model_context_window, reserved_output_tokens);
        if messages.len() <= self.keep_recent + 2 || estimate.total_tokens <= trigger {
            return None;
        }
        self.plan_unconditional(messages)
    }

    /// The emergency valve, inside the turn loop: this projection plus its output reservation no
    /// longer fits the proven window, so the alternative to compacting is a refused request.
    /// Without a proven window there is no admission boundary to defend and the documented
    /// absolute fallback stands in for one.
    pub fn plan_before_overflow(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolSpec],
        model_context_window: Option<u64>,
        reserved_output_tokens: u32,
    ) -> Option<CompactionPlan> {
        if !self.enabled {
            return None;
        }
        if messages.len() <= self.keep_recent + 2 {
            return None;
        }
        let estimate = estimate_request_context(system, messages, tools);
        let fits = match model_context_window.filter(|window| *window > 0) {
            Some(window) => {
                u64::try_from(estimate.total_tokens)
                    .unwrap_or(u64::MAX)
                    .saturating_add(u64::from(reserved_output_tokens))
                    <= window
            }
            None => {
                estimate.total_tokens <= self.effective_trigger_tokens(None, reserved_output_tokens)
            }
        };
        if fits {
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
        if !self.enabled {
            return None;
        }
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
            obligations: crate::compact_obligations::CompactionObligations::gather(
                &to_summarize,
                &task_anchor,
                &keep_verbatim,
            ),
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
         Preserve, as terse bullet points: the goal; every still-applicable operator constraint; \
         files inspected and what was found; edits already made; commands run and their outcomes; \
         decisions taken and why; and what remains to do. Mark superseded operator instructions as \
         superseded. Omit pleasantries and reasoning that did not change the plan. This note \
         replaces the detailed history, so anything you drop is lost."
    }

    /// Rebuild the transcript from a produced summary string. The result is:
    /// [task_anchor, summary-as-user-message, ...keep_verbatim].
    pub fn rebuild(plan: &CompactionPlan, summary: String) -> Vec<Message> {
        let mut out = Vec::with_capacity(2 + plan.keep_verbatim.len());
        out.push(plan.task_anchor.clone());
        out.push(compaction_summary_message(
            plan.to_summarize.len(),
            &summary,
        ));
        out.extend(plan.keep_verbatim.iter().cloned());
        out
    }
}

/// The opening of a compaction summary message. What sits between this and
/// [`COMPACTION_MARKER_CLOSE`] is the plan range: how many messages, counted from just after the
/// task anchor, this summary replaced.
const COMPACTION_MARKER_OPEN: &str = "[Compacted history — ";
const COMPACTION_MARKER_CLOSE: &str = " earlier turns summarized]";

/// The one message a compaction actually produces. The plan range travels in the marker rather
/// than in a side channel, which is what lets the record carry a summary instead of a rewritten
/// copy of a transcript it already holds.
pub fn compaction_summary_message(summarized: usize, summary: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![Block::Text {
            text: format!(
                "{COMPACTION_MARKER_OPEN}{summarized}{COMPACTION_MARKER_CLOSE}\n{summary}"
            ),
        }],
    }
}

/// How many messages this summary folded away, if it is a compaction summary at all.
pub fn compaction_summary_range(message: &Message) -> Option<usize> {
    let Some(Block::Text { text }) = message.content.first() else {
        return None;
    };
    let (count, _) = text
        .strip_prefix(COMPACTION_MARKER_OPEN)?
        .split_once(COMPACTION_MARKER_CLOSE)?;
    count.parse().ok()
}

/// Everything a compaction is worth recording: the summary text, with the plan range in its
/// marker. The rebuild is a deterministic function of this plus the transcript already on the
/// record, so writing the rebuilt transcript back out would be writing the same bytes twice —
/// once measured at 115949 of them, inline, inside the operator's turn.
pub fn compaction_seed(plan: &CompactionPlan, summary: &str) -> Vec<Message> {
    vec![compaction_summary_message(plan.to_summarize.len(), summary)]
}

/// Replay a recorded compaction against the transcript projected so far, reproducing exactly what
/// [`CompactionPolicy::rebuild`] produced live.
///
/// A one-message seed carries the plan range and the rest is reconstructed. Anything else is a
/// full snapshot from before the seed format and is adopted verbatim, as is a seed whose range
/// the projected prefix cannot satisfy — a record that does not describe this transcript is not
/// reconstructable, and guessing would be worse than replaying what was written.
pub fn replay_compaction(prior: Vec<Message>, recorded: Vec<Message>) -> Vec<Message> {
    let [seed] = recorded.as_slice() else {
        return recorded;
    };
    let Some(summarized) = compaction_summary_range(seed) else {
        return recorded;
    };
    if prior.len() < summarized + 1 {
        return recorded;
    }
    let mut out = Vec::with_capacity(prior.len() - summarized + 1);
    out.push(prior[0].clone());
    out.push(seed.clone());
    out.extend(prior[summarized + 1..].iter().cloned());
    out
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TranscriptComponents {
    conversation: usize,
    tool_results: usize,
    lsp_results: usize,
}

impl TranscriptComponents {
    fn total(self) -> usize {
        self.conversation
            .saturating_add(self.tool_results)
            .saturating_add(self.lsp_results)
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            conversation: self.conversation.saturating_add(other.conversation),
            tool_results: self.tool_results.saturating_add(other.tool_results),
            lsp_results: self.lsp_results.saturating_add(other.lsp_results),
        }
    }
}

fn transcript_components(
    messages: &[Message],
    profile: crate::TokenEstimatorProfile,
) -> TranscriptComponents {
    let mut lsp_tool_ids = std::collections::BTreeSet::new();
    messages
        .iter()
        .fold(TranscriptComponents::default(), |total, message| {
            total.saturating_add(message_components(message, &mut lsp_tool_ids, profile))
        })
}

fn message_components(
    message: &Message,
    lsp_tool_ids: &mut std::collections::BTreeSet<String>,
    profile: crate::TokenEstimatorProfile,
) -> TranscriptComponents {
    let mut estimate = TranscriptComponents::default();
    for block in &message.content {
        match block {
            Block::Text { text } => {
                estimate.conversation =
                    estimate.conversation.saturating_add(profile.estimate(text));
            }
            Block::Thinking { thinking } => {
                estimate.conversation = estimate
                    .conversation
                    .saturating_add(profile.estimate(thinking));
            }
            // Adapter-private state still consumes provider context when its route matches. The
            // producing adapter enforces a strict byte bound before this reaches the transcript.
            Block::ProviderState(state) => {
                estimate.conversation = estimate
                    .conversation
                    .saturating_add(profile.estimate(&state.payload.to_string()) + 8);
            }
            Block::ToolUse(tool) => {
                if tool.name == "lsp_query" {
                    lsp_tool_ids.insert(tool.id.clone());
                }
                estimate.conversation = estimate
                    .conversation
                    .saturating_add(profile.estimate(&tool.input.to_string()) + 8);
            }
            Block::ToolResult(result) => {
                let tokens = profile.estimate(&result.content) + 8;
                if lsp_tool_ids.contains(&result.tool_use_id) {
                    estimate.lsp_results = estimate.lsp_results.saturating_add(tokens);
                } else {
                    estimate.tool_results = estimate.tool_results.saturating_add(tokens);
                }
            }
        }
    }
    estimate
}

fn message_content_tokens(message: &Message) -> usize {
    message_components(
        message,
        &mut std::collections::BTreeSet::new(),
        crate::TokenEstimatorProfile::default(),
    )
    .total()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big_user(n: usize) -> Message {
        Message::user_text("x".repeat(n))
    }

    /// `Message` has no `PartialEq`; the wire form is the identity that matters here anyway,
    /// because that is what the record writes and the replay reads back.
    fn wire(messages: &[Message]) -> String {
        serde_json::to_string(messages).expect("messages serialize")
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
            purity: iteron_protocol::Purity::Pure,
            capability: iteron_protocol::Capability::ReadOnly,
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
    fn route_aware_checkpointed_selector_tracks_cross_provider_changes() {
        let mut estimator = RequestEstimator::for_route(Some("openai"), "gpt-5");
        estimator.pin_policy(crate::TokenEstimatorPolicy::RouteAwareV2);
        assert_eq!(
            estimator.tokenizer_identity().catalog_id,
            "iteron.openai-bpe-approx"
        );

        estimator.set_route(Some("anthropic"), "claude-opus");
        assert_eq!(
            estimator.tokenizer_identity().catalog_id,
            "iteron.anthropic-bpe-approx"
        );
        assert_eq!(
            crate::TokenEstimatorPolicy::RouteAwareV2.id(),
            crate::ROUTE_AWARE_ESTIMATOR_POLICY_ID
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
                purity: iteron_protocol::Purity::Pure,
                capability: iteron_protocol::Capability::ReadOnly,
            },
            ToolSpec {
                name: "bash".into(),
                description: "y".repeat(120),
                input_schema: serde_json::json!({"type":"object","properties":{"command":{"type":"string"}}}),
                purity: iteron_protocol::Purity::Effecting,
                capability: iteron_protocol::Capability::CodeExecuting,
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
        let messages = vec![big_user(2_200); policy.keep_recent + 3];
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

    #[test]
    fn a_request_that_still_fits_never_compacts_inside_the_turn() {
        // The audited defect: a transcript over the routine trigger but comfortably inside the
        // window bought an extra synchronous summary round before the operator's own request.
        // The emergency valve declines it; only the end-of-turn path takes it.
        let policy = CompactionPolicy::default();
        // The unidentified-route fallback is one token per UTF-8 byte. Keep this projection
        // between the 60% trigger and the 75% admission boundary under that conservative owner.
        let messages = vec![big_user(2_200); policy.keep_recent + 3];
        let estimate = estimate_request_context("system", &messages, &[]);
        assert!(estimate.total_tokens.saturating_add(8_192) < 32_768);
        assert!(estimate.total_tokens > policy.effective_trigger_tokens(Some(32_768), 8_192));
        assert!(
            policy
                .plan_before_overflow("system", &messages, &[], Some(32_768), 8_192)
                .is_none(),
            "a request that fits is admitted as-is; compaction is not a size opinion"
        );
        assert!(
            policy
                .plan_at_turn_end("system", &messages, &[], Some(32_768), 8_192)
                .is_some(),
            "the same transcript compacts once the turn is over"
        );
    }

    #[test]
    fn the_emergency_valve_still_fires_when_the_projection_cannot_be_admitted() {
        let policy = CompactionPolicy::default();
        let messages = vec![big_user(10_000); policy.keep_recent + 3];
        let estimate = estimate_request_context("sys", &messages, &[]);
        assert!(estimate.total_tokens.saturating_add(8_192) > 32_768);
        assert!(
            policy
                .plan_before_overflow("sys", &messages, &[], Some(32_768), 8_192)
                .is_some()
        );
        // Unknown window: no admission boundary exists, so the absolute fallback stands in.
        assert!(
            policy
                .plan_before_overflow("sys", &messages, &[], None, 8_192)
                .is_none()
        );
        let huge = vec![big_user(500_000); policy.keep_recent + 3];
        assert!(
            policy
                .plan_before_overflow("sys", &huge, &[], None, 8_192)
                .is_some()
        );
    }

    #[test]
    fn the_end_of_turn_trigger_is_three_quarters_of_the_real_one() {
        let policy = CompactionPolicy::default();
        assert_eq!(
            policy.approaching_trigger_tokens(Some(32_768), 8_192),
            14_745
        );
        assert_eq!(policy.approaching_trigger_tokens(None, 8_192), 90_000);
        let mut fixed = CompactionPolicy::default();
        fixed.set_fixed_trigger_tokens(40_000);
        assert_eq!(
            fixed.approaching_trigger_tokens(Some(1_000_000), 8_192),
            30_000
        );
    }

    #[test]
    fn the_seed_is_one_message_and_replay_rebuilds_the_identical_transcript() {
        let mut policy = CompactionPolicy {
            keep_recent: 2,
            ..CompactionPolicy::default()
        };
        policy.set_fixed_trigger_tokens(100);
        let prior = vec![
            Message::user_text("THE TASK"),
            big_user(500),
            big_user(500),
            big_user(500),
            Message::user_text("recent-1"),
            Message::user_text("recent-2"),
        ];
        let plan = policy.plan(&prior).expect("should compact");
        let live = CompactionPolicy::rebuild(&plan, "SUMMARY".into());

        let seed = compaction_seed(&plan, "SUMMARY");
        assert_eq!(
            seed.len(),
            1,
            "the record carries the summary, not the transcript"
        );
        assert!(
            seed[0]
                .content
                .iter()
                .any(|b| matches!(b, Block::Text { text } if text.len() < 200)),
            "the recorded event is small"
        );
        assert_eq!(compaction_summary_range(&seed[0]), Some(3));

        assert_eq!(
            wire(&replay_compaction(prior.clone(), seed)),
            wire(&live),
            "replay reconstructs byte-identically to what ran"
        );
        // A pre-seed full snapshot on an existing rollout still replays as itself.
        assert_eq!(wire(&replay_compaction(prior, live.clone())), wire(&live));
    }

    #[test]
    fn a_seed_whose_range_the_prefix_cannot_satisfy_replays_as_written() {
        let seed = vec![compaction_summary_message(9, "SUMMARY")];
        let prior = vec![Message::user_text("task"), Message::user_text("one")];
        assert_eq!(wire(&replay_compaction(prior, seed.clone())), wire(&seed));
        // Ordinary transcript text is not mistaken for a seed.
        assert_eq!(
            compaction_summary_range(&Message::user_text("[Compacted history — x turns]")),
            None
        );
    }
}
