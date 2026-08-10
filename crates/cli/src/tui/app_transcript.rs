use super::*;

impl App {
    /// Push a structured block, assigning a monotonic id; returns the id.
    pub(super) fn push_block(&mut self, kind: block::BlockKind) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.transcript.push(Arc::new(block::Block::new(id, kind)));
        self.mark_transcript_changed();
        self.autoscroll();
        id
    }

    pub(super) fn mark_transcript_changed(&mut self) {
        self.transcript_revision = self.transcript_revision.wrapping_add(1);
    }

    /// Echo the operator's submitted prompt as a User block.
    pub(super) fn push_user(&mut self, text: impl Into<String>) {
        self.flush_text();
        self.push_block(block::BlockKind::User(ui_safe_text(&text.into())));
    }

    /// How long the provider has been silent since the model phase opened, and whether that is
    /// merely slow or long enough to describe as stalled. `None` once a token has arrived, when no
    /// model request is open, or while the wait is still ordinary (I-64).
    pub(super) fn first_token_stall(&self) -> Option<FirstTokenStall> {
        if !self.running {
            return None;
        }
        let waited = self.awaiting_first_token_since?.elapsed();
        let state = if waited >= FIRST_TOKEN_STALL_AFTER {
            FirstTokenState::Stalled
        } else if waited >= FIRST_TOKEN_SLOW_AFTER {
            FirstTokenState::Slow
        } else {
            return None;
        };
        Some(FirstTokenStall { state, waited })
    }

    /// Append streamed assistant text; the in-flight buffer renders as a live markdown block.
    pub(super) fn stream_text(&mut self, delta: &str) {
        // A token arrived: this connection is slow at worst, not stalled (I-64).
        self.awaiting_first_token_since = None;
        self.flush_think();
        if let Some(complete) = self.text_scrubber.push(delta) {
            if complete.is_empty() {
                return;
            }
            self.cur_text.push_str(&ui_safe_text(&complete));
            self.cur_text_revision = self.cur_text_revision.wrapping_add(1);
            self.autoscroll();
        }
    }

    /// Append streamed reasoning; the in-flight buffer renders as a live Thinking block (bounded).
    pub(super) fn stream_think(&mut self, delta: &str) {
        // Extended thinking is the model producing tokens, so it stops the stall clock exactly
        // like text does — the same rule `TurnEnd.ttft_ms` already measures by (I-64).
        self.awaiting_first_token_since = None;
        if let Some(complete) = self.thinking_scrubber.push(delta) {
            if complete.is_empty() {
                return;
            }
            self.cur_think.push_str(&ui_safe_text(&complete));
            self.autoscroll();
        }
        let count = self.cur_think.chars().count();
        if count > 4000 {
            self.cur_think = self.cur_think.chars().skip(count - 4000).collect();
        }
    }

    /// Finalize streamed reasoning into a persisted (collapsed) Thinking block — kept, not wiped.
    pub(super) fn flush_think(&mut self) {
        if let Some(pending) = self.thinking_scrubber.finish() {
            self.cur_think.push_str(&ui_safe_text(&pending));
        }
        if !self.cur_think.trim().is_empty() {
            let t = std::mem::take(&mut self.cur_think);
            self.push_block(block::BlockKind::Thinking {
                text: t,
                open: false,
            });
        } else {
            self.cur_think.clear();
        }
    }

    /// Finalize streamed assistant text into a parsed Assistant markdown block.
    pub(super) fn flush_text(&mut self) {
        self.flush_think();
        if let Some(pending) = self.text_scrubber.finish() {
            self.cur_text.push_str(&ui_safe_text(&pending));
            self.cur_text_revision = self.cur_text_revision.wrapping_add(1);
        }
        if !self.cur_text.trim().is_empty() {
            let t = std::mem::take(&mut self.cur_text);
            self.push_block(block::BlockKind::Assistant(
                crate::markdown::MarkdownDoc::parse(&t),
            ));
        } else {
            self.cur_text.clear();
        }
        self.cur_doc = None;
        self.cur_doc_revision = self.cur_text_revision;
    }

    /// A tool is starting: finalize streaming and expose it in the activity shelf immediately, but
    /// delay its transcript card briefly. This copies Codex's anti-flash state-machine boundary
    /// without borrowing its hook-only deletion policy: Core's current `UiEvent` has no explicit
    /// ephemeral disposition, so every completed model tool still settles into history.
    pub(super) fn tool_start(&mut self, id: String, name: String, args: serde_json::Value) {
        self.tool_start_at(id, name, args, Instant::now());
    }

    pub(super) fn tool_start_at(
        &mut self,
        id: String,
        name: String,
        args: serde_json::Value,
        now: Instant,
    ) {
        self.flush_text();
        let name = ui_safe_text(&name);
        let args = ui_safe_json(&args);
        let activity = block::activity_label(&name, &args);
        self.active_tools.retain(|(active_id, _)| active_id != &id);
        self.active_tools.push_back((id.clone(), activity));
        while self.active_tools.len() > 16 {
            self.active_tools.pop_front();
        }

        // Duplicate starts refresh one projection instead of leaking an orphan running card. A
        // start arriving after reveal keeps the existing id-correlated card; protocol ids are
        // expected to be unique within a run, but a repeated transport notification must be safe.
        if self.tool_index.contains_key(&id) {
            self.autoscroll();
            return;
        }
        self.pending_tools.retain(|pending| pending.id != id);
        while self.pending_tools.len() >= MAX_PENDING_TOOL_PROJECTIONS {
            let oldest = self
                .pending_tools
                .pop_front()
                .expect("the pending projection cap was reached");
            self.reveal_tool(oldest);
        }
        self.pending_tools.push_back(PendingToolProjection {
            id,
            name,
            args,
            started: now,
            reveal_deadline: now + TOOL_REVEAL_DELAY,
        });
        self.autoscroll();
    }

    /// When the next queued tool card stops being suppressed, so the render loop can sleep exactly
    /// that long instead of polling for it.
    pub(super) fn next_tool_reveal(&self) -> Option<Instant> {
        self.pending_tools
            .front()
            .map(|pending| pending.reveal_deadline)
    }

    /// Advance the anti-flash timer. Passing `now` makes the state machine deterministic in tests;
    /// production calls it once per render-loop wakeup, scheduled by `next_tool_reveal`.
    pub(super) fn advance_tool_presentations(&mut self, now: Instant) -> bool {
        let mut changed = false;
        while self
            .pending_tools
            .front()
            .is_some_and(|pending| now >= pending.reveal_deadline)
        {
            let pending = self
                .pending_tools
                .pop_front()
                .expect("front was checked above");
            self.reveal_tool(pending);
            changed = true;
        }
        changed
    }

    pub(super) fn reveal_tool(&mut self, pending: PendingToolProjection) {
        let id = pending.id;
        let card = block::ToolCard {
            name: pending.name,
            args: pending.args,
            status: block::ToolStatus::Running,
            output: String::new(),
            diff: None,
            exit_code: None,
            started: pending.started,
            elapsed: None,
            open: false,
        };
        let bid = self.push_block(block::BlockKind::Tool(card));
        self.tool_index.insert(id, bid);
    }

    /// A tool finished: mutate its originating card by id (R2), or append one if the start was missed.
    pub(super) fn tool_end(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<core_protocol::FileDiff>,
    ) {
        self.tool_end_at(id, ok, exit_code, output, diff, Instant::now());
    }

    pub(super) fn tool_end_at(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<core_protocol::FileDiff>,
        now: Instant,
    ) {
        let output = ui_safe_text(&output);
        self.active_tools.retain(|(active_id, _)| active_id != id);
        let status = if ok {
            block::ToolStatus::Ok
        } else {
            block::ToolStatus::Err
        };

        // A fast completion becomes one already-settled card: no running-row flash, no deletion.
        // Failures, diffs, mutations, and ordinary read/search/list results therefore all retain
        // their transcript evidence until the protocol grows an explicit Ephemeral disposition.
        if let Some(index) = self
            .pending_tools
            .iter()
            .position(|pending| pending.id == id)
        {
            let pending = self
                .pending_tools
                .remove(index)
                .expect("position came from this deque");
            let card = block::ToolCard {
                name: pending.name,
                args: pending.args,
                status,
                output,
                diff,
                exit_code,
                started: pending.started,
                elapsed: Some(now.saturating_duration_since(pending.started)),
                open: false,
            };
            self.push_block(block::BlockKind::Tool(card));
            return;
        }

        if let Some(&bid) = self.tool_index.get(id)
            && let Some(b) = self.transcript.iter_mut().find(|b| b.id == bid)
            && let block::BlockKind::Tool(card) = &mut Arc::make_mut(b).kind
        {
            card.status = status;
            card.output = output;
            card.diff = diff;
            card.exit_code = exit_code;
            card.elapsed = Some(now.saturating_duration_since(card.started));
            Arc::make_mut(b).touch();
            self.tool_index.remove(id);
            self.mark_transcript_changed();
            self.autoscroll();
            return;
        }
        let card = block::ToolCard {
            name: "tool".into(),
            args: serde_json::Value::Null,
            status,
            output,
            diff,
            exit_code,
            started: Instant::now(),
            elapsed: Some(Duration::ZERO),
            open: false,
        };
        self.push_block(block::BlockKind::Tool(card));
    }

    pub(super) fn settle_unfinished_tools(&mut self) {
        let mut ids: Vec<String> = self
            .pending_tools
            .iter()
            .map(|pending| pending.id.clone())
            .chain(self.tool_index.keys().cloned())
            .collect();
        ids.sort();
        ids.dedup();
        for id in ids {
            self.tool_end(
                &id,
                false,
                None,
                "tool ended without a terminal event because the run stopped".into(),
                None,
            );
        }
        self.active_tools.clear();
    }

    pub(super) fn workflow_card_mut(&mut self, run_id: &str) -> Option<&mut block::WorkflowCard> {
        let block_id = *self.workflow_index.get(run_id)?;
        self.transcript
            .iter_mut()
            .find(|block| block.id == block_id)
            .map(Arc::make_mut)
            .and_then(|block| match &mut block.kind {
                block::BlockKind::Workflow(card) => Some(card),
                _ => None,
            })
    }
}
