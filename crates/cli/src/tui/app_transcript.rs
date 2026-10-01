use super::tool_presentations::ToolReveal;
use super::{
    App, Duration, FIRST_TOKEN_SLOW_AFTER, FIRST_TOKEN_STALL_AFTER, FirstTokenStall,
    FirstTokenState, Instant, block, ui_safe_text,
};

impl App {
    /// Push a structured block, assigning a monotonic id; returns the id.
    pub(super) fn push_block(&mut self, kind: block::BlockKind) -> u64 {
        let id = self.history.append(kind);
        self.autoscroll();
        id
    }

    pub(super) fn mark_transcript_changed(&mut self) {
        self.history.mark_changed_from(0);
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
        if !self.run.running() {
            return None;
        }
        let wait = self.activity_observations.provider_wait()?;
        let waited = wait.started.elapsed();
        let state = if waited
            >= iteron_tunables::param_duration(
                "cli.tui.first_token_stall_after",
                FIRST_TOKEN_STALL_AFTER,
            ) {
            FirstTokenState::Stalled
        } else if waited
            >= iteron_tunables::param_duration(
                "cli.tui.first_token_slow_after",
                FIRST_TOKEN_SLOW_AFTER,
            )
        {
            FirstTokenState::Slow
        } else {
            return None;
        };
        Some(FirstTokenStall {
            state,
            waited,
            accepted: wait.accepted,
        })
    }

    pub(super) fn stream_text(&mut self, delta: &str) {
        self.activity_observations.finish_provider_wait();
        self.flush_think();
        if self.assistant.append_text(delta) {
            self.autoscroll();
        }
    }
    pub(super) fn stream_think(&mut self, delta: &str) {
        self.activity_observations.finish_provider_wait();
        if self.assistant.append_thinking(delta) {
            self.autoscroll();
        }
    }
    pub(super) fn flush_think(&mut self) {
        if let Some(text) = self.assistant.take_thinking() {
            self.push_block(block::BlockKind::Thinking { text, open: false });
        }
    }
    pub(super) fn flush_text(&mut self) {
        self.flush_think();
        if let Some(document) = self.assistant.take_document() {
            let id = self.push_block(block::BlockKind::Assistant(document));
            self.assistant.track_block(id);
        }
    }
    pub(super) fn finish_text_boundary(&mut self) {
        self.assistant.finish_text_boundary();
    }
    pub(super) fn reconcile_terminal_assistant(&mut self, authoritative: &str) -> bool {
        let (block_ids, document) = match self.assistant.reconcile(authoritative) {
            super::assistant_stream::Reconciliation::Unchanged => return false,
            super::assistant_stream::Reconciliation::Appended => {
                self.autoscroll();
                return false;
            }
            super::assistant_stream::Reconciliation::Replace {
                block_ids,
                document,
            } => (block_ids, document),
        };
        let ids = block_ids
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        self.geometry.forget(&ids);
        if let Some(id) = self.history.replace_answer(&ids, document) {
            self.assistant.track_block(id);
        }
        self.autoscroll();
        true
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
        for revealed in self.tools.start(id, name, args, now) {
            self.reveal_tool(revealed);
        }
        self.autoscroll();
    }

    /// When the next queued tool card stops being suppressed, so the render loop can sleep exactly
    /// that long instead of polling for it.
    pub(super) fn next_tool_reveal(&self) -> Option<Instant> {
        self.tools.next_reveal()
    }

    /// Advance the anti-flash timer. Passing `now` makes the state machine deterministic in tests;
    /// production calls it once per render-loop wakeup, scheduled by `next_tool_reveal`.
    pub(super) fn advance_tool_presentations(&mut self, now: Instant) -> bool {
        let mut changed = false;
        while let Some(pending) = self.tools.take_due(now) {
            self.reveal_tool(pending);
            changed = true;
        }
        changed
    }

    pub(super) fn reveal_tool(&mut self, pending: ToolReveal) {
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
        self.tools.bind_revealed(id, bid);
    }

    /// A tool finished: mutate its originating card by id (R2), or append one if the start was missed.
    pub(super) fn tool_end(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<iteron_protocol::FileDiff>,
    ) {
        self.tool_end_at(id, ok, exit_code, output, diff, Instant::now());
    }

    pub(super) fn tool_end_at(
        &mut self,
        id: &str,
        ok: bool,
        exit_code: Option<i32>,
        output: String,
        diff: Option<iteron_protocol::FileDiff>,
        now: Instant,
    ) {
        let output = ui_safe_text(&output);
        self.tools.finish_activity(id);
        let status = if ok {
            block::ToolStatus::Ok
        } else {
            block::ToolStatus::Err
        };

        // A fast completion becomes one already-settled card: no running-row flash, no deletion.
        // Failures, diffs, mutations, and ordinary read/search/list results therefore all retain
        // their transcript evidence until the protocol grows an explicit Ephemeral disposition.
        if let Some(pending) = self.tools.take_pending(id) {
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

        if let Some(bid) = self.tools.revealed_block(id)
            && self.history.is_tool(bid)
        {
            self.history
                .settle_tool(bid, status, output, diff, exit_code, now);
            self.tools.finish(id);
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
        let ids = self.tools.unfinished_ids();
        for id in ids {
            self.tool_end(
                &id,
                false,
                None,
                "tool ended without a terminal event because the run stopped".into(),
                None,
            );
        }
        self.tools.clear();
    }
}

#[cfg(test)]
mod terminal_reconcile_tests {
    use super::*;

    fn visible_current_answer(app: &App) -> String {
        app.history
            .blocks()
            .iter()
            .filter(|block| app.assistant.block_ids().contains(&block.id))
            .filter_map(|block| match &block.kind {
                block::BlockKind::Assistant(document) => Some(document.to_text()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn terminal_authority_rebuilds_middle_gap_and_rewrite_exactly() {
        let mut app = App::new();
        app.assistant.fixture_authority("abef".into());
        let id = app.push_block(block::BlockKind::Assistant(
            crate::markdown::MarkdownDoc::parse("abef"),
        ));
        app.assistant.track_block(id);

        assert!(app.reconcile_terminal_assistant("abcdef"));
        assert_eq!(visible_current_answer(&app), "abcdef");
        assert_eq!(app.assistant.authority(), "abcdef");

        assert!(app.reconcile_terminal_assistant("rewritten answer"));
        assert_eq!(visible_current_answer(&app), "rewritten answer");
        assert_eq!(app.assistant.authority(), "rewritten answer");
    }

    #[test]
    fn terminal_authority_rebuilds_duplicate_delta_without_touching_other_cards() {
        let mut app = App::new();
        let prior = app.push_block(block::BlockKind::User("prior turn".into()));
        app.assistant.fixture_authority("abcabc".into());
        let duplicated = app.push_block(block::BlockKind::Assistant(
            crate::markdown::MarkdownDoc::parse("abcabc"),
        ));
        app.assistant.track_block(duplicated);
        let tool = app.push_block(block::BlockKind::Notice {
            level: block::NoticeLevel::Info,
            text: "tool card".into(),
        });

        assert!(app.reconcile_terminal_assistant("abc"));
        assert_eq!(visible_current_answer(&app), "abc");
        assert_eq!(app.assistant.authority(), "abc");
        assert!(app.history.blocks().iter().any(|block| block.id == prior));
        assert!(app.history.blocks().iter().any(|block| block.id == tool));
        assert!(
            !app.history
                .blocks()
                .iter()
                .any(|block| block.id == duplicated)
        );
    }

    #[test]
    fn terminal_authority_adds_only_a_missing_suffix() {
        let mut app = App::new();
        app.stream_text("arbitrary");
        app.finish_text_boundary();

        assert!(!app.reconcile_terminal_assistant("arbitrary chunking"));
        app.flush_text();
        assert_eq!(visible_current_answer(&app), "arbitrary chunking");
        assert_eq!(
            app.assistant.block_ids().len(),
            1,
            "terminal suffix reconciliation must not split one answer with a blank transcript row"
        );
    }
}
