//! The ordinary terminal's bounded Product V1 cursor. Headless and TUI read the same resident
//! Thread/Turn/Item projection; EQ still carries rich local metrics and legacy tool cards.

use super::*;
use iteron_protocol::product_contract::{
    ItemContentChannelV1, PRODUCT_CONTRACT_VERSION, ProductEventKindV1, ProductEventsPageV1,
    ProductEventsReadErrorV1, TurnStateV1,
};

const MAX_PAGES_PER_EQ_EVENT: usize = 8;
const MAX_TERMINAL_TEXT_BYTES: usize = 256 * 1024;

#[derive(Default)]
pub(super) struct ProductProjection {
    cursor: u64,
    thread_id: Option<iteron_protocol::SessionId>,
    run_id: Option<iteron_protocol::RunId>,
    final_answer: String,
    final_seen: bool,
    final_complete: bool,
}

impl ProductProjection {
    /// A product event may already exist when its EQ envelope is read. Restrict projection to
    /// this envelope's source sequence so a busy producer cannot paint later-turn content early.
    pub(super) fn sync(
        &mut self,
        app: &mut App,
        client: &app_server::AppServerClient,
        source_seq: u64,
    ) {
        let Some(snapshot) = client.thread_snapshot_v1() else {
            app.product_stream_active = false;
            app.product_turn_status = None;
            return;
        };
        if snapshot.contract_version != PRODUCT_CONTRACT_VERSION {
            app.product_stream_active = false;
            app.product_turn_status = None;
            return;
        }
        if self.thread_id.as_ref() != Some(&snapshot.thread_id) {
            self.cursor = 0;
            self.thread_id = Some(snapshot.thread_id.clone());
            self.run_id = None;
        }
        self.select_run(app, snapshot.run_id.clone());
        app.product_stream_active = true;
        app.product_turn_status = snapshot.turn.as_ref().map(|turn| {
            format!(
                "turn {} · {} item{}{}",
                turn.turn_id.0,
                turn.items.len(),
                if turn.items.len() == 1 { "" } else { "s" },
                if turn.omitted_items > 0 {
                    format!(" · {} omitted", turn.omitted_items)
                } else {
                    String::new()
                }
            )
        });

        for _ in 0..iteron_tunables::param_integer(
            "cli.tui.product_projection.max_pages_per_eq_event",
            MAX_PAGES_PER_EQ_EVENT,
        ) {
            let Some(page) = client.product_events_read_v1(self.cursor) else {
                app.product_stream_active = false;
                return;
            };
            let page = match page {
                Ok(page) => page,
                Err(ProductEventsReadErrorV1::CursorAhead { latest_cursor, .. }) => {
                    app.note(block::NoticeLevel::Warn, "product cursor moved beyond the resident event ring; live content will resume from its current head");
                    self.cursor = latest_cursor;
                    return;
                }
            };
            if page.contract_version != PRODUCT_CONTRACT_VERSION
                || self.thread_id.as_ref() != Some(&page.thread_id)
            {
                app.product_stream_active = false;
                app.note(
                    block::NoticeLevel::Err,
                    "product event identity changed during terminal projection",
                );
                return;
            }
            let previous = self.cursor;
            let reached_terminal = self.ingest_page(app, page, source_seq);
            if self.cursor == previous || reached_terminal {
                break;
            }
        }
    }

    /// A run rebind keeps the thread's monotonic Product cursor. The App Server retains old-run
    /// events in that ring, so resetting to zero would replay old assistant text into the new run.
    pub(super) fn select_run(&mut self, app: &mut App, run_id: iteron_protocol::RunId) {
        if self.run_id.as_ref() == Some(&run_id) {
            return;
        }
        self.run_id = Some(run_id);
        self.final_answer.clear();
        self.final_seen = false;
        self.final_complete = true;
        app.product_terminal_answer = None;
    }

    pub(super) fn ingest_page(
        &mut self,
        app: &mut App,
        page: ProductEventsPageV1,
        source_seq: u64,
    ) -> bool {
        if let Some(gap) = page.gap
            && gap.oldest_available > self.cursor.saturating_add(1)
        {
            app.note(
                block::NoticeLevel::Warn,
                format!(
                    "product content gap after event {}; resumed at {}",
                    self.cursor, gap.oldest_available
                ),
            );
            self.cursor = gap.oldest_available - 1;
            self.final_complete = false;
        }
        for event in page.events {
            if event.event_seq <= self.cursor {
                continue;
            }
            if event.source_event_seq.is_some_and(|seq| seq > source_seq) {
                break;
            }
            if event.event_seq != self.cursor.saturating_add(1) {
                app.note(block::NoticeLevel::Warn, "product event sequence skipped; final answer will require terminal reconciliation");
                self.final_complete = false;
            }
            self.cursor = event.event_seq;
            if self
                .run_id
                .as_ref()
                .is_some_and(|run_id| run_id != &event.run_id)
            {
                continue;
            }
            let reached_terminal = matches!(&event.event, ProductEventKindV1::TurnEnded { .. });
            self.apply_event(app, event.event);
            // TurnStarted has no source EQ sequence. A producer can admit the next turn while the
            // TUI is still reading this run's terminal envelope; do not let its unsequenced start
            // erase the exact terminal answer before RunEnded consumes it.
            if reached_terminal {
                return true;
            }
        }
        false
    }

    fn apply_event(&mut self, app: &mut App, event: ProductEventKindV1) {
        match event {
            ProductEventKindV1::TurnStarted { .. } => {
                self.final_answer.clear();
                self.final_seen = false;
                self.final_complete = true;
                app.product_terminal_answer = None;
            }
            ProductEventKindV1::ItemContent { channel, content } => match channel {
                ItemContentChannelV1::Assistant => app.stream_text(&content),
                ItemContentChannelV1::Reasoning => app.stream_think(&content),
                ItemContentChannelV1::FinalAnswer => {
                    self.final_seen = true;
                    if self.final_answer.len().saturating_add(content.len())
                        <= iteron_tunables::param_integer(
                            "cli.tui.product_projection.max_terminal_text_bytes",
                            MAX_TERMINAL_TEXT_BYTES,
                        )
                    {
                        self.final_answer.push_str(&content);
                    } else {
                        self.final_complete = false;
                    }
                }
                ItemContentChannelV1::ToolInputJson | ItemContentChannelV1::ToolOutput => {}
            },
            ProductEventKindV1::ContentOmitted { channel, .. } => {
                if matches!(
                    channel,
                    ItemContentChannelV1::Assistant | ItemContentChannelV1::FinalAnswer
                ) {
                    self.final_complete = false;
                    app.note(block::NoticeLevel::Warn, "product answer exceeded the resident content bound; terminal text requires reconciliation");
                }
            }
            ProductEventKindV1::Submission { receipt } => {
                if receipt.state == iteron_protocol::SubmissionLifecycleState::Applied {
                    app.settle_steer_submission(receipt.submission_id);
                }
                if app.pending_approval_response == Some(receipt.submission_id) {
                    match receipt.state {
                        iteron_protocol::SubmissionLifecycleState::Applied => {
                            app.status =
                                "approval response applied · awaiting tool decision".into();
                        }
                        iteron_protocol::SubmissionLifecycleState::Rejected
                        | iteron_protocol::SubmissionLifecycleState::Expired => {
                            app.pending_approval_response = None;
                            app.status =
                                "approval response rejected · prompt remains pending".into();
                        }
                        _ => {}
                    }
                }
            }
            ProductEventKindV1::ApprovalRequested {
                approval_id,
                tool,
                capability,
                reason,
                arguments_json,
                workspace,
                prompt_complete,
            } => {
                if app
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.id != approval_id)
                {
                    app.pending_approval_response = None;
                }
                app.flush_text();
                app.transcript_viewer.close();
                app.approval_choice = ApprovalChoice::Deny;
                app.pending = Some(Pending {
                    id: approval_id,
                    tool: ui_safe_text(&tool),
                    cap: capability,
                    reason: ui_safe_text(&reason),
                    arguments: arguments_json
                        .and_then(|json| serde_json::from_str(&json).ok())
                        .map(|json| ui_safe_json(&json))
                        .unwrap_or(serde_json::Value::Null),
                    workspace: ui_safe_text(&workspace),
                    prompt_complete,
                });
                app.status = "approval required".into();
            }
            ProductEventKindV1::ApprovalResolved {
                approval_id,
                resolution,
                reason_code,
            } => {
                if app
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.id == approval_id)
                {
                    app.pending = None;
                    app.pending_approval_response = None;
                    app.status = format!(
                        "approval {} · {}",
                        match resolution {
                            iteron_protocol::product_contract::ApprovalResolutionV1::Approved =>
                                "approved · tool pending",
                            iteron_protocol::product_contract::ApprovalResolutionV1::Denied =>
                                "denied",
                            iteron_protocol::product_contract::ApprovalResolutionV1::Cancelled =>
                                "cancelled",
                            iteron_protocol::product_contract::ApprovalResolutionV1::TimedOut =>
                                "timed out",
                        },
                        ui_safe_text(&reason_code)
                    );
                }
            }
            ProductEventKindV1::SourceGap { dropped } => {
                self.final_complete = false;
                app.note(
                    block::NoticeLevel::Warn,
                    format!(
                        "product source lost {dropped} update(s); terminal answer will reconcile"
                    ),
                );
            }
            ProductEventKindV1::TurnEnded {
                state,
                terminal_text_exact,
                ..
            } => {
                if terminal_text_exact && self.final_seen && self.final_complete {
                    let answer = self.final_answer.clone();
                    app.finish_text_boundary();
                    app.reconcile_terminal_assistant(&answer);
                    app.product_terminal_answer = Some(answer);
                }
                if state == TurnStateV1::Failed {
                    app.status = "turn failed · finalizing".into();
                }
            }
            ProductEventKindV1::TerminalTextUnavailable { .. } => {
                self.final_complete = false;
            }
            ProductEventKindV1::ItemStarted { .. } | ProductEventKindV1::ItemEnded { .. } => {}
        }
    }
}
