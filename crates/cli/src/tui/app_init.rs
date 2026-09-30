use super::{
    App, ApprovalChoice, CostState, Editor, Effort, PermissionMode, RouteView, block, hyperlink,
    mouse_capture, theme, transcript_layout, transcript_viewer, ui_safe_text, workflow_region,
    workflows_panel,
};
use ratatui::style::{Color, Style};
#[cfg(test)]
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

impl App {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        let environment = theme::capabilities::Environment::capture();
        let detected = theme::Theme::detect_with(environment, None);
        Self::new_with_detected_theme(detected)
    }

    pub(super) fn new_with_detected_theme(detected: theme::DetectedTheme) -> Self {
        let theme::DetectedTheme { theme, color_depth } = detected;
        // The pet landing is a one-time terminal-native signature in the transcript, not permanent
        // chrome. It progressively collapses with width and naturally scrolls away after work starts.
        let welcome = block::Block::new(
            0,
            block::BlockKind::Welcome {
                tagline: "Iteron · Build, explain, and verify".into(),
            },
        );
        App {
            session_name: "New session".into(),
            transcript: vec![Arc::new(welcome)],
            transcript_viewer: transcript_viewer::Viewer::default(),
            transcript_revision: 0,
            transcript_dirty_from: Some(0),
            next_id: 1,
            tool_index: std::collections::HashMap::new(),
            pending_tools: VecDeque::new(),
            workflow_index: std::collections::HashMap::new(),
            workflow_monitor: workflow_region::WorkflowMonitor::default(),
            workflows_panel: workflows_panel::View::default(),
            workflows_dir: None,
            attached_job: None,
            persistent_agent_views: Vec::new(),
            theme,
            color_depth,
            theme_epoch: 0,
            hyperlink_policy: hyperlink::Policy::disabled(),
            render_cache: std::collections::HashMap::new(),
            render_cache_width: 0,
            render_cache_theme_epoch: 0,
            transcript_layout: transcript_layout::HeightIndex::default(),
            editor: Editor::new(),
            pending_mcp_input: None,
            queued_mcp_inputs: VecDeque::new(),
            status: "idle".into(),
            last_result: None,
            running: false,
            interrupting: false,
            force_cancelling: false,
            cancel_requested_at: None,
            draining: false,
            bottom_offset: 0,
            follow_tail: true,
            unread_updates: 0,
            last_total_rows: 0,
            last_view_h: 0,
            quit: false,
            force_quit_requested: false,
            ctrl_c_quit_deadline: None,
            keymap_status: "keys:standard".into(),
            vim_anchor: None,
            cur_text: String::new(),
            assistant_stream_authority: String::new(),
            assistant_turn_block_ids: Vec::new(),
            cur_text_revision: 0,
            cur_doc_revision: 0,
            cur_doc: None,
            cur_doc_parse: crate::markdown::StreamingParse::default(),
            live_markdown_layout: Default::default(),
            text_scrubber: crate::machine_projection::StreamingScrubber::default(),
            cur_think: String::new(),
            thinking_scrubber: crate::machine_projection::StreamingScrubber::default(),
            mode: PermissionMode::default(),
            effort: Effort::default(),
            model: String::new(),
            route: RouteView::unresolved(),
            cost: CostState::Zero,
            last_turn_usage: None,
            last_context: None,
            model_context_window: None,
            reserved_output_tokens: None,
            compaction_trigger_tokens: iteron_ctx::CompactionPolicy::default().trigger_tokens,
            effort_application: None,
            turns: 0,
            pending: None,
            approval_choice: ApprovalChoice::Deny,
            completions: super::completion_owner::CompletionOwner::default(),
            pickers: super::picker_owner::PickerOwner::default(),
            navigation: super::session_navigation::SessionNavigationOwner::default(),
            workspace_command_job: None,
            attachments: super::attachment_owner::AttachmentOwner::default(),
            activities: std::collections::BTreeMap::new(),
            retired_activity_ids: VecDeque::new(),
            resume_handoff: None,
            run_started: None,
            last_run_latency: None,
            workspace_dirty: None,
            retryable_task: None,
            awaiting_first_token_since: None,
            provider_accepted: false,
            active_tools: VecDeque::new(),
            spin: 0,
            row_map: Vec::new(),
            view_top: 0,
            view_scroll: 0,
            view_h: 0,
            mouse_capture: mouse_capture::State::default(),
            input_lanes: super::input_lanes::InputLanes::default(),
            pending_turn_receipt: None,
            pending_approval_response: None,
            product_stream_active: false,
            product_terminal_answer: None,
            product_turn_status: None,
            #[cfg(test)]
            refused_image_paths: HashSet::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn refresh_completion(&mut self, repo: &std::path::Path) {
        self.completions.refresh(&self.editor, repo);
    }
    pub(super) fn schedule_completion(&mut self) {
        self.completions.schedule(&self.editor, Instant::now());
    }
    pub(super) fn accept_completion(&mut self) {
        self.completions.accept(&mut self.editor);
    }
    pub(super) fn accept_completion_for_enter(&mut self) -> bool {
        let submit = self.completions.enter_submits();
        self.completions.accept(&mut self.editor);
        submit
    }

    /// Push a single-line harness notice. The old `push(style,text)` sites keep working, but the
    /// STYLE is now mapped to a semantic `NoticeLevel` and rendered as a structured `Notice` block —
    /// there is NO plain-text path (R7.e). Color literal encodes intent: green→Ok, red→Err,
    /// yellow→Warn, else→Info.
    pub(super) fn push(&mut self, style: Style, text: impl Into<String>) {
        let level = match style.fg {
            Some(Color::Green) => block::NoticeLevel::Ok,
            Some(Color::Red) => block::NoticeLevel::Err,
            Some(Color::Yellow) => block::NoticeLevel::Warn,
            _ => block::NoticeLevel::Info,
        };
        self.note(level, text);
    }

    /// Push a one-line notice at an explicit level.
    pub(super) fn note(&mut self, level: block::NoticeLevel, text: impl Into<String>) {
        self.flush_text();
        self.push_block(block::BlockKind::Notice {
            level,
            text: ui_safe_text(&text.into()),
        });
    }

    /// Push a completed operator `!shell` command as an OPEN Tool card (❯ Run · output · ✓/✗) —
    /// never plain lines (R7.b "see shell").
    pub(super) fn push_shell_card(
        &mut self,
        cmd: &str,
        mut output: String,
        ok: bool,
        exit_code: i32,
    ) {
        self.flush_text();
        let cmd = ui_safe_text(cmd);
        output = ui_safe_text(&output);
        if !ok {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(&format!("[exit {exit_code}]"));
        }
        let card = block::ToolCard {
            name: "bash".into(),
            args: serde_json::json!({ "command": cmd }),
            status: if ok {
                block::ToolStatus::Ok
            } else {
                block::ToolStatus::Err
            },
            output,
            diff: None,
            exit_code: Some(exit_code),
            started: Instant::now(),
            elapsed: Some(Duration::ZERO),
            open: true, // shell output is the point — default open
        };
        self.push_block(block::BlockKind::Tool(card));
    }

    /// Push a structured command-output Panel (titled card of typed rows). Rows are bounded (C4).
    // `_icon` is retained in the signature so the ~13 call sites read cleanly, but the per-panel icon
    // is no longer rendered (TUI v3 §2 deleted the panel icons — the title carries identity).
    pub(super) fn panel(&mut self, _icon: &str, title: &str, mut rows: Vec<block::PanelRow>) {
        const CAP: usize = 120;
        if rows.len() > iteron_tunables::param_integer("cli.tui.app_init.cap", CAP) {
            let extra = rows.len() - iteron_tunables::param_integer("cli.tui.app_init.cap", CAP);
            rows.truncate(iteron_tunables::param_integer("cli.tui.app_init.cap", CAP));
            rows.push(block::PanelRow::Note(format!("… {extra} more")));
        }
        for row in &mut rows {
            match row {
                block::PanelRow::KeyValue { key, value } => {
                    *key = ui_safe_text(key);
                    *value = ui_safe_text(value);
                }
                block::PanelRow::Item { label, hint } => {
                    *label = ui_safe_text(label);
                    *hint = ui_safe_text(hint);
                }
                block::PanelRow::Note(text) => *text = ui_safe_text(text),
            }
        }
        self.flush_text();
        self.push_block(block::BlockKind::Panel {
            title: ui_safe_text(title),
            rows,
        });
    }
}
