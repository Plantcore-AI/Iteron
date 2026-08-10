use super::*;

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
            next_id: 1,
            tool_index: std::collections::HashMap::new(),
            pending_tools: VecDeque::new(),
            workflow_index: std::collections::HashMap::new(),
            workflow_monitor: workflow_region::WorkflowMonitor::default(),
            workflows_panel: workflows_panel::View::default(),
            workflows_dir: None,
            attached_job: None,
            theme,
            color_depth,
            theme_epoch: 0,
            hyperlink_policy: hyperlink::Policy::disabled(),
            render_cache: std::collections::HashMap::new(),
            render_cache_width: 0,
            render_cache_theme_epoch: 0,
            editor: Editor::new(),
            status: "idle".into(),
            last_result: None,
            running: false,
            interrupting: false,
            force_cancelling: false,
            draining: false,
            bottom_offset: 0,
            follow_tail: true,
            unread_updates: 0,
            last_total_rows: 0,
            last_view_h: 0,
            quit: false,
            keymap_status: "keys:standard".into(),
            vim_anchor: None,
            cur_text: String::new(),
            cur_text_revision: 0,
            cur_doc_revision: 0,
            cur_doc: None,
            cur_doc_parse: crate::markdown::StreamingParse::default(),
            text_scrubber: crate::output::StreamingScrubber::default(),
            cur_think: String::new(),
            thinking_scrubber: crate::output::StreamingScrubber::default(),
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
            completion: None,
            picker: None,
            resume_handoff: None,
            run_started: None,
            retryable_task: None,
            awaiting_first_token_since: None,
            active_tools: VecDeque::new(),
            spin: 0,
            row_map: Vec::new(),
            view_top: 0,
            view_scroll: 0,
            view_h: 0,
            mouse_capture: mouse_capture::State::default(),
            queued: VecDeque::new(),
            steer_previews: VecDeque::new(),
            next_submission_seq: 0,
            pending_turn_receipt: None,
            refused_image_paths: HashSet::new(),
        }
    }

    /// Recompute the autocomplete menu from the current editor state (called after each edit while
    /// idle or while composing a queued follow-up). Sets `self.completion` to a slash menu, a file
    /// menu, or None. A running agent must not degrade the editor into a text-only field.
    pub(super) fn refresh_completion(&mut self, repo: &std::path::Path) {
        self.completion = None;
        let text = self.editor.text();
        if text.contains('\n') {
            return; // no menu in multi-line mode
        }
        // slash-command menu
        if let Some(prefix) = commands::slash_prefix(&text) {
            let items: Vec<(String, String)> = commands::complete_slash(prefix)
                .into_iter()
                .map(|c| (c.name.to_string(), format!("{}  {}", c.args, c.help)))
                .collect();
            if !items.is_empty() {
                self.completion = Some(Completion {
                    items,
                    sel: 0,
                    token_start: 1,
                    lead: '/',
                });
            }
            return;
        }
        // @file menu (path completion at the cursor)
        let cursor_bytes = byte_index(&text, self.editor.cursor());
        if let Some((at, partial)) = commands::at_mention_at(&text, cursor_bytes) {
            let matches = complete_path(repo, partial);
            if !matches.is_empty() {
                let items = matches.into_iter().map(|p| (p, String::new())).collect();
                self.completion = Some(Completion {
                    items,
                    sel: 0,
                    token_start: at + 1,
                    lead: '@',
                });
            }
        }
    }

    /// Accept the selected completion: replace the WHOLE token (from `token_start` to the next
    /// whitespace or end — not just up to the cursor) with the chosen item + a single trailing
    /// space, and place the cursor right after it. Replacing the whole token fixes corruption when
    /// the cursor is in the middle of the token (review).
    pub(super) fn accept_completion(&mut self) {
        let Some(comp) = self.completion.take() else {
            return;
        };
        let Some((item, _)) = comp.items.get(comp.sel).cloned() else {
            return;
        };
        let text = self.editor.text();
        let token_end = text[comp.token_start.min(text.len())..]
            .find(char::is_whitespace)
            .map(|i| comp.token_start + i)
            .unwrap_or(text.len());
        // A directory item (ends with '/') gets NO trailing space, so the mention token stays open
        // and the menu re-populates for drill-down (review: accepting a dir closed the menu).
        let sep = if item.ends_with('/') { "" } else { " " };
        let mut new = String::new();
        new.push_str(&text[..comp.token_start]);
        new.push_str(&item);
        new.push_str(sep);
        new.push_str(text[token_end..].trim_start_matches(' ')); // avoid a double space
        let want =
            text[..comp.token_start].chars().count() + item.chars().count() + sep.chars().count();
        self.editor.clear();
        self.editor.insert_str(&new);
        self.editor.home();
        for _ in 0..want {
            self.editor.right();
        }
    }

    /// Enter activates a slash-menu entry when the command has no required arguments. Tab remains
    /// completion-only, and commands with required arguments (for example `/memory`) leave the
    /// composer open for the missing value. Keeping this decision separate from dispatch prevents
    /// one physical Enter from both opening a picker and accepting its first row.
    pub(super) fn accept_completion_for_enter(&mut self) -> bool {
        let submit = self.completion.as_ref().is_some_and(|completion| {
            if completion.lead != '/' {
                return false;
            }
            let Some((name, _)) = completion.items.get(completion.sel) else {
                return false;
            };
            commands::COMMANDS.iter().any(|command| {
                command.name == name && (command.args.is_empty() || command.args.starts_with('['))
            })
        });
        self.accept_completion();
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
        if rows.len() > CAP {
            let extra = rows.len() - CAP;
            rows.truncate(CAP);
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
