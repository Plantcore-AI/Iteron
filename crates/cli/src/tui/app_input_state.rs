use super::*;

impl App {
    pub(super) fn autoscroll(&mut self) {
        if self.follow_tail {
            self.bottom_offset = 0;
        } else {
            // Transport deltas are not user-meaningful item counts. This is an honest boolean
            // signal that visible output changed while the operator was reading history.
            self.unread_updates = 1;
        }
        // Bounded: evict the oldest settled blocks past the cap. A nonterminal workflow is a live
        // projection of durable state, so pin its one card until RunFinished arrives; otherwise a
        // long foreground transcript can silently discard the only place the terminal update can
        // land. With the current one-foreground-run TUI there is always an evictable settled block.
        //
        // A live script run's card is pinned for a second reason as well: it is the tree the
        // workflow region draws, and the region renders that card rather than a copy of it (see
        // `workflow_region`). Evicting it would blank the region mid-run — the failure this pin
        // already existed to prevent, on the surface the operator is actually watching.
        if self.transcript.len()
            > iteron_tunables::param_integer("cli.tui.driver_support.max_blocks", MAX_BLOCKS)
        {
            let mut drop = self.transcript.len()
                - iteron_tunables::param_integer("cli.tui.driver_support.max_blocks", MAX_BLOCKS);
            let pinned = self
                .workflow_index
                .values()
                .copied()
                .chain(self.workflow_monitor.live_blocks())
                .collect::<std::collections::HashSet<_>>();
            let mut evicted = std::collections::HashSet::new();
            self.transcript.retain(|block| {
                if drop > 0 && !pinned.contains(&block.id) {
                    drop -= 1;
                    evicted.insert(block.id);
                    false
                } else {
                    true
                }
            });
            self.render_cache
                .retain(|block_id, _| !evicted.contains(block_id));
            self.tool_index.retain(|_, bid| !evicted.contains(bid));
            self.workflow_index.retain(|_, bid| !evicted.contains(bid));
        }
    }

    pub(super) fn follow_latest(&mut self) {
        self.follow_tail = true;
        self.bottom_offset = 0;
        self.unread_updates = 0;
    }

    pub(super) fn set_theme(&mut self, theme: theme::Theme) {
        self.theme = self.color_depth.project_theme(theme);
        self.theme_epoch = self.theme_epoch.wrapping_add(1);
        self.render_cache.clear();
    }

    /// Adopt a theme that late terminal evidence detected AFTER the first frame was painted.
    /// Detection now happens behind the frame, so an identical result must stay a no-op: bumping
    /// the epoch would throw away a warm render cache for a repaint nobody can see.
    pub(super) fn adopt_detected_theme(&mut self, detected: theme::DetectedTheme) -> bool {
        if detected.theme == self.theme {
            return false;
        }
        self.set_theme(detected.theme);
        true
    }

    /// The fallback after an adoption this process could not perform — most often because another
    /// `iteron` process holds that run's exclusive writer lock, which no amount of retrying here will
    /// change. The command is display/copy state only; nothing executes it.
    pub(super) fn prepare_resume_handoff(&mut self, run_id: &str) {
        let command = format_resume_command(run_id);
        self.editor.clear();
        self.editor.insert_str(&command);
        self.completion = None;
        self.resume_handoff = Some(command.clone());
        self.note(
            block::NoticeLevel::Info,
            format!("not resumed here — copy this restart command into a new terminal: {command}"),
        );
    }

    pub(super) fn is_resume_handoff_draft(&self) -> bool {
        self.resume_handoff
            .as_deref()
            .is_some_and(|command| command == self.editor.text())
    }

    pub(super) fn scroll_up(&mut self, rows: u16) {
        self.follow_tail = false;
        self.bottom_offset = self.bottom_offset.saturating_add(rows);
    }

    pub(super) fn scroll_down(&mut self, rows: u16) {
        self.bottom_offset = self.bottom_offset.saturating_sub(rows);
        if self.bottom_offset == 0 {
            self.follow_latest();
        }
    }

    pub(super) fn queue_after_turn(&mut self, text: String) -> Result<(), String> {
        self.queue_after_turn_with(
            text,
            image_input::ImageAttachments::default(),
            file_input::FileAttachments::default(),
        )
    }

    /// Queue a submission together with the chips it was composed with.
    ///
    /// An empty draft is still queued when it carries attachments: "[1 image attachment]" is a real
    /// submission, and the admission check would otherwise drop it as empty and take the images with
    /// it. The admission BOUND (how many may be pending) still applies to both.
    pub(super) fn queue_after_turn_with(
        &mut self,
        text: String,
        images: image_input::ImageAttachments,
        files: file_input::FileAttachments,
    ) -> Result<(), String> {
        let has_attachments = !images.is_empty() || !files.is_empty();
        let pending = self.queued.len().saturating_add(self.steer_previews.len());
        match self.submission_admission(&text, pending, "pending input") {
            SubmissionAdmission::Accept => {
                let mut input = self.pending_input(text);
                input.images = images;
                input.files = files;
                self.queued.push_back(input);
            }
            SubmissionAdmission::IgnoreEmpty if has_attachments => {
                if pending
                    >= iteron_tunables::param_integer(
                        "cli.tui.driver_support.max_pending_submissions",
                        MAX_PENDING_SUBMISSIONS,
                    )
                {
                    return Err(text);
                }
                let mut input = self.pending_input(text);
                input.images = images;
                input.files = files;
                self.queued.push_back(input);
            }
            SubmissionAdmission::IgnoreEmpty => {}
            SubmissionAdmission::Reject => return Err(text),
        }
        Ok(())
    }

    pub(super) fn steer_admission(&mut self, text: &str) -> SubmissionAdmission {
        let pending = self.queued.len().saturating_add(self.steer_previews.len());
        self.submission_admission(text, pending, "pending input")
    }

    pub(super) fn submission_admission(
        &mut self,
        text: &str,
        pending: usize,
        lane: &str,
    ) -> SubmissionAdmission {
        if text.trim().is_empty() {
            return SubmissionAdmission::IgnoreEmpty;
        }
        if text.len()
            > iteron_tunables::param_integer(
                "cli.tui.driver_support.max_submission_bytes",
                MAX_SUBMISSION_BYTES,
            )
        {
            self.note(
                block::NoticeLevel::Warn,
                format!(
                    "{lane} accepts at most {MAX_SUBMISSION_BYTES} bytes; the draft was preserved"
                ),
            );
            return SubmissionAdmission::Reject;
        }
        if pending
            >= iteron_tunables::param_integer(
                "cli.tui.driver_support.max_pending_submissions",
                MAX_PENDING_SUBMISSIONS,
            )
        {
            self.note(
                block::NoticeLevel::Warn,
                format!("{lane} is full; the draft was preserved"),
            );
            return SubmissionAdmission::Reject;
        }
        SubmissionAdmission::Accept
    }

    pub(super) fn track_steer(&mut self, text: String) {
        debug_assert!(!text.trim().is_empty());
        debug_assert!(
            text.len()
                <= iteron_tunables::param_integer(
                    "cli.tui.driver_support.max_submission_bytes",
                    MAX_SUBMISSION_BYTES
                )
        );
        debug_assert!(
            self.steer_previews.len()
                < iteron_tunables::param_integer(
                    "cli.tui.driver_support.max_pending_submissions",
                    MAX_PENDING_SUBMISSIONS
                )
        );
        let input = self.pending_input(text);
        self.steer_previews.push_back(input);
    }

    pub(super) fn pending_input(&mut self, text: String) -> PendingInput {
        let seq = self.next_submission_seq;
        self.next_submission_seq = self.next_submission_seq.wrapping_add(1);
        PendingInput {
            seq,
            text,
            images: image_input::ImageAttachments::default(),
            files: file_input::FileAttachments::default(),
        }
    }

    pub(super) fn requeue_unadmitted(&mut self, unadmitted: Vec<String>) -> (usize, usize) {
        let count = unadmitted.len();
        for text in unadmitted {
            let input = if let Some(preview) = self.steer_previews.pop_front() {
                // A steered submission never carried chips (a draft with any is queued, never
                // steered), so the requeued form has none to restore.
                PendingInput {
                    seq: preview.seq,
                    text,
                    images: image_input::ImageAttachments::default(),
                    files: file_input::FileAttachments::default(),
                }
            } else {
                self.pending_input(text)
            };
            self.queued.push_back(input);
        }
        // The producer join + final event drain should make this empty: every submitted preview is
        // either acknowledged by SteerApplied or returned by take_unadmitted_steers. If those two
        // counts ever disagree, preserve at-least-once operator intent as ordered after-turn input
        // instead of silently dropping the words with `mem::take(...).count()`.
        let unmatched_previews = self.steer_previews.len();
        self.queued.extend(self.steer_previews.drain(..));
        self.queued.make_contiguous().sort_by_key(|input| input.seq);
        debug_assert!(
            self.queued.len()
                <= iteron_tunables::param_integer(
                    "cli.tui.driver_support.max_pending_submissions",
                    MAX_PENDING_SUBMISSIONS
                )
        );
        (count, unmatched_previews)
    }
}
