use super::{
    App, MAX_BLOCKS, MAX_SUBMISSION_BYTES, SubmissionAdmission, SubmissionId, block, file_input,
    format_resume_command, image_input, theme,
};

impl App {
    pub(super) fn autoscroll(&mut self) {
        self.viewport.observe_output();
        let pinned = self
            .history
            .live_workflow_blocks()
            .chain(self.workflow_monitor.live_blocks())
            .collect::<std::collections::HashSet<_>>();
        let evicted = self.history.evict_settled(
            iteron_tunables::param_integer("cli.tui.driver_support.max_blocks", MAX_BLOCKS),
            &pinned,
        );
        self.geometry.forget(&evicted);
        self.tools.forget_blocks(&evicted);
    }

    pub(super) fn follow_latest(&mut self) {
        self.viewport.follow_latest();
    }

    pub(super) fn set_theme(&mut self, theme: theme::Theme) {
        self.theme = self.color_depth.project_theme(theme);
        self.theme_epoch = self.theme_epoch.wrapping_add(1);
        self.geometry.clear();
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
        self.completions.dismiss();
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
        self.viewport.scroll_up(rows);
    }
    pub(super) fn scroll_down(&mut self, rows: u16) {
        self.viewport.scroll_down(rows);
    }

    pub(super) fn queue_after_turn(&mut self, text: String) -> Result<(), String> {
        self.queue_after_turn_with_draft(
            text,
            image_input::ImageAttachments::default(),
            file_input::FileAttachments::default(),
            None,
        )
        .map_err(|refusal| refusal.into_owned_draft().text)
    }

    /// Acceptance transfers the complete draft to the lane. Refusal returns every owned store;
    /// the composer adapter keeps its original draft until this port actually accepts it.
    pub(super) fn queue_after_turn_with_draft(
        &mut self,
        text: String,
        images: image_input::ImageAttachments,
        files: file_input::FileAttachments,
        draft: Option<crate::editor::QueuedDraftMetadata>,
    ) -> Result<(), Box<super::input_lanes::QueueRefusal>> {
        match self.input_lanes.queue(text, images, files, draft) {
            Ok(()) => Ok(()),
            Err(refusal) => {
                self.note_lane_refusal(refusal.reason, "pending input");
                Err(refusal)
            }
        }
    }

    pub(super) fn steer_admission(&mut self, text: &str) -> SubmissionAdmission {
        let pending = self.input_lanes.pending_count();
        self.submission_admission(text, pending, "pending input")
    }

    pub(super) fn submission_admission(
        &mut self,
        text: &str,
        pending: usize,
        lane: &str,
    ) -> SubmissionAdmission {
        match super::input_lanes::InputLanes::admission(text, pending) {
            Ok(admission) => admission,
            Err(reason) => {
                self.note_lane_refusal(reason, lane);
                SubmissionAdmission::Reject
            }
        }
    }

    fn note_lane_refusal(&mut self, reason: super::input_lanes::LaneRefusal, lane: &str) {
        let text = match reason {
            super::input_lanes::LaneRefusal::TooLarge => format!(
                "{lane} accepts at most {MAX_SUBMISSION_BYTES} bytes; the draft was preserved"
            ),
            super::input_lanes::LaneRefusal::Full => {
                format!("{lane} is full; the draft was preserved")
            }
        };
        self.note(block::NoticeLevel::Warn, text);
    }

    pub(super) fn track_steer(&mut self, text: String, id: SubmissionId) {
        self.input_lanes.track_steer(text, id);
    }

    pub(super) fn settle_steer_submission(&mut self, id: SubmissionId) {
        self.input_lanes.settle_steer_submission(id);
    }

    pub(super) fn requeue_unadmitted(
        &mut self,
        unadmitted: Vec<String>,
        submission_ids: &[Option<SubmissionId>],
    ) -> (usize, usize) {
        let report = self
            .input_lanes
            .requeue_unadmitted(unadmitted, submission_ids);
        if report.foreign > 0 {
            self.note(block::NoticeLevel::Info, format!("{} unadmitted steering submission(s) belong to another client; this TUI did not resubmit them", report.foreign));
        }
        if report.legacy_unrestored > 0 {
            self.note(block::NoticeLevel::Warn, format!("{} legacy steering submission(s) have no matched frontend identity or pending capacity; inspect the session before resubmitting", report.legacy_unrestored));
        }
        (report.queued, report.unmatched)
    }
}
