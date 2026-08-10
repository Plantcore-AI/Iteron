use super::*;

impl App {
    /// Project one script-engine lifecycle message onto the live phase→agent tree (ADR-0001 step 1,
    /// `crate::workflow::WorkflowRunUiEvent`).
    ///
    /// The three shapes are the three things the card needs that the `ProgressEvent` stream cannot
    /// say on its own: when a run BEGINS (so the card exists, named, with its declared phase boxes
    /// already laid out), what happened next, and when the run SETTLED — `ingest` never sets
    /// `finished`, so without the last one the tree would spin for the rest of the session. The
    /// match is total: a new seam variant does not compile until it is rendered.
    pub(super) fn workflow_run_ui_event(&mut self, event: crate::workflow::WorkflowRunUiEvent) {
        match event {
            crate::workflow::WorkflowRunUiEvent::KernelActivity {
                kind,
                output_chars,
                thinking_chars,
            } => {
                if output_chars > 0 || thinking_chars > 0 {
                    self.awaiting_first_token_since = None;
                }
                self.status = match (output_chars, thinking_chars) {
                    (0, 0) => kind.label().to_string(),
                    (output, 0) => format!(
                        "{} · {} chars",
                        kind.label(),
                        fmt_token_count(output as u64)
                    ),
                    (0, thinking) => format!(
                        "{} · {} reasoning chars",
                        kind.label(),
                        fmt_token_count(thinking as u64)
                    ),
                    (output, thinking) => format!(
                        "{} · {} chars · {} reasoning",
                        kind.label(),
                        fmt_token_count(output as u64),
                        fmt_token_count(thinking as u64)
                    ),
                };
            }
            crate::workflow::WorkflowRunUiEvent::Started {
                run_id,
                name,
                phases,
            } => self.workflow_run_started(&run_id, &name, &phases),
            // The name is only read if `Started` never arrived, which the EQ's authoritative
            // delivery rules out; `list_runs` uses the same word for a run whose manifest is
            // missing, so an unnamed card reads the same way there and here.
            crate::workflow::WorkflowRunUiEvent::Progress { run_id, event } => {
                self.workflow_run_event(&run_id, "workflow", event)
            }
            crate::workflow::WorkflowRunUiEvent::Finished { run_id, .. } => {
                self.workflow_run_finished(&run_id)
            }
        }
    }

    /// Open the card for a run before its first event, seeded with the script's declared
    /// `meta.phases` so the whole shape of the run is on the first frame. Idempotent: a repeated
    /// `Started` for a live run re-declares nothing (`declare_phases` skips titles it already has).
    pub(super) fn workflow_run_started(&mut self, run_id: &str, name: &str, phases: &[String]) {
        if self.workflow_run_card_mut(run_id).is_none() {
            self.flush_text();
            let card = block::WorkflowRunCard::new(
                ui_safe_text(run_id),
                crate::workflow::ui_safe_label(name),
            );
            let block_id = self.push_block(block::BlockKind::WorkflowRun(card));
            self.workflow_monitor.ingest(
                run_id,
                workflow_region::WorkflowRunSignal::Live { block_id },
            );
        }
        let block_id = self.workflow_monitor.block_id(run_id);
        if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.declare_phases(
                phases
                    .iter()
                    .map(|title| crate::workflow::ui_safe_label(title)),
            );
        }
        if let Some(block) =
            block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
        {
            Arc::make_mut(block).touch();
        }
        self.mark_transcript_changed();
        self.autoscroll();
    }

    /// The rows the workflow region draws this frame, at `width`, in their NATURAL length — the
    /// count is what the layout is then asked for, and `block::window_workflow_rows` fits the same
    /// rows into whatever height it grants.
    ///
    /// The region renders the transcript's card, not a copy: `workflow_region` holds no tree of its
    /// own precisely so that there is nothing to drift. An empty answer is the honest one for every
    /// frame with no live run, and it is what makes the region cost zero rows.
    pub(super) fn workflow_region_rows(&self, width: u16) -> Vec<Line<'static>> {
        let Some(block_id) = self.workflow_monitor.region_block() else {
            return Vec::new();
        };
        self.transcript
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| match &block.kind {
                block::BlockKind::WorkflowRun(card) => Some(card),
                _ => None,
            })
            .map(|card| block::render_workflow_run(card, width, &self.theme, self.spin))
            .unwrap_or_default()
    }

    // REPL seam (see `workflow_monitor`). Live since ADR-0001 step 1: `app_server::ServerEvent`
    // carries the engine's progress off the kernel thread and `workflow_run_ui_event` lands it here.
    pub(super) fn workflow_run_card_mut(
        &mut self,
        run_id: &str,
    ) -> Option<&mut block::WorkflowRunCard> {
        let block_id = self.workflow_monitor.block_id(run_id)?;
        self.transcript
            .iter_mut()
            .find(|block| block.id == block_id)
            .map(Arc::make_mut)
            .and_then(|block| match &mut block.kind {
                block::BlockKind::WorkflowRun(card) => Some(card),
                _ => None,
            })
    }

    /// Upsert one QuickJS `iteron-workflow` progress event into its one live phase→agent tree card
    /// (design §3.2), creating the card on first sight of a run id. This is the interactive-TUI seam
    /// for a workflow launched from the REPL; the one-shot `iteron workflow run` command drives an
    /// equivalent card through its own live loop (`workflow::run_live`). Wired up by ADR-0001
    /// step 1 (docs/project/decisions/0001-workflow-renderer-convergence.md).
    pub(super) fn workflow_run_event(
        &mut self,
        run_id: &str,
        name: &str,
        event: iteron_workflow::events::ProgressEvent,
    ) {
        if self.workflow_run_card_mut(run_id).is_none() {
            self.flush_text();
            let card = block::WorkflowRunCard::new(ui_safe_text(run_id), ui_safe_text(name));
            let block_id = self.push_block(block::BlockKind::WorkflowRun(card));
            self.workflow_monitor.ingest(
                run_id,
                workflow_region::WorkflowRunSignal::Live { block_id },
            );
        }
        let changed = if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.ingest(event);
            true
        } else {
            false
        };
        if changed {
            let block_id = self.workflow_monitor.block_id(run_id);
            if let Some(block) =
                block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
            {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed();
        }
        self.autoscroll();
    }

    /// Mark a QuickJS workflow run terminal (its engine future resolved). The card collapses finished
    /// agents but stays in the transcript.
    pub(super) fn workflow_run_finished(&mut self, run_id: &str) {
        let block_id = self.workflow_monitor.block_id(run_id);
        let changed = if let Some(card) = self.workflow_run_card_mut(run_id) {
            card.finished = true;
            true
        } else {
            false
        };
        if changed {
            if let Some(block) =
                block_id.and_then(|id| self.transcript.iter_mut().find(|block| block.id == id))
            {
                Arc::make_mut(block).touch();
            }
            self.mark_transcript_changed();
        }
        // Settling ends the live binding: the card stays in the transcript, but events for this run
        // no longer land on it.
        self.workflow_monitor
            .ingest(run_id, workflow_region::WorkflowRunSignal::Settled);
        self.autoscroll();
    }

    /// Toggle the fold of a collapsible block at transcript index `i`.
    pub(super) fn toggle_fold(&mut self, i: usize) {
        // A workflow run's collapse bit belongs to the workflow region's store, and the card's
        // `verbose` field is the projection the renderer reads. Flipping it there FIRST and writing
        // the card from that answer keeps one writer for one bit; a block the store does not know
        // answers `None` and its card falls back to flipping itself.
        let workflow_run_verbose = self
            .transcript
            .get(i)
            .filter(|b| matches!(b.kind, block::BlockKind::WorkflowRun(_)))
            .map(|b| b.id)
            .and_then(|block_id| self.workflow_monitor.toggle_collapsed_for_block(block_id))
            .map(|collapsed| !collapsed);
        if let Some(b) = self.transcript.get_mut(i) {
            let b = Arc::make_mut(b);
            let changed = match &mut b.kind {
                block::BlockKind::Tool(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::Workflow(c) => {
                    c.open = !c.open;
                    true
                }
                block::BlockKind::WorkflowRun(c) => {
                    // Open the full phase/agent tree, or return to the one-line run summary.
                    c.verbose = workflow_run_verbose.unwrap_or(!c.verbose);
                    true
                }
                block::BlockKind::Thinking { open, .. } => {
                    *open = !*open;
                    true
                }
                block::BlockKind::Error { open, .. } => {
                    *open = !*open;
                    true
                }
                _ => false,
            };
            if changed {
                b.touch();
                self.mark_transcript_changed();
            }
        }
    }

    /// Ctrl-O: toggle the fold of the most recent collapsible block (Claude Code's `ctrl+o` expand
    /// affordance; teardown D10 — a keyboard-truthful replacement for the removed mouse click).
    pub(super) fn toggle_last_fold(&mut self) {
        // The run the region is drawing is the most recent collapsible thing on screen, and it is
        // deliberately absent from the transcript's row map, so the click that used to reach its
        // fold no longer can. Ctrl-O is what keeps design §3.3's collapse reachable while a run is
        // live; without this the store's one collapse writer would be unreachable for exactly the
        // runs an operator wants to expand.
        if let Some(block_id) = self.workflow_monitor.region_block()
            && let Some(i) = self
                .transcript
                .iter()
                .position(|block| block.id == block_id)
        {
            self.toggle_fold(i);
            return;
        }
        if let Some(i) = self.transcript.iter().rposition(|b| {
            matches!(
                b.kind,
                block::BlockKind::Tool(_)
                    | block::BlockKind::Thinking { .. }
                    | block::BlockKind::Workflow(_)
                    | block::BlockKind::Error { .. }
            )
        }) {
            self.toggle_fold(i);
        }
    }
}
