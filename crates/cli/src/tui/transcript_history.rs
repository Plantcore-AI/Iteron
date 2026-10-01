//! One writer for retained semantic blocks and their revision/identity. Renderers and inspectors
//! borrow immutable slices; mutation ports always touch the exact record and dirty suffix together.

mod legacy_workflow;

use crate::block;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub(super) struct TranscriptHistory {
    blocks: Vec<Arc<block::Block>>,
    revision: u64,
    dirty_from: Option<usize>,
    next_id: u64,
    workflow_index: HashMap<String, u64>,
    selected_run: Option<iteron_protocol::RunId>,
}
impl TranscriptHistory {
    pub(super) fn with_landing(kind: block::BlockKind) -> Self {
        Self {
            blocks: vec![Arc::new(block::Block::new(0, kind))],
            revision: 0,
            dirty_from: Some(0),
            next_id: 1,
            workflow_index: HashMap::new(),
            selected_run: None,
        }
    }
    pub(super) fn blocks(&self) -> &[Arc<block::Block>] {
        &self.blocks
    }
    pub(super) fn selected_run(&self) -> Option<&iteron_protocol::RunId> {
        self.selected_run.as_ref()
    }
    pub(super) fn bind_selected_run(&mut self, run: &iteron_protocol::RunId) {
        self.selected_run = Some(run.clone());
    }
    pub(super) fn clear_selected_run_binding(&mut self) {
        self.selected_run = None;
    }
    pub(super) fn snapshot(&self) -> Vec<Arc<block::Block>> {
        self.blocks.clone()
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }
    pub(super) fn dirty_from(&self) -> Option<usize> {
        self.dirty_from
    }
    pub(super) fn geometry_prepared(&mut self) {
        self.dirty_from = None;
    }
    pub(super) fn mark_changed_from(&mut self, index: usize) {
        self.revision = self.revision.wrapping_add(1);
        self.dirty_from = Some(self.dirty_from.map_or(index, |old| old.min(index)));
    }
    pub(super) fn append(&mut self, kind: block::BlockKind) -> u64 {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("TUI block identity space exhausted");
        let index = self.blocks.len();
        self.blocks.push(Arc::new(block::Block::new(id, kind)));
        self.mark_changed_from(index);
        id
    }
    pub(super) fn clear(&mut self) {
        self.blocks.clear();
        self.workflow_index.clear();
        self.mark_changed_from(0);
    }
    pub(super) fn retain_ids(&mut self, retained: &HashSet<u64>) -> HashSet<u64> {
        let mut removed = HashSet::new();
        self.blocks.retain(|block| {
            if retained.contains(&block.id) {
                true
            } else {
                removed.insert(block.id);
                false
            }
        });
        self.forget_indices(&removed);
        if !removed.is_empty() {
            self.mark_changed_from(0);
        }
        removed
    }
    pub(super) fn evict_settled(&mut self, limit: usize, pinned: &HashSet<u64>) -> HashSet<u64> {
        let mut remaining = self.blocks.len().saturating_sub(limit);
        let mut removed = HashSet::new();
        self.blocks.retain(|block| {
            if remaining > 0 && !pinned.contains(&block.id) {
                remaining -= 1;
                removed.insert(block.id);
                false
            } else {
                true
            }
        });
        self.forget_indices(&removed);
        if !removed.is_empty() {
            self.mark_changed_from(0);
        }
        removed
    }
    fn forget_indices(&mut self, removed: &HashSet<u64>) {
        self.workflow_index.retain(|_, id| !removed.contains(id));
    }
    pub(super) fn live_workflow_blocks(&self) -> impl Iterator<Item = u64> + '_ {
        self.workflow_index.values().copied()
    }
    pub(super) fn clear_workflow_bindings(&mut self) {
        self.workflow_index.clear();
    }
    /// Replace the exact answer fragments, preserving unrelated tools and previous turns.
    pub(super) fn replace_answer(
        &mut self,
        ids: &HashSet<u64>,
        document: Option<crate::markdown::MarkdownDoc>,
    ) -> Option<u64> {
        let insertion = self
            .blocks
            .iter()
            .position(|block| ids.contains(&block.id))
            .unwrap_or(self.blocks.len());
        self.blocks.retain(|block| !ids.contains(&block.id));
        let inserted = document.map(|document| {
            let id = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .expect("TUI block identity space exhausted");
            self.blocks.insert(
                insertion.min(self.blocks.len()),
                Arc::new(block::Block::new(id, block::BlockKind::Assistant(document))),
            );
            id
        });
        self.mark_changed_from(insertion.min(self.blocks.len()));
        inserted
    }
    pub(super) fn is_tool(&self, id: u64) -> bool {
        self.blocks
            .iter()
            .any(|block| block.id == id && matches!(block.kind, block::BlockKind::Tool(_)))
    }
    pub(super) fn settle_tool(
        &mut self,
        id: u64,
        status: block::ToolStatus,
        output: String,
        diff: Option<iteron_protocol::FileDiff>,
        exit_code: Option<i32>,
        now: std::time::Instant,
    ) -> bool {
        self.update_kind(id, |kind| {
            let block::BlockKind::Tool(card) = kind else {
                return false;
            };
            card.status = status;
            card.output = output;
            card.diff = diff;
            card.exit_code = exit_code;
            card.elapsed = Some(now.saturating_duration_since(card.started));
            true
        })
    }
    pub(super) fn script_workflow_card(&self, id: u64) -> Option<&block::WorkflowRunCard> {
        match &self.blocks.iter().find(|block| block.id == id)?.kind {
            block::BlockKind::WorkflowRun(card) => Some(card),
            _ => None,
        }
    }
    pub(super) fn declare_workflow_phases(&mut self, id: u64, phases: &[String]) -> bool {
        self.update_kind(id, |kind| {
            let block::BlockKind::WorkflowRun(card) = kind else {
                return false;
            };
            card.declare_phases(
                phases
                    .iter()
                    .map(|title| crate::workflow::ui_safe_label(title)),
            );
            true
        })
    }
    pub(super) fn ingest_workflow_progress(
        &mut self,
        id: u64,
        event: iteron_workflow::events::ProgressEvent,
    ) -> bool {
        self.update_kind(id, |kind| {
            let block::BlockKind::WorkflowRun(card) = kind else {
                return false;
            };
            card.ingest(event);
            true
        })
    }
    pub(super) fn finish_workflow_run(&mut self, id: u64) -> bool {
        self.update_kind(id, |kind| {
            let block::BlockKind::WorkflowRun(card) = kind else {
                return false;
            };
            card.finished = true;
            true
        })
    }
    fn update_kind(&mut self, id: u64, update: impl FnOnce(&mut block::BlockKind) -> bool) -> bool {
        let Some(index) = self.blocks.iter().position(|block| block.id == id) else {
            return false;
        };
        let block = Arc::make_mut(&mut self.blocks[index]);
        if !update(&mut block.kind) {
            return false;
        }
        block.touch();
        self.mark_changed_from(index);
        true
    }
    pub(super) fn toggle_fold(&mut self, index: usize, workflow_verbose: Option<bool>) -> bool {
        let Some(id) = self.blocks.get(index).map(|block| block.id) else {
            return false;
        };
        self.update_kind(id, |kind| match kind {
            block::BlockKind::Tool(card) => {
                card.open = !card.open;
                true
            }
            block::BlockKind::Workflow(card) => {
                card.open = !card.open;
                true
            }
            block::BlockKind::WorkflowRun(card) => {
                card.verbose = workflow_verbose.unwrap_or(!card.verbose);
                true
            }
            block::BlockKind::Thinking { open, .. } | block::BlockKind::Error { open, .. } => {
                *open = !*open;
                true
            }
            _ => false,
        })
    }
    #[cfg(test)]
    pub(super) fn workflow_binding(&self, run: &str) -> Option<u64> {
        self.workflow_index.get(run).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::TranscriptHistory;
    use crate::block;
    use std::collections::HashSet;
    use std::time::Instant;

    #[test]
    fn product_scope_observation_cannot_relabel_retained_transcript_source() {
        let mut app = crate::tui::App::new();
        let original = iteron_protocol::RunId("verified-visible-origin".into());
        app.history.bind_selected_run(&original);
        app.product
            .select_run(&iteron_protocol::RunId("host-selected-new-run".into()));
        assert_eq!(app.history.selected_run(), Some(&original));
        crate::tui::session_adoption::clear_transcript_for_adoption(&mut app);
        assert!(app.history.selected_run().is_none());
    }

    #[test]
    fn owned_settlement_fold_and_answer_rewrite_leave_old_observer_snapshot_immutable() {
        let mut history =
            TranscriptHistory::with_landing(block::BlockKind::User("old prompt".into()));
        let answer = history.append(block::BlockKind::Assistant(
            crate::markdown::MarkdownDoc::parse("partial"),
        ));
        let tool = history.append(block::BlockKind::Tool(block::ToolCard {
            name: "read_file".into(),
            args: serde_json::Value::Null,
            status: block::ToolStatus::Running,
            output: String::new(),
            diff: None,
            exit_code: None,
            started: Instant::now(),
            elapsed: None,
            open: false,
        }));
        let snapshot = history.snapshot();
        let revision = history.revision();
        history.geometry_prepared();
        assert!(history.settle_tool(
            tool,
            block::ToolStatus::Ok,
            "actual observed output".into(),
            None,
            None,
            Instant::now()
        ));
        assert!(history.revision() > revision);
        assert_eq!(history.dirty_from(), Some(2));
        let block::BlockKind::Tool(old) = &snapshot[2].kind else {
            panic!("retained old tool");
        };
        assert_eq!(old.status, block::ToolStatus::Running);
        let replacement = history
            .replace_answer(
                &HashSet::from([answer]),
                Some(crate::markdown::MarkdownDoc::parse("complete")),
            )
            .unwrap();
        assert_ne!(replacement, answer);
        assert_eq!(history.blocks()[1].id, replacement);
        assert_eq!(history.blocks()[2].id, tool);
        history.geometry_prepared();
        assert!(history.toggle_fold(2, None));
        assert_eq!(history.dirty_from(), Some(2));
        let block::BlockKind::Tool(current) = &history.blocks()[2].kind else {
            panic!("current tool");
        };
        assert!(current.open);
        assert_eq!(current.output, "actual observed output");
        assert!(!old.open);
    }

    #[test]
    fn live_legacy_workflow_binding_is_pinned_and_terminal_missing_children_stay_unknown() {
        use crate::runtime::{WorkflowRunOutcomeUi, WorkflowUiEvent};
        let mut history = TranscriptHistory::with_landing(block::BlockKind::User("prompt".into()));
        assert!(history.observe_workflow(WorkflowUiEvent::RunStarted {
            run_id: "actual-run".into(),
            name: "work".into(),
            class: "investigate".into(),
        }));
        let live = history.workflow_binding("actual-run").unwrap();
        assert!(history.observe_workflow(WorkflowUiEvent::PlanReady {
            run_id: "actual-run".into(),
            tasks: vec![crate::runtime::WorkflowTaskUi {
                id: 1,
                label: "waiting child".into()
            }],
            dropped: 0,
            duplicates_removed: 0,
            invalid_removed: 0,
            execution_mode: crate::runtime::WorkflowExecutionModeUi::Direct,
            fan_turn_budget: 1,
            writer_turn_reserve: 1,
            fan_wall_secs: 1,
            writer_wall_reserve_secs: 1,
        }));
        for row in 0..12 {
            history.append(block::BlockKind::User(format!("row {row}")));
        }
        let pinned = history.live_workflow_blocks().collect();
        let removed = history.evict_settled(4, &pinned);
        assert!(!removed.contains(&live));
        assert_eq!(history.workflow_binding("actual-run"), Some(live));
        let before = history.snapshot();
        assert!(history.observe_workflow(WorkflowUiEvent::RunFinished {
            run_id: "actual-run".into(),
            outcome: WorkflowRunOutcomeUi::Stopped,
            reason: Some("observed stopped".into()),
            elapsed_ms: 20,
            provider_attempts: 1,
            turns: 1,
            tokens: 2,
            tool_calls: 0,
            failed_tasks: 0,
            skipped_tasks: 0,
        }));
        assert_eq!(history.workflow_binding("actual-run"), None);
        assert!(
            history
                .blocks()
                .iter()
                .any(|block| block.id == live && block.to_text().contains("observed stopped"))
        );
        assert!(before.iter().any(|block| block.id == live && matches!(&block.kind, block::BlockKind::Workflow(card) if !card.status.is_terminal())));
        let block::BlockKind::Workflow(card) = &history
            .blocks()
            .iter()
            .find(|block| block.id == live)
            .unwrap()
            .kind
        else {
            panic!("workflow card");
        };
        assert_eq!(card.tasks[0].status, block::WorkflowTaskStatus::Unknown);
        assert!(card.open, "missing child evidence remains visible");
        history.clear();
        let next = history.append(block::BlockKind::User("new observed run".into()));
        assert!(next > live);
        assert!(!history.is_tool(live));
    }
}
