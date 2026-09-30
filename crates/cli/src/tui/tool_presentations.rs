//! Private anti-flash timer, tool-card identity and compact activity projection. This state never
//! grants a tool or synthesizes a durable terminal; it only correlates observed presentation facts.

use super::driver_support::{MAX_PENDING_TOOL_PROJECTIONS, TOOL_REVEAL_DELAY};
use crate::block;
use crate::semantic_text::{ui_safe_json, ui_safe_text};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

pub(super) struct ToolReveal {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) args: serde_json::Value,
    pub(super) started: Instant,
}
struct Pending {
    reveal: ToolReveal,
    deadline: Instant,
}
#[derive(Default)]
pub(super) struct ToolPresentations {
    pending: VecDeque<Pending>,
    revealed: HashMap<String, u64>,
    active: VecDeque<(String, String)>,
}
impl ToolPresentations {
    pub(super) fn start(
        &mut self,
        id: String,
        name: String,
        args: serde_json::Value,
        now: Instant,
    ) -> Vec<ToolReveal> {
        let name = ui_safe_text(&name);
        let args = ui_safe_json(&args);
        self.active.retain(|(active, _)| active != &id);
        self.active
            .push_back((id.clone(), block::activity_label(&name, &args)));
        while self.active.len() > 16 {
            self.active.pop_front();
        }
        if self.revealed.contains_key(&id) {
            return Vec::new();
        }
        self.pending.retain(|pending| pending.reveal.id != id);
        let limit = iteron_tunables::param_integer(
            "cli.tui.driver_support.max_pending_tool_projections",
            MAX_PENDING_TOOL_PROJECTIONS,
        )
        .clamp(1, MAX_PENDING_TOOL_PROJECTIONS);
        let mut due = Vec::new();
        while self.pending.len() >= limit {
            due.push(
                self.pending
                    .pop_front()
                    .expect("pending length admitted a row")
                    .reveal,
            );
        }
        let delay = iteron_tunables::param_duration(
            "cli.tui.driver_support.tool_reveal_delay",
            TOOL_REVEAL_DELAY,
        );
        self.pending.push_back(Pending {
            reveal: ToolReveal {
                id,
                name,
                args,
                started: now,
            },
            deadline: now + delay,
        });
        due
    }
    pub(super) fn next_reveal(&self) -> Option<Instant> {
        self.pending.front().map(|pending| pending.deadline)
    }
    pub(super) fn take_due(&mut self, now: Instant) -> Option<ToolReveal> {
        self.pending
            .front()
            .is_some_and(|pending| now >= pending.deadline)
            .then(|| {
                self.pending
                    .pop_front()
                    .expect("deadline belonged to the front")
                    .reveal
            })
    }
    pub(super) fn take_pending(&mut self, id: &str) -> Option<ToolReveal> {
        let index = self
            .pending
            .iter()
            .position(|pending| pending.reveal.id == id)?;
        self.pending.remove(index).map(|pending| pending.reveal)
    }
    pub(super) fn bind_revealed(&mut self, id: String, block_id: u64) {
        self.revealed.insert(id, block_id);
    }
    pub(super) fn revealed_block(&self, id: &str) -> Option<u64> {
        self.revealed.get(id).copied()
    }
    pub(super) fn finish(&mut self, id: &str) {
        self.active.retain(|(active, _)| active != id);
        self.revealed.remove(id);
    }
    pub(super) fn finish_activity(&mut self, id: &str) {
        self.active.retain(|(active, _)| active != id);
    }
    pub(super) fn unfinished_ids(&self) -> Vec<String> {
        let mut ids = self
            .pending
            .iter()
            .map(|pending| pending.reveal.id.clone())
            .chain(self.revealed.keys().cloned())
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        ids
    }
    pub(super) fn forget_blocks(&mut self, removed: &HashSet<u64>) {
        self.revealed.retain(|_, id| !removed.contains(id));
    }
    pub(super) fn active_summary(&self) -> Option<(&str, usize)> {
        self.active
            .back()
            .map(|(_, activity)| (activity.as_str(), self.active.len()))
    }
    pub(super) fn clear_revealed(&mut self) {
        self.revealed.clear();
    }
    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.revealed.clear();
        self.active.clear();
    }
    #[cfg(test)]
    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }
    #[cfg(test)]
    pub(super) fn revealed_len(&self) -> usize {
        self.revealed.len()
    }
    #[cfg(test)]
    pub(super) fn active_len(&self) -> usize {
        self.active.len()
    }
    #[cfg(test)]
    pub(super) fn has_active(&self, id: &str) -> bool {
        self.active.iter().any(|(active, _)| active == id)
    }
    #[cfg(test)]
    pub(super) fn fixture_active(&mut self, id: String, label: String) {
        self.active.push_back((id, label));
    }
}

#[cfg(test)]
mod tests {
    use super::ToolPresentations;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};
    #[test]
    fn duplicate_timer_reveal_and_eviction_keep_one_exact_correlated_projection() {
        let mut owner = ToolPresentations::default();
        let now = Instant::now();
        assert!(
            owner
                .start(
                    "same-call".into(),
                    "read_file".into(),
                    serde_json::json!({"path":"a"}),
                    now
                )
                .is_empty()
        );
        assert!(
            owner
                .start(
                    "same-call".into(),
                    "read_file".into(),
                    serde_json::json!({"path":"b"}),
                    now
                )
                .is_empty()
        );
        assert_eq!(owner.pending_len(), 1);
        let deadline = owner.next_reveal().unwrap();
        assert!(
            owner
                .take_due(deadline - Duration::from_millis(1))
                .is_none()
        );
        let reveal = owner.take_due(deadline).unwrap();
        assert_eq!(reveal.args["path"], "b");
        owner.bind_revealed(reveal.id, 44);
        owner.start(
            "same-call".into(),
            "read_file".into(),
            serde_json::Value::Null,
            now,
        );
        assert_eq!(owner.pending_len(), 0);
        assert_eq!(owner.revealed_block("same-call"), Some(44));
        assert_eq!(owner.active_len(), 1);
        owner.forget_blocks(&HashSet::from([44]));
        assert!(owner.revealed_block("same-call").is_none());
        assert!(owner.has_active("same-call"));
        owner.finish("same-call");
        assert_eq!(owner.active_len(), 0);
        owner.start(
            "fresh".into(),
            "read_file".into(),
            serde_json::Value::Null,
            now,
        );
        owner.clear();
        assert!(owner.take_due(deadline).is_none());
        assert!(owner.unfinished_ids().is_empty());
    }
}
