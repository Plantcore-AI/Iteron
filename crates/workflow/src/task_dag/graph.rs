use std::collections::BTreeSet;

use super::reducer::TaskDag;
use super::types::TaskId;

impl TaskDag {
    /// Returns whether `start` already waits (transitively) for `target` across the union of
    /// explicit dependency edges and implicit parent-waits-direct-child edges.
    pub(super) fn waits_for(&self, start: TaskId, target: TaskId) -> bool {
        let mut pending = vec![start];
        let mut visited = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if current == target {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            if let Some(task) = self.tasks.get(&current) {
                pending.extend(task.spec.dependencies.iter().copied());
            }
            pending.extend(
                self.tasks
                    .iter()
                    .filter_map(|(id, task)| (task.spec.parent == Some(current)).then_some(*id)),
            );
        }
        false
    }
}
