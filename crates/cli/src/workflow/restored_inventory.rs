//! Finite restart-sidecar observations. A sidecar status is recorded history, never proof that
//! a process/controller is currently live. No frontend constructs a native sidecar reader.
use super::restart_read::RestartDirectory;
use super::run_store::load_held_run_listing;
use super::{RunListing, valid_run_id};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct RestoredWorkflowInventory {
    pub(crate) rows: Vec<RunListing>,
    pub(crate) omitted: usize,
    pub(crate) incomplete: bool,
}

pub(crate) fn restored_inventory(root: &Path, limit: usize) -> RestoredWorkflowInventory {
    let limit = limit.min(16);
    let mut observation = RestoredWorkflowInventory::default();
    if limit == 0 {
        return observation;
    }
    let root = match RestartDirectory::open(root) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return observation,
        Err(_) => {
            observation.incomplete = true;
            return observation;
        }
    };
    let entries = match root.entries() {
        Ok(entries) => entries,
        Err(_) => {
            observation.incomplete = true;
            return observation;
        }
    };
    let started = Instant::now();
    let mut newest = BinaryHeap::with_capacity(limit + 1);
    for (index, entry) in entries.enumerate() {
        if index >= 4096 || started.elapsed() >= Duration::from_secs(5) {
            observation.incomplete = true;
            break;
        }
        let Ok(name) = entry else {
            observation.incomplete = true;
            continue;
        };
        let Some(run_id) = name
            .to_str()
            .filter(|id| valid_run_id(id))
            .map(str::to_owned)
        else {
            continue;
        };
        if root.child(&run_id).is_err() {
            continue;
        }
        newest.push(Reverse((run_timestamp(&run_id), run_id)));
        if newest.len() > limit {
            newest.pop();
            observation.omitted += 1;
        }
    }
    let mut candidates: Vec<_> = newest.into_iter().map(|Reverse(row)| row).collect();
    candidates.sort_by(|left, right| right.cmp(left));
    let mut bytes = 0usize;
    let known_candidates = candidates.len();
    for (index, (_, run_id)) in candidates.into_iter().enumerate() {
        if started.elapsed() >= Duration::from_secs(5) {
            observation.incomplete = true;
            observation.omitted += known_candidates - index;
            break;
        }
        match load_held_run_listing(&root, run_id) {
            Some(row) => {
                let charge = row
                    .run_id
                    .capacity()
                    .saturating_add(row.name.capacity())
                    .saturating_add(row.model.capacity())
                    .saturating_add(std::mem::size_of::<RunListing>());
                if bytes.saturating_add(charge) > 256 * 1024 {
                    observation.incomplete = true;
                    observation.omitted += 1;
                    continue;
                }
                bytes += charge;
                observation.rows.push(row);
            }
            None => {
                observation.incomplete = true;
                observation.omitted += 1;
            }
        }
    }
    observation
}

fn run_timestamp(run_id: &str) -> u128 {
    run_id
        .strip_prefix("wf_")
        .unwrap_or_default()
        .split('_')
        .take(2)
        .filter_map(|part| u128::from_str_radix(part, 16).ok())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "restored_inventory_tests.rs"]
mod tests;
