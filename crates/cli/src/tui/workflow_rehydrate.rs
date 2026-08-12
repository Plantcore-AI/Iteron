//! Bounded selection of restart-sidecar candidates plus its isolated tests.
//!
//! Sidecar interpretation remains in `crate::workflow`, next to the readers used by
//! `iteron workflow list|resume|watch`. This module chooses which recent directories are affordable
//! on the first-frame path and delegates each winner to that one command-owned reader.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::path::Path;

/// Timestamp given to a run id whose hex fields do not parse. Legacy ids sort last as a block and
/// then fall back to lexicographic id order, which is why the floor is the minimum, not a guess.
const UNPARSED_RUN_TIMESTAMP: u128 = 0;

/// Reuse the command-side sidecar reader for at most `limit` recently-active run directories.
///
/// Fresh run ids carry their creation nanoseconds (both `wf_<nanos>_<seq>` and the standalone
/// command's older `wf_<pid>_<nanos>` shape), so recency needs no `stat` per stale entry. A bounded
/// min-heap keeps ordering work and memory at `O(entries * log(limit))` / `O(limit)`; only the
/// winning candidates have sidecars opened. Legacy ids with no timestamp fall back to id order.
pub(crate) fn restore(workflows_dir: &Path, limit: usize) -> Vec<crate::workflow::RunListing> {
    if limit == 0 {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(workflows_dir) else {
        return Vec::new();
    };
    let mut newest = BinaryHeap::with_capacity(limit.saturating_add(1));
    for entry in entries.flatten() {
        let run_id = entry.file_name().to_string_lossy().into_owned();
        newest.push(Reverse((run_timestamp(&run_id), run_id)));
        if newest.len() > limit {
            newest.pop();
        }
    }
    let mut candidates: Vec<_> = newest
        .into_iter()
        .map(|Reverse(candidate)| candidate)
        .collect();
    candidates.sort_by(|left, right| right.cmp(left));
    candidates
        .into_iter()
        .filter_map(|(_, run_id)| crate::workflow::load_run_listing(workflows_dir, run_id))
        .collect()
}

fn run_timestamp(run_id: &str) -> u128 {
    let mut parts = run_id.strip_prefix("wf_").unwrap_or_default().split('_');
    let first = parts
        .next()
        .and_then(|part| u128::from_str_radix(part, 16).ok())
        .unwrap_or(UNPARSED_RUN_TIMESTAMP);
    let second = parts
        .next()
        .and_then(|part| u128::from_str_radix(part, 16).ok())
        .unwrap_or(UNPARSED_RUN_TIMESTAMP);
    first.max(second)
}

#[cfg(test)]
mod tests {
    use super::super::workflow_region::{RESTORE_LIMIT, WorkflowMonitor, WorkflowRunSignal};
    use super::restore;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let serial = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "iteron-workflow-rehydrate-{tag}-{}-{serial}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch workflows directory");
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn manifest(dir: &Path, run_id: &str, name: &str, created_at: u64) {
        crate::workflow::persist_inputs(
            dir,
            &crate::workflow::RunManifest {
                run_id: run_id.into(),
                name: name.into(),
                args: serde_json::json!({}),
                provider_id: "anthropic".into(),
                model: "core-model-1".into(),
                created_at,
            },
            "export default async function () { return null; }",
        )
        .expect("persist inputs");
    }

    fn journal(dir: &Path, run_id: &str, results: usize) {
        let text: String = (0..results)
            .map(|n| {
                format!(
                    "{}\n",
                    serde_json::json!({
                        "type": "result",
                        "version": 1,
                        "key": format!("v2:{n}"),
                        "agent_id": format!("{n:04x}"),
                        "record": { "outcome": { "t": "text", "text": "ok" } }
                    })
                )
            })
            .collect();
        std::fs::write(
            crate::workflow::run_dir(dir, run_id).join("journal.jsonl"),
            text,
        )
        .expect("write journal");
    }

    fn raw_journal(dir: &Path, run_id: &str, bytes: &[u8]) {
        std::fs::write(
            crate::workflow::run_dir(dir, run_id).join("journal.jsonl"),
            bytes,
        )
        .expect("write raw journal");
    }

    fn completed_run(dir: &Path, run_id: &str, name: &str, results: usize, created_at: u64) {
        manifest(dir, run_id, name, created_at);
        journal(dir, run_id, results);
        crate::workflow::persist_result(
            dir,
            run_id,
            &iteron_workflow::RunReport {
                run_id: iteron_workflow::RunId::new(run_id),
                value: serde_json::json!("done"),
                stopped: false,
                cache_hits: 0,
                cache_misses: results,
                errors: 0,
                tokens: 12,
                tool_calls: 3,
                elapsed_ms: 40,
            },
        )
        .expect("persist result");
    }

    #[test]
    fn workflow_rehydrate_finds_a_completed_run() {
        let scratch = Scratch::new("completed");
        completed_run(scratch.path(), "wf_done", "triage", 3, 100);

        let command_row = crate::workflow::list_runs(scratch.path()).remove(0);
        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 1);
        let restored = monitor.restored_runs().next().expect("restored row");

        assert_eq!(restored, &command_row, "the TUI reuses the command summary");
        assert_eq!(restored.run_id, "wf_done");
        assert_eq!(restored.status, "done");
        assert_eq!(restored.agents, 3);
    }

    #[test]
    fn workflow_rehydrate_terminal_renders_the_restored_inventory_as_history() {
        use super::super::{App, draw};
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let scratch = Scratch::new("render");
        completed_run(
            scratch.path(),
            "wf_18d0000000000000_0",
            "restored measurement",
            1,
            1,
        );
        let mut app = App::new();
        assert_eq!(app.workflow_monitor.rehydrate(Some(scratch.path())), 1);
        app.workflows_panel.open();

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }

        assert!(
            rendered.contains("plantcore · New session · workflows"),
            "{rendered}"
        );
        assert!(rendered.contains("restored measurement"), "{rendered}");
        assert!(rendered.contains("done"), "{rendered}");
        assert!(rendered.contains("durable history"), "{rendered}");
        assert!(rendered.contains("wf_18d0000000000000_0"), "{rendered}");
    }

    #[test]
    fn workflow_rehydrate_skips_truncated_or_corrupt_journals_but_loads_neighbours() {
        let scratch = Scratch::new("bad-journals");
        completed_run(scratch.path(), "wf_before", "before", 1, 1);
        completed_run(scratch.path(), "wf_truncated", "truncated", 1, 2);
        raw_journal(
            scratch.path(),
            "wf_truncated",
            b"{\"type\":\"result\",\"key\":\"v2:0\"}\n{\"type\":\"res",
        );
        completed_run(scratch.path(), "wf_corrupt", "corrupt", 1, 3);
        raw_journal(scratch.path(), "wf_corrupt", b"{not-json}\n");
        completed_run(scratch.path(), "wf_after", "after", 1, 4);

        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 2);
        let ids: Vec<_> = monitor
            .restored_runs()
            .map(|run| run.run_id.as_str())
            .collect();

        assert!(ids.contains(&"wf_before"), "{ids:?}");
        assert!(ids.contains(&"wf_after"), "{ids:?}");
        assert!(!ids.contains(&"wf_truncated"), "{ids:?}");
        assert!(!ids.contains(&"wf_corrupt"), "{ids:?}");
    }

    #[test]
    fn workflow_rehydrate_enforces_the_candidate_bound() {
        let scratch = Scratch::new("bound");
        for n in 0..(RESTORE_LIMIT * 4) {
            completed_run(
                scratch.path(),
                &format!("wf_{n:04}"),
                "historical",
                1,
                n as u64,
            );
        }

        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), RESTORE_LIMIT);
        assert_eq!(monitor.restored_runs().count(), RESTORE_LIMIT);
        assert!(restore(scratch.path(), 0).is_empty());
    }

    #[test]
    fn workflow_rehydrate_orders_both_time_ordered_id_shapes_by_recency() {
        assert_eq!(super::run_timestamp("wf_20_1"), 0x20);
        assert_eq!(
            super::run_timestamp("wf_2_30"),
            0x30,
            "the standalone command writes pid before nanoseconds"
        );

        let scratch = Scratch::new("recency");
        completed_run(scratch.path(), "wf_10_1", "old", 1, 300);
        completed_run(scratch.path(), "wf_20_2", "middle", 1, 200);
        completed_run(scratch.path(), "wf_3_30", "new", 1, 100);

        let ids: Vec<_> = restore(scratch.path(), 2)
            .into_iter()
            .map(|run| run.run_id)
            .collect();
        assert_eq!(ids, ["wf_3_30", "wf_20_2"]);
    }

    #[test]
    fn workflow_rehydrate_empty_or_missing_directory_has_no_rows() {
        let scratch = Scratch::new("empty");
        let mut empty = WorkflowMonitor::default();
        assert_eq!(empty.rehydrate(Some(scratch.path())), 0);
        assert_eq!(empty.live_count(), 0);
        assert!(empty.restored_runs().next().is_none());

        let mut missing = WorkflowMonitor::default();
        assert_eq!(missing.rehydrate(Some(&scratch.path().join("missing"))), 0);
        assert!(missing.restored_runs().next().is_none());
    }

    #[test]
    fn workflow_rehydrate_restored_running_status_is_not_local_liveness() {
        let scratch = Scratch::new("not-live");
        manifest(scratch.path(), "wf_detached", "detached", 7);
        journal(scratch.path(), "wf_detached", 4);

        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 1);

        assert_eq!(
            monitor.restored_runs().next().map(|run| run.status),
            Some("running"),
            "the sidecars' status remains visible"
        );
        assert_eq!(
            monitor.live_count(),
            0,
            "but this process is not driving it"
        );
        assert!(!monitor.is_live("wf_detached"));
        assert_eq!(monitor.block_id("wf_detached"), None);
        assert_eq!(monitor.region_block(), None);
        assert!(monitor.live_blocks().is_empty());
    }

    #[test]
    fn workflow_rehydrate_runs_once_and_again_after_adoption_reset() {
        let scratch = Scratch::new("adoption");
        completed_run(scratch.path(), "wf_old", "old", 1, 1);

        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 1);
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 0);

        monitor.reset();
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 1);
    }

    #[test]
    fn workflow_rehydrate_never_displaces_a_run_this_process_drives() {
        let scratch = Scratch::new("driven");
        completed_run(scratch.path(), "wf_live", "live", 2, 1);

        let mut monitor = WorkflowMonitor::default();
        monitor.ingest("wf_live", WorkflowRunSignal::Live { block_id: 7 });
        assert_eq!(monitor.rehydrate(Some(scratch.path())), 0);

        assert_eq!(monitor.block_id("wf_live"), Some(7));
        assert_eq!(monitor.live_count(), 1);
        assert!(monitor.restored_runs().next().is_none());
    }
}
