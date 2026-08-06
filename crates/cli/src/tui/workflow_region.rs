//! The workflow region's store: which QuickJS `core-workflow` runs this TUI is watching, which one
//! the operator's attention is pointed at, and whether a run's finished agents are collapsed.
//!
//! # What lives here, and what deliberately does not
//!
//! A run's CONTENT — its phase boxes, agent rows, logs, and settled flag — lives in the
//! [`crate::block::WorkflowRunCard`] inside the transcript, and the transcript remains the
//! authority the renderer reads (ADR-015 semantic transcript). This store holds only what the
//! transcript cannot say on its own:
//!
//! * the run id → block id binding, so a progress event that arrives later finds the one card that
//!   already exists for its run instead of opening a second one (design §3.2 upsert),
//! * whether the engine future for that run has settled,
//! * which run the region is focused on,
//! * whether that run's finished agents are collapsed (design §3.3).
//!
//! Copying the tree in here as well would create a second truth that drifts the first time an
//! event lands on one copy and not the other, so it is not copied. The collapse bit is the single
//! piece of state that necessarily exists in both places, because the renderer reads it off the
//! card: it has exactly ONE writer, [`WorkflowMonitor::toggle_collapsed_for_block`], and the
//! card's `verbose` field is written from that call's return value at the same instant. There is
//! no second path that can move one without the other.
//!
//! # This store decides where a run is watched
//!
//! It is the authority for ONE placement question, and [`WorkflowMonitor::region_block`] is the
//! whole of it: while a run is live, its tree is drawn in the workflow region above the composer
//! and the transcript draws nothing for it; once it settles, the region lets go and the card it
//! was drawing — the same card, at the position in the conversation where the run began — becomes
//! the run's permanent record. The tree is therefore never rendered twice and never disappears.
//!
//! The region costs exactly zero rows until `region_block` answers `Some`, so a session in which
//! no workflow ever runs has the layout it had before this store existed.
//!
//! # Runs this process did not launch
//!
//! [`WorkflowMonitor::rehydrate`] reads the workspace's durable run sidecars back after a restart.
//! Those rows are inventory: they carry no card, they are registered settled, and
//! [`WorkflowRun::live`] refuses them — because no event this session receives can ever belong to
//! one, and a store that claimed otherwise would make the status row's live counter lie.

use super::workflow_rehydrate;

/// Prior runs retained in the restart inventory. Sixteen keeps `/workflows` readable and, more
/// importantly, bounds first-frame sidecar reads even when the directory holds years of history.
pub(crate) const RESTORE_LIMIT: usize = 16;

/// One watched run. Identity plus the presentation state the transcript does not carry.
#[derive(Debug, Clone)]
struct WorkflowRun {
    run_id: String,
    /// The transcript block rendering this run's tree, or `None` for a run rebuilt from disk, which
    /// has no card and never gets one (see [`WorkflowMonitor::rehydrate`]).
    block_id: Option<u64>,
    /// The engine future resolved. The card stays in the transcript; the live binding does not.
    settled: bool,
    /// Finished agent rows collapse to one dim summary line. `true` is the card's own default
    /// (`WorkflowRunCard::verbose == false`), so a fresh entry and a fresh card agree by
    /// construction.
    collapsed: bool,
    /// `Some` for a run this process did NOT launch, read back off disk after a restart. The
    /// summary its sidecars stated is all such a run has; there is no card and no event stream.
    restored: Option<crate::workflow::RunListing>,
}

impl WorkflowRun {
    /// Whether THIS process is driving this run right now.
    ///
    /// Two independent reasons a restored run can never answer `true`, which is deliberate: it is
    /// registered already-settled, AND it has no block. Every liveness question in this store goes
    /// through this one predicate, so a future edit that flips one of those two still cannot make
    /// a restored run claim liveness — and `live_count` feeds the status row's `⟳ n run(s)`, which
    /// would otherwise stand there lying for the rest of the session about a run no event will
    /// ever arrive for.
    fn live(&self) -> bool {
        self.restored.is_none() && !self.settled && self.block_id.is_some()
    }
}

/// What a run's lifecycle just told the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkflowRunSignal {
    /// A card was minted for this run at `block_id`, and this run's events land on that block.
    Live { block_id: u64 },
    /// The engine future for this run resolved.
    Settled,
}

/// The workflow region's store: the runs it is watching, its focus, and its collapse state.
#[derive(Debug, Default)]
pub(crate) struct WorkflowMonitor {
    /// First-seen order. A run that settles keeps its slot until [`Self::clear_finished`] or
    /// [`Self::reset`]; a run that speaks again after settling is replaced in place, so the order
    /// stays the order the operator saw the cards appear in.
    runs: Vec<WorkflowRun>,
    /// The run the region is pointed at, by id rather than by position so that clearing finished
    /// runs cannot silently re-point it at a different run.
    focus: Option<String>,
    /// Set after the first rehydration attempt; cleared only by [`Self::reset`].
    rehydrated: bool,
}

impl WorkflowMonitor {
    /// Record one lifecycle signal for `run_id`.
    ///
    /// This takes the run's lifecycle, not its `ProgressEvent`s: ingesting the events themselves
    /// would mean rebuilding the phase→agent tree here, which is precisely the second copy this
    /// store must not hold. The card ingests the events; the monitor ingests what happened to the
    /// run.
    pub(crate) fn ingest(&mut self, run_id: &str, signal: WorkflowRunSignal) {
        match signal {
            WorkflowRunSignal::Live { block_id } => {
                let fresh = WorkflowRun {
                    run_id: run_id.to_owned(),
                    block_id: Some(block_id),
                    settled: false,
                    collapsed: true,
                    restored: None,
                };
                // A run whose card is minted a second time (it settled, then spoke again) takes
                // the new block and the new card's collapse default, and keeps its position. The
                // same replacement upgrades a restored row to a driven run, which is the honest
                // outcome if a run id this process launches ever coincides with one on disk.
                match self.position(run_id) {
                    Some(pos) => self.runs[pos] = fresh,
                    None => self.runs.push(fresh),
                }
                self.focus = Some(run_id.to_owned());
            }
            WorkflowRunSignal::Settled => {
                if let Some(pos) = self.position(run_id) {
                    self.runs[pos].settled = true;
                }
                // Focus deliberately stays on a run that just finished: the operator is still
                // looking at the tree that settled in front of them.
            }
        }
    }

    /// The block a LIVE run's events land on.
    ///
    /// A settled run answers `None`. Its card is still in the transcript, but the run is over, so
    /// a progress event arriving afterwards mints a fresh card — the same thing that happened when
    /// this binding was deleted on settle. A restored run answers `None` for good: it has no card,
    /// and this session's engine has no run by that id to send progress for.
    pub(crate) fn block_id(&self, run_id: &str) -> Option<u64> {
        self.runs
            .iter()
            .find(|run| run.run_id == run_id && run.live())
            .and_then(|run| run.block_id)
    }

    /// Toggle the collapse state of the run rendered by `block_id` and report the NEW value; `None`
    /// for a block this store does not know, whose card must fall back to flipping its own field.
    ///
    /// This is the ONLY writer of the collapse bit — see the module note on why one writer is what
    /// keeps the card's mirrored `verbose` field from drifting. It is keyed by block rather than by
    /// run id because the fold arrives as a transcript position, and because a card carries the
    /// SANITIZED run id (`ui_safe_text`) while this store is keyed by the raw id the engine emits:
    /// matching those two strings would silently miss for exactly the run ids that needed
    /// sanitizing.
    pub(crate) fn toggle_collapsed_for_block(&mut self, block_id: u64) -> Option<bool> {
        let pos = self
            .runs
            .iter()
            .position(|run| run.block_id == Some(block_id))?;
        self.runs[pos].collapsed = !self.runs[pos].collapsed;
        Some(self.runs[pos].collapsed)
    }

    /// Drop every run, live or settled. Used when the transcript's projections are dropped
    /// wholesale (session adoption), where a retained binding would point at a block that the
    /// incoming run's transcript no longer contains.
    /// The adopted run's own prior workflows are what should be on screen afterwards, so the
    /// rehydration flag is cleared too and the next frame reads the directory again.
    pub(crate) fn reset(&mut self) {
        self.runs.clear();
        self.focus = None;
        self.rehydrated = false;
    }

    /// Rebuild the runs this workspace has on disk, ONCE per store.
    ///
    /// A run's tree lives in a [`crate::block::WorkflowRunCard`], which is memory-only: restarting
    /// leaves the frontend with no idea that this workspace was in the middle of anything. The runs
    /// themselves are durable — `core workflow list` reads them from an entirely different process
    /// — so after a restart this store is the one thing that is emptier than the truth.
    ///
    /// An inventory row per run, exactly what the command-side readers state. No card is minted:
    /// the journal records no `agent()` label or `phase()` title, so a reconstructed tree could
    /// only be an empty box claiming `0/0 agents` over a journal that says otherwise.
    ///
    /// Restored runs are registered SETTLED and blockless, so [`WorkflowRun::live`] refuses them
    /// twice over. A sidecar may say `running` in another process, but this process cannot receive
    /// its events; counting it live would permanently corrupt S6's status-line count. A locally
    /// driven run wins over a disk row with the same id.
    ///
    /// Returns how many rows were added. `None` for a session with no run directory (which still
    /// settles the flag — the path is session-constant, so retrying it every frame would only cost
    /// syscalls).
    pub(crate) fn rehydrate(&mut self, workflows_dir: Option<&std::path::Path>) -> usize {
        if self.rehydrated {
            return 0;
        }
        self.rehydrated = true;
        let Some(dir) = workflows_dir else {
            return 0;
        };
        let mut added = 0;
        for restored in workflow_rehydrate::restore(dir, RESTORE_LIMIT) {
            if self.position(&restored.run_id).is_some() {
                continue;
            }
            self.runs.push(WorkflowRun {
                run_id: restored.run_id.clone(),
                block_id: None,
                settled: true,
                collapsed: true,
                restored: Some(restored),
            });
            added += 1;
        }
        added
    }

    /// The runs read back off disk, newest creation first — history, not this session's work.
    pub(crate) fn restored_runs(&self) -> impl Iterator<Item = &crate::workflow::RunListing> + '_ {
        self.runs.iter().filter_map(|run| run.restored.as_ref())
    }

    /// The block the workflow region draws this frame, or `None` when the region must cost zero
    /// rows.
    ///
    /// Only a LIVE run is watched here. Focus picks which one when several are running, but focus
    /// survives a settle on purpose (see [`Self::ingest`]), so it is filtered rather than trusted:
    /// a settled run's card belongs to the transcript from the instant it settles, and answering
    /// with it would keep the region holding a tree that has stopped moving while the conversation
    /// still owed the reader its record. When focus names a settled run the region falls back to
    /// the most recently started live run, and to `None` when nothing is running at all — which is
    /// every frame of a session that never launched a workflow.
    ///
    /// `draw` skips exactly this block in the transcript pass, so this one answer is what keeps a
    /// tree from being rendered twice or nowhere.
    pub(crate) fn region_block(&self) -> Option<u64> {
        self.focus
            .as_deref()
            .and_then(|run_id| {
                self.runs
                    .iter()
                    .find(|run| run.run_id == run_id && run.live())
            })
            .or_else(|| self.runs.iter().rev().find(|run| run.live()))
            .and_then(|run| run.block_id)
    }

    /// The blocks of every run that is still running, in first-seen order.
    ///
    /// Clearing the conversation does not cancel a QuickJS run, so these are the cards the
    /// transcript has to keep: they are the region's backing store, and dropping them would leave
    /// a run with nowhere to draw itself for the rest of its life.
    pub(crate) fn live_blocks(&self) -> Vec<u64> {
        self.runs
            .iter()
            .filter(|run| run.live())
            .filter_map(|run| run.block_id)
            .collect()
    }

    /// How many runs are still live.
    ///
    /// Read by the status row's compact liveness bit (`crate::tui::status_right_bits`), which is
    /// the only indication a run is still going on a terminal too short to draw the region.
    /// The test-only marker S5 carried is gone because that bit is a real caller.
    pub(crate) fn live_count(&self) -> usize {
        self.runs.iter().filter(|run| run.live()).count()
    }

    /// Whether this run is live — it has a card that events still land on.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_live(&self, run_id: &str) -> bool {
        self.block_id(run_id).is_some()
    }

    /// Forget every run that is not live, keeping the live ones. Focus follows: a focus on a run
    /// that was just forgotten is dropped rather than left dangling on an id nothing can resolve.
    ///
    /// Restored rows leave here with the settled ones — clearing the conversation clears its
    /// history, and a run from a previous process is history. They do not come back: `/clear` does
    /// not touch the rehydration flag, so a cleared conversation stays cleared.
    pub(crate) fn clear_finished(&mut self) {
        self.runs.retain(|run| run.live());
        if let Some(focused) = self.focus.as_deref()
            && self.position(focused).is_none()
        {
            self.focus = None;
        }
    }

    /// The run the region is pointed at.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn focus(&self) -> Option<&str> {
        self.focus.as_deref()
    }

    /// Point the region at a run it knows. Reports whether the run was known: focus never names a
    /// run this store cannot resolve.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn focus_on(&mut self, run_id: &str) -> bool {
        if self.position(run_id).is_some() {
            self.focus = Some(run_id.to_owned());
            true
        } else {
            false
        }
    }

    /// Whether this run's finished agents are collapsed; `None` for a run this store does not know.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn collapsed(&self, run_id: &str) -> Option<bool> {
        self.position(run_id).map(|pos| self.runs[pos].collapsed)
    }

    /// Position of a run's entry, live or settled.
    fn position(&self, run_id: &str) -> Option<usize> {
        self.runs.iter().position(|run| run.run_id == run_id)
    }
}

#[cfg(test)]
mod tests {
    use super::{WorkflowMonitor, WorkflowRunSignal};

    fn live(block_id: u64) -> WorkflowRunSignal {
        WorkflowRunSignal::Live { block_id }
    }

    /// The binding a late progress event resolves against, and the settle that ends it. This is the
    /// behaviour the `App`-owned `HashMap` had: present while live, gone once the run settled.
    #[test]
    fn a_live_run_resolves_to_its_block_and_a_settled_one_does_not() {
        let mut monitor = WorkflowMonitor::default();
        monitor.ingest("wf_1", live(7));

        assert_eq!(monitor.block_id("wf_1"), Some(7));
        assert!(monitor.is_live("wf_1"));
        assert_eq!(monitor.live_count(), 1);
        assert_eq!(monitor.block_id("wf_2"), None);

        monitor.ingest("wf_1", WorkflowRunSignal::Settled);
        assert_eq!(monitor.block_id("wf_1"), None, "the run is over");
        assert!(!monitor.is_live("wf_1"));
        assert_eq!(monitor.live_count(), 0);
    }

    /// A settled run that speaks again gets a fresh card, so its entry must adopt that card's block
    /// AND that card's collapse default — otherwise the store would answer for a block that no
    /// longer renders the run.
    #[test]
    fn a_re_minted_card_replaces_the_entry_in_place() {
        let mut monitor = WorkflowMonitor::default();
        monitor.ingest("wf_1", live(7));
        monitor.ingest("wf_2", live(8));
        monitor.toggle_collapsed_for_block(7);
        assert_eq!(monitor.collapsed("wf_1"), Some(false));

        monitor.ingest("wf_1", WorkflowRunSignal::Settled);
        monitor.ingest("wf_1", live(9));

        assert_eq!(monitor.block_id("wf_1"), Some(9));
        assert_eq!(
            monitor.collapsed("wf_1"),
            Some(true),
            "a fresh card starts collapsed, and the entry mirrors the card"
        );
        assert_eq!(monitor.live_count(), 2, "wf_2 was not disturbed");
    }

    /// Collapse is a toggle with a defined answer for a block this store does not know, because the
    /// caller uses that `None` to fall back to the card's own field instead of guessing here.
    #[test]
    fn collapse_toggles_by_block_and_an_unknown_block_reports_nothing() {
        let mut monitor = WorkflowMonitor::default();
        monitor.ingest("wf_1", live(7));

        assert_eq!(
            monitor.collapsed("wf_1"),
            Some(true),
            "cards start collapsed"
        );
        assert_eq!(monitor.toggle_collapsed_for_block(7), Some(false));
        assert_eq!(monitor.collapsed("wf_1"), Some(false));
        assert_eq!(monitor.toggle_collapsed_for_block(7), Some(true));

        assert_eq!(monitor.toggle_collapsed_for_block(999), None);
        assert_eq!(monitor.collapsed("nobody"), None);

        // A settled run keeps its collapse state: its card is still in the transcript and still
        // foldable.
        monitor.ingest("wf_1", WorkflowRunSignal::Settled);
        assert_eq!(monitor.toggle_collapsed_for_block(7), Some(false));
    }

    #[test]
    fn focus_names_a_known_run_and_never_a_forgotten_one() {
        let mut monitor = WorkflowMonitor::default();
        assert_eq!(monitor.focus(), None);

        monitor.ingest("wf_1", live(7));
        assert_eq!(monitor.focus(), Some("wf_1"), "a new card takes the focus");
        monitor.ingest("wf_2", live(8));
        assert_eq!(monitor.focus(), Some("wf_2"));

        assert!(monitor.focus_on("wf_1"));
        assert!(!monitor.focus_on("nobody"));
        assert_eq!(
            monitor.focus(),
            Some("wf_1"),
            "an unknown run never takes it"
        );

        monitor.ingest("wf_1", WorkflowRunSignal::Settled);
        assert_eq!(
            monitor.focus(),
            Some("wf_1"),
            "the operator is still looking at the tree that just settled"
        );

        monitor.clear_finished();
        assert_eq!(
            monitor.focus(),
            None,
            "focus does not dangle on a dropped run"
        );
        assert_eq!(monitor.live_count(), 1);
        assert_eq!(monitor.block_id("wf_2"), Some(8));
        assert_eq!(monitor.collapsed("wf_1"), None, "wf_1 is gone entirely");
    }

    /// The region watches what is RUNNING. Focus survives a settle on purpose, so `region_block`
    /// filters it rather than trusting it — otherwise the region would go on holding a tree that
    /// had stopped moving while the conversation still owed the reader its record.
    #[test]
    fn the_region_draws_a_live_run_and_lets_go_the_moment_it_settles() {
        let mut monitor = WorkflowMonitor::default();
        assert_eq!(
            monitor.region_block(),
            None,
            "no workflow ever ran: the region costs nothing"
        );
        assert!(monitor.live_blocks().is_empty());

        monitor.ingest("wf_1", live(7));
        assert_eq!(monitor.region_block(), Some(7));

        monitor.ingest("wf_2", live(8));
        assert_eq!(
            monitor.region_block(),
            Some(8),
            "a run that just started takes the focus, and with it the region"
        );
        assert_eq!(monitor.live_blocks(), vec![7, 8]);

        monitor.ingest("wf_2", WorkflowRunSignal::Settled);
        assert_eq!(
            monitor.focus(),
            Some("wf_2"),
            "focus is unchanged by design"
        );
        assert_eq!(
            monitor.region_block(),
            Some(7),
            "the region does not follow it: it falls back to what is still running"
        );
        assert_eq!(monitor.live_blocks(), vec![7]);

        monitor.ingest("wf_1", WorkflowRunSignal::Settled);
        assert_eq!(
            monitor.region_block(),
            None,
            "both cards are the transcript's records now"
        );
        assert!(monitor.live_blocks().is_empty());
    }

    #[test]
    fn reset_drops_live_and_settled_runs_alike() {
        let mut monitor = WorkflowMonitor::default();
        monitor.ingest("wf_1", live(7));
        monitor.ingest("wf_2", live(8));
        monitor.ingest("wf_2", WorkflowRunSignal::Settled);

        monitor.reset();

        assert_eq!(monitor.live_count(), 0);
        assert_eq!(monitor.block_id("wf_1"), None);
        assert_eq!(monitor.collapsed("wf_2"), None);
        assert_eq!(monitor.focus(), None);
    }
}
