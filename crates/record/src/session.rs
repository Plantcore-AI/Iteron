//! Session management as a projection of the rollout (SESS-1/SESS-4, R5 design §2).
//!
//! A session is not a second source of truth: it is a *projection* of its per-run rollout
//! (ADR-006). Every field of [`SessionMeta`] is derivable by replaying the record — `title`
//! from the first user message, `turns`/`cache_hit`/`last_outcome` from recorded events,
//! and `cwd`/initial model/`effort`/`created_at`/`parent` from the seq-0
//! [`iteron_protocol::EventKind::RunStart`] genesis header. Later [`iteron_protocol::EventKind::ModelSelected`] events update the
//! provider/model projection. The `.meta.json` per-run file and compacted `sessions.index` are a
//! rebuildable cache in front of that replay (R5 design §2.4): a missing or stale cache is never an
//! error, it degrades to a replay.
//!
//! Fork is a record operation, not an in-place edit. The rollout is append-only and
//! hash-chained (ADR-008), so a single log cannot branch in place. A fork is therefore a new
//! `RunId` whose genesis records the branch point by *reference* (SESS-1/SESS-5): the child
//! stores only its new events and, on load, replays the parent prefix up to the fork seq. To
//! make that reference tamper-evident (ADR-008 §4, R5-review Risk 3), the genesis pins
//! `parent_hash_at_seq` — the parent chain's hash at the fork point — so a child replay
//! detects an altered parent prefix rather than trusting it. Unknown event kinds are tolerated
//! on replay via `iteron_protocol::EventKind::Unknown` (R5-review Risk 6), so a cross-version scan does not fail.

mod bounded_reindex;
mod cache_receipts;
mod index;
mod lifecycle;
mod model;
mod paths;
mod projection;
mod replay;
pub use bounded_reindex::{ReindexReceipt, reindex_bounded};
#[path = "session_private_cache.rs"]
pub(crate) mod private_cache;
#[path = "tunables.rs"]
pub mod tunables;
use index::{SESSION_INDEX_HEADER, merge_rewrite_index, sidecar_is_unchanged};
pub use index::{
    SessionPage, SessionPageCursor, list, list_scoped, meta, meta_with_pricing, most_recent, page,
    reindex,
};
pub(crate) use index::{
    cached_projection_is_current, invalidate_rebuildable_indexes, write_meta, write_meta_if_current,
};
pub use lifecycle::{DeleteSessionError, PrunePolicy, PruneReport, delete, prune};
pub(crate) use lifecycle::{complete_deleted_session_cleanup, prune_at};
pub use model::{Provenance, ScopedEvent, SessionAncestryReceipt, SessionMeta, title_from_text};
use paths::per_run_meta_path;
pub(crate) use projection::{SessionProjection, bounded_meta};
pub(crate) use replay::{bounded_physical_events, bounded_scoped};
pub use replay::{
    fork, fork_with_checkpoint, fork_with_resolved_tunables, fork_with_tunables_snapshot,
    load_forked, load_forked_scoped, replay_run_timed,
};

#[cfg(test)]
std::thread_local! {
    static READ_CHAIN_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECEIPT_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static AFTER_PAGE_SNAPSHOT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;
