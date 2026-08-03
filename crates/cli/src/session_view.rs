//! The machine read path for session listing and transcript retrieval.
//!
//! The data was always durable and always readable: `.core/runs/<run>.jsonl`, a per-run
//! `.meta.json`, and a compacted `sessions.index`. The only published surface was `--sessions`,
//! which prints human text, and combining it with a machine format was refused outright. For a
//! client that is not a terminal the supported answer was therefore "there is none", so it read
//! `sessions.index` directly and coupled itself to a private layout the record layer is free to
//! change.
//!
//! This publishes the read contract instead, and owns it here rather than in `core-record`, which
//! stays the truth. Nothing about how runs are written changes: this module opens no rollout for
//! append and mints no id.
//!
//! Three properties are worth stating because a client will rely on them.
//!
//! **Redaction is applied on read, not assumed from write.** `Rollout::append` scrubs on the way
//! in, so a record written by this build is already clean. A record written by an older build is
//! not, and a historical transcript is exactly where a leaked credential would sit. Every event
//! goes back through `redact_event` before it leaves this module.
//!
//! **Truncation is counted, never silent.** A page that stops early and a transcript that hits its
//! byte ceiling both say so in the document, because a client that cannot tell the difference
//! between "no more" and "we stopped" will render a partial conversation as a complete one.
//!
//! **A torn record is an error, not a short answer.** The rollout is hash-chained, so a partial
//! final line fails replay rather than yielding a prefix that looks whole. That failure is
//! surfaced; it is not smoothed into an empty transcript.

use core_protocol::{RunId, TenantId};
use core_record::SessionMeta;
use core_record::redact::redact_event;
use serde::Serialize;
use std::path::Path;

/// The schema a client pins on. Additive changes keep the number; a removal or a retype moves it.
pub(crate) const SESSION_VIEW_SCHEMA_VERSION: u32 = 1;

/// The most sessions one listing returns. A repository with more is paged, not truncated silently.
pub(crate) const MAX_SESSIONS_PER_PAGE: usize = 200;

/// The most transcript bytes one read returns, measured on the serialized events.
pub(crate) const MAX_TRANSCRIPT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionSummary {
    pub run_id: String,
    pub title: String,
    pub turns: u32,
    pub provider_id: String,
    pub model: String,
    /// `None` when the run has no signed pricing evidence. Absent is honest; zero would not be.
    pub cost_usd: Option<f64>,
    pub cost_state: &'static str,
    pub created_at: u64,
    pub updated_at: u64,
    /// Present only for a fork or rewind child.
    pub parent_run: Option<String>,
}

impl SessionSummary {
    fn from_meta(meta: &SessionMeta) -> Self {
        Self {
            // Every string here crosses into a durable client surface, so it goes through the same
            // scrubber the live seam uses. A title is the first line of a user message.
            run_id: meta.run_id.to_string(),
            title: core_record::redact::scrub(&meta.title),
            turns: meta.turns,
            provider_id: core_record::redact::scrub_route_identifier(&meta.provider_id),
            model: core_record::redact::scrub_route_identifier(&meta.model),
            cost_usd: meta.cost_usd(),
            cost_state: if meta.cost_usd().is_some() {
                "known"
            } else {
                "unknown"
            },
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            parent_run: meta
                .parent
                .as_ref()
                .map(|parent| parent.parent_run.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionListDocument {
    pub schema_version: u32,
    /// How many sessions matched the request, including its repository scope, before the page bound.
    pub total: usize,
    /// True when `total` exceeded the page bound, so a client knows the list is a page.
    pub truncated: bool,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TranscriptDocument {
    pub schema_version: u32,
    pub run_id: String,
    /// How many events the run holds, before the byte ceiling.
    pub total_events: usize,
    /// True when the byte ceiling stopped the read before the end of the run.
    pub truncated: bool,
    pub events: Vec<serde_json::Value>,
}

/// List sessions for a tenant, bounded and redacted.
///
/// `repo` is the same recorded-working-directory scope `--continue` selects from, so a client that
/// asks for "the sessions in this repository" and a continue that picks one of them cannot be
/// looking at two different sets. `None` lists every repository the runs dir holds.
///
/// Degrades exactly as the human path does: `core_record::list_scoped` falls back to replay when
/// the index is stale or missing, so a client still gets an answer rather than an error.
pub(crate) fn list_sessions(
    runs_dir: &Path,
    tenant: &TenantId,
    repo: Option<&Path>,
    limit: usize,
) -> SessionListDocument {
    let metas = core_record::list_scoped(runs_dir, tenant, repo);
    let total = metas.len();
    let limit = limit.min(MAX_SESSIONS_PER_PAGE);
    let sessions = metas
        .iter()
        .take(limit)
        .map(SessionSummary::from_meta)
        .collect();
    SessionListDocument {
        schema_version: SESSION_VIEW_SCHEMA_VERSION,
        total,
        truncated: total > limit,
        sessions,
    }
}

/// Read one session's transcript, bounded and redacted.
///
/// The logical history is used, so a fork returns the conversation a reader would see rather than
/// only the child's own divergent tail.
pub(crate) fn read_transcript(
    runs_dir: &Path,
    run: &RunId,
) -> Result<TranscriptDocument, core_record::RecordError> {
    let events = core_record::load_forked(runs_dir, run)?;
    let total_events = events.len();
    let mut budget = 0usize;
    let mut truncated = false;
    let mut rendered = Vec::with_capacity(total_events);
    for event in &events {
        let scrubbed = redact_event(event);
        let value = serde_json::to_value(&scrubbed)?;
        // Measure what the client will actually receive, not the in-memory event.
        let size = value.to_string().len();
        if budget.saturating_add(size) > MAX_TRANSCRIPT_BYTES {
            truncated = true;
            break;
        }
        budget = budget.saturating_add(size);
        rendered.push(value);
    }
    Ok(TranscriptDocument {
        schema_version: SESSION_VIEW_SCHEMA_VERSION,
        run_id: run.to_string(),
        total_events,
        truncated,
        events: rendered,
    })
}

#[cfg(test)]
#[path = "session_view_tests.rs"]
mod tests;
