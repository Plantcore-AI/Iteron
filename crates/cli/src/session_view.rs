//! The machine read path for session listing and transcript retrieval.
//!
//! The data was always durable and always readable: `.iteron/runs/<run>.jsonl`, a per-run
//! `.meta.json`, and a compacted `sessions.index`. The only published surface was `--sessions`,
//! which prints human text, and combining it with a machine format was refused outright. For a
//! client that is not a terminal the supported answer was therefore "there is none", so it read
//! `sessions.index` directly and coupled itself to a private layout the record layer is free to
//! change.
//!
//! This publishes the read contract instead, and owns it here rather than in `iteron-record`, which
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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use iteron_protocol::{RunId, TenantId};
use iteron_record::SessionMeta;
use iteron_record::redact::redact_event;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The schema a client pins on. Additive changes keep the number; a removal or a retype moves it.
pub(crate) const SESSION_VIEW_SCHEMA_VERSION: u32 = 1;

/// The most sessions one listing returns. A repository with more is paged, not truncated silently.
pub(crate) const MAX_SESSIONS_PER_PAGE: usize = 200;

/// The most transcript bytes one read returns, measured on the serialized events.
pub(crate) const MAX_TRANSCRIPT_BYTES: usize = 8 * 1024 * 1024;

/// Operator-defined grouping metadata is deliberately small enough for every session page.
pub(crate) const MAX_AGENT_DEFINITION_TAG_BYTES: usize =
    iteron_protocol::MAX_AGENT_DEFINITION_TAG_BYTES;
const MAX_CURSOR_BYTES: usize = 4 * 1024;
const CURSOR_VERSION: u32 = 1;

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
    /// Bounded operator-defined grouping metadata. Legacy sessions are untagged.
    pub agent_definition_tag: Option<String>,
}

impl SessionSummary {
    fn from_meta(meta: &SessionMeta) -> Self {
        Self {
            // Every string here crosses into a durable client surface, so it goes through the same
            // scrubber the live seam uses. A title is the first line of a user message.
            run_id: meta.run_id.to_string(),
            title: iteron_record::redact::scrub(&meta.title),
            turns: meta.turns,
            provider_id: iteron_record::redact::scrub_route_identifier(&meta.provider_id),
            model: iteron_record::redact::scrub_route_identifier(&meta.model),
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
            agent_definition_tag: meta.agent_definition_tag.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionListPage {
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    pub sessions: Vec<SessionSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionTranscriptPage {
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    pub run_id: String,
    pub events: Vec<serde_json::Value>,
    pub older_cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CursorEnvelope {
    payload: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionListCursor {
    version: u32,
    kind: String,
    tenant: String,
    agent_definition_tag: Option<String>,
    record: iteron_record::SessionPageCursor,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionListError {
    #[error("invalid session cursor: {0}")]
    InvalidCursor(String),
    #[error("session cursor is stale; restart the list without a cursor")]
    CursorStale,
    #[error("session index is unavailable after one rebuild attempt")]
    IndexUnavailable,
    #[error(transparent)]
    Record(#[from] iteron_record::RecordError),
}

#[derive(Debug, Serialize, Deserialize)]
struct TranscriptCursor {
    version: u32,
    kind: String,
    run_id: String,
    end_index: usize,
}

fn cursor_digest(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"iteron-cli-session-cursor-v1\0");
    digest.update(payload);
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn encode_cursor<T: Serialize>(cursor: &T) -> anyhow::Result<String> {
    let payload = serde_json::to_vec(cursor)?;
    let envelope = CursorEnvelope {
        digest: cursor_digest(&payload),
        payload: URL_SAFE_NO_PAD.encode(payload),
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope)?);
    if encoded.len()
        > iteron_tunables::param_integer("cli.session_view.max_cursor_bytes", MAX_CURSOR_BYTES)
    {
        anyhow::bail!("session cursor exceeds its byte bound");
    }
    Ok(encoded)
}

fn decode_cursor<T: for<'de> Deserialize<'de>>(token: &str) -> anyhow::Result<T> {
    if token.is_empty()
        || token.len()
            > iteron_tunables::param_integer("cli.session_view.max_cursor_bytes", MAX_CURSOR_BYTES)
    {
        anyhow::bail!("session cursor is empty or exceeds its byte bound");
    }
    let envelope_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| anyhow::anyhow!("session cursor is not valid base64url"))?;
    if envelope_bytes.len()
        > iteron_tunables::param_integer("cli.session_view.max_cursor_bytes", MAX_CURSOR_BYTES)
    {
        anyhow::bail!("decoded session cursor exceeds its byte bound");
    }
    let envelope: CursorEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| anyhow::anyhow!("session cursor envelope is invalid"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| anyhow::anyhow!("session cursor payload is invalid"))?;
    if payload.len()
        > iteron_tunables::param_integer("cli.session_view.max_cursor_bytes", MAX_CURSOR_BYTES)
        || cursor_digest(&payload) != envelope.digest
    {
        anyhow::bail!("session cursor integrity check failed");
    }
    serde_json::from_slice(&payload)
        .map_err(|_| anyhow::anyhow!("session cursor payload is invalid"))
}

pub(crate) fn validate_agent_definition_tag(tag: &str) -> anyhow::Result<()> {
    if tag.trim().is_empty()
        || tag.len() > MAX_AGENT_DEFINITION_TAG_BYTES
        || tag.chars().any(char::is_control)
    {
        anyhow::bail!(
            "--agent-definition-tag must be non-blank, control-free, and at most {MAX_AGENT_DEFINITION_TAG_BYTES} UTF-8 bytes"
        );
    }
    if iteron_record::redact::scrub_route_identifier(tag) != tag {
        anyhow::bail!("--agent-definition-tag looks like a credential and cannot be recorded");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionListDocument {
    pub schema_version: u32,
    /// Number of sessions in this bounded response. Exact corpus cardinality is deliberately not
    /// computed on the foreground path; `truncated` says whether another indexed page exists.
    pub total: usize,
    /// True when another indexed page exists.
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
/// A missing/corrupt index pays one explicit rebuild. A healthy index never lists run files or
/// hydrates sessions outside the requested page.
pub(crate) fn list_sessions(
    runs_dir: &Path,
    tenant: &TenantId,
    repo: Option<&Path>,
    limit: usize,
) -> Result<SessionListDocument, SessionListError> {
    let limit = limit.min(iteron_tunables::param_integer(
        "cli.session_view.max_sessions_per_page",
        MAX_SESSIONS_PER_PAGE,
    ));
    let page = indexed_page(runs_dir, tenant, repo, None, limit.max(1), true)?;
    let sessions = page
        .sessions
        .iter()
        .map(SessionSummary::from_meta)
        .collect::<Vec<_>>();
    Ok(SessionListDocument {
        schema_version: SESSION_VIEW_SCHEMA_VERSION,
        total: sessions.len(),
        truncated: page.has_more,
        sessions,
    })
}

/// One bounded metadata page for the human CLI. Normal indexed reads are O(limit); only an absent
/// or corrupt projection is rebuilt, once, before retrying.
pub(crate) fn list_session_metas(
    runs_dir: &Path,
    tenant: &TenantId,
    repo: Option<&Path>,
    limit: usize,
) -> Result<iteron_record::SessionPage, SessionListError> {
    indexed_page(runs_dir, tenant, repo, None, limit.max(1), true)
}

fn indexed_page(
    runs_dir: &Path,
    tenant: &TenantId,
    repo: Option<&Path>,
    cursor: Option<iteron_record::SessionPageCursor>,
    limit: usize,
    allow_rebuild: bool,
) -> Result<iteron_record::SessionPage, SessionListError> {
    let mut page = iteron_record::page(runs_dir, tenant, repo, cursor, Some(limit));
    if page.cursor_stale {
        return Err(SessionListError::CursorStale);
    }
    if !page.index_ready && page.rebuild_recommended && allow_rebuild && cursor.is_none() {
        iteron_record::reindex(runs_dir)?;
        page = iteron_record::page(runs_dir, tenant, repo, None, Some(limit));
    }
    if page.cursor_stale {
        Err(SessionListError::CursorStale)
    } else if page.index_ready {
        Ok(page)
    } else {
        Err(SessionListError::IndexUnavailable)
    }
}

/// Return one stable newest-first v4 page. The cursor is tied to tenant, filter, and the exact
/// final row of the previous page; a changed or cross-query token is rejected instead of silently
/// producing duplicates or gaps.
pub(crate) fn list_sessions_page(
    runs_dir: &Path,
    tenant: &TenantId,
    agent_definition_tag: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
    schema_version: u32,
) -> Result<SessionListPage, SessionListError> {
    if let Some(tag) = agent_definition_tag {
        validate_agent_definition_tag(tag)
            .map_err(|error| SessionListError::InvalidCursor(error.to_string()))?;
    }
    let limit = limit.clamp(
        1,
        iteron_tunables::param_integer(
            "cli.session_view.max_sessions_per_page",
            MAX_SESSIONS_PER_PAGE,
        ),
    );
    let mut record_cursor = if let Some(token) = cursor {
        let cursor: SessionListCursor = decode_cursor(token)
            .map_err(|error| SessionListError::InvalidCursor(error.to_string()))?;
        if cursor.version != CURSOR_VERSION
            || cursor.kind != "session_list"
            || cursor.tenant != tenant.0
            || cursor.agent_definition_tag.as_deref() != agent_definition_tag
        {
            return Err(SessionListError::InvalidCursor(
                "cursor does not belong to this list query".into(),
            ));
        }
        Some(cursor.record)
    } else {
        None
    };

    // A sparse tag filter must not turn one foreground page into a corpus scan. Examine at most
    // four indexed rows per requested result and return an explicit continuation if more remain.
    let scan_budget = limit
        .saturating_mul(4)
        .clamp(limit, MAX_SESSIONS_PER_PAGE * 4);
    let mut scanned = 0usize;
    let mut sessions = Vec::with_capacity(limit);
    let mut has_more = false;
    while sessions.len() < limit && scanned < scan_budget {
        let page = indexed_page(
            runs_dir,
            tenant,
            None,
            record_cursor,
            1,
            cursor.is_none() && record_cursor.is_none(),
        )?;
        scanned = scanned.saturating_add(page.examined.max(1));
        if let Some(meta) = page.sessions.first()
            && agent_definition_tag
                .is_none_or(|tag| meta.agent_definition_tag.as_deref() == Some(tag))
        {
            sessions.push(SessionSummary::from_meta(meta));
        }
        has_more = page.has_more;
        record_cursor = page.next_cursor;
        if !has_more || record_cursor.is_none() {
            break;
        }
    }
    let next_cursor = if has_more {
        record_cursor
            .map(|record| SessionListCursor {
                version: CURSOR_VERSION,
                kind: "session_list".into(),
                tenant: tenant.0.clone(),
                agent_definition_tag: agent_definition_tag.map(str::to_owned),
                record,
            })
            .map(|cursor| encode_cursor(&cursor))
            .transpose()
            .map_err(|error| SessionListError::InvalidCursor(error.to_string()))?
    } else {
        None
    };
    Ok(SessionListPage {
        schema_version,
        frame_type: "session_list_page",
        sessions,
        next_cursor,
    })
}

/// Read one session's transcript, bounded and redacted.
///
/// The logical history is used, so a fork returns the conversation a reader would see rather than
/// only the child's own divergent tail.
pub(crate) fn read_transcript(
    runs_dir: &Path,
    run: &RunId,
) -> Result<TranscriptDocument, iteron_record::RecordError> {
    let events = iteron_record::load_forked(runs_dir, run)?;
    let total_events = events.len();
    let mut budget = 0usize;
    let mut truncated = false;
    let mut rendered = Vec::with_capacity(total_events);
    for event in &events {
        let scrubbed = redact_event(event);
        let value = serde_json::to_value(&scrubbed)?;
        // Measure what the client will actually receive, not the in-memory event.
        let size = value.to_string().len();
        if budget.saturating_add(size)
            > iteron_tunables::param_integer(
                "cli.session_view.max_transcript_bytes",
                MAX_TRANSCRIPT_BYTES,
            )
        {
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

/// Return one tail-first transcript page while preserving chronological order inside the page.
/// The cursor stores the exclusive older boundary, so later appends cannot duplicate or skip an
/// already traversed historical event.
pub(crate) fn read_transcript_page(
    runs_dir: &Path,
    run: &RunId,
    cursor: Option<&str>,
    schema_version: u32,
) -> anyhow::Result<SessionTranscriptPage> {
    read_transcript_page_with_limit(
        runs_dir,
        run,
        cursor,
        schema_version,
        iteron_tunables::param_integer(
            "cli.session_view.max_transcript_bytes",
            MAX_TRANSCRIPT_BYTES,
        ),
    )
}

fn read_transcript_page_with_limit(
    runs_dir: &Path,
    run: &RunId,
    cursor: Option<&str>,
    schema_version: u32,
    max_bytes: usize,
) -> anyhow::Result<SessionTranscriptPage> {
    let events = iteron_record::load_forked(runs_dir, run)?;
    let end = if let Some(token) = cursor {
        let cursor: TranscriptCursor = decode_cursor(token)?;
        if cursor.version != CURSOR_VERSION
            || cursor.kind != "session_transcript"
            || cursor.run_id != run.0
            || cursor.end_index > events.len()
        {
            anyhow::bail!("transcript cursor does not belong to this run");
        }
        cursor.end_index
    } else {
        events.len()
    };

    let mut start = end;
    let mut budget = 0usize;
    let mut rendered = Vec::new();
    while start > 0 {
        let scrubbed = redact_event(&events[start - 1]);
        let value = serde_json::to_value(&scrubbed)?;
        let size = serde_json::to_vec(&value)?.len().saturating_add(1);
        if budget.saturating_add(size) > max_bytes {
            if rendered.is_empty() {
                anyhow::bail!("one transcript event exceeds the page byte bound");
            }
            break;
        }
        budget = budget.saturating_add(size);
        rendered.push(value);
        start -= 1;
    }
    rendered.reverse();
    let older_cursor = if start > 0 {
        Some(encode_cursor(&TranscriptCursor {
            version: CURSOR_VERSION,
            kind: "session_transcript".into(),
            run_id: run.0.clone(),
            end_index: start,
        })?)
    } else {
        None
    };
    Ok(SessionTranscriptPage {
        schema_version,
        frame_type: "session_transcript_page",
        run_id: run.to_string(),
        events: rendered,
        older_cursor,
    })
}

#[cfg(test)]
#[path = "session_view_tests.rs"]
mod tests;
