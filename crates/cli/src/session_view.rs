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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use core_protocol::{RunId, TenantId};
use core_record::SessionMeta;
use core_record::redact::redact_event;
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
    core_protocol::MAX_AGENT_DEFINITION_TAG_BYTES;
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
    updated_at: u64,
    updated_at_subsec_nanos: u32,
    run_id: String,
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
    digest.update(b"core-cli-session-cursor-v1\0");
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
    if encoded.len() > MAX_CURSOR_BYTES {
        anyhow::bail!("session cursor exceeds its byte bound");
    }
    Ok(encoded)
}

fn decode_cursor<T: for<'de> Deserialize<'de>>(token: &str) -> anyhow::Result<T> {
    if token.is_empty() || token.len() > MAX_CURSOR_BYTES {
        anyhow::bail!("session cursor is empty or exceeds its byte bound");
    }
    let envelope_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| anyhow::anyhow!("session cursor is not valid base64url"))?;
    if envelope_bytes.len() > MAX_CURSOR_BYTES {
        anyhow::bail!("decoded session cursor exceeds its byte bound");
    }
    let envelope: CursorEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| anyhow::anyhow!("session cursor envelope is invalid"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| anyhow::anyhow!("session cursor payload is invalid"))?;
    if payload.len() > MAX_CURSOR_BYTES || cursor_digest(&payload) != envelope.digest {
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
    if core_record::redact::scrub_route_identifier(tag) != tag {
        anyhow::bail!("--agent-definition-tag looks like a credential and cannot be recorded");
    }
    Ok(())
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
    let metas = core_record::session::list_scoped(runs_dir, tenant, repo);
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
) -> anyhow::Result<SessionListPage> {
    if let Some(tag) = agent_definition_tag {
        validate_agent_definition_tag(tag)?;
    }
    let limit = limit.clamp(1, MAX_SESSIONS_PER_PAGE);
    let metas: Vec<_> = core_record::list(runs_dir, tenant)
        .into_iter()
        .filter(|meta| {
            agent_definition_tag.is_none_or(|tag| meta.agent_definition_tag.as_deref() == Some(tag))
        })
        .collect();
    let start = if let Some(token) = cursor {
        let cursor: SessionListCursor = decode_cursor(token)?;
        if cursor.version != CURSOR_VERSION
            || cursor.kind != "session_list"
            || cursor.tenant != tenant.0
            || cursor.agent_definition_tag.as_deref() != agent_definition_tag
        {
            anyhow::bail!("session cursor does not belong to this list query");
        }
        metas
            .iter()
            .position(|meta| {
                meta.updated_at == cursor.updated_at
                    && meta.updated_at_subsec_nanos == cursor.updated_at_subsec_nanos
                    && meta.run_id.0 == cursor.run_id
            })
            .map(|index| index + 1)
            .ok_or_else(|| anyhow::anyhow!("session cursor is stale for the current list"))?
    } else {
        0
    };
    let end = start.saturating_add(limit).min(metas.len());
    let sessions = metas[start..end]
        .iter()
        .map(SessionSummary::from_meta)
        .collect();
    let next_cursor = if end < metas.len() {
        let last = &metas[end - 1];
        Some(encode_cursor(&SessionListCursor {
            version: CURSOR_VERSION,
            kind: "session_list".into(),
            tenant: tenant.0.clone(),
            agent_definition_tag: agent_definition_tag.map(str::to_owned),
            updated_at: last.updated_at,
            updated_at_subsec_nanos: last.updated_at_subsec_nanos,
            run_id: last.run_id.0.clone(),
        })?)
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

/// Return one tail-first transcript page while preserving chronological order inside the page.
/// The cursor stores the exclusive older boundary, so later appends cannot duplicate or skip an
/// already traversed historical event.
pub(crate) fn read_transcript_page(
    runs_dir: &Path,
    run: &RunId,
    cursor: Option<&str>,
    schema_version: u32,
) -> anyhow::Result<SessionTranscriptPage> {
    read_transcript_page_with_limit(runs_dir, run, cursor, schema_version, MAX_TRANSCRIPT_BYTES)
}

fn read_transcript_page_with_limit(
    runs_dir: &Path,
    run: &RunId,
    cursor: Option<&str>,
    schema_version: u32,
    max_bytes: usize,
) -> anyhow::Result<SessionTranscriptPage> {
    let events = core_record::load_forked(runs_dir, run)?;
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
