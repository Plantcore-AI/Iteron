//! Verified session goals and redacted trace display from the scoped record/artifact owners.

use crate::artifacts::ArtifactReadScope;
use iteron_protocol::client_artifact::ClientArtifactCommandV1;
use iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1;
use iteron_protocol::{Block, EventKind, Role, RunId, SessionId};
use iteron_record::SessionMeta;
use iteron_record::bounded_replay::{
    ReplayReadLimits, load_forked_scoped_bounded, meta_bounded, replay_bounded,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_INSPECTION_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSPECTION_RECORDS: usize = 64;
const MAX_INSPECTION_EVENTS: usize = 16_384;
const MAX_GOAL_BYTES: usize = 1024;
const MAX_TRACE_DISPLAY_BYTES: usize = 64 * 1024;
const MAX_TRACE_PAGE_BYTES: usize = 512 * 1024;

fn limits() -> ReplayReadLimits {
    ReplayReadLimits {
        physical_bytes: MAX_INSPECTION_RECORD_BYTES as usize,
        hydrated_bytes: MAX_INSPECTION_RECORD_BYTES as usize,
        events: MAX_INSPECTION_EVENTS,
    }
}

pub(super) fn metadata(runs: &Path, run: &RunId) -> Result<SessionMeta, String> {
    let physical = std::fs::symlink_metadata(runs.join(format!("{}.jsonl", run.0)))
        .map_err(|_| "inspection record unavailable")?;
    if !physical.is_file() || physical.len() > MAX_INSPECTION_RECORD_BYTES {
        return Err("inspection exceeds its bounded physical record window".into());
    }
    meta_bounded(runs, run, limits()).map_err(|_| "bounded verified metadata unavailable".into())
}

pub(super) fn inspect(runs: &Path, meta: &SessionMeta, workspace: &Path) -> Result<Value, String> {
    admit(runs, meta)?;
    let events = load_forked_scoped_bounded(runs, &meta.run_id, limits())
        .map_err(|_| "verified session history unavailable")?;
    if events.len() > MAX_INSPECTION_EVENTS
        || events.iter().any(|event| event.tenant != meta.tenant)
    {
        return Err("session inspection exceeds its verified scope or event bound".into());
    }
    let goal = events.iter().rev().find_map(|scoped| {
        let EventKind::Message { message } = &scoped.event.kind else {
            return None;
        };
        if message.role != Role::User {
            return None;
        }
        let text = message
            .content
            .iter()
            .filter_map(|block| match block {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() {
            return None;
        }
        let safe = iteron_record::redact::scrub(&text);
        let end = utf8_end(&safe, MAX_GOAL_BYTES);
        Some(
            json!({"source_run_id":scoped.run_id,"source_seq":scoped.event.seq.0,
            "text":&safe[..end],"complete":end == safe.len()}),
        )
    });
    let terminal = events
        .iter()
        .rev()
        .find_map(|scoped| {
            let EventKind::Done { outcome } = &scoped.event.kind else {
                return None;
            };
            let code = match outcome.as_str() {
                "Done" => "done",
                "Drained" => "drained",
                "Interrupted" => "interrupted",
                "Stuck" => "stuck",
                "HarnessError" => "harness_error",
                "BudgetExhausted(\"max_turns\")"
                | "BudgetExhausted(\"max_tokens\")"
                | "BudgetExhausted(\"max_usd\")"
                | "BudgetExhausted(\"max_wall_secs\")"
                | "BudgetExhausted(\"verify_attempts\")" => "budget_exhausted",
                _ => {
                    return Some(
                        json!({"available":false,"reason_code":"unknown_recorded_terminal"}),
                    );
                }
            };
            Some(json!({"available":true,"source_run_id":scoped.run_id,
            "source_seq":scoped.event.seq.0,"outcome":code}))
        })
        .unwrap_or_else(|| json!({"available":false,"reason_code":"no_recorded_terminal"}));
    let thread = SessionId(format!("session-{}", meta.run_id.0));
    let scope = ArtifactReadScope::capture(
        runs.to_owned(),
        meta.tenant.clone(),
        meta.run_id.clone(),
        workspace.to_owned(),
    );
    let changes = match scope.read(
        &thread,
        ClientArtifactCommandV1::List {
            thread_id: thread.clone(),
        },
    ) {
        Ok(list) => {
            let artifacts = list["artifacts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|artifact| {
                    artifact["schema"] == "iteron.file-diff.v1" && artifact["complete"] == true
                })
                .cloned()
                .collect::<Vec<_>>();
            json!({"available":true,"source":"retained_owner_manifest","file_diff_artifacts":artifacts,
                "evicted_artifacts":list["evicted_artifacts"], "coverage":"retained_native_commit_receipts"})
        }
        Err(_) => json!({"available":false,"reason_code":"retained_changes_unavailable"}),
    };
    Ok(
        json!({"type":"thread_inspection_v1","contract_version":1,"run_id":meta.run_id,
        "workspace":iteron_record::redact::scrub(&meta.cwd.to_string_lossy()),
        "recent_goal":goal,"recorded_terminal":terminal,"changes":changes,
        "background":{"available":false,"reason_code":"requires_bound_live_owner"},
        "execution_state":{"available":false,"reason_code":"record_terminal_is_not_liveness"}}),
    )
}

pub(super) fn trace(
    runs: &Path,
    meta: &SessionMeta,
    after: Option<u64>,
    limit: u16,
) -> Result<Value, String> {
    admit(runs, meta)?;
    // Trace pages describe this physical owner only. Fork origins remain explicit in inspection.
    let events = replay_bounded(&runs.join(format!("{}.jsonl", meta.run_id.0)), limits())
        .map_err(|_| "verified trace unavailable")?;
    let newest = events.last().map_or(0, |event| event.seq.0);
    if after.is_some_and(|after| after > newest) {
        return Err("trace cursor is ahead of the verified record".into());
    }
    let mut rows = Vec::new();
    let mut page_bytes = 0usize;
    let mut next = after;
    for event in events
        .iter()
        .filter(|event| after.is_none_or(|after| event.seq.0 > after))
        .take(limit as usize)
    {
        let display = scrub_value(
            serde_json::to_value(&event.kind).map_err(|_| "trace projection unavailable")?,
        );
        let bytes = serde_json::to_vec(&display).map_err(|_| "trace projection unavailable")?;
        let row = if bytes.len() > MAX_TRACE_DISPLAY_BYTES {
            let text = String::from_utf8(bytes).map_err(|_| "trace encoding unavailable")?;
            let end = utf8_end(&text, MAX_TRACE_DISPLAY_BYTES);
            json!({"source_seq":event.seq.0,"turn_id":event.turn.0,"complete":false,
                "display_json_prefix":&text[..end],"omitted_redacted_bytes":text.len()-end})
        } else {
            json!({"source_seq":event.seq.0,"turn_id":event.turn.0,"complete":true,"display_event":display})
        };
        let charge = serde_json::to_vec(&row)
            .map_err(|_| "trace projection unavailable")?
            .len();
        if page_bytes.saturating_add(charge) > MAX_TRACE_PAGE_BYTES {
            break;
        }
        page_bytes += charge;
        next = Some(event.seq.0);
        rows.push(row);
    }
    Ok(
        json!({"type":"thread_trace_v1","contract_version":1,"run_id":meta.run_id,
        "source":"verified_physical_record","redaction":"display_fields",
        "events":rows,"next_seq":next,"has_more":!events.is_empty() && next.is_none_or(|next| next < newest)}),
    )
}

fn admit(runs: &Path, meta: &SessionMeta) -> Result<(), String> {
    let mut identities = BTreeSet::new();
    identities.insert(meta.run_id.0.as_str());
    identities.extend(
        meta.ancestry
            .iter()
            .map(|ancestor| ancestor.run_id.0.as_str()),
    );
    if identities.len() > MAX_INSPECTION_RECORDS {
        return Err("inspection ancestry exceeds its bound".into());
    }
    let mut bytes = 0u64;
    for id in identities {
        ThreadLifecycleCommandV1::Read {
            run_id: RunId(id.into()),
        }
        .validate()
        .map_err(str::to_owned)?;
        let metadata = std::fs::symlink_metadata(runs.join(format!("{id}.jsonl")))
            .map_err(|_| "inspection record unavailable")?;
        if !metadata.is_file() {
            return Err("inspection refuses non-file records".into());
        }
        bytes = bytes
            .checked_add(metadata.len())
            .ok_or("inspection byte count overflow")?;
        if bytes > MAX_INSPECTION_RECORD_BYTES {
            return Err("inspection exceeds its bounded record window".into());
        }
    }
    Ok(())
}

fn utf8_end(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn scrub_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(iteron_record::redact::scrub(&text)),
        Value::Array(values) => Value::Array(values.into_iter().map(scrub_value).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (iteron_record::redact::scrub(&key), scrub_value(value)))
                .collect(),
        ),
        other => other,
    }
}
