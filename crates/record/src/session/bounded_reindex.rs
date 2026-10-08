//! Operator index repair with finite enumeration, verified aggregate hydration and retained metadata.
use super::{RecordError, RunId};
use crate::bounded_replay::{ReplayReadLimits, meta_bounded};
use std::path::Path;
use std::time::{Duration, Instant};
const MAX_ENTRIES: usize = 4096;
const MAX_RUNS: usize = 256;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_WALL: Duration = Duration::from_secs(10);
const REPLAY_LIMITS: ReplayReadLimits = ReplayReadLimits {
    physical_bytes: 16 * 1024 * 1024,
    hydrated_bytes: 16 * 1024 * 1024,
    events: 16_384,
};

#[derive(Debug, Clone, Copy)]
pub struct ReindexReceipt {
    pub indexed: usize,
    pub unavailable: usize,
}
/// Enumeration or work-budget exhaustion refuses before publishing a partial replacement index.
/// Unavailable/corrupt records are explicitly counted; they are not silently called indexed.
pub fn reindex_bounded(runs: &Path) -> Result<ReindexReceipt, RecordError> {
    let started = Instant::now();
    let mut selected = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(runs)? {
        require_time(started)?;
        scanned += 1;
        if scanned > MAX_ENTRIES {
            return Err(bound());
        }
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|id| id.to_str()) else {
            continue;
        };
        let run = RunId(id.to_owned());
        if crate::validate_run_id(&run).is_err() {
            continue;
        }
        if selected.len() >= MAX_RUNS {
            return Err(bound());
        }
        selected.push(run);
    }
    let mut metas = Vec::with_capacity(selected.len());
    let mut retained = metas.capacity() * std::mem::size_of::<super::SessionMeta>();
    let mut unavailable = 0usize;
    for run in selected {
        require_time(started)?;
        match meta_bounded(runs, &run, REPLAY_LIMITS) {
            Ok(meta) => {
                retained = retained
                    .checked_add(retained_bytes(&meta))
                    .ok_or_else(bound)?;
                if retained > MAX_METADATA_BYTES {
                    return Err(bound());
                }
                metas.push(meta);
            }
            Err(_) => unavailable += 1,
        }
    }
    require_time(started)?;
    // The actual existing maintenance barriers, private sidecars, index lock and crash recovery
    // transaction remain in the record domain. No caller-supplied metadata is admitted.
    crate::session_maintenance::flush()?;
    crate::create_state_dir(runs)?;
    let recovery = crate::session_maintenance::ReindexRecovery::acquire(runs)?;
    let mut wrote = false;
    for meta in &metas {
        if super::sidecar_is_unchanged(runs, meta) {
            continue;
        }
        let path = super::per_run_meta_path(runs, &meta.run_id)?;
        super::private_cache::write_sidecar(runs, &path, meta, true)?;
        wrote = true;
    }
    if wrote {
        crate::cache_io::sync_dir(runs)?;
    }
    super::merge_rewrite_index(runs, metas.iter().cloned())?;
    recovery.complete()?;
    Ok(ReindexReceipt {
        indexed: metas.len(),
        unavailable,
    })
}
fn retained_bytes(meta: &super::SessionMeta) -> usize {
    let mut bytes = std::mem::size_of::<super::SessionMeta>()
        + meta.run_id.0.capacity()
        + meta.tenant.0.capacity()
        + meta.cwd.capacity()
        + meta.provider_id.capacity()
        + meta.model.capacity()
        + meta.title.capacity()
        + meta.record_tail_hash.capacity()
        + meta.projection_digest.capacity()
        + meta
            .agent_definition_tag
            .as_ref()
            .map_or(0, String::capacity)
        + meta.ancestry.capacity() * std::mem::size_of::<super::SessionAncestryReceipt>();
    for ancestor in &meta.ancestry {
        bytes += ancestor.run_id.0.capacity()
            + ancestor.tenant.0.capacity()
            + ancestor.tail_hash.capacity()
            + ancestor.observed_tail_hash.capacity();
    }
    if let iteron_obs::CostState::Known {
        rate_card_digest, ..
    } = &meta.cost
    {
        bytes += rate_card_digest.capacity();
    }
    if let Some(parent) = &meta.parent {
        bytes += parent.parent_run.0.capacity() + parent.parent_hash_at_seq.capacity();
    }
    bytes
}
fn require_time(started: Instant) -> Result<(), RecordError> {
    if started.elapsed() > MAX_WALL {
        Err(bound())
    } else {
        Ok(())
    }
}
fn bound() -> RecordError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "bounded session index repair limit exceeded; use the explicit offline reindex command",
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excess_enumeration_refuses_before_replacing_existing_index() {
        let directory = std::env::temp_dir().join(format!(
            "iteron-bounded-repair-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let sentinel = b"existing index must remain intact";
        std::fs::write(directory.join("sessions.index"), sentinel).unwrap();
        for index in 0..=MAX_RUNS {
            std::fs::write(directory.join(format!("run-{index}.jsonl")), b"").unwrap();
        }
        assert!(reindex_bounded(&directory).is_err());
        assert_eq!(
            std::fs::read(directory.join("sessions.index")).unwrap(),
            sentinel
        );
        assert!(!directory.join("sessions.reindex.pending").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn actual_fork_repair_preserves_pinned_parent_provenance() {
        use iteron_protocol::{Effort, Event, EventKind, Message, RunId, Seq, TenantId, TurnId};
        let directory = std::env::temp_dir().join(format!(
            "iteron-bounded-fork-repair-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let tenant = TenantId("bounded-fork-repair".into());
        let parent = RunId("actual-parent".into());
        let mut writer = crate::Rollout::open(&directory, &parent, tenant.clone()).unwrap();
        writer
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: directory.to_string_lossy().into(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: "actual-fixture".into(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let at = writer
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("actual parent history"),
                },
            })
            .unwrap();
        drop(writer);
        let child = super::super::fork(&directory, &parent, at, &tenant).unwrap();
        let before = super::super::meta(&directory, &child)
            .unwrap()
            .parent
            .unwrap();
        let receipt = reindex_bounded(&directory).unwrap();
        assert_eq!(receipt.indexed, 2);
        assert_eq!(receipt.unavailable, 0);
        let after = super::super::meta(&directory, &child)
            .unwrap()
            .parent
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(after.parent_run, parent);
        assert_eq!(after.forked_at, at);
        assert!(!after.parent_hash_at_seq.is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
