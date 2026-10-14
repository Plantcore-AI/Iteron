//! Rebuildable cache validation against exact physical genesis, tail and ancestor receipts.
#[cfg(test)]
use super::RECEIPT_BYTES_READ;
use super::model::{MAX_FORK_DEPTH, Provenance, SessionMeta};
use super::paths::rollout_path;
use crate::RecordError;
use iteron_obs::CostState;
use iteron_protocol::{Event, EventKind, RunId, Seq, TenantId};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

pub(super) const RECEIPT_SCAN_CHUNK_BYTES: usize = 8 * 1024;

pub(super) fn file_mtime(path: &Path) -> Option<(u64, u32)> {
    let duration = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some((duration.as_secs(), duration.subsec_nanos()))
}

/// Return the exact physical length only when the file ends at a complete JSONL boundary.
pub(super) fn complete_record_len(path: &Path) -> Option<u64> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return Some(0);
    }
    file.seek(SeekFrom::End(-1)).ok()?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).ok()?;
    (byte[0] == b'\n').then_some(len)
}

pub(super) fn projection_digest(meta: &SessionMeta) -> Result<String, RecordError> {
    let mut canonical = meta.clone();
    canonical.projection_digest.clear();
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&canonical)?);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Normalize a floating-point cache field to a fixed point of this build's JSON codec. Some
/// feature combinations round a decimal by one ULP on the first parse; persisting the converged
/// value lets the projection digest bind the exact f64 without inventing an integrity tolerance.
pub(super) fn json_f64_fixed_point(mut value: f64) -> Result<f64, RecordError> {
    if !value.is_finite() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session cache-hit ratio is not finite",
        )
        .into());
    }
    for _ in 0..8 {
        let encoded = serde_json::to_vec(&value)?;
        let next: f64 = serde_json::from_slice(&encoded)?;
        if next.to_bits() == value.to_bits() {
            return Ok(value);
        }
        value = next;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "session cache-hit ratio JSON encoding did not reach a fixed point",
    )
    .into())
}

struct PhysicalReceipt {
    seq: u64,
    hash: String,
    tenant: String,
}

#[cfg(test)]
fn charge_receipt_read(bytes: usize) {
    RECEIPT_BYTES_READ.with(|total| total.set(total.get().saturating_add(bytes as u64)));
}

#[cfg(not(test))]
fn charge_receipt_read(_bytes: usize) {}

/// Read the last nonblank complete chain line ending at the exact byte boundary. Work is
/// proportional to that physical line (plus one fixed chunk), not to the rollout prefix.
fn read_receipt_ending_at(path: &Path, end_bytes: u64) -> Option<PhysicalReceipt> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if end_bytes == 0 || end_bytes > len {
        return None;
    }
    file.seek(SeekFrom::Start(end_bytes - 1)).ok()?;
    let mut terminator = [0u8; 1];
    file.read_exact(&mut terminator).ok()?;
    charge_receipt_read(1);
    if terminator[0] != b'\n' {
        return None;
    }
    let mut cursor = end_bytes - 1;
    let mut reverse_chunks: Vec<Vec<u8>> = Vec::new();
    let mut candidate_len = 0usize;
    let mut scanned = 1u64;

    let line = loop {
        if cursor == 0 {
            if candidate_len == 0 {
                return None;
            }
            let mut line = Vec::with_capacity(candidate_len);
            for chunk in reverse_chunks.iter().rev() {
                line.extend_from_slice(chunk);
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            break line;
        }
        let start = cursor.saturating_sub(iteron_tunables::param_integer(
            "record.session.receipt_scan_chunk_bytes",
            RECEIPT_SCAN_CHUNK_BYTES,
        ) as u64);
        let chunk_len = usize::try_from(cursor - start).ok()?;
        let mut chunk = vec![0u8; chunk_len];
        file.seek(SeekFrom::Start(start)).ok()?;
        file.read_exact(&mut chunk).ok()?;
        charge_receipt_read(chunk_len);
        scanned = scanned.checked_add(chunk_len as u64)?;
        if scanned > crate::MAX_ROLLOUT_BYTES {
            return None;
        }

        if let Some(newline) = chunk.iter().rposition(|byte| *byte == b'\n') {
            let head = &chunk[newline + 1..];
            candidate_len = candidate_len.checked_add(head.len())?;
            if candidate_len.checked_add(1)? > crate::MAX_RECORD_LINE_BYTES {
                return None;
            }
            let nonblank = head
                .iter()
                .chain(reverse_chunks.iter().rev().flat_map(|part| part.iter()));
            if nonblank.clone().all(u8::is_ascii_whitespace) {
                // Skip a complete blank line and continue from its preceding delimiter.
                reverse_chunks.clear();
                candidate_len = 0;
                cursor = start + newline as u64;
                continue;
            }
            let mut line = Vec::with_capacity(candidate_len);
            line.extend_from_slice(head);
            for part in reverse_chunks.iter().rev() {
                line.extend_from_slice(part);
            }
            break line;
        }

        candidate_len = candidate_len.checked_add(chunk.len())?;
        if candidate_len.checked_add(1)? > crate::MAX_RECORD_LINE_BYTES {
            return None;
        }
        reverse_chunks.push(chunk);
        cursor = start;
    };

    let text = std::str::from_utf8(&line).ok()?;
    let chain: crate::ChainLine = serde_json::from_str(text).ok()?;
    (crate::hash_line(&chain.prev, chain.seq, &chain.payload) == chain.hash).then_some(
        PhysicalReceipt {
            seq: chain.seq,
            hash: chain.hash,
            tenant: chain.tenant,
        },
    )
}

pub(super) fn read_tail_receipt(path: &Path) -> Option<(u64, u64, String, String)> {
    let len = std::fs::metadata(path).ok()?.len();
    let receipt = read_receipt_ending_at(path, len)?;
    Some((len, receipt.seq, receipt.hash, receipt.tenant))
}

struct GenesisProjection {
    tenant: TenantId,
    cwd: PathBuf,
    created_at: u64,
    agent_definition_tag: Option<String>,
    parent: Option<Provenance>,
}

fn read_genesis_projection(path: &Path) -> Option<GenesisProjection> {
    let Ok(file) = std::fs::File::open(path) else {
        return None;
    };
    let mut reader = std::io::BufReader::new(file);
    let Ok(Some((bytes, true, _))) = crate::read_bounded_line(&mut reader) else {
        return None;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return None;
    };
    let Ok(chain) = serde_json::from_str::<crate::ChainLine>(text) else {
        return None;
    };
    if chain.seq != 0
        || chain.prev != crate::ZERO_HASH
        || crate::hash_line(&chain.prev, chain.seq, &chain.payload) != chain.hash
    {
        return None;
    }
    let mut payload = chain.payload;
    let runs_dir = path.parent()?;
    if crate::content_store::hydrate_event_payload(
        runs_dir,
        &TenantId(chain.tenant.clone()),
        &mut payload,
    )
    .is_err()
    {
        return None;
    }
    let Ok(event) = serde_json::from_value::<Event>(payload) else {
        return None;
    };
    match event.kind {
        EventKind::RunStart {
            cwd,
            created_at,
            agent_definition_tag,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } => {
            let parent = match (parent_run, forked_at, parent_hash_at_seq) {
                (Some(parent_run), Some(forked_at), Some(parent_hash_at_seq)) => Some(Provenance {
                    parent_run: RunId(parent_run),
                    forked_at: Seq(forked_at),
                    parent_hash_at_seq,
                }),
                (None, None, None) => None,
                _ => return None,
            };
            Some(GenesisProjection {
                tenant: TenantId(chain.tenant),
                cwd: PathBuf::from(cwd),
                created_at,
                agent_definition_tag,
                parent,
            })
        }
        _ => None,
    }
}

pub(super) fn genesis_matches_meta(path: &Path, meta: &SessionMeta) -> bool {
    read_genesis_projection(path).is_some_and(|genesis| {
        genesis.tenant == meta.tenant
            && genesis.cwd == meta.cwd
            && genesis.created_at == meta.created_at
            && genesis.agent_definition_tag == meta.agent_definition_tag
            && genesis.parent == meta.parent
    })
}

fn ancestry_matches_rollout(runs_dir: &Path, meta: &SessionMeta) -> bool {
    if meta.ancestry.len()
        > iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH)
    {
        return false;
    }
    let mut expected = meta.parent.clone();
    for receipt in meta.ancestry.iter().rev() {
        let Some(provenance) = expected.take() else {
            return false;
        };
        if receipt.run_id != provenance.parent_run
            || receipt.tenant != meta.tenant
            || receipt.through_seq != provenance.forked_at.0
            || receipt.tail_hash != provenance.parent_hash_at_seq
            || receipt.prefix_bytes == 0
            || receipt.prefix_bytes > crate::MAX_ROLLOUT_BYTES
            || receipt.observed_record_bytes < receipt.prefix_bytes
            || receipt.observed_record_bytes > crate::MAX_ROLLOUT_BYTES
            || receipt.observed_tail_seq < receipt.through_seq
        {
            return false;
        }
        let Ok(path) = rollout_path(runs_dir, &receipt.run_id) else {
            return false;
        };
        let prefix_matches =
            read_receipt_ending_at(&path, receipt.prefix_bytes).is_some_and(|physical| {
                physical.seq == receipt.through_seq
                    && physical.hash == receipt.tail_hash
                    && physical.tenant == receipt.tenant.0
            });
        if !prefix_matches {
            return false;
        }
        let Ok(metadata) = std::fs::metadata(&path) else {
            return false;
        };
        let observation_matches = if metadata.len() == receipt.observed_record_bytes {
            file_mtime(&path).is_some_and(|mtime| {
                mtime
                    == (
                        receipt.observed_updated_at,
                        receipt.observed_updated_at_subsec_nanos,
                    )
            })
        } else if metadata.len() > receipt.observed_record_bytes {
            read_receipt_ending_at(&path, receipt.observed_record_bytes).is_some_and(|physical| {
                physical.seq == receipt.observed_tail_seq
                    && physical.hash == receipt.observed_tail_hash
                    && physical.tenant == receipt.tenant.0
            })
        } else {
            false
        };
        if !observation_matches {
            return false;
        }
        let Some(genesis) = read_genesis_projection(&path) else {
            return false;
        };
        if genesis.tenant != meta.tenant {
            return false;
        }
        expected = genesis.parent;
    }
    expected.is_none()
}

pub(super) fn projection_is_current(runs_dir: &Path, meta: &SessionMeta) -> bool {
    let Ok(path) = rollout_path(runs_dir, &meta.run_id) else {
        return false;
    };
    let digest_matches =
        projection_digest(meta).is_ok_and(|expected| expected == meta.projection_digest);
    let tail_matches = read_tail_receipt(&path).is_some_and(|(bytes, seq, hash, tenant)| {
        bytes == meta.record_bytes
            && Some(seq) == meta.record_tail_seq
            && hash == meta.record_tail_hash
            && tenant == meta.tenant.0
    });
    let mtime_matches = file_mtime(&path)
        .is_some_and(|mtime| mtime == (meta.updated_at, meta.updated_at_subsec_nanos));
    meta.pricing_schema_version == 2
        && meta.projection_schema_version == 3
        && crate::content_store::content_revocation_generation(runs_dir, &meta.tenant)
            .is_ok_and(|generation| generation == meta.content_revocation_generation)
        && meta.record_bytes > 0
        && digest_matches
        && tail_matches
        && mtime_matches
        && genesis_matches_meta(&path, meta)
        && ancestry_matches_rollout(runs_dir, meta)
}

/// Mutable caches cannot independently prove exact zero or a signed monetary amount. Those
/// structurally current projections remain useful index entries, but reads replay the rollout so
/// only an honest `Unknown` cost is ever accepted directly from cache bytes.
pub(super) fn projection_covers_rollout(runs_dir: &Path, meta: &SessionMeta) -> bool {
    matches!(&meta.cost, CostState::Unknown { .. }) && projection_is_current(runs_dir, meta)
}
