//! Durable, bounded source-to-derivative lineage indexes.

use super::model::{
    LineageEdge, MAX_CONTENT_LINEAGE_EDGES, MAX_LINEAGE_EDGE_BYTES, ReferenceEdge, STORE_VERSION,
};
use super::storage::{Layout, private_replace, read_limited, remove_if_present};
use super::{ContentReferenceSurface, ContentStoreError, PrivateContentSource};
use iteron_protocol::{ErasureContentDigest, RunId, Seq};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(test)]
std::thread_local! {
    static FAIL_AFTER_WRITES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn fail_after_writes_for_test(writes: Option<usize>) {
    FAIL_AFTER_WRITES.with(|slot| slot.set(writes));
}

pub(super) struct PublishedLineage {
    created: Vec<PathBuf>,
}

impl PublishedLineage {
    pub(super) fn rollback(self) -> Result<(), ContentStoreError> {
        for path in self.created.into_iter().rev() {
            remove_if_present(&path)?;
            if let Some(parent) = path.parent() {
                remove_empty_dir(parent)?;
            }
        }
        Ok(())
    }
}

/// Durably publish a complete source set before its reference becomes readable.
///
/// All encodings and per-index capacity are checked first. An ordinary write failure rolls back
/// every entry created by this attempt. A crash may leave conservative lineage without a readable
/// reference, which can only cause extra revocation work and can never let a derivative escape.
pub(super) fn publish_locked(
    layout: &Layout,
    sources: &[PrivateContentSource],
    derivative_owner: &RunId,
    derivative_digest: &ErasureContentDigest,
    derivative_seq: Seq,
    surface: ContentReferenceSurface,
) -> Result<PublishedLineage, ContentStoreError> {
    validate_owner(derivative_owner)?;
    let mut prepared = Vec::with_capacity(sources.len());
    for source in sources {
        validate_owner(&source.owner)?;
        let edge = LineageEdge {
            version: STORE_VERSION,
            source_owner: source.owner.clone(),
            source_digest: source.digest.clone(),
            derivative_owner: derivative_owner.clone(),
            derivative_digest: derivative_digest.clone(),
            derivative_seq: derivative_seq.0,
            surface,
        };
        let bytes = serde_json::to_vec(&edge)?;
        if bytes.len()
            > iteron_tunables::param_integer(
                "record.content_store.model.max_lineage_edge_bytes",
                MAX_LINEAGE_EDGE_BYTES,
            )
        {
            return Err(ContentStoreError::Corrupt);
        }
        let id = hex::encode(Sha256::digest(&bytes));
        let from = digest_dir(&layout.lineage_from, &source.digest).join(format!("{id}.json"));
        let to = digest_dir(&layout.lineage_to, derivative_digest).join(format!("{id}.json"));
        prepared.push((from, to, bytes));
    }

    preflight_capacity(&prepared)?;
    let mut created = Vec::with_capacity(prepared.len().saturating_mul(2));
    for (from, to, bytes) in prepared {
        let result = (|| {
            if ensure_index_path(&from, &bytes)? {
                created.push(from.clone());
            }
            if ensure_index_path(&to, &bytes)? {
                created.push(to.clone());
            }
            Ok::<(), ContentStoreError>(())
        })();
        if let Err(error) = result {
            PublishedLineage { created }.rollback()?;
            return Err(error);
        }
    }
    Ok(PublishedLineage { created })
}

pub(super) fn sources_for_reference(
    layout: &Layout,
    owner: &RunId,
    digest: &ErasureContentDigest,
    seq: Seq,
    surface: ContentReferenceSurface,
) -> Result<Vec<PrivateContentSource>, ContentStoreError> {
    let mut sources = BTreeSet::new();
    for edge in read_index(
        &digest_dir(&layout.lineage_to, digest),
        digest,
        Direction::To,
    )? {
        if edge.derivative_owner == *owner
            && edge.derivative_digest == *digest
            && edge.derivative_seq == seq.0
            && edge.surface == surface
        {
            sources.insert(PrivateContentSource {
                owner: edge.source_owner,
                digest: edge.source_digest,
            });
        }
    }
    Ok(sources.into_iter().collect())
}

pub(super) fn descendants(
    layout: &Layout,
    digest: &ErasureContentDigest,
) -> Result<Vec<LineageEdge>, ContentStoreError> {
    read_index(
        &digest_dir(&layout.lineage_from, digest),
        digest,
        Direction::From,
    )
}

/// Remove both lineage directions for one derivative reference being unlinked.
pub(super) fn remove_for_reference_locked(
    layout: &Layout,
    reference: &ReferenceEdge,
) -> Result<u32, ContentStoreError> {
    let to_dir = digest_dir(&layout.lineage_to, &reference.digest);
    let edges = read_index(&to_dir, &reference.digest, Direction::To)?;
    let mut removed = 0usize;
    for edge in edges {
        if edge.derivative_owner != reference.run_id
            || edge.derivative_digest != reference.digest
            || edge.derivative_seq != reference.seq
            || edge.surface != reference.surface
        {
            continue;
        }
        let bytes = serde_json::to_vec(&edge)?;
        let id = hex::encode(Sha256::digest(&bytes));
        remove_if_present(
            &digest_dir(&layout.lineage_from, &edge.source_digest).join(format!("{id}.json")),
        )?;
        remove_if_present(&to_dir.join(format!("{id}.json")))?;
        removed = removed.saturating_add(1);
    }
    remove_empty_dir(&to_dir)?;
    u32::try_from(removed).map_err(|_| ContentStoreError::ReferenceBound {
        max: iteron_tunables::param_integer(
            "record.content_store.model.max_content_lineage_edges",
            MAX_CONTENT_LINEAGE_EDGES,
        ),
    })
}

fn ensure_index_path(path: &Path, bytes: &[u8]) -> Result<bool, ContentStoreError> {
    let dir = path.parent().ok_or(ContentStoreError::Corrupt)?;
    std::fs::create_dir_all(dir)?;
    if path.exists() {
        let existing = read_limited(
            path,
            iteron_tunables::param_integer(
                "record.content_store.model.max_lineage_edge_bytes",
                MAX_LINEAGE_EDGE_BYTES,
            ),
        )?;
        return if existing == bytes {
            Ok(false)
        } else {
            Err(ContentStoreError::Corrupt)
        };
    }
    let count = std::fs::read_dir(dir)?
        .take(
            iteron_tunables::param_integer(
                "record.content_store.model.max_content_lineage_edges",
                MAX_CONTENT_LINEAGE_EDGES,
            ) + 1,
        )
        .count();
    if count
        >= iteron_tunables::param_integer(
            "record.content_store.model.max_content_lineage_edges",
            MAX_CONTENT_LINEAGE_EDGES,
        )
    {
        return Err(ContentStoreError::ReferenceBound {
            max: iteron_tunables::param_integer(
                "record.content_store.model.max_content_lineage_edges",
                MAX_CONTENT_LINEAGE_EDGES,
            ),
        });
    }
    #[cfg(test)]
    FAIL_AFTER_WRITES.with(|slot| {
        if let Some(remaining) = slot.get() {
            if remaining == 0 {
                return Err(ContentStoreError::Io(std::io::Error::other(
                    "injected lineage publication failure",
                )));
            }
            slot.set(Some(remaining - 1));
        }
        Ok(())
    })?;
    private_replace(path, bytes)?;
    Ok(true)
}

fn preflight_capacity(prepared: &[(PathBuf, PathBuf, Vec<u8>)]) -> Result<(), ContentStoreError> {
    let mut additions = std::collections::BTreeMap::<PathBuf, usize>::new();
    for (from, to, bytes) in prepared {
        for path in [from, to] {
            if path.exists() {
                if read_limited(
                    path,
                    iteron_tunables::param_integer(
                        "record.content_store.model.max_lineage_edge_bytes",
                        MAX_LINEAGE_EDGE_BYTES,
                    ),
                )? != *bytes
                {
                    return Err(ContentStoreError::Corrupt);
                }
                continue;
            }
            let dir = path
                .parent()
                .ok_or(ContentStoreError::Corrupt)?
                .to_path_buf();
            *additions.entry(dir).or_default() += 1;
        }
    }
    for (dir, adding) in additions {
        let current = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .take(
                    iteron_tunables::param_integer(
                        "record.content_store.model.max_content_lineage_edges",
                        MAX_CONTENT_LINEAGE_EDGES,
                    ) + 1,
                )
                .count(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if current.saturating_add(adding)
            > iteron_tunables::param_integer(
                "record.content_store.model.max_content_lineage_edges",
                MAX_CONTENT_LINEAGE_EDGES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_lineage_edges",
                    MAX_CONTENT_LINEAGE_EDGES,
                ),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Direction {
    From,
    To,
}

fn read_index(
    dir: &Path,
    expected: &ErasureContentDigest,
    direction: Direction,
) -> Result<Vec<LineageEdge>, ContentStoreError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut edges = Vec::new();
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_lineage_edges",
            MAX_CONTENT_LINEAGE_EDGES,
        ) + 1,
    ) {
        if edges.len()
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_lineage_edges",
                MAX_CONTENT_LINEAGE_EDGES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_lineage_edges",
                    MAX_CONTENT_LINEAGE_EDGES,
                ),
            });
        }
        let edge: LineageEdge = serde_json::from_slice(&read_limited(
            &entry?.path(),
            iteron_tunables::param_integer(
                "record.content_store.model.max_lineage_edge_bytes",
                MAX_LINEAGE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION
            || match direction {
                Direction::From => edge.source_digest != *expected,
                Direction::To => edge.derivative_digest != *expected,
            }
        {
            return Err(ContentStoreError::Corrupt);
        }
        validate_owner(&edge.source_owner)?;
        validate_owner(&edge.derivative_owner)?;
        edges.push(edge);
    }
    edges.sort_by(|left, right| {
        (
            &left.source_digest,
            &left.derivative_digest,
            &left.derivative_owner.0,
            left.derivative_seq,
            left.surface.label(),
        )
            .cmp(&(
                &right.source_digest,
                &right.derivative_digest,
                &right.derivative_owner.0,
                right.derivative_seq,
                right.surface.label(),
            ))
    });
    Ok(edges)
}

fn validate_owner(owner: &RunId) -> Result<(), ContentStoreError> {
    crate::validate_run_id(owner).map_err(|_| ContentStoreError::Corrupt)
}

fn digest_dir(root: &Path, digest: &ErasureContentDigest) -> PathBuf {
    root.join(digest.as_str().trim_start_matches("sha256:"))
}

fn remove_empty_dir(path: &Path) -> Result<(), ContentStoreError> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
