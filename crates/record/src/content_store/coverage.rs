//! Executable production-adapter coverage for private-content revocation.

use super::model::{
    MAX_CONTENT_REFERENCES, MAX_CONTENT_RUNS, MAX_REFERENCE_EDGE_BYTES, PrivateContentClass,
    PrivateContentNamespace, ReferenceEdge, RevocationState, STORE_VERSION,
};
use super::storage::{Layout, load_bytes, read_limited};
use super::{ContentReferenceSurface, ContentStoreError};
use iteron_protocol::{ErasureContentDigest, ErasurePropagationCoverage};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub(super) enum WriterRoute {
    Derivative(PrivateContentClass),
    Semantic(fn(&str) -> bool),
}

/// Sealed registration minted only by the production writer which owns this route.
#[derive(Clone, Copy)]
pub(super) struct WriterRegistration {
    namespace: PrivateContentNamespace,
    route: WriterRoute,
}

impl WriterRegistration {
    pub(super) const fn derivative(
        namespace: PrivateContentNamespace,
        class: PrivateContentClass,
    ) -> Self {
        Self {
            namespace,
            route: WriterRoute::Derivative(class),
        }
    }

    pub(super) const fn semantic(
        namespace: PrivateContentNamespace,
        accepts: fn(&str) -> bool,
    ) -> Self {
        Self {
            namespace,
            route: WriterRoute::Semantic(accepts),
        }
    }

    pub(super) const fn namespace(self) -> PrivateContentNamespace {
        self.namespace
    }

    pub(super) const fn derivative_class(self) -> Option<PrivateContentClass> {
        match self.route {
            WriterRoute::Derivative(class) => Some(class),
            WriterRoute::Semantic(_) => None,
        }
    }

    pub(super) fn accepts_field_class(self, field_class: &str) -> bool {
        match self.route {
            WriterRoute::Derivative(class) => field_class == super::class_label(class),
            WriterRoute::Semantic(accepts) => accepts(field_class),
        }
    }

    fn accepts(self, edge: &ReferenceEdge) -> bool {
        if edge.surface != self.namespace.surface() {
            return false;
        }
        self.accepts_field_class(&edge.field_class)
    }
}

type GateVerifier =
    fn(&Layout, &ReferenceEdge, Option<PrivateContentClass>) -> Result<Vec<u8>, ContentStoreError>;

/// Sealed registration minted by the production consumer/read gate for one writer route.
#[derive(Clone, Copy)]
pub(super) struct ReadGateRegistration {
    namespace: PrivateContentNamespace,
    route: WriterRoute,
    verifier: GateVerifier,
}

impl ReadGateRegistration {
    pub(super) const fn new(writer: WriterRegistration, verifier: GateVerifier) -> Self {
        Self {
            namespace: writer.namespace,
            route: writer.route,
            verifier,
        }
    }

    fn matches(self, writer: WriterRegistration) -> bool {
        self.namespace == writer.namespace
            && match (self.route, writer.route) {
                (WriterRoute::Derivative(left), WriterRoute::Derivative(right)) => left == right,
                (WriterRoute::Semantic(left), WriterRoute::Semantic(right)) => {
                    std::ptr::fn_addr_eq(left, right)
                }
                _ => false,
            }
    }

    fn verify(self, layout: &Layout, edge: &ReferenceEdge) -> Result<Vec<u8>, ContentStoreError> {
        let class = match self.route {
            WriterRoute::Derivative(class) => Some(class),
            WriterRoute::Semantic(_) => None,
        };
        (self.verifier)(layout, edge, class)
    }
}

#[derive(Clone, Copy)]
struct LiveAdapter {
    writer: WriterRegistration,
    gate: ReadGateRegistration,
}

/// Verify the closed production writer registry, every physically registered surface, and the
/// exact read gate for every affected handle before constructing coverage.
pub(super) fn verify_registered_adapters(
    layout: &Layout,
    state: &RevocationState,
    affected: &[ErasureContentDigest],
) -> Result<ErasurePropagationCoverage, ContentStoreError> {
    let affected = affected.iter().cloned().collect::<BTreeSet<_>>();
    let adapters = collect_live_adapters(&affected, PrivateContentNamespace::ALL)?;
    let edges = all_reference_edges(layout)?;
    let mut coverage = empty_coverage();

    // Telemetry is the one intentionally content-free surface and every other content-bearing
    // surface is represented by the closed namespace enum. A future/forged surface must fail
    // before the absence proof below; otherwise an unvisited edge could be hidden behind the
    // schema-level telemetry invariant and still mint complete coverage.
    for edge in &edges {
        if edge.surface != ContentReferenceSurface::RecordField
            && PrivateContentNamespace::from_surface(edge.surface).is_none()
        {
            return Err(ContentStoreError::Unresolved {
                digest: edge.digest.clone(),
                reason: "unregistered_content_surface",
            });
        }
    }

    // Record fields are roots rather than one of the derivative namespaces. Validate them first,
    // then prove every namespace from the exhaustive physical edge inventory. An affected edge
    // invokes the production gate; no affected edge is a bounded absence proof. Registration by
    // itself never sets a coverage bit.
    for edge in edges
        .iter()
        .filter(|edge| edge.surface == ContentReferenceSurface::RecordField)
    {
        validate_registered_edge(layout, state, &affected, &adapters, edge)?;
    }
    for namespace in PrivateContentNamespace::ALL {
        for edge in edges
            .iter()
            .filter(|edge| edge.surface == namespace.surface())
        {
            validate_registered_edge(layout, state, &affected, &adapters, edge)?;
        }
        mark(&mut coverage, namespace);
    }

    let telemetry = iteron_protocol::lifecycle::content_free_telemetry_schema_proof()
        .filter(|proof| proof.event_count == iteron_protocol::lifecycle::EVENT_COUNT)
        .is_some();
    coverage.telemetry_debug = telemetry;
    if !coverage.is_complete() {
        return Err(ContentStoreError::Unresolved {
            digest: affected.iter().next().cloned().unwrap_or_else(zero_digest),
            reason: "content_adapter_coverage_incomplete",
        });
    }
    Ok(coverage)
}

fn collect_live_adapters(
    affected: &BTreeSet<ErasureContentDigest>,
    namespaces: impl IntoIterator<Item = PrivateContentNamespace>,
) -> Result<Vec<LiveAdapter>, ContentStoreError> {
    let mut registered = BTreeSet::new();
    let mut adapters = Vec::new();
    for namespace in namespaces {
        let writers = [
            super::derivative::registered_writer(namespace),
            super::registered_semantic_writer(namespace),
        ];
        let mut writer_count = 0usize;
        for writer in writers.into_iter().flatten() {
            let Some(gate) = super::registered_read_gate(writer) else {
                return Err(unresolved(affected, "content_adapter_read_gate_missing"));
            };
            if writer.namespace != namespace || !gate.matches(writer) {
                return Err(unresolved(affected, "content_adapter_registry_invalid"));
            }
            adapters.push(LiveAdapter { writer, gate });
            writer_count = writer_count.saturating_add(1);
        }
        let surface = namespace.surface();
        if writer_count == 0
            || PrivateContentNamespace::from_surface(surface) != Some(namespace)
            || !registered.insert(surface.label())
        {
            return Err(ContentStoreError::Unresolved {
                digest: affected.iter().next().cloned().unwrap_or_else(zero_digest),
                reason: "content_adapter_registry_invalid",
            });
        }
    }
    if registered.len() != PrivateContentNamespace::ALL.len() {
        return Err(ContentStoreError::Unresolved {
            digest: affected.iter().next().cloned().unwrap_or_else(zero_digest),
            reason: "content_adapter_registry_incomplete",
        });
    }

    Ok(adapters)
}

fn validate_registered_edge(
    layout: &Layout,
    state: &RevocationState,
    affected: &BTreeSet<ErasureContentDigest>,
    adapters: &[LiveAdapter],
    edge: &ReferenceEdge,
) -> Result<(), ContentStoreError> {
    if edge.version != STORE_VERSION {
        return Err(ContentStoreError::Corrupt);
    }
    if edge.surface == ContentReferenceSurface::RecordField {
        if affected.contains(&edge.digest) {
            return expect_revoked(state, affected, load_bytes(layout, &edge.digest));
        }
        return Ok(());
    }
    let Some(namespace) = PrivateContentNamespace::from_surface(edge.surface) else {
        return Err(ContentStoreError::Unresolved {
            digest: edge.digest.clone(),
            reason: "unregistered_content_surface",
        });
    };
    if namespace.surface() != edge.surface {
        return Err(ContentStoreError::Corrupt);
    }
    let matches = adapters
        .iter()
        .copied()
        .filter(|adapter| adapter.writer.namespace == namespace)
        .filter(|adapter| adapter.writer.accepts(edge))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(ContentStoreError::Unresolved {
            digest: edge.digest.clone(),
            reason: "unregistered_content_writer",
        });
    }
    if !affected.contains(&edge.digest) {
        return Ok(());
    }
    expect_revoked(state, affected, matches[0].gate.verify(layout, edge))
}

fn expect_revoked(
    state: &RevocationState,
    affected: &BTreeSet<ErasureContentDigest>,
    result: Result<Vec<u8>, ContentStoreError>,
) -> Result<(), ContentStoreError> {
    match result {
        Err(ContentStoreError::Revoked { digest, generation })
            if affected.contains(&digest)
                && state
                    .tombstone(&digest)
                    .is_some_and(|tombstone| tombstone.generation == generation) =>
        {
            Ok(())
        }
        _ => Err(ContentStoreError::Unresolved {
            digest: affected.iter().next().cloned().unwrap_or_else(zero_digest),
            reason: "registered_content_read_gate_unverified",
        }),
    }
}

fn all_reference_edges(layout: &Layout) -> Result<Vec<ReferenceEdge>, ContentStoreError> {
    let mut edges = Vec::new();
    let mut reverse_identities = BTreeSet::new();
    let mut runs = 0usize;
    match std::fs::read_dir(&layout.run_refs) {
        Ok(run_dirs) => {
            for run_dir in run_dirs.take(MAX_CONTENT_RUNS + 1) {
                if runs == MAX_CONTENT_RUNS {
                    return Err(ContentStoreError::ReferenceBound {
                        max: MAX_CONTENT_RUNS,
                    });
                }
                runs = runs.saturating_add(1);
                let run_dir = run_dir?;
                if !run_dir.file_type()?.is_dir() {
                    return Err(ContentStoreError::Corrupt);
                }
                let run_path = run_dir.path();
                let mut owner = None;
                let mut directory_edges = 0usize;
                for edge in std::fs::read_dir(&run_path)?.take(MAX_CONTENT_REFERENCES + 1) {
                    if edges.len() == MAX_CONTENT_REFERENCES {
                        return Err(ContentStoreError::ReferenceBound {
                            max: MAX_CONTENT_REFERENCES,
                        });
                    }
                    let entry = edge?;
                    if !entry.file_type()?.is_file() {
                        return Err(ContentStoreError::Corrupt);
                    }
                    let path = entry.path();
                    let bytes = read_limited(&path, MAX_REFERENCE_EDGE_BYTES)?;
                    let edge: ReferenceEdge = serde_json::from_slice(&bytes)?;
                    let expected_name = format!("{}.json", hex::encode(Sha256::digest(&bytes)));
                    let identity = (edge.digest.as_str().to_owned(), expected_name.clone());
                    let expected_forward = layout
                        .object_path(&layout.refs, &edge.digest)
                        .join(&expected_name);
                    let forward_metadata = std::fs::symlink_metadata(&expected_forward)?;
                    if edge.version != STORE_VERSION
                        || crate::validate_run_id(&edge.run_id).is_err()
                        || layout.run_reference_dir(&edge.run_id) != run_path
                        || owner
                            .as_ref()
                            .is_some_and(|candidate| candidate != &edge.run_id)
                        || path.file_name().and_then(std::ffi::OsStr::to_str)
                            != Some(expected_name.as_str())
                        || !forward_metadata.file_type().is_file()
                        || read_limited(&expected_forward, MAX_REFERENCE_EDGE_BYTES)? != bytes
                        || !reverse_identities.insert(identity)
                    {
                        return Err(ContentStoreError::Corrupt);
                    }
                    owner = Some(edge.run_id.clone());
                    directory_edges = directory_edges.saturating_add(1);
                    edges.push(edge);
                }
                if directory_edges == 0 {
                    return Err(ContentStoreError::Corrupt);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    // Reverse edges alone cannot prove absence: a forged/orphaned content-addressed edge could
    // otherwise evade every namespace gate. Exhaust the forward index and require exact bijection.
    let mut forward_identities = BTreeSet::new();
    let mut forward_count = 0usize;
    match std::fs::read_dir(&layout.refs) {
        Ok(digest_dirs) => {
            for digest_dir in digest_dirs.take(MAX_CONTENT_REFERENCES + 1) {
                let digest_dir = digest_dir?;
                if !digest_dir.file_type()?.is_dir() {
                    return Err(ContentStoreError::Corrupt);
                }
                let mut directory_edges = 0usize;
                for entry in std::fs::read_dir(digest_dir.path())?.take(MAX_CONTENT_REFERENCES + 1)
                {
                    if forward_count == MAX_CONTENT_REFERENCES {
                        return Err(ContentStoreError::ReferenceBound {
                            max: MAX_CONTENT_REFERENCES,
                        });
                    }
                    forward_count = forward_count.saturating_add(1);
                    directory_edges = directory_edges.saturating_add(1);
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        return Err(ContentStoreError::Corrupt);
                    }
                    let bytes = read_limited(&entry.path(), MAX_REFERENCE_EDGE_BYTES)?;
                    let edge: ReferenceEdge = serde_json::from_slice(&bytes)?;
                    let expected_name = format!("{}.json", hex::encode(Sha256::digest(&bytes)));
                    let digest_name = edge.digest.as_str().trim_start_matches("sha256:");
                    let expected_reverse =
                        layout.run_reference_dir(&edge.run_id).join(&expected_name);
                    if edge.version != STORE_VERSION
                        || crate::validate_run_id(&edge.run_id).is_err()
                        || digest_dir.file_name().to_str() != Some(digest_name)
                        || entry.file_name().to_str() != Some(expected_name.as_str())
                        || !expected_reverse.is_file()
                        || read_limited(&expected_reverse, MAX_REFERENCE_EDGE_BYTES)? != bytes
                        || !forward_identities
                            .insert((edge.digest.as_str().to_owned(), expected_name))
                    {
                        return Err(ContentStoreError::Corrupt);
                    }
                }
                if directory_edges == 0 {
                    return Err(ContentStoreError::Corrupt);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if forward_identities != reverse_identities {
        return Err(ContentStoreError::Corrupt);
    }
    Ok(edges)
}

fn unresolved(
    affected: &BTreeSet<ErasureContentDigest>,
    reason: &'static str,
) -> ContentStoreError {
    ContentStoreError::Unresolved {
        digest: affected.iter().next().cloned().unwrap_or_else(zero_digest),
        reason,
    }
}

fn empty_coverage() -> ErasurePropagationCoverage {
    ErasurePropagationCoverage {
        session_projections: false,
        indexes: false,
        prompt_history: false,
        attachments: false,
        tool_artifacts: false,
        checkpoints: false,
        memory_context: false,
        exports: false,
        telemetry_debug: false,
        trajectories: false,
        datasets: false,
        evaluator_inputs: false,
        candidate_stores: false,
    }
}

fn mark(coverage: &mut ErasurePropagationCoverage, namespace: PrivateContentNamespace) {
    match namespace {
        PrivateContentNamespace::SessionProjection => coverage.session_projections = true,
        PrivateContentNamespace::SessionIndex => coverage.indexes = true,
        PrivateContentNamespace::PromptHistory => coverage.prompt_history = true,
        PrivateContentNamespace::Attachment => coverage.attachments = true,
        PrivateContentNamespace::ToolArtifact => coverage.tool_artifacts = true,
        PrivateContentNamespace::Checkpoint => coverage.checkpoints = true,
        PrivateContentNamespace::MemoryContext => coverage.memory_context = true,
        PrivateContentNamespace::Export => coverage.exports = true,
        PrivateContentNamespace::Trajectory => coverage.trajectories = true,
        PrivateContentNamespace::Dataset => coverage.datasets = true,
        PrivateContentNamespace::EvaluatorInput => coverage.evaluator_inputs = true,
        PrivateContentNamespace::CandidateStore => coverage.candidate_stores = true,
    }
}

fn zero_digest() -> ErasureContentDigest {
    ErasureContentDigest::new(format!("sha256:{}", "0".repeat(64)))
        .expect("the fixed zero digest is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_live_adapter_cannot_construct_complete_registry() {
        let affected = BTreeSet::new();
        let without_candidate = PrivateContentNamespace::ALL
            .into_iter()
            .filter(|namespace| *namespace != PrivateContentNamespace::CandidateStore);
        assert!(matches!(
            collect_live_adapters(&affected, without_candidate),
            Err(ContentStoreError::Unresolved {
                reason: "content_adapter_registry_incomplete",
                ..
            })
        ));
    }
}
