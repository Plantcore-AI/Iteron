//! Production projection from hash-verified Iteron records to governed policy trajectories.
//!
//! Unlike `iteron-evolve`'s fixture loader, this adapter owns no caller-supplied revocation bit. It
//! replays the physical run through `iteron-record` for every projection, so exact deletion,
//! content tombstones, broken fork lineage, and corrupt hash chains all remain authoritative.

use iteron_evolve::{
    ContractError, DataGovernance, POLICY_EVIDENCE_RUN_SCHEMA_VERSION, PolicyBundle,
    PolicyEvidenceRunFixture, PolicyEvidenceRunProjector, PolicyProjectionRewardContext, PolicyRef,
    StrategySlot, TrainingAdmissionPolicy, TrajectoryEnvelope, TrajectoryProjection,
};
use iteron_protocol::{EventKind, RunId, TenantId};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Trusted offline metadata that the runtime record intentionally cannot infer.
#[derive(Debug, Clone)]
pub struct RecordedPolicyRunSpec {
    pub run_id: RunId,
    pub task_id: String,
    pub domain: String,
    pub reward_context: PolicyProjectionRewardContext,
    pub governance: DataGovernance,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordPolicyProjectionError {
    #[error("record replay failed: {0}")]
    Record(#[from] iteron_record::RecordError),
    #[error("run {0} has no physical events")]
    EmptyRun(String),
    #[error("run {0} has an invalid or ambiguous immutable tunables checkpoint")]
    TunablesCheckpoint(String),
    #[error("run {0} has an invalid or ambiguous immutable policy bundle checkpoint")]
    PolicyCheckpoint(String),
    #[error("run {0} contains policy evidence under another run identity")]
    CrossRunEvidence(String),
    #[error("two configured records have the same canonical projection digest")]
    DuplicateDigest,
    #[error("record projection changed since the projector inventory was opened")]
    ProjectionChanged,
    #[error("recorded policy trajectory is invalid: {0}")]
    Evolve(#[from] iteron_evolve::PolicyEvidenceRunProjectorError),
    #[error("recorded policy trajectory contract is invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("record-backed trajectory registry could not be opened: {0}")]
    Registry(#[from] iteron_evolve::TrajectoryRegistryError),
}

/// Live record-backed implementation of the frozen record → evolve seam.
///
/// Construction inventories canonical digests, while every `project` call replays the record and
/// compares that digest again. A later tombstone therefore cannot be hidden by this in-memory
/// index. Deleted/revoked records yield `Ok(None)`; malformed or changed evidence fails closed.
#[derive(Debug, Clone)]
pub struct RecordPolicyRunProjector {
    runs_dir: PathBuf,
    specs: BTreeMap<String, RecordedPolicyRunSpec>,
    training_policy: TrainingAdmissionPolicy,
}

impl RecordPolicyRunProjector {
    pub fn open(
        runs_dir: impl Into<PathBuf>,
        specs: Vec<RecordedPolicyRunSpec>,
        training_policy: TrainingAdmissionPolicy,
    ) -> Result<Self, RecordPolicyProjectionError> {
        let runs_dir = runs_dir.into();
        let mut indexed = BTreeMap::new();
        for spec in specs {
            let fixture = build_fixture(&runs_dir, &spec)?;
            if indexed.insert(fixture.rollout_digest, spec).is_some() {
                return Err(RecordPolicyProjectionError::DuplicateDigest);
            }
        }
        Ok(Self {
            runs_dir,
            specs: indexed,
            training_policy,
        })
    }

    pub fn digests(&self) -> impl Iterator<Item = &str> {
        self.specs.keys().map(String::as_str)
    }

    /// Open the durable trajectory owner on the exact content graph replayed by this projector.
    /// Generic registries may use a co-located graph; this production path must not, because exact
    /// session deletion and content revocation need one shared owner/reference namespace.
    pub fn open_trajectory_registry(
        &self,
        directory: &Path,
    ) -> Result<iteron_evolve::TrajectoryRegistry, RecordPolicyProjectionError> {
        Ok(iteron_evolve::TrajectoryRegistry::open_with_content_store(
            directory,
            &self.runs_dir,
        )?)
    }

    pub fn project_record(
        &self,
        rollout_digest: &str,
    ) -> Result<Option<TrajectoryEnvelope>, RecordPolicyProjectionError> {
        let Some(spec) = self.specs.get(rollout_digest) else {
            return Ok(None);
        };
        let fixture = match build_fixture(&self.runs_dir, spec) {
            Ok(fixture) => fixture,
            Err(RecordPolicyProjectionError::Record(error)) if record_is_unavailable(&error) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if fixture.rollout_digest != rollout_digest {
            return Err(RecordPolicyProjectionError::ProjectionChanged);
        }
        let projector =
            PolicyEvidenceRunProjector::new(vec![fixture], self.training_policy.clone())?;
        let projected = projector
            .project(rollout_digest)
            .map_err(RecordPolicyProjectionError::Contract)?;
        let Some(envelope) = projected else {
            return Ok(None);
        };

        // The production seam never hands an unregistered in-memory copy to training. Persist it
        // through the shared record content graph, then read it back through the trajectory
        // tombstone/lineage gate. This also gives revocation a real production trajectory writer,
        // reader, and source lineage caller rather than a merely available helper API.
        let directory = self.runs_dir.join(".derivatives").join("trajectories");
        let mut registry = self.open_trajectory_registry(&directory)?;
        registry.ingest(&envelope)?;
        Ok(registry
            .get_by_run(&spec.run_id)?
            .map(|registered| registered.envelope))
    }
}

impl TrajectoryProjection for RecordPolicyRunProjector {
    fn project(&self, rollout_digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        self.project_record(rollout_digest)
            .map_err(|error| match error {
                RecordPolicyProjectionError::Contract(error) => error,
                _ => ContractError::ProjectionFailed(
                    "live record evidence is unavailable, changed, or invalid",
                ),
            })
    }
}

fn build_fixture(
    runs_dir: &Path,
    spec: &RecordedPolicyRunSpec,
) -> Result<PolicyEvidenceRunFixture, RecordPolicyProjectionError> {
    let scoped = iteron_record::load_forked_scoped(runs_dir, &spec.run_id)?;
    let physical = scoped
        .iter()
        .filter(|entry| entry.run_id == spec.run_id)
        .collect::<Vec<_>>();
    let tenant = physical
        .first()
        .map(|entry| entry.tenant.clone())
        .ok_or_else(|| RecordPolicyProjectionError::EmptyRun(spec.run_id.0.clone()))?;
    if physical.iter().any(|entry| entry.tenant != tenant) {
        return Err(RecordPolicyProjectionError::CrossRunEvidence(
            spec.run_id.0.clone(),
        ));
    }

    let mut checkpoint_digest = None;
    let mut policy_snapshot = None;
    let mut decisions = Vec::new();
    let mut outcomes = Vec::new();
    for entry in physical {
        match &entry.event.kind {
            EventKind::TunablesSnapshot { snapshot, .. } => {
                set_unique(
                    &mut checkpoint_digest,
                    snapshot.snapshot_digest_sha256.clone(),
                )
                .map_err(|_| {
                    RecordPolicyProjectionError::TunablesCheckpoint(spec.run_id.0.clone())
                })?;
            }
            EventKind::TunablesSnapshotV2 { snapshot, .. } => {
                set_unique(
                    &mut checkpoint_digest,
                    snapshot.snapshot_digest_sha256.clone(),
                )
                .map_err(|_| {
                    RecordPolicyProjectionError::TunablesCheckpoint(spec.run_id.0.clone())
                })?;
            }
            EventKind::PolicyBundleSnapshot { snapshot, .. } => {
                iteron_record::policy_bundle::validate_policy_bundle_snapshot(snapshot).map_err(
                    |_| RecordPolicyProjectionError::PolicyCheckpoint(spec.run_id.0.clone()),
                )?;
                set_unique(&mut policy_snapshot, snapshot.clone()).map_err(|_| {
                    RecordPolicyProjectionError::PolicyCheckpoint(spec.run_id.0.clone())
                })?;
            }
            EventKind::PolicyDecision { evidence } => {
                if evidence.run_id != spec.run_id {
                    return Err(RecordPolicyProjectionError::CrossRunEvidence(
                        spec.run_id.0.clone(),
                    ));
                }
                decisions.push(evidence.clone());
            }
            EventKind::PolicyOutcome { evidence } => {
                if evidence.run_id != spec.run_id {
                    return Err(RecordPolicyProjectionError::CrossRunEvidence(
                        spec.run_id.0.clone(),
                    ));
                }
                outcomes.push(evidence.clone());
            }
            _ => {}
        }
    }
    let checkpoint_digest = checkpoint_digest
        .ok_or_else(|| RecordPolicyProjectionError::TunablesCheckpoint(spec.run_id.0.clone()))?;
    let snapshot = policy_snapshot
        .ok_or_else(|| RecordPolicyProjectionError::PolicyCheckpoint(spec.run_id.0.clone()))?;
    let policies = snapshot
        .slots
        .iter()
        .map(|binding| {
            Ok(PolicyRef {
                slot: StrategySlot::new(binding.slot.as_persisted_str())?,
                policy_id: binding.policy.policy_id.clone(),
                version: binding.policy.policy_version.clone(),
                digest: binding.policy.policy_digest_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    let unique_slots = policies
        .iter()
        .map(|policy| policy.slot.as_str())
        .collect::<BTreeSet<_>>();
    if unique_slots.len() != policies.len() {
        return Err(RecordPolicyProjectionError::PolicyCheckpoint(
            spec.run_id.0.clone(),
        ));
    }
    let bundle = PolicyBundle {
        bundle_id: snapshot.bundle_id,
        digest: snapshot.bundle_digest_sha256,
        policies,
        rollback_to: None,
    };
    let mut fixture = PolicyEvidenceRunFixture {
        schema_version: POLICY_EVIDENCE_RUN_SCHEMA_VERSION,
        rollout_digest: "0".repeat(64),
        checkpoint_digest,
        run_id: spec.run_id.clone(),
        tenant_id: TenantId(tenant.0),
        task_id: spec.task_id.clone(),
        domain: spec.domain.clone(),
        bundle,
        decisions,
        outcomes,
        reward_context: spec.reward_context.clone(),
        governance: spec.governance.clone(),
        // Live record availability is checked above and again on every project call. There is no
        // caller-controlled revocation bit in this adapter.
        training_revoked: false,
    };
    fixture.rollout_digest = fixture.canonical_rollout_digest()?;
    // Reuse evolve's full ordering, join, identity, reward, and governance validator here rather
    // than maintaining a second relaxed validation path.
    let _ = PolicyEvidenceRunProjector::new(
        vec![fixture.clone()],
        TrainingAdmissionPolicy::new(BTreeSet::new(), BTreeMap::new())?,
    )?;
    Ok(fixture)
}

fn set_unique<T>(slot: &mut Option<T>, value: T) -> Result<(), ()> {
    if slot.is_some() {
        Err(())
    } else {
        *slot = Some(value);
        Ok(())
    }
}

fn record_is_unavailable(error: &iteron_record::RecordError) -> bool {
    match error {
        iteron_record::RecordError::Io(error) => error.kind() == std::io::ErrorKind::NotFound,
        iteron_record::RecordError::PrivateContent(
            iteron_record::ContentStoreError::Revoked { .. }
            | iteron_record::ContentStoreError::Unresolved { .. },
        ) => true,
        _ => false,
    }
}
