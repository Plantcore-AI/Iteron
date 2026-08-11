//! Closed checkpoint algebra over validated bundles plus the manifests a bare bundle omits.
//!
//! `PolicyBundle` intentionally carries only policy identities. Admission, base-model rebinding,
//! and held-out attribution need `PolicyManifest` and `PromotionEvidence`, so every operator in
//! this module takes an explicit [`PolicyCheckpoint`] rather than pretending the bare bundle holds
//! facts it does not.

use crate::checkpoint_transfer::TransferMetric;
use crate::dataset::sha256_hex;
use crate::{
    BaseModelId, CapabilityAdmissionError, ContractError, DeploymentBundle, Interval,
    ManifestAdmissionPolicy, PolicyBundle, PolicyManifest, PolicyRef, PromotionAuthorityError,
    PromotionEvidence, StrategySlot,
};
use iteron_protocol::Capability;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A closed checkpoint: one manifest for every policy identity and exact deployment bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckpoint {
    bundle: PolicyBundle,
    manifests: BTreeMap<StrategySlot, PolicyManifest>,
    deployment_bytes: Vec<u8>,
    /// Slots whose permission surface or lineage changed without a checkpoint-bound fresh
    /// held-out evaluation. A pending checkpoint is a valid algebra value, but it is deliberately
    /// not a deployable value.
    #[serde(default)]
    fresh_held_out_slots: BTreeSet<StrategySlot>,
}

#[derive(Deserialize)]
struct DeploymentContent {
    schema_version: u16,
    bundle_id: String,
    rollback_to: Option<String>,
    manifests: BTreeMap<StrategySlot, PolicyManifest>,
}

#[derive(Serialize)]
struct CanonicalDeploymentContent<'a> {
    schema_version: u16,
    bundle_id: &'a str,
    rollback_to: &'a Option<String>,
    manifests: &'a BTreeMap<StrategySlot, PolicyManifest>,
}

fn canonical_deployment_bytes(
    bundle_id: &str,
    rollback_to: &Option<String>,
    manifests: &BTreeMap<StrategySlot, PolicyManifest>,
) -> Result<Vec<u8>, CheckpointAlgebraError> {
    serde_json::to_vec(&CanonicalDeploymentContent {
        schema_version: 1,
        bundle_id,
        rollback_to,
        manifests,
    })
    .map_err(CheckpointAlgebraError::Encoding)
}

impl PolicyCheckpoint {
    pub fn build(
        bundle_id: impl Into<String>,
        rollback_to: Option<String>,
        manifests: BTreeMap<StrategySlot, PolicyManifest>,
    ) -> Result<Self, CheckpointAlgebraError> {
        Self::build_with_fresh_held_out(bundle_id, rollback_to, manifests, BTreeSet::new())
    }

    pub(crate) fn build_with_fresh_held_out(
        bundle_id: impl Into<String>,
        rollback_to: Option<String>,
        manifests: BTreeMap<StrategySlot, PolicyManifest>,
        fresh_held_out_slots: BTreeSet<StrategySlot>,
    ) -> Result<Self, CheckpointAlgebraError> {
        if manifests.is_empty() {
            return Err(CheckpointAlgebraError::EmptyCheckpoint);
        }
        for (slot, manifest) in &manifests {
            manifest.validate()?;
            if slot != &manifest.policy.slot {
                return Err(CheckpointAlgebraError::ManifestSlotMismatch(
                    slot.as_str().to_owned(),
                ));
            }
        }
        let bundle_id = bundle_id.into();
        let policies: Vec<_> = manifests
            .values()
            .map(|manifest| manifest.policy.clone())
            .collect();
        let deployment_bytes = canonical_deployment_bytes(&bundle_id, &rollback_to, &manifests)?;
        let bundle = PolicyBundle {
            bundle_id,
            digest: sha256_hex(&deployment_bytes),
            policies,
            rollback_to,
        };
        let checkpoint = Self {
            bundle,
            manifests,
            deployment_bytes,
            fresh_held_out_slots,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub(crate) fn from_deployment(
        deployment: &DeploymentBundle,
    ) -> Result<Self, CheckpointAlgebraError> {
        let content: DeploymentContent =
            serde_json::from_slice(deployment.bytes()).map_err(CheckpointAlgebraError::Encoding)?;
        if content.schema_version != 1 {
            return Err(CheckpointAlgebraError::UnsupportedDeploymentSchema(
                content.schema_version,
            ));
        }
        let checkpoint = Self::build(content.bundle_id, content.rollback_to, content.manifests)?;
        if checkpoint.bundle() != deployment.bundle()
            || checkpoint.deployment_bytes() != deployment.bytes()
        {
            return Err(CheckpointAlgebraError::DeploymentDigestMismatch);
        }
        Ok(checkpoint)
    }

    pub(crate) fn changed_slots(&self, other: &Self) -> BTreeSet<StrategySlot> {
        self.manifests
            .keys()
            .chain(other.manifests.keys())
            .filter(|slot| self.manifests.get(*slot) != other.manifests.get(*slot))
            .cloned()
            .collect()
    }

    pub fn validate(&self) -> Result<(), CheckpointAlgebraError> {
        self.bundle.validate()?;
        if sha256_hex(&self.deployment_bytes) != self.bundle.digest {
            return Err(CheckpointAlgebraError::DeploymentDigestMismatch);
        }
        if self.deployment_bytes
            != canonical_deployment_bytes(
                &self.bundle.bundle_id,
                &self.bundle.rollback_to,
                &self.manifests,
            )?
        {
            return Err(CheckpointAlgebraError::DeploymentDigestMismatch);
        }
        if self.manifests.len() != self.bundle.policies.len() {
            return Err(CheckpointAlgebraError::ManifestSetMismatch);
        }
        for policy in &self.bundle.policies {
            let manifest = self
                .manifests
                .get(&policy.slot)
                .ok_or_else(|| CheckpointAlgebraError::MissingManifest(policy.slot.clone()))?;
            manifest.validate()?;
            if &manifest.policy != policy {
                return Err(CheckpointAlgebraError::ManifestPolicyMismatch(
                    policy.slot.clone(),
                ));
            }
        }
        let canonical_policies: Vec<_> = self
            .manifests
            .values()
            .map(|manifest| manifest.policy.clone())
            .collect();
        if self.bundle.policies != canonical_policies {
            return Err(CheckpointAlgebraError::ManifestSetMismatch);
        }
        if !self
            .fresh_held_out_slots
            .iter()
            .all(|slot| self.manifests.contains_key(slot))
        {
            return Err(CheckpointAlgebraError::FreshHeldOutSetMismatch);
        }
        Ok(())
    }

    pub fn bundle(&self) -> &PolicyBundle {
        &self.bundle
    }

    pub fn manifests(&self) -> &BTreeMap<StrategySlot, PolicyManifest> {
        &self.manifests
    }

    pub fn manifest_for(&self, slot: &StrategySlot) -> Option<&PolicyManifest> {
        self.manifests.get(slot)
    }

    pub fn deployment_bytes(&self) -> &[u8] {
        &self.deployment_bytes
    }

    pub fn deployment_bundle(&self) -> Result<DeploymentBundle, PromotionAuthorityError> {
        self.validate()
            .map_err(|_| PromotionAuthorityError::LineageMismatch)?;
        if !self.fresh_held_out_slots.is_empty() {
            return Err(PromotionAuthorityError::FreshHeldOutRequired);
        }
        self.deployment_bundle_unchecked()
    }

    pub fn fresh_held_out_slots(&self) -> &BTreeSet<StrategySlot> {
        &self.fresh_held_out_slots
    }

    pub(crate) fn deployment_bundle_unchecked(
        &self,
    ) -> Result<DeploymentBundle, PromotionAuthorityError> {
        DeploymentBundle::new(self.bundle.clone(), self.deployment_bytes.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckpointEvent {
    FreshHeldOutRequired {
        slots: Vec<StrategySlot>,
    },
    CapabilitiesRestricted {
        slot: StrategySlot,
        before: BTreeSet<Capability>,
        after: BTreeSet<Capability>,
    },
    Retired {
        slot: StrategySlot,
        retired: PolicyRef,
        restored: PolicyRef,
    },
    Transferred {
        slots: Vec<StrategySlot>,
        from: BaseModelId,
        to: BaseModelId,
        portable_fraction: f64,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlgebraOutput {
    pub checkpoint: PolicyCheckpoint,
    pub events: Vec<CheckpointEvent>,
    /// Permission-surface or lineage operations never inherit a previous held-out pass.
    pub fresh_held_out_required: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SlotDelta {
    pub slot: StrategySlot,
    /// `None` means the slot was not present in the earlier checkpoint.
    pub before: Option<PolicyRef>,
    /// `None` means the slot is no longer present in the later checkpoint.
    pub after: Option<PolicyRef>,
    /// Comparable before/after identities are required for a meaningful held-out delta. An added
    /// or removed slot has no policy on one side. A manifest-only change retains the same
    /// `PolicyRef`, so raw [`PromotionEvidence`] cannot bind both checkpoint manifests either. The
    /// algebra reports those changes without fabricating an attribution.
    pub held_out_delta: Option<Interval>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointDiff {
    pub changed: Vec<SlotDelta>,
}

pub fn diff(
    before: &PolicyCheckpoint,
    after: &PolicyCheckpoint,
    evidence_by_slot: &BTreeMap<StrategySlot, PromotionEvidence>,
) -> Result<CheckpointDiff, CheckpointAlgebraError> {
    before.validate()?;
    after.validate()?;
    let mut changed = Vec::new();
    let slots: BTreeSet<_> = before
        .manifests
        .keys()
        .chain(after.manifests.keys())
        .cloned()
        .collect();
    for slot in slots {
        let left_manifest = before.manifests.get(&slot);
        let right_manifest = after.manifests.get(&slot);
        if left_manifest == right_manifest {
            continue;
        }
        let left = left_manifest.map(|manifest| manifest.policy.clone());
        let right = right_manifest.map(|manifest| manifest.policy.clone());
        let held_out_delta = match (left_manifest, right_manifest) {
            (Some(left_manifest), Some(right_manifest))
                if left_manifest.policy == right_manifest.policy =>
            {
                None
            }
            (Some(left_manifest), Some(right_manifest)) => {
                let evidence = evidence_by_slot
                    .get(&slot)
                    .ok_or_else(|| CheckpointAlgebraError::MissingHeldOutEvidence(slot.clone()))?;
                evidence.validate_contract()?;
                if evidence.baseline != left_manifest.policy
                    || evidence.candidate != right_manifest.policy
                    || evidence.base_model != right_manifest.base_model
                {
                    return Err(CheckpointAlgebraError::EvidenceIdentityMismatch(slot));
                }
                Some(evidence.task_score_delta)
            }
            (None, Some(_)) | (Some(_), None) => None,
            (None, None) => continue,
        };
        changed.push(SlotDelta {
            slot,
            before: left,
            after: right,
            held_out_delta,
        });
    }
    Ok(CheckpointDiff { changed })
}

pub fn merge(
    bundle_id: impl Into<String>,
    rollback_to: Option<String>,
    checkpoints: &[PolicyCheckpoint],
    admissions: &BTreeMap<StrategySlot, ManifestAdmissionPolicy>,
) -> Result<AlgebraOutput, CheckpointAlgebraError> {
    if checkpoints.is_empty() {
        return Err(CheckpointAlgebraError::EmptyMerge);
    }
    let mut manifests = BTreeMap::new();
    for checkpoint in checkpoints {
        checkpoint.validate()?;
        for (slot, manifest) in checkpoint.manifests() {
            if manifests.insert(slot.clone(), manifest.clone()).is_some() {
                return Err(CheckpointAlgebraError::DuplicateSlot(slot.clone()));
            }
        }
    }
    readmit_all(&manifests, admissions)?;
    let slots: BTreeSet<_> = manifests.keys().cloned().collect();
    Ok(AlgebraOutput {
        checkpoint: PolicyCheckpoint::build_with_fresh_held_out(
            bundle_id,
            rollback_to,
            manifests,
            slots.clone(),
        )?,
        events: vec![CheckpointEvent::FreshHeldOutRequired {
            slots: slots.into_iter().collect(),
        }],
        fresh_held_out_required: true,
    })
}

pub fn restrict(
    source: &PolicyCheckpoint,
    bundle_id: impl Into<String>,
    slot: &StrategySlot,
    capabilities: BTreeSet<Capability>,
    admissions: &BTreeMap<StrategySlot, ManifestAdmissionPolicy>,
) -> Result<AlgebraOutput, CheckpointAlgebraError> {
    source.validate()?;
    let mut manifests = source.manifests.clone();
    let manifest = manifests
        .get_mut(slot)
        .ok_or_else(|| CheckpointAlgebraError::MissingManifest(slot.clone()))?;
    let before = manifest.required_capabilities.clone();
    if !capabilities.is_subset(&before) {
        return Err(CheckpointAlgebraError::CapabilityWidening { slot: slot.clone() });
    }
    manifest.required_capabilities = capabilities.clone();
    readmit_all(&manifests, admissions)?;
    let mut fresh_held_out_slots = source.fresh_held_out_slots.clone();
    fresh_held_out_slots.insert(slot.clone());
    let rollback_to = if source.fresh_held_out_slots.is_empty() {
        Some(source.bundle.bundle_id.clone())
    } else {
        source.bundle.rollback_to.clone()
    };
    Ok(AlgebraOutput {
        checkpoint: PolicyCheckpoint::build_with_fresh_held_out(
            bundle_id,
            rollback_to,
            manifests,
            fresh_held_out_slots,
        )?,
        events: vec![
            CheckpointEvent::CapabilitiesRestricted {
                slot: slot.clone(),
                before,
                after: capabilities,
            },
            CheckpointEvent::FreshHeldOutRequired {
                slots: vec![slot.clone()],
            },
        ],
        fresh_held_out_required: true,
    })
}

pub fn retire(
    source: &PolicyCheckpoint,
    baseline: &PolicyCheckpoint,
    bundle_id: impl Into<String>,
    slot: &StrategySlot,
    admissions: &BTreeMap<StrategySlot, ManifestAdmissionPolicy>,
) -> Result<AlgebraOutput, CheckpointAlgebraError> {
    source.validate()?;
    baseline.validate()?;
    let retired = source
        .bundle
        .policy_for(slot)
        .cloned()
        .ok_or_else(|| CheckpointAlgebraError::MissingManifest(slot.clone()))?;
    let restored_manifest = baseline
        .manifest_for(slot)
        .cloned()
        .ok_or_else(|| CheckpointAlgebraError::MissingBaseline(slot.clone()))?;
    let restored = restored_manifest.policy.clone();
    let mut manifests = source.manifests.clone();
    manifests.insert(slot.clone(), restored_manifest);
    readmit_all(&manifests, admissions)?;
    let mut fresh_held_out_slots = source.fresh_held_out_slots.clone();
    fresh_held_out_slots.insert(slot.clone());
    Ok(AlgebraOutput {
        checkpoint: PolicyCheckpoint::build_with_fresh_held_out(
            bundle_id,
            source.bundle.rollback_to.clone(),
            manifests,
            fresh_held_out_slots,
        )?,
        events: vec![
            CheckpointEvent::Retired {
                slot: slot.clone(),
                retired,
                restored,
            },
            CheckpointEvent::FreshHeldOutRequired {
                slots: vec![slot.clone()],
            },
        ],
        fresh_held_out_required: true,
    })
}

pub(crate) fn readmit_all(
    manifests: &BTreeMap<StrategySlot, PolicyManifest>,
    admissions: &BTreeMap<StrategySlot, ManifestAdmissionPolicy>,
) -> Result<(), CheckpointAlgebraError> {
    for (slot, manifest) in manifests {
        let policy = admissions
            .get(slot)
            .ok_or_else(|| CheckpointAlgebraError::MissingAdmissionPolicy(slot.clone()))?;
        policy.assess(manifest)?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointAlgebraError {
    #[error("checkpoint contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("checkpoint deployment JSON could not be encoded: {0}")]
    Encoding(#[source] serde_json::Error),
    #[error("checkpoint deployment schema {0} is unsupported")]
    UnsupportedDeploymentSchema(u16),
    #[error("checkpoint must contain at least one manifest")]
    EmptyCheckpoint,
    #[error("merge requires at least one checkpoint")]
    EmptyMerge,
    #[error("manifest map key does not match manifest slot `{0}`")]
    ManifestSlotMismatch(String),
    #[error("checkpoint manifest set does not exactly match its policy bundle")]
    ManifestSetMismatch,
    #[error("checkpoint is missing a manifest for slot `{0:?}`")]
    MissingManifest(StrategySlot),
    #[error("checkpoint manifest policy does not match bundle policy for slot `{0:?}`")]
    ManifestPolicyMismatch(StrategySlot),
    #[error("checkpoint deployment bytes do not match the bundle digest")]
    DeploymentDigestMismatch,
    #[error("checkpoint fresh-held-out set names a slot absent from the manifest set")]
    FreshHeldOutSetMismatch,
    #[error("checkpoint merge contains duplicate slot `{0:?}`")]
    DuplicateSlot(StrategySlot),
    #[error("checkpoint change for slot `{0:?}` lacks held-out attribution")]
    MissingHeldOutEvidence(StrategySlot),
    #[error("held-out attribution does not match the policies changed in slot `{0:?}`")]
    EvidenceIdentityMismatch(StrategySlot),
    #[error("no admission policy was supplied for slot `{0:?}`")]
    MissingAdmissionPolicy(StrategySlot),
    #[error("checkpoint capability admission failed: {0}")]
    Admission(#[from] CapabilityAdmissionError),
    #[error("restrict would widen required capabilities for slot `{slot:?}`")]
    CapabilityWidening { slot: StrategySlot },
    #[error("baseline checkpoint has no policy for slot `{0:?}`")]
    MissingBaseline(StrategySlot),
    #[error("cross-model transfer requires distinct source and target models")]
    SameBaseModel,
    #[error("held-out evaluations do not match the declared source and target base models")]
    EvaluationBaseModelMismatch,
    #[error("held-out evaluations do not attest the same policy identity")]
    TransferIdentityMismatch,
    #[error("cross-model transfer evaluations do not cover the checkpoint slots exactly")]
    TransferEvaluationSetMismatch,
    #[error("source delta must be finite and positive and target delta must be finite")]
    InvalidTransferDelta,
    #[error("manifest in slot `{0:?}` is not bound to the declared source model")]
    ManifestBaseModelMismatch(StrategySlot),
    #[error("target-model held-out evidence for slot `{slot:?}` failed its own promotion gate")]
    TargetGateRejected {
        slot: StrategySlot,
        metric: TransferMetric,
        reasons: Vec<String>,
    },
    #[error("target-model gate returned an unsupported assessment")]
    UnexpectedTargetAssessment,
}

#[cfg(test)]
#[path = "checkpoint_algebra_tests.rs"]
mod tests;
