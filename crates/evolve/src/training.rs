//! Explicit offline admission policy for training-data use.
//!
//! Governance fields in a trajectory are untrusted declarations. A non-empty license or retention
//! string is never authorization by itself: callers must supply a bounded license allowlist and a
//! retention-policy table, and every unknown or prohibited value fails closed. This module creates
//! only an offline eligibility proof; it has no runtime, registry, or permission authority.

use crate::{
    ContractError, DataClass, MAX_SHORT_STRING_BYTES, TrainingConsent, TrajectoryEnvelope,
    validate_collection, validate_nonempty_string,
};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_TRAINING_LICENSE_ALLOWLIST_ENTRIES: usize = 128;
pub const MAX_RETENTION_POLICY_TABLE_ENTRIES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionTrainingUse {
    Allowed,
    Prohibited,
}

/// Caller-configured offline training-use policy.
///
/// The exact strings are deployment policy identifiers. This crate does not infer license
/// compatibility or reinterpret an unknown retention policy as permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingAdmissionPolicy {
    allowed_licenses: BTreeSet<String>,
    retention_policies: BTreeMap<String, RetentionTrainingUse>,
}

impl TrainingAdmissionPolicy {
    pub fn new(
        allowed_licenses: BTreeSet<String>,
        retention_policies: BTreeMap<String, RetentionTrainingUse>,
    ) -> Result<Self, ContractError> {
        let policy = Self {
            allowed_licenses,
            retention_policies,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn allowed_licenses(&self) -> &BTreeSet<String> {
        &self.allowed_licenses
    }

    pub fn retention_policies(&self) -> &BTreeMap<String, RetentionTrainingUse> {
        &self.retention_policies
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        validate_collection(
            "training_admission.allowed_licenses",
            self.allowed_licenses.len(),
            MAX_TRAINING_LICENSE_ALLOWLIST_ENTRIES,
        )?;
        for license in &self.allowed_licenses {
            validate_nonempty_string(
                "training_admission.allowed_license",
                license,
                MAX_SHORT_STRING_BYTES,
            )?;
        }

        validate_collection(
            "training_admission.retention_policies",
            self.retention_policies.len(),
            MAX_RETENTION_POLICY_TABLE_ENTRIES,
        )?;
        for retention_policy in self.retention_policies.keys() {
            validate_nonempty_string(
                "training_admission.retention_policy",
                retention_policy,
                MAX_SHORT_STRING_BYTES,
            )?;
        }
        Ok(())
    }

    /// Validate all governance declarations against this explicit policy.
    pub fn validate_trajectory(
        &self,
        envelope: &TrajectoryEnvelope,
    ) -> Result<(), TrainingEligibilityError> {
        self.validate()
            .map_err(TrainingEligibilityError::InvalidAdmissionPolicy)?;
        envelope.validate()?;
        if envelope.governance.consent != TrainingConsent::Allowed {
            return Err(TrainingEligibilityError::ConsentNotAllowed(
                envelope.governance.consent,
            ));
        }
        if envelope.governance.contains_secret_material {
            return Err(TrainingEligibilityError::ContainsSecretMaterial);
        }
        if matches!(
            envelope.governance.class,
            DataClass::Secret | DataClass::Unknown
        ) {
            return Err(TrainingEligibilityError::ProhibitedDataClass(
                envelope.governance.class,
            ));
        }

        let license = envelope
            .governance
            .content_license
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(TrainingEligibilityError::MissingContentLicense)?;
        if !self.allowed_licenses.contains(license) {
            return Err(TrainingEligibilityError::LicenseNotAllowed {
                license: license.clone(),
            });
        }

        let retention_policy = &envelope.governance.retention_policy;
        match self.retention_policies.get(retention_policy) {
            Some(RetentionTrainingUse::Allowed) => Ok(()),
            Some(RetentionTrainingUse::Prohibited) => {
                Err(TrainingEligibilityError::RetentionPolicyProhibitsTraining {
                    retention_policy: retention_policy.clone(),
                })
            }
            None => Err(TrainingEligibilityError::UnknownRetentionPolicy {
                retention_policy: retention_policy.clone(),
            }),
        }
    }

    /// Admit a bounded borrow for offline training use. This is not runtime authority.
    pub fn admit<'a>(
        &self,
        envelope: &'a TrajectoryEnvelope,
    ) -> Result<TrainingEligibleTrajectory<'a>, TrainingEligibilityError> {
        self.validate_trajectory(envelope)?;
        Ok(TrainingEligibleTrajectory { envelope })
    }
}

impl TrajectoryEnvelope {
    /// Legacy no-policy entry point retained fail-closed for source compatibility.
    ///
    /// Call [`TrainingAdmissionPolicy::validate_trajectory`] with an explicit caller-owned policy.
    pub fn validate_for_training(&self) -> Result<(), TrainingEligibilityError> {
        self.validate()?;
        Err(TrainingEligibilityError::ExplicitAdmissionPolicyRequired)
    }

    pub fn validate_for_training_with(
        &self,
        policy: &TrainingAdmissionPolicy,
    ) -> Result<(), TrainingEligibilityError> {
        policy.validate_trajectory(self)
    }
}

/// A borrow proven eligible under one explicit offline [`TrainingAdmissionPolicy`].
///
/// This proof does not authenticate the trajectory producer or grant runtime authority; a future
/// evolution TCB must establish those properties before use.
#[derive(Debug, Clone, Copy)]
pub struct TrainingEligibleTrajectory<'a> {
    envelope: &'a TrajectoryEnvelope,
}

impl<'a> TrainingEligibleTrajectory<'a> {
    pub fn envelope(self) -> &'a TrajectoryEnvelope {
        self.envelope
    }
}

impl<'a> TryFrom<&'a TrajectoryEnvelope> for TrainingEligibleTrajectory<'a> {
    type Error = TrainingEligibilityError;

    fn try_from(envelope: &'a TrajectoryEnvelope) -> Result<Self, Self::Error> {
        envelope.validate()?;
        Err(TrainingEligibilityError::ExplicitAdmissionPolicyRequired)
    }
}

impl<'a, 'p> TryFrom<(&'a TrajectoryEnvelope, &'p TrainingAdmissionPolicy)>
    for TrainingEligibleTrajectory<'a>
{
    type Error = TrainingEligibilityError;

    fn try_from(
        (envelope, policy): (&'a TrajectoryEnvelope, &'p TrainingAdmissionPolicy),
    ) -> Result<Self, Self::Error> {
        policy.admit(envelope)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TrainingEligibilityError {
    #[error("trajectory contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("training admission policy is invalid: {0}")]
    InvalidAdmissionPolicy(#[source] ContractError),
    #[error("training admission requires an explicit caller-configured policy")]
    ExplicitAdmissionPolicyRequired,
    #[error("training consent is {0:?}, not allowed")]
    ConsentNotAllowed(TrainingConsent),
    #[error("data class {0:?} is prohibited for training")]
    ProhibitedDataClass(DataClass),
    #[error("trajectory is marked as containing secret material")]
    ContainsSecretMaterial,
    #[error("training requires a non-empty content license")]
    MissingContentLicense,
    #[error("content license is not in the training allowlist")]
    LicenseNotAllowed { license: String },
    #[error("retention policy is unknown to the training policy table")]
    UnknownRetentionPolicy { retention_policy: String },
    #[error("retention policy explicitly prohibits training use")]
    RetentionPolicyProhibitsTraining { retention_policy: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DataGovernance, EVOLUTION_SCHEMA_VERSION, PolicyBundle, PolicyRef, RewardVector,
        StrategySlot,
    };
    use iteron_protocol::{RunId, TenantId};

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy() -> TrainingAdmissionPolicy {
        TrainingAdmissionPolicy::new(
            ["apache-2.0".to_owned()].into(),
            [
                ("training-v1".to_owned(), RetentionTrainingUse::Allowed),
                (
                    "audit-only-30d".to_owned(),
                    RetentionTrainingUse::Prohibited,
                ),
            ]
            .into(),
        )
        .unwrap()
    }

    fn envelope(license: &str, retention_policy: &str) -> TrajectoryEnvelope {
        let policy_ref = PolicyRef {
            slot: StrategySlot::router(),
            policy_id: "router-a".into(),
            version: "1.0.0".into(),
            digest: D.into(),
        };
        TrajectoryEnvelope {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            run_id: RunId("run-training-admission".into()),
            tenant_id: TenantId::default(),
            task_id: "task-training-admission".into(),
            domain: "coding".into(),
            environment_digest: D.into(),
            bundle: PolicyBundle {
                bundle_id: "bundle-a".into(),
                digest: D.into(),
                policies: vec![policy_ref],
                rollback_to: None,
            },
            decisions: Vec::new(),
            terminal_outcome: "completed".into(),
            reward: RewardVector {
                task_score: 1.0,
                correctness: 1.0,
                safety_violations: 0,
                policy_violations: 0,
                cost_usd: 0.01,
                wall_time_ms: 10,
                human_acceptance: None,
                domain: BTreeMap::new(),
            },
            governance: DataGovernance {
                class: DataClass::Public,
                consent: TrainingConsent::Allowed,
                content_license: Some(license.into()),
                contains_secret_material: false,
                retention_policy: retention_policy.into(),
            },
        }
    }

    #[test]
    fn non_allowlisted_license_is_rejected_even_when_nonempty() {
        assert!(matches!(
            policy().admit(&envelope("proprietary", "training-v1")),
            Err(TrainingEligibilityError::LicenseNotAllowed { license })
                if license == "proprietary"
        ));
    }

    #[test]
    fn retention_policy_that_prohibits_training_is_rejected() {
        assert!(matches!(
            policy().admit(&envelope("apache-2.0", "audit-only-30d")),
            Err(TrainingEligibilityError::RetentionPolicyProhibitsTraining {
                retention_policy
            }) if retention_policy == "audit-only-30d"
        ));
    }

    #[test]
    fn explicitly_allowed_license_and_retention_combination_passes() {
        let envelope = envelope("apache-2.0", "training-v1");
        let proof = policy().admit(&envelope).unwrap();
        assert_eq!(proof.envelope().task_id, "task-training-admission");
    }

    #[test]
    fn unknown_retention_policy_is_rejected_fail_closed() {
        assert!(matches!(
            policy().admit(&envelope("apache-2.0", "unregistered-policy")),
            Err(TrainingEligibilityError::UnknownRetentionPolicy { retention_policy })
                if retention_policy == "unregistered-policy"
        ));
    }

    #[test]
    fn legacy_no_policy_conversion_cannot_admit_training_data() {
        let envelope = envelope("apache-2.0", "training-v1");
        assert!(matches!(
            TrainingEligibleTrajectory::try_from(&envelope),
            Err(TrainingEligibilityError::ExplicitAdmissionPolicyRequired)
        ));
    }

    #[test]
    fn caller_policy_strings_and_collections_are_bounded() {
        let oversized_license = "x".repeat(MAX_SHORT_STRING_BYTES + 1);
        assert!(matches!(
            TrainingAdmissionPolicy::new([oversized_license].into(), BTreeMap::new()),
            Err(ContractError::StringTooLong { .. })
        ));

        let too_many_licenses = (0..=MAX_TRAINING_LICENSE_ALLOWLIST_ENTRIES)
            .map(|index| format!("license-{index}"))
            .collect();
        assert!(matches!(
            TrainingAdmissionPolicy::new(too_many_licenses, BTreeMap::new()),
            Err(ContractError::CollectionTooLarge { .. })
        ));
    }
}
