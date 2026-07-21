//! Least-privilege assessment for candidate capability declarations.
//!
//! This is deliberately a pure policy boundary, not an authority source. It can reject a
//! manifest whose requested capabilities exceed a trusted slot or parent ceiling, and it can
//! calculate the intersection a runtime must enforce. It cannot grant a capability, mutate a
//! permission policy, or authorize an effect.

use crate::{
    ContractError, MAX_REQUIRED_CAPABILITIES, PolicyManifest, PolicyRef, StrategySlot,
    validate_collection,
};
use core_protocol::Capability;
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum CapabilityAdmissionError {
    #[error("candidate manifest contract is invalid: {0}")]
    InvalidManifest(#[from] ContractError),
    #[error("candidate slot `{found}` does not match admission-policy slot `{expected}`")]
    CandidateSlotMismatch { expected: String, found: String },
    #[error("candidate parent must target the same strategy slot as the candidate")]
    ParentSlotMismatch,
    #[error("candidate declares a parent but the admission policy has no parent ceiling")]
    MissingParentCeiling,
    #[error("admission policy supplies a parent ceiling for a root candidate")]
    UnexpectedParentCeiling,
    #[error("candidate parent identity does not match the parent capability ceiling")]
    ParentIdentityMismatch,
    #[error("candidate requires capabilities outside its slot ceiling: {disallowed:?}")]
    ExceedsSlotCeiling { disallowed: BTreeSet<Capability> },
    #[error("candidate requires capabilities outside its parent ceiling: {disallowed:?}")]
    ExceedsParentCeiling { disallowed: BTreeSet<Capability> },
}

/// Capability ceiling tied to the exact immutable parent policy identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentCapabilityCeiling {
    parent: PolicyRef,
    allowed: BTreeSet<Capability>,
}

impl ParentCapabilityCeiling {
    pub fn new(parent: PolicyRef, allowed: BTreeSet<Capability>) -> Self {
        Self { parent, allowed }
    }

    pub fn parent(&self) -> &PolicyRef {
        &self.parent
    }

    pub fn allowed(&self) -> &BTreeSet<Capability> {
        &self.allowed
    }
}

/// Trusted ceilings against which one candidate manifest may be assessed.
///
/// Constructing this policy does not grant its capabilities. The caller is responsible for
/// sourcing the slot and parent ceilings from an authoritative registry rather than candidate
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestAdmissionPolicy {
    slot: StrategySlot,
    slot_allowed: BTreeSet<Capability>,
    parent: Option<ParentCapabilityCeiling>,
}

impl ManifestAdmissionPolicy {
    pub fn new(slot: StrategySlot, slot_allowed: BTreeSet<Capability>) -> Self {
        Self {
            slot,
            slot_allowed,
            parent: None,
        }
    }

    pub fn with_parent_ceiling(mut self, parent: ParentCapabilityCeiling) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn slot(&self) -> &StrategySlot {
        &self.slot
    }

    pub fn slot_allowed(&self) -> &BTreeSet<Capability> {
        &self.slot_allowed
    }

    /// Check that required capabilities are a subset of both the slot and exact-parent ceilings.
    pub fn assess(
        &self,
        manifest: &PolicyManifest,
    ) -> Result<CapabilityAdmission, CapabilityAdmissionError> {
        manifest.validate()?;
        validate_collection(
            "manifest_admission.slot_allowed",
            self.slot_allowed.len(),
            MAX_REQUIRED_CAPABILITIES,
        )?;
        if manifest.policy.slot != self.slot {
            return Err(CapabilityAdmissionError::CandidateSlotMismatch {
                expected: self.slot.as_str().to_owned(),
                found: manifest.policy.slot.as_str().to_owned(),
            });
        }

        let parent_allowed = match (&manifest.parent, &self.parent) {
            (Some(parent), Some(ceiling)) => {
                validate_collection(
                    "manifest_admission.parent_allowed",
                    ceiling.allowed.len(),
                    MAX_REQUIRED_CAPABILITIES,
                )?;
                if parent.slot != manifest.policy.slot {
                    return Err(CapabilityAdmissionError::ParentSlotMismatch);
                }
                if parent != &ceiling.parent {
                    return Err(CapabilityAdmissionError::ParentIdentityMismatch);
                }
                Some(&ceiling.allowed)
            }
            (Some(_), None) => return Err(CapabilityAdmissionError::MissingParentCeiling),
            (None, Some(_)) => return Err(CapabilityAdmissionError::UnexpectedParentCeiling),
            (None, None) => None,
        };

        let disallowed_by_slot: BTreeSet<_> = manifest
            .required_capabilities
            .difference(&self.slot_allowed)
            .copied()
            .collect();
        if !disallowed_by_slot.is_empty() {
            return Err(CapabilityAdmissionError::ExceedsSlotCeiling {
                disallowed: disallowed_by_slot,
            });
        }

        if let Some(parent_allowed) = parent_allowed {
            let disallowed_by_parent: BTreeSet<_> = manifest
                .required_capabilities
                .difference(parent_allowed)
                .copied()
                .collect();
            if !disallowed_by_parent.is_empty() {
                return Err(CapabilityAdmissionError::ExceedsParentCeiling {
                    disallowed: disallowed_by_parent,
                });
            }
        }

        Ok(CapabilityAdmission {
            candidate: manifest.policy.clone(),
            required: manifest.required_capabilities.clone(),
            slot_allowed: self.slot_allowed.clone(),
            parent_allowed: parent_allowed.cloned(),
        })
    }
}

/// Successful least-privilege assessment of a manifest declaration.
///
/// This value is not a permission grant. A runtime must still supply its independently derived
/// allowed set and enforce the resulting [`EffectiveCapabilities`] through its ordinary
/// permission, approval, sandbox, and effect gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAdmission {
    candidate: PolicyRef,
    required: BTreeSet<Capability>,
    slot_allowed: BTreeSet<Capability>,
    parent_allowed: Option<BTreeSet<Capability>>,
}

impl CapabilityAdmission {
    pub fn candidate(&self) -> &PolicyRef {
        &self.candidate
    }

    pub fn required(&self) -> &BTreeSet<Capability> {
        &self.required
    }

    /// Apply the runtime ceiling by intersection only. No capability present solely in the
    /// manifest, slot policy, parent policy, or runtime policy can enter the effective set.
    pub fn intersect_runtime(
        &self,
        runtime_allowed: &BTreeSet<Capability>,
    ) -> EffectiveCapabilities {
        let capabilities = self
            .required
            .iter()
            .copied()
            .filter(|capability| {
                runtime_allowed.contains(capability)
                    && self.slot_allowed.contains(capability)
                    && self
                        .parent_allowed
                        .as_ref()
                        .is_none_or(|parent| parent.contains(capability))
            })
            .collect();
        EffectiveCapabilities { capabilities }
    }
}

/// Intersection-only capability ceiling for the runtime's next permission decision.
///
/// The contained set is intentionally immutable through this API. Membership means only that all
/// candidate/slot/parent/runtime ceilings include the capability; it does not authorize an effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCapabilities {
    capabilities: BTreeSet<Capability>,
}

impl EffectiveCapabilities {
    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn as_set(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactKind, EVOLUTION_SCHEMA_VERSION, EvolutionMethod, ProtocolRange, StrategySlot,
    };

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn capabilities(values: &[Capability]) -> BTreeSet<Capability> {
        values.iter().copied().collect()
    }

    fn policy(id: &str) -> PolicyRef {
        PolicyRef {
            slot: StrategySlot::router(),
            policy_id: id.into(),
            version: "1.0.0".into(),
            digest: D.into(),
        }
    }

    fn manifest(required: &[Capability], parent: Option<PolicyRef>) -> PolicyManifest {
        PolicyManifest {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            policy: policy("candidate"),
            artifact_kind: ArtifactKind::Rules,
            artifact_locator: "registry://candidate@1.0.0".into(),
            parent,
            method: EvolutionMethod::HandAuthored,
            protocol: ProtocolRange { min: 1, max: 1 },
            required_capabilities: capabilities(required),
            training_dataset_digest: None,
            evaluation_suite_digest: D.into(),
        }
    }

    #[test]
    fn required_capabilities_must_fit_both_slot_and_parent_ceilings() {
        let parent = policy("parent");
        let policy = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly, Capability::ReversibleLocal]),
        )
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            parent.clone(),
            capabilities(&[Capability::ReadOnly]),
        ));

        let excessive = manifest(
            &[Capability::ReadOnly, Capability::ReversibleLocal],
            Some(parent.clone()),
        );
        assert!(matches!(
            policy.assess(&excessive),
            Err(CapabilityAdmissionError::ExceedsParentCeiling { disallowed })
                if disallowed == capabilities(&[Capability::ReversibleLocal])
        ));

        let least_privilege = manifest(&[Capability::ReadOnly], Some(parent.clone()));
        assert_eq!(
            policy.assess(&least_privilege).unwrap().required(),
            &capabilities(&[Capability::ReadOnly])
        );

        let slot_excess = manifest(
            &[Capability::ReadOnly, Capability::IrreversibleExternal],
            Some(parent),
        );
        assert!(matches!(
            policy.assess(&slot_excess),
            Err(CapabilityAdmissionError::ExceedsSlotCeiling { disallowed })
                if disallowed == capabilities(&[Capability::IrreversibleExternal])
        ));
    }

    #[test]
    fn parent_ceiling_is_exact_and_missing_context_fails_closed() {
        let parent = policy("parent");
        let candidate = manifest(&[Capability::ReadOnly], Some(parent.clone()));
        let without_parent = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly]),
        );
        assert!(matches!(
            without_parent.assess(&candidate),
            Err(CapabilityAdmissionError::MissingParentCeiling)
        ));

        let wrong_parent = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly]),
        )
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            policy("different-parent"),
            capabilities(&[Capability::ReadOnly]),
        ));
        assert!(matches!(
            wrong_parent.assess(&candidate),
            Err(CapabilityAdmissionError::ParentIdentityMismatch)
        ));

        let root_with_parent_policy = manifest(&[Capability::ReadOnly], None);
        let unexpected = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly]),
        )
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            parent,
            capabilities(&[Capability::ReadOnly]),
        ));
        assert!(matches!(
            unexpected.assess(&root_with_parent_policy),
            Err(CapabilityAdmissionError::UnexpectedParentCeiling)
        ));

        let mut cross_slot_parent = policy("cross-slot-parent");
        cross_slot_parent.slot = StrategySlot::planner();
        let cross_slot_candidate =
            manifest(&[Capability::ReadOnly], Some(cross_slot_parent.clone()));
        let cross_slot_policy = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly]),
        )
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            cross_slot_parent,
            capabilities(&[Capability::ReadOnly]),
        ));
        assert!(matches!(
            cross_slot_policy.assess(&cross_slot_candidate),
            Err(CapabilityAdmissionError::ParentSlotMismatch)
        ));
    }

    #[test]
    fn effective_capabilities_are_intersection_only_never_union() {
        let parent = policy("parent");
        let candidate = manifest(
            &[Capability::ReadOnly, Capability::CodeExecuting],
            Some(parent.clone()),
        );
        let admission = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[
                Capability::ReadOnly,
                Capability::CodeExecuting,
                Capability::TrustMutating,
            ]),
        )
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            parent,
            capabilities(&[Capability::ReadOnly, Capability::CodeExecuting]),
        ))
        .assess(&candidate)
        .unwrap();

        let runtime_allowed = capabilities(&[
            Capability::ReadOnly,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ]);
        let effective = admission.intersect_runtime(&runtime_allowed);
        assert_eq!(effective.as_set(), &capabilities(&[Capability::ReadOnly]));
        assert!(!effective.contains(Capability::CodeExecuting));
        assert!(!effective.contains(Capability::TrustMutating));
        assert!(!effective.contains(Capability::IrreversibleExternal));
    }

    #[test]
    fn admission_is_not_a_grant_when_runtime_allows_nothing() {
        let candidate = manifest(&[Capability::ReadOnly], None);
        let admission = ManifestAdmissionPolicy::new(
            StrategySlot::router(),
            capabilities(&[Capability::ReadOnly]),
        )
        .assess(&candidate)
        .unwrap();

        assert!(admission.intersect_runtime(&BTreeSet::new()).is_empty());
    }
}
