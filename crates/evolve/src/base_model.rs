//! `BaseModelId` — the frozen identity of the base model a policy was learned against.
//!
//! # The contradiction this type resolves
//!
//! Issue #26 asks for two things that read as incompatible: `base_model` must be **required and
//! validated** on `PolicyManifest`, and every document migrated from schema 2 must carry a
//! **reserved sentinel**, because a v2 document simply does not record which model produced it.
//! An adversarial review flagged this as self-voiding: a required-and-validated field whose
//! migration path mints a placeholder is not required in any useful sense.
//!
//! It is only self-voiding if "valid" is one predicate. It is two:
//!
//! - [`BaseModelId::validate`] answers **is this well-formed** — bounds, encoding, no empty parts.
//!   The sentinel passes, because a migrated document is a legitimate document.
//! - [`BaseModelId::is_admissible`] answers **may an authority decision rest on this** — and the
//!   sentinel is permanently, deliberately `false`.
//!
//! So a v2 manifest still loads, still validates, and still round-trips; it simply cannot be
//! promoted, transferred across models, or used as held-out evidence, because nothing about it
//! records what it was trained against. That is the honest reading of a document that never
//! carried the field.
//!
//! # Where the second predicate is actually enforced
//!
//! An adversarial review of this freeze found the first draft of this paragraph claiming the split
//! was "enforced by the type rather than remembered by a caller". It was not: `is_admissible` had
//! a single non-test caller, inside a trait with no implementations, while the offline producer
//! hard-coded [`BaseModelId::unspecified`] onto every candidate it emitted. A predicate nothing
//! calls is a comment.
//!
//! It is now called in the two places that matter, and the list is kept here so the claim stays
//! checkable:
//!
//! - `EvolutionVerifier::verify_candidate_inputs` refuses an inadmissible identity. Every
//!   candidate crosses it before any promotion decision, so that is the chokepoint.
//! - `OfflineRuleSearchSpec::new` refuses one at production time. A candidate minted now knows
//!   what it searched against; only a document recovered from schema 2 has an excuse.
//! - `HeldOutEvidence::validate` refuses one, because evidence gathered against unknown weights
//!   attests nothing about any particular model.

use crate::ContractError;
use serde::{Deserialize, Serialize};

/// Upper bound on each component of a base-model identity.
pub const MAX_BASE_MODEL_PART_BYTES: usize = 128;

/// The reserved family used by [`BaseModelId::unspecified`]. It is not a valid vendor family and
/// never will be: the leading `!` cannot appear in a real family, which is what makes the
/// sentinel unforgeable by an ordinary document.
pub const UNSPECIFIED_FAMILY: &str = "!unspecified";

/// Which frozen base model a policy was learned against.
///
/// All three parts are required. `model_digest` is what makes the identity verifiable rather than
/// declarative: two vendors may reuse a family and an id, but a digest pins the weights.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BaseModelId {
    /// Vendor/family, e.g. `anthropic/claude`.
    pub model_family: String,
    /// The vendor's identifier for the specific model.
    pub model_id: String,
    /// Digest pinning the weights this policy was learned against.
    pub model_digest: String,
}

impl BaseModelId {
    /// The reserved identity minted by the schema 2 -> 3 migration.
    ///
    /// A document carrying this is well-formed but **never admissible**: schema 2 did not record
    /// a base model, so there is nothing to recover and nothing to trust.
    pub fn unspecified() -> Self {
        Self {
            model_family: UNSPECIFIED_FAMILY.to_owned(),
            model_id: String::new(),
            model_digest: String::new(),
        }
    }

    /// Is this the migration sentinel?
    pub fn is_unspecified(&self) -> bool {
        self.model_family == UNSPECIFIED_FAMILY
    }

    /// Is this well-formed? The sentinel passes: a migrated document is still a document.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.is_unspecified() {
            // The sentinel's shape is fixed. Anything else wearing the reserved family is a forgery.
            return if self.model_id.is_empty() && self.model_digest.is_empty() {
                Ok(())
            } else {
                Err(ContractError::InvalidBaseModel(
                    "the reserved unspecified family must carry no id and no digest",
                ))
            };
        }
        for (label, part) in [
            ("model_family", &self.model_family),
            ("model_id", &self.model_id),
            ("model_digest", &self.model_digest),
        ] {
            if part.is_empty() {
                return Err(ContractError::InvalidBaseModel(match label {
                    "model_family" => "base model family must not be empty",
                    "model_id" => "base model id must not be empty",
                    _ => "base model digest must not be empty",
                }));
            }
            if part.len() > MAX_BASE_MODEL_PART_BYTES {
                return Err(ContractError::InvalidBaseModel(
                    "base model component exceeds its declared bound",
                ));
            }
        }
        Ok(())
    }

    /// May an authority decision — promotion, cross-model transfer, held-out evidence — rest on
    /// this identity?
    ///
    /// Well-formedness is not enough. The sentinel is well-formed and permanently inadmissible.
    pub fn is_admissible(&self) -> bool {
        !self.is_unspecified() && self.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{BaseModelId, UNSPECIFIED_FAMILY};

    fn real() -> BaseModelId {
        BaseModelId {
            model_family: "anthropic/claude".into(),
            model_id: "claude-opus-5".into(),
            model_digest: "a".repeat(64),
        }
    }

    #[test]
    fn the_migration_sentinel_is_well_formed_but_never_admissible() {
        let sentinel = BaseModelId::unspecified();
        assert!(
            sentinel.validate().is_ok(),
            "a migrated v2 document is a legitimate document and must still load"
        );
        assert!(
            !sentinel.is_admissible(),
            "but nothing records what it was trained against, so no authority may rest on it"
        );
        assert!(sentinel.is_unspecified());
    }

    #[test]
    fn a_real_identity_is_both_well_formed_and_admissible() {
        assert!(real().validate().is_ok());
        assert!(real().is_admissible());
        assert!(!real().is_unspecified());
    }

    #[test]
    fn the_reserved_family_cannot_be_dressed_up_as_a_real_identity() {
        // An attacker-supplied document claiming the reserved family with real-looking parts
        // must not become admissible by filling them in.
        let forged = BaseModelId {
            model_family: UNSPECIFIED_FAMILY.into(),
            model_id: "claude-opus-5".into(),
            model_digest: "a".repeat(64),
        };
        assert!(forged.validate().is_err());
        assert!(!forged.is_admissible());
    }

    #[test]
    fn every_component_of_a_real_identity_is_required() {
        for mutate in [
            |m: &mut BaseModelId| m.model_family.clear(),
            |m: &mut BaseModelId| m.model_id.clear(),
            |m: &mut BaseModelId| m.model_digest.clear(),
        ] {
            let mut candidate = real();
            mutate(&mut candidate);
            assert!(candidate.validate().is_err());
            assert!(!candidate.is_admissible());
        }
    }

    #[test]
    fn components_are_bounded() {
        let mut oversized = real();
        oversized.model_id = "x".repeat(129);
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn the_wire_form_round_trips_exactly() {
        for candidate in [real(), BaseModelId::unspecified()] {
            let json = serde_json::to_string(&candidate).expect("serialises");
            let back: BaseModelId = serde_json::from_str(&json).expect("round-trips");
            assert_eq!(back, candidate);
            assert_eq!(serde_json::to_string(&back).expect("re-serialises"), json);
        }
    }
}

/// The other half of #26's fail-closed sweep: an open vocabulary that degrades on read but is
/// refused on use. These live here rather than beside the enums because the two halves are one
/// argument — a document may be *readable* by a build that does not understand it, and must still
/// never be *runnable* by that build.
#[cfg(test)]
mod vocabulary_tests {
    use crate::{
        ArtifactKind, BaseModelId, ContractError, EVOLUTION_SCHEMA_VERSION, EvolutionMethod,
        PolicyManifest, PolicyRef, ProtocolRange, StrategySlot,
    };
    use std::collections::BTreeSet;

    fn manifest() -> PolicyManifest {
        let digest = "d".repeat(64);
        PolicyManifest {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            policy: PolicyRef {
                slot: StrategySlot::router(),
                policy_id: "candidate".into(),
                version: "1.0.0".into(),
                digest: digest.clone(),
            },
            artifact_kind: ArtifactKind::Rules,
            artifact_locator: "registry://candidate@1.0.0".into(),
            parent: None,
            method: EvolutionMethod::HandAuthored,
            protocol: ProtocolRange { min: 1, max: 1 },
            required_capabilities: BTreeSet::new(),
            training_dataset_digest: None,
            evaluation_suite_digest: digest,
            base_model: BaseModelId {
                model_family: "anthropic/claude".into(),
                model_id: "claude-opus-5".into(),
                model_digest: "e".repeat(64),
            },
        }
    }

    #[test]
    fn the_baseline_manifest_this_module_mutates_is_itself_valid() {
        // Otherwise every assertion below could be passing for the wrong reason.
        assert!(manifest().validate().is_ok());
    }

    #[test]
    fn an_unrecognised_vocabulary_member_decodes_to_the_sentinel_rather_than_failing_the_parse() {
        let kind: ArtifactKind =
            serde_json::from_value(serde_json::json!("quantum_lattice")).expect("degrades");
        assert_eq!(kind, ArtifactKind::Unknown);

        let method: EvolutionMethod =
            serde_json::from_value(serde_json::json!("telepathy")).expect("degrades");
        assert_eq!(method, EvolutionMethod::Unknown);
    }

    #[test]
    fn but_a_manifest_carrying_one_is_refused_rather_than_loaded_optimistically() {
        // Degrading the parse is not the same as accepting the document. A newer producer's
        // artifact kind is readable; it is not runnable, because this build has no idea what it
        // is. That distinction is the whole point of fail-closed.
        for mutate in [
            (|m: &mut PolicyManifest| m.artifact_kind = ArtifactKind::Unknown)
                as fn(&mut PolicyManifest),
            |m: &mut PolicyManifest| m.method = EvolutionMethod::Unknown,
        ] {
            let mut candidate = manifest();
            mutate(&mut candidate);
            assert!(
                matches!(
                    candidate.validate(),
                    Err(ContractError::UnrecognisedVocabulary(_))
                ),
                "an unknown vocabulary member must be refused, not silently accepted"
            );
        }
    }

    #[test]
    fn the_refusal_is_typed_rather_than_collapsed_into_a_generic_shape_error() {
        // A caller has to be able to tell "this build is too old for this document" apart from
        // "this document is malformed". Only the first is fixed by upgrading.
        let mut candidate = manifest();
        candidate.artifact_kind = ArtifactKind::Unknown;
        match candidate.validate() {
            Err(ContractError::UnrecognisedVocabulary(what)) => {
                assert!(
                    what.contains("artifact kind"),
                    "the error must name the field"
                );
            }
            other => panic!("expected UnrecognisedVocabulary, got {other:?}"),
        }
    }

    #[test]
    fn deployment_stage_hard_fails_on_an_unrecognised_member_instead_of_degrading() {
        // This pins the exemption recorded on `DeploymentStage`. The two enums above describe
        // what a *producer* made and may legitimately be extended by a newer peer; a stage is
        // this build's own promotion state, so an unrecognised one is a corrupt or forged
        // record, not forward compatibility. If someone later gives `DeploymentStage` an
        // `#[serde(other)]` variant, this test fails and they have to argue with the doc comment.
        let decoded: Result<crate::DeploymentStage, _> =
            serde_json::from_value(serde_json::json!("quantum_lattice"));
        assert!(
            decoded.is_err(),
            "an unrecognised deployment stage must be a decode error, never a sentinel"
        );
    }
}
