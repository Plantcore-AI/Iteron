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
//! carried the field, and it is enforced by the type rather than remembered by a caller.

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
