//! The three cross-owner seams #26 freezes as **declared, not implemented**.
//!
//! Each of these is a boundary between two workstreams that will be built by different people on
//! different weeks. Declaring the signature now is what lets both sides start; implementing it now
//! would be guessing at the half that has not been written.
//!
//! # Why these are traits with no implementation and no default body
//!
//! An adversarial review of this freeze made a specific charge worth answering here: *"a trait
//! designed with no live caller is a trait designed from imagination."* That is true, and the
//! mitigation is not to pretend otherwise. So each seam below is kept as narrow as it can
//! possibly be — it takes what the producing side already has and returns what the consuming side
//! already needs, in types that already exist — and each one records what is deliberately absent.
//! A seam that carries nothing speculative is a seam that can be widened later without breaking.
//!
//! There is no blanket implementation and no default body anywhere in this module. An unimplemented
//! seam must fail to compile at its first real use, not silently return an empty answer.

use crate::{BaseModelId, ContractError, PolicyBundle, StrategySlot, TrajectoryEnvelope};

/// record -> evolve: project a recorded run into a learning trajectory.
///
/// The recorder owns the run; evolution owns what a trajectory means. This seam is the only way
/// the second gets the first.
///
/// Deliberately absent: any notion of *which* runs are eligible. Selection is a policy decision
/// that belongs to whoever implements this, not to the seam.
pub trait TrajectoryProjection {
    /// Project one recorded run, identified by its rollout digest, into a trajectory.
    ///
    /// Returns `Ok(None)` when the run exists but yields nothing learnable — an empty result is a
    /// legitimate answer and must be distinguishable from a failure.
    fn project(&self, rollout_digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError>;
}

/// eval -> evolve: carry independently produced held-out evidence across the boundary.
///
/// The evaluator must not be the promoter. This seam is the shape of that separation: evolution
/// asks for evidence and receives it, and cannot manufacture it.
///
/// Deliberately absent: any scoring, thresholding or verdict. Those live on the evolution side,
/// downstream of this call, so that changing a promotion rule never changes the seam.
pub trait HeldOutEvidenceBridge {
    /// Fetch the held-out evidence recorded for a candidate under a specific base model.
    ///
    /// `base_model` is required rather than inferred, because evidence gathered against one set
    /// of weights says nothing about another. Passing an inadmissible identity - the migration
    /// sentinel, for instance - must be refused rather than treated as a wildcard.
    fn evidence_for(
        &self,
        policy_digest: &str,
        base_model: &BaseModelId,
    ) -> Result<Option<HeldOutEvidence>, ContractError>;
}

/// What a held-out evaluation attests. Carried across the eval -> evolve seam.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldOutEvidence {
    /// The candidate this evidence is about.
    pub policy_digest: String,
    /// The base model it was gathered against.
    pub base_model: BaseModelId,
    /// Digest of the held-out partition used, so train/eval overlap is checkable by a third party.
    pub held_out_digest: String,
    /// Number of items scored. Zero is a legitimate value and is not the same as absent.
    pub scored: u32,
    /// Number that passed.
    pub passed: u32,
}

impl HeldOutEvidence {
    /// Validate encoding and internal consistency. Pure; states no opinion about whether the
    /// evidence is *good*, which is a promotion decision, not a shape question.
    pub fn validate(&self) -> Result<(), ContractError> {
        crate::validate_digest(&self.policy_digest)?;
        crate::validate_digest(&self.held_out_digest)?;
        self.base_model.validate()?;
        if !self.base_model.is_admissible() {
            return Err(ContractError::InvalidBaseModel(
                "held-out evidence cannot rest on an inadmissible base model identity",
            ));
        }
        if self.passed > self.scored {
            return Err(ContractError::InvalidBaseModel(
                "held-out evidence reports more passes than items scored",
            ));
        }
        Ok(())
    }
}

/// evolve -> agents: resolve the active policy bundle at boot, read only.
///
/// The composition root asks once, at startup, and gets an immutable answer. Nothing downstream
/// can swap a bundle mid-run, which is what makes a run's strategy set reproducible.
///
/// Deliberately absent: any way to *set* the active bundle. Promotion is human-gated and lives
/// entirely on the evolution side; this seam is the read half and only the read half.
pub trait PolicyBundleResolver {
    /// The bundle in force for this process, if any.
    ///
    /// `Ok(None)` means no bundle is active and the built-in strategies apply — a normal state,
    /// not an error.
    fn active_bundle(&self) -> Result<Option<PolicyBundle>, ContractError>;

    /// Whether a given slot is governed by the active bundle.
    fn governs(&self, slot: &StrategySlot) -> Result<bool, ContractError>;
}

#[cfg(test)]
mod tests {
    use super::{
        HeldOutEvidence, HeldOutEvidenceBridge, PolicyBundleResolver, TrajectoryProjection,
    };
    use crate::{BaseModelId, ContractError, PolicyBundle, StrategySlot, TrajectoryEnvelope};

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn real_model() -> BaseModelId {
        BaseModelId {
            model_family: "anthropic/claude".into(),
            model_id: "claude-opus-5".into(),
            model_digest: digest('b'),
        }
    }

    // Every seam is exercised through a test double. This is what stops the traits being
    // unimplementable in principle: if a double cannot satisfy the signature, neither can a
    // real implementation.
    struct NoRuns;
    impl TrajectoryProjection for NoRuns {
        fn project(&self, _d: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
            Ok(None)
        }
    }

    struct NoEvidence;
    impl HeldOutEvidenceBridge for NoEvidence {
        fn evidence_for(
            &self,
            _p: &str,
            _b: &BaseModelId,
        ) -> Result<Option<HeldOutEvidence>, ContractError> {
            Ok(None)
        }
    }

    struct NoBundle;
    impl PolicyBundleResolver for NoBundle {
        fn active_bundle(&self) -> Result<Option<PolicyBundle>, ContractError> {
            Ok(None)
        }
        fn governs(&self, _slot: &StrategySlot) -> Result<bool, ContractError> {
            Ok(false)
        }
    }

    #[test]
    fn every_seam_is_satisfiable_and_distinguishes_empty_from_failure() {
        assert!(matches!(NoRuns.project(&digest('a')), Ok(None)));
        assert!(matches!(
            NoEvidence.evidence_for(&digest('a'), &real_model()),
            Ok(None)
        ));
        assert!(matches!(NoBundle.active_bundle(), Ok(None)));
        assert!(matches!(
            NoBundle.governs(&StrategySlot::router()),
            Ok(false)
        ));
    }

    #[test]
    fn held_out_evidence_refuses_to_rest_on_the_migration_sentinel() {
        let evidence = HeldOutEvidence {
            policy_digest: digest('a'),
            base_model: BaseModelId::unspecified(),
            held_out_digest: digest('c'),
            scored: 10,
            passed: 7,
        };
        assert!(
            evidence.validate().is_err(),
            "a document that never recorded its base model cannot attest anything about one"
        );
    }

    #[test]
    fn held_out_evidence_rejects_more_passes_than_items() {
        let evidence = HeldOutEvidence {
            policy_digest: digest('a'),
            base_model: real_model(),
            held_out_digest: digest('c'),
            scored: 3,
            passed: 4,
        };
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn zero_scored_is_legitimate_and_not_an_error() {
        let evidence = HeldOutEvidence {
            policy_digest: digest('a'),
            base_model: real_model(),
            held_out_digest: digest('c'),
            scored: 0,
            passed: 0,
        };
        assert!(evidence.validate().is_ok());
    }
}
