//! Frozen cross-owner seam contracts with their first bounded production implementations.
//!
//! [`crate::RecordedRunProjector`] implements [`TrajectoryProjection`], and
//! [`crate::HeldOutEvidenceStore`] implements [`HeldOutEvidenceBridge`]. The traits remain the
//! stable boundary: callers can substitute another implementation without depending on those
//! concrete types. There are no blanket implementations, default bodies, or not-implemented
//! variants.
//!
//! The repository gate treats seam implementation as an explicit state transition. A seam still
//! listed in the gate must have no reachable product implementation; removing it from that list
//! requires a reachable implementation in the same candidate. This prevents both a premature
//! implementation and a registry-only removal.
//!
//! `crates/evolve/tests/seam_satisfiability.rs` remains an integration test so it also proves an
//! external crate holding only `iteron-evolve` can implement the contracts. Its doubles return
//! non-empty payloads, which verifies that every type in these signatures is publicly nameable.
//!
//! # Where the third seam went
//!
//! Bundle resolution used to be declared here, over this crate's own `PolicyBundle` and
//! `StrategySlot`. That made it unimplementable by its only intended consumer: naming the trait
//! would have forced `crates/agents` to depend on `iteron-evolve`, which is the one dependency edge
//! the runtime must never grow. It now lives in `iteron_protocol::bundle`, the crate both sides
//! already depend on, and `PolicyBundle::resolve` is the producing half.

use crate::{BaseModelId, ContractError, SignedHeldOutEvaluation, TrajectoryEnvelope};

/// record -> evolve: project a recorded run into a learning trajectory.
///
/// The recorder owns the run; evolution owns what a trajectory means. This seam is the only way
/// the second gets the first.
///
/// Implementing this means constructing a [`TrajectoryEnvelope`], whose `run_id` and `tenant_id`
/// are `iteron-protocol` types. They are re-exported from this crate ([`crate::RunId`],
/// [`crate::TenantId`]) so an implementor needs no dependency beyond `iteron-evolve`. An earlier shape
/// did not re-export them, and the seam was in fact unimplementable from outside.
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

/// eval -> evolve: carry independently produced, independently signed held-out evidence.
///
/// # What this seam guarantees, and what it does not
///
/// It carries a [`SignedHeldOutEvaluation`]: an attestation that [`crate::PromotionAuthority`]
/// re-verifies before admitting any candidate, and again on every journal replay.
///
/// Note the precise claim, because the loose version of it was wrong: **anyone can mint one.**
/// `PromotionAuthorityKey::new` and `IndependentEvaluator::new` are public, so a crate holding only
/// `iteron-evolve` can produce a well-formed `SignedHeldOutEvaluation` with a key of its own choosing —
/// a review did exactly that. What only a key-holder can produce is an attestation whose HMAC
/// *verifies against an anchor the authority configured*. The distinction is the whole guarantee.
///
/// **This trait authenticates nothing on its own.** An implementor may return whatever it likes, and
/// anyone can construct the *bytes* of a `SignedHeldOutEvaluation`; only a key-holder can construct
/// bytes whose HMAC verifies. The separation of duties lives downstream: in
/// `PromotionAuthority::verify_held_out`, which resolves the evaluator id against the configured
/// anchors, compares the signature in constant time, binds the report to the candidate identity and
/// base model, and refuses an evaluator id equal to the candidate policy id or the bundle id; and in
/// `PromotionAuthority::open`, which refuses at construction any configuration where an evaluator id
/// is also a promotion party id.
///
/// This comment previously claimed that evolution "cannot manufacture" the evidence this seam
/// carries. That was false. The seam returned a plain struct with public fields and no attester, so
/// a struct literal was all it took. The guarantee is real, but it belongs to the verification path
/// and to the key — never to a trait signature — and the correction is recorded here so the next
/// reader does not repeat the claim.
///
/// `PromotionAuthority::open` checks both identity strings and key material across the evaluator and
/// promotion anchor sets. Reusing the same identity or the same key under another id is therefore
/// rejected. Organizational ownership separation beyond those cryptographic identities remains a
/// deployment-configuration obligation.
///
/// Deliberately absent: any scoring, thresholding or verdict. Those live on the evolution side,
/// downstream of this call, so that changing a promotion rule never changes the seam.
pub trait HeldOutEvidenceBridge {
    /// Fetch the attestation recorded for a candidate under a specific base model.
    ///
    /// `base_model` is required rather than inferred, because evidence gathered against one set
    /// of weights says nothing about another. Passing an inadmissible identity - the migration
    /// sentinel, for instance - must be refused rather than treated as a wildcard.
    ///
    /// The base model is inside the signed payload (`HeldOutEvaluation::base_model`), so this
    /// argument is checkable against the returned report rather than decorative.
    fn evidence_for(
        &self,
        policy_digest: &str,
        base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError>;
}
