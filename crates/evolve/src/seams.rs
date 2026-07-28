//! The two cross-owner seams this crate declares as **declared, not implemented**.
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
//! There is no blanket implementation and no default body anywhere in this module, and no
//! not-implemented error variant exists for one to return.
//!
//! A second review challenged that, on the ground that the issue text asked for stub bodies so both
//! sides could start. The premise turned out to be false in this language, and it was settled by
//! building it rather than by arguing: a probe crate outside this workspace compiled generic
//! callers, `&dyn` callers, and a composition root holding these seams as trait objects, with zero
//! implementors in existence. **Rust trait bounds require no inhabitants.** A stub therefore
//! unblocks nobody, while a shipped `Stub` would be a public, importable, permanently-compiling
//! type that satisfies the bound and whose removal before release nothing enforces.
//!
//! "Declared but not implemented" is a property of *absence*, so it is proved mechanically over the
//! tree — `core-xtask boundaries check` fails if any `impl` of these traits appears outside a test
//! target — and never by a test asserting that a function returns the error it was written to
//! return.
//!
//! # What proves these seams are implementable
//!
//! `crates/evolve/tests/seam_satisfiability.rs`, and deliberately not a `#[cfg(test)]` module here.
//! An in-crate test module compiles at crate-private visibility, so it can reach names an outside
//! implementor cannot, and it would prove only that *this* crate can satisfy the seam — the one
//! crate that must never implement it. An integration test links this crate exactly as an external
//! consumer does.
//!
//! That test also returns a **non-empty** payload from at least one double per seam. `Ok(None)`
//! constructs nothing, so it certifies nothing about whether the types in a signature can actually
//! be named and built from outside. The distinction is not hypothetical: it is what exposed
//! [`crate::TrajectoryEnvelope`]'s `run_id` and `tenant_id` being unnameable outside this crate,
//! which is why [`crate::RunId`] and [`crate::TenantId`] are now re-exported.
//!
//! # Where the third seam went
//!
//! Bundle resolution used to be declared here, over this crate's own `PolicyBundle` and
//! `StrategySlot`. That made it unimplementable by its only intended consumer: naming the trait
//! would have forced `crates/agents` to depend on `core-evolve`, which is the one dependency edge
//! the runtime must never grow. It now lives in `core_protocol::bundle`, the crate both sides
//! already depend on, and `PolicyBundle::resolve` is the producing half.

use crate::{BaseModelId, ContractError, SignedHeldOutEvaluation, TrajectoryEnvelope};

/// record -> evolve: project a recorded run into a learning trajectory.
///
/// The recorder owns the run; evolution owns what a trajectory means. This seam is the only way
/// the second gets the first.
///
/// Implementing this means constructing a [`TrajectoryEnvelope`], whose `run_id` and `tenant_id`
/// are `core-protocol` types. They are re-exported from this crate ([`crate::RunId`],
/// [`crate::TenantId`]) so an implementor needs no dependency beyond `core-evolve`. An earlier shape
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
/// It carries a [`SignedHeldOutEvaluation`]: an attestation only a holder of an
/// [`crate::EvaluatorTrustAnchor`] key can mint, and one that [`crate::PromotionAuthority`]
/// re-verifies before admitting any candidate and again on every journal replay.
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
/// One honest residual gap, since a partial guarantee stated as a whole one is exactly how the first
/// version of this comment went wrong: evaluator/promoter disjointness is checked by identity
/// *string*, not by key material, so one party registered twice under two ids with the same key
/// defeats it and nothing detects that today.
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
