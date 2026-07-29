//! Proof that the two frozen seam contracts remain implementable from outside.
//!
//! # Why this file exists and why it is not a `#[cfg(test)]` module
//!
//! An in-crate test module compiles at crate-private visibility. It can reach privately imported
//! names, private modules, and `pub(crate)` items that no outside implementor can touch, so it would
//! prove only that `core-evolve` itself can satisfy these seams. An integration test links this
//! crate exactly as an external consumer does, independently of the bounded in-crate
//! implementations.
//!
//! That distinction is not theoretical. The first version of these seams was proved "satisfiable" by
//! in-crate doubles that all returned `Ok(None)`. `Ok(None)` constructs no payload, so it certified
//! nothing about whether the types in the signatures could be named and built from outside — and in
//! fact `TrajectoryEnvelope` could not be, because `run_id: RunId` and `tenant_id: TenantId` were
//! privately imported and never re-exported (E0603). The seam advertised a cost it did not charge
//! until an implementor hit a compile error.
//!
//! # ONE DEPENDENCY, AND THAT IS THE POINT
//!
//! Everything below is reached through `core_evolve::` and nothing else. That is the property under
//! test: a crate that depends on `core-evolve` alone must be able to implement these seams. A test
//! under `crates/evolve/tests/` inherits the crate's own `[dependencies]`, so `core_protocol` would
//! compile here even though an outside implementor may not have it — which means position alone
//! cannot prove this. `core-xtask boundaries check` therefore asserts mechanically that this file
//! names no other internal crate. **Do not add an import here to make something compile.** If a type
//! in a seam signature is not reachable through `core_evolve::`, that is the seam being wrong, not
//! this test.

use core_evolve::{
    BaseModelId, ContractError, DataClass, DataGovernance, EVOLUTION_SCHEMA_VERSION,
    HeldOutEvaluation, HeldOutEvidenceBridge, IndependentEvaluator, Interval, PolicyBundle,
    PolicyRef, PromotionAuthorityKey, PromotionEvidence, RewardVector, RunId,
    SignedHeldOutEvaluation, StrategySlot, TenantId, TrainingConsent, TrajectoryEnvelope,
    TrajectoryProjection, VerifiedCandidateInputs,
};

fn digest(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn real_base_model() -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-5".into(),
        model_digest: digest('b'),
    }
}

/// A fully populated envelope, built by struct literal from outside the crate.
///
/// This is the assertion that matters. Every type named here has to be publicly reachable through
/// `core_evolve::`, and an empty answer would have exercised none of them.
fn a_real_trajectory() -> TrajectoryEnvelope {
    TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId("run-2026-07-28-0001".into()),
        tenant_id: TenantId("acme".into()),
        task_id: "swe-bench/astropy-12907".into(),
        domain: "software-engineering".into(),
        environment_digest: digest('c'),
        bundle: PolicyBundle {
            bundle_id: "acme-2026-07".into(),
            digest: digest('d'),
            policies: vec![PolicyRef {
                slot: StrategySlot::new("core/router").expect("a valid slot"),
                policy_id: "acme.router".into(),
                version: "1.4.0".into(),
                digest: digest('e'),
            }],
            rollback_to: None,
        },
        decisions: Vec::new(),
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.42,
            wall_time_ms: 91_000,
            human_acceptance: None,
            domain: Default::default(),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: None,
            contains_secret_material: false,
            retention_policy: "standard-30d".into(),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// record -> evolve
// ---------------------------------------------------------------------------------------------

/// Finds the run, and it yields nothing learnable. A legitimate answer, not a failure.
struct NoLearnableRuns;
impl TrajectoryProjection for NoLearnableRuns {
    fn project(&self, _digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        Ok(None)
    }
}

/// Cannot answer at all. Must be distinguishable from the above.
struct UnreadableRuns;
impl TrajectoryProjection for UnreadableRuns {
    fn project(&self, _digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        Err(ContractError::InvalidDigest)
    }
}

/// Returns a real, fully populated trajectory. This is the double that proves the signature.
struct RealProjection;
impl TrajectoryProjection for RealProjection {
    fn project(&self, _digest: &str) -> Result<Option<TrajectoryEnvelope>, ContractError> {
        Ok(Some(a_real_trajectory()))
    }
}

// ---------------------------------------------------------------------------------------------
// eval -> evolve
// ---------------------------------------------------------------------------------------------

/// No evidence has been recorded for this candidate yet.
struct NoEvidence;
impl HeldOutEvidenceBridge for NoEvidence {
    fn evidence_for(
        &self,
        _policy_digest: &str,
        _base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError> {
        Ok(None)
    }
}

/// The evidence store is unreachable. Distinct from "there is none".
struct UnreachableEvidence;
impl HeldOutEvidenceBridge for UnreachableEvidence {
    fn evidence_for(
        &self,
        _policy_digest: &str,
        _base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError> {
        Err(ContractError::InvalidDigest)
    }
}

/// Returns a REAL, HMAC-signed attestation. This is the double that proves the signature.
///
/// It exists because an adversarial review caught the first version of this file returning only
/// `Ok(None)` and `Err` for this seam — the exact proof-of-nothing the whole exercise was written to
/// eliminate — while the module doc above claimed a non-empty payload for every seam. `Ok(None)`
/// touches no payload type, so it certified nothing about whether `SignedHeldOutEvaluation` could be
/// obtained at all from outside this crate.
///
/// Minting one here is not a hole in the separation of duties, but the reason is narrower than it
/// first looks. `pub(crate)` blocks a struct literal; it does NOT block `serde_json::from_value`,
/// because the derived `Deserialize` is generated inside `core-evolve` — a review reconstituted one
/// from outside with an attacker-chosen evaluator id and signature. This double goes through the
/// key-holder path because that is what an honest evaluator crate does, and what it proves is that
/// the public surface is sufficient for one. It proves nothing about authenticity, which only
/// `PromotionAuthority` decides. What that proves is that a real evaluator crate can do
/// its job through the public surface — and what it does NOT prove is authenticity, which only
/// `PromotionAuthority` can decide by resolving the evaluator id against its configured anchors.
struct RealEvidence;

impl RealEvidence {
    fn sign(base_model: &BaseModelId) -> SignedHeldOutEvaluation {
        let candidate = PolicyRef {
            slot: StrategySlot::new("core/router").expect("a valid slot"),
            policy_id: "acme.router".into(),
            version: "2.0.0".into(),
            digest: digest('e'),
        };
        let baseline = PolicyRef {
            policy_id: "acme.router".into(),
            version: "1.0.0".into(),
            ..candidate.clone()
        };
        let verified = VerifiedCandidateInputs {
            artifact_digest: digest('e'),
            training_dataset_digest: None,
            evaluation_suite_digest: digest('f'),
            base_model: base_model.clone(),
        };
        let flat = Interval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        };
        let evidence = PromotionEvidence {
            base_model: base_model.clone(),
            baseline,
            candidate: candidate.clone(),
            paired_tasks: 128,
            task_score_delta: Interval {
                estimate: 0.04,
                lower: 0.01,
                upper: 0.07,
            },
            cost_delta_usd: flat,
            latency_delta_ms: flat,
            candidate_safety_violations: 0,
            candidate_policy_violations: 0,
            train_eval_overlap: false,
            replay_equivalence_passed: true,
            sandbox_suite_passed: true,
            invariant_suites: Default::default(),
        };
        let report = HeldOutEvaluation::new(candidate, &verified, evidence)
            .expect("a well-formed held-out evaluation");
        let key = PromotionAuthorityKey::new(vec![7u8; 32]).expect("a valid key");
        IndependentEvaluator::new("acme-evaluator", key)
            .expect("a valid evaluator")
            .sign_held_out(report)
            .expect("signs")
    }
}

impl HeldOutEvidenceBridge for RealEvidence {
    fn evidence_for(
        &self,
        _policy_digest: &str,
        base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError> {
        Ok(Some(Self::sign(base_model)))
    }
}

/// Refuses the migration sentinel rather than treating it as a wildcard.
///
/// This is the behaviour the seam's doc comment requires of an implementor, written here as an
/// example that compiles rather than as prose that cannot be checked.
struct SentinelRefusingEvidence;
impl HeldOutEvidenceBridge for SentinelRefusingEvidence {
    fn evidence_for(
        &self,
        _policy_digest: &str,
        base_model: &BaseModelId,
    ) -> Result<Option<SignedHeldOutEvaluation>, ContractError> {
        if !base_model.is_admissible() {
            return Err(ContractError::InvalidBaseModel(
                "held-out evidence cannot be fetched for an inadmissible base model identity",
            ));
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------------------------

#[test]
fn a_crate_holding_only_core_evolve_can_implement_every_seam() {
    // Generic dispatch.
    fn ingest<P: TrajectoryProjection>(projection: &P) -> Option<TrajectoryEnvelope> {
        projection.project(&digest('a')).expect("projection ok")
    }
    // Dynamic dispatch, and a composition root holding both seams as trait objects.
    struct Root<'a> {
        runs: &'a dyn TrajectoryProjection,
        evidence: &'a dyn HeldOutEvidenceBridge,
    }
    let root = Root {
        runs: &RealProjection,
        evidence: &NoEvidence,
    };

    assert!(ingest(&NoLearnableRuns).is_none());
    assert!(ingest(&RealProjection).is_some());
    assert!(root.runs.project(&digest('a')).expect("ok").is_some());
    assert!(
        root.evidence
            .evidence_for(&digest('a'), &real_base_model())
            .expect("ok")
            .is_none()
    );
}

#[test]
fn a_non_empty_payload_is_constructible_from_outside_this_crate() {
    // The assertion the original `Ok(None)` doubles could not make. If any type in
    // `TrajectoryEnvelope` stops being publicly reachable, this stops compiling - which is the
    // point, and is exactly how `RunId`/`TenantId` were found to be unreachable.
    let projected = RealProjection
        .project(&digest('a'))
        .expect("projection ok")
        .expect("a real trajectory");
    assert_eq!(projected.schema_version, EVOLUTION_SCHEMA_VERSION);
    assert_eq!(projected.run_id.0, "run-2026-07-28-0001");
    assert_eq!(projected.tenant_id.0, "acme");
    projected
        .validate()
        .expect("a trajectory built through the public surface must be valid");

    // The second seam, which the first version of this file never exercised with a payload at all.
    // This also checks the property `HeldOutEvidenceBridge`'s doc comment promises an implementor:
    // that the `base_model` argument is checkable against the returned report. It was NOT, until an
    // accessor was added — the type was fully opaque outside this crate, so the doc described
    // something an external implementation could not do.
    let asked = real_base_model();
    let attested = RealEvidence
        .evidence_for(&digest('a'), &asked)
        .expect("bridge ok")
        .expect("a real attestation");
    assert_eq!(attested.evaluator_id(), "acme-evaluator");
    assert_eq!(
        attested.report().base_model(),
        &asked,
        "an implementor must be able to check the argument against the signed report"
    );
}

#[test]
fn a_caller_can_tell_a_legitimate_empty_answer_from_a_failure() {
    // `Ok(None)` and `Err(..)` mean opposite things and a caller must never collapse them. For the
    // projection seam, "no eligible runs" and "the recorder is unreadable" would otherwise be the
    // same number on a counter.
    assert!(matches!(NoLearnableRuns.project(&digest('a')), Ok(None)));
    assert!(UnreadableRuns.project(&digest('a')).is_err());

    assert!(matches!(
        NoEvidence.evidence_for(&digest('a'), &real_base_model()),
        Ok(None)
    ));
    assert!(
        UnreachableEvidence
            .evidence_for(&digest('a'), &real_base_model())
            .is_err()
    );
}

#[test]
fn the_evidence_seam_can_refuse_the_migration_sentinel_as_its_docs_require() {
    // A manifest migrated from schema 2 carries `BaseModelId::unspecified()`. Evidence gathered
    // against unknown weights attests nothing, so an implementor must be able to say so - and the
    // signature has to let it.
    assert!(matches!(
        SentinelRefusingEvidence.evidence_for(&digest('a'), &BaseModelId::unspecified()),
        Err(ContractError::InvalidBaseModel(_))
    ));
    assert!(matches!(
        SentinelRefusingEvidence.evidence_for(&digest('a'), &real_base_model()),
        Ok(None)
    ));
}
