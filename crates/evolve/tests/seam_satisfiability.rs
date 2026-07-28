//! Proof that the two declared-not-implemented seams can actually be implemented, from outside.
//!
//! # Why this file exists and why it is not a `#[cfg(test)]` module
//!
//! An in-crate test module compiles at crate-private visibility. It can reach privately imported
//! names, private modules, and `pub(crate)` items that no outside implementor can touch, so it would
//! prove only that `core-evolve` itself can satisfy these seams — the one crate that must never
//! implement them. An integration test links this crate exactly as an external consumer does.
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
    HeldOutEvidenceBridge, PolicyBundle, PolicyRef, RewardVector, RunId, SignedHeldOutEvaluation,
    StrategySlot, TenantId, TrainingConsent, TrajectoryEnvelope, TrajectoryProjection,
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
    // Dynamic dispatch, and a composition root holding both seams as trait objects. Neither needs
    // an inhabitant to compile, which is why no stub is shipped.
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
