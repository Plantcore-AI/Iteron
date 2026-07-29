//! Offline, local-only demonstration of two immutable boot snapshots over one promotion journal.

use crate::bundle_adapter::ActivePromotionBundleResolver;
use core_agents::{BootPolicySnapshot, ToolFilter, ToolPolicyBinding, ToolPolicyCatalog};
use core_evolve::{
    ArtifactKind, AttestationKey, BaseModelId, ConsentAwareDatasetRegistry, DeploymentBundle,
    DeploymentStage, EvaluationSuite, EvaluationTask, EvaluatorTrustAnchor, EvolutionMethod,
    EvolutionVerifier, HeldOutEvaluation, IndependentEvaluator, Interval, ManifestAdmissionPolicy,
    ParentCapabilityCeiling, PolicyBundle, PolicyManifest, PolicyRef, ProducerTrustAnchor,
    PromotionAuthority, PromotionAuthorityKey, PromotionAuthorizer, PromotionControlPolicy,
    PromotionEvidence, PromotionRequest, PromotionRole, PromotionTrustAnchor, ProtocolRange,
    SignedStageObservation, StageLimits, StageObservation, StagePermit, StrategySlot,
    TrainingAdmissionPolicy,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AUTHORITY_ID: &str = "policy-bundle-demo";
const PROMOTION_PARTY: &str = "release-owner";
const EVALUATOR_ID: &str = "independent-evaluator";
const SUITE_OWNER: &str = "held-out-owner";
const SECURITY_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DURABILITY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(crate) struct PolicyBundleDemoResult {
    pub(crate) baseline_tools: Vec<String>,
    pub(crate) promoted_tools: Vec<String>,
}

pub(crate) fn run() -> anyhow::Result<PolicyBundleDemoResult> {
    let root = scratch();
    let result = run_inner(&root);
    std::fs::remove_dir_all(&root).ok();
    result
}

fn run_inner(root: &Path) -> anyhow::Result<PolicyBundleDemoResult> {
    let baseline_policy = policy("baseline-tool-policy", b"baseline-tool-policy");
    let candidate_artifact = b"deny-grep-tool-policy-v1";
    let candidate_policy = policy("promoted-tool-policy", candidate_artifact);
    let baseline = deployment(
        "baseline-bundle",
        baseline_policy.clone(),
        None,
        b"baseline-bundle-exact-bytes".to_vec(),
    )?;
    let candidate = deployment(
        "promoted-bundle",
        candidate_policy.clone(),
        Some("baseline-bundle"),
        b"promoted-bundle-exact-bytes".to_vec(),
    )?;
    let catalog = ToolPolicyCatalog::new([
        ToolPolicyBinding::new(
            &baseline_policy.policy_id,
            &baseline_policy.version,
            &baseline_policy.digest,
            ToolFilter::All,
        )?,
        ToolPolicyBinding::new(
            &candidate_policy.policy_id,
            &candidate_policy.version,
            &candidate_policy.digest,
            ToolFilter::Deny(vec!["grep".into()]),
        )?,
    ])?;

    let control = control_policy()?;
    let authorizer =
        PromotionAuthorizer::new(AUTHORITY_ID, control.digest()?, PROMOTION_PARTY, key(0x11)?)?;
    let mut authority = PromotionAuthority::open(
        root,
        AUTHORITY_ID,
        control,
        vec![promotion_anchor()?],
        vec![evaluator_anchor()?],
    )?;
    let bootstrap = PromotionRequest::bootstrap("demo-bootstrap", &baseline.bundle().digest)?;
    authority.bootstrap(
        &bootstrap,
        &authorizer.authorize(&bootstrap)?,
        baseline.clone(),
    )?;
    let baseline_boot = boot(&mut authority, &catalog)?;

    let suite = evaluation_suite()?;
    let manifest = manifest(
        candidate_policy.clone(),
        baseline_policy.clone(),
        suite.digest(),
    );
    ManifestAdmissionPolicy::new(StrategySlot::tool_policy(), BTreeSet::new())
        .with_parent_ceiling(ParentCapabilityCeiling::new(
            baseline_policy.clone(),
            BTreeSet::new(),
        ))
        .assess(&manifest)?;
    let verifier = verifier()?;
    let verified = verifier.verify_candidate_inputs(&manifest, candidate_artifact, None, &suite)?;
    let evidence = evidence(&baseline_policy, &candidate_policy);
    let held_out = evaluator()?.sign_held_out(HeldOutEvaluation::new(
        candidate_policy.clone(),
        &verified,
        evidence.clone(),
    )?)?;
    let datasets = ConsentAwareDatasetRegistry::new();
    let admit = PromotionRequest::admit_candidate("demo-admit", &candidate.bundle().digest)?;
    authority.admit_candidate(
        &admit,
        &authorizer.authorize(&admit)?,
        &verifier,
        &datasets,
        &manifest,
        candidate_artifact,
        None,
        &suite,
        held_out,
        candidate.clone(),
    )?;
    let candidate_boot = boot(&mut authority, &catalog)?;

    let shadow_request = PromotionRequest::enter_shadow("demo-shadow", &candidate.bundle().digest)?;
    let shadow =
        authority.enter_shadow(&shadow_request, &authorizer.authorize(&shadow_request)?)?;
    let shadow_boot = boot(&mut authority, &catalog)?;

    let canary_request =
        PromotionRequest::complete_shadow("demo-canary", &candidate.bundle().digest)?;
    let canary = authority.complete_shadow(
        &canary_request,
        &authorizer.authorize(&canary_request)?,
        stage_observation(&shadow, &evidence)?,
    )?;
    let active_request =
        PromotionRequest::complete_canary("demo-active", &candidate.bundle().digest)?;
    authority.complete_canary(
        &active_request,
        &authorizer.authorize(&active_request)?,
        stage_observation(&canary, &evidence)?,
    )?;
    let promoted_boot = boot(&mut authority, &catalog)?;
    let baseline_tools = baseline_boot.narrowed_tools();
    let promoted_tools = promoted_boot.narrowed_tools();
    if baseline_tools == promoted_tools
        || !baseline_tools.iter().any(|tool| tool == "grep")
        || promoted_tools.iter().any(|tool| tool == "grep")
    {
        anyhow::bail!("promoted tool policy did not narrow the observable agent tool set");
    }
    let baseline_digest = baseline.bundle().digest.as_str();
    let candidate_kept_baseline = candidate_boot
        .resolved_bundle()
        .is_some_and(|bundle| bundle.digest == baseline_digest);
    let shadow_kept_baseline = shadow_boot
        .resolved_bundle()
        .is_some_and(|bundle| bundle.digest == baseline_digest);
    if !candidate_kept_baseline || !shadow_kept_baseline {
        anyhow::bail!("candidate or shadow bundle escaped the offline active pointer");
    }

    Ok(PolicyBundleDemoResult {
        baseline_tools,
        promoted_tools,
    })
}

fn boot(
    authority: &mut PromotionAuthority,
    catalog: &ToolPolicyCatalog,
) -> anyhow::Result<std::sync::Arc<BootPolicySnapshot>> {
    let resolver = ActivePromotionBundleResolver::capture(authority)?;
    Ok(BootPolicySnapshot::resolve_once(&resolver, catalog)?)
}

fn policy(id: &str, artifact: &[u8]) -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::tool_policy(),
        policy_id: id.into(),
        version: "1.0.0".into(),
        digest: digest_bytes(artifact),
    }
}

fn deployment(
    bundle_id: &str,
    policy: PolicyRef,
    rollback_to: Option<&str>,
    bytes: Vec<u8>,
) -> Result<DeploymentBundle, core_evolve::PromotionAuthorityError> {
    DeploymentBundle::new(
        PolicyBundle {
            bundle_id: bundle_id.into(),
            digest: digest_bytes(&bytes),
            policies: vec![policy],
            rollback_to: rollback_to.map(str::to_owned),
        },
        bytes,
    )
}

fn manifest(candidate: PolicyRef, parent: PolicyRef, evaluation_digest: &str) -> PolicyManifest {
    PolicyManifest {
        schema_version: core_evolve::EVOLUTION_SCHEMA_VERSION,
        policy: candidate,
        artifact_kind: ArtifactKind::Rules,
        artifact_locator: "inert:demo-tool-policy".into(),
        parent: Some(parent),
        method: EvolutionMethod::HandAuthored,
        protocol: ProtocolRange { min: 1, max: 1 },
        required_capabilities: BTreeSet::new(),
        training_dataset_digest: None,
        evaluation_suite_digest: evaluation_digest.into(),
        base_model: base_model(),
    }
}

fn evidence(baseline: &PolicyRef, candidate: &PolicyRef) -> PromotionEvidence {
    PromotionEvidence {
        baseline: baseline.clone(),
        candidate: candidate.clone(),
        base_model: base_model(),
        paired_tasks: 100,
        task_score_delta: Interval {
            estimate: 0.125,
            lower: 0.125,
            upper: 0.125,
        },
        cost_delta_usd: Interval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        },
        latency_delta_ms: Interval {
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        },
        candidate_safety_violations: 0,
        candidate_policy_violations: 0,
        train_eval_overlap: false,
        replay_equivalence_passed: true,
        sandbox_suite_passed: true,
        invariant_suites: [
            ("runtime".into(), true),
            ("security".into(), true),
            ("durability".into(), true),
        ]
        .into(),
    }
}

fn stage_observation(
    permit: &StagePermit,
    evidence: &PromotionEvidence,
) -> Result<SignedStageObservation, core_evolve::PromotionAuthorityError> {
    let traffic = match permit.stage() {
        DeploymentStage::Shadow => 0,
        DeploymentStage::Canary => 500,
        _ => return Err(core_evolve::PromotionAuthorityError::InvalidRequestTransition),
    };
    evaluator()?.sign_stage(StageObservation::new(
        permit,
        2,
        1,
        100,
        traffic,
        100,
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
        evidence.clone(),
    )?)
}

fn evaluation_suite() -> Result<EvaluationSuite, core_evolve::VerifierError> {
    EvaluationSuite::new(
        SUITE_OWNER,
        "demo-suite-v1",
        (0..100)
            .map(|index| EvaluationTask {
                task_id: format!("demo-held-out-{index:03}"),
                fixture_digest: format!("{:064x}", index + 1),
            })
            .collect(),
    )
}

fn verifier() -> Result<EvolutionVerifier, core_evolve::VerifierError> {
    EvolutionVerifier::new(
        vec![ProducerTrustAnchor::new(
            "unused-record-producer",
            core_evolve::TenantId::default(),
            AttestationKey::new(vec![0x44; 32])?,
        )?],
        TrainingAdmissionPolicy::new(BTreeSet::new(), BTreeMap::new())
            .expect("empty no-training policy is bounded"),
    )
}

fn control_policy() -> Result<PromotionControlPolicy, core_evolve::PromotionAuthorityError> {
    PromotionControlPolicy::new(
        core_evolve::PromotionGate::default(),
        StageLimits::new(20, 2, 5_000, 0, 2_000)?,
        StageLimits::new(10, 1, 2_000, 500, 1_000)?,
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
    )
}

fn promotion_anchor() -> Result<PromotionTrustAnchor, core_evolve::PromotionAuthorityError> {
    PromotionTrustAnchor::new(
        PROMOTION_PARTY,
        [
            PromotionRole::Bootstrap,
            PromotionRole::AdmitCandidate,
            PromotionRole::AdvanceStage,
            PromotionRole::Rollback,
        ]
        .into(),
        key(0x11)?,
    )
}

fn evaluator_anchor() -> Result<EvaluatorTrustAnchor, core_evolve::PromotionAuthorityError> {
    EvaluatorTrustAnchor::new(EVALUATOR_ID, SUITE_OWNER, key(0x22)?)
}

fn evaluator() -> Result<IndependentEvaluator, core_evolve::PromotionAuthorityError> {
    IndependentEvaluator::new(EVALUATOR_ID, key(0x22)?)
}

fn key(byte: u8) -> Result<PromotionAuthorityKey, core_evolve::PromotionAuthorityError> {
    PromotionAuthorityKey::new(vec![byte; 32])
}

fn base_model() -> BaseModelId {
    BaseModelId {
        model_family: "demo/frozen".into(),
        model_id: "tool-policy-model".into(),
        model_digest: "1".repeat(64),
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!(
        "core-policy-bundle-demo-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_and_shadow_bundles_cannot_be_resolved_as_active() {
        let result = run().unwrap();
        assert_ne!(result.baseline_tools, result.promoted_tools);
    }
}
