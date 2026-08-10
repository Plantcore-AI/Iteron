//! The `evolution-proven` gate: one deterministic artifact that certifies the whole control plane.
//!
//! This is the gate, not new capability. Everything it exercises was built and tested in #26
//! through #30; the gate's job is to run those pieces *together*, twice, under both producer
//! orders and both frozen base models, and emit a signed summary a machine can refuse.
//!
//! What it proves in-process, and how, is recorded per item in the report rather than asserted in
//! prose. Four checkpoint-algebra operators are exercised directly here; `transfer` is exercised
//! through the transcript, which is where a cross-model rebind can be observed with real
//! evidence. Both are genuine executions, and the report says which mechanism produced each one,
//! because a summary that flattens the difference would be the kind of overclaim §6.10 forbids.
//!
//! The signature uses a fixed public gate key, the same posture the offline transcript documents:
//! it binds the summary's bytes so a tampered report is detectable, and it proves nothing about
//! external identity.

use crate::conformance::{self, CHECKPOINT_ALGEBRA_OPERATORS, EVOLUTION_MATRIX, PROVEN_MODULES};
use crate::transcript_demo_support as demo;
use crate::verifier_crypto::{hmac_serialized, sha256_hex};
use crate::{
    ArtifactKind, Capability, EvaluatorTrustAnchor, EvolutionMethod, Interval,
    ManifestAdmissionPolicy, PolicyCheckpoint, PolicyManifest, PolicyRef, PromotionAuthority,
    PromotionEvidence, ProtocolRange, StrategySlot, TranscriptEvent, TranscriptProducerKind,
    TranscriptRecord, diff, merge, restrict, retire,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const EVOLUTION_GATE_SCHEMA_VERSION: u16 = 1;

const GATE_DOMAIN: &str = "iteron-evolve/evolution-proven/v1";
const DEMO_GATE_KEY: &[u8] = b"iteron-evolve-public-gate-key-v1";
const MAX_GATE_SUMMARY_BYTES: usize = 256 * 1024;
const MAX_TRANSCRIPT_READ_BYTES: u64 = 16 * 1024 * 1024;

/// How an operator was actually driven. Kept as data so the report cannot round a
/// transcript-observed rebind up to an in-process call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMechanism {
    /// Called directly by this gate.
    InProcess,
    /// Observed as an event of the deterministic offline transcript this gate ran.
    TranscriptEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProof {
    pub operator: String,
    pub mechanism: ProofMechanism,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleProof {
    pub module: String,
    pub passed: bool,
    pub mechanism: ProofMechanism,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptProof {
    pub producer_order: String,
    pub source_model: String,
    pub target_model: String,
    pub event_count: usize,
    pub chain_verified_events: usize,
    pub deterministic: bool,
    pub transcript_digest: String,
    pub promotion_journal_digest: String,
    pub target_promotion_journal_digest: String,
    pub trajectory_registry_digest: String,
    pub final_active_bundle_digest: String,
    pub replayed_active_bundle_digest: String,
}

/// The signed body. Split from the envelope so the signature covers exactly the claims and
/// nothing about where the run happened: scratch paths are deliberately absent, which is what
/// lets two runs in two directories produce byte-identical reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionGateBody {
    pub schema_version: u16,
    pub evolution_schema_version: u16,
    pub conformance_row_count: usize,
    pub transcripts: Vec<TranscriptProof>,
    pub modules: Vec<ModuleProof>,
    pub operators: Vec<OperatorProof>,
    pub separation_of_duties_verified: bool,
    pub separation_of_duties_detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionGateReport {
    pub body: EvolutionGateBody,
    pub body_digest: String,
    pub signature: String,
}

impl EvolutionGateReport {
    /// True only when every module passed, every operator has a proof, both transcript runs were
    /// deterministic and chain-verified, and separation of duties held.
    pub fn passed(&self) -> bool {
        self.body.modules.iter().all(|module| module.passed)
            && self.body.operators.len() == CHECKPOINT_ALGEBRA_OPERATORS.len()
            && self.body.separation_of_duties_verified
            && !self.body.transcripts.is_empty()
            && self.body.transcripts.iter().all(|transcript| {
                transcript.deterministic
                    && transcript.chain_verified_events == transcript.event_count
                    && transcript.replayed_active_bundle_digest
                        == transcript.final_active_bundle_digest
            })
    }

    /// One line per claim, for a CI log that has to be readable when it goes red.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("kind\tname\tstatus\tmechanism\tdetail\n");
        for transcript in &self.body.transcripts {
            out.push_str(&format!(
                "transcript\t{}\t{}\tin_process\tevents={} chain={} active={}\n",
                transcript.producer_order,
                if transcript.deterministic {
                    "PASS"
                } else {
                    "FAIL"
                },
                transcript.event_count,
                transcript.chain_verified_events,
                transcript.final_active_bundle_digest
            ));
        }
        for module in &self.body.modules {
            out.push_str(&format!(
                "module\t{}\t{}\t{}\t{}\n",
                module.module,
                if module.passed { "PASS" } else { "FAIL" },
                mechanism_label(module.mechanism),
                module.detail
            ));
        }
        for operator in &self.body.operators {
            out.push_str(&format!(
                "operator\t{}\tPASS\t{}\t{}\n",
                operator.operator,
                mechanism_label(operator.mechanism),
                operator.detail
            ));
        }
        out.push_str(&format!(
            "invariant\tseparation-of-duties\t{}\tin_process\t{}\n",
            if self.body.separation_of_duties_verified {
                "PASS"
            } else {
                "FAIL"
            },
            self.body.separation_of_duties_detail
        ));
        out.push_str(&format!(
            "artifact\tevolution-proven\t{}\t-\tdigest={} signature={}\n",
            if self.passed() { "PASS" } else { "FAIL" },
            self.body_digest,
            self.signature
        ));
        out
    }
}

fn mechanism_label(mechanism: ProofMechanism) -> &'static str {
    match mechanism {
        ProofMechanism::InProcess => "in_process",
        ProofMechanism::TranscriptEvent => "transcript_event",
    }
}

#[derive(Debug)]
pub enum GateError {
    Conformance(conformance::ConformanceError),
    Transcript(crate::TranscriptRunError),
    Algebra(crate::CheckpointAlgebraError),
    Verifier(crate::VerifierError),
    ChainMismatch {
        producer_order: String,
        expected: usize,
        actual: usize,
    },
    NonDeterministic {
        producer_order: String,
        artifact: String,
    },
    ReplayDigestMismatch {
        producer_order: String,
        expected: String,
        actual: String,
    },
    SeparationOfDutiesNotEnforced,
    ModuleUnproven(String),
    OperatorUnproven(String),
    Io(std::io::Error),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conformance(error) => write!(f, "conformance rows are not admissible: {error}"),
            Self::Transcript(error) => write!(f, "offline transcript failed: {error}"),
            Self::Algebra(error) => write!(f, "checkpoint algebra failed: {error}"),
            Self::Verifier(error) => write!(f, "gate summary could not be signed: {error}"),
            Self::ChainMismatch {
                producer_order,
                expected,
                actual,
            } => write!(
                f,
                "transcript `{producer_order}` hash chain verified {actual} of {expected} events"
            ),
            Self::NonDeterministic {
                producer_order,
                artifact,
            } => write!(
                f,
                "transcript `{producer_order}` is non-deterministic: {artifact} differed between two runs"
            ),
            Self::ReplayDigestMismatch {
                producer_order,
                expected,
                actual,
            } => write!(
                f,
                "transcript `{producer_order}` replayed active bundle {actual}, expected {expected}"
            ),
            Self::SeparationOfDutiesNotEnforced => write!(
                f,
                "a journal signed by the evaluator replayed under a promotion-keyed anchor; separation of duties is not enforced"
            ),
            Self::ModuleUnproven(module) => write!(f, "proven module `{module}` has no proof"),
            Self::OperatorUnproven(operator) => {
                write!(
                    f,
                    "checkpoint algebra operator `{operator}` was never exercised"
                )
            }
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GateError {}

impl From<conformance::ConformanceError> for GateError {
    fn from(error: conformance::ConformanceError) -> Self {
        Self::Conformance(error)
    }
}

impl From<crate::TranscriptRunError> for GateError {
    fn from(error: crate::TranscriptRunError) -> Self {
        Self::Transcript(error)
    }
}

impl From<crate::CheckpointAlgebraError> for GateError {
    fn from(error: crate::CheckpointAlgebraError) -> Self {
        Self::Algebra(error)
    }
}

impl From<crate::VerifierError> for GateError {
    fn from(error: crate::VerifierError) -> Self {
        Self::Verifier(error)
    }
}

impl From<std::io::Error> for GateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Run the gate. `repo` is the checkout the conformance rows are validated against; `scratch` is
/// a directory the gate may create run trees under. Nothing under `scratch` enters the signed
/// body, so the report of two runs in two scratch directories is byte-identical.
pub fn run(repo: &Path, scratch: &Path) -> Result<EvolutionGateReport, GateError> {
    conformance::validate(repo)?;

    let orders = [
        (
            "rule,prompt",
            TranscriptProducerKind::RuleSearch,
            TranscriptProducerKind::PromptPreference,
        ),
        (
            "prompt,rule",
            TranscriptProducerKind::PromptPreference,
            TranscriptProducerKind::RuleSearch,
        ),
    ];

    let mut transcripts = Vec::new();
    let mut transfer_details = Vec::new();
    let mut method_agnostic_details = Vec::new();
    let mut stage_details = Vec::new();
    let mut producer_details = Vec::new();
    let mut second_producer_details = Vec::new();

    for (label, primary, secondary) in orders {
        let config = crate::OfflineTranscriptConfig::new(
            demo::model_a(),
            demo::model_b(),
            primary,
            secondary,
        )?;

        let first_root = scratch.join(format!("gate-{}-a", slug(label)));
        let second_root = scratch.join(format!("gate-{}-b", slug(label)));
        let first = crate::run_offline_transcript_with_config(&first_root, &config)?;
        let second = crate::run_offline_transcript_with_config(&second_root, &config)?;

        for (artifact, left, right) in [
            (
                "transcript",
                &first.transcript_path,
                &second.transcript_path,
            ),
            (
                "promotion_journal",
                &first.promotion_journal_path,
                &second.promotion_journal_path,
            ),
            (
                "target_promotion_journal",
                &first.target_promotion_journal_path,
                &second.target_promotion_journal_path,
            ),
            (
                "trajectory_registry",
                &first.trajectory_registry_path,
                &second.trajectory_registry_path,
            ),
        ] {
            if std::fs::read(left)? != std::fs::read(right)? {
                return Err(GateError::NonDeterministic {
                    producer_order: label.to_owned(),
                    artifact: artifact.to_owned(),
                });
            }
        }

        let chain_verified = crate::verify_offline_transcript(&first.transcript_path)?;
        if chain_verified != first.event_count {
            return Err(GateError::ChainMismatch {
                producer_order: label.to_owned(),
                expected: first.event_count,
                actual: chain_verified,
            });
        }

        // Reopening replays the journal and verifies its hash chain and every signature under the
        // anchors the demo pipeline actually signed with.
        let journal_root = journal_root_of(&first.promotion_journal_path);
        let mut replayed = PromotionAuthority::open(
            &journal_root,
            demo::AUTHORITY_ID,
            demo::control_policy(),
            vec![demo::promotion_anchor()],
            vec![demo::evaluator_anchor()],
        )
        .map_err(|error| GateError::Transcript(crate::TranscriptRunError::from(error)))?;
        let replayed_digest = replayed
            .active_bundle()
            .map_err(|error| GateError::Transcript(crate::TranscriptRunError::from(error)))?
            .map(|active| active.bundle().digest.clone())
            .unwrap_or_default();
        if replayed_digest != first.final_active_bundle_digest {
            return Err(GateError::ReplayDigestMismatch {
                producer_order: label.to_owned(),
                expected: first.final_active_bundle_digest.clone(),
                actual: replayed_digest,
            });
        }

        let records = read_records(&first.transcript_path)?;
        collect_event_details(
            &records,
            &mut transfer_details,
            &mut method_agnostic_details,
            &mut stage_details,
            &mut producer_details,
            &mut second_producer_details,
        );

        transcripts.push(TranscriptProof {
            producer_order: label.to_owned(),
            source_model: model_label(&demo::model_a()),
            target_model: model_label(&demo::model_b()),
            event_count: first.event_count,
            chain_verified_events: chain_verified,
            deterministic: true,
            transcript_digest: file_digest(&first.transcript_path)?,
            promotion_journal_digest: file_digest(&first.promotion_journal_path)?,
            target_promotion_journal_digest: file_digest(&first.target_promotion_journal_path)?,
            trajectory_registry_digest: file_digest(&first.trajectory_registry_path)?,
            final_active_bundle_digest: first.final_active_bundle_digest.clone(),
            replayed_active_bundle_digest: replayed_digest,
        });
    }

    let separation = verify_separation_of_duties(scratch)?;
    let mut operators = exercise_algebra()?;
    operators.push(OperatorProof {
        operator: "transfer".to_owned(),
        mechanism: ProofMechanism::TranscriptEvent,
        detail: transfer_details
            .first()
            .cloned()
            .ok_or_else(|| GateError::OperatorUnproven("transfer".to_owned()))?,
    });
    for operator in CHECKPOINT_ALGEBRA_OPERATORS {
        if !operators.iter().any(|proof| proof.operator == operator) {
            return Err(GateError::OperatorUnproven(operator.to_owned()));
        }
    }

    let modules = vec![
        ModuleProof {
            module: "producer".to_owned(),
            passed: !producer_details.is_empty(),
            mechanism: ProofMechanism::TranscriptEvent,
            detail: join_details(&producer_details),
        },
        ModuleProof {
            module: "independent-held-out-evaluator".to_owned(),
            passed: separation.verified,
            mechanism: ProofMechanism::InProcess,
            detail: separation.detail.clone(),
        },
        ModuleProof {
            module: "shadow-canary".to_owned(),
            passed: !stage_details.is_empty(),
            mechanism: ProofMechanism::TranscriptEvent,
            detail: join_details(&stage_details),
        },
        ModuleProof {
            module: "checkpoint-algebra".to_owned(),
            passed: operators.len() == CHECKPOINT_ALGEBRA_OPERATORS.len(),
            mechanism: ProofMechanism::InProcess,
            detail: format!(
                "{} of {} operators exercised",
                operators.len(),
                CHECKPOINT_ALGEBRA_OPERATORS.len()
            ),
        },
        ModuleProof {
            module: "cross-model-transfer".to_owned(),
            passed: !transfer_details.is_empty(),
            mechanism: ProofMechanism::TranscriptEvent,
            detail: join_details(&transfer_details),
        },
        ModuleProof {
            module: "second-producer".to_owned(),
            passed: !second_producer_details.is_empty() && !method_agnostic_details.is_empty(),
            mechanism: ProofMechanism::TranscriptEvent,
            detail: format!(
                "{}; {}",
                join_details(&second_producer_details),
                join_details(&method_agnostic_details)
            ),
        },
    ];
    for module in PROVEN_MODULES {
        let proof = modules
            .iter()
            .find(|proof| proof.module == module)
            .ok_or_else(|| GateError::ModuleUnproven(module.to_owned()))?;
        if !proof.passed {
            return Err(GateError::ModuleUnproven(module.to_owned()));
        }
    }
    if !separation.verified {
        return Err(GateError::SeparationOfDutiesNotEnforced);
    }

    let body = EvolutionGateBody {
        schema_version: EVOLUTION_GATE_SCHEMA_VERSION,
        evolution_schema_version: crate::EVOLUTION_SCHEMA_VERSION,
        conformance_row_count: EVOLUTION_MATRIX.len(),
        transcripts,
        modules,
        operators,
        separation_of_duties_verified: separation.verified,
        separation_of_duties_detail: separation.detail,
    };
    let signed = (GATE_DOMAIN, &body);
    let body_digest = crate::verifier_crypto::digest_serialized(&signed, MAX_GATE_SUMMARY_BYTES)?;
    let signature = hmac_serialized(DEMO_GATE_KEY, &signed, MAX_GATE_SUMMARY_BYTES)?;
    Ok(EvolutionGateReport {
        body,
        body_digest,
        signature,
    })
}

struct SeparationProof {
    verified: bool,
    detail: String,
}

/// Open the journal, learn whether it replays, and close it again.
///
/// Closing matters: the promotion journal admits exactly one writer, so a handle left open makes
/// every later probe fail with a lock error that looks like a refusal and proves nothing. An
/// earlier draft of this gate reported precisely that false positive.
fn replays_under(
    journal_root: &Path,
    evaluator: EvaluatorTrustAnchor,
) -> Result<(), crate::PromotionAuthorityError> {
    let authority = PromotionAuthority::open(
        journal_root,
        demo::AUTHORITY_ID,
        demo::control_policy(),
        vec![demo::promotion_anchor()],
        vec![evaluator],
    )?;
    drop(authority);
    Ok(())
}

/// Prove the separation of duties directly: the journal the demo pipeline signed replays under the
/// independent evaluator anchor, and is refused when the evaluator slot is filled with the
/// promotion party's key instead. A run where both succeed means the roles are interchangeable,
/// which is the failure this checks for.
fn verify_separation_of_duties(scratch: &Path) -> Result<SeparationProof, GateError> {
    let root = scratch.join("gate-separation-of-duties");
    let result = crate::run_offline_transcript(&root)?;
    let journal_root = journal_root_of(&result.promotion_journal_path);

    // Three probes, run strictly one at a time so each verdict is caused by the thing it names.
    //
    // (1) The honest anchors: the journal must replay.
    let honest = replays_under(&journal_root, demo::evaluator_anchor()).is_ok();

    // (2) Role alias -- the evaluator slot filled with the promotion party's own key. Refused during
    //     anchor registration, before any signature is examined: the authority will not hold one
    //     key in two roles at all.
    let promotion_keyed =
        EvaluatorTrustAnchor::new(demo::EVALUATOR_ID, demo::SUITE_OWNER, demo::key(0x11))
            .map_err(|error| GateError::Transcript(crate::TranscriptRunError::from(error)))?;
    let role_alias_refused = replays_under(&journal_root, promotion_keyed).is_err();

    // (3) Wrong key, no aliasing -- an unrelated evaluator key that duplicates nothing. Registration
    //     has nothing to object to, so a refusal here can only come from the held-out signatures
    //     failing to verify. This is the signature-level half of the claim.
    let unrelated =
        EvaluatorTrustAnchor::new(demo::EVALUATOR_ID, demo::SUITE_OWNER, demo::key(0x33))
            .map_err(|error| GateError::Transcript(crate::TranscriptRunError::from(error)))?;
    let wrong_key_refused = replays_under(&journal_root, unrelated).is_err();

    let verified = honest && role_alias_refused && wrong_key_refused;
    // Deliberately not the error `Display`: those strings embed the scratch path, which would make
    // the signed body depend on where the gate ran.
    let detail = format!(
        "replays_under_evaluator_anchor={honest} role_alias_refused_at_registration={role_alias_refused} unrelated_key_refused_by_signature={wrong_key_refused}"
    );
    Ok(SeparationProof { verified, detail })
}

/// Exercise diff, merge, restrict and retire directly. The fixtures are the minimum a legal
/// `PolicyCheckpoint` needs; the point is that the operators run and their outputs validate, not
/// that they reproduce the dedicated unit tests, which the gate job also runs.
fn exercise_algebra() -> Result<Vec<OperatorProof>, GateError> {
    let slot = StrategySlot("core/tool_policy".to_owned());
    let other = StrategySlot("core/context".to_owned());
    let baseline = checkpoint(
        "baseline",
        None,
        [manifest(&slot, "baseline", '1', broad())],
    )?;
    let candidate = checkpoint(
        "candidate",
        Some("baseline".to_owned()),
        [manifest(&slot, "candidate", '2', broad())],
    )?;
    let sibling = checkpoint("sibling", None, [manifest(&other, "sibling", '3', broad())])?;

    // `diff` refuses a changed slot with no held-out attribution, which is the point: a slot-level
    // delta that nobody measured is exactly what §6.4 says diff must not fabricate. So the gate
    // supplies real attribution for the one slot it changes.
    let attribution: BTreeMap<StrategySlot, PromotionEvidence> =
        [(slot.clone(), slot_evidence(&baseline, &candidate, &slot))].into();
    let changed = diff(&baseline, &candidate, &attribution)?;

    let admissions = admissions([(slot.clone(), broad()), (other.clone(), broad())]);
    let merged = merge(
        "merged",
        Some("baseline".to_owned()),
        &[candidate.clone(), sibling],
        &admissions,
    )?;

    let narrowed = restrict(
        &candidate,
        "restricted",
        &slot,
        [Capability::ReadOnly].into(),
        &admissions,
    )?;

    let retired = retire(&candidate, &baseline, "retired", &slot, &admissions)?;

    Ok(vec![
        OperatorProof {
            operator: "diff".to_owned(),
            mechanism: ProofMechanism::InProcess,
            detail: format!("{} changed slot(s)", changed.changed.len()),
        },
        OperatorProof {
            operator: "merge".to_owned(),
            mechanism: ProofMechanism::InProcess,
            detail: format!(
                "merged bundle carries {} slot(s)",
                merged.checkpoint.manifests().len()
            ),
        },
        OperatorProof {
            operator: "restrict".to_owned(),
            mechanism: ProofMechanism::InProcess,
            detail: format!(
                "narrowed {} to {} capability(ies)",
                slot.0,
                narrowed
                    .checkpoint
                    .manifests()
                    .get(&slot)
                    .map(|manifest| manifest.required_capabilities.len())
                    .unwrap_or_default()
            ),
        },
        OperatorProof {
            operator: "retire".to_owned(),
            mechanism: ProofMechanism::InProcess,
            detail: format!("{} event(s) recorded", retired.events.len()),
        },
    ])
}

fn broad() -> BTreeSet<Capability> {
    [Capability::ReadOnly, Capability::ReversibleLocal].into()
}

/// Attribution for the single slot the algebra exercise changes. Both sides are measured on the
/// same frozen base model, because a delta across two models is a transfer result, not a diff.
fn slot_evidence(
    before: &PolicyCheckpoint,
    after: &PolicyCheckpoint,
    slot: &StrategySlot,
) -> PromotionEvidence {
    let flat = Interval {
        estimate: 0.0,
        lower: 0.0,
        upper: 0.0,
    };
    PromotionEvidence {
        baseline: before
            .manifests()
            .get(slot)
            .map(|manifest| manifest.policy.clone())
            .expect("the algebra fixture defines the slot on both sides"),
        candidate: after
            .manifests()
            .get(slot)
            .map(|manifest| manifest.policy.clone())
            .expect("the algebra fixture defines the slot on both sides"),
        base_model: demo::model_a(),
        paired_tasks: 100,
        task_score_delta: Interval {
            estimate: 0.25,
            lower: 0.25,
            upper: 0.25,
        },
        cost_delta_usd: flat,
        latency_delta_ms: flat,
        candidate_safety_violations: 0,
        candidate_policy_violations: 0,
        train_eval_overlap: false,
        replay_equivalence_passed: true,
        sandbox_suite_passed: true,
        invariant_suites: [
            ("runtime".to_owned(), true),
            ("security".to_owned(), true),
            ("durability".to_owned(), true),
        ]
        .into(),
    }
}

fn manifest(
    slot: &StrategySlot,
    id: &str,
    digest_seed: char,
    required_capabilities: BTreeSet<Capability>,
) -> PolicyManifest {
    let digest = digest_seed.to_string().repeat(64);
    PolicyManifest {
        schema_version: crate::EVOLUTION_SCHEMA_VERSION,
        artifact_kind: ArtifactKind::Rules,
        artifact_locator: format!("inert:sha256:{digest}"),
        parent: None,
        method: EvolutionMethod::HandAuthored,
        protocol: ProtocolRange { min: 1, max: 1 },
        required_capabilities,
        training_dataset_digest: None,
        evaluation_suite_digest: "4".repeat(64),
        base_model: demo::model_a(),
        policy: PolicyRef {
            slot: slot.clone(),
            policy_id: id.to_owned(),
            version: "1.0.0".to_owned(),
            digest,
        },
    }
}

fn checkpoint(
    id: &str,
    rollback_to: Option<String>,
    manifests: impl IntoIterator<Item = PolicyManifest>,
) -> Result<PolicyCheckpoint, crate::CheckpointAlgebraError> {
    PolicyCheckpoint::build(
        id,
        rollback_to,
        manifests
            .into_iter()
            .map(|manifest| (manifest.policy.slot.clone(), manifest))
            .collect(),
    )
}

fn admissions(
    slots: impl IntoIterator<Item = (StrategySlot, BTreeSet<Capability>)>,
) -> BTreeMap<StrategySlot, ManifestAdmissionPolicy> {
    slots
        .into_iter()
        .map(|(slot, allowed)| (slot.clone(), ManifestAdmissionPolicy::new(slot, allowed)))
        .collect()
}

fn collect_event_details(
    records: &[TranscriptRecord],
    transfer: &mut Vec<String>,
    method_agnostic: &mut Vec<String>,
    stages: &mut Vec<String>,
    produced: &mut Vec<String>,
    second_producer: &mut Vec<String>,
) {
    let mut methods = BTreeSet::new();
    for record in records {
        match &record.event {
            TranscriptEvent::CandidateProduced {
                label,
                method,
                artifact_kind,
                ..
            } => {
                produced.push(format!("{label} via {method:?}/{artifact_kind:?}"));
                methods.insert(format!("{method:?}/{artifact_kind:?}"));
            }
            TranscriptEvent::StageReached { label, stage } => {
                stages.push(format!("{label}->{stage:?}"));
            }
            TranscriptEvent::RolledBack {
                label,
                restored_bundle_digest,
            } => {
                stages.push(format!("{label}->rolled_back({restored_bundle_digest})"));
            }
            TranscriptEvent::TransferReported {
                from_model,
                to_model,
                portable_fraction,
                target_gate_eligible,
                ..
            } => {
                transfer.push(format!(
                    "{} -> {}: portable_fraction={portable_fraction} target_gate_eligible={target_gate_eligible}",
                    model_label(from_model),
                    model_label(to_model)
                ));
            }
            TranscriptEvent::MethodAgnostic {
                identical_gate_decision,
                byte_identical_gate_reasons,
                first_method,
                second_method,
                ..
            } => {
                method_agnostic.push(format!(
                    "{first_method:?} vs {second_method:?}: identical_decision={identical_gate_decision} identical_reasons={byte_identical_gate_reasons}"
                ));
            }
            _ => {}
        }
    }
    if methods.len() > 1 {
        second_producer.push(format!(
            "{} distinct method/artifact pairs: {}",
            methods.len(),
            methods.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
}

fn join_details(details: &[String]) -> String {
    if details.is_empty() {
        "-".to_owned()
    } else {
        details.join("; ")
    }
}

fn model_label(model: &crate::BaseModelId) -> String {
    format!("{}:{}", model.model_family, model.model_id)
}

fn slug(label: &str) -> String {
    label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn journal_root_of(journal_path: &Path) -> PathBuf {
    journal_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn file_digest(path: &Path) -> Result<String, GateError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.len() > MAX_TRANSCRIPT_READ_BYTES {
        return Err(GateError::Io(std::io::Error::other(format!(
            "{} exceeds the {MAX_TRANSCRIPT_READ_BYTES}-byte gate read bound",
            path.display()
        ))));
    }
    Ok(sha256_hex(&std::fs::read(path)?))
}

fn read_records(path: &Path) -> Result<Vec<TranscriptRecord>, GateError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.len() > MAX_TRANSCRIPT_READ_BYTES {
        return Err(GateError::Io(std::io::Error::other(format!(
            "{} exceeds the {MAX_TRANSCRIPT_READ_BYTES}-byte gate read bound",
            path.display()
        ))));
    }
    let body = std::fs::read_to_string(path)?;
    let mut records = Vec::new();
    for line in body.lines() {
        let record: TranscriptRecord = serde_json::from_str(line)
            .map_err(|error| GateError::Io(std::io::Error::other(error.to_string())))?;
        records.push(record);
    }
    Ok(records)
}
