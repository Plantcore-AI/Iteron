//! Fail-closed owning-human review gate for optimization-census invariants.
//!
//! Mechanical source inspection is not human approval. This module emits a deterministic packet
//! and only accepts ledger rows backed by a current GitHub `APPROVED` review from the human who
//! owns the candidate's source boundary. The review body must contain the packet's exact batch
//! token, which binds every candidate id and source-evidence digest in that boundary.

mod batch;

use crate::model::{Boundary, Registry};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use batch::check_batch_ledger;

const CENSUS_PATH: &str = "governance/optimization-census.json";
const LEDGER_PATH: &str = "governance/optimization-invariant-reviews.json";
const BOUNDARIES_PATH: &str = "governance/boundaries.json";
const CENSUS_SCHEMA_VERSION: u16 = 4;
const LEGACY_REVIEW_SCHEMA_VERSION: u16 = 1;
const BATCH_REVIEW_SCHEMA_VERSION: u16 = 2;
const PACKET_SCHEMA_VERSION: u16 = 2;
const MAX_CENSUS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REVIEW_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CANDIDATES: usize = 10_000;
const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CensusFile {
    schema_version: u16,
    total: usize,
    runtime_settable: usize,
    invariant_read_only: usize,
    binding_required: usize,
    advertised_runtime_settable: usize,
    runtime_applied: usize,
    externally_addressed_runtime_settable: usize,
    unaddressed_runtime_settable: usize,
    mechanical_invariant_dispositions: usize,
    owning_human_review_required: usize,
    explicit_invariant_overrides: usize,
    address_kind_counts: BTreeMap<String, usize>,
    invariant_kind_counts: BTreeMap<String, usize>,
    source_coverage: SourceCoverage,
    candidates: Vec<CensusCandidate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCoverage {
    completeness_claim: String,
    production_rust_files_scanned: usize,
    source_form_counts: BTreeMap<String, usize>,
    candidate_row_counts: BTreeMap<String, usize>,
    unclassified_source_forms: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CensusOwner {
    krate: String,
    path: String,
    symbol: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CensusUseSite {
    path: String,
    line: usize,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalAddress {
    kind: String,
    selector_kind: String,
    selector: String,
    owner_kind: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerInputProof {
    kind: String,
    path: String,
    symbol: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CensusCandidate {
    id: String,
    candidate_kind: String,
    rust_type: String,
    value: String,
    owner: CensusOwner,
    use_sites: Vec<CensusUseSite>,
    disposition: String,
    external_address: Option<ExternalAddress>,
    caller_input_proof: Option<CallerInputProof>,
    binding_requirement: Option<String>,
    invariant_kind: Option<String>,
    review_evidence: Option<String>,
    owning_human_review: Option<String>,
    explicit_invariant_override: bool,
    applied: bool,
    behavior_oracle: Option<String>,
    tier2_id: Option<String>,
}

#[derive(Serialize)]
struct CandidateEvidence<'a> {
    candidate_id: &'a str,
    candidate_kind: &'a str,
    rust_type: &'a str,
    value: &'a str,
    owner: &'a CensusOwner,
    use_sites: &'a [CensusUseSite],
    invariant_kind: &'a str,
    mechanical_review_evidence: &'a str,
    explicit_invariant_override: bool,
    tier2_id: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReviewPacketEntry {
    candidate_id: String,
    candidate_evidence_sha256: String,
    candidate_kind: String,
    rust_type: String,
    value: String,
    owner: CensusOwner,
    use_sites: Vec<CensusUseSite>,
    invariant_kind: String,
    mechanical_review_evidence: String,
    explicit_invariant_override: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier2_id: Option<String>,
    ownership_boundary_id: String,
    invariant_overlay_ids: Vec<String>,
    owner_person_id: String,
    owner_github: String,
    approval_token: String,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReviewPacket {
    schema_version: u16,
    census_schema_version: u16,
    census_sha256: String,
    boundary_registry_sha256: String,
    required_reviews: usize,
    required_batches: usize,
    batches: Vec<ReviewPacketBatch>,
    candidates: Vec<ReviewPacketEntry>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReviewPacketBatch {
    ownership_boundary_id: String,
    owner_person_id: String,
    owner_github: String,
    candidate_count: usize,
    candidates: Vec<BatchCandidateEvidence>,
    approval_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct BatchCandidateEvidence {
    candidate_id: String,
    candidate_evidence_sha256: String,
}

#[derive(Serialize)]
struct ApprovalBatch<'a> {
    schema_version: u16,
    census_sha256: &'a str,
    boundary_registry_sha256: &'a str,
    ownership_boundary_id: &'a str,
    owner_person_id: &'a str,
    candidates: &'a [(String, String)],
}

struct ReviewContext {
    packet: ReviewPacket,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReviewLedger {
    schema_version: u16,
    census_sha256: String,
    boundary_registry_sha256: String,
    reviews: Vec<InvariantReview>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchReviewLedger {
    schema_version: u16,
    census_sha256: String,
    boundary_registry_sha256: String,
    batches: Vec<InvariantBatchReview>,
}

enum ReviewLedger {
    Legacy(LegacyReviewLedger),
    Batch(BatchReviewLedger),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ReviewDecision {
    AffirmInvariant,
    ReclassifyRuntimeSettable,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantReview {
    candidate_id: String,
    candidate_evidence_sha256: String,
    census_sha256: String,
    boundary_registry_sha256: String,
    ownership_boundary_id: String,
    invariant_overlay_ids: Vec<String>,
    owner_person_id: String,
    github_reviewer: String,
    decision: ReviewDecision,
    rationale: String,
    github_review_id: u64,
    github_review_commit_sha: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvariantBatchReview {
    ownership_boundary_id: String,
    owner_person_id: String,
    github_reviewer: String,
    candidate_evidence: Vec<BatchCandidateEvidence>,
    census_sha256: String,
    boundary_registry_sha256: String,
    decision: ReviewDecision,
    rationale: String,
    github_review_id: u64,
    github_review_commit_sha: String,
}

#[derive(Debug, Deserialize)]
struct GithubReview {
    id: u64,
    user: Option<GithubReviewUser>,
    state: String,
    commit_id: String,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GithubReviewUser {
    login: String,
}

pub(crate) fn print_packet(root: &Path) -> Result<()> {
    let context = load_context(root)?;
    let mut rendered = serde_json::to_string_pretty(&context.packet)?;
    rendered.push('\n');
    print!("{rendered}");
    Ok(())
}

pub(crate) fn print_review_body(root: &Path) -> Result<()> {
    let context = load_context(root)?;
    println!("## Iteron optimization invariant owner review\n");
    println!(
        "This review covers {} invariant candidates in {} owner×boundary batches. The tokens bind the exact census and boundary registry digests; approval is valid only for the reviewed commit.\n",
        context.packet.required_reviews, context.packet.required_batches
    );
    println!(
        "Approve only after reviewing every candidate in the packet. Keep every token below on its own line in the GitHub APPROVED review body.\n"
    );
    for batch in &context.packet.batches {
        println!(
            "### `{}` — `{}` ({}, {} candidates)\n\n{}\n",
            batch.ownership_boundary_id,
            batch.owner_person_id,
            batch.owner_github,
            batch.candidate_count,
            batch.approval_token
        );
    }
    Ok(())
}

pub(crate) fn check(root: &Path, review_evidence: Option<&Path>) -> Result<()> {
    let context = load_context(root)?;
    let ledger_bytes = read_bounded(&root.join(LEDGER_PATH), MAX_LEDGER_BYTES, "review ledger")?;
    let ledger = parse_review_ledger(&ledger_bytes)
        .with_context(|| format!("{LEDGER_PATH} is not a valid schema-v1/v2 review ledger"))?;
    let evidence = match review_evidence {
        Some(path) => {
            let bytes = read_bounded(path, MAX_REVIEW_EVIDENCE_BYTES, "GitHub review evidence")?;
            parse_github_reviews(&bytes)?
        }
        None => Vec::new(),
    };
    let approved = check_ledger(&context, &ledger, &evidence)?;
    println!(
        "optimization invariant owner reviews valid: {approved}/{approved} current, externally attested approvals"
    );
    Ok(())
}

fn parse_review_ledger(bytes: &[u8]) -> Result<ReviewLedger> {
    #[derive(Deserialize)]
    struct VersionOnly {
        schema_version: u16,
    }
    let version: VersionOnly = serde_json::from_slice(bytes)
        .context("review ledger is not a JSON object with schema_version")?;
    match version.schema_version {
        LEGACY_REVIEW_SCHEMA_VERSION => Ok(ReviewLedger::Legacy(
            serde_json::from_slice(bytes).context("invalid legacy candidate review ledger")?,
        )),
        BATCH_REVIEW_SCHEMA_VERSION => Ok(ReviewLedger::Batch(
            serde_json::from_slice(bytes).context("invalid batch review ledger")?,
        )),
        other => bail!(
            "unsupported ledger schema {other}; expected {LEGACY_REVIEW_SCHEMA_VERSION} or {BATCH_REVIEW_SCHEMA_VERSION}"
        ),
    }
}

fn load_context(root: &Path) -> Result<ReviewContext> {
    let current = crate::tunables_census::render_current(root)
        .context("cannot derive a source-current optimization census")?;
    let census_bytes = read_bounded(
        &root.join(CENSUS_PATH),
        MAX_CENSUS_BYTES,
        "optimization census",
    )?;
    if census_bytes != current.as_bytes() {
        bail!(
            "{CENSUS_PATH} is stale; owner reviews cannot target evidence which differs from current sources"
        );
    }
    let census: CensusFile = serde_json::from_slice(&census_bytes)
        .with_context(|| format!("{CENSUS_PATH} is not a valid schema-v4 census"))?;
    validate_census(&census)?;

    let boundary_bytes = read_bounded(
        &root.join(BOUNDARIES_PATH),
        2 * 1024 * 1024,
        "boundary registry",
    )?;
    let registry: Registry = serde_json::from_slice(&boundary_bytes)
        .with_context(|| format!("{BOUNDARIES_PATH} is invalid"))?;
    crate::validate::validate(root, &registry)
        .context("boundary registry must be valid before assigning invariant owners")?;

    let packet = build_packet(
        &census,
        &registry,
        &sha256(&census_bytes),
        &sha256(&boundary_bytes),
    )?;
    Ok(ReviewContext { packet })
}

fn validate_census(census: &CensusFile) -> Result<()> {
    if census.schema_version != CENSUS_SCHEMA_VERSION {
        bail!(
            "unsupported optimization census schema {}; expected {CENSUS_SCHEMA_VERSION}",
            census.schema_version
        );
    }
    if census.candidates.len() > MAX_CANDIDATES || census.total != census.candidates.len() {
        bail!("optimization census candidate total is invalid or exceeds {MAX_CANDIDATES}");
    }
    let mut ids = BTreeSet::new();
    let mut runtime = 0usize;
    let mut invariants = 0usize;
    let mut binding_required = 0usize;
    let mut addressed = BTreeSet::new();
    let mut address_counts = BTreeMap::new();
    for candidate in &census.candidates {
        bounded_text("candidate id", &candidate.id, 1024)?;
        if !ids.insert(candidate.id.as_str()) {
            bail!(
                "optimization census repeats candidate id `{}`",
                candidate.id
            );
        }
        match candidate.disposition.as_str() {
            "runtime_settable" => {
                runtime += 1;
                let address = candidate.external_address.as_ref().with_context(|| {
                    format!("{} has no concrete external address", candidate.id)
                })?;
                for (field, value) in [
                    ("kind", address.kind.as_str()),
                    ("selector_kind", address.selector_kind.as_str()),
                    ("selector", address.selector.as_str()),
                    ("owner_kind", address.owner_kind.as_str()),
                    ("owner", address.owner.as_str()),
                ] {
                    bounded_text(field, value, MAX_TEXT_BYTES)?;
                }
                let identity = format!(
                    "{}\0{}\0{}\0{}\0{}",
                    address.kind,
                    address.selector_kind,
                    address.selector,
                    address.owner_kind,
                    address.owner
                );
                if !addressed.insert(identity) {
                    bail!("{} repeats an external address", candidate.id);
                }
                *address_counts
                    .entry(address.kind.as_str())
                    .or_insert(0usize) += 1;
                if !candidate.applied || candidate.use_sites.is_empty() {
                    bail!("{} is advertised but not applied/evidenced", candidate.id);
                }
                if candidate
                    .behavior_oracle
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    bail!("{} lacks a behavioral oracle", candidate.id);
                }
                if address.kind == "caller_input" {
                    let proof = candidate.caller_input_proof.as_ref().with_context(|| {
                        format!(
                            "{} has caller_input without public protocol proof",
                            candidate.id
                        )
                    })?;
                    for (field, value) in [
                        ("proof kind", proof.kind.as_str()),
                        ("proof path", proof.path.as_str()),
                        ("proof symbol", proof.symbol.as_str()),
                        ("proof evidence", proof.evidence.as_str()),
                    ] {
                        bounded_text(field, value, MAX_TEXT_BYTES)?;
                    }
                    if proof.path != candidate.owner.path {
                        bail!(
                            "{} caller proof path does not match its owner",
                            candidate.id
                        );
                    }
                } else if candidate.caller_input_proof.is_some() {
                    bail!("{} has caller proof for a non-caller address", candidate.id);
                }
                if candidate.binding_requirement.is_some() {
                    bail!(
                        "{} is runtime_settable but marked binding_required",
                        candidate.id
                    );
                }
            }
            "invariant_read_only" => {
                invariants += 1;
                if candidate.external_address.is_some()
                    || candidate
                        .invariant_kind
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || candidate
                        .review_evidence
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || candidate.owning_human_review.as_deref()
                        != Some("required_not_source_proven")
                    || candidate.applied
                    || candidate.behavior_oracle.is_some()
                    || candidate.caller_input_proof.is_some()
                    || candidate.binding_requirement.is_some()
                    || candidate.use_sites.is_empty()
                {
                    bail!("{} has an invalid pending-invariant shape", candidate.id);
                }
            }
            "binding_required" => {
                binding_required += 1;
                if candidate.external_address.is_some()
                    || candidate.caller_input_proof.is_some()
                    || candidate
                        .binding_requirement
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || candidate.use_sites.is_empty()
                    || !candidate.applied
                    || candidate
                        .behavior_oracle
                        .as_deref()
                        .is_none_or(str::is_empty)
                    || candidate.invariant_kind.is_some()
                    || candidate.review_evidence.is_some()
                    || candidate.owning_human_review.is_some()
                {
                    bail!("{} has an invalid binding_required shape", candidate.id);
                }
            }
            other => bail!("{} has unknown disposition `{other}`", candidate.id),
        }
    }
    let explicit = census
        .candidates
        .iter()
        .filter(|candidate| candidate.explicit_invariant_override)
        .count();
    if runtime != census.runtime_settable
        || runtime != census.advertised_runtime_settable
        || runtime != census.runtime_applied
        || runtime != census.externally_addressed_runtime_settable
        || census.unaddressed_runtime_settable != 0
        || addressed.len() != runtime
        || invariants != census.invariant_read_only
        || invariants != census.mechanical_invariant_dispositions
        || invariants != census.owning_human_review_required
        || explicit != census.explicit_invariant_overrides
        || binding_required != census.binding_required
        || runtime + invariants + binding_required != census.total
        || address_counts
            != census
                .address_kind_counts
                .iter()
                .map(|(key, value)| (key.as_str(), *value))
                .collect()
        || census.invariant_kind_counts.values().sum::<usize>() != invariants
    {
        bail!("optimization census summary does not match its candidate rows");
    }
    if census.source_coverage.production_rust_files_scanned == 0
        || census.source_coverage.unclassified_source_forms != 0
        || census
            .source_coverage
            .source_form_counts
            .values()
            .sum::<usize>()
            < census.total
        || census
            .source_coverage
            .candidate_row_counts
            .values()
            .sum::<usize>()
            != census.total
        || census.source_coverage.completeness_claim
            != "complete_for_declared_production_source_forms_not_mathematical_universe"
    {
        bail!("optimization census source coverage is incomplete or unclassified");
    }
    Ok(())
}

fn build_packet(
    census: &CensusFile,
    registry: &Registry,
    census_sha256: &str,
    boundary_registry_sha256: &str,
) -> Result<ReviewPacket> {
    let mut entries = Vec::new();
    for candidate in census
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == "invariant_read_only")
    {
        let invariant_kind = candidate
            .invariant_kind
            .as_deref()
            .context("validated invariant lacks a kind")?;
        let evidence = candidate
            .review_evidence
            .as_deref()
            .context("validated invariant lacks evidence")?;
        let boundary = unique_boundary(registry, &candidate.owner.path)?;
        let owner_person_id = boundary
            .primary
            .as_deref()
            .unwrap_or(&registry.enforcement.project_owner);
        let person = registry
            .people
            .iter()
            .find(|person| person.id == owner_person_id)
            .with_context(|| {
                format!(
                    "boundary `{}` owner `{owner_person_id}` is not registered",
                    boundary.id
                )
            })?;
        if person.kind != "human" || !matches!(person.role.as_str(), "owner" | "maintainer") {
            bail!(
                "boundary `{}` effective owner `{owner_person_id}` is not an owning human",
                boundary.id
            );
        }
        let owner_github = person.github.as_deref().with_context(|| {
            format!("owning human `{owner_person_id}` has no verifiable GitHub identity")
        })?;
        let projection = CandidateEvidence {
            candidate_id: &candidate.id,
            candidate_kind: &candidate.candidate_kind,
            rust_type: &candidate.rust_type,
            value: &candidate.value,
            owner: &candidate.owner,
            use_sites: &candidate.use_sites,
            invariant_kind,
            mechanical_review_evidence: evidence,
            explicit_invariant_override: candidate.explicit_invariant_override,
            tier2_id: candidate.tier2_id.as_deref(),
        };
        let candidate_evidence_sha256 = sha256(&serde_json::to_vec(&projection)?);
        let mut invariant_overlay_ids = registry
            .overlays
            .iter()
            .filter(|overlay| {
                overlay
                    .paths
                    .iter()
                    .any(|claim| crate::validate::claim_matches(claim, &candidate.owner.path))
            })
            .map(|overlay| overlay.id.clone())
            .collect::<Vec<_>>();
        invariant_overlay_ids.sort();
        entries.push(ReviewPacketEntry {
            candidate_id: candidate.id.clone(),
            candidate_evidence_sha256,
            candidate_kind: candidate.candidate_kind.clone(),
            rust_type: candidate.rust_type.clone(),
            value: candidate.value.clone(),
            owner: candidate.owner.clone(),
            use_sites: candidate.use_sites.clone(),
            invariant_kind: invariant_kind.to_owned(),
            mechanical_review_evidence: evidence.to_owned(),
            explicit_invariant_override: candidate.explicit_invariant_override,
            tier2_id: candidate.tier2_id.clone(),
            ownership_boundary_id: boundary.id.clone(),
            invariant_overlay_ids,
            owner_person_id: owner_person_id.to_owned(),
            owner_github: normalize_handle(owner_github),
            approval_token: String::new(),
        });
    }
    entries.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let batches = bind_approval_tokens(&mut entries, census_sha256, boundary_registry_sha256)?;
    Ok(ReviewPacket {
        schema_version: PACKET_SCHEMA_VERSION,
        census_schema_version: census.schema_version,
        census_sha256: census_sha256.to_owned(),
        boundary_registry_sha256: boundary_registry_sha256.to_owned(),
        required_reviews: entries.len(),
        required_batches: batches.len(),
        batches,
        candidates: entries,
    })
}

fn bind_approval_tokens(
    entries: &mut [ReviewPacketEntry],
    census_sha256: &str,
    boundary_registry_sha256: &str,
) -> Result<Vec<ReviewPacketBatch>> {
    let mut batches: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for entry in entries.iter() {
        batches
            .entry((
                entry.ownership_boundary_id.clone(),
                entry.owner_person_id.clone(),
            ))
            .or_default()
            .push((
                entry.candidate_id.clone(),
                entry.candidate_evidence_sha256.clone(),
            ));
    }
    let mut packet_batches = Vec::new();
    let mut tokens = BTreeMap::new();
    for ((boundary, owner), candidates) in &batches {
        let digest = sha256(&serde_json::to_vec(&ApprovalBatch {
            schema_version: PACKET_SCHEMA_VERSION,
            census_sha256,
            boundary_registry_sha256,
            ownership_boundary_id: boundary,
            owner_person_id: owner,
            candidates,
        })?);
        tokens.insert(
            (boundary.clone(), owner.clone()),
            format!(
                "ITERON-INVARIANT-OWNER-REVIEW-V2 boundary={boundary} owner={owner} batch_sha256={digest}"
            ),
        );
        let first = entries
            .iter()
            .find(|entry| {
                entry.ownership_boundary_id == *boundary && entry.owner_person_id == *owner
            })
            .context("approval batch has no packet entry")?;
        packet_batches.push(ReviewPacketBatch {
            ownership_boundary_id: boundary.clone(),
            owner_person_id: owner.clone(),
            owner_github: first.owner_github.clone(),
            candidate_count: candidates.len(),
            candidates: candidates
                .iter()
                .map(
                    |(candidate_id, candidate_evidence_sha256)| BatchCandidateEvidence {
                        candidate_id: candidate_id.clone(),
                        candidate_evidence_sha256: candidate_evidence_sha256.clone(),
                    },
                )
                .collect(),
            approval_token: tokens
                .get(&(boundary.clone(), owner.clone()))
                .context("new approval batch token is missing")?
                .clone(),
        });
    }
    for entry in entries {
        entry.approval_token = tokens
            .get(&(
                entry.ownership_boundary_id.clone(),
                entry.owner_person_id.clone(),
            ))
            .context("approval batch token is missing")?
            .clone();
    }
    Ok(packet_batches)
}

fn check_ledger(
    context: &ReviewContext,
    ledger: &ReviewLedger,
    github_reviews: &[GithubReview],
) -> Result<usize> {
    match ledger {
        ReviewLedger::Legacy(ledger) => check_legacy_ledger(context, ledger, github_reviews),
        ReviewLedger::Batch(ledger) => check_batch_ledger(context, ledger, github_reviews),
    }
}

fn check_legacy_ledger(
    context: &ReviewContext,
    ledger: &LegacyReviewLedger,
    github_reviews: &[GithubReview],
) -> Result<usize> {
    let mut errors = Vec::new();
    if ledger.schema_version != LEGACY_REVIEW_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported legacy ledger schema {}; expected {LEGACY_REVIEW_SCHEMA_VERSION}",
            ledger.schema_version
        ));
    }
    if ledger.census_sha256 != context.packet.census_sha256 {
        errors.push("ledger census_sha256 is stale".to_owned());
    }
    if ledger.boundary_registry_sha256 != context.packet.boundary_registry_sha256 {
        errors.push("ledger boundary_registry_sha256 is stale".to_owned());
    }
    if ledger.reviews.len() > context.packet.required_reviews {
        errors.push("ledger contains more rows than the invariant review packet".to_owned());
    }

    let packet_by_id: BTreeMap<_, _> = context
        .packet
        .candidates
        .iter()
        .map(|candidate| (candidate.candidate_id.as_str(), candidate))
        .collect();
    let mut evidence_by_id = BTreeMap::new();
    for review in github_reviews {
        if evidence_by_id.insert(review.id, review).is_some() {
            errors.push(format!(
                "GitHub review evidence repeats review id {}",
                review.id
            ));
        }
    }
    let mut latest_by_actor_commit: BTreeMap<(String, String), &GithubReview> = BTreeMap::new();
    for review in github_reviews.iter().filter(|review| {
        matches!(
            review.state.as_str(),
            "APPROVED" | "CHANGES_REQUESTED" | "DISMISSED"
        )
    }) {
        let Some(user) = &review.user else { continue };
        let key = (
            normalize_handle(&user.login),
            review.commit_id.to_ascii_lowercase(),
        );
        if latest_by_actor_commit
            .get(&key)
            .is_none_or(|previous| review.id > previous.id)
        {
            latest_by_actor_commit.insert(key, review);
        }
    }

    let mut seen_candidates = BTreeSet::new();
    let mut approved = BTreeSet::new();
    for review in &ledger.reviews {
        if !seen_candidates.insert(review.candidate_id.as_str()) {
            errors.push(format!(
                "ledger repeats candidate approval `{}`",
                review.candidate_id
            ));
            continue;
        }
        let Some(expected) = packet_by_id.get(review.candidate_id.as_str()) else {
            errors.push(format!(
                "ledger contains unknown or no-longer-invariant candidate `{}`",
                review.candidate_id
            ));
            continue;
        };
        if let Err(error) = validate_review_row(
            review,
            expected,
            &context.packet,
            &evidence_by_id,
            &latest_by_actor_commit,
        ) {
            errors.push(format!("{}: {error:#}", review.candidate_id));
        } else {
            approved.insert(review.candidate_id.as_str());
        }
    }

    let missing = context
        .packet
        .candidates
        .iter()
        .filter(|candidate| !approved.contains(candidate.candidate_id.as_str()))
        .collect::<Vec<_>>();
    if errors.is_empty() && missing.is_empty() {
        return Ok(approved.len());
    }
    let mut message = format!(
        "invariant owner review incomplete: {}/{} current approvals",
        approved.len(),
        context.packet.required_reviews
    );
    if !errors.is_empty() {
        message.push_str("\ninvalid or stale review evidence:\n- ");
        message.push_str(&errors.join("\n- "));
    }
    if !missing.is_empty() {
        message.push_str(&format!(
            "\nmissing owning-human approvals ({}):",
            missing.len()
        ));
        for candidate in missing {
            message.push_str(&format!(
                "\n- {} [{} -> {} {}]",
                candidate.candidate_id,
                candidate.ownership_boundary_id,
                candidate.owner_person_id,
                candidate.owner_github
            ));
        }
    }
    bail!(message)
}

fn validate_review_row(
    review: &InvariantReview,
    expected: &ReviewPacketEntry,
    packet: &ReviewPacket,
    evidence_by_id: &BTreeMap<u64, &GithubReview>,
    latest_by_actor_commit: &BTreeMap<(String, String), &GithubReview>,
) -> Result<()> {
    for (field, value, limit) in [
        ("candidate_id", review.candidate_id.as_str(), 1024usize),
        ("rationale", review.rationale.as_str(), MAX_TEXT_BYTES),
        ("github_reviewer", review.github_reviewer.as_str(), 256usize),
    ] {
        bounded_text(field, value, limit)?;
    }
    if review.candidate_evidence_sha256 != expected.candidate_evidence_sha256
        || review.census_sha256 != packet.census_sha256
        || review.boundary_registry_sha256 != packet.boundary_registry_sha256
    {
        bail!("candidate/source/census evidence digest is stale");
    }
    if review.ownership_boundary_id != expected.ownership_boundary_id
        || review.invariant_overlay_ids != expected.invariant_overlay_ids
        || review.owner_person_id != expected.owner_person_id
    {
        bail!("ownership boundary or registered owner does not match the packet");
    }
    if normalize_handle(&review.github_reviewer) != expected.owner_github {
        bail!("approval is from a non-owner or unregistered actor");
    }
    if review.decision != ReviewDecision::AffirmInvariant {
        bail!("owner rejected the invariant; reclassify the census before continuing");
    }
    if review.github_review_id == 0 || !valid_sha(&review.github_review_commit_sha) {
        bail!("GitHub review id or commit SHA is invalid");
    }
    let attestation = evidence_by_id
        .get(&review.github_review_id)
        .with_context(|| {
            format!(
                "GitHub review {} is absent; ledger-only/self-attested approval is forbidden",
                review.github_review_id
            )
        })?;
    let actor = attestation
        .user
        .as_ref()
        .map(|user| normalize_handle(&user.login))
        .context("GitHub review has no authenticated actor")?;
    if actor != expected.owner_github {
        bail!(
            "GitHub review actor `{actor}` is not owning human `{}`",
            expected.owner_github
        );
    }
    if attestation.state != "APPROVED"
        || !attestation
            .commit_id
            .eq_ignore_ascii_case(&review.github_review_commit_sha)
    {
        bail!("GitHub review is not an approval of the ledger's exact commit");
    }
    let token_present = attestation.body.as_deref().is_some_and(|body| {
        body.lines()
            .any(|line| line.trim() == expected.approval_token)
    });
    if !token_present {
        bail!("GitHub review body does not contain the exact deterministic approval token");
    }
    let key = (actor, review.github_review_commit_sha.to_ascii_lowercase());
    if latest_by_actor_commit
        .get(&key)
        .is_none_or(|latest| latest.state != "APPROVED")
    {
        bail!("owning human's latest decisive review for this commit is not APPROVED");
    }
    Ok(())
}

fn unique_boundary<'a>(registry: &'a Registry, path: &str) -> Result<&'a Boundary> {
    let matches = registry
        .boundaries
        .iter()
        .filter(|boundary| {
            boundary
                .paths
                .iter()
                .any(|claim| crate::validate::claim_matches(claim, path))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [boundary] => Ok(*boundary),
        [] => bail!("source evidence path `{path}` has no ownership boundary"),
        _ => bail!("source evidence path `{path}` has overlapping ownership boundaries"),
    }
}

fn parse_github_reviews(bytes: &[u8]) -> Result<Vec<GithubReview>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("GitHub review evidence is invalid JSON")?;
    let mut reviews = Vec::new();
    flatten_github_reviews(&value, &mut reviews)?;
    Ok(reviews)
}

fn flatten_github_reviews(
    value: &serde_json::Value,
    reviews: &mut Vec<GithubReview>,
) -> Result<()> {
    let rows = value
        .as_array()
        .context("GitHub review evidence must be an array (or --slurp nested arrays)")?;
    for row in rows {
        if row.is_array() {
            flatten_github_reviews(row, reviews)?;
        } else {
            reviews.push(
                serde_json::from_value(row.clone())
                    .context("GitHub review evidence contains an invalid review")?,
            );
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot stat {label} at {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        bail!("{label} is not a regular file or exceeds {max_bytes} bytes");
    }
    std::fs::read(path).with_context(|| format!("cannot read {label} at {}", path.display()))
}

fn bounded_text(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes || value.contains('\0') {
        bail!("{label} is empty, contains NUL, or exceeds {max_bytes} bytes");
    }
    Ok(())
}

fn normalize_handle(handle: &str) -> String {
    format!(
        "@{}",
        handle.trim().trim_start_matches('@').to_ascii_lowercase()
    )
}

fn valid_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
