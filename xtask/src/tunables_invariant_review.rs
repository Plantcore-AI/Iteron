//! Fail-closed owning-human review gate for optimization-census invariants.
//!
//! Mechanical source inspection is not human approval. This module emits a deterministic packet
//! and only accepts ledger rows backed by a current GitHub `APPROVED` review from the human who
//! owns the candidate's source boundary. The review body must contain the packet's exact batch
//! token, which binds every candidate id and source-evidence digest in that boundary.

use crate::model::{Boundary, Registry};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CENSUS_PATH: &str = "governance/optimization-census.json";
const LEDGER_PATH: &str = "governance/optimization-invariant-reviews.json";
const BOUNDARIES_PATH: &str = "governance/boundaries.json";
const CENSUS_SCHEMA_VERSION: u16 = 3;
const REVIEW_SCHEMA_VERSION: u16 = 1;
const PACKET_SCHEMA_VERSION: u16 = 1;
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
    advertised_runtime_settable: usize,
    runtime_applied: usize,
    externally_addressed_runtime_settable: usize,
    unaddressed_runtime_settable: usize,
    mechanical_invariant_dispositions: usize,
    owning_human_review_required: usize,
    explicit_invariant_overrides: usize,
    address_kind_counts: BTreeMap<String, usize>,
    invariant_kind_counts: BTreeMap<String, usize>,
    candidates: Vec<CensusCandidate>,
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
struct CensusCandidate {
    id: String,
    candidate_kind: String,
    rust_type: String,
    value: String,
    owner: CensusOwner,
    use_sites: Vec<CensusUseSite>,
    disposition: String,
    external_address: Option<ExternalAddress>,
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
    candidates: Vec<ReviewPacketEntry>,
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
struct ReviewLedger {
    schema_version: u16,
    census_sha256: String,
    boundary_registry_sha256: String,
    reviews: Vec<InvariantReview>,
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

pub(crate) fn check(root: &Path, review_evidence: Option<&Path>) -> Result<()> {
    let context = load_context(root)?;
    let ledger_bytes = read_bounded(&root.join(LEDGER_PATH), MAX_LEDGER_BYTES, "review ledger")?;
    let ledger: ReviewLedger = serde_json::from_slice(&ledger_bytes)
        .with_context(|| format!("{LEDGER_PATH} is not a valid schema-v1 review ledger"))?;
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
        .with_context(|| format!("{CENSUS_PATH} is not a valid schema-v3 census"))?;
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
                    || candidate.use_sites.is_empty()
                {
                    bail!("{} has an invalid pending-invariant shape", candidate.id);
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
    bind_approval_tokens(&mut entries, census_sha256, boundary_registry_sha256)?;
    Ok(ReviewPacket {
        schema_version: PACKET_SCHEMA_VERSION,
        census_schema_version: census.schema_version,
        census_sha256: census_sha256.to_owned(),
        boundary_registry_sha256: boundary_registry_sha256.to_owned(),
        required_reviews: entries.len(),
        candidates: entries,
    })
}

fn bind_approval_tokens(
    entries: &mut [ReviewPacketEntry],
    census_sha256: &str,
    boundary_registry_sha256: &str,
) -> Result<()> {
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
                "ITERON-INVARIANT-OWNER-REVIEW-V1 boundary={boundary} owner={owner} batch_sha256={digest}"
            ),
        );
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
    Ok(())
}

fn check_ledger(
    context: &ReviewContext,
    ledger: &ReviewLedger,
    github_reviews: &[GithubReview],
) -> Result<usize> {
    let mut errors = Vec::new();
    if ledger.schema_version != REVIEW_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported ledger schema {}; expected {REVIEW_SCHEMA_VERSION}",
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
mod tests {
    use super::*;

    const CENSUS_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const REGISTRY_DIGEST: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn context() -> ReviewContext {
        ReviewContext {
            packet: ReviewPacket {
                schema_version: PACKET_SCHEMA_VERSION,
                census_schema_version: CENSUS_SCHEMA_VERSION,
                census_sha256: CENSUS_DIGEST.to_owned(),
                boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
                required_reviews: 1,
                candidates: vec![ReviewPacketEntry {
                    candidate_id: "agents.catalog.domain".to_owned(),
                    candidate_evidence_sha256: "33".repeat(32),
                    candidate_kind: "const".to_owned(),
                    rust_type: "&[u8]".to_owned(),
                    value: "b\"domain\"".to_owned(),
                    owner: CensusOwner {
                        krate: "agents".to_owned(),
                        path: "crates/agents/src/catalog.rs".to_owned(),
                        symbol: "AgentCatalog::DOMAIN".to_owned(),
                    },
                    use_sites: vec![CensusUseSite {
                        path: "crates/agents/src/catalog.rs".to_owned(),
                        line: 10,
                        evidence: "Rust path reference".to_owned(),
                    }],
                    invariant_kind: "identity".to_owned(),
                    mechanical_review_evidence: "mechanical only".to_owned(),
                    explicit_invariant_override: false,
                    tier2_id: Some("agents.catalog.domain".to_owned()),
                    ownership_boundary_id: "agents-runtime".to_owned(),
                    invariant_overlay_ids: vec!["public-compatibility".to_owned()],
                    owner_person_id: "core-owner".to_owned(),
                    owner_github: "@human-owner".to_owned(),
                    approval_token: "ITERON-INVARIANT-OWNER-REVIEW-V1 test-token".to_owned(),
                }],
            },
        }
    }

    fn review() -> InvariantReview {
        let expected = &context().packet.candidates[0];
        InvariantReview {
            candidate_id: expected.candidate_id.clone(),
            candidate_evidence_sha256: expected.candidate_evidence_sha256.clone(),
            census_sha256: CENSUS_DIGEST.to_owned(),
            boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
            ownership_boundary_id: expected.ownership_boundary_id.clone(),
            invariant_overlay_ids: expected.invariant_overlay_ids.clone(),
            owner_person_id: expected.owner_person_id.clone(),
            github_reviewer: expected.owner_github.clone(),
            decision: ReviewDecision::AffirmInvariant,
            rationale: "Reviewed stable identity and all production uses.".to_owned(),
            github_review_id: 7,
            github_review_commit_sha: COMMIT.to_owned(),
        }
    }

    fn ledger(review_rows: Vec<InvariantReview>) -> ReviewLedger {
        ReviewLedger {
            schema_version: REVIEW_SCHEMA_VERSION,
            census_sha256: CENSUS_DIGEST.to_owned(),
            boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
            reviews: review_rows,
        }
    }

    fn github_review(id: u64, state: &str, actor: &str, body: Option<&str>) -> GithubReview {
        GithubReview {
            id,
            user: Some(GithubReviewUser {
                login: actor.to_owned(),
            }),
            state: state.to_owned(),
            commit_id: COMMIT.to_owned(),
            body: body.map(str::to_owned),
        }
    }

    #[test]
    fn strict_parser_rejects_self_attested_or_unknown_fields() {
        let raw = format!(
            r#"{{
              "schema_version": 1,
              "census_sha256": "{CENSUS_DIGEST}",
              "boundary_registry_sha256": "{REGISTRY_DIGEST}",
              "reviews": [],
              "self_attested": true
            }}"#
        );
        assert!(serde_json::from_str::<ReviewLedger>(&raw).is_err());
    }

    #[test]
    fn checker_accepts_only_external_current_owner_approval() {
        let context = context();
        let token = context.packet.candidates[0].approval_token.as_str();
        let evidence = vec![github_review(7, "APPROVED", "human-owner", Some(token))];
        assert_eq!(
            check_ledger(&context, &ledger(vec![review()]), &evidence).unwrap(),
            1
        );

        let error = check_ledger(&context, &ledger(vec![review()]), &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("ledger-only/self-attested approval is forbidden"));

        let agent = vec![github_review(7, "APPROVED", "agent-bot", Some(token))];
        let error = check_ledger(&context, &ledger(vec![review()]), &agent)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is not owning human"));
    }

    #[test]
    fn checker_rejects_stale_unknown_duplicate_and_non_owner_rows() {
        let context = context();
        let token = context.packet.candidates[0].approval_token.as_str();
        let evidence = vec![github_review(7, "APPROVED", "human-owner", Some(token))];

        let mut stale = review();
        stale.candidate_evidence_sha256 = "44".repeat(32);
        assert!(
            check_ledger(&context, &ledger(vec![stale]), &evidence)
                .unwrap_err()
                .to_string()
                .contains("evidence digest is stale")
        );

        let mut unknown = review();
        unknown.candidate_id = "unknown.candidate".to_owned();
        assert!(
            check_ledger(&context, &ledger(vec![unknown]), &evidence)
                .unwrap_err()
                .to_string()
                .contains("unknown or no-longer-invariant")
        );

        let duplicate = review();
        assert!(
            check_ledger(
                &context,
                &ledger(vec![duplicate.clone(), duplicate]),
                &evidence
            )
            .unwrap_err()
            .to_string()
            .contains("repeats candidate approval")
        );

        let mut non_owner = review();
        non_owner.github_reviewer = "@not-the-owner".to_owned();
        assert!(
            check_ledger(&context, &ledger(vec![non_owner]), &evidence)
                .unwrap_err()
                .to_string()
                .contains("non-owner")
        );
    }

    #[test]
    fn checker_reports_missing_and_rejects_revoked_or_unbound_reviews() {
        let context = context();
        let error = check_ledger(&context, &ledger(Vec::new()), &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing owning-human approvals (1)"));
        assert!(error.contains("agents.catalog.domain"));

        let token = context.packet.candidates[0].approval_token.as_str();
        let revoked = vec![
            github_review(7, "APPROVED", "human-owner", Some(token)),
            github_review(8, "CHANGES_REQUESTED", "human-owner", None),
        ];
        assert!(
            check_ledger(&context, &ledger(vec![review()]), &revoked)
                .unwrap_err()
                .to_string()
                .contains("latest decisive review")
        );

        let unbound = vec![github_review(7, "APPROVED", "human-owner", None)];
        assert!(
            check_ledger(&context, &ledger(vec![review()]), &unbound)
                .unwrap_err()
                .to_string()
                .contains("exact deterministic approval token")
        );
    }
}
