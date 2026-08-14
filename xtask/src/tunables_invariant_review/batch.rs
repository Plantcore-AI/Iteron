use super::*;

pub(super) fn check_batch_ledger(
    context: &ReviewContext,
    ledger: &BatchReviewLedger,
    github_reviews: &[GithubReview],
) -> Result<usize> {
    let mut errors = Vec::new();
    if ledger.schema_version != BATCH_REVIEW_SCHEMA_VERSION {
        errors.push(format!(
            "unsupported batch ledger schema {}; expected {BATCH_REVIEW_SCHEMA_VERSION}",
            ledger.schema_version
        ));
    }
    if ledger.census_sha256 != context.packet.census_sha256 {
        errors.push("ledger census_sha256 is stale".to_owned());
    }
    if ledger.boundary_registry_sha256 != context.packet.boundary_registry_sha256 {
        errors.push("ledger boundary_registry_sha256 is stale".to_owned());
    }
    if ledger.batches.len() > context.packet.required_batches {
        errors.push("ledger contains more batches than the invariant review packet".to_owned());
    }

    let expected_batches: BTreeMap<_, _> = context
        .packet
        .batches
        .iter()
        .map(|batch| {
            (
                (
                    batch.ownership_boundary_id.as_str(),
                    batch.owner_person_id.as_str(),
                ),
                batch,
            )
        })
        .collect();
    let packet_candidates: BTreeMap<_, _> = context
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

    let mut seen_batches = BTreeSet::new();
    let mut approved_candidates = BTreeSet::new();
    for review in &ledger.batches {
        let key = (
            review.ownership_boundary_id.as_str(),
            review.owner_person_id.as_str(),
        );
        if !seen_batches.insert(key) {
            errors.push(format!(
                "ledger repeats owner×boundary batch `{} × {}`",
                review.ownership_boundary_id, review.owner_person_id
            ));
            continue;
        }
        let Some(expected) = expected_batches.get(&key) else {
            errors.push(format!(
                "ledger contains unknown owner×boundary batch `{} × {}`",
                review.ownership_boundary_id, review.owner_person_id
            ));
            continue;
        };
        if let Err(error) = validate_batch_review(
            review,
            expected,
            &context.packet,
            &packet_candidates,
            &evidence_by_id,
            &latest_by_actor_commit,
        ) {
            errors.push(format!(
                "{} × {}: {error:#}",
                review.ownership_boundary_id, review.owner_person_id
            ));
            continue;
        }
        approved_candidates.extend(
            expected
                .candidates
                .iter()
                .map(|candidate| candidate.candidate_id.as_str()),
        );
    }

    let missing_batches = context
        .packet
        .batches
        .iter()
        .filter(|batch| {
            !seen_batches.contains(&(
                batch.ownership_boundary_id.as_str(),
                batch.owner_person_id.as_str(),
            ))
        })
        .collect::<Vec<_>>();
    if errors.is_empty()
        && missing_batches.is_empty()
        && approved_candidates.len() == context.packet.required_reviews
    {
        return Ok(approved_candidates.len());
    }
    let mut message = format!(
        "invariant owner review incomplete: {}/{} candidate approvals across {}/{} batches",
        approved_candidates.len(),
        context.packet.required_reviews,
        context
            .packet
            .required_batches
            .saturating_sub(missing_batches.len()),
        context.packet.required_batches
    );
    if !errors.is_empty() {
        message.push_str("\ninvalid or stale batch review evidence:\n- ");
        message.push_str(&errors.join("\n- "));
    }
    if !missing_batches.is_empty() {
        message.push_str(&format!(
            "\nmissing owning-human approval batches ({}):",
            missing_batches.len()
        ));
        for batch in missing_batches {
            message.push_str(&format!(
                "\n- {} [{} {} -> {}]",
                batch.ownership_boundary_id,
                batch.candidate_count,
                batch.owner_person_id,
                batch.owner_github
            ));
        }
    }
    bail!(message)
}

fn validate_batch_review<'a>(
    review: &InvariantBatchReview,
    expected: &ReviewPacketBatch,
    packet: &ReviewPacket,
    packet_candidates: &BTreeMap<&'a str, &'a ReviewPacketEntry>,
    evidence_by_id: &BTreeMap<u64, &GithubReview>,
    latest_by_actor_commit: &BTreeMap<(String, String), &GithubReview>,
) -> Result<()> {
    for (field, value, limit) in [
        (
            "ownership_boundary_id",
            review.ownership_boundary_id.as_str(),
            1024usize,
        ),
        (
            "owner_person_id",
            review.owner_person_id.as_str(),
            1024usize,
        ),
        ("rationale", review.rationale.as_str(), MAX_TEXT_BYTES),
        ("github_reviewer", review.github_reviewer.as_str(), 256usize),
    ] {
        bounded_text(field, value, limit)?;
    }
    if review.census_sha256 != packet.census_sha256
        || review.boundary_registry_sha256 != packet.boundary_registry_sha256
    {
        bail!("census or boundary digest is stale");
    }
    if review.ownership_boundary_id != expected.ownership_boundary_id
        || review.owner_person_id != expected.owner_person_id
    {
        bail!("ownership boundary or registered owner does not match the packet");
    }
    if normalize_handle(&review.github_reviewer) != expected.owner_github {
        bail!("approval is from a non-owner or unregistered actor");
    }
    if review.decision != ReviewDecision::AffirmInvariant {
        bail!("owner rejected the batch; reclassify the census before continuing");
    }
    let mut actual = BTreeMap::new();
    for candidate in &review.candidate_evidence {
        bounded_text("candidate_id", &candidate.candidate_id, 1024)?;
        if actual
            .insert(
                candidate.candidate_id.as_str(),
                candidate.candidate_evidence_sha256.as_str(),
            )
            .is_some()
        {
            bail!("batch repeats candidate `{}`", candidate.candidate_id);
        }
        let packet_candidate = packet_candidates
            .get(candidate.candidate_id.as_str())
            .with_context(|| {
                format!(
                    "batch contains unknown candidate `{}`",
                    candidate.candidate_id
                )
            })?;
        if candidate.candidate_evidence_sha256 != packet_candidate.candidate_evidence_sha256 {
            bail!(
                "candidate `{}` source evidence digest is stale",
                candidate.candidate_id
            );
        }
        if packet_candidate.ownership_boundary_id != expected.ownership_boundary_id
            || packet_candidate.owner_person_id != expected.owner_person_id
        {
            bail!(
                "candidate `{}` belongs to another owner×boundary",
                candidate.candidate_id
            );
        }
    }
    let expected_evidence = expected
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.candidate_id.as_str(),
                candidate.candidate_evidence_sha256.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual != expected_evidence {
        bail!("batch candidate evidence set is incomplete or not exact");
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
    if !attestation.body.as_deref().is_some_and(|body| {
        body.lines()
            .any(|line| line.trim() == expected.approval_token)
    }) {
        bail!("GitHub review body does not contain the exact deterministic batch token");
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
