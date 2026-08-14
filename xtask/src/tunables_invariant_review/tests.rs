use super::*;

const CENSUS_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REGISTRY_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn context() -> ReviewContext {
    ReviewContext {
        packet: ReviewPacket {
            schema_version: PACKET_SCHEMA_VERSION,
            census_schema_version: CENSUS_SCHEMA_VERSION,
            census_sha256: CENSUS_DIGEST.to_owned(),
            boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
            required_reviews: 1,
            required_batches: 1,
            batches: vec![ReviewPacketBatch {
                ownership_boundary_id: "agents-runtime".to_owned(),
                owner_person_id: "core-owner".to_owned(),
                owner_github: "@human-owner".to_owned(),
                candidate_count: 1,
                candidates: vec![BatchCandidateEvidence {
                    candidate_id: "agents.catalog.domain".to_owned(),
                    candidate_evidence_sha256: "33".repeat(32),
                }],
                approval_token: "ITERON-INVARIANT-OWNER-REVIEW-V2 test-token".to_owned(),
            }],
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
                approval_token: "ITERON-INVARIANT-OWNER-REVIEW-V2 test-token".to_owned(),
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
    ReviewLedger::Legacy(LegacyReviewLedger {
        schema_version: LEGACY_REVIEW_SCHEMA_VERSION,
        census_sha256: CENSUS_DIGEST.to_owned(),
        boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
        reviews: review_rows,
    })
}

fn batch_review() -> InvariantBatchReview {
    let mut context = context();
    let expected = context.packet.batches.remove(0);
    InvariantBatchReview {
        ownership_boundary_id: expected.ownership_boundary_id,
        owner_person_id: expected.owner_person_id,
        github_reviewer: expected.owner_github,
        candidate_evidence: expected.candidates,
        census_sha256: CENSUS_DIGEST.to_owned(),
        boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
        decision: ReviewDecision::AffirmInvariant,
        rationale: "Reviewed every candidate and its mechanical evidence.".to_owned(),
        github_review_id: 7,
        github_review_commit_sha: COMMIT.to_owned(),
    }
}

fn batch_ledger(batch_rows: Vec<InvariantBatchReview>) -> ReviewLedger {
    ReviewLedger::Batch(BatchReviewLedger {
        schema_version: BATCH_REVIEW_SCHEMA_VERSION,
        census_sha256: CENSUS_DIGEST.to_owned(),
        boundary_registry_sha256: REGISTRY_DIGEST.to_owned(),
        batches: batch_rows,
    })
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
    assert!(parse_review_ledger(raw.as_bytes()).is_err());
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
fn batch_v2_accepts_one_exact_owner_boundary_row_and_rechecks_each_digest() {
    let context = context();
    let token = context.packet.batches[0].approval_token.as_str();
    let evidence = vec![github_review(7, "APPROVED", "human-owner", Some(token))];
    assert_eq!(
        check_ledger(&context, &batch_ledger(vec![batch_review()]), &evidence).unwrap(),
        1
    );

    let mut stale = batch_review();
    stale.candidate_evidence[0].candidate_evidence_sha256 = "44".repeat(32);
    assert!(
        check_ledger(&context, &batch_ledger(vec![stale]), &evidence)
            .unwrap_err()
            .to_string()
            .contains("source evidence digest is stale")
    );

    let agent = vec![github_review(7, "APPROVED", "agent-bot", Some(token))];
    assert!(
        check_ledger(&context, &batch_ledger(vec![batch_review()]), &agent)
            .unwrap_err()
            .to_string()
            .contains("not owning human")
    );
    assert!(
        check_ledger(&context, &batch_ledger(vec![batch_review()]), &[])
            .unwrap_err()
            .to_string()
            .contains("self-attested approval is forbidden")
    );
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
