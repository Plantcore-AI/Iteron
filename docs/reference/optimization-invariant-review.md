# Optimization invariant owner review

`governance/optimization-census.json` records mechanical source evidence. It does not prove that a
human agreed that a value is a host invariant. The invariant review gate keeps that distinction
fail-closed.

## Review packet

Generate the source-current, deterministic packet:

```sh
cargo run --locked -p iteron-xtask -- tunables invariant-review-packet > /tmp/invariant-review-packet.json
```

The command first regenerates the census in memory and rejects a stale committed artifact. Each
invariant packet row contains its exact candidate id, source owner and use sites, mechanical
evidence, evidence SHA-256, primary ownership boundary, matching invariant overlays, and effective
human owner from `governance/boundaries.json`. Packet schema v2 also emits a `batches` array with
exactly one row per owner × primary-boundary pair. Each batch has one `approval_token`; its digest
covers the complete candidate-id/evidence-digest set plus both the census and boundary-registry
digests. Candidate rows remain in the packet so reviewers and the checker can inspect every source
fact independently.

## Human approval

The registered owning human must inspect every row in their batch and submit a GitHub
`APPROVED` review whose body contains the packet's exact `approval_token` on its own line. An agent
must not create or copy an approval into the ledger. If any row is quality-affecting rather than a
true host invariant, the owner chooses `reclassify_runtime_settable`; the census must then be fixed
and a new packet generated.

Generate one PR review body containing every current batch token:

```sh
cargo run --locked -p iteron-xtask -- tunables invariant-review-body > /tmp/invariant-review-body.md
```

This prepares review text only. It does not submit a review, populate the ledger, or claim an
approval. The owning human must review the packet and personally submit the GitHub review.

The preferred ledger schema v2 uses one row in `batches` per owner × boundary. That row records:

- the complete `candidate_evidence` list of candidate ids and evidence digests;
- the census digest, boundary-registry digest, exact boundary, owner id, and GitHub handle;
- `affirm_invariant` plus a non-empty human rationale; and
- the GitHub review id and exact reviewed commit SHA.

`governance/optimization-invariant-reviews.json` intentionally starts with an empty schema-v2
`batches` array bound to the current census and boundary-registry digests. Empty means pending, not
approved. The checker still accepts strict schema-v1 candidate rows during migration, but new
approvals use schema v2 and require externally verifiable owning-human evidence.

## Verification

Fetch review evidence from GitHub in CI or another authenticated environment, then run:

```sh
gh api --paginate --slurp repos/Plantcore-AI/Iteron/pulls/PR_NUMBER/reviews > /tmp/invariant-reviews.json
cargo run --locked -p iteron-xtask -- tunables check-invariant-reviews \
  --reviews /tmp/invariant-reviews.json
```

The checker expands every v2 batch and verifies each candidate evidence digest against the packet.
It rejects a stale census or registry, partial/duplicate/unknown batches or candidates, changed
source evidence, wrong boundaries or owners, non-owner actors, ledger-only/self-attested claims,
merge-without-review claims, non-`APPROVED` or superseded GitHub reviews, wrong commits, and missing
approval tokens. The gate succeeds only when every current invariant candidate has an external
owning-human attestation.

## Freeze manifest

`governance/optimization-invariant-review-freeze.json` records the exact packet the owner is
attesting to: the census digest, the boundary-registry digest, the candidate count, and one
`approval_token` per owner × ownership-boundary batch. Each `batch_sha256` already commits to that batch's
exact candidate-id/evidence-digest pairs, so the manifest is complete evidence without restating
every row.

Regenerate it from the source-current packet and confirm it is unchanged before approving:

```sh
cargo run --locked -p iteron-xtask -- tunables invariant-review-packet > /tmp/packet.json
```

If the manifest and the regenerated packet disagree on any digest, the census moved and every
prior approval token is void.
