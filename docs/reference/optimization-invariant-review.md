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
human owner from `governance/boundaries.json`. The packet also gives one `approval_token` per
owner/boundary batch. A batch digest covers the exact candidate-id/evidence-digest pairs plus both
the census and boundary-registry digests.

## Human approval

The registered owning human must inspect every row in their batch and submit a GitHub
`APPROVED` review whose body contains the packet's exact `approval_token` on its own line. An agent
must not create or copy an approval into the ledger. If any row is quality-affecting rather than a
true host invariant, the owner chooses `reclassify_runtime_settable`; the census must then be fixed
and a new packet generated.

For each inspected candidate, the human-authored ledger row records:

- the candidate id, candidate evidence digest, census digest, and boundary-registry digest;
- the exact ownership boundary, invariant overlays, registered owner id, and GitHub handle;
- `affirm_invariant` plus a non-empty human rationale; and
- the GitHub review id and exact reviewed commit SHA.

`governance/optimization-invariant-reviews.json` intentionally starts with an empty `reviews`
array. Empty means pending, not approved.

## Verification

Fetch review evidence from GitHub in CI or another authenticated environment, then run:

```sh
gh api --paginate --slurp repos/Plantcore-AI/core/pulls/PR_NUMBER/reviews > /tmp/invariant-reviews.json
cargo run --locked -p iteron-xtask -- tunables check-invariant-reviews \
  --reviews /tmp/invariant-reviews.json
```

The checker rejects a stale census or registry, duplicate or unknown candidates, changed source
evidence, wrong boundaries or overlays, non-owner actors, ledger-only/self-attested claims,
non-`APPROVED` or superseded GitHub reviews, wrong commits, and missing approval tokens. It reports
every candidate still lacking a valid owning-human approval. The gate succeeds only when all
current invariant candidates have external owner attestations.
