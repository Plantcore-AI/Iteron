# Release engineering

Only the human Project Owner can authorize a Iteron release. A release is a
supply-chain event, not a local `cargo build` plus an uploaded binary.

## Preconditions

- The release commit is on protected `main` and all required checks are green.
- `CHANGELOG.md` contains the version and date.
- Workspace version and annotated SemVer tag match exactly.
- The release environment receives Owner approval.
- Immutable releases, tag protection, and full-SHA Action pins are enabled.
- The repository-level `RELEASE_IMMUTABLE_CONFIRMED=true` variable records the
  Owner's current immutable-release audit; it does not replace the GitHub
  repository setting.
- Third-party license policy, SBOM generation, provenance, and installer tests are
  green on clean hosted runners.

Before creating an immutable tag, dispatch `release.yml` against the exact
candidate commit. This preflight runs the same validation, legal-evidence, native
five-target test/package, SBOM, and attestation graph, but the publish and canary
canary jobs are structurally restricted to `refs/tags/v*`. All preflight jobs must
be green before the Owner creates the tag.

## Required artifacts

Every platform archive contains the `core` or `iteron.exe` binary, `LICENSE`, `README.md`, audited
third-party licenses and notices, an SPDX SBOM, and build metadata. The release
also publishes `SHA256SUMS`, a versioned machine-readable manifest, a receipt containing the
SHA-256 and size of the final canonical manifest bytes, the POSIX installer, and GitHub artifact
attestations. CLI stream versions come from each built binary's `--machine-contract` report and
remain distinct from the resident queue `protocol_version`.

The first supported targets are documented by the release workflow and
installation guide. A target enters the public distribution matrix only after a
native runner builds, tests, packages, and smoke-tests it successfully.

## Publication order

1. Validate tag, commit, source, dependencies, and legal policy.
2. Build and smoke-test each target independently.
3. Create deterministic archives and verify their contents.
4. Generate checksums, SBOMs, build provenance, the canonical release manifest, and its receipt.
5. Create a draft release and upload the complete set.
6. Compare uploaded asset digests with the local manifest.
7. Publish once, as the immutable latest release.
8. Content-verify and smoke every native artifact, then run fixed-version and `latest` POSIX
   installer canaries.

A failed draft is deleted or corrected before publication. An immutable published
release is never edited; publish a new patch version.

## Repository controls

Before creating a version tag, the Owner verifies the repository-level immutable
release setting through GitHub's administration API. The `release` environment
requires Owner approval and accepts only tags matching `v*`. Separate active tag
rulesets allow only the Owner to create version tags and prohibit every actor,
including the Owner, from moving or deleting an existing version tag.

The workflow fails closed if any release already exists for the tag. If the
workflow-created release does not become immutable after publication, it removes
only that newly created mutable release and fails; it never deletes the tag or an
unrelated draft.

## Verification

Maintainers use `gh release verify`, `gh release verify-asset`, and
`gh attestation verify` against the release tag, workflow identity, source ref,
and source digest. A checksum fetched over the same channel as an archive detects
corruption but is not independent publisher authentication.

The manifest receipt is a stable content identifier, not a signature. It lets a consumer reject
one changed byte before execution, while repository controls and attestations provide separate
source-authenticity evidence. Windows Authenticode and other platform signing remain outside this
bounded artifact addition.

Manual uploads and local-machine release builds are not accepted release evidence.
