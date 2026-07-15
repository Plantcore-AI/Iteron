# Release engineering

Only the human Project Owner can authorize a Core Code release. A release is a
supply-chain event, not a local `cargo build` plus an uploaded binary.

## Preconditions

- The release commit is on protected `main` and all required checks are green.
- `CHANGELOG.md` contains the version and date.
- Workspace version and annotated SemVer tag match exactly.
- The release environment receives Owner approval.
- Immutable releases, tag protection, and full-SHA Action pins are enabled.
- Third-party license policy, SBOM generation, provenance, and installer tests are
  green on clean hosted runners.

## Required artifacts

Every platform archive contains the `core` binary, `LICENSE`, `README.md`, audited
third-party licenses and notices, an SPDX SBOM, and build metadata. The release
also publishes `SHA256SUMS`, a versioned machine-readable manifest, the installer,
and GitHub artifact attestations.

The first supported targets are documented by the release workflow and
installation guide. A target enters the installer allowlist only after a native
runner builds, tests, packages, and installs it successfully.

## Publication order

1. Validate tag, commit, source, dependencies, and legal policy.
2. Build and smoke-test each target independently.
3. Create deterministic archives and verify their contents.
4. Generate checksums, SBOMs, build provenance, and the release manifest.
5. Create a draft release and upload the complete set.
6. Compare uploaded asset digests with the local manifest.
7. Publish once, as the immutable latest release.
8. Run fixed-version and `latest` public installer canaries.

A failed draft is deleted or corrected before publication. An immutable published
release is never edited; publish a new patch version.

## Verification

Maintainers use `gh release verify`, `gh release verify-asset`, and
`gh attestation verify` against the release tag, workflow identity, source ref,
and source digest. A checksum fetched over the same channel as an archive detects
corruption but is not independent publisher authentication.

Manual uploads and local-machine release builds are not accepted release evidence.
