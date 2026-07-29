# Releases and changelog

Core Code defines an immutable pre-alpha release process, but does not currently
claim an accepted binary release. Native receipts for the complete target matrix
and the corresponding public assets are still pending. A future published
artifact must pass the release workflow; publication will not imply stable CLI,
configuration, record, or runtime compatibility.

## Release artifacts

The [GitHub Releases](https://github.com/Plantcore-AI/core/releases) page will be
the canonical binary distribution channel. An accepted release must contain:

- native macOS, Linux, and Windows archives for the documented target matrix;
- a version-bound `install.sh` and `SHA256SUMS`;
- `release-manifest.json` with commit, size, and digest evidence;
- Apache-2.0 and third-party license and notice material;
- per-target SPDX SBOMs;
- build provenance, SBOM attestations, and offline bundles.

Accepted releases must be protected by GitHub immutable releases. Version tags
are Owner-created and cannot be moved or deleted. If a published release needs a
correction, the project must publish a new patch version.

See the [installation guide](../getting-started/installation.md) for the planned
curl path, version pinning, required targets, verification, and uninstall
instructions.

## Changelog

The source repository's
[CHANGELOG.md](https://github.com/Plantcore-AI/core/blob/main/CHANGELOG.md) is the
canonical human-readable change history. GitHub release notes identify the exact
artifact set for a tag.

Do not infer release support from the workspace version alone. During `0.0.x`,
public interfaces may change between releases.

## Acceptance gate

A binary release may be accepted only when all of the following are true:

- the annotated SemVer tag resolves to the current protected `main` commit;
- source, ownership, formatting, clippy, and full workspace tests pass;
- every target is built, tested, packaged, and smoke-tested natively;
- archive structure, licenses, notices, checksums, SBOMs, and provenance pass;
- the Owner approves the protected `release` environment;
- the published release reports itself immutable;
- fixed-version and `latest` public-download canaries pass on all five required
  release targets.

Maintainers follow the detailed [release guide](../development/releasing.md).
