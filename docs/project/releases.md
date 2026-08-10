# Releases and changelog

Iteron publishes immutable pre-alpha releases. A published artifact has passed
the release workflow; it does not imply stable CLI, configuration, record, or
runtime compatibility.

## Release artifacts

The [GitHub Releases](https://github.com/Plantcore-AI/Iteron/releases) page is the
canonical binary distribution channel. Each accepted release contains:

- native macOS/Linux archives and the bounded Windows x86-64 one-shot ZIP;
- a version-bound `install.sh` and `SHA256SUMS`;
- `release-manifest.json` with commit, CLI stream, target, size, and digest evidence;
- `release-manifest.receipt.json` identifying the exact final manifest bytes;
- Apache-2.0 and third-party license and notice material;
- per-target SPDX SBOMs;
- build provenance, SBOM attestations, and offline bundles.

Published releases are protected by GitHub immutable releases. Version tags are
Owner-created and cannot be moved or deleted. If a correction is required, the
project publishes a new patch version.

See the [installation guide](../getting-started/installation.md) for curl,
version pinning, supported targets, verification, and uninstall instructions.

## Changelog

The source repository's
[CHANGELOG.md](https://github.com/Plantcore-AI/Iteron/blob/main/CHANGELOG.md) is the
canonical human-readable change history. GitHub release notes identify the exact
artifact set for a tag.

Do not infer release support from the workspace version alone. During `0.0.x`,
public interfaces may change between releases.

## Acceptance gate

A release is accepted only when all of the following are true:

- the annotated SemVer tag resolves to the current protected `main` commit;
- source, ownership, formatting, clippy, and full workspace tests pass;
- every target is built, tested, packaged, and smoke-tested natively;
- archive structure, licenses, notices, checksums, SBOMs, and provenance pass;
- the Owner approves the protected `release` environment;
- the published release reports itself immutable;
- content-addressed native artifact canaries pass on all five targets, and fixed-version plus
  `latest` curl canaries pass on the four POSIX installer targets.

Maintainers follow the detailed [release guide](../development/releasing.md).
