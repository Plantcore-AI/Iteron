# Releases and changelog

Iteron publishes immutable pre-alpha artifacts. Availability does not imply a
stable CLI, configuration, record, or runtime compatibility promise.

## Published history

The [GitHub Releases](https://github.com/Plantcore-AI/Iteron/releases) page is the
canonical binary channel. Its release notes are authoritative for the exact
assets attached to each tag.

| Tag | Published | Build origin | Native archives |
| --- | --- | --- | --- |
| `v0.0.1` | 2026-08-06 | local macOS build | `aarch64-apple-darwin` |
| `v0.0.2` | 2026-08-07 | local macOS build | `aarch64-apple-darwin` |
| `v0.0.3` | 2026-08-10 | local macOS build | `aarch64-apple-darwin` |
| `v0.0.4` | 2026-08-10 | local macOS build | `aarch64-apple-darwin` |
| `v0.0.5` | 2026-08-14 | release workflow | release page is authoritative |

The first four were produced while hosted Actions capacity was unavailable. They carry
content-addressed manifests, receipts, checksums, legal evidence, and SBOMs, but
not GitHub OIDC attestations or the complete three-target matrix. They are useful
historical pre-alpha artifacts and do **not** satisfy the accepted workflow
release contract below.

`v0.0.5` is the current pre-alpha release. Its release manifest and GitHub asset
list, rather than this summary table, are authoritative for its exact targets and
attestations.

## Accepted release artifacts

The supported distribution matrix is macOS and Linux:

- `aarch64-apple-darwin`;
- `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl`.

An accepted release contains the targets named by its release notes and, for the
complete supported matrix:

- three native macOS/Linux archives;
- a version-bound `install.sh` and `SHA256SUMS`;
- `release-manifest.json` with commit, CLI stream, target, size, and digest
  evidence;
- `release-manifest.receipt.json` identifying the exact final manifest bytes;
- Apache-2.0 and third-party license and notice material;
- per-target SPDX SBOMs;
- GitHub build provenance, SBOM attestations, and offline bundles.

The only executable payload is `iteron`. The repository research binary `iteron-harness`, its
fixture optimizer, and its protocol development assets are not release or installer payloads.
Researchers build that binary explicitly from a reviewed source checkout; see the
[research harness protocol](../reference/research-harness-protocol.md).

Windows is not a release target. Published releases are expected to use GitHub's
immutable-release control; if a correction is required, the project publishes a
new patch version rather than moving a tag or editing assets.

See the [installation guide](../getting-started/installation.md) for current
availability, version pinning, verification, and uninstall instructions.

## Changelog

The source repository's
[CHANGELOG.md](https://github.com/Plantcore-AI/Iteron/blob/main/CHANGELOG.md) is
the canonical human-readable change history. GitHub release notes identify the
exact artifact set for a tag.

Do not infer release support from the workspace version alone. During `0.0.x`,
public interfaces may change between releases.

## Acceptance gate

A release is accepted only when all of the following are true:

- the annotated SemVer tag resolves to the current protected `main` commit;
- source, ownership, formatting, clippy, and full workspace tests pass;
- all three macOS/Linux targets are built, tested, packaged, and smoke-tested on
  their declared release runners;
- archive structure, licenses, notices, checksums, SBOMs, and provenance pass;
- the Owner approves the protected `release` environment;
- the published release reports itself immutable;
- content-addressed artifact canaries and fixed-version plus `latest` installer
  canaries pass on all three targets.

Maintainers follow the detailed [release guide](../development/releasing.md).
