# Installation

Iteron's supported distribution matrix is macOS and Linux. Windows is not
supported. The current `v0.0.4` release contains only the macOS Apple Silicon
archive; the two Linux entries in the three-target matrix remain pending until
the DGX release workflow can run successfully.

!!! warning "Pre-alpha release"
    A downloadable release is not a compatibility or unattended-safety promise.
    Review the [project status](../project/status.md) and
    [sandbox limitations](../using/permissions-and-sandbox.md) before using
    Iteron on important work.

## Install the latest public release

When the repository and selected release archive are publicly accessible, a
host for which the latest release actually contains an archive can use:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh
```

Then run `iteron --version`.

The installer:

- accepts only a version-bound release from `Plantcore-AI/Iteron`;
- maps the current operating system and architecture to an explicit allowlist;
- downloads with HTTPS-only redirects, timeouts, retries, and size ceilings;
- requires exactly one lowercase SHA-256 entry for the selected archive;
- rejects unexpected archive members, links, special files, and path traversal;
- smoke-tests the downloaded binary before replacing an existing installation;
- installs atomically without `sudo` and never edits a shell profile.

After installation, follow [Setup and BYOK](setup-and-byok.md) to validate and
store a provider credential outside the repository.

An explicit `--bin-dir` wins. Otherwise the destination is
`$ITERON_INSTALL_DIR`, the legacy `$ITERON_CODE_INSTALL_DIR`, `$XDG_BIN_HOME`, or
`$HOME/.local/bin`, in that order. Ensure that directory is already on `PATH`.

## Pin a version or destination

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/download/v0.0.4/install.sh \
  | sh -s -- --version v0.0.4 --bin-dir "$HOME/bin"
```

The only mutating options are `--version vX.Y.Z` and `--bin-dir PATH`. Run the
downloaded release asset with `--help` to inspect the complete interface.

Windows is not supported: there is no Windows release target, installer, or
code-execution sandbox. See [supported platforms](../reference/platforms.md).

## Release matrix and current availability

| Host | Release target | Native release runner | In `v0.0.4` |
| --- | --- | --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` | `macos-15` | available |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `dgx` | pending |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `dgx` | pending |

The release workflow requires all three targets to be built, tested, packaged,
and smoke-tested before a release counts as accepted
multi-target evidence. Release notes remain authoritative for the archives a
particular tag actually contains.

## Linux prerequisite for confined code execution

The shipped default is unconfined. When `--confine` is selected on Linux, code
execution (`bash`, builds, and tests) uses bubblewrap and fails **closed** if a
usable `bwrap` boundary cannot be established. Install the `bubblewrap` package;
on Ubuntu 24.04, also grant it an AppArmor profile for unprivileged user
namespaces.

The installer probes the confined backend after installing and prints the exact
remedy as a warning when it fails; installation itself still succeeds. See
[supported platforms](../reference/platforms.md#linux-requirements) for the
commands.

## Verify a release independently

The four published tags through `v0.0.4` were built locally and contain only an
`aarch64-apple-darwin` archive. They include checksums, a manifest and receipt,
legal material, and an SPDX SBOM. Each tag's release notes and manifest record
the absence of GitHub OIDC attestation; `v0.0.2` through `v0.0.4` also carry a
per-archive offline provenance document. They are historical pre-alpha
artifacts, not accepted three-target release evidence.

An accepted workflow release is expected to publish:

- deterministic archives for all three macOS/Linux targets;
- `SHA256SUMS`, `release-manifest.json`, and
  `release-manifest.receipt.json`;
- the Apache-2.0 license and audited third-party notices;
- an SPDX SBOM for each target;
- GitHub artifact attestations and offline provenance bundles.

Download the desired archive and verification material from the
[release page](https://github.com/Plantcore-AI/Iteron/releases). Check its exact
row in `SHA256SUMS`. For a future workflow-built release that advertises GitHub
attestation, also run:

```sh
gh attestation verify iteron-vX.Y.Z-aarch64-apple-darwin.tar.gz \
  --repo Plantcore-AI/Iteron
```

A checksum fetched from the same release detects corruption. GitHub attestation
additionally binds an artifact to this repository and its release workflow. The
receipt identifies the exact final manifest bytes; the manifest identifies each
archive and the CLI stream versions reported by every packaged binary. This
content addressing proves byte integrity, not publisher authenticity by itself.
Platform signing is outside the current release slice.

## Build from source

Building from source is the available path on any macOS/Linux target missing
from the latest release:

```sh
git clone https://github.com/Plantcore-AI/Iteron.git
cd Iteron
cargo install --locked --path crates/cli
iteron --version
```

`--locked` preserves the reviewed dependency resolution. A local source build is
not equivalent to the release workflow's native-target, legal, SBOM, provenance,
and public-install evidence.

## Upgrade or uninstall

Run the installer again to upgrade to the latest release, or pass `--version` to
install a specific release. The existing executable is preserved if download,
verification, extraction, or smoke testing fails.

To uninstall, remove only the executable from the destination you selected:

```sh
rm "$HOME/.local/bin/iteron"
```

Iteron does not remove `.iteron/` session and recovery data automatically.
Review that evidence before deleting it.
