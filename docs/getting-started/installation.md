# Installation

Core Code publishes pre-alpha binaries for macOS and Linux. Rust 1.90 or newer
is required only when building from source.

!!! warning "Pre-alpha software"
    A verified release is not a compatibility or unattended-safety promise.
    Review the [project status](../project/status.md) and
    [sandbox limitations](../using/permissions-and-sandbox.md) before using
    Core Code on important work.

## Install the latest release

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/core/releases/latest/download/install.sh | sh

core --version
```

The installer:

- accepts only a version-bound release from `Plantcore-AI/core`;
- maps the current operating system and architecture to an explicit allowlist;
- downloads with HTTPS-only redirects, timeouts, retries, and size ceilings;
- requires exactly one lowercase SHA-256 entry for the selected archive;
- rejects unexpected archive members, links, special files, and path traversal;
- smoke-tests the downloaded binary before replacing an existing installation;
- installs atomically without `sudo` and never edits a shell profile.

An explicit `--bin-dir` wins. Otherwise the destination is
`$CORE_CODE_INSTALL_DIR`, `$XDG_BIN_HOME`, or `$HOME/.local/bin`, in that order.
Ensure that directory is already on `PATH`.

## Pin a version or destination

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/core/releases/download/v0.0.1/install.sh \
  | sh -s -- --version v0.0.1 --bin-dir "$HOME/bin"
```

The only mutating options are `--version vX.Y.Z` and `--bin-dir PATH`. Run the
downloaded release asset with `--help` to inspect the complete interface.

## Supported release targets

| Host | Release target | Native release runner |
| --- | --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` | `macos-15` |
| macOS, Intel | `x86_64-apple-darwin` | `macos-15-intel` |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |

Each target is built, tested, packaged, and installed on a native hosted runner.
Windows is not a supported runtime target today.

## Verify a release independently

Every release publishes:

- deterministic platform archives;
- `SHA256SUMS` and `release-manifest.json`;
- the Apache-2.0 license and audited third-party notices;
- an SPDX SBOM for each target;
- GitHub artifact attestations and offline provenance bundles.

Download the desired archive and verification material from the
[release page](https://github.com/Plantcore-AI/core/releases). Check its exact
row in `SHA256SUMS`, then verify the GitHub attestation:

```sh
gh attestation verify core-code-v0.0.1-aarch64-apple-darwin.tar.gz \
  --repo Plantcore-AI/core
```

A checksum fetched from the same release detects corruption. The GitHub
attestation additionally binds an artifact to this repository and its release
workflow. Inspect `release-manifest.json` for the release commit, target set,
artifact sizes, and digests.

## Build from source

```sh
git clone https://github.com/Plantcore-AI/core.git
cd core
cargo install --locked --path crates/cli
core --version
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
rm "$HOME/.local/bin/core"
```

Core Code does not remove `.core/` session and recovery data automatically.
Review that evidence before deleting it.
