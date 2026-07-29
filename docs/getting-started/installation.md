# Installation

Core Code does not currently publish an accepted binary release. The proposed
pre-alpha release matrix covers macOS, Linux, and 64-bit Windows, but those
downloads remain pending until every target has a native receipt and the
corresponding public assets exist. Building from source is the currently
available path and requires Rust 1.90 or newer.

!!! warning "Pre-alpha software"
    A verified release is not a compatibility or unattended-safety promise.
    Review the [project status](../project/status.md) and
    [sandbox limitations](../using/permissions-and-sandbox.md) before using
    Core Code on important work.

## Planned binary installation on macOS or Linux

The following command is the intended installation path after an accepted
release appears on the
[GitHub Releases](https://github.com/Plantcore-AI/core/releases) page. It is not
a currently available binary installation path.

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/core/releases/latest/download/install.sh | sh

core --version
```

The planned release installer:

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

The POSIX installer does not run on Windows. After an accepted Windows release
exists, download its `core-code-vVERSION-x86_64-pc-windows-msvc.zip` asset and
`SHA256SUMS` from the same immutable release, verify the archive's exact
lowercase SHA-256 row with `Get-FileHash`, and use `Expand-Archive`. The planned
archive contains `core-code-vVERSION-x86_64-pc-windows-msvc\core.exe`; move that
executable to a directory already on `PATH`. Release acceptance requires the
same checksum, extraction, `--version`, and latest-release canaries to pass on
`windows-2022`.

## Planned version pinning or destination

After a version is published, pin that actual version and, optionally, its
destination:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/core/releases/download/v0.0.1/install.sh \
  | sh -s -- --version v0.0.1 --bin-dir "$HOME/bin"
```

The intended installer interface has only two mutating options:
`--version vX.Y.Z` and `--bin-dir PATH`. Run a published installer asset with
`--help` to inspect its complete interface.

## Required binary-release targets

| Host | Required release target | Required native runner |
| --- | --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` | `macos-15` |
| macOS, Intel | `x86_64-apple-darwin` | `macos-15-intel` |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| Windows, x86-64 | `x86_64-pc-windows-msvc` | `windows-2022` |

An accepted release must build, test, package, and smoke-test all five targets
on their native hosted runners. This table is the release gate, not an inventory
of binaries that are currently available. Native receipts and published assets
are still pending, so no row currently claims binary support.

The Windows source implementation keeps the sandbox as a fall-closed stub:
unavailable code-execution confinement is refused while TUI, one-shot, and
headless client paths are developed independently of that backend.

## Verify a future release independently

Every accepted release must publish:

- deterministic platform archives;
- `SHA256SUMS` and `release-manifest.json`;
- the Apache-2.0 license and audited third-party notices;
- an SPDX SBOM for each target;
- GitHub artifact attestations and offline provenance bundles.

After those assets exist, download the desired archive and verification material
from the release page. Check its exact row in `SHA256SUMS`, then verify the
GitHub attestation, substituting the actual published version:

```sh
gh attestation verify core-code-v0.0.1-aarch64-apple-darwin.tar.gz \
  --repo Plantcore-AI/core
```

For a future Windows asset, pass its `.zip` name to the same
`gh attestation verify` command.

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

## Upgrade or uninstall a future binary release

After accepted assets are published, run the installer again to upgrade to the
latest release, or pass `--version` to install a specific release. The installer
preserves the existing executable if download, verification, extraction, or
smoke testing fails.

For a future Windows release, repeat the verified archive procedure and replace
only `core.exe` after the downloaded binary passes `core.exe --version`.

To uninstall, remove only the executable from the destination you selected:

```sh
rm "$HOME/.local/bin/core"
```

On Windows, remove only the `core.exe` file from the directory where you placed
it.

Core Code does not remove `.core/` session and recovery data automatically.
Review that evidence before deleting it.
