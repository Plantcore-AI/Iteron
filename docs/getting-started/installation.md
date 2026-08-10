# Installation

Iteron publishes pre-alpha binaries for macOS and Linux plus a bounded Windows x86-64
one-shot artifact. Rust 1.90 or newer is required only when building from source.

!!! warning "Pre-alpha software"
    A verified release is not a compatibility or unattended-safety promise.
    Review the [project status](../project/status.md) and
    [sandbox limitations](../using/permissions-and-sandbox.md) before using
    Iteron on important work.

## Install the latest release

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh

iteron --version
```

The installer:

- accepts only a version-bound release from `Plantcore-AI/Iteron`;
- maps the current operating system and architecture to an explicit allowlist;
- downloads with HTTPS-only redirects, timeouts, retries, and size ceilings;
- requires exactly one lowercase SHA-256 entry for the selected archive;
- rejects unexpected archive members, links, special files, and path traversal;
- smoke-tests the downloaded binary before replacing an existing installation;
- installs atomically without `sudo` and never edits a shell profile.

An explicit `--bin-dir` wins. Otherwise the destination is
`$ITERON_CODE_INSTALL_DIR`, `$XDG_BIN_HOME`, or `$HOME/.local/bin`, in that order.
Ensure that directory is already on `PATH`.

## Pin a version or destination

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/download/v0.0.2/install.sh \
  | sh -s -- --version v0.0.2 --bin-dir "$HOME/bin"
```

The only mutating options are `--version vX.Y.Z` and `--bin-dir PATH`. Run the
downloaded release asset with `--help` to inspect the complete interface.

## Install the Windows one-shot archive

The POSIX `install.sh` does not run on Windows. Download the
`iteron-vVERSION-x86_64-pc-windows-msvc.zip` asset and `SHA256SUMS` from the
same immutable release, verify the archive's exact lowercase SHA-256 row with
`Get-FileHash`, and use `Expand-Archive`. The archive contains
`iteron-vVERSION-x86_64-pc-windows-msvc\iteron.exe`; move that executable to a
directory already on `PATH`. Release acceptance runs the same checksum,
extraction, `--version`, and `--machine-contract` content canary on
`windows-2025`.

## Supported release targets

| Host | Release target | Native release runner |
| --- | --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` | `macos-15` |
| macOS, Intel | `x86_64-apple-darwin` | `macos-15-intel` |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| Windows, x86-64 one-shot CLI | `x86_64-pc-windows-msvc` | `windows-2025` |

Each target is built, compatibility-tested, packaged, and smoke-tested on a native hosted runner.
The POSIX `install.sh` remains limited to macOS and Linux. The Windows ZIP is the verified
`iteron.exe` one-shot boundary used by downstream installers; it does not claim Windows TUI,
ConPTY, resident-server, or sandbox support.

## Linux prerequisite for code execution

Code execution (`bash`, builds, tests) is confined by bubblewrap on Linux, and the
sandbox fails **closed**: without a usable `bwrap` the agent can read and edit but
cannot run anything. Install the `bubblewrap` package, and on Ubuntu 24.04 also
grant it an AppArmor profile for unprivileged user namespaces.

The installer runs the sandbox's own probe after installing and prints the exact
remedy as a warning when it fails; installation itself still succeeds. See
[supported platforms](../reference/platforms.md#linux-requirements) for the
commands.

## Verify a release independently

Every release publishes:

- deterministic platform archives;
- `SHA256SUMS`, `release-manifest.json`, and `release-manifest.receipt.json`;
- the Apache-2.0 license and audited third-party notices;
- an SPDX SBOM for each target;
- GitHub artifact attestations and offline provenance bundles.

Download the desired archive and verification material from the
[release page](https://github.com/Plantcore-AI/Iteron/releases). Check its exact
row in `SHA256SUMS`, then verify the GitHub attestation:

```sh
gh attestation verify iteron-v0.0.2-aarch64-apple-darwin.tar.gz \
  --repo Plantcore-AI/Iteron
```

For the Windows asset, pass its `.zip` name to the same
`gh attestation verify` command.

A checksum fetched from the same release detects corruption. The GitHub
attestation additionally binds an artifact to this repository and its release
workflow. The receipt identifies the exact final manifest bytes; the manifest identifies each
archive and the CLI stream versions reported by every packaged binary. This content addressing
proves byte integrity, not publisher authenticity by itself. Platform signing is outside this
release slice.

## Build from source

```sh
git clone https://github.com/Plantcore-AI/Iteron.git
cd iteron
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

On Windows, repeat the verified archive procedure and replace only `iteron.exe`
after the downloaded binary passes `iteron.exe --version`.

To uninstall, remove only the executable from the destination you selected:

```sh
rm "$HOME/.local/bin/iteron"
```

On Windows, remove only the `iteron.exe` file from the directory where you placed
it.

Iteron does not remove `.iteron/` session and recovery data automatically.
Review that evidence before deleting it.
