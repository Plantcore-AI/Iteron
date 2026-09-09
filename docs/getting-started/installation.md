# Installation

The v0.0.20 distribution matrix covers macOS arm64, Linux arm64, Linux x86-64,
and Windows x86-64. Consult the selected release's asset list before installing;
source versioning alone does not prove that an archive exists for a host.

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

On Windows PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri 'https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.ps1' | Invoke-Expression
```

Then verify shell resolution and the binary version:

```sh
command -v iteron
iteron --version
```

In PowerShell, use `Get-Command iteron` followed by `iteron --version`.

`command -v` must print the intended executable path. If it prints nothing, the
binary may be installed but not on `PATH`. If it prints a different path, invoke
the intended path directly or fix `PATH` ordering before diagnosing providers.
Neither check reads a provider credential.

### Confirm the install directory is on PATH

The default destination is `~/.local/bin` (unless you overrode it with
`--bin-dir`, `$ITERON_INSTALL_DIR`, the legacy `$ITERON_CODE_INSTALL_DIR`, or
`$XDG_BIN_HOME`). The installer never edits shell startup files; add the
directory yourself if needed.

**1. Is the binary present (installed)?**

```sh
test -x "$HOME/.local/bin/iteron" && echo "installed: $HOME/.local/bin/iteron" || echo "not installed at default path"
```

**2. Is that directory already on PATH?**

POSIX `sh` / bash / zsh (same one-liner):

```sh
case ":$PATH:" in *":$HOME/.local/bin:"*) echo "on PATH";; *) echo "NOT on PATH";; esac
```

**3. If installed but NOT on PATH**, add it for the current session, then
re-check with `command -v iteron`:

```sh
export PATH="$HOME/.local/bin:$PATH"
command -v iteron
```

To persist across new shells, append the same `export` line to the startup file
you actually use (`~/.profile` for login `sh`, `~/.bashrc` for interactive bash,
`~/.zshrc` for zsh), then open a new terminal. Do not run an automated profile
editor; choose the file for your shell deliberately.

The POSIX installer:

- accepts only a version-bound release from `Plantcore-AI/Iteron`;
- maps the current operating system and architecture to an explicit allowlist;
- downloads with HTTPS-only redirects, timeouts, retries, and size ceilings;
- requires exactly one lowercase SHA-256 entry for the selected archive;
- rejects unexpected archive members, links, special files, and path traversal;
- smoke-tests the downloaded binary before replacing an existing installation;
- installs atomically without `sudo` and never edits a shell profile.

It installs only the `iteron` command. `iteron-harness` is a repository-only research executable;
it is not included in an archive or installed by this script. Its source-build instructions and
language-neutral client contract are documented in the
[research harness protocol](../reference/research-harness-protocol.md).

After installation, follow [Setup and BYOK](setup-and-byok.md) to validate and
store a provider credential outside the repository.

For `install.sh`, an explicit `--bin-dir` wins. Otherwise the destination is
`$ITERON_INSTALL_DIR`, the legacy `$ITERON_CODE_INSTALL_DIR`, `$XDG_BIN_HOME`, or
`$HOME/.local/bin`, in that order. Ensure that directory is already on `PATH`.

## Pin a version or destination

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/download/v0.0.20/install.sh \
  | sh -s -- --version v0.0.20 --bin-dir "$HOME/bin"
```

The only mutating options are `--version vX.Y.Z` and `--bin-dir PATH`. Run the
downloaded release asset with `--help` to inspect the complete interface.

Do not use Windows for untrusted code execution: it has no code-execution
sandbox, `--confine` refuses to execute commands, and the default
operator-authority mode runs commands unconfined. See
[supported platforms](../reference/platforms.md#windows).

## Release matrix and current availability

| Host | Release target | Native release runner | Expected release asset |
| --- | --- | --- | --- |
| macOS, Apple Silicon | `aarch64-apple-darwin` | `macos-15` | verify on the release page |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `dgx` | verify on the release page |
| Linux, x86-64 | `x86_64-unknown-linux-musl` | `dgx` | verify on the release page |
| Windows, x86-64 | `x86_64-pc-windows-msvc` | `windows-2025` | published in v0.0.20 |

The v0.0.20 release publishes all four targets above. Release notes remain
authoritative for the archives a particular tag actually contains. A Windows
archive proves distribution and native validation; it does not add the missing
code-execution sandbox or make Windows a fully supported runtime.

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

The historical tags through `v0.0.4` were built locally and contain only an
`aarch64-apple-darwin` archive. They include checksums, a manifest and receipt,
legal material, and an SPDX SBOM. Each tag's release notes and manifest record
the absence of GitHub OIDC attestation; `v0.0.2` through `v0.0.4` also carry a
per-archive offline provenance document. They are historical pre-alpha
artifacts, not accepted workflow release evidence.

An accepted workflow release is expected to publish:

- deterministic archives for the three macOS/Linux targets and Windows x86-64;
- version-bound `install.sh` and `install.ps1` assets recorded by digest and size
  in the release manifest;
- `SHA256SUMS`, `release-manifest.json`, and
  `release-manifest.receipt.json`;
- the Apache-2.0 license and audited third-party notices;
- an SPDX SBOM for each target;
- GitHub artifact attestations and offline provenance bundles.

Download the desired archive and verification material from the
[release page](https://github.com/Plantcore-AI/Iteron/releases). Check its exact
row in `SHA256SUMS`. For a workflow-built release that advertises GitHub
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

Building from source is the available path on any release target missing from
the latest release:

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

On Windows, remove `%LOCALAPPDATA%\Iteron\bin\iteron.exe` (or your selected
`-BinDir` copy) and remove that directory from the user `PATH` if desired.

Iteron does not remove `.iteron/` session and recovery data automatically.
Review that evidence before deleting it.
