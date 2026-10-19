# Installation

The release matrix contains macOS Apple Silicon, Linux arm64, Linux x86-64,
and Windows x86-64 packages. Check the selected release's asset list before
installing. Release v0.0.29 includes all four archives but does not include
installer scripts. Starting with v0.0.30, the release includes version-bound
`install.sh` and `install.ps1` assets and a dedicated `iteron-app-server` command.
Windows archive availability does not establish full native isolation or
interactive TUI support; see [supported platforms](../reference/platforms.md).

!!! warning "Pre-alpha release"
    Review the [project status](../project/status.md) and
    [sandbox limitations](../using/permissions-and-sandbox.md) before using
    Iteron on important work.

## Install the latest public release

On macOS Apple Silicon or Linux arm64/x86-64:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh
```

On Windows x86-64, using Windows PowerShell 5.1 or PowerShell 7:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Invoke-RestMethod -Uri 'https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.ps1' | Invoke-Expression
```

Windows requires the Microsoft Visual C++ x64 runtime. Install that prerequisite
if Windows reports a missing runtime DLL. Run installers as your ordinary user.
Neither installer elevates privileges or edits shell profiles. POSIX installation
uses standard command-line tools, including `curl`, `tar`, `gzip`, and either
`sha256sum` or `shasum`; Python is not required.

The default POSIX directory is `$HOME/.local/bin`. An explicit `--bin-dir` wins,
followed by `$ITERON_INSTALL_DIR`, the deprecated `$ITERON_CODE_INSTALL_DIR`,
`$XDG_BIN_HOME`, then the default. PowerShell uses `-BinDir`, then the two Iteron
environment variables, then `%LOCALAPPDATA%\Iteron\bin`. PowerShell adds the
selected directory to the user's `PATH` unless `-SkipPathUpdate` is passed.

Verify the selected executable:

```sh
command -v iteron
iteron --version
```

In PowerShell, run `Get-Command iteron` and `iteron --version`. The resolved path
must match your selected installation directory. POSIX users can add the default
directory to the current shell with:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Choose your own shell startup file if you want that setting to persist. The
installer reports a missing `PATH` entry and does not edit that file.

The installed commands are `iteron`, `iteron-workspace-hook`, and, for packages
that contain it, `iteron-app-server` (with `.exe` on Windows). The dedicated
AppServer shares the existing protocol and session runtime. Its help is available
with `iteron-app-server --help`. `iteron-harness` remains a repository research
executable; see the [research harness protocol](../reference/research-harness-protocol.md).

Continue with [Setup and BYOK](setup-and-byok.md) to store a provider credential
outside the repository.

## Pin a version or destination

Download the version-bound installer asset before running it when you want to
inspect or retain the script:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/Iteron/releases/download/v0.0.30/install.sh \
  -o install.sh
sh install.sh --version v0.0.30 --bin-dir "$HOME/.local/bin"
```

```powershell
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/Plantcore-AI/Iteron/releases/download/v0.0.30/install.ps1' -OutFile install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Version v0.0.30 -BinDir "$env:LOCALAPPDATA\Iteron\bin" -SkipPathUpdate
```

`ExecutionPolicy Bypass` applies only to that process. To install v0.0.29 with
these newer scripts, change only the `--version` or `-Version` argument to
`v0.0.29`. Downloading `install.sh` or `install.ps1` from v0.0.29 itself returns
404 because those historical assets do not exist.

Release installer assets embed an immutable version. Reusing an older downloaded
script without an explicit version reinstalls that script's release. Download
the latest installer again to upgrade, or select an exact tag explicitly.

## Verification and package formats

Both installers select the archive by exact release tag and host target, require
one lowercase SHA-256 row from `SHA256SUMS`, and verify the downloaded bytes
before extraction. They bound archive sizes and reject duplicate or unexpected
members, path traversal, symlinks, and special files.

The supported package formats are the workflow layout and the manual layout
selected by a checksum-listed `manual-release-manifest.json`. The manual layout
adds `STANDALONE-PERSISTENCE.md` and `machine-contract.json`. Its Unix Hook may
be a hardlink only to the regular `iteron` sibling. The dedicated AppServer is
an optional exact member in either layout. No arbitrary manifest path becomes
an extraction or installation destination. Installers check executable versions
before replacement and after installation.

Checksums retrieved from the same release establish byte integrity, not
independent publisher authenticity. Manual releases do not claim GitHub build
attestation, notarization, or Authenticode. Read the selected release's notes
and `BUILD-INFO.json` for its build and verification scope. For a workflow
release that explicitly advertises GitHub artifact attestation, also run:

```sh
gh attestation verify iteron-vX.Y.Z-aarch64-apple-darwin.tar.gz \
  --repo Plantcore-AI/Iteron
```

## Upgrade, rollback, or uninstall

Stop running Iteron and AppServer processes before updating. Rerun a current
installer to upgrade. Verification completes before replacing executables. The
installer keeps one previous executable set in `.iteron-previous` inside the
chosen bin directory. If replacement or the final smoke check fails, it restores
the previous set, including whether the standalone AppServer existed.

Restore that previous set without a network download:

```sh
sh install.sh --rollback --bin-dir "$HOME/.local/bin"
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Rollback -BinDir "$env:LOCALAPPDATA\Iteron\bin" -SkipPathUpdate
```

Rollback swaps the current and previous executable sets. It requires a previous
installation; a first install has no rollback copy. It does not roll back session
data or settings. You can also reinstall a selected older release using the
version argument.

A directory lock prevents overlapping installer runs. Handled errors and
interruptions restore the saved set; forced process termination or power loss can
leave `.iteron-install.lock` and `.iteron-transaction.*` behind. Preserve those
backups, ensure no installer is active, and inspect the saved executables before
removing a stale lock and reinstalling an exact release. A running Windows
executable may leave a reported `.old.*` file that can be deleted after it exits.

To uninstall, remove the commands and the saved previous copy from the destination
you selected:

```sh
rm -f "$HOME/.local/bin/iteron" "$HOME/.local/bin/iteron-workspace-hook" \
  "$HOME/.local/bin/iteron-app-server"
rm -rf "$HOME/.local/bin/.iteron-previous"
```

On Windows, remove the corresponding `.exe` files and `.iteron-previous` from
`%LOCALAPPDATA%\Iteron\bin` (or your chosen `-BinDir`). Remove that directory
from your user `PATH` if desired. Session and recovery data in `.iteron/` are
retained; review them before deleting them.

## Linux confinement prerequisite

Ordinary sessions use host authority. Explicit `--confine` code execution needs
a usable bubblewrap boundary and refuses if it cannot establish one. The
installer prints a warning when its probe fails; installation still succeeds.
See [Linux requirements](../reference/platforms.md#linux-requirements) for
package and Ubuntu AppArmor setup.

## Build from source

```sh
git clone https://github.com/Plantcore-AI/Iteron.git
cd Iteron
cargo install --locked --path crates/cli
iteron --version
```

A source build does not imply the release workflow's platform, legal, SBOM,
provenance, or installation evidence. macOS Intel users currently need a source
build; published macOS archives target Apple Silicon.

Release archives are limited to 256 MiB compressed and 256 MiB unpacked. The unpacked
limit accommodates the CLI, workspace hook and independent AppServer executable.
