# Supported platforms

Iteron is developed and tested primarily on macOS and Linux. Those remain the
only platforms where the whole product is supported. Release v0.0.29 ships
macOS arm64, Linux arm64, Linux x86-64, and Windows x86-64 assets. Windows
remains a non-required CI surface. Source includes a Windows LPAC backend with
Job, pipe, and ConPTY ownership; actual native acceptance and interactive TUI
support remain pending.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release; PR CI paused | supported | system Seatbelt interface |
| macOS x86-64 | source/internal CI only | supported from source | system Seatbelt interface |
| Linux x86-64 on `dgx` | release target and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `dgx` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Windows x86-64 | v0.0.29 release asset; non-required CI | not claimed | LPAC implementation; native acceptance pending |

## Windows

Windows can be installed from the v0.0.29 archive or built from source. It has a
non-required CI lane and is packaged as `x86_64-pc-windows-msvc`. Starting with
v0.0.30, a version-bound `install.ps1` also installs the manual archive layout;
that newer script can install v0.0.29 with `-Version v0.0.29`. The v0.0.29
release itself has no installer asset. Windows requires the Microsoft Visual C++
x64 runtime. Archive availability does not imply full runtime support.

What exists:

- `.github/workflows/windows.yml` compiles the workspace for
  `x86_64-pc-windows-msvc`. Explicit manual runs additionally compile default
  and script test cohorts once each and execute exact native Job, ConPTY, pipe,
  LPAC, process, LSP, and journal cases from those retained compiler artifacts.
  Listings, substantive case counts, source/binary digests, and real cleanup
  are required; an unavailable or empty suite fails.
- Source required-confinement execution uses an LPAC token and retained exact
  object permissions, with network capabilities only when the host grants egress.
  The actual suspended process token is checked before its initial resume.
  One Job and its native transport retain cleanup custody until physical terminal
  observations; a Job alone does not establish filesystem or network isolation.
- `v0.0.26` publishes a workflow installer and archive. `v0.0.29` publishes a
  manual `x86_64-pc-windows-msvc` archive with checksums, a manual manifest,
  source SBOM, and build records; it does not claim workflow provenance or
  Authenticode. Newer installers validate both documented archive layouts and
  retain the previous executable set for `-Rollback`.

What remains unverified, and is not implied by any of the above:

- **Native isolation acceptance.** The source adapter and authored oracles
  have not established same-candidate Git Bash/PowerShell runtime availability,
  file/network/environment denial, or complete process/LSP/terminal cleanup.
  A failed confined launch refuses; it never retries with an unrestricted token.
  The host's explicit unconfined choice retains host authority.
- **No interactive TUI claim.** The ConPTY oracle proves the pseudoconsole path
  compiles and runs; it is not a statement that the TUI is supported.
- Commands use Git for Windows Bash from the host's frozen absolute PATH.
  Source does not grant ambient HOME/PATH directories as runtime read trees.

Two operational notes, so nobody reads more into the CI lane than it says. The
Windows lane is **not a required context** in the branch ruleset, and it is
deliberately not marked `continue-on-error`: a lane that cannot run must report
that, not a pass it never earned. And it runs on company hardware only once an
operator publishes the runner labels:

```console
$ gh variable set WINDOWS_RUNNER_LABELS --repo Plantcore-AI/Iteron \
    --body '["self-hosted","Windows","X64","iteron-win"]'
```

While that variable is unset, `windows.yml` is skipped outright. See
`ops/windows-runner/README.md` for the machine's provisioning runbook.

`v0.0.20` is the first release in this project history to publish Windows
artifacts. Verify the selected release's asset list because this does not imply a
compatibility promise for every future pre-alpha tag; historical tags need not
contain the Windows archive or installer.

## Linux requirements

Explicit `--confine` code execution needs bubblewrap, and the backend fails
**closed** when it cannot establish that boundary. Ordinary sessions use host
authority and do not require bubblewrap. Having a `bwrap`
executable is not sufficient either — it must be a root-owned, non-group/world-
writable file at `/usr/bin/bwrap`, `/bin/bwrap`, or `/usr/local/bin/bwrap`, and
the operating system must permit the confinement probe to establish the required
namespace boundary.

Install the package first:

```console
$ sudo apt-get install -y bubblewrap    # Debian/Ubuntu
$ sudo dnf install -y bubblewrap        # Fedora/RHEL
$ sudo apk add bubblewrap               # Alpine
```

Ubuntu 24.04 additionally restricts unprivileged user namespaces, so a perfectly
valid bubblewrap still fails the probe. Grant the capability to that one binary
rather than disabling a system-wide security control:

```console
$ sudo apt-get install -y apparmor apparmor-utils
$ sudo tee /etc/apparmor.d/iteron-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile iteron-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
PROFILE
$ sudo apparmor_parser --replace /etc/apparmor.d/iteron-bwrap
```

`install.sh` runs this exact probe after installing and prints the remedy above as
a warning when it fails. It is a warning, not an installation failure.

The confined command runs under `/bin/bash` when it exists and `/bin/sh`
otherwise, so the musl artifact also executes code on BusyBox userlands such as
Alpine.

## Terminal behavior

The TUI requires terminal stdin and stdout and restores terminal state on normal
exit and panic, plus the SIGTERM and SIGHUP paths covered by the implementation
on Unix. Rendering degrades for narrow or non-truecolor terminals; `NO_COLOR`
selects a monochrome surface.

Pre-alpha support means these are implementation targets and CI surfaces, not a
compatibility SLA. Release notes must name the exact triples that were actually
built and smoke-tested.
