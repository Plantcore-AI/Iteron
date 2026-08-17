# Supported platforms

Iteron is developed and tested on macOS and Linux. Those remain the only
platforms where the whole product is supported. Windows is a build and
distribution target only, and the table's sandbox column says why. The source
workspace is `v0.0.5`; verify the selected release's asset list for actual host
availability. Historical `v0.0.4` assets cover macOS arm64 only;
the remaining release rows are the release workflow's required matrix, not a
claim that every historical tag contains every archive.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release; PR CI paused | supported | system Seatbelt interface |
| macOS x86-64 | source/internal CI only | supported from source | system Seatbelt interface |
| Linux x86-64 on `dgx` | release target and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `dgx` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Windows x86-64 | release target and non-required CI | not claimed | **none — no backend** |

## Windows

Windows has a build, an archive, and an installer. It does not have a sandbox,
and that is the whole distinction this section exists to make.

What exists:

- `x86_64-pc-windows-msvc` is in the release matrix. A tagged release produces a
  `.zip` containing `iteron.exe`, verified as a real PE image, digested into the
  release manifest, and covered by the same attestation checks as every other
  archive.
- `install.ps1` at the repository root is the Windows counterpart to
  `install.sh`. It pins TLS 1.2+, verifies the archive's SHA-256 before opening
  it, validates every ZIP entry against an exact expected member set before
  extracting a byte, and installs per-user without elevation.
- `.github/workflows/windows.yml` compiles the workspace for
  `x86_64-pc-windows-msvc` and runs the native ConPTY oracle.

What does not exist, and is not implied by any of the above:

- **No code-execution sandbox.** `crates/sandbox` returns `Unsupported` for
  every non-macOS, non-Linux target. `--confine` therefore refuses to run
  commands on Windows, and the default operator-authority mode runs them
  unconfined. This is the reason Windows is not a supported runtime.
- **No interactive TUI claim.** The ConPTY oracle proves the pseudoconsole path
  compiles and runs; it is not a statement that the TUI is supported.
- Lifecycle paths in places still assume a POSIX shell.

Two operational notes, so nobody reads more into the CI lane than it says. The
Windows lane is **not a required context** in the branch ruleset, and it is
deliberately not marked `continue-on-error`: a lane that cannot run must report
that, not a pass it never earned. And it runs on company hardware only once an
operator publishes the runner labels:

```console
$ gh variable set WINDOWS_RUNNER_LABELS --repo Plantcore-AI/Iteron \
    --body '["self-hosted","Windows","X64","iteron-win"]'
```

While that variable is unset, `windows.yml` is skipped outright and the release
leg falls back to a hosted `windows-2025` runner. See
`ops/windows-runner/README.md` for the machine's provisioning runbook.

Read a closed Windows tracking issue as closed, not as shipped: until a tag is
cut with the release leg above, no published tag contains a Windows artifact.

## Linux requirements

Code execution needs bubblewrap, and the backend fails **closed**: with no usable
`bwrap` there is no `bash` tool at all, only reading and editing. Having a `bwrap`
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
