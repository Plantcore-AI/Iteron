# Supported platforms

Core Code is currently developed and tested on macOS and Linux. There is no
supported Windows runtime today: the release matrix carries a bounded Windows
x86-64 `core.exe` one-shot artifact, and that artifact is the whole Windows
claim.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release and CI | supported | system Seatbelt interface |
| macOS x86-64 on `macos-15-intel` | native release | supported | system Seatbelt interface |
| Linux x86-64 on `ubuntu-24.04` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `ubuntu-24.04-arm` | native release | supported | usable bubblewrap/user-namespace boundary required |
| Windows x86-64 on `windows-2025` | bounded one-shot release, advisory CI | unsupported | no backend |

## Windows

Windows support is exactly one artifact wide, and nothing beyond it has been
delivered. Read a closed Windows tracking issue as closed, not as shipped: the
released `core.exe` is a one-shot CLI, and it does not claim interactive TUI,
resident-server, or sandbox support. The lifecycle paths still assume a POSIX
shell.

There is no Windows code-execution backend. The sandbox returns `Unsupported`
for every non-macOS, non-Linux target, and Confinement is consumed as a
fall-closed stub: an unavailable confinement refuses the operation rather than
running an unconfined command. Source paths that do not require the sandbox
remain separate from it, which is a source invariant and not a runtime support
claim.

Two Windows lanes report without gating. `windows / check` in
`.github/workflows/windows.yml` is a `cargo check --target x86_64-pc-windows-msvc`
on every pull request, and `rust / windows-2025` in `.github/workflows/ci.yml`
runs the workspace suite on a native Windows runner. Both are
`continue-on-error` and neither is a required context, so they publish how far
the port still has to go without ever blocking a merge. A green result is not a
support claim.

At source level, the interactive client shares the crossterm composition root
with Unix and is designed to run in a ConPTY terminal; there is no Windows copy
of the SQ/EQ protocol or result-v5 wire. The native Windows oracle creates and
resizes a ConPTY around the production TUI through `portable-pty`; Core itself
uses the console supplied by its terminal host. One-shot mode and `core serve`
share the same App Server client. Headless clients use bounded JSONL over
loopback TCP rather than a Unix-domain socket and perform the same admission
handshake. These source paths exist and that oracle exercises them; the released
artifact's bounded one-shot claim does not extend to them.

The source implementation capability-probes terminal features. A non-empty
`WT_SESSION` is positive evidence for Windows Terminal OSC 8 links and OSC 9
notification intent. Conhost, redirected streams, unknown hosts, and failed
CSI-u negotiation keep plain visible paths, BEL notifications, and ordinary
keyboard input. Core never assumes escape-sequence support merely because the
operating system is Windows.

The Windows release artifact is a deterministic
`core-code-vVERSION-x86_64-pc-windows-msvc.zip` archive containing `core.exe`,
licenses, notices, SBOM, and build metadata. Verify it against `SHA256SUMS` and
its GitHub build/SBOM attestations before extraction. The POSIX `install.sh`
does not install Windows archives.

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
$ sudo tee /etc/apparmor.d/core-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,
include <tunables/global>

profile core-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
PROFILE
$ sudo apparmor_parser --replace /etc/apparmor.d/core-bwrap
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
