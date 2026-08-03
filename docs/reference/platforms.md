# Supported platforms

Core Code is currently developed and tested on macOS and Linux. There is no
supported Windows runtime today.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release and CI | supported | system Seatbelt interface |
| macOS x86-64 on `macos-15-intel` | native release | supported | system Seatbelt interface |
| Linux x86-64 on `ubuntu-24.04` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `ubuntu-24.04-arm` | native release | supported | usable bubblewrap/user-namespace boundary required |
| Windows | unsupported (advisory `windows / check` only) | unsupported | no backend |

## Windows

Windows is **not supported and nothing has been delivered toward supporting it**.
Read a closed Windows tracking issue as closed, not as shipped: the sandbox
returns `Unsupported` for every non-macOS, non-Linux target, no release target is
Windows, and the lifecycle paths assume a POSIX shell.

The `windows / check` lane in `.github/workflows/windows.yml` is a **non-blocking**
`cargo check --target x86_64-pc-windows-msvc` on every pull request. It publishes
whether the workspace still compiles for Windows, so the distance to a port stays
an observed status. It is not a required context and a green result is not a
support claim.

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
exit, panic, SIGTERM, and SIGHUP paths covered by the implementation. Rendering
degrades for narrow or non-truecolor terminals; `NO_COLOR` selects a monochrome
surface.

Pre-alpha support means these are implementation targets and CI surfaces, not a
compatibility SLA. Release notes must name the exact triples that were actually
built and smoke-tested.
