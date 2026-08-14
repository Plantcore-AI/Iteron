# Supported platforms

Iteron is developed and tested on macOS and Linux. Those are the only supported
source and release platforms. The current `v0.0.4` assets cover macOS arm64 only;
the remaining release rows are the release workflow's required matrix, not a
claim that every historical tag contains every archive.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release; PR CI paused | supported | system Seatbelt interface |
| macOS x86-64 | source/internal CI only | supported from source | system Seatbelt interface |
| Linux x86-64 on `dgx` | release target and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `dgx` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |

## Windows

Windows is explicitly unsupported. Iteron has no Windows sandbox backend, no
Windows release target, and no Windows installer. Lifecycle paths still assume
a POSIX shell, and no published tag contains a supported Windows artifact.

The sandbox returns `Unsupported` for every non-macOS, non-Linux target. The
former advisory Windows cross-compilation runner is currently paused. There is
no Windows runtime, installer, sandbox, or release evidence.

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
