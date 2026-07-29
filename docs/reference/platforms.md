# Supported platforms

Core Code has native pre-alpha build, test, and release lanes for macOS, Linux,
and 64-bit Windows. Platform support names an exact Rust target and a native CI
runner; it does not imply that every code-execution sandbox backend is available.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release and CI | supported | system Seatbelt interface |
| macOS x86-64 on `macos-15-intel` | native release | supported | system Seatbelt interface |
| Linux x86-64 on `ubuntu-24.04` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `ubuntu-24.04-arm` | native release | supported | usable bubblewrap/user-namespace boundary required |
| Windows x86-64 on `windows-2022` | native `x86_64-pc-windows-msvc` release and CI | supported through ConPTY | unavailable operations fail closed until the WS5 backend lands |

## Linux requirements

Having a `bwrap` executable is not sufficient: the operating system must permit
the confinement probe to establish the required namespace boundary. Core Code
fails closed when bubblewrap is installed but unusable.

Ubuntu policy can restrict unprivileged user namespaces. Use a narrowly reviewed
profile for the installed bubblewrap binary rather than disabling a system-wide
security control.

## Windows

The interactive client uses the same crossterm composition root as Unix when it
runs in a ConPTY terminal; there is no Windows copy of the SQ/EQ protocol or
result-v5 wire. The native terminal oracle creates and resizes the ConPTY through
`portable-pty`. One-shot mode and `core serve` use the same App Server client.
Headless clients attach over bounded JSONL on loopback TCP, which is available on
Windows without a Unix-domain socket, and perform the same version handshake
before a submission is admitted.

Terminal features are capability-probed. A non-empty `WT_SESSION` is positive
evidence for Windows Terminal OSC 8 links and OSC 9 notification intent.
Conhost, redirected streams, unknown hosts, and failed CSI-u negotiation keep
plain visible paths, BEL notifications, and ordinary keyboard input. Core never
assumes escape-sequence support merely because the operating system is Windows.

Windows releases are deterministic
`core-code-vVERSION-x86_64-pc-windows-msvc.zip` archives containing `core.exe`,
licenses, notices, SBOM, and build metadata. Verify the archive against
`SHA256SUMS` and its GitHub build/SBOM attestations before extracting it. The
POSIX `install.sh` does not install Windows archives.

The Windows Confinement implementation is intentionally consumed as a
fall-closed stub. The TUI, one-shot client, and headless App Server remain usable
for operations that do not require the unavailable sandbox; Core does not
silently execute an unconfined command.

## Terminal behavior

The TUI requires terminal stdin and stdout and restores terminal state on normal
exit and panic on every supported platform, plus the covered SIGTERM and SIGHUP
paths on Unix. Rendering degrades for narrow or non-truecolor terminals;
`NO_COLOR` selects a monochrome surface.

Pre-alpha support means these are implementation targets and CI surfaces, not a
compatibility SLA. Release notes must name the exact triples that were actually
built and smoke-tested.
