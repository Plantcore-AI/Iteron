# Supported platforms

The Core Code source tree contains platform paths for macOS, Linux, and 64-bit
Windows. The proposed pre-alpha release matrix has five exact Rust targets, but
none currently has both a native release receipt and a published asset. The
matrix below describes source implementation and the release evidence still
required; it does not claim that binaries are currently supported.

| Proposed release target | Current source status | Evidence required for release | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | source target and TUI path present | native receipt and public asset pending | system Seatbelt interface |
| macOS x86-64 on `macos-15-intel` | source target and TUI path present | native receipt and public asset pending | system Seatbelt interface |
| Linux x86-64 on `ubuntu-24.04` | source target and TUI path present | native receipt and public asset pending | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `ubuntu-24.04-arm` | source target and TUI path present | native receipt and public asset pending | usable bubblewrap/user-namespace boundary required |
| Windows x86-64 on `windows-2022` | source target includes a ConPTY path | native receipt and public asset pending | unavailable operations fail closed until the WS5 backend lands |

## Linux requirements

Having a `bwrap` executable is not sufficient: the operating system must permit
the confinement probe to establish the required namespace boundary. Core Code
fails closed when bubblewrap is installed but unusable.

Ubuntu policy can restrict unprivileged user namespaces. Use a narrowly reviewed
profile for the installed bubblewrap binary rather than disabling a system-wide
security control.

## Windows

At source level, the interactive client shares the crossterm composition root
with Unix and is designed to run in a ConPTY terminal; there is no Windows copy
of the SQ/EQ protocol or result-v5 wire. The Windows terminal path creates and
resizes the ConPTY through `portable-pty`. One-shot mode and `core serve` share
the same App Server client. Headless clients use bounded JSONL over loopback TCP
rather than a Unix-domain socket and perform the same admission handshake.
These paths have not yet earned a native Windows release receipt.

The source implementation capability-probes terminal features. A non-empty
`WT_SESSION` is positive evidence for Windows Terminal OSC 8 links and OSC 9
notification intent. Conhost, redirected streams, unknown hosts, and failed
CSI-u negotiation keep plain visible paths, BEL notifications, and ordinary
keyboard input. Core never assumes escape-sequence support merely because the
operating system is Windows.

The planned Windows release artifact is a deterministic
`core-code-vVERSION-x86_64-pc-windows-msvc.zip` archive containing `core.exe`,
licenses, notices, SBOM, and build metadata. Once published, it must be verified
against `SHA256SUMS` and its GitHub build/SBOM attestations before extraction.
The POSIX `install.sh` does not install Windows archives.

The Windows Confinement implementation is intentionally consumed as a
fall-closed stub. Source paths that do not require the unavailable sandbox remain
separate from it; Core does not silently execute an unconfined command. This
source invariant does not by itself confer native runtime or release support.

## Terminal behavior

The TUI source path requires terminal stdin and stdout and includes terminal
restoration on normal exit and panic, plus covered SIGTERM and SIGHUP paths on
Unix. Rendering degrades for narrow or non-truecolor terminals; `NO_COLOR`
selects a monochrome surface. Native release receipts remain required before
these source-level behaviors become platform support claims.

These are implementation and proposed release targets, not a compatibility SLA.
Release notes must name only exact triples that were actually built and
smoke-tested.
