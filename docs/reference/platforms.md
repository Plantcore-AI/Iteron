# Supported platforms

Core Code is currently developed and tested on macOS and Linux. There is no
supported Windows runtime today.

| Platform | Build | Interactive TUI | Code-execution sandbox |
| --- | --- | --- | --- |
| macOS arm64 on `macos-15` | native release and CI | supported | system Seatbelt interface |
| macOS x86-64 on `macos-15-intel` | native release | supported | system Seatbelt interface |
| Linux x86-64 on `ubuntu-24.04` | native release and CI | supported | usable bubblewrap/user-namespace boundary required |
| Linux arm64 on `ubuntu-24.04-arm` | native release | supported | usable bubblewrap/user-namespace boundary required |
| Windows | unsupported | unsupported | no backend |

## Linux requirements

Having a `bwrap` executable is not sufficient: the operating system must permit
the confinement probe to establish the required namespace boundary. Core Code
fails closed when bubblewrap is installed but unusable.

Ubuntu policy can restrict unprivileged user namespaces. Use a narrowly reviewed
profile for the installed bubblewrap binary rather than disabling a system-wide
security control.

## Terminal behavior

The TUI requires terminal stdin and stdout and restores terminal state on normal
exit, panic, SIGTERM, and SIGHUP paths covered by the implementation. Rendering
degrades for narrow or non-truecolor terminals; `NO_COLOR` selects a monochrome
surface.

Pre-alpha support means these are implementation targets and CI surfaces, not a
compatibility SLA. Release notes must name the exact triples that were actually
built and smoke-tested.
