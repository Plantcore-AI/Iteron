# Development setup

## Prerequisites

Core Code development is supported on macOS, Linux, and 64-bit Windows. Install
Git, a Rust toolchain at version 1.90 or newer, and the native compiler/linker
required by Rust. Windows builds use the MSVC toolchain and require the Visual
Studio Build Tools C++ workload. The repository does not use a JavaScript build
for the product runtime.

```sh
rustup toolchain install 1.90.0 --profile minimal \
  --component clippy,rustfmt
rustup default 1.90.0
```

Linux developers should install bubblewrap so the live sandbox test executes:

```sh
sudo apt-get install bubblewrap
```

Ubuntu 24.04 restricts unprivileged user namespaces with AppArmor. Core Code
detects an installed-but-unusable `bwrap` and fails closed; it never falls back to
unconfined execution. Use a reviewed profile attached only to `/usr/bin/bwrap`, as
the Linux CI job does. Do not disable the system-wide user-namespace restriction
to make a test pass.

macOS uses the system `sandbox-exec`/Seatbelt boundary and needs no extra package.

Windows uses the `x86_64-pc-windows-msvc` target. The client, ConPTY TUI, and
loopback App Server build natively, but code-execution operations whose WS5
Confinement backend is not yet available fail closed rather than running
unconfined.

## Fork and clone

Create a GitHub fork, then:

```sh
git clone https://github.com/YOUR-ACCOUNT/core.git
cd core
git remote add upstream https://github.com/Plantcore-AI/core.git
git fetch upstream
```

Keep `origin` pointed at your fork and `upstream` pointed at the public project.

## Build and run

```sh
cargo build --locked -p core-cli
./target/debug/core --help
./target/debug/core -C /path/to/a/test/repository
```

In PowerShell, run the built executable as `.\target\debug\core.exe`.

Use a disposable test repository for changes involving edits, shell execution,
permissions, hooks, or sandboxing. Code execution remains off unless explicitly
granted.

The default provider is GLM. A real interactive model call requires a provider
credential in the process environment, but builds and default tests require no
credential and make no provider request.

## Local configuration

User configuration lives below `~/.core`; repository-local `.core` state is
untrusted input and cannot grant itself new authority or redirect provider
credentials. Never commit either location or copy a real session into a fixture.

Use synthetic strings in tests. Secret-shaped fixtures must be constructed so
public push-protection scanners do not mistake them for live credentials.

## Troubleshooting

- Run `rustc --version` and confirm it satisfies the workspace `rust-version`.
- Use `cargo metadata --locked --no-deps` to catch workspace configuration errors.
- If Linux sandbox tests report `Unsupported`, run the exact capability probe in
  `crates/sandbox/src/bubblewrap.rs` and inspect local AppArmor policy.
- If a PTY test hangs, rerun only `cargo test -p core-cli --test tui_pty --locked
  -- --nocapture` on Unix, or `cargo test -p core-cli --test windows_conpty
  --locked -- --nocapture` on Windows, and capture the terminal size and OS.
- If generated ownership is stale, run `cargo run --locked -p core-xtask --
  boundaries generate`, then validate the resulting diff.

Do not solve a local failure by weakening a security test, disabling a gate, or
adding a credential to the repository.
