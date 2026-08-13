# Development setup

## Prerequisites

The supported Iteron source and release targets are macOS and Linux. Install Git,
a Rust toolchain at version 1.90 or newer, and the compiler/linker required by
the target. Windows is not supported and its advisory cross-compilation CI is
currently paused. The repository does not use a JavaScript build for the product
runtime.

```sh
rustup toolchain install 1.90.0 --profile minimal \
  --component clippy,rustfmt
rustup default 1.90.0
```

Linux developers should install bubblewrap so the live sandbox test executes:

```sh
sudo apt-get install bubblewrap
```

Ubuntu 24.04 restricts unprivileged user namespaces with AppArmor. Iteron
detects an installed-but-unusable `bwrap` and fails closed; it never falls back to
unconfined execution. Use a reviewed profile attached only to `/usr/bin/bwrap`, as
the Linux CI job does. Do not disable the system-wide user-namespace restriction
to make a test pass.

macOS uses the system `sandbox-exec`/Seatbelt boundary and needs no extra package.

The advisory Windows lane runs
`cargo check --workspace --locked --target x86_64-pc-windows-msvc`. It is
non-blocking, does not package a release, and is not support evidence. There is
no Windows code-execution sandbox backend.

## Fork and clone

Create a GitHub fork, then:

```sh
git clone https://github.com/YOUR-ACCOUNT/Iteron.git
cd Iteron
git remote add upstream https://github.com/Plantcore-AI/Iteron.git
git fetch upstream
```

Keep `origin` pointed at your fork and `upstream` pointed at the upstream project.

## Build and run

```sh
cargo build --locked -p iteron-cli
./target/debug/iteron --help
./target/debug/iteron -C /path/to/a/test/repository
```

Use a disposable test repository for changes involving edits, shell execution,
permissions, hooks, or sandboxing. Code execution and the permission bypass are
on by default; use `--confine`, `--ask-permissions`, or `--mode plan` to narrow
the posture under test.

The default provider is GLM. A real interactive model call requires a provider
credential in the process environment, but builds and default tests require no
credential and make no provider request.

## Local configuration

User configuration lives below `~/.iteron`; repository-local `.iteron` state is
untrusted input and cannot grant itself new authority or redirect provider
credentials. Never commit either location or copy a real session into a fixture.

Use synthetic strings in tests. Secret-shaped fixtures must be constructed so
public push-protection scanners do not mistake them for live credentials.

## Troubleshooting

- Run `rustc --version` and confirm it satisfies the workspace `rust-version`.
- Use `cargo metadata --locked --no-deps` to catch workspace configuration errors.
- If Linux sandbox tests report `Unsupported`, run the exact capability probe in
  `crates/sandbox/src/bubblewrap.rs` and inspect local AppArmor policy.
- If a PTY test hangs, rerun only `cargo test -p iteron-cli --test tui_pty
  --locked -- --nocapture` and capture the terminal size and OS.
- If generated ownership is stale, run `cargo run --locked -p iteron-xtask --
  boundaries generate`, then validate the resulting diff.

Do not solve a local failure by weakening a security test, disabling a gate, or
adding a credential to the repository.
