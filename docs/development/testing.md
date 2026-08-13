# Testing

Iteron uses layered tests so local iteration stays fast while merge gates cover
the complete workspace and platform boundaries.

## Focused iteration

Run the smallest crate or named test that demonstrates the changed contract:

```sh
cargo test -p iteron-provider catalog --locked
cargo test -p iteron-cli tui::tests::picker --locked
cargo test -p iteron-sandbox --all-targets --locked
```

Tests should prove both the successful outcome and the bounded failure path.
Regression tests should fail for the original reason before the production fix.

## Full local gate

```sh
cargo fmt --all -- --check
cargo run --locked -p iteron-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

`--all-targets` is required: integration binaries, PTY tests, and less common
targets are part of the public contract.

## Test isolation

- Default tests must not require a network connection or provider account.
- Tests must not inherit real provider credentials.
- Temporary repositories must set their own synthetic Git identity and clean up.
- Time, output, file count, recursion, and allocation limits need adversarial
  tests at and beyond the boundary.
- Tests that spawn processes must prove timeout teardown and child reaping.
- Durable-state tests need normal, interrupted, corrupt, and incompatible input.

Real-network tests are marked ignored and run only through an explicit command.
They never become a required check unless the account, quota, data policy, and
failure ownership are documented.

## Platform evidence

macOS and Linux required jobs run the full workspace Rust gate. Linux CI installs
bubblewrap and loads a path-specific AppArmor user-namespace profile so the live
network-denial test must execute rather than skip. macOS runs live Seatbelt
confinement tests.

Windows is unsupported. The only always-on Windows lane is the non-blocking
`windows / check` job on `windows-latest`, which runs
`cargo check --workspace --locked --target x86_64-pc-windows-msvc`. It keeps
compile drift visible but is not native runtime, ConPTY, sandbox, installer, or
release evidence.

Do not treat a local macOS or DGX Linux pass as native Windows evidence, or any
one operating-system pass as evidence for another.

## Remote canaries

Changes to GitHub workflows, CODEOWNERS, rulesets, releases, installers, or Pages
need a real pull-request or public-download canary. Static YAML validation and a
local HTTP server are useful but not proof of GitHub enforcement.
