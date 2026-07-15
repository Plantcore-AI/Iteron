# Contributing

Core Code welcomes focused bug fixes, tests, provider evidence, terminal
compatibility work, documentation, and design discussion. Human contributors
remain accountable for changes produced with or without coding agents.

## Choose an entry path

- Small documentation or reproducible bug fixes may go directly to a pull
  request.
- Behavior, public interface, security-boundary, protocol, or cross-module work
  should start with an issue or Discussion.
- Vulnerabilities use the private security route.
- Ongoing module responsibility uses an ownership-claim issue; a contribution
  does not require becoming a maintainer.

Read the complete
[CONTRIBUTING.md](https://github.com/Plantcore-AI/core/blob/main/CONTRIBUTING.md)
and [Code of Conduct](https://github.com/Plantcore-AI/core/blob/main/CODE_OF_CONDUCT.md)
before opening a pull request.

## Local start

```sh
git clone https://github.com/YOUR-ACCOUNT/core.git
cd core
cargo build --locked -p core-cli
cargo test --workspace --all-targets --locked
```

Default tests need no provider credential. Linux contributors should install a
usable bubblewrap so the live confinement test runs.

## Required evidence

```sh
cargo fmt --all -- --check
cargo run --locked -p core-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

Behavior changes need a regression or integration test. TUI rendering changes
need semantic and terminal evidence. Do not include real credentials, private
sessions, proprietary source, generated-by trailers, or unrelated cleanup.

Start with the [development setup](../development/setup.md),
[testing guide](../development/testing.md), and
[review process](../development/review-process.md).
