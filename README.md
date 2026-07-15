# Core

Core is an experimental coding agent and the beginning of a general-agent
microkernel. The coding distribution is the first vertical; the long-term goal is a
small invariant runtime surrounded by replaceable providers, context strategies,
tools, planners, verifiers, clients, and domain adapters.

> **Status: pre-alpha.** Core is useful for development and evaluation, but it is
> not production-ready and should not be run unattended against sensitive systems.

## What exists today

- A terminal-native interactive UI and one-shot CLI.
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters.
- Built-in provider profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and
  Fireworks, with explicit disabled and unknown model states.
- Workspace read, search, edit, shell, Git, memory, MCP, hooks, and verification
  primitives.
- Hash-chained local session records with resume and fork support.
- Permission modes, scoped effects, bounded retries, and macOS/Linux sandbox
  backends.
- Initial contracts for a future governed strategy-evolution control plane.

The current runtime is still a modular monolith. A true microkernel, a stable App
Server protocol, complete process supervision, full MCP/LSP support, trustworthy
cost accounting, cross-platform release hardening, and production evaluation are
active roadmap work.

## Principles

Core evaluates every mechanism against five invariants:

1. **Bounded** — loops, retries, queues, output, time, cost, and concurrency have
   explicit ceilings.
2. **Recoverable** — interruption and crash have explicit durable recovery
   semantics.
3. **Reproducible** — recorded nondeterministic decisions replay; model outputs are
   replayed rather than re-derived.
4. **Observable** — phase, usage, effect, verification, and strategy attribution
   are emitted.
5. **Security-bounded** — authority is deny-by-default and its blast radius is
   explicit.

Learned or replaceable strategies may propose actions. They may not grant
capabilities, rewrite evidence, relax hard budgets, or promote themselves.

## Build

Core currently requires Rust 1.90 or newer.

```sh
cargo build --release -p core-cli
./target/release/core --help
```

Run the TUI from a repository:

```sh
./target/release/core -C /path/to/repository
```

Run a one-shot task:

```sh
./target/release/core -p -C /path/to/repository \
  "Find the failing test, fix the cause, and verify the change"
```

Provider credentials are read from the process environment. Never commit them to
the target repository or Core configuration. Code execution is disabled by
default; review the permission and sandbox limitations before enabling it.

## Verify a change

```sh
cargo fmt --all -- --check
cargo run --locked -p core-xtask -- boundaries check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

## Architecture and roadmap

- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Repository enforcement](docs/repository-enforcement.md)
- [Maintainer onboarding](docs/maintainer-onboarding.md)
- [Governance](GOVERNANCE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Community

Core has one human Owner/Project Lead with final override authority and an
open-ended group of human maintainer/engineers. Maintainers choose coherent module
or invariant boundaries from the machine-validated
[ownership registry](governance/boundaries.json); the generated human view is
[OWNERSHIP.md](OWNERSHIP.md), and the number of maintainers is not fixed. Each
maintainer may use one persistent coding agent,
but agents do not hold maintainer authority, approve changes, or coordinate the
project autonomously. The Owner's authority cannot be delegated to an agent.

Issues, design discussions, tests, bug fixes, provider adapters, documentation, and
focused feature contributions are welcome. The human submitting a contribution is
responsible for understanding and supporting it, whether or not AI tools assisted.

## License

Core is licensed under the [Apache License, Version 2.0](LICENSE). Unless a
contributor explicitly states otherwise, intentionally submitted contributions are
licensed under the same terms as described in Section 5 of that license. No CLA is
required.
