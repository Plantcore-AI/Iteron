# Core Code

[![CI](https://github.com/Plantcore-AI/core/actions/workflows/ci.yml/badge.svg)](https://github.com/Plantcore-AI/core/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Plantcore-AI/core?display_name=tag&sort=semver)](https://github.com/Plantcore-AI/core/releases)
[![Docs](https://img.shields.io/badge/docs-online-0969da)](https://plantcore-ai.github.io/core/)
[![MSRV](https://img.shields.io/badge/rust-1.90%2B-93450a)](https://www.rust-lang.org/)
[![License](https://img.shields.io/github/license/Plantcore-AI/core)](LICENSE)

Core Code is an open-source, terminal-native coding agent and a modular Rust
substrate for bounded, recoverable, and observable agent runtimes. The `core`
binary is the first product built on that substrate.

Created and led by [Jamal Cao (@fr0m-scratch)](https://github.com/fr0m-scratch),
Core Code's Creator and Project Lead.

> [!WARNING]
> **Status: public pre-alpha.** Core Code is suitable for development and
> evaluation, but interfaces can change and it is not yet production-ready. Do
> not run it unattended against sensitive systems.

## Install

Install the latest release on macOS or Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Plantcore-AI/core/releases/latest/download/core-installer.sh | sh
```

The installer selects the archive for the current OS and architecture, verifies
its SHA-256 digest, and installs `core` without `sudo`. See the
[installation guide](docs/getting-started/installation.md) for supported targets,
version pinning, install locations, checksum and provenance verification, manual
installation, and uninstall instructions.

To build from source instead:

```sh
git clone https://github.com/Plantcore-AI/core.git
cd core
cargo install --locked --path crates/cli
```

Core Code requires Rust 1.90 or newer when built from source.

## Quickstart

Provider credentials are read from the process environment and are never written
to project configuration. Core Code defaults to the GLM provider and its
documented GLM 5.2 catalog default; a missing credential leaves the provider and
its models visibly unavailable.

```sh
export GLM_API_KEY='your-key-from-a-secret-manager'
cd /path/to/repository
core
```

Inside the TUI, describe the outcome you want. Use `/model` to inspect available
providers and models, `/permissions` before granting additional authority, and
`/help` for the complete command list.

For a bounded one-shot run:

```sh
core -p -C /path/to/repository \
  --max-turns 24 \
  "Explain the failing test and propose the smallest correct fix"
```

Code execution is disabled by default. Enable it only when the repository and the
configured sandbox boundary are appropriate:

```sh
core -p -C /path/to/repository \
  --allow-code \
  --verify 'cargo test --workspace --all-targets --locked' \
  "Fix the failing test, verify the change, and summarize the evidence"
```

Read the [quickstart](docs/getting-started/quickstart.md),
[provider guide](docs/getting-started/providers.md), and
[permissions and sandbox guide](docs/using/permissions-and-sandbox.md) before
using Core Code on important work.

## What ships today

- A full-screen terminal UI with a persistent transcript, model and effort
  controls, permission prompts, session history, and observable tool activity.
- Interactive and one-shot CLI surfaces, including text, JSON, and stream-JSON
  output contracts.
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible chat transports,
  with built-in profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and
  Fireworks.
- Credential-aware, bounded model discovery that distinguishes documented models,
  account-visible models, disabled entries, and unknown availability.
- Workspace read, search, edit, shell, Git, web, memory, skills, hooks, MCP, and
  verification primitives with typed capabilities.
- Deny-by-default authority, bounded retries and output, macOS Seatbelt and Linux
  bubblewrap backends, and explicit external-egress escalation.
- Hash-chained local session records with resume, continue, fork, checkpoint, and
  replay-oriented contracts.
- Modular planning, context, verification, evaluation, observability, and future
  evolution boundaries that can be replaced without granting them kernel
  authority.

## Architecture

Core Code separates authority-bearing runtime mechanisms from replaceable agent
strategies. The workspace is modular today, while the runtime remains a modular
monolith; it does **not** yet claim full microkernel conformance.

| Plane | Current modules | Responsibility |
| --- | --- | --- |
| Authority | `protocol`, `kernel`, `sched` | Events, capabilities, effects, budgets, retries, and lifecycle |
| Intelligence | `provider`, `ctx`, `agents`, `verify` | Models, context, decomposition, synthesis, and evidence selection |
| Execution | `tools`, `sandbox`, `mcp` | Bounded workspace effects and external tool integration |
| Evidence | `record`, `obs`, `eval` | Durable records, telemetry contracts, and evaluation ground truth |
| Evolution | `evolve` | Non-authoritative strategy candidates and promotion contracts |
| Product | `cli` | TUI, one-shot CLI, configuration, provider selection, and output surfaces |

Every mechanism is evaluated against five invariants:

1. **Bounded** — loops, retries, queues, output, time, cost, and concurrency have
   explicit ceilings.
2. **Recoverable** — interruption and crash have explicit durable recovery
   semantics.
3. **Reproducible** — recorded nondeterministic decisions can be replayed without
   silently re-deriving model output.
4. **Observable** — phase, usage, effects, verification, and strategy attribution
   are represented as events.
5. **Security-bounded** — authority is deny-by-default and its blast radius is
   explicit.

Learned or replaceable strategies may propose actions. They may not grant
capabilities, rewrite evidence, relax hard budgets, or promote themselves. See the
[architecture](docs/architecture.md) and
[machine-validated ownership map](OWNERSHIP.md) for the current contracts.

## Current limitations

- The project is pre-alpha; CLI, configuration, record, and protocol compatibility
  can change before a stable release.
- macOS and Linux are the current supported platforms. Windows is not supported.
- The sandbox reduces blast radius but is not a VM or a confidentiality boundary;
  a kernel or policy failure remains in the trusted computing base.
- Provider catalog visibility does not prove account funding, quota, entitlement,
  or future model availability.
- Monetary accounting is reported only when authoritative provider evidence is
  available; Core Code does not invent prices from token counts.
- The App Server, complete MCP and LSP surfaces, production evaluation corpus,
  stable plugin ABI, and governed learning or self-evolution loop remain roadmap
  work.

The [roadmap](docs/roadmap.md) uses acceptance evidence rather than marketing
dates and keeps delivered foundations separate from unaccepted milestones.

## Documentation

The complete documentation is published at
**[plantcore-ai.github.io/core](https://plantcore-ai.github.io/core/)**.

- [Installation](docs/getting-started/installation.md)
- [Quickstart](docs/getting-started/quickstart.md)
- [Providers and models](docs/getting-started/providers.md)
- [Terminal UI](docs/using/tui.md)
- [Permissions and sandbox](docs/using/permissions-and-sandbox.md)
- [CLI reference](docs/reference/cli.md)
- [Configuration reference](docs/reference/configuration.md)
- [Architecture](docs/architecture.md)
- [Roadmap](docs/roadmap.md)
- [Contributor guide](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md) and [ownership](OWNERSHIP.md)
- [Security policy](SECURITY.md) and [support](SUPPORT.md)
- [Changelog](CHANGELOG.md)

## Contributing

Focused issues, tests, bug fixes, provider adapters, documentation, evaluation
fixtures, and carefully scoped features are welcome. Start with the
[contributor guide](CONTRIBUTING.md), follow the
[Code of Conduct](CODE_OF_CONDUCT.md), and open or join an issue before a
cross-boundary or public-contract change.

Core Code uses human-owned module and invariant boundaries rather than a fixed
maintainer count. A contributor does not need to become a maintainer, and coding
agents never hold review, merge, or governance authority. See
[GOVERNANCE.md](GOVERNANCE.md) for the human decision model.

## Security

Please do not report suspected vulnerabilities in a public issue. Use GitHub's
private **Report a vulnerability** flow described in [SECURITY.md](SECURITY.md).
Never include real credentials, customer data, or weaponized exploit material in
public discussions.

## License

Core Code is licensed under the [Apache License, Version 2.0](LICENSE). Unless a
contributor explicitly states otherwise, intentionally submitted contributions
are licensed under the same terms as described in Section 5 of the license. No CLA
is required.
