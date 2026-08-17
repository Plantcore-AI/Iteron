<h1 align="center">
  <img src="docs/assets/brand/iteron-logo.svg" width="720" alt="Iteron">
</h1>

<p align="center">
  <strong>An Apache-2.0 coding agent for the terminal.</strong><br>
  Bounded execution, durable evidence, observable work, and explicit authority.
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-CN.md"><strong>简体中文</strong></a>
</p>

<p align="center">
  <a href="https://github.com/Plantcore-AI/Iteron/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Plantcore-AI/Iteron/ci.yml?branch=main&amp;label=CI&amp;style=flat-square"></a>
  <a href="https://github.com/Plantcore-AI/Iteron/actions/workflows/docs.yml"><img alt="Documentation" src="https://img.shields.io/github/actions/workflow/status/Plantcore-AI/Iteron/docs.yml?branch=main&amp;label=docs&amp;style=flat-square"></a>
  <a href="https://github.com/Plantcore-AI/Iteron/releases"><img alt="Release" src="https://img.shields.io/github/v/release/Plantcore-AI/Iteron?display_name=tag&amp;sort=semver&amp;style=flat-square"></a>
  <a href="https://www.rust-lang.org/"><img alt="Rust 1.90+" src="https://img.shields.io/badge/rust-1.90%2B-93450a?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/github/license/Plantcore-AI/Iteron?style=flat-square"></a>
</p>

<p align="center">
  <a href="https://plantcore-ai.github.io/Iteron/">Documentation</a>
  · <a href="#install">Install</a>
  · <a href="#quickstart">Quickstart</a>
  · <a href="docs/getting-started/setup-and-byok.md">BYOK</a>
  · <a href="docs/architecture.md">Architecture</a>
  · <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!WARNING]
> **Pre-alpha; code execution is unconfined by default.** Iteron is intended for
> development and evaluation, not unattended use on sensitive repositories.
> Use `--ask-permissions` to restore the capability gate and `--confine` to put
> executed code inside the macOS Seatbelt or Linux bubblewrap sandbox. Windows
> has no code-execution sandbox; `--confine` refuses to run commands there.

Iteron combines a focused full-screen coding experience with a modular Rust
runtime. It supports interactive work, bounded one-shot automation, explicit
permissions, provider routing, durable sessions, verification, and
machine-readable output. The current workspace version is **v0.0.7**.

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh
```

On Windows, use the PowerShell installer from the same release:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri 'https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.ps1' | Invoke-Expression
```

The installers verify the selected release archive and install per-user without
elevation. Release targets are macOS arm64, Linux arm64, Linux x86-64, and
Windows x86-64. See the [installation and verification
guide](docs/getting-started/installation.md) for version pinning, checksums,
attestations, and source builds.

Windows gets a binary and an installer, and nothing more: there is no Windows
code-execution sandbox, so confinement is unavailable there. See
[supported platforms](docs/reference/platforms.md) before relying on it.

Verify that the installed directory is on the shell's executable search path:

```sh
command -v iteron
iteron --version
```

If the first command prints nothing, add the install directory (normally
`$HOME/.local/bin`) to `PATH` and open a new shell. This check does not need a
provider credential.

## Quickstart

Validate and store a provider credential outside the repository:

```sh
iteron setup --byok glm
```

Then open a repository:

```sh
cd /path/to/repository
iteron
```

Inside the TUI, describe the outcome you want. Use `/model` to choose an
account-visible model, `/permissions` to inspect authority, and `/help` for the
command registry. A missing credential leaves that provider unavailable rather
than pretending the route works.

For bounded one-shot work:

```sh
iteron -p -C /path/to/repository \
  --max-turns 24 \
  --verify 'cargo test --workspace --all-targets --locked' \
  "Fix the failing test, verify the change, and summarize the evidence"
```

Use both safety controls for an untrusted repository:

```sh
iteron -p -C /path/to/untrusted-repository --ask-permissions --confine \
  "Explain what this repository's build script does"
```

Continue with the [five-minute quickstart](docs/getting-started/quickstart.md),
[Setup and BYOK](docs/getting-started/setup-and-byok.md), and the
[permissions and sandbox guide](docs/using/permissions-and-sandbox.md).
Provider setup can be diagnosed without exposing or loading a credential; see
[credential-free provider diagnosis](docs/getting-started/provider-diagnosis.md).

## Why Iteron

| Principle | Contract |
| --- | --- |
| **Terminal native** | Full-screen TUI plus text, JSON, and stream-JSON automation. |
| **Bounded runtime** | Explicit ceilings for turns, time, cost, retries, queues, output, and concurrency. |
| **Authority separation** | Strategies may propose work; they cannot grant capabilities, relax hard budgets, or rewrite evidence. |
| **Durable evidence** | Hash-chained sessions, checkpoints, correlated tool events, and provider-grounded usage states. |
| **Provider truth** | Credential-visible discovery and explicit available, disabled, or unknown capability states. |
| **Modular ownership** | Machine-validated Rust boundaries with accountable human maintainers and protected review. |

## Architecture

The target boundary freezes authority in a small trusted computing base while
strategy slots and execution modules remain replaceable. Offline candidates can
reach the runtime only through held-out evaluation, shadow, canary, and explicit
human promotion. See the [architecture guide](docs/architecture.md) for the
current implementation boundary and extraction path.

Iteron optimizes **harness artifacts only**. Base-model weights and adapters are
frozen: their reserved manifest values are rejected. SFT, preference, GRPO, and
RL names in the evolution wire vocabulary describe producer provenance for a
harness artifact; they do not authorize model training or trajectory export for
model training.

![Iteron target architecture in English](docs/assets/architecture/iteron-architecture-en.png)

## What ships today

- Interactive TUI and bounded one-shot interfaces.
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters.
- Built-in profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and
  Fireworks, plus operator-defined compatible routes.
- Workspace read, search, edit, shell, Git, web, memory, skills, hooks, MCP, and
  verification primitives with typed capabilities.
- Permission rules behind `--ask-permissions`; macOS Seatbelt and Linux
  bubblewrap backends behind `--confine`.
- Hash-chained local sessions with resume, continue, fork, checkpoint, and
  replay-oriented contracts.

Iteron remains a modular monolith; it does not claim complete microkernel
conformance, production readiness, confidentiality isolation, live
self-evolution, or benchmark performance. The [evidence-bound claim
sheet](docs/reference/claim-sheet.md), [systems-paper
draft](docs/reference/harness-checkpoints-paper.md),
[architecture](docs/architecture.md), [project
status](docs/project/status.md), and [roadmap](docs/roadmap.md) distinguish
shipped behavior from target contracts.

## Documentation

| Start | Use | Build and govern |
| --- | --- | --- |
| [Installation](docs/getting-started/installation.md) | [Terminal UI](docs/using/tui.md) | [Architecture](docs/architecture.md) |
| [Quickstart](docs/getting-started/quickstart.md) | [Models and providers](docs/using/models-and-providers.md) | [Contributor guide](CONTRIBUTING.md) |
| [Setup and BYOK](docs/getting-started/setup-and-byok.md) | [Sessions](docs/using/sessions.md) | [Governance](GOVERNANCE.md) |
| [Troubleshooting](docs/reference/troubleshooting.md) | [Permissions and sandbox](docs/using/permissions-and-sandbox.md) | [Security](SECURITY.md) |

## Contributing

Bug fixes, tests, documentation, provider adapters, evaluation fixtures, and
carefully scoped features are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md),
follow the [Code of Conduct](CODE_OF_CONDUCT.md), and browse the
[good first issues](https://github.com/Plantcore-AI/Iteron/labels/good%20first%20issue).

## Governance and leadership

<table>
  <tr>
    <td width="92" align="center">
      <a href="https://github.com/fr0m-scratch"><img src="https://github.com/fr0m-scratch.png?size=160" width="76" alt="Jamal Cao (@fr0m-scratch)"></a>
    </td>
    <td>
      <strong><a href="https://github.com/fr0m-scratch">Jamal Cao</a></strong><br>
      <code>@fr0m-scratch</code> · Creator and Project Lead<br>
      Final project direction and override authority remain human-owned and
      auditable through the public governance contract.
    </td>
  </tr>
</table>

Maintainer count is intentionally not fixed. Humans claim coherent module or
invariant boundaries, accept ongoing responsibility, and use protected review
paths. See [GOVERNANCE.md](GOVERNANCE.md) and
[OWNERSHIP.md](OWNERSHIP.md).

## Security

Do not report vulnerabilities in public issues. Use GitHub's private **Report a
vulnerability** flow described in [SECURITY.md](SECURITY.md). Never include
credentials, customer data, private session records, or weaponized exploit
material in public channels.

## License

Iteron is licensed under the [Apache License, Version 2.0](LICENSE). No CLA is
required.
