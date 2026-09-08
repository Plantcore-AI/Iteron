<h1 align="center">
  <img src="docs/assets/brand/iteron-logo.svg" width="720" alt="Iteron">
</h1>

<p align="center">
  <strong>The open-source substrate for domain-specific harness checkpoints.</strong><br>
  Build, evaluate, and govern the harness around each model × task pair.
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
  · <a href="#why-iteron">Why Iteron</a>
  · <a href="docs/architecture.md">Architecture</a>
  · <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!WARNING]
> **Pre-alpha; code execution is unconfined by default.** Iteron is intended for
> development and evaluation, not unattended use on sensitive repositories.
> Use `--ask-permissions` to restore the capability gate and `--confine` for
> macOS Seatbelt or Linux bubblewrap. Windows has no code-execution sandbox;
> `--confine` refuses command execution there.

Iteron is an open-source substrate for building, evaluating, and governing
**harness checkpoints for domain-specific AI agents**. It provides modular Rust runtime
contracts for context, tools, policies, permissions, evidence, and the checkpoint
lifecycle. A terminal coding agent is the first reference implementation, with
interactive work, bounded automation, provider routing, durable sessions,
verification, and machine-readable output. The workspace and latest public
release are **v0.0.20**.

## Install

macOS and Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh
```

Windows PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; Invoke-RestMethod -Uri 'https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.ps1' | Invoke-Expression
```

The v0.0.20 release publishes macOS arm64, Linux arm64, Linux x86-64, and
Windows x86-64 binaries. The installer verifies the selected archive and
installs for the current user without elevation. Windows distribution does not
change the sandbox boundary described above. See the [installation and
verification guide](docs/getting-started/installation.md) for version pinning,
checksums, attestations, and source builds.

Verify shell resolution without loading a provider credential:

```sh
command -v iteron
iteron --version
```

## Quickstart

Validate and store a provider credential outside the repository:

```sh
iteron setup --byok glm
```

Open a repository and start the full-screen interface:

```sh
cd /path/to/repository
iteron
```

Inside the TUI, describe the outcome you want. Use `/model` to choose an
account-visible model, `/permissions` to inspect authority, and `/help` for the
command registry.

For bounded one-shot work:

```sh
iteron -p -C /path/to/repository \
  --max-turns 24 \
  --verify 'cargo test --workspace --all-targets --locked' \
  "Fix the failing test, verify the change, and summarize the evidence"
```

For an untrusted repository, enable both controls:

```sh
iteron -p -C /path/to/untrusted-repository --ask-permissions --confine \
  "Explain what this repository's build script does"
```

Continue with the [five-minute quickstart](docs/getting-started/quickstart.md),
[Setup and BYOK](docs/getting-started/setup-and-byok.md), and [permissions and
sandbox guide](docs/using/permissions-and-sandbox.md).

## Why Iteron

| Principle | Contract |
| --- | --- |
| **Domain-specific substrate** | Shared runtime contracts let each domain define its model and task profiles, harness policies, evidence, and checkpoints. |
| **Terminal native** | Full-screen TUI plus text, JSON, and stream-JSON automation. |
| **Bounded runtime** | Explicit ceilings for turns, time, cost, retries, queues, output, and concurrency. |
| **Authority separation** | Strategies may propose work; they cannot grant capabilities, relax hard budgets, or rewrite evidence. |
| **Durable evidence** | Hash-chained sessions, checkpoints, correlated tool events, and provider-grounded usage states. |
| **Provider truth** | Credential-visible discovery and explicit available, disabled, or unknown capability states. |
| **Model-task fit** | Harness choices are evaluated for a model and task profile instead of being treated as universal defaults. |
| **Modular ownership** | Machine-validated Rust boundaries with accountable human maintainers and protected review. |

### Harness checkpoints

Iteron's central design thesis is that agent behavior comes from the interaction
of a frozen model, a task, and the harness around them:

```text
agent behavior = frozen model × task × harness
```

A **harness checkpoint** is the typed, versioned bundle of context, prompts,
tools, planning, budgets, verification, and recovery policies selected for a
measured model-task region. Quality, cost, latency, and reliability remain
separate outcomes; permissions, evidence integrity, and hard resource ceilings
remain fixed constraints.

This thesis guides Iteron's architecture without changing the everyday product
surface: users install one CLI, choose a provider, work in the terminal, and get
bounded execution with durable evidence. Read [Harness
checkpoints](docs/concepts/harness-checkpoints.md) for the search surface,
sensitivity model, applicability rules, and current implementation boundary.

## Architecture

Iteron freezes authority in the host and lets typed harness policies propose
bounded work. Offline candidates move through independent evaluation, human
promotion, and a content-pinned registry before a resolver can install them into
runtime slots.

<p align="center">
  <img src="docs/assets/architecture/iteron-runtime-architecture-en.png" width="940" alt="Iteron runtime architecture showing offline evaluation, human promotion, policy resolution, the fixed kernel, and bounded execution">
</p>

Iteron optimizes **harness artifacts only**. Base-model weights and adapters are
frozen. Historical SFT, preference, GRPO, and RL names in the wire vocabulary
describe producer provenance for a harness artifact; they do not authorize model
training or trajectory export for model training.

The current codebase is a **modular monolith**. The fixed-kernel boundary above
is a target contract and extraction direction, not a shipped microkernel claim.
The [architecture guide](docs/architecture.md), [claim
sheet](docs/reference/claim-sheet.md), and [project
status](docs/project/status.md) keep current implementation facts separate from
the target.

## What ships today

- Interactive TUI and bounded one-shot text, JSON, and stream-JSON interfaces.
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters.
- Built-in profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and
  Fireworks, plus operator-defined compatible routes.
- Workspace read, search, edit, shell, Git, web, memory, skills, hooks, external
  tool servers, and verification primitives with typed capabilities.
- Permission rules behind `--ask-permissions`; macOS Seatbelt and Linux
  bubblewrap backends behind `--confine`.
- Hash-chained local sessions with resume, continue, fork, checkpoint, and
  replay-oriented contracts.

Iteron remains pre-alpha. It does not claim production readiness,
confidentiality isolation, complete microkernel conformance, live
self-evolution, or benchmark superiority. Current evidence and open work are
tracked in the [claim sheet](docs/reference/claim-sheet.md), [project
status](docs/project/status.md), and [roadmap](docs/roadmap.md).

## Documentation

| Start | Use | Build and govern |
| --- | --- | --- |
| [Installation](docs/getting-started/installation.md) | [Terminal UI](docs/using/tui.md) | [Architecture](docs/architecture.md) |
| [Quickstart](docs/getting-started/quickstart.md) | [Models and providers](docs/using/models-and-providers.md) | [Contributor guide](CONTRIBUTING.md) |
| [Setup and BYOK](docs/getting-started/setup-and-byok.md) | [Sessions](docs/using/sessions.md) | [Governance](GOVERNANCE.md) |
| [Troubleshooting](docs/reference/troubleshooting.md) | [Permissions and sandbox](docs/using/permissions-and-sandbox.md) | [Harness checkpoints](docs/concepts/harness-checkpoints.md) |

## Contributing

Bug fixes, tests, documentation, provider adapters, evaluation fixtures, and
carefully scoped features are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md),
follow the [Code of Conduct](CODE_OF_CONDUCT.md), and browse the [good first
issues](https://github.com/Plantcore-AI/Iteron/labels/good%20first%20issue).

## Governance and leadership

<table>
  <tr>
    <td width="92" align="center">
      <a href="https://github.com/fr0m-scratch"><img src="https://github.com/fr0m-scratch.png?size=160" width="76" alt="Jamal Cao (@fr0m-scratch)"></a>
    </td>
    <td>
      <strong><a href="https://github.com/fr0m-scratch">Jamal Cao</a></strong><br>
      <code>@fr0m-scratch</code> · <strong>Creator and Project Lead</strong><br>
      Sets Iteron's direction and holds final human override authority under the
      public governance contract.
    </td>
  </tr>
</table>

Maintainer count is intentionally not fixed. Humans claim coherent module or
invariant boundaries, accept ongoing responsibility, and use protected review
paths. See [GOVERNANCE.md](GOVERNANCE.md) and
[OWNERSHIP.md](OWNERSHIP.md).

### Community contributors

<table>
  <tr>
    <td align="center" width="33%"><a href="https://github.com/gomnitrix"><img src="https://github.com/gomnitrix.png?size=120" width="56" alt="gomnitrix"><br><strong>@gomnitrix</strong></a></td>
    <td align="center" width="33%"><a href="https://github.com/XZhouuuu"><img src="https://github.com/XZhouuuu.png?size=120" width="56" alt="XZhouuuu"><br><strong>@XZhouuuu</strong></a></td>
    <td align="center" width="33%"><a href="https://github.com/yadonkai"><img src="https://github.com/yadonkai.png?size=120" width="56" alt="yadonkai"><br><strong>@yadonkai</strong></a></td>
  </tr>
</table>

## Security

Do not report vulnerabilities in public issues. Use GitHub's private **Report a
vulnerability** flow described in [SECURITY.md](SECURITY.md). Never include
credentials, customer data, private session records, or weaponized exploit
material in public channels.

## License

Iteron is licensed under the [Apache License, Version 2.0](LICENSE). No CLA is
required.
