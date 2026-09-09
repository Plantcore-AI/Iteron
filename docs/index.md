<div class="iteron-hero">
  <img class="iteron-hero__logo" src="assets/brand/iteron-logo.png" alt="Iteron">
  <div class="iteron-hero__eyebrow">OPEN SOURCE · RUST · PRE-ALPHA · v0.0.20</div>
  <h1>Harness checkpoints for domain-specific agents.</h1>
  <p>Iteron is an open-source substrate for building, evaluating, and governing
  the harness around each model × task pair. Terminal coding is the first
  reference implementation.</p>
  <div class="iteron-actions">
    <a class="iteron-button iteron-button--primary" href="getting-started/installation/">Install Iteron</a>
    <a class="iteron-button" href="getting-started/quickstart/">Quickstart</a>
    <a class="iteron-button" href="https://github.com/Plantcore-AI/Iteron">GitHub</a>
  </div>
</div>

!!! warning "Pre-alpha software"
    Code execution is unconfined by default. Use `--ask-permissions` for the
    capability gate and `--confine` for macOS Seatbelt or Linux bubblewrap.
    Windows has no code-execution sandbox.

## What works today

<div class="grid cards" markdown>

-   **Terminal-first operation**

    ---

    A responsive full-screen TUI plus text, JSON, and stream-JSON interfaces
    for bounded automation.

-   **Provider choice**

    ---

    Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters,
    with built-in profiles for six providers.

-   **Explicit authority**

    ---

    Capability-based permissions, scoped effects, hard run limits, and
    macOS/Linux sandbox backends.

-   **Durable sessions**

    ---

    Hash-chained local records with continuation, resume, fork, checkpoint,
    and verification contracts.

</div>

Iteron can read, search, and edit a workspace; run explicitly authorized
commands; work with Git, web, memory, skills, hooks, and external tool servers;
and run a verification command before accepting completion.

## Start in five minutes

Install the latest public release on macOS or Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Plantcore-AI/Iteron/releases/latest/download/install.sh | sh
```

Then validate a provider credential and open a repository:

```sh
iteron setup --byok glm
cd /path/to/repository
iteron
```

Release v0.0.20 also publishes a Windows x86-64 binary and PowerShell installer;
Windows remains unconfined for code execution. Follow [Installation and
verification](getting-started/installation.md), then review [permissions and
sandbox limitations](using/permissions-and-sandbox.md) before using an important
repository.

## Why Iteron

| Principle | What it means in practice |
| --- | --- |
| **Domain-specific substrate** | Each domain can define its model and task profiles, harness policies, evidence, and checkpoints on shared runtime contracts. |
| **Bounded runtime** | Turns, time, cost, retries, queues, output, and concurrency have explicit ceilings. |
| **Authority separation** | Strategies can propose work; they cannot grant capabilities or weaken hard constraints. |
| **Durable evidence** | Sessions, tool events, checkpoints, and verification results remain attributable and inspectable. |
| **Provider truth** | Model discovery reflects the credentials and capabilities actually available to the operator. |
| **Model-task fit** | Harness choices are evaluated for a model and task profile instead of being treated as universal defaults. |
| **Accountable ownership** | Public, machine-checked boundaries connect each subsystem to a responsible human maintainer. |

### Harness checkpoints

<div class="iteron-thesis">
agent behavior = frozen model × task × harness
</div>

A model is only one part of an agent system. Context selection, prompts, tools,
planning, scheduling, budgets, verification, and recovery can change the result
for a particular model and task. Iteron calls a typed, versioned bundle of those
choices a **harness checkpoint**.

The checkpoint thesis guides the architecture while the product remains a
straightforward CLI and terminal application. Safety, authority, evidence
integrity, and hard resource ceilings stay outside the optimization surface.
[Read the concept, current search surface, and implementation boundary
→](concepts/harness-checkpoints.md)

## Architecture

<div class="iteron-figure">
  <img src="assets/architecture/iteron-runtime-architecture-en.png" alt="Iteron runtime architecture showing offline evaluation, human promotion, policy resolution, the fixed kernel, and bounded execution">
</div>

The current codebase is a **modular monolith**. Source boundaries are machine
checked, while concrete composition still lives in the kernel and CLI/TUI. The
fixed-kernel layout in the diagram is a target contract and extraction direction,
not a shipped microkernel claim. Read the [architecture](architecture.md),
[project status](project/status.md), and [roadmap](roadmap.md) for the current
implementation truth and planned work.

## Community

Bug fixes, tests, documentation, provider adapters, evaluation fixtures, and
carefully scoped features are welcome. Start with the [contributor
guide](project/contributing.md) and [Code of
Conduct](https://github.com/Plantcore-AI/Iteron/blob/main/CODE_OF_CONDUCT.md).

<div class="iteron-lead">
  <a href="https://github.com/fr0m-scratch"><img src="https://github.com/fr0m-scratch.png?size=180" width="80" alt="Jamal Cao"></a>
  <div><strong><a href="https://github.com/fr0m-scratch">Jamal Cao</a></strong><br>
  <code>@fr0m-scratch</code> · <strong>Creator and Project Lead</strong><br>
  Sets Iteron's direction and holds final human override authority under the
  public governance contract.</div>
</div>

### Community contributors

<div class="iteron-contributor-grid">
  <a class="iteron-person" href="https://github.com/gomnitrix"><img src="https://github.com/gomnitrix.png?size=120" alt="gomnitrix"><strong>gomnitrix</strong><small>@gomnitrix</small></a>
  <a class="iteron-person" href="https://github.com/XZhouuuu"><img src="https://github.com/XZhouuuu.png?size=120" alt="XZhouuuu"><strong>XZhouuuu</strong><small>@XZhouuuu</small></a>
  <a class="iteron-person" href="https://github.com/yadonkai"><img src="https://github.com/yadonkai.png?size=120" alt="yadonkai"><strong>yadonkai</strong><small>@yadonkai</small></a>
</div>

Maintainer count is not fixed. Humans claim coherent module or invariant
boundaries, accept ongoing responsibility, and use protected review paths. Read
the [governance contract](project/governance.md) and [project status](project/status.md).

## Explore the documentation

<div class="grid cards" markdown>

-   **Get started**

    [Installation](getting-started/installation.md) ·
    [Setup and BYOK](getting-started/setup-and-byok.md) ·
    [Quickstart](getting-started/quickstart.md)

-   **Use Iteron**

    [Terminal UI](using/tui.md) ·
    [Models and providers](using/models-and-providers.md) ·
    [Sessions](using/sessions.md)

-   **Understand the system**

    [Architecture](architecture.md) ·
    [Harness checkpoints](concepts/harness-checkpoints.md) ·
    [Effects and authority](concepts/effects-and-authority.md)

-   **Build with us**

    [Contributing](project/contributing.md) ·
    [Development setup](development/setup.md) ·
    [Governance](project/governance.md)

</div>
