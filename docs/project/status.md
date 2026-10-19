# Project status

Iteron is Apache-2.0 licensed and **pre-alpha**. The current `main` branch is the
only development line; there is no stable compatibility or support promise.
The current source workspace declares **v0.0.30**. Published versions are listed
on [GitHub Releases](https://github.com/Plantcore-AI/Iteron/releases).

## Delivered baseline

The repository currently contains:

- a Rust workspace split across protocol, record, observability, provider, tools,
  sandbox, context, verification, MCP, scheduling, agent policy, kernel, host, App Server, CLI,
  evaluation, and evolution-contract crates;
- an interactive TUI and one-shot text/JSON/JSONL frontend;
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters;
- built-in profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and Fireworks;
- workspace read/search/edit, shell, Git, memory, skills, hooks, initial MCP, and
  verification primitives;
- hash-chained local records with sessions, continuation, resume, and fork;
- four permission modes, an optional capability gate, bounded runs, and
  macOS/Linux sandbox backends selected with `--confine`; the shipped default is
  unconfined and bypasses permission prompts;
- machine-validated human ownership boundaries and repository review policy;
- a repository-only `iteron-harness` research executable, versioned JSON protocol schema,
  stdlib-only Python client, and credential-free fixture optimizer; these research tools are
  source interfaces and are deliberately absent from release archives and the installer;
- versioned pre-alpha releases. The GitHub release page, manifest and asset list
  are authoritative for each version's published targets and attestations;
- a release workflow covering macOS arm64, Linux arm64/x86-64, and Windows
  x86-64, with installers, checksums, license evidence, SBOMs, provenance, and
  public-install canaries. Windows distribution remains narrower than full
  runtime support because it has no code-execution sandbox.

## Not accepted as complete

Iteron does not yet claim:

- production readiness or unattended safety on sensitive repositories;
- conformance to the target microkernel architecture;
- a stable App Server or public runtime protocol;
- complete MCP, LSP, plugin, PTY, or background-process lifecycle support;
- authoritative context, cache, cost, or billing truth for every provider route;
- a Windows code-execution sandbox or supported Windows interactive TUI;
- a stable compatibility promise or long-term support;
- model training or fine-tuning of any kind; legacy SFT, preference, GRPO, and
  RL names are provenance labels for harness candidates only;
- autonomous policy promotion;
- benchmark-performance superiority or results from a completed real campaign;
- parity with Codex, Claude Code, or another production coding agent.

## How progress is accepted

Roadmap milestones are evidence gates, not marketing dates. A feature existing in
one crate is not enough: cross-platform tests, failure behavior, recovery,
observability, security boundaries, and integration evidence determine whether a
milestone can be accepted.

See the [roadmap](../roadmap.md), [architecture](../architecture.md), and
[repository enforcement](../repository-enforcement.md).
