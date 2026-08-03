# Project status

Core Code is public, Apache-2.0 licensed, and **pre-alpha**. The current `main`
branch is the only development line; there is no stable compatibility or support
promise.

## Delivered baseline

The repository currently contains:

- a Rust workspace split across protocol, record, observability, provider, tools,
  sandbox, context, verification, MCP, scheduling, agent policy, kernel, CLI,
  evaluation, and evolution-contract crates;
- an interactive TUI and one-shot text/JSON/JSONL frontend;
- Anthropic Messages, OpenAI Responses, and OpenAI-compatible Chat adapters;
- built-in profiles for Anthropic, OpenAI, DeepSeek, GLM, MiniMax, and Fireworks;
- workspace read/search/edit, shell, Git, memory, skills, hooks, initial MCP, and
  verification primitives;
- hash-chained local records with sessions, continuation, resume, and fork;
- four permission modes, capability-based approval, bounded runs, and macOS/Linux
  sandbox backends;
- machine-validated human ownership boundaries and repository review policy;
- release tooling for a future native target matrix, installer, checksums,
  license evidence, SBOMs, provenance, and public-install canaries. No accepted
  binary release or native receipt currently exists.

## Not accepted as complete

Core Code does not yet claim:

- production readiness or unattended safety on sensitive repositories;
- conformance to the target microkernel architecture;
- a stable App Server or public runtime protocol;
- complete MCP, LSP, plugin, PTY, or background-process lifecycle support;
- authoritative context, cache, cost, or billing truth for every provider route;
- Windows distribution, a stable compatibility promise, or long-term support;
- live self-training, GRPO, reinforcement learning, or autonomous policy
  promotion;
- parity with Codex, Claude Code, or another production coding agent.

## How progress is accepted

Roadmap milestones are evidence gates, not marketing dates. A feature existing in
one crate is not enough: cross-platform tests, failure behavior, recovery,
observability, security boundaries, and integration evidence determine whether a
milestone can be accepted.

See the [roadmap](../roadmap.md), [architecture](../architecture.md), and
[repository enforcement](../repository-enforcement.md).
