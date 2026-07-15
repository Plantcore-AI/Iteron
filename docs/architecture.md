# Architecture

## Target boundary

Core is intended to have three planes.

### Fixed runtime TCB

The trusted computing base owns versioned protocol and correlation, deterministic
state reduction, canonical record/checkpoint/replay, identity and trust,
capability admission, budgets/deadlines/cancellation, the single effect broker,
plugin lifecycle, and the exact policy bundle pinned to a run.

It does not read files or environment variables, call providers, build prompts,
select context, spawn processes, parse MCP, render UI, or train and activate a
policy directly.

### Replaceable strategy and world modules

Provider routing, planning, context, memory, tools, scheduling, verification,
orchestration, extensions, UI, and vertical-specific world adapters live outside
the TCB. They return bounded proposals and receive capability-scoped results; they
do not receive ambient authority.

### Evolution control plane

A future isolated control plane may produce immutable strategy candidates through
search, bandits, SFT, preference optimization, GRPO, offline RL, or later methods.
Promotion follows trajectory to governed dataset to candidate to held-out
evaluation to shadow to canary to active, with deterministic rollback.

Safety policy, permissions, durability, evidence integrity, budgets, data consent,
and promotion authority remain human-controlled and cannot be optimized away.

## Current implementation truth

The workspace is divided into protocol, record, observability, provider, tools,
sandbox, context, verification, MCP, scheduling, agents, kernel, CLI, evaluation,
and evolution-contract crates. This is useful modularity, but the kernel still
depends on concrete implementations and the CLI/TUI still participates in runtime
composition. Core therefore does not yet claim microkernel conformance.

This current modular monolith is nevertheless divided into machine-checked human
development boundaries. The boundary registry guarantees unique path
responsibility and detects internal Cargo dependency drift; invariant overlays
identify changes that need cross-cutting review. This collaboration contract does
not imply runtime isolation or microkernel conformance.

The extraction path is:

1. versioned canonical command/event envelopes;
2. a pure state reducer producing action requests;
3. one capability and effect broker;
4. injected provider, world, context, verification, and scheduler ports;
5. a long-lived session runtime with bounded flow control;
6. a versioned App Server used by the CLI/TUI and future clients.
