# ADR-0002: Model-directed workflow topology

- Status: accepted
- Date: 2026-08-14
- Supersedes: ADR-0001 decision 2 only (the single-renderer decision remains active)
- Applies to: `crates/cli/src/runtime`, `crates/tools/src/workflow_tool.rs`,
  `crates/agents/src/catalog.rs`, `crates/workflow`

## Context

Ultracode previously classified an operator task before the main model saw it. Every positive
route launched one fixed planning -> read-only fan -> return script in the background, while the
main model continued independently. An unmatched task defaulted to an under-specified fan class.
The result was a deterministic positive trigger for a topology whose evidence was not necessarily
on the causal path of the work it was meant to inform.

The workflow engine already exposes the safer and more general seam: the main model can call
`Workflow` with a task-specific ESM script, while QuickJS and the host bound calls, concurrency,
wall time, recursion, capabilities, persistence, cancellation, and writer merges.

## Decision

The main model owns positive workflow admission and topology.

- A submission enters the ordinary model loop. Not calling `Workflow` is the direct plan and must
  remain a first-class outcome.
- When delegation has expected value, the model may submit an inline workflow script whose graph,
  phases, dependencies, concurrency, joins, conditionals, and failure handling fit that task.
- No lexical rule, task class, named preset, or harness prompt may positively require a workflow
  or impose canonical stages. Host policy may deny or narrow a proposal only to preserve fixed
  safety, authority, budget, or merge invariants; it may not turn a direct model decision into
  fan-out.
- Workflow results are in-turn by default so prerequisite evidence reaches the model that requested
  it. Background execution is an explicit model choice for work independent of the current turn.
- An `agent()` failure remains local evidence (`null` plus a surfaced degradation). The script may
  continue, stop, or use another bounded branch, and the main model may revise the next proposal
  after observing the result.

The host fixes only safety, authority, budget, and merge boundaries; topology remains model-owned.
In particular, model-authored scripts cannot widen run or session budgets, delegate recursively,
grant tools, bypass capability admission, write outside an isolated writer worktree, merge their
own patch, or arbitrate a conflict. Multiple writer nodes may be declared, but verified merges
remain serialized.

## Consequences

- Ultracode describes a reasoning-effort posture, not a fixed workflow.
- The public `Workflow` tool describes dynamic composition and the choice between in-turn and
  background execution. A built-in `ultracode` workflow name is not part of that model surface.
- The generic script engine and its renderer, journal, resume, bounded scheduler, and writer
  isolation remain unchanged. Failure handling and bounded alternate branches remain script-owned.
- Router and planner strategy slots remain valid extension points for bounded proposals, but they
  are not an ambient pre-model dispatcher.

## Affected boundaries and invariant overlays

Boundary IDs: `cli-host`, `tools-execution`, `agent-catalog`, `workflow-engine`,
`architecture-roadmap`, `public-compatibility`.

Invariant overlays retained: bounded, recoverable, reproducible, observable, security-bounded;
plus `spawn_depth_control`, `per_session_spawn_cap`, `writer_worktree_isolation_mode`,
and `merge_conflict_arbitration`.
