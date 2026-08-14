# Ultracode

Ultracode is Iteron's highest effort setting. It combines the maximum
provider-facing reasoning intent with access to Iteron's bounded dynamic-workflow
engine.

```sh
iteron --effort ultracode
```

## Model-directed workflows

An Ultracode submission goes to the main model before any workflow is launched. The model may work
directly, or call `Workflow` with a task-specific JavaScript program when delegation or a richer
execution topology is useful. There is no mandatory stage sequence and no keyword router that
turns an under-specified task into fan-out.

Scripts may compose `agent()`, `parallel()`, `pipeline()`, `phase()`, and `log()` in whatever
bounded graph the task needs. They must handle failed agents, represented as `null`, explicitly.
Omitting `background`, or setting it to `false`, keeps prerequisite results in the current turn;
`background: true` is for independent work and returns a task receipt immediately.

The same engine runs standalone workflow scripts from the CLI. See
`iteron workflow` in the [CLI reference](../reference/cli.md) and the example
script at `crates/workflow/examples/repo-audit.js`.

## Authority remains fixed

The host, not the script, grants agent definitions and tools. Workflow calls remain bounded by the
same concurrency, call, turn, token, wall-time, recursion, durable-record, and cancellation
controls. Write-capable agents use host-owned worktrees; the host verifies and serially merges
their patches, rejecting conflicts. A model-authored workflow cannot grant capabilities, relax a
ceiling, merge its own patch, rewrite evidence, or promote a learned strategy.

Ultracode is an experimental harness policy, not an autonomous software team and
not a claim of parity with another coding agent.
