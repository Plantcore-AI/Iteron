# ADR-0001: One workflow renderer

- Status: accepted
- Date: 2026-08-03
- Implementation: migration steps 1–2 complete; native-card retirement and the compatibility
  cleanup in steps 3–4 remain.
- Supersedes: nothing
- Applies to: `crates/cli/src/block.rs`, `crates/cli/src/runtime.rs`,
  `crates/cli/src/workflow.rs`, `crates/workflow`

## Context

Iteron ships two subsystems that share the word *workflow* and nothing else.

**Native ultracode orchestration.** The kernel decomposes a task, fans out
read-only investigators, reduces their evidence, and hands one writer the
result. It emits `WorkflowUiEvent` — a fixed, id-correlated vocabulary
(`RunStarted`, `PlanReady`, `PhaseChanged`, `AgentStarted`, `AgentActivity`,
`AgentFinished`, `RunFinished`) — and the TUI projects those into a
`WorkflowCard`: a flat connector tree with a `done/total` header. That
vocabulary is also a **published machine-stream contract**: every variant is a
`cli.machine-stream.workflow-*` surface in
`governance/schema-compatibility.json`, frozen at `schema_version` 5 with
golden fixtures under `crates/cli/tests/golden/`.

**The script engine.** `crates/workflow` embeds QuickJS and runs `.js` workflow
scripts with `agent()` / `parallel()` / `pipeline()` / `phase()` / `log()`. It
emits `iteron_workflow::events::ProgressEvent` — an unfrozen, in-process
vocabulary carrying free-form phase titles, narrator log lines, and per-agent
metrics — and the TUI projects those into a `WorkflowRunCard`: bordered phase
boxes, branch rows, collapsed finished agents.

The two renderers do not share a row, a glyph, a header, or a state model. The
code says so out loud:

- `block.rs` labels the phase-box tree "a SEPARATE projection from the
  native-ultracode `WorkflowCard` above".
- `BlockKind::WorkflowRun`, `App::workflow_run_event`, and
  `App::workflow_run_finished` all carry `#[allow(dead_code)]` with the note
  "live at M9" — the phase-tree renderer has **no non-test caller** from the
  interactive TUI. It is reachable only from the one-shot `iteron workflow run`
  live loop.
- `runtime.rs::launch_workflow` — the in-turn `Workflow` tool — passes
  `iteron_workflow::NullSink` and then blocks on `join`. Every phase, log, and
  agent event of an in-turn run is discarded.

The result is one product with two half-built progress surfaces, and no
principled answer to "which one gets the next fix". This ADR gives that answer
so no further feature work lands in either renderer blind.

## Decision

**The phase-tree renderer survives. The native ultracode card is retired.**

Concretely:

1. `WorkflowRunCard` / `render_workflow_run` (`block.rs`) is the one workflow
   renderer. New progress affordances — headers, run totals, per-row clocks,
   queued rows, phase layout — land there and only there.
2. Ultracode's Fan → Reduce is migrated onto the script engine as a **built-in
   decomposition script**, rather than the reverse. The engine already owns the
   parts that would otherwise have to be rebuilt inside the native path: a
   permit-bounded fan, a content-addressed resume journal, schema-forced
   structured output, background launch with cancellation, and a declarative
   phase header.
3. `WorkflowCard` / `render_workflow` retires **when, and only when,** ultracode
   runs as a script. Until then it stays live and correct — it is the only thing
   rendering ultracode today.
4. `WorkflowUiEvent` is **not** deleted. It is a published compatibility
   surface: `iteron --output-format stream-json` consumers read
   `workflow_start` / `workflow_plan` / `workflow_phase` /
   `workflow_agent_*` / `workflow_end`. It keeps being emitted for as long as
   the deprecation runway in `governance/schema-compatibility.json` requires,
   independently of which renderer draws the TTY.

### Why this direction and not the other

Routing the script engine's `ProgressEvent`s into `WorkflowUiEvent` was the
cheaper-looking option, and it is not viable:

- `WorkflowUiEvent::PhaseChanged` carries `WorkflowPhaseUi`, a closed enum
  (`Planning`/`Exploring`/`Synthesizing`/`Writing`/`Direct`). A script's
  `phase('build the index')` has nowhere to go.
- There is no `Log` variant, so the narrator line is unrepresentable.
- The native card matches agents against a `PlanReady` task list known up front.
  A script's agent set is discovered as the script runs.

Widening `WorkflowUiEvent` to fit is not a refactor: each variant is a frozen
governed surface, so it costs a shared CLI stream schema-version bump. Paying
that to make the *retiring* renderer more expressive is the wrong direction.

## Migration path for the retiring renderer

Ordered, each step independently shippable:

1. **Carry script progress to the interactive TUI.** `launch_workflow` must
   forward its `ProgressSink` to the UI channel the way the investigator child
   forwarder already does, behind one new UI event that reaches
   `App::workflow_run_event` / `App::workflow_run_finished`, and their
   `#[allow(dead_code)]` attributes must go so the compiler holds the seam.
   **This step requires a CLI stream schema-version bump** (5 → 6): a new
   `UiEvent` variant becomes a new `cli.machine-stream.*` record type, and
   `xtask` refuses a new stream surface at the current version
   (`new CLI stream surface ... requires a shared CLI schema version bump`).
   It therefore cannot ride along with a renderer change; it is its own
   release-contract PR.
2. **Move ultracode's decomposition into a built-in script** driven by
   `KernelSpawner`, keeping the existing authority, budget, and read-only
   investigator guarantees exactly as they are. Investigators become
   `agent()` calls inside a `phase()`; the writer stays on the kernel path.
3. **Delete `WorkflowCard`, `render_workflow`, `App::workflow_event`, and
   `workflow_index`** once nothing constructs them, keeping `WorkflowUiEvent`
   and its `stream_event` producer for the machine surface.
4. **Retire `WorkflowExecutionModeUi::Sequential`** on the same schema-version
   bump that step 1 pays for. It is never emitted by the kernel, but it is
   serialized as `"execution_mode":"sequential"` inside the frozen
   `machine_stream_all_v4`/`v5` goldens and mirrors
   `iteron_protocol::WorkflowExecutionMode::SequentialFan` in the frozen ABI, so
   removing it is a contract change, not a cleanup.

## Consequences

- Every downstream workflow issue references this ADR. Work on
  `render_workflow` is limited to correctness of what is already there
  (for example: rendering one row per concurrent investigator); new capability
  goes to `render_workflow_run`.
- Until step 1 lands, an in-turn `Workflow` tool call renders no live progress.
  That is a known, named gap with a named cost, not an oversight.
- The `stream-json` contract is unaffected by steps 2 and 3.
