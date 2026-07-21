# Runtime lifecycle

Core Code currently runs as one CLI process that composes the frontend and runtime
dependencies. The intended App Server boundary does not exist yet.

## Current startup path

At a high level, the executable:

1. validates local CLI values before opening a run record;
2. loads repository and trusted user configuration under different authority
   rules;
3. registers built-in workspace, edit, shell, Git, memory, skill, and web-related
   tools;
4. starts operator-configured MCP stdio servers and registers their discovered
   tools;
5. resolves provider, model, effort, budgets, permission mode, and continuation;
6. on a fresh run, captures bounded workspace environment facts;
7. opens or reconstructs the hash-chained rollout;
8. discovers bounded repository instructions, memory, skills, hooks, and agent
   definitions with their source trust;
9. starts the interactive TUI or one-shot event emitter;
10. runs bounded model/tool/verification turns until a terminal outcome.

The order matters. Routing-sensitive values never come from a cloned repository,
and invalid one-shot arguments are rejected before they can create an orphan run.

The fresh-run system prefix contains a 4 KiB-max environment snapshot: canonical
workspace cwd, one UTC timestamp shared with `RunStart`, compile-target OS/arch,
and a Git branch plus clean/dirty counts. Git status filenames are never included.
The CLI obtains Git facts through the same confined, hook/filter/config-neutralized
and output-bounded Git harness used by read-only tools; any non-repository, timeout,
malformed output, or unavailable Git result becomes only `git: unavailable`.
The three-second startup collector currently runs only where Unix process-group
teardown is available; other targets fail closed to that same unavailable value.

These values are Workspace-trusted data, not instructions. The kernel does not
read the clock or spawn Git. It bounds and redacts the proposed snapshot, commits
one crash-safe copy in `RunStart`, commits the authoritative copy inside
`ContextInjection` before provider admission, and materializes context in
environment → instructions → memory/skills order using the lowest governing trust.
Resume and fork do not run the environment collector or sample its clock: they
reuse the exact durable snapshot bytes, falling back to the genesis copy only
until the first injection commits. The same bound is revalidated on append, replay,
open, and fork; an independently hash-valid oversized field fails closed instead of
falling back to live state. Older records without this additive field remain valid
and resume without inventing historical environment facts.

## Submissions and events

The protocol crate defines one id-correlated submission/event vocabulary. User
input, approval responses, steering, interrupt, and drain operations are explicit
submissions. Phases and tool or workflow activity are emitted as events for the
frontend and record path.

The current in-process use of that vocabulary is a useful extraction seam, not a
stable network or App Server API.

`Interrupt` and `Drain` have deliberately different terminal semantics. Interrupt
stops at the next turn-safe point and records `Interrupted`. Drain stops admitting
new turns, lets already admitted work quiesce, writes a synchronous Git-backed
workspace `Checkpoint` into the rollout, and records `Drained`. A drained rollout
can be resumed normally; Core never treats the checkpoint as reconciliation proof
for an unresolved external effect. The checkpoint contract requires a Git
worktree; the TUI probes that capability before entering raw mode and refuses
Ctrl-D drain explicitly in a non-Git directory. No new Stop hook is admitted after
`Drained`, so an arbitrary lifecycle hook cannot mutate the workspace past the
final checkpoint.

Checkpoint trees unconditionally exclude the active rollout/session-state root,
including descendant-agent journals and rebuildable indexes, even when the
repository does not ignore `.core/runs`. Rewind therefore cannot replace the
append-only record that authorizes it. The distinct drained workflow and direct
child terminals use new top-level V2 event tags; a V1 reader skips those tags via
its unknown-event fallback instead of failing on a new nested enum value. The
record append boundary rejects mismatched tag/version combinations.

## Target extraction

The planned runtime boundary is:

1. versioned canonical command and event envelopes;
2. a pure reducer that requests actions rather than performing them;
3. one capability and effect broker;
4. injected provider, world, context, verification, and scheduler ports;
5. a long-lived session runtime with bounded queues and reconnect semantics;
6. a versioned App Server used by the TUI, CLI, and future clients.

Until those gates land, describe Core Code as a modular monolith rather than a
completed microkernel.
