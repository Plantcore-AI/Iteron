# Runtime lifecycle

Iteron runs one resident App Server task per session. The TUI, one-shot
emitter, and headless transport are clients of its bounded SQ/EQ queues; none
reclaims or directly runs the kernel `Agent`.

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
9. moves the runtime into the resident App Server and attaches the interactive
   TUI, one-shot emitter, or headless transport as a versioned client;
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

The TUI and one-shot client use the in-process versioned wire. `iteron serve`
projects the same events onto an authenticated, bounded loopback JSONL
transport. A managing parent supplies a fresh bearer capability through stdin
before bind; each client's first `hello` proves that capability before any
version or event behavior is exposed. Every live event has a checked monotonic
cursor. The transport retains a serialized-byte- and item-bounded replay ring;
when a requested cursor predates that ring it sends hash-verified Rollout events
on a separate `rollout_seq` field before resuming live delivery. Logical frames
larger than the 1 MiB physical ceiling are streamed as ordered, independently
bounded `frame_chunk` frames and occupy one atomic ring entry. A slow or idle
external client is disconnected instead of blocking the runtime and can
reconnect from its last fully assembled cursor. If an exact terminal result has
already left the ring, reconnect fails explicitly with `cursor_expired`;
Rollout replay is never mislabeled as a reconstruction of result-v5.

Live reattach and session resume are deliberately different operations:

- `resume_from` is a presentation-stream cursor within one still-running App
  Server. It never selects or opens a run record.
- `--resume RUN_ID` reconstructs a session from the hash-chained Rollout before
  the App Server starts. It never accepts an EQ cursor.

Keeping the identifiers and frame variants separate prevents a live reconnect
from creating a second Rollout writer or a session resume from pretending that
durable record sequence numbers are presentation events.

`Interrupt` and `Drain` have deliberately different terminal semantics. Interrupt
stops at the next turn-safe point and records `Interrupted`. Drain stops admitting
new turns, lets already admitted work quiesce, writes a synchronous Git-backed
workspace `Checkpoint` into the rollout, and records `Drained`. A drained rollout
can be resumed normally; Iteron never treats the checkpoint as reconciliation proof
for an unresolved external effect. The checkpoint contract requires a Git
worktree; the TUI probes that capability before entering raw mode and refuses
Ctrl-D drain explicitly in a non-Git directory. No new Stop hook is admitted after
`Drained`, so an arbitrary lifecycle hook cannot mutate the workspace past the
final checkpoint.

Checkpoint trees unconditionally exclude the active rollout/session-state root,
including descendant-agent journals and rebuildable indexes, even when the
repository does not ignore `.iteron/runs`. Rewind therefore cannot replace the
append-only record that authorizes it. The distinct drained workflow and direct
child terminals use new top-level V2 event tags; a V1 reader skips those tags via
its unknown-event fallback instead of failing on a new nested enum value. The
record append boundary rejects mismatched tag/version combinations.

## Runtime boundary

The runtime boundary is:

1. versioned canonical command and event envelopes;
2. a pure reducer that requests actions rather than performing them;
3. one capability and effect broker;
4. injected provider, world, context, verification, and scheduler ports;
5. a long-lived session runtime with bounded queues and reconnect semantics;
6. a versioned App Server used by the TUI, one-shot CLI, and headless clients.

The process remains a modular monolith: the boundary isolates ownership and
client contracts, but it does not claim that every component is a separately
deployed service.
