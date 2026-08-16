# UI activity and performance contract

This contract defines when Iteron may present a run as responsive, complete, or
cancelled. It applies to the interactive TUI, one-shot clients, workflow cards,
tool cards, evaluation commands, and evolution commands. The machine-readable
limits are in `governance/uiux-slo.json` and are checked by:

```bash
cargo run --locked -p iteron-xtask -- conformance uiux
```

The command checks the contract shape and fixed release thresholds. Release
qualification must additionally measure the workloads below; a valid JSON file
is not performance evidence.

## Completion authority

No tool call is not a completion condition. A provider `EndTurn` completes only
one model step. The runtime still resolves pending steering, cancellation,
verification, checkpoints, records, required hooks, and unknown external effects.
Only the authoritative `RunEnded` event ends the client run state.

The user-visible sequence is:

```text
model
  -> [tool proposed -> hook/approval -> queued -> running -> settled -> model]*
  -> provider EndTurn
  -> steering/control
  -> optional verification
  -> answer complete
  -> finalizing(checkpoint/record/hooks/compaction/cleanup)
  -> RunEnded
```

Clients never infer completion from a quiet stream or the absence of a tool call.
The terminal event reconciles streamed assistant text against the authoritative
complete message so a saturated presentation queue cannot permanently omit or
duplicate text.

## Activity projection

Activity is additive, content-free presentation state. Durable `Phase`, policy,
effect-ledger, and terminal events remain authoritative. Activity records carry
run and activity identities, parent identity, a closed kind and state, owner,
timestamps, optional attempt/deadline, cancellation authority, a bounded detail
code, and bounded numeric progress.

- Local preparation is never labelled `thinking`.
- Time-to-first-token starts at the recorded transport `request_sent`, not at
  context assembly or route admission.
- Work exceeding 250 ms has a name; after one second it shows elapsed time; after
  two seconds it exposes cancellation or a concrete remedy when permitted.
- Retry shows attempt, limit, reason code, absolute next time, and countdown.
- `answer complete` and `finalizing` are distinct states.
- A force-cancel label is legal only after stronger runtime authority is accepted;
  unresolved effecting calls remain `Unknown` until reconciled.

## Provider waiting contract

Successful response headers produce an `accepted` activity before any model token. The UI then
distinguishes connection setup, accepted/provider generation, first byte, first token, reasoning,
and response streaming. Retry and route failover always expose their attempt, bounded wait, and
selected route; a quiet stream is never presented as an unexplained hang.

The shipped interactive defaults are a 10 second connect deadline, a 60 second response-header
deadline, and a 120 second stream-idle deadline. Slow-first-token guidance appears after three
seconds and stall guidance after twelve seconds. A server retry delay is a lower bound, but an
interactive wait above 60 seconds terminates with a typed remedy instead of silently sleeping.
The default route concurrency is four, is independently tunable from workflow fan concurrency, and
remains narrowed by provider quotas, cost authority, session budgets, and an installed host ceiling.
Interactive deferred discovery starts only after the first frame; a selected uncached route may use
the bounded first-use admission wait, but discovery construction itself performs no network I/O.
Observed non-HTTP/2 responses produce fixed compatibility evidence rather than silently changing
the run's claims.

OpenAI-compatible streams treat complete tool calls as stronger execution evidence than a
misreported `finish_reason: stop`; this exact compatibility case continues as tool use and emits a
fixed notice. Incomplete calls and refusal, stop-sequence, or unknown terminals still fail closed.

## Context and cache visibility

Core file tools are present on the first model request. Deferred tool exposure is monotonic within
a run so a follow-up cannot reorder and invalidate the stable provider prefix. Skills are selected
by task/path relevance before deterministic fallback order. Live token counts are explicitly
approximate until provider usage arrives; cache read/write counts are shown only from measured
provider usage and unknown values never render as zero.

Adaptive compaction derives usable input from the selected model context window minus its output
reservation. Its default recent-tail budget is 25 percent of that usable input, clamped by the host
to 2,000--15,000 tokens. Process and shell tools expose 30,000 bytes to the model by default; a
profile may widen that view only up to 150,000 bytes, while the independent 256 KiB evidence ring
and its resume cursor remain authoritative.

The renderer coalesces adjacent updates for 16 ms and never exceeds 63 frames per second. This
keeps token streaming visually continuous without turning a nominal 16 ms timer into an accidental
60-fps/16.67-ms mismatch or repainting once per provider delta.

## Main-thread boundary

The TUI event loop projects state and renders. Filesystem access, session/history
hydration, provider discovery, attachments, completion scans, protocol requests,
record maintenance, hooks, and workflow persistence run in bounded actors. The
first frame does not perform work proportional to total sessions, content objects,
history entries, or workflows.

Session selection paints a shell first, then loads 25 rows per page and prefetches
five rows before the boundary. Attachments expose queued, reading, decoding,
ready, failed, and cancelled states. Long shell commands yield a session and
partial output after ten seconds instead of withholding all output until exit.

Session metadata and content references are rebuildable projections with incremental direct
indexes. A normal turn, first frame, title lookup, or picker page must not scan or rewrite all
sessions. Cross-process recovery still verifies the authoritative rollout and effect journal;
normal in-process follow-ups use the already-admitted working set rather than replaying the entire
run on every message.

## Measurement matrix

Release qualification covers at least:

- warm startup and cold startup with 10,000 sessions;
- 1 MiB unfinished Markdown paragraphs and fences;
- saturated and slow presentation consumers with interleaved text/reasoning;
- slow disk, lock contention, cache misses, and index rebuilds;
- slow and concurrent shell, MCP, LSP, hook, verifier, and workflow operations;
- retry, failover, provider terminal, cooperative cancel, and force cancel;
- Unicode grapheme, CJK, emoji, tmux, and narrow-terminal rendering;
- deterministic final-text equality and bounded RSS under queue pressure.

Security, permission, budget, durability, replay, and effect-ledger guarantees are
never weakened to meet a latency target.
