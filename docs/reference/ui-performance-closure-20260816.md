# UI/UX performance engineering closure (2026-08-16)

This page records the engineering closure of the Iteron UI/UX and performance
audit. It covers findings F-001 through F-046 and D1 through D49 from the two
2026-08-15 audit reports. The normative contract remains
[UI activity and performance](ui-performance-contract.md); machine-readable
thresholds remain in `governance/uiux-slo.json`.

This is an implementation and conformance record, not a measured performance
claim. Release qualification must still execute the contract's workload matrix
on the supported machines and publish the resulting evidence.

## Closure outcome

All valid engineering findings are implemented or resolved by preserving a
stronger existing invariant. The completed work falls into these groups:

| Area | Engineering result |
| --- | --- |
| Streaming | Presentation deltas are bounded and coalesced; the terminal summary reconciles the visible answer byte-for-byte. Sensitive-pattern scrubbing retains only a bounded possible suffix, so ordinary trailing tokens are not withheld until unrelated finalization finishes. |
| Activity and completion | A closed, content-free activity protocol distinguishes preparation, provider wait, reasoning, response, tools, retry, failover, verification, checkpointing, hooks, workflow persistence, finalization, and input-ready. Only authoritative `RunEnded` clears the run. |
| First frame and sessions | First paint no longer hydrates all history or scans every run. Prompt history is asynchronous and incremental. Session selection uses a seekable, generation-bound index with 25-row pages and cancellable preview hydration. |
| Input and rendering | Attachment reads, decoding, conversion, and encoding run outside the TUI loop. Markdown settlement is incremental, transcript layout uses a retained height index, and editing/rendering operate on Unicode grapheme clusters. |
| Cancellation | Escape and Ctrl-C share an explicit cancellation state machine. Cooperative cancellation is acknowledged first; stronger cancellation kills the process group and waits for bounded reap evidence. Cancelling cleanup remains visible and is never presented as idle. |
| Provider path | Connection, acceptance, first byte, first token, retry, and failover are separate activities. Provider discovery is deferred past first paint when a validated snapshot exists. Retry and idle waits are bounded and visible. |
| Tools and hooks | Shell output is projected through a bounded real-time channel while the terminal tool result remains authoritative. Hook execution is bounded, non-conflicting hooks may run concurrently, and stop hooks cannot silently hold `RunEnded` or input-ready. |
| Context | Tool schemas are prepared once and reused by providers and token estimation. Route-scoped token calibration consumes measured provider usage. Skills and memory shortlist metadata are indexed before bounded body reads. |
| Records and telemetry | Record writes have a single append authority, bounded deltas, crash-detectable indexes, and true terminal semantic batching. Rebuildable indexes never block input-ready. Telemetry drains at most once instead of replaying the full run. |
| Workflow and protocols | Workflow submissions, progress, logs, MCP, LSP, marketplace runtime messages, and process output have item, byte, time, and concurrency bounds. Cancellation and terminal state use typed, independently deliverable paths. |
| Governance | UI/UX thresholds are source controlled and conformance checked. New operational ceilings are runtime-bound tunables that can only narrow immutable host maxima. Security, permission, durability, replay, budget, and effect-ledger invariants remain non-trainable. |

## Second-round default-policy closure

The independent default-policy audit was resolved against production source, not
by copying comparator constants. Its accepted findings have these exact outcomes:

- deferred provider discovery is dormant until the interactive TUI has painted;
  one-shot and headless callers use a separate bounded first-use settlement path;
- the stream-idle default is 60 seconds, per-route provider concurrency defaults
  to four independently of workflow fan-out, and rendering coalesces at 16 ms with
  a 63-frame-per-second ceiling;
- adaptive compaction derives usable input from the selected model window minus
  the output reserve, triggers at 82 percent, retains 25 percent of that usable window, and applies the
  immutable 2,000--15,000-token host clamp;
- a bare 5xx may select a different route only with proven pre-dispatch or terminal
  evidence; it is never retried on the same route, preserving at-most-once effects;
- process and shell results expose 30,000 model-visible bytes by default, may be
  widened by profile only up to 150,000 bytes, and keep the independent 256 KiB
  evidence ring unchanged;
- lifecycle event lookup is constant-time and saturated observers evict low-value
  records before high-value terminal records without scanning the queue;
- provider response-version downgrade is emitted as fixed compatibility evidence,
  and web search clients refuse redirects so credentials cannot cross origins.

The UI/UX conformance command contains 16 source bindings from contract values to
their production owners. It therefore fails when source and governance drift; it
does not merely validate `governance/uiux-slo.json` against duplicated literals.

## Authoritative end-turn semantics

The absence of a tool call does not end an Iteron run. It can end one provider
step only. The public state machine is:

```text
model
  -> [tool -> model]*
  -> provider EndTurn
  -> pending steering/control
  -> optional verification
  -> answer complete
  -> finalizing(checkpoint/record/hooks/compaction/cleanup)
  -> RunEnded
  -> input ready
```

Clients must not infer completion from a quiet stream, a provider connection
closing, or a model response containing no tool call. The TUI reconciles the
authoritative completed answer before it presents the run as ended.

## Boundedness and durability decision

Every production queue that may carry variable-size data has both an item bound
and an aggregate-byte or per-message envelope. Terminal state uses an
independent authoritative path where a lossy cosmetic path would be unsafe.

Ordinary record appends intentionally retain synchronous write-ahead durability.
The append actor can coalesce already adjacent tickets, and the terminal boundary
is a real multi-event batch. The ordinary synchronous facade does not delay one
completed durable append merely to manufacture a larger batch. Weakening that
contract for a small storage-latency optimization would violate the audit's
durability constraint.

## Optimization surface after closure

The generated source census reports:

- 2,875 candidate rows in total;
- 2,009 runtime-settable, advertised, applied, and externally addressed rows;
- 1,380 unified-profile rows, 303 direct-configuration rows, and 326
  caller-input rows;
- zero runtime-settable rows without an external address and zero rows requiring
  a new binding;
- 866 read-only invariants that deliberately require human-owner review and are
  not trainable values;
- 28 module identities and 160 tunable families, of which 119 are directly
  profile-addressable.

These figures are generated evidence for the source revision, not a claim that
every conceivable future source form or external research adapter already
exists.

## Verification boundary

The merge gate for this closure is:

```bash
cargo fmt --all
git diff --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo run --locked -p iteron-xtask -- tunables check
cargo run --locked -p iteron-xtask -- boundaries check
cargo run --locked -p iteron-xtask -- conformance check
cargo run --locked -p iteron-xtask -- docs check
cargo run --locked -p iteron-xtask -- lifecycle check
```

Targeted terminal evidence additionally covers Kitty keyboard negotiation,
Shift+Enter, SIGTERM/SIGHUP while a picker is open, process-group cancellation,
final-answer reconciliation, saturated queues, session paging, and Unicode
rendering.

## Explicit non-claims and remaining external evidence

- The thresholds in `governance/uiux-slo.json` are release requirements. This
  change does not by itself prove their distribution on every machine, terminal,
  filesystem, network, or provider.
- No external provider benchmark, Harbor/Terminal-Bench campaign, or model-quality
  comparison is claimed here. Hermetic and synthetic evidence validates the
  engineering contracts only.
- A deterministic two-turn provider fixture proves that cache creation and cache
  read usage reach the context ledger without being collapsed to zero. It does not
  prove a nonzero cache-hit rate for any external provider or workload.
- HTTP/2 enablement and observed response-version compatibility are checked; this
  is not a claim that raw TLS ALPN was captured for every provider route.
- The 866 invariant rows still require their accountable human owners' review.
  An agent cannot replace that approval.
- Harness optimization does not train model weights. The implementation supports
  harness-only candidate search while preserving host invariants.
- Several legacy production modules remain larger than the preferred 1,200-line
  maintenance target. Their behavior is covered by the gates above; further
  decomposition is maintainability work, not an unresolved UI correctness claim.
