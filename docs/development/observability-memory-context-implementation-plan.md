# Hooks, OpenTelemetry, memory, and context observability implementation plan

Status: proposed implementation plan
Execution order: plan 2 of 2
Depends on: [Control, benchmark, tunables, and trainable-harness implementation plan](control-benchmark-harness-implementation-plan.md)

## 1. Outcome and literal scale requirement

Build a versioned lifecycle and observability plane that is literally 5-10x larger than the
strongest publicly verifiable comparator in each signal class, while making memory and context
window decisions the most deeply observable parts of Core.

The hard catalog targets are:

| Signal | Comparator baseline | Required 5-10x range | Core target |
| --- | ---: | ---: | ---: |
| Hook event types | Claude Code public lifecycle: 31 | 155-310 | **192** |
| OTel metric instruments | Codex 0.146.1: 51 | 255-510 | **320** |
| OTel log event schemas | Claude Code public monitoring: 24 | 120-240 | **192** |
| OTel span templates | Claude Code public tracing: 6 | 30-60 | **48** |

The comparison is contract count, not repository line count. Raw macro/call-site counts are tracked
as implementation coverage, but the product acceptance target is the stable typed surface above.

Memory and context requirements:

- 80 of 192 Hook events (41.7%);
- 96 of 192 OTel log schemas (50%);
- 192 of 320 metrics (60%);
- 24 of 48 span templates (50%).

No later feature may reduce those shares without a versioned catalog change and explicit product
decision.

## 2. Non-negotiable architecture rules

1. Durable record is the causal truth. OTel and hooks are projections/interventions, not a second
   authority.
2. Cancellation, force-cancel, process reap and queue control never wait for hooks or exporters.
3. Metric attributes are bounded; run/session/turn/submission/fact IDs never become metric labels.
4. Prompt, memory, file and tool content are disabled by default.
5. Local full-fidelity metadata and remote exported telemetry are separate retention/sampling
   policies.
6. All loops, channels, output, hook execution, batches, cardinality and retention are bounded.
7. All 192 Hook events are subscribable, but only a small declared subset may block or mutate.
8. Hook and OTel catalogs are generated or exhaustively checked from one lifecycle registry.
9. Security, permission, durability, effect, record and evaluator decisions cannot be rewritten by
   observability hooks.
10. Every benchmark trace records the exact observability catalog version and dropped-event count.

## 3. Scope and boundary declaration

Affected boundaries:

| Boundary | Risk | Change |
| --- | --- | --- |
| `protocol-compat` | critical | lifecycle IDs, payload envelopes and versioning |
| `record-core` | critical | durable causal summaries and artifact references |
| `observability` | elevated | OTel metrics/logs/traces, projections, local recorder |
| `telemetry-export` | critical | authorised bounded OTLP egress |
| `kernel-hooks` | critical | 192-event Hook registry and execution runtime |
| `context-core` | elevated | `ContextLedger`, tokenizer/cache/compaction evidence |
| `context-knowledge` | elevated | `MemoryDecisionTrace`, visibility and contamination evidence |
| `cli-host` | critical | trusted config, exporter composition, runtime event bus |
| `cli-tui` | elevated | status/inspect surfaces without control-path coupling |
| `kernel-runtime` / `kernel-effects` | critical | causal event production at state/effect boundaries |
| `provider-core` / `provider-adapters` | elevated | trace propagation, actual usage/cache/token evidence |
| `tools-execution` | critical | process/tool lifecycle evidence |
| `workflow-engine` / `agent-orchestration` | elevated | planning/child/reduction traces |
| `evaluation` | elevated | completeness, overhead and benchmark telemetry evidence |
| `tunability-registry` | elevated | observability controls and trainable decision features |
| `documentation-site` | elevated | generated public reference and operator guide |

Invariant overlays:

- `append-only-record`
- `secret-redaction`
- `runtime-protocol`
- `durable-event-schema`
- `trusted-hook-origin`
- `bounded-hook-process`
- `usage-ledger`
- `cost-state`
- `no-invented-price`
- `memory-provenance`
- `bounded-context`
- `bounded-recall`
- `intent-execute-terminal`
- `unknown-effect-block`
- `fixed-invariant-nontrainability`

## 4. Current gap

Core currently has:

- 5 declared Hook names: `PreToolUse`, `PostToolUse`, `Stop`, `UserPromptSubmit`,
  `SessionStart`;
- only 3 production call paths: pre-tool, post-tool and stop;
- 34 top-level durable `EventKind` variants plus 7 workflow variants;
- 2 emitted OTel metric names;
- 4 span projection shapes;
- an end-of-run flat JSON projection rather than a complete OTLP metrics/logs/traces pipeline;
- documentation that mentions token-usage export although the projection does not emit it.

This implementation replaces the small hand-maintained Hook enum and OTel projection with a
catalogued lifecycle system. It must preserve compatibility with historical durable events.

## 5. Three-tier evidence model

```text
Tier 0: durable causal record
  decisions, admissions, mutations, terminals, catalog/profile digests
  hash-chained, replayable, never sampled

Tier 1: local flight recorder
  full metadata granularity, bounded ring/segmented files, content off by default
  no network, 100% lifecycle coverage, explicit dropped counters

Tier 2: OpenTelemetry export
  metrics 100%, logs/traces policy-controlled, batched and bounded
  user-configured endpoint only, content gated, backpressure never reaches runtime
```

Hooks subscribe to the lifecycle bus. A hook result that is allowed to alter execution becomes a
new Tier-0 decision event before it takes effect.

## 6. Canonical lifecycle registry

### 6.1 Location and module layout

Create a lifecycle catalog under the protocol crate so every frontend/runtime/exporter shares the
same stable IDs:

```text
crates/protocol/src/lifecycle.rs
crates/protocol/src/lifecycle/
  envelope.rs
  registry.rs
  capability.rs
  privacy.rs
  context.rs
  memory.rs
  control.rs
  tool.rs
  model.rs
  workflow.rs
  session.rs
  verification.rs
  runtime.rs
```

Keep each production module below 500 lines. Split payload structs from registry rows when needed.

### 6.2 Registry row

```rust
struct LifecycleEventSpec {
    id: LifecycleEventId,
    schema_version: u16,
    domain: LifecycleDomain,
    phase: LifecyclePhase,
    durability: DurabilityClass,
    hook_capability: HookCapability,
    privacy: PrivacyClass,
    cardinality: CardinalityClass,
    payload_schema: PayloadSchemaId,
    metric_family: Option<MetricFamilyId>,
    span_template: Option<SpanTemplateId>,
    default_export: ExportPolicy,
}
```

Required enums:

- `DurabilityClass::{Required, Summary, FlightRecorderOnly}`
- `HookCapability::{Observe, Augment, Gate}`
- `PrivacyClass::{ContentFree, SensitiveMetadata, Content}`
- `CardinalityClass::{MetricSafe, TraceOnly, LocalOnly}`
- `ExportPolicy::{Always, ErrorsAndBenchmarks, Sampled, LocalOnly}`

### 6.3 Lifecycle envelope

```rust
struct LifecycleEventEnvelope {
    catalog_version: LifecycleCatalogVersion,
    event_id: LifecycleEventId,
    event_version: u16,
    occurred_at_mono_ns: u64,
    run_id: Option<RunId>,
    turn_id: Option<TurnId>,
    submission_id: Option<ClientSubmissionId>,
    effect_id: Option<EffectId>,
    workflow_id: Option<String>,
    parent_event: Option<LifecycleEventRef>,
    durable_seq: Option<Seq>,
    payload: LifecyclePayload,
}
```

Wall time enters only at an admitted nondeterminism boundary. Monotonic elapsed time may be used
for live telemetry; durable evidence stores the already measured duration rather than remeasuring
during export.

## 7. Exact 192-event Hook catalog

All IDs below are stable lower-snake/dot names. Renaming requires an alias and catalog-version
migration; removal requires a deprecation cycle.

### 7.1 Context: 40

```text
context.assembly.started
context.source.discovered
context.source.classified
context.source.rejected
context.source.selected
context.source.deduplicated
context.source.truncated
context.source.serialized
context.segment.created
context.segment.updated
context.segment.removed
context.segment.ordered
context.segment.budget_requested
context.segment.budget_granted
context.segment.budget_denied
context.tokenizer.estimate_started
context.tokenizer.estimate_completed
context.tokenizer.actual_observed
context.tokenizer.error_calculated
context.window.capacity_resolved
context.window.output_reserved
context.window.headroom_updated
context.window.high_watermark
context.window.overflow_predicted
context.tool_catalog.discovered
context.tool_catalog.filtered
context.tool_catalog.lazy_route
context.tool_schema.admitted
context.tool_schema.rejected
context.stable_prefix.computed
context.cache_region.classified
context.request.serialized
context.request.submitted
context.request.usage_reconciled
context.compaction.considered
context.compaction.started
context.compaction.completed
context.compaction.failed
context.obligation.preserved
context.obligation.lost
```

### 7.2 Memory: 40

```text
memory.query.created
memory.query.rewritten
memory.scope.resolved
memory.store.opened
memory.store.scanned
memory.store.failed
memory.candidate.discovered
memory.candidate.scored
memory.candidate.ranked
memory.candidate.filtered
memory.candidate.deduplicated
memory.candidate.contradiction
memory.candidate.superseded
memory.candidate.expired
memory.budget.requested
memory.budget.granted
memory.budget.denied
memory.recall.selected
memory.recall.rejected
memory.recall.serialized
memory.recall.injected
memory.recall.used
memory.recall.unused
memory.fact.add_requested
memory.fact.added
memory.fact.add_failed
memory.fact.update_requested
memory.fact.updated
memory.fact.delete_requested
memory.fact.deleted
memory.fact.superseded
memory.visibility.scheduled
memory.visibility.activated
memory.contamination.check_started
memory.contamination.check_passed
memory.contamination.check_failed
memory.benchmark.scope_created
memory.benchmark.scope_destroyed
memory.attribution.recorded
memory.policy.decision
```

### 7.3 Submission, queue and control: 24

```text
submission.created
submission.enqueued
submission.received
submission.admitted
submission.applied
submission.requeued
submission.rejected
submission.deduplicated
submission.expired
queue.capacity_resolved
queue.overflow
queue.depth_changed
steer.requested
steer.admitted
steer.rejected
cancel.requested
cancel.received
cancel.cooperative
cancel.forced
cancel.completed
cancel.failed
drain.requested
drain.settled
control.stale_rejected
```

### 7.4 Tool and process: 20

```text
tool.call_proposed
tool.policy_evaluated
tool.call_admitted
tool.call_started
tool.output_chunk
tool.call_completed
tool.call_failed
tool.call_unknown
tool.call_cancelled
process.spawn_requested
process.spawned
process.term_sent
process.kill_sent
process.reaped
process.reap_failed
background.detached
background.attached
background.input_written
background.stopped
background.orphan_detected
```

### 7.5 Model, provider and transport: 16

```text
model.route_requested
model.route_selected
model.route_rejected
model.request_prepared
model.request_sent
model.first_byte
model.first_token
model.stream_item
model.stream_completed
model.request_failed
model.retry_scheduled
model.retry_cancelled
model.usage_reported
model.usage_reconciled
model.rate_limit_observed
model.quota_updated
```

### 7.6 Workflow and subagent: 16

```text
workflow.planning_started
workflow.planning_delta
workflow.planning_completed
workflow.planning_failed
workflow.run_started
workflow.phase_started
workflow.phase_completed
workflow.child_proposed
workflow.child_started
workflow.child_progress
workflow.child_completed
workflow.child_failed
workflow.reduction_started
workflow.reduction_completed
workflow.run_cancelled
workflow.run_completed
```

### 7.7 Session: 12

```text
session.created
session.title_selected
session.started
session.resumed
session.configured
session.profile_bound
session.record_opened
session.idle
session.stopping
session.stopped
session.failed
session.deleted
```

### 7.8 Verification and checkpoint: 12

```text
verification.planned
verification.check_started
verification.check_completed
verification.check_failed
verification.repair_started
verification.repair_completed
verification.repair_exhausted
checkpoint.requested
checkpoint.created
checkpoint.failed
replay.started
replay.completed
```

### 7.9 Hook and exporter runtime: 12

```text
hook.registered
hook.matched
hook.started
hook.completed
hook.blocked
hook.failed
hook.timed_out
hook.circuit_opened
exporter.started
exporter.batch_flushed
exporter.batch_dropped
exporter.failed
```

Count assertion: `40 + 40 + 24 + 20 + 16 + 16 + 12 + 12 + 12 = 192`.

## 8. Hook capability and runtime design

Capability allocation:

- 160 `Observe`: asynchronous, cannot modify execution;
- 20 `Augment`: may append bounded typed metadata/context;
- 12 `Gate`: may allow, deny, rewrite or defer within an explicit deadline.

Only pre-decision events can be `Gate`. Terminal, cancel, drain, process-reap, record and exporter
events are observe-only.

The 12 `Gate` events are fixed initially to:

```text
submission.created
steer.requested
context.source.discovered
context.segment.budget_requested
context.compaction.considered
memory.query.created
memory.budget.requested
memory.fact.add_requested
memory.fact.update_requested
memory.fact.delete_requested
tool.call_proposed
workflow.child_proposed
```

The 20 `Augment` events are fixed initially to:

```text
context.assembly.started
context.source.classified
context.segment.created
context.tokenizer.estimate_started
context.window.capacity_resolved
context.tool_catalog.discovered
context.stable_prefix.computed
context.compaction.started
memory.scope.resolved
memory.store.opened
memory.candidate.discovered
memory.candidate.scored
memory.recall.serialized
memory.visibility.scheduled
model.route_requested
model.request_prepared
workflow.planning_started
verification.planned
session.created
session.title_selected
```

Every other catalog event is `Observe`. A capability change is a versioned registry change, not a
configuration toggle.

### 8.1 Handler types

Support:

- `command`
- `http`
- `mcp_tool`
- `prompt`
- `agent`

Each handler declares:

- exact event IDs or bounded prefix/glob matcher;
- capability requested;
- timeout class;
- maximum input/output bytes;
- whether execution is synchronous or asynchronous;
- content permissions;
- failure policy;
- source/provenance and immutable config digest.

### 8.2 Runtime layout

Split the current single hook file:

```text
crates/cli/src/runtime/hooks.rs
crates/cli/src/runtime/hooks/
  config.rs
  registry.rs
  matcher.rs
  executor.rs
  command.rs
  http.rs
  mcp.rs
  prompt.rs
  agent.rs
  decision.rs
  redaction.rs
  circuit_breaker.rs
  evidence.rs
  tests.rs
```

Update `governance/boundaries.json` so `kernel-hooks` owns the tree, then regenerate ownership
artifacts rather than editing them manually.

### 8.3 Execution rules

1. Matching hooks run concurrently up to a bounded per-event and global ceiling.
2. Identical handler/config digests are deduplicated.
3. Observer hooks execute off the runtime control path.
4. Augment/gate hooks use a bounded ordered decision reducer.
5. Hook output is capped using the existing head/tail evidence pattern.
6. Timeouts open a circuit after a configured bounded failure count.
7. A gate decision is durably recorded before it changes execution.
8. Hook failure cannot invent an allow decision.
9. `Ctrl-C` cancels pending gate hooks and continues turn cancellation immediately.
10. Environment inheritance excludes credentials and OTel exporter secrets unless explicitly
    allowed by trusted operator configuration.

## 9. Exact 320-metric catalog construction

Use 80 metric families with exactly four instruments per family:

```text
iteron.<domain>.<family>.calls
iteron.<domain>.<family>.failures
iteron.<domain>.<family>.duration_ms
iteron.<domain>.<family>.<magnitude>
```

The magnitude is declared per family: `bytes`, `tokens`, `items`, `depth`, `ratio_ppm`,
`headroom_tokens`, `cost_microusd`, or another bounded unit. It is never an untyped `value`.

### 9.1 Context: 24 families x 4 = 96

```text
assembly
source_discovery
source_selection
source_rejection
deduplication
truncation
segment
budget
token_estimate
tokenizer_error
window_usage
window_headroom
output_reserve
overflow_prediction
stable_prefix
cache_read
cache_write
cache_miss
tool_catalog
tool_schema
request_serialization
compaction
obligation_preservation
attachment
```

### 9.2 Memory: 24 families x 4 = 96

```text
query
query_rewrite
scope
store_scan
store_failure
candidate
scoring
ranking
filtering
deduplication
contradiction
supersession
expiry
budget
recall_selection
recall_injection
recall_use
fact_add
fact_update
fact_delete
visibility
contamination
benchmark_scope
policy
```

### 9.3 Remaining: 32 families x 4 = 128

- control/queue: `submission`, `queue`, `steer`, `cancel`, `drain`, `acknowledgement` = 6
  families / 24 instruments;
- model/provider: `route`, `request`, `stream`, `retry`, `usage`, `quota`, `rate_limit`, `cache` =
  8 families / 32 instruments;
- tool/process: `policy`, `effect`, `tool_call`, `tool_output`, `process_spawn`,
  `process_termination`, `process_reap`, `background_job` = 8 families / 32 instruments;
- workflow/subagent: `planning`, `run`, `phase`, `child`, `reduction`, `cancellation` = 6 families /
  24 instruments;
- verification: `checks`, `checkpoint_replay` = 2 families / 8 instruments;
- hook/exporter: `hooks`, `exporter` = 2 families / 8 instruments.

Total assertion: `(24 + 24 + 6 + 8 + 8 + 6 + 2 + 2) * 4 = 320`.

### 9.4 Metric-label policy

Allowed bounded labels include:

- event outcome/reason enum;
- lifecycle phase enum;
- provider/model catalog slug after bounded catalog admission;
- tool class, not arbitrary tool arguments;
- memory tier/scope/trust class;
- context source class;
- cache class;
- profile/catalog version;
- benchmark ID from a bounded registry.

Forbidden labels include:

- run/session/turn/submission/effect/fact IDs;
- prompt/tool/memory contents;
- raw file paths, commands or URLs;
- arbitrary error strings;
- user/account/email identifiers;
- unbounded plugin/MCP names before normalization.

The catalog checker must calculate worst-case label combinations and reject a metric whose declared
cardinality budget is exceeded.

## 10. Exact 192 log schemas and 48 span templates

OTel log schemas map one-to-one to the 192 lifecycle event IDs. Hook payload and OTel log payload
share the same versioned content-free base schema; capability-specific Hook output is separate.

Span allocation:

| Domain | Templates |
| --- | ---: |
| context | 12 |
| memory | 12 |
| control/queue | 4 |
| model/provider | 6 |
| tool/process | 6 |
| workflow/subagent | 4 |
| verification | 2 |
| hook/exporter | 2 |
| total | **48** |

Template names are fixed initially to:

- context (12): `context.assembly`, `context.source_selection`, `context.budget`,
  `context.tokenization`, `context.window`, `context.tool_catalog`, `context.tool_schema`,
  `context.serialization`, `context.cache`, `context.compaction`, `context.obligation`,
  `context.attachment`;
- memory (12): `memory.query`, `memory.scope`, `memory.store_scan`, `memory.candidate_score`,
  `memory.rank_filter`, `memory.contradiction`, `memory.budget`, `memory.recall`,
  `memory.injection`, `memory.visibility`, `memory.mutation`, `memory.contamination`;
- control/queue (4): `control.submission`, `control.steer`, `control.cancel`, `control.drain`;
- model/provider (6): `model.route`, `model.request`, `model.stream`, `model.retry`, `model.usage`,
  `model.quota`;
- tool/process (6): `tool.policy`, `tool.effect`, `tool.call`, `process.foreground`,
  `process.background`, `process.reap`;
- workflow/subagent (4): `workflow.planning`, `workflow.run`, `workflow.child`,
  `workflow.reduction`;
- verification (2): `verification.run`, `checkpoint.replay`;
- hook/exporter (2): `hook.run`, `exporter.batch`.

Required parentage:

```text
session
  turn
    submission/steer
    context.assembly
      context.source/*
      memory.recall
      context.tool_catalog
      context.compaction
    model.request
    tool.call
      permission/hook wait
      process execution
    workflow.run
      workflow.plan
      workflow.child
      workflow.reduce
    verification
```

W3C `traceparent`/`tracestate` travels through submission envelopes, provider requests where the
provider contract permits it, subprocess environments without exporter credentials, MCP calls and
subagent runs.

## 11. Real OpenTelemetry pipeline

### 11.1 Crate/module layout

Refactor the current flat projector:

```text
crates/obs/src/otel.rs
crates/obs/src/otel/
  catalog.rs
  metrics.rs
  logs.rs
  spans.rs
  attributes.rs
  context.rs
  memory.rs
  projection.rs
  sampling.rs
  cardinality.rs
  redaction.rs
  tests.rs
```

Runtime/exporter composition:

```text
crates/cli/src/runtime/telemetry.rs
crates/cli/src/runtime/telemetry/
  config.rs
  queue.rs
  worker.rs
  otlp_http.rs
  shutdown.rs
  health.rs
  tests.rs
```

Update `telemetry-export` ownership to the tree and regenerate ownership artifacts.

### 11.2 Dependency decision

Before adding Rust OTel dependencies, write a short ADR covering license, MSRV, binary-size and
dependency-tree impact. Preferred first transport:

- OpenTelemetry SDK metrics/logs/traces;
- OTLP HTTP/protobuf using the existing HTTP stack where supported;
- console/local test exporter;
- gRPC only after a measured requirement and dependency audit.

Do not hand-build a partial OTLP implementation that silently diverges from the protocol.

### 11.3 Runtime guarantees

- one bounded telemetry ingress queue;
- authoritative/durable summaries never dropped;
- high-frequency flight-recorder events may be coalesced with explicit drop counts;
- network batches have count, byte, age and retry ceilings;
- exporter retry is independent of provider/tool retry;
- shutdown has a bounded flush and records incomplete export;
- no exporter endpoint or header can come from repository config;
- exporter authentication is never recorded or passed to hooks/tools;
- endpoint failure never fails a turn.

## 12. ContextLedger: per-segment context observability

### 12.1 Data model

Add a content-free `ContextLedger` under `iteron-ctx` with protocol projection types:

```rust
struct ContextLedger {
    turn_id: TurnId,
    model_context_window: Option<u64>,
    usable_window: Option<u64>,
    output_reserved_tokens: u64,
    estimator: TokenizerIdentity,
    segments: Vec<ContextSegmentEvidence>,
    transforms: Vec<ContextTransformEvidence>,
    totals: ContextTotals,
    cache: CacheEvidence,
    compaction: Option<CompactionEvidence>,
    dropped: u32,
}

struct ContextSegmentEvidence {
    segment_id: ContextSegmentId,
    source_class: ContextSourceClass,
    source_digest: Digest,
    trust: TrustClass,
    authority: AuthorityClass,
    ordinal: u32,
    bytes_before: u64,
    bytes_after: u64,
    estimated_tokens: u64,
    actual_tokens: Option<u64>,
    token_range: Option<TokenRange>,
    cache_class: CacheClass,
    decision: ContextDecision,
    reason: ContextDecisionReason,
}
```

### 12.2 Required stages

Every segment passes through observable stages:

```text
discovered -> classified -> selected -> deduplicated -> budgeted
-> serialized -> tokenized -> submitted -> billed -> cached -> compacted
```

For every stage record:

- input/output count, bytes and tokens;
- policy/tunable identity;
- decision and closed reason enum;
- stable-prefix position;
- cache-read/write/miss classification;
- elapsed duration from admitted measurements;
- dropped/truncated amount;
- parent source and resulting segment IDs.

### 12.3 Source classes

At minimum:

- kernel system prompt;
- operator/developer instructions;
- project/directory `AGENTS.md` instructions;
- environment context;
- workspace outline;
- user/workspace/session memory;
- skills and skill references;
- tool schemas;
- transcript user/assistant/tool messages;
- compaction summary;
- images/files/attachments;
- workflow/subagent evidence;
- steering and queued messages.

### 12.4 Window and cache evidence

Each turn must report:

- declared, usable and actually billed context;
- output reserve;
- used/headroom/high-watermark tokens;
- per-source percentage;
- duplicate and reclaimable tokens;
- stable prefix length/digest;
- cache-read/cache-write/uncached tokens by segment;
- heuristic versus provider-tokenizer error;
- predicted turns until compaction under current growth;
- compaction trigger and proactive threshold;
- tool-schema overhead and reachable-tool coverage;
- obligations preserved/lost during compaction.

### 12.5 Instrumentation locations

- `crates/ctx/src/context_assembly.rs`: source/segment transforms;
- `crates/ctx/src/context_strategy.rs`: policy decisions;
- `crates/ctx/src/compact.rs`: thresholds, before/after and obligation retention;
- `crates/cli/src/runtime/context_runtime.rs`: runtime ownership and request boundary;
- provider adapters: actual usage/cache reconciliation;
- tool catalog and image/file submission paths.

Do not add telemetry calls throughout business logic manually. Pass a bounded `ContextObserver`
port into these modules and project typed observations at their existing decision boundaries.

## 13. MemoryDecisionTrace: per-candidate memory observability

### 13.1 Data model

```rust
struct MemoryDecisionTrace {
    query: MemoryQueryEvidence,
    scope: MemoryScopeEvidence,
    stores: Vec<MemoryStoreEvidence>,
    candidates: Vec<MemoryCandidateEvidence>,
    budget: MemoryBudgetEvidence,
    selected: Vec<MemorySelectionEvidence>,
    injection: Option<MemoryInjectionEvidence>,
    visibility: Vec<MemoryVisibilityEvidence>,
    contamination: Option<ContaminationEvidence>,
    attribution: Option<MemoryAttributionEvidence>,
    dropped_candidates: u32,
}
```

Candidate evidence includes:

- fact ID and digest, never content by default;
- store/tier/scope/trust/authority;
- creation/update/version metadata;
- BM25 component scores;
- embedding/semantic score when enabled;
- recency and confidence terms;
- combined score and rank;
- threshold and filter decisions;
- duplicate, contradiction, supersession and expiry relation IDs;
- bytes/tokens requested and granted;
- selected/rejected reason;
- final prompt segment and token range;
- later use/citation attribution when observable.

### 13.2 Required memory stages

```text
query -> scope -> stores -> candidates -> score -> rank -> filter
-> deduplicate/contradict -> budget -> select -> serialize -> inject
-> visible -> used/unused -> attributed -> mutate/supersede/delete
```

### 13.3 Same-session visibility

When memory is added:

1. record add request and durable fact terminal;
2. schedule visibility at an exact turn boundary;
3. emit `memory.visibility.scheduled` with source/destination turn IDs;
4. emit `memory.visibility.activated` before the first request that can use it;
5. prove the injected segment references the same fact digest;
6. never rewrite the stable prefix mid-request.

### 13.4 Benchmark isolation

Every attempt emits:

- `memory.benchmark.scope_created` before task input;
- empty initial store digest;
- rejected access counters for parent/user/workspace stores;
- canary contamination results;
- `memory.benchmark.scope_destroyed` after evidence flush.

The evaluator fails the attempt as harness-invalid if a non-task memory scope was readable.

### 13.5 Instrumentation locations

- `crates/ctx/src/memory.rs`: query, store, candidate, ranking and budgets;
- `crates/ctx/src/context_port.rs`: strategy boundary;
- `crates/tools/src/mem.rs`: mutation requests and terminals;
- `crates/cli/src/runtime/context_runtime.rs`: injection and visibility;
- `crates/eval/src/provisioner.rs` / runner: benchmark isolation;
- `crates/evolve`: attribution/training projection, never runtime authority.

## 14. Other-domain instrumentation

### 14.1 Submission/control

Instrument the command state machine from the companion plan. Every submission gets created,
received, admitted/applied/requeued/rejected evidence. Cancel/drain timing includes keypress receive,
actor receive, token cancel, process signals, task terminal and TUI terminal projection.

### 14.2 Model/provider

Record route selection, request preparation, wire send, first byte/token, stream count, retry,
rate-limit headers, quota snapshot, usage and cache reconciliation. Raw prompts/responses remain off
by default.

### 14.3 Tool/process

Record proposal, policy decision, effect admission, execution, bounded output, terminal/unknown,
TERM/KILL/reap and background ownership. An unknown effect has no invented zero duration.

### 14.4 Workflow/subagent

Planning must stream lifecycle evidence. Record planner start/deltas/result, task validation,
fan-out decisions, per-child budgets, progress, reduction and writer work. Default TUI rendering may
remain folded; observability never hides the planning phase.

### 14.5 Verification/checkpoint

Record selected checks, results, repair loops, checkpoint requests/outcomes and replay. Evaluator
ground truth remains separate and cannot be modified by hooks.

## 15. Operator surfaces

Add read-only commands after the underlying evidence is stable:

- `iteron telemetry status`: exporter, queue, catalog, drops, last flush;
- `iteron telemetry schema [event|metric|span]`: generated catalog inspection;
- `iteron context inspect [turn]`: segment/window/cache ledger without content;
- `iteron context explain <segment-id>`: source, budgets, transforms and decision;
- `iteron memory trace [turn]`: query/store/candidate/selection summary;
- `iteron memory explain <fact-id>`: provenance, scores, visibility and injection ranges;
- `/context`, `/memory`, `/telemetry` TUI panels using the same projections;
- machine JSON output for evaluation and paper tooling.

No inspect command reads credentials or reveals content unless a trusted operator enables a local
content-debug profile with explicit warning and retention path.

## 16. Trainable-harness projection

For every trainable decision, add a content-free `PolicyDecisionEvidence`:

```rust
struct PolicyDecisionEvidence {
    opportunity_id: PolicyOpportunityId,
    policy_digest: Digest,
    eligible_actions: Vec<ActionId>,
    selected_action: ActionId,
    score_or_propensity: Option<f64>,
    feature_schema: FeatureSchemaVersion,
    feature_digest: Digest,
    fixed_invariants_digest: Digest,
}
```

Memory/context features may include counts, budgets, scores, headroom, cache classes and task
classification. They may not include raw prompt, code, path or memory content in the promoted
policy artifact.

The evaluation layer joins decisions to solve/cost/latency outcomes by IDs in logs/evidence, not by
high-cardinality metric labels.

## 17. Sampling, retention and privacy profiles

### 17.1 Default interactive

- metrics: 100%;
- durable summaries: 100%;
- local content-free lifecycle logs: 100% within bounded retention;
- remote normal traces: sampled;
- errors, interrupt/drain, unknown effects, memory contradictions and compaction loss: 100%;
- prompt/tool/memory content: off.

### 17.2 Benchmark

- all content-free lifecycle logs and traces: 100%;
- raw task content governed by benchmark evidence policy, not ordinary OTel;
- catalog/profile/drop counters required;
- exporter network may be disabled while local evidence remains complete.

### 17.3 Local debug

- explicit operator opt-in;
- separate bounded directory and retention;
- redaction before persistence;
- visual TUI warning;
- never enabled by repository config;
- never inherited by benchmark workers automatically.

## 18. Performance and reliability acceptance

Targets:

- OTel disabled: <=2% benchmark wall-time overhead;
- OTel enabled with local exporter: <=5% wall-time overhead;
- lifecycle enqueue p99 <=100 microseconds under normal load;
- cancel/control path waits on zero hook/exporter futures;
- metrics report 100% of admitted measurements;
- every dropped/coalesced log/span increments a stable drop metric and emits bounded health evidence;
- exporter memory and disk usage have configured hard caps;
- shutdown flush is bounded and honest about incomplete export;
- no production module grows beyond repository size guidance.

Load tests:

1. 16-agent workflow at maximum allowed tool concurrency;
2. long provider stream with token/chunk events;
3. 4,096-span projection cap and overflow;
4. exporter endpoint down for the full run;
5. exporter responds slowly or returns retryable/non-retryable errors;
6. 192 Hook events with zero handlers;
7. many matching observer handlers;
8. hanging gate handler followed by `Ctrl-C`;
9. context with thousands of candidate memory facts;
10. repeated compaction and cache reconciliation.

## 19. Executable implementation slices

### B0. Catalog contract and comparator attestation

1. Check in a comparator attestation containing product/version/source URL/counting method.
2. Add catalog count constants and tests for 192/320/192/48.
3. Document what counts as an event, metric instrument and span template.
4. Refuse generated output if counts or memory/context shares drift.

### B1. Lifecycle registry and generators

1. Add protocol lifecycle modules and all 192 stable IDs.
2. Add payload schema/version metadata.
3. Add `xtask lifecycle generate` and `xtask lifecycle check`.
4. Generate Hook names, OTel log names, metric catalog, span catalog, JSON schemas and docs.
5. Add deterministic-generation and stale-output tests.

### B2. Local event bus and flight recorder

1. Add bounded ingress with critical/normal/high-frequency classes.
2. Project required causal events to the durable record.
3. Add bounded local segmented storage/ring with drop counters.
4. Add replay and corruption/torn-tail tests.
5. Ensure event production requires no network/runtime global singleton.

### B3. Hook runtime expansion

1. Split hook runtime modules.
2. Implement matcher, capabilities and five handler types.
3. Implement parallelism, dedup, deadlines, cancellation and circuit breakers.
4. Add durable decision evidence before augment/gate results apply.
5. Migrate existing Pre/PostTool/Stop config compatibly.
6. Wire all 192 event IDs; no handler is required for an event to fire.

### B4. OTel metrics/logs/traces pipeline

1. Complete dependency/ADR audit.
2. Implement generated 320-instrument catalog.
3. Implement 192 log schemas and 48 span templates.
4. Add OTLP HTTP/protobuf and local test exporters.
5. Add W3C propagation, sampling, redaction and cardinality enforcement.
6. Replace the end-of-run JSON-only sink while retaining a compatibility output if needed.

### B5. ContextLedger

1. Add structs and bounded observer port.
2. Instrument all assembly/selection/budget/token/cache stages.
3. Reconcile provider actual usage.
4. Instrument tool-catalog lazy selection and attachment segments.
5. Instrument compaction obligations and loss.
6. Add `/context` and machine output only after correctness tests pass.

### B6. MemoryDecisionTrace

1. Add query/store/candidate/budget/selection/injection evidence.
2. Add contradiction/supersession/expiry events.
3. Add same-session visibility evidence.
4. Add benchmark scope/canary evidence.
5. Add attribution projection for tuner/evaluation.
6. Add `/memory` and machine output only after privacy tests pass.

### B7. Remaining domains

1. Submission/control IDs and cancel timings.
2. Provider/model request/usage/quota evidence.
3. Tool/effect/process lifecycle evidence.
4. Workflow planning/child/reduction evidence.
5. Verification/checkpoint/replay evidence.
6. Session title/profile/record lifecycle evidence.

### B8. Evaluation and paper integration

1. Validate catalog completeness on every benchmark attempt.
2. Join policy decisions to outcomes.
3. Measure observability overhead with OTel off/local/remote.
4. Fail evidence bundles with silent drops or missing required lifecycle events.
5. Produce memory/context ablation and attribution datasets.

### B9. Operator rollout

1. Ship local content-free recorder first.
2. Ship metrics next.
3. Ship traces/log exports behind trusted user config.
4. Ship observe-only Hooks.
5. Ship augment Hooks after replay tests.
6. Ship 12 gate Hooks last, with policy and cancellation audits.
7. Promote schemas to stable only after two compatibility cycles.

## 20. Test matrix

| Area | Required tests |
| --- | --- |
| catalog | exact counts, unique IDs, aliases, versions, deterministic generation |
| Hook | matcher, parallel/dedup, timeout, circuit, cancellation, output bounds, provenance |
| OTel metrics | 320 names, instrument types/units, bounded labels, no ID labels |
| OTel logs | 192 schemas, privacy classes, drop accounting, exporter retry |
| spans | 48 templates, parentage, error status, W3C propagation |
| context | every stage, token ranges, estimator error, cache classes, compaction obligations |
| memory | scores/ranks, budgets, contradictions, visibility, benchmark isolation |
| control | full SQ plus immediate cancel, stale cancel, force-cancel, drain |
| process | TERM/KILL/reap evidence, descendants, background ownership |
| workflow | streamed planning, nested subagent traces, cancel/reduce terminal |
| privacy | content-off snapshots, redaction, config trust, no exporter-secret inheritance |
| load | queue/batch/disk caps, endpoint outage, high fan-out, drop counters |
| compatibility | historical record replay, old Hook config, catalog alias/migration |

## 21. Required commands and gates

Add a new generated-catalog gate:

```text
cargo run --locked -p iteron-xtask -- lifecycle check \
  --hooks 192 --metrics 320 --logs 192 --spans 48
```

Run per affected slice:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test -p iteron-protocol --locked
cargo test -p iteron-record --locked
cargo test -p iteron-obs --locked
cargo test -p iteron-ctx --locked
cargo test -p iteron-cli hooks --locked
cargo test -p iteron-cli telemetry --locked
cargo test -p iteron-cli tui --locked
cargo test -p iteron-cli --test tui_pty --locked
cargo run --locked -p iteron-xtask -- tunables check
cargo run --locked -p iteron-xtask -- boundaries check
```

Run documentation checks when generated references/navigation change:

```text
python -m pip install --require-hashes -r requirements-docs.lock
mkdocs build --strict --clean
```

## 22. Recommended PR sequence

1. Comparator attestation and catalog-count specification.
2. Protocol lifecycle IDs and schemas.
3. `xtask lifecycle` generator/checker.
4. Local bounded event bus and flight recorder.
5. Hook runtime module split and legacy compatibility.
6. Observe-only Hook wiring.
7. OTel dependency/transport ADR.
8. Metrics pipeline and 320 generated instruments.
9. Log pipeline and 192 schemas.
10. Trace pipeline and 48 templates.
11. ContextLedger types and assembly instrumentation.
12. Context tokenizer/cache/compaction reconciliation.
13. MemoryDecisionTrace query/candidate instrumentation.
14. Memory visibility/mutation/benchmark isolation.
15. Control/provider/tool/process instrumentation.
16. Workflow/verification/session instrumentation.
17. Augment Hook capability.
18. Gate Hook capability.
19. Operator inspect surfaces.
20. Benchmark completeness/overhead gates and paper export.

## 23. Definition of done

- Generated catalog reports exactly 192 Hook events, 320 metrics, 192 logs and 48 spans.
- Counts are 5-10x the attested maximum comparator baseline in each signal class.
- Memory/context meet or exceed the required catalog shares.
- All 192 lifecycle events have versioned content-free schemas and Hook wiring.
- All 320 metrics have unit, type, bounded label schema and owner.
- All 48 spans have documented parentage and error semantics.
- ContextLedger explains why every segment/token class entered or left the provider request.
- MemoryDecisionTrace explains every candidate's rank, admission, visibility and injection range.
- Benchmark attempts prove memory isolation and telemetry completeness.
- Hooks/exporters cannot delay cancellation or process reap.
- Content export is off by default and repository config cannot enable it.
- OTel overhead and drop-accounting targets pass under benchmark and stress load.
- Historical records and existing Hook configurations remain compatible.
- No implementation is pushed, merged or released without explicit user direction.
