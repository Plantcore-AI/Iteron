# Trainable Harness Runtime Acceptance Contract

Status: accepted locally with focused behavioral evidence (2026-08-11)
Owner: human Project Owner
Scope: close every code-level gap named in the two 2026-08-10 runtime-gap inputs
Delivery rule: local worktree only; do not push, merge, publish, or change the public installer

## 1. Outcome

Iteron is accepted only when one immutable, runtime-effective harness checkpoint controls all
nine `core/*` strategy slots; every selectable decision produces outcome-joinable evidence; and the
provider, context, process, LSP, MCP, verification, and collaboration controls named below are real
bounded production paths rather than registry-only declarations.

This contract deliberately does not use catalog size, type existence, unit fixtures, comments, or
an offline demo as proof that a feature is live. A capability is accepted only when the production
composition root resolves it, the runtime consumes it, the run record identifies it, and a focused
behavioral oracle demonstrates the resulting state transition.

## 2. Scope boundaries

Included:

- the 160-family tunables registry, resolver, runtime bindings, immutable run snapshot, and profile;
- all nine strategy slots: `router`, `planner`, `context`, `memory`, `scheduler`, `tool_policy`,
  `verifier`, `model_router`, and `collaboration`;
- policy artifact compilation, implementation lookup, boot-time installation, receipts, and child
  inheritance;
- decision evidence sufficient to train and evaluate a harness policy;
- all 26 currently `missing` and all 51 currently `partial` tunable families;
- context/token/tool-catalog efficiency; provider governor; persistent process/LSP/MCP controls;
  and controlled collaboration.
- content-level record revocation/erasure, including every runtime projection and trainable-data
  derivative rather than only unlinking an entire leaf-session journal.

Excluded from this implementation pass:

- Windows support;
- broad workspace, stress, soak, benchmark-score, and cross-platform test matrices;
- publishing, pushing, merging, releasing, or changing the public one-line installer;
- live self-evolution or self-promotion. Candidate production and promotion remain offline,
  non-authoritative, and human-gated.

Focused compile and behavioral checks are required. “Minimal tests” means the narrowest command
that proves each changed contract, not zero verification.

Affected boundary IDs:

- `protocol-compat`, `kernel-reduction`, `kernel-runtime`, `kernel-effects`;
- `cli-host`, `cli-tui`, `provider-core`, `provider-adapters`;
- `scheduler`, `context-core`, `context-knowledge`, `tools-execution`;
- `workflow-engine`, `agent-orchestration`, `evaluation`, `evolution-control`;
- `tunability-registry`, `record-core`, `record-sessions`, `mcp-client`, `verification`.

Invariant overlays:

- `bounded-queues`, `bounded-run`, `bounded-retry`, `bounded-concurrency`;
- `append-only-record`, `hash-chain`, `intent-execute-terminal`, `unknown-effect-block`;
- `trusted-config-precedence`, `memory-provenance`, `bounded-context`, `bounded-recall`;
- `fixed-model-comparison`, `no-runtime-activation`, `fixed-invariant-nontrainability`.

## 3. Status vocabulary

- `[ ]` not implemented or evidence absent;
- `[-]` production path exists but one or more acceptance clauses remain false;
- `[~]` code complete with focused compile/source evidence, behavioral oracle still absent;
- `[x]` every clause has direct production and focused behavioral evidence.

No parent item becomes `[x]` while one child criterion remains below `[x]`.

## 4. Acceptance requirements

### H01 — One runtime-effective tunables truth

- [x] `H01.1` The trusted composition root calls the typed resolver exactly once before opening a
  fresh run, and rejects the entire set atomically on an active-family resolution failure.
- [x] `H01.2` Provider/model/effort/budgets/retry/context/memory/tools/verification/orchestration/
  extension settings used by production are read from that resolved set. No second default is
  derived in `main`, `runtime`, a provider adapter, or a child spawner.
- [x] `H01.3` A fresh rollout appends the immutable 160-family snapshot immediately after
  `run_start`; resume, continue, fork, workflow children, and direct children validate/inherit the
  same effective digest instead of consulting current machine defaults.
- [x] `H01.4` `iteron config explain --effective`, `/tunables`, status output, run record, and runtime
  getters project the same value, provenance, profile, ceiling, and inactive reason.
- [x] `H01.5` Interactive, benchmark, and research profiles are explicit typed inputs. Repository
  configuration may only tighten operator authority and ceilings.
- [x] `H01.6` Runtime defaults no longer drift: one canonical value owns turns, wall time,
  consecutive tool errors, token/cost optionality, memory, compaction, and retry.
- [x] `H01.7` After the owning production paths below land, the registry contains zero `Missing`
  and zero `Partial` families. A fixed security/effect invariant remains `FixedHidden`, never made
  trainable merely to improve the count.

### H02 — Complete harness-checkpoint compiler and executor

- [x] `H02.1` A versioned implementation registry maps an admitted `(slot, policy_id, version,
  digest, artifact)` to a bounded typed policy implementation; lookup never executes arbitrary
  configuration text.
- [x] `H02.2` Policy artifacts are content-addressed, size bounded, schema checked, and loaded only
  from an operator-trusted active bundle. Project configuration cannot select or widen one.
- [x] `H02.3` All nine iteron slots accept at least one non-baseline recognized implementation whose
  decision differs observably from the baseline while respecting the same ceiling.
- [x] `H02.4` Unknown slot versions, unknown policy implementations, digest mismatch, malformed
  artifacts, duplicate slots, and attempts to widen authority fail closed with operator-visible
  diagnostics. They never silently claim the bundle was applied.
- [x] `H02.5` The complete bundle is compiled once at boot, pinned immutably for the run, inherited
  by every child/workflow, and identified in run genesis and every policy-decision record.
- [x] `H02.6` A bounded application receipt lists every requested slot as `applied`, `baseline`, or
  `rejected` with a stable reason. Partial application is never reported as full application.

### H03 — Trainable policy-decision evidence

- [x] `H03.1` A versioned, content-free `PolicyDecisionEvidence` carries opportunity ID, run/turn,
  slot, policy/bundle identity, eligible actions, selected action, score or propensity, feature
  schema/digest, fixed-invariants digest, tunables digest, and decision timestamp/sequence.
- [x] `H03.2` Eligible and selected actions use bounded typed IDs; raw prompts, source, paths,
  memory text, tool arguments, and credentials cannot enter the evidence payload.
- [x] `H03.3` Every live decision by each of the nine slots emits exactly one selection record,
  including deterministic baselines and explicit abstention/fallback.
- [x] `H03.4` Run/turn terminal evidence joins selections to quality, cost, tokens, latency,
  verifier result, and harness-error outcome without high-cardinality metric labels.
- [x] `H03.5` Trajectory projection preserves the join and refuses incomplete, duplicate, or
  cross-run decision identities; governed datasets retain negative and failed trajectories.

### H04 — Context, memory, and prompt efficiency

- [x] `H04.1` Token estimation is provider/model aware where a tokenizer or authoritative usage
  model exists; the byte heuristic is an explicitly identified conservative fallback.
- [x] `H04.2` Tool schemas are selected by authority and bounded task relevance. A lazy discovery
  route keeps every admitted tool reachable without eagerly sending every schema.
- [x] `H04.3` Stable prefix, instructions, task context, memory, transcript, attachments, tool
  results, and tool schemas have separately resolved budgets and stable digests.
- [x] `H04.4` Compaction trigger, hysteresis, topology, summary profile, recent retention, and
  obligation/coverage checking are runtime-effective policies, not hidden constants.
- [x] `H04.5` Memory budgets are enforced as one total ceiling; retrieval supports bounded lexical/
  hybrid weights and recency decay without allowing relevance to raise trust.
- [x] `H04.6` LSP evidence has a resolved context budget and is attributed separately from source,
  transcript, memory, and ordinary tool results.

### H05 — Industrial provider governor

- [x] `H05.1` Each physical provider attempt has its own durable intent/terminal and obeys the
  resolved retry schedule; opaque adapter-internal retries remain refused.
- [x] `H05.2` A bounded ordered fallback chain advances only for an admitted error taxonomy and
  records route transition, quota/circuit reason, and per-route usage/cost truth.
- [x] `H05.3` Rate-limit-aware admission and account/model circuit state can lower concurrency or
  defer work but never exceed the resolved ceiling.
- [x] `H05.4` Quality/cost/latency objectives, service tier, response verbosity, request
  compression, and prompt-cache TTL/breakpoints are typed route policies with capability checks.
- [x] `H05.5` Optional hedging is bounded, idempotent-only, separately journaled per attempt, and
  deterministically cancels/reaps losing attempts without double-accounting.

### H06 — Persistent process, LSP, output, and MCP lifecycle

- [x] `H06.1` Persistent PTY backend selection, background-job cap, idle/stall timeout, and
  interactive-stdin wait policy are runtime-effective and session-owned.
- [x] `H06.2` Large tool output spills into a bounded private content-addressed artifact while the
  model receives a bounded preview and durable handle; cleanup and retention are explicit.
- [x] `H06.3` LSP servers are selected by typed language policy, reused by session/workspace,
  bounded, restartable, cancellable, and freshness-attributed.
- [x] `H06.4` MCP connections use bounded reconnect/backoff, preserve protocol/version identity,
  and never duplicate an unknown external effect after reconnect.
- [x] `H06.5` MCP result caps/spill, deferred discovery, resources/prompts/plugins, and per-server
  lifecycle controls are runtime-effective rather than registry-only declarations.

### H07 — Controlled collaboration

- [x] `H07.1` The durable task DAG owns task/message/budget/dependency/attempt identities and each
  terminal exactly once; partial failure and orphan cleanup have explicit owners.
- [x] `H07.2` Speculative siblings are bounded, share no writer authority, and losing siblings are
  cancelled from recorded evidence without cancelling unrelated work.
- [x] `H07.3` Every write-capable child receives an isolated worktree and cannot write the parent
  workspace directly.
- [x] `H07.4` Child output is merged only through a validating merge controller with deterministic
  conflict classification and explicit human escalation for unresolved conflicts.
- [x] `H07.5` Failed tasks can be retried or reassigned under a bounded policy while preserving
  lineage, consumed budget, unknown-effect refusal, and previous evidence.
- [x] `H07.6` Verification supports summary coverage checking, incremental/full selection, flaky
  quarantine, quorum, and operator-authorized rollback after failure.

### H08 — Registry and operator truth

- [x] `H08.1` Every formerly missing/partial family names one production owner, one runtime getter,
  one strategy slot or fixed authority, and one evidence projection.
- [x] `H08.2` Generated tunables documentation, configuration documentation, CLI help, and runtime
  warnings are regenerated from the same canonical metadata.
- [x] `H08.3` Operator diagnostics show the effective profile/bundle/tunables digest, slot
  application receipt, provider governor state, context budget, process/LSP/MCP health, and
  collaboration limits without revealing content or credentials.

### H09 — Record revocation, retention, and verifiable erasure

- [x] `H09.1` Exact-session deletion, retention pruning, and content-level revocation are distinct
  typed operations. Each has one authority owner, bounded target resolution, active-writer
  exclusion, crash recovery, and an idempotent terminal receipt.
- [x] `H09.2` Content-bearing record fields and large payloads live behind bounded private
  content-addressed references that support tombstoning and cryptographic erasure without silently
  rewriting the append-only decision chain.
- [x] `H09.3` A bounded reference graph propagates revocation to session projections, indexes,
  prompt history, attachments, tool artifacts, checkpoints, memory/context materializations,
  exports, telemetry debug stores, trajectories, datasets, evaluator inputs, and candidate stores.
  A surviving fork cannot retain revoked parent content merely because it shares history.
- [x] `H09.4` Future context assembly, replay, resume, fork, export, training admission, and
  diagnostics fail closed on a revoked or unresolved handle and expose only a content-free
  tombstone reason. They never reconstruct data from a stale derivative.
- [x] `H09.5` Erasure keeps the minimum content-free audit proof needed to show target, authority,
  propagation coverage, terminal state, and failures. Operator diagnostics can distinguish
  `requested`, `quiescing`, `tombstoned`, `shredded`, `propagating`, `verified`, and `failed`.

## 5. Implementation DAG

```text
H01 resolver/snapshot foundation
   +--> H02 checkpoint compiler/executor
   |       +--> H03 policy-decision evidence
   |       +--> H04 context/memory policies
   |       +--> H05 provider governor
   |       +--> H06 process/LSP/MCP policies
   |       +--> H07 collaboration policies
   +-----------------------------------------> H08 registry/operator truth

H09 record erasure foundation
   +--> record/artifact/memory/context/evolve projection propagation
   +--> replay/resume/fork/export/training fail-closed admission

H03 + H04 + H05 + H06 + H07 + H08 + H09 -> final requirement-by-requirement audit
```

## 6. Minimal verification policy

During implementation, run only the narrowest relevant commands, normally:

```console
cargo fmt --all -- --check
cargo check --locked -p <changed-crate> --all-targets
cargo test --locked -p <changed-crate> <focused-test-filter>
cargo run --locked -p iteron-xtask -- boundaries check
```

Use a targeted `iteron-cli` binary check only when the composition root changes. Do not run the full
workspace suite, broad benchmark ladder, soak matrix, or cross-platform matrix during this pass.

## 7. Final acceptance ledger

For every `Hxx.y` row, final acceptance must record:

1. production owner path and symbol;
2. runtime composition path proving it is live;
3. durable/observable evidence path;
4. focused behavioral command and result;
5. any intentionally unsupported state and its fail-closed behavior.

The final audit must inspect the current worktree after implementation. A checkbox, generated
catalog, passing compilation, or absence of a TODO is not independently sufficient evidence.

## 8. Final local acceptance ledger (2026-08-11)

The accepted registry seal is `iteron-tunables` revision 16, digest
`4f79c8296326a2b1b84ccf3bbea61a3f30095cc5b634c4ae0371efc9b0b51b55`: 160 families are
`97 Full / 0 Partial / 0 Missing / 63 FixedHidden`, with 196 external constraint policies.
Shared gates passed: `cargo fmt --all -- --check`; `cargo check --locked -p iteron-cli
--all-targets`; the 11-test registry contract; canonical tunables/docs drift checks; and
`iteron-xtask boundaries check` at 1,097 files, 41 boundaries, 13 overlays, 23 packages, and 192
active lifecycle events with zero reserved. `schema-compat check-base --base HEAD` also passes.

The final adversarial re-audit does not accept a fixed family from schema shape or checkpoint
self-attestation. Every effective `FixedHidden` family is in exactly one closed class: an immutable
process owner re-sampled at resume (A), a V2 value decoded by its registered physical consumer (B),
or a governed content identity accompanied by an exact live materializer receipt (C). Missing,
duplicate, wrong-authority, stale-owner, missing-consumer, and digest-tampered receipts fail before
an effect. The production fresh-composition seal passes 1/1, the effective-runtime projection and
resume seal pass 7/7, and V2 fixed-authority mutation coverage passes 1/1.

### H01 evidence

- `H01.1` — Owner/composition: `RuntimeResolutionBuilder` is consumed exactly once by
  `runtime_tunables::composition::compose_fresh` before rollout creation. Durable evidence: the
  resolved digest and V2 snapshot. Oracle: registry contract 11/11 plus CLI all-target check.
  Unsupported/fail-closed: any active-family resolution gap aborts the whole composition.
- `H01.2` — Owner/composition: `effective_{core,provider,execution,tooling,mcp,content,
  app_server,binary_media}` decode the immutable set into Agent, Registry, Workflow, MCP, and
  provider controls. Durable evidence: V2 checkpoint, policy decisions, and physical-effect
  records. Oracle: schema-retry, process, app-server, image, provider-objective, and MCP focused
  suites all pass. Unsupported/fail-closed: missing pins, duplicate installation, catalog mismatch,
  or unknown capability reject before an effect.
- `H01.3` — Owner/composition: `record::append_fresh_genesis_with_tunables` and snapshot-v2 place
  the checkpoint immediately after `run_start`; resume/fork/direct/workflow children validate and
  inherit it. Durable evidence: `TunablesSnapshotV2` plus `inherited_from`. Oracle: `cargo test
  --locked -p iteron-cli a_child_inherits_the_exact_nonbaseline_policy_checkpoint` 1/1.
  Unsupported/fail-closed: stale, missing, or tampered snapshots stop before child execution.
- `H01.4` — Owner/composition: `EffectiveTunablesView` backs effective config, `/tunables`, status,
  TUI, runtime getters, and record projection. Durable evidence: value, provenance, profile,
  ceiling, and inactive reason remain in one checkpoint. Oracle: canonical registry and generated
  docs drift tests pass. Unsupported/fail-closed: wrong type, missing family, V1 ambiguity, or digest
  mismatch is refused rather than synthesized.
- `H01.5` — Owner/composition: `HarnessProfileArg` maps to typed `Interactive`, `Benchmark`, or
  `Research` profiles and exact session-isolation constraints. Durable evidence: profile and digest
  in genesis/status. Oracle: registry authority/constraint contract 11/11. Unsupported/fail-closed:
  repository input may tighten but cannot widen operator or benchmark authority.
- `H01.6` — Owner/composition: core/execution/provider/process fact getters own defaults, including
  derived cwd/environment owners; decoders install those exact values. Durable evidence:
  `OwnerSnapshot` and default provenance. Oracle: process launch one-shot 1/1 and the opaque-retry
  fixture 1/1. Unsupported/fail-closed: getter/default drift aborts decode or installation.
- `H01.7` — Owner/composition: `families.rs` and canonical metadata seal the 160-entry registry.
  Durable evidence: revision 16 and its digest. Oracle: registry contract 11/11, production fresh
  composition 1/1, and `tunables check`.
  Unsupported/fail-closed: security/effect invariants remain `FixedHidden`; none were made trainable
  to improve counts.

### H02 evidence

- `H02.1` — Owner/composition: `bundle_adapter::{schema,registry}` maps the exact policy tuple and
  `compile_configured_bundle`/`compile_recorded_bundle` installs only known typed implementations.
  Durable evidence: genesis bundle snapshot and nine runtime identities. Oracle:
  `registry_has_baseline_and_non_baseline_for_every_slot` and recorded-genesis reconstruction pass.
  Unsupported/fail-closed: configuration text is never executable.
- `H02.2` — Owner/composition: artifacts are capped at 2 KiB, canonicalized, schema-v1 checked,
  SHA-256 addressed, and admitted only from trusted user configuration. Durable evidence: artifact
  identities/digests in snapshot and receipt. Oracle: unknown identity/version/digest and malformed
  project selection tests pass. Unsupported/fail-closed: oversize, malformed, project-selected, or
  digest-mismatched artifacts reject atomically.
- `H02.3` — Owner/composition: all nine slots register a baseline and typed narrower alternative;
  `CompiledSlots` installs into every Agent strategy port and child path. Durable evidence: receipt
  row and per-decision policy identity. Oracle: alternative-decision and caller-ceiling intersection
  tests pass. Unsupported/fail-closed: alternatives intersect authority and cannot widen it.
- `H02.4` — Owner/composition: closed `RejectionCode` values and the compiler's atomic resolution
  own rejection. Durable evidence: stable rejected receipt rows and no rejected genesis. Oracle:
  one-bad-request atomic-rejection plus malformed/duplicate/unknown tests pass.
  Unsupported/fail-closed: rejected or partial coverage is never reported as full.
- `H02.5` — Owner/composition: one immutable `Arc<CompiledPolicyBundle>` is compiled at boot,
  reconstructed on resume, and shared with workflow, collect, side-conversation, and direct child
  paths. Durable evidence: `PolicyBundleSnapshot` and exact parent receipt link. Oracle: child
  checkpoint inheritance/replay 1/1. Unsupported/fail-closed: equality or parent-receipt mismatch
  stops before execution.
- `H02.6` — Owner/composition: `BundleCompilationReceipt` owns nine bounded rows with
  `Applied|Baseline|Rejected`. Durable evidence: content-free rows and receipt digest in genesis.
  Oracle: stable nine-slot receipt and absent/partial-not-full tests pass. Unsupported/fail-closed:
  a rejected receipt cannot seal genesis.

### H03 evidence

- `H03.1` — Owner/composition: protocol `PolicyDecisionEvidence` v1 and
  `PolicyEvidenceRecorder::{begin_opportunity,append_decision}` own sequence, time, tunables, and
  frozen policy binding. Durable evidence: `EventKind::PolicyDecision`. Oracle: `cargo test --locked
  -p iteron-cli policy_evidence_recorder` 9/9. Unsupported/fail-closed: schema/bundle/ordinal/time
  mismatch rejects before append.
- `H03.2` — Owner/composition: bounded `PolicyActionId` and typed drafts prevent callers from
  inserting arbitrary content. Durable evidence: digest-only feature/invariant/tunable fields.
  Oracle: invalid/duplicate decision and cross-recorder opportunity tests pass.
  Unsupported/fail-closed: bad IDs, digests, selection, or propensity consume no opportunity.
- `H03.3` — Owner/composition: router, scheduler, context, memory, tool policy, verifier,
  model-router, collaboration, and planner call the same pending-to-decided recorder. Durable
  evidence: exactly one decision per opportunity, including abstention/fallback. Oracle: all-frozen-
  slots unique/monotone test passes. Unsupported/fail-closed: duplicate or pending opportunities
  block terminal evidence.
- `H03.4` — Owner/composition: `PolicyOutcomeEvidence` joins exact opportunity digests/counts to
  quality, cost, tokens, latency, verifier, and harness result. Durable evidence:
  `EventKind::PolicyOutcome`. Oracle: exact turn/run outcome ordering tests pass.
  Unsupported/fail-closed: scope, join, count, digest, ordinal, or duplicate terminal mismatch is
  refused; content never becomes a metric label.
- `H03.5` — Owner/composition: `PolicyEvidenceRunProjector` builds governed trajectory records from
  durable decisions/outcomes. Durable evidence: rollout/checkpoint digests and governance state.
  Oracle: evolve policy-evidence projection 4/4. Unsupported/fail-closed: incomplete, duplicate,
  cross-run, join-tampered, or revoked evidence is refused; negative/failed trajectories remain.

### H04 evidence

- `H04.1` — Owner/composition: `TokenEstimatorProfile` selects a provider/model estimator and
  `RequestEstimator` reconciles authoritative usage. Durable evidence: tokenizer identity and
  estimated/actual error in `ContextLedger`. Oracle: route-profile/fallback test plus ctx 135/135.
  Unsupported/fail-closed: unknown routes use named one-token-per-UTF-8-byte fallback v2, never the
  undercounting legacy heuristic.
- `H04.2` — Owner/composition: `DeferredToolCatalog` intersects authority and task relevance before
  lazy discovery. Durable evidence: admitted/deferred/rejected catalog lifecycle and schema digest.
  Oracle: `cargo test --locked -p iteron-tools tool_search` 3/3. Unsupported/fail-closed: search
  cannot expose schemas outside the admitted set.
- `H04.3` — Owner/composition: `ContextBudgetPolicy` and `ContextMaterializationPolicy` independently
  budget all context classes before provider admission. Durable evidence: segment source digest,
  bytes, tokens, decision, cache class, and totals. Oracle: non-transferable component and explicit
  truncation/rejection tests pass. Unsupported/fail-closed: no cross-class borrowing.
- `H04.4` — Owner/composition: compaction policy, hysteresis, topology/profile, recent retention,
  and obligation coverage drive the live runtime. Durable evidence: compaction seed/events and
  preserved/lost transforms in ContextLedger. Oracle: compaction 15/15 plus hysteresis/obligation
  tests. Unsupported/fail-closed: obligation or coverage loss cannot be reported as preserved.
- `H04.5` — Owner/composition: one `MemBudget` total and `MemoryRetrievalPolicy` apply trust before
  relevance, then bounded lexical/structural/recency/novelty ranking. Durable evidence:
  `MemoryDecisionTrace`. Oracle: total-ceiling, recency, trust-floor, and recall-audit tests in the
  135-test ctx suite. Unsupported/fail-closed: relevance never raises trust or exceeds the total.
- `H04.6` — Owner/composition: `lsp_result_tokens` is a non-transferable context component and LSP
  result IDs are classified separately. Durable evidence: LSP source/totals in ContextLedger.
  Oracle: `lsp_evidence_has_a_non_transferable_attributed_budget`. Unsupported/fail-closed: LSP
  overflow cannot borrow source, transcript, or ordinary tool budget.

### H05 evidence

- `H05.1` — Owner/composition: provider attempt semantics and
  `runtime::provider_route::{admit_provider_effect_inner,brokered_provider_turn}` wrap every
  physical dispatch. Durable evidence: independent effect intent/terminal, route, retry index, and
  physical-attempt ID. Oracle: opaque retry 1/1 with zero calls/attempts; typed pre-stream retry
  1/1 with two intents for two calls. Unsupported/fail-closed: opaque, streamed, unknown, or
  interrupted attempts are never automatically replayed.
- `H05.2` — Owner/composition: governor failover taxonomy and Agent fallback activation share one
  bounded route chain in both provider loops. Durable evidence: model-router selection, route
  transition, usage/cost truth, and quota/circuit notice. Oracle: durable transition 1/1 and
  `cargo test --locked -p iteron-provider --test provider_governor` 6/6.
  Unsupported/fail-closed: non-admitted taxonomy, output-started, unknown-effect, or unattested
  candidate cannot switch routes.
- `H05.3` — Owner/composition: `ProviderGovernor::admit`, `AttemptPermit`, rate policy, and circuit
  state gate every physical and hedge attempt. Durable evidence: rejection lifecycle, intent, and
  quota/circuit state. Oracle: provider-governor 6/6. Unsupported/fail-closed: unknown/exhausted
  quota only lowers, defers, or rejects and never exceeds the ceiling.
- `H05.4` — Owner/composition: `ObjectiveWeights`, `RouteObjectiveScores`, effective provider
  decoding, capability validation, and fallback ranking consume typed quality/cost/latency facts,
  tier, verbosity, compression, and cache controls. Durable evidence: objective score and evidence
  digest in each provider intent. Oracle:
  `objective_weights_change_the_real_fallback_order_and_unknown_facts_fail_closed` 1/1.
  Unsupported/fail-closed: missing facts are ineligible; ranking grants no authority and unsupported
  wire controls reject before dispatch.
- `H05.5` — Owner/composition: `HedgePolicy` and `execute_hedged_provider_turn` require idempotency,
  governor permits, bounded duplicates, cancellation, and reap. Durable evidence: separate hedge
  intents/terminals and exact usage aggregation. Oracle:
  `hedged_attempts_are_separately_journaled_and_losing_delay_is_suppressed` 1/1 plus usage merge
  1/1. Unsupported/fail-closed: an optional duplicate is suppressed at the ceiling; an unknown
  dispatched loser marks accounting incomplete.

### H06 evidence

- `H06.1` — Owner/composition: process runtime/launch/stdin policies install once into Registry and
  `process::Supervisor::start`; resume verifies the same owner. Durable evidence: checkpoint,
  process effects, health, and output cursors. Oracle: `cargo test --locked -p iteron-tools process
  --no-fail-fast` 15/15. Unsupported/fail-closed: invalid cwd/environment, missing one-shot policy,
  unsupported backend, or unbounded limits reject before spawn.
- `H06.2` — Owner/composition: `ToolOutputSpillPolicy`, `ToolOutputSpillStore`, and the private
  derivative store cover ordinary result paths and explicit cleanup boundaries. Durable evidence:
  the preview's whole-artifact SHA-256 is the revocation handle. Oracle: spill suite 8/8.
  Unsupported/fail-closed: incomplete markers, storage/capacity failure, or unretained output emits
  a content-free error only; the former raw-prefix leak is covered by the suite.
- `H06.3` — Owner/composition: typed LSP language/recovery policy installs into the session/workspace
  pool, driver, and supervisor. Durable evidence: tool effects plus server identity, epoch, reuse,
  restart, freshness, and truncation. Oracle: `cargo test --locked -p iteron-tools lsp
  --no-fail-fast` 29/29. Unsupported/fail-closed: stale/unsupported/unbounded routes refuse or
  return Unknown rather than fabricate success.
- `H06.4` — Owner/composition: reconnect policy, lifecycle core, supervisor, and generation-fenced
  identities gate every MCP dispatch. Durable evidence: generation/protocol health and definite vs
  unknown effect terminal. Oracle: reconnect, exponential backoff, cancellation/reap, and schema-
  identity focused tests 4/4. Unsupported/fail-closed: post-dispatch transport uncertainty is
  Unknown and never replayed.
- `H06.5` — Owner/composition: MCP result/spill policy, capability exposure, and session control
  preflight exact tools/resources/prompts/plugins and proxy IDs. Durable evidence: private spill
  marker/cleanup, health, and effect journal. Oracle: MCP spill 4/4, remote resources/prompts 1/1,
  capability exposure 2/2. Unsupported/fail-closed: unknown capability or proxy grants nothing;
  oversize/unretained results reject without content leakage.

### H07 evidence

- `H07.1` — Owner/composition: workflow `ExecutionLedger`/`TaskDagStore` own task, attempt, message,
  ACK, dependency, budget, and terminal identity; reopen reconciles nonterminal state once. Durable
  evidence: task-DAG JSONL and workflow journal. Oracle: durable reopen terminalization 2/2 and
  workflow parallel 14/14. Unsupported/fail-closed: malformed/dependency-invalid work receives a
  durable negative terminal; unknown effect never becomes success.
- `H07.2` — Owner/composition: speculative sibling policy admits read-only candidates only, keeps
  group-local permits/tokens, records a winner before group cancellation, and leaves unrelated work
  alone. Durable evidence: per-sibling attempts and ACKed winner digest. Oracle: workflow parallel
  14/14. Unsupported/fail-closed: writer speculation and unknown-effect quorum are refused.
- `H07.3` — Owner/composition: `KernelSpawner` derives isolated-writer authority from the pinned
  AgentDef, holds a session writer lane, provisions a host-owned detached worktree, and installs an
  isolated Registry. Durable evidence: child rollout, patch digest, and DAG result. Oracle:
  `h07_isolated_writer_seals_the_verified_index_before_deterministic_merge` 1/1.
  Unsupported/fail-closed: class/worktree/root/dirty-state mismatch returns no parent write.
- `H07.4` — Owner/composition: worktree `prepare_patch`, verifier, and merge controller seal bytes,
  SHA-256, index tree, parent HEAD, and consume one in-memory patch for check+apply. Durable evidence:
  merge receipt and stable failure classification. Oracle: H07 isolated-writer/receipt tests 1/1.
  Unsupported/fail-closed: receipt mismatch, conflict, verifier mutation, or parent drift requires
  human resolution and leaves the parent unchanged.
- `H07.5` — Owner/composition: typed AttemptSpec retry/reassignment lineage derives its prior digest
  from the durable predecessor and is revalidated by the reducer. Durable evidence: retry_of,
  assignment, cause, budget, and terminal. Oracle: retry canonical-lineage 1/1 and parallel 14/14.
  Unsupported/fail-closed: cross-task, skipped ordinal, wrong cause/digest, nonterminal, or
  unknown-effect retry is rejected.
- `H07.6` — Owner/composition: exact summary coverage, verification policy, typed quarantine,
  consensus/quorum, and operator-authorized rollback are live; rollback holds a verified content
  owner through Git restore. Durable evidence: `VerificationPolicy` receipts and workflow reduce
  evidence. Oracle: `cargo test --locked -p iteron-cli h07_` 5/5, agents coverage 1/1, and event
  schema replay 1/1. Unsupported/fail-closed: missing coverage, indeterminate/quarantined result,
  absent checkpoint, or absent operator authority cannot turn green or roll back.

### H08 evidence

- `H08.1` — Owner/composition: every former gap is mapped in canonical metadata to one typed owner,
  runtime getter/installer, consumer slot or fixed authority, and evidence projection; the main
  clusters are retry, context/instructions, shell/grep/git, workflow/image/app-server/discovery,
  provider controls, process/media/cache, collaboration, MCP, and session isolation. Durable
  evidence: owner/V2 snapshots plus their physical decisions/effects. Oracle: registry 11/11 and
  all focused suites named above. Unsupported/fail-closed: no known schema blocker remains; 63
  security/effect invariants stay fixed-hidden and require typed A/B/C authority evidence.
- `H08.2` — Owner/composition: families, schemas, provenance, defaults, activation, and constraints
  are the sole canonical source for generated JSON/Markdown and CLI reference. Durable evidence:
  revision/digest and checked generated files. Oracle: `tunables check`, generated-artifact drift
  1/1, and `docs check`. Unsupported/fail-closed: hand drift is a hard generator/check failure.
- `H08.3` — Owner/composition: operator-status snapshots and the TUI status renderer expose profile,
  bundle/tunables digests, nine receipts, governor routes, context ceilings/use, process/LSP/MCP
  health, and collaboration limits. Durable evidence: bounded counters, IDs, and digests only.
  Oracle: CLI all-target, boundaries, and the complete status-panel sentinel privacy test 1/1.
  Unsupported/fail-closed: private environment values, content, and credentials never enter
  status/evidence.

### H09 evidence

- `H09.1` — Owner/composition: protocol/record erasure implements distinct exact-session,
  retention, and content-revocation state graphs with local authority proof, target locks,
  active-writer exclusion, recovery, and idempotent receipts. Durable evidence: atomic state receipt
  at every transition. Oracle: protocol erasure 4/4 and record erasure 10/10.
  Unsupported/fail-closed: rebinding, absent target, retained derivative, graph/storage failure, or
  active writer produces a typed failure and no alternate deletion.
- `H09.2` — Owner/composition: record externalization and private content store place bounded fields,
  attachments, spill, history, export, and training derivatives behind authenticated CAS+AEAD
  references. Durable evidence: append-only marker/hash chain plus tombstone, generation, key shred,
  and verified absence. Oracle: content-store 12/12, record erasure 10/10, spill-marker 1/1, partial-
  marker 1/1. Unsupported/fail-closed: partial material, bad AAD, revoked generation, oversize, or
  incomplete marker is unreadable and never silently inline.
- `H09.3` — Owner/composition: durable bounded lineage covers all 13 managed namespaces: session
  projection, index, prompt history, attachment, tool artifact, checkpoint, memory/context, export,
  content-free telemetry, trajectory, dataset, evaluator input, and candidate store. Durable
  evidence: bidirectional source/derivative edges published before serving references. Oracle:
  transitive content-store tests, fork/revoke tests, and
  `production_dataset_evaluator_and_candidate_reads_close_after_trajectory_revocation` 1/1.
  Unsupported/fail-closed: forged owners, missing lineage, bound overflow, or revoked ancestor blocks
  publication/read; telemetry is accepted only through its content-free absence invariant.
- `H09.4` — Owner/composition: record hydration, derivative `read_at`, attachments, exports,
  checkpoint preview/rewind/rollback, and training readers acquire exact owner/read gates and hold
  leases through the real consumer. Durable evidence: source generation/owner/reference checks at
  the read linearization point. Oracle: attachment 1/1, export revoke 1/1, H07 rollback 5/5, and
  dataset/evaluator/candidate revoke 1/1. Unsupported/fail-closed: stale cache/inline fallback is
  absent; a revoke before read rejects, while a read already holding the lease linearizes first.
- `H09.5` — Owner/composition: bounded content-free erasure receipt records target, proven authority,
  operation, state, counts, generation, 13 coverage bits, and typed failure only. Durable evidence:
  immutable terminal receipt and seven distinguishable states. Oracle: telemetry privacy-schema
  1/1, protocol erasure 4/4, and record verification tests 10/10. Unsupported/fail-closed: arbitrary
  content is rejected from telemetry/receipts and `verified` requires re-reading material absence
  and every serving gate.

H09's accepted authority boundary is deliberate: plaintext already atomically published to an
external destination is outside Iteron's record authority; the operator-owned Git object database
is not physically garbage-collected by record erasure; and telemetry coverage depends on its
enforced content-free schema. Adding an Iteron-managed content-bearing debug store must lower the
13/13 receipt until that store gains CAS, lineage, and read gates.
