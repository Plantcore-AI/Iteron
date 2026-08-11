# Trainable Harness Runtime Acceptance Contract

Status: active implementation contract  
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

- [ ] `H01.1` The trusted composition root calls the typed resolver exactly once before opening a
  fresh run, and rejects the entire set atomically on an active-family resolution failure.
- [ ] `H01.2` Provider/model/effort/budgets/retry/context/memory/tools/verification/orchestration/
  extension settings used by production are read from that resolved set. No second default is
  derived in `main`, `runtime`, a provider adapter, or a child spawner.
- [ ] `H01.3` A fresh rollout appends the immutable 160-family snapshot immediately after
  `run_start`; resume, continue, fork, workflow children, and direct children validate/inherit the
  same effective digest instead of consulting current machine defaults.
- [ ] `H01.4` `iteron config explain --effective`, `/tunables`, status output, run record, and runtime
  getters project the same value, provenance, profile, ceiling, and inactive reason.
- [ ] `H01.5` Interactive, benchmark, and research profiles are explicit typed inputs. Repository
  configuration may only tighten operator authority and ceilings.
- [ ] `H01.6` Runtime defaults no longer drift: one canonical value owns turns, wall time,
  consecutive tool errors, token/cost optionality, memory, compaction, and retry.
- [ ] `H01.7` After the owning production paths below land, the registry contains zero `Missing`
  and zero `Partial` families. A fixed security/effect invariant remains `FixedHidden`, never made
  trainable merely to improve the count.

### H02 — Complete harness-checkpoint compiler and executor

- [ ] `H02.1` A versioned implementation registry maps an admitted `(slot, policy_id, version,
  digest, artifact)` to a bounded typed policy implementation; lookup never executes arbitrary
  configuration text.
- [ ] `H02.2` Policy artifacts are content-addressed, size bounded, schema checked, and loaded only
  from an operator-trusted active bundle. Project configuration cannot select or widen one.
- [ ] `H02.3` All nine iteron slots accept at least one non-baseline recognized implementation whose
  decision differs observably from the baseline while respecting the same ceiling.
- [ ] `H02.4` Unknown slot versions, unknown policy implementations, digest mismatch, malformed
  artifacts, duplicate slots, and attempts to widen authority fail closed with operator-visible
  diagnostics. They never silently claim the bundle was applied.
- [ ] `H02.5` The complete bundle is compiled once at boot, pinned immutably for the run, inherited
  by every child/workflow, and identified in run genesis and every policy-decision record.
- [ ] `H02.6` A bounded application receipt lists every requested slot as `applied`, `baseline`, or
  `rejected` with a stable reason. Partial application is never reported as full application.

### H03 — Trainable policy-decision evidence

- [ ] `H03.1` A versioned, content-free `PolicyDecisionEvidence` carries opportunity ID, run/turn,
  slot, policy/bundle identity, eligible actions, selected action, score or propensity, feature
  schema/digest, fixed-invariants digest, tunables digest, and decision timestamp/sequence.
- [ ] `H03.2` Eligible and selected actions use bounded typed IDs; raw prompts, source, paths,
  memory text, tool arguments, and credentials cannot enter the evidence payload.
- [ ] `H03.3` Every live decision by each of the nine slots emits exactly one selection record,
  including deterministic baselines and explicit abstention/fallback.
- [ ] `H03.4` Run/turn terminal evidence joins selections to quality, cost, tokens, latency,
  verifier result, and harness-error outcome without high-cardinality metric labels.
- [ ] `H03.5` Trajectory projection preserves the join and refuses incomplete, duplicate, or
  cross-run decision identities; governed datasets retain negative and failed trajectories.

### H04 — Context, memory, and prompt efficiency

- [ ] `H04.1` Token estimation is provider/model aware where a tokenizer or authoritative usage
  model exists; the byte heuristic is an explicitly identified conservative fallback.
- [ ] `H04.2` Tool schemas are selected by authority and bounded task relevance. A lazy discovery
  route keeps every admitted tool reachable without eagerly sending every schema.
- [ ] `H04.3` Stable prefix, instructions, task context, memory, transcript, attachments, tool
  results, and tool schemas have separately resolved budgets and stable digests.
- [ ] `H04.4` Compaction trigger, hysteresis, topology, summary profile, recent retention, and
  obligation/coverage checking are runtime-effective policies, not hidden constants.
- [ ] `H04.5` Memory budgets are enforced as one total ceiling; retrieval supports bounded lexical/
  hybrid weights and recency decay without allowing relevance to raise trust.
- [ ] `H04.6` LSP evidence has a resolved context budget and is attributed separately from source,
  transcript, memory, and ordinary tool results.

### H05 — Industrial provider governor

- [ ] `H05.1` Each physical provider attempt has its own durable intent/terminal and obeys the
  resolved retry schedule; opaque adapter-internal retries remain refused.
- [ ] `H05.2` A bounded ordered fallback chain advances only for an admitted error taxonomy and
  records route transition, quota/circuit reason, and per-route usage/cost truth.
- [ ] `H05.3` Rate-limit-aware admission and account/model circuit state can lower concurrency or
  defer work but never exceed the resolved ceiling.
- [ ] `H05.4` Quality/cost/latency objectives, service tier, response verbosity, request
  compression, and prompt-cache TTL/breakpoints are typed route policies with capability checks.
- [ ] `H05.5` Optional hedging is bounded, idempotent-only, separately journaled per attempt, and
  deterministically cancels/reaps losing attempts without double-accounting.

### H06 — Persistent process, LSP, output, and MCP lifecycle

- [ ] `H06.1` Persistent PTY backend selection, background-job cap, idle/stall timeout, and
  interactive-stdin wait policy are runtime-effective and session-owned.
- [ ] `H06.2` Large tool output spills into a bounded private content-addressed artifact while the
  model receives a bounded preview and durable handle; cleanup and retention are explicit.
- [ ] `H06.3` LSP servers are selected by typed language policy, reused by session/workspace,
  bounded, restartable, cancellable, and freshness-attributed.
- [ ] `H06.4` MCP connections use bounded reconnect/backoff, preserve protocol/version identity,
  and never duplicate an unknown external effect after reconnect.
- [ ] `H06.5` MCP result caps/spill, deferred discovery, resources/prompts/plugins, and per-server
  lifecycle controls are runtime-effective rather than registry-only declarations.

### H07 — Controlled collaboration

- [ ] `H07.1` The durable task DAG owns task/message/budget/dependency/attempt identities and each
  terminal exactly once; partial failure and orphan cleanup have explicit owners.
- [ ] `H07.2` Speculative siblings are bounded, share no writer authority, and losing siblings are
  cancelled from recorded evidence without cancelling unrelated work.
- [ ] `H07.3` Every write-capable child receives an isolated worktree and cannot write the parent
  workspace directly.
- [ ] `H07.4` Child output is merged only through a validating merge controller with deterministic
  conflict classification and explicit human escalation for unresolved conflicts.
- [ ] `H07.5` Failed tasks can be retried or reassigned under a bounded policy while preserving
  lineage, consumed budget, unknown-effect refusal, and previous evidence.
- [ ] `H07.6` Verification supports summary coverage checking, incremental/full selection, flaky
  quarantine, quorum, and operator-authorized rollback after failure.

### H08 — Registry and operator truth

- [ ] `H08.1` Every formerly missing/partial family names one production owner, one runtime getter,
  one strategy slot or fixed authority, and one evidence projection.
- [ ] `H08.2` Generated tunables documentation, configuration documentation, CLI help, and runtime
  warnings are regenerated from the same canonical metadata.
- [ ] `H08.3` Operator diagnostics show the effective profile/bundle/tunables digest, slot
  application receipt, provider governor state, context budget, process/LSP/MCP health, and
  collaboration limits without revealing content or credentials.

### H09 — Record revocation, retention, and verifiable erasure

- [ ] `H09.1` Exact-session deletion, retention pruning, and content-level revocation are distinct
  typed operations. Each has one authority owner, bounded target resolution, active-writer
  exclusion, crash recovery, and an idempotent terminal receipt.
- [ ] `H09.2` Content-bearing record fields and large payloads live behind bounded private
  content-addressed references that support tombstoning and cryptographic erasure without silently
  rewriting the append-only decision chain.
- [ ] `H09.3` A bounded reference graph propagates revocation to session projections, indexes,
  prompt history, attachments, tool artifacts, checkpoints, memory/context materializations,
  exports, telemetry debug stores, trajectories, datasets, evaluator inputs, and candidate stores.
  A surviving fork cannot retain revoked parent content merely because it shares history.
- [ ] `H09.4` Future context assembly, replay, resume, fork, export, training admission, and
  diagnostics fail closed on a revoked or unresolved handle and expose only a content-free
  tombstone reason. They never reconstruct data from a stale derivative.
- [ ] `H09.5` Erasure keeps the minimum content-free audit proof needed to show target, authority,
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
