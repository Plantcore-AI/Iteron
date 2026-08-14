# Iteron versus DeepSeek Harness: universal optimization gap audit

Audit date: 2026-08-14

DeepSeek reference: `deepseek-ai/deepseek-harness` commit
`47f943859bef60e4160492346772ded9b24f765a` (2026-08-13T19:38:46+08:00).

## Verdict

Iteron now has the broader *declared optimization and research contract*: Candidate Graph v3,
1,894 externally addressed runtime values, 28 independently identified optimization modules, a
66-node runtime service graph, a language-neutral research protocol, content-pinned external
implementations, and transactional stateful hot swap. Those are stronger optimization-specific
contracts than the audited DeepSeek Harness revision exposes.

The source-form gap is now closed: the census reports zero unresolved bindings and zero unaddressed
runtime values. The universal-harness goal is nevertheless not complete. All 830 mechanically
classified invariants still require owning-human approval, and the official installed
Terminal-Bench 2.1 campaign has not been executed. Thus Iteron may claim a larger governed
*declared* surface, but not a mathematical inventory of every possible generated value or
benchmark-performance superiority.

## Three different completion tests

These properties must not be collapsed into one grade:

1. **Tunable**: a run-start input can change a value; its type/domain, owner, use sites, resolved
   value, and behavior are observable.
2. **Replaceable**: an external implementation can occupy a versioned module/capability seam
   without editing or rebuilding the host, while host invariants remain authoritative.
3. **Trainable**: a native or external optimizer can enumerate candidates, run trials, receive
   reward/trajectory/evidence, checkpoint and resume, and isolate train from held-out scoring.

A profile parameter can be tunable without making its owning module replaceable. A plugin can be
replaceable without providing a trainable state or reward protocol.

## Current Iteron evidence

Generated registry revision 18 reports:

- 160 Tier-1 families: 137 `Full`, 23 `FixedHidden`, and 119 profile-addressable;
- 2,001 Tier-2 entries: 486 searchable, 795 bounded, 720 structural, and all 1,281 searchable or
  bounded entries applied;
- 10/10 prompt artifacts and 26/26 built-in tool descriptions overridable;
- 28 optimization modules, each with a stable external provider/consumer identity;
- 66 runtime-service nodes: 28 optimization modules, nine production consumer ports, 22 platform
  services, and seven immutable host-invariant classes.

Optimization census schema v4 reports 2,724 independent candidate rows. Of these, 1,894 are applied
and have concrete external addresses: 1,281 `unified_profile`, 296 `direct_config`, and 318
`caller_input`.
Candidate Graph v3 materializes these address classes, and the generic native adapter accepts only
after a correlated consumption receipt proves every patch was loaded, applied, and observed.

The same fail-closed census reports zero `binding_required` rows and 830 read-only invariant rows.
Every runtime row is advertised, applied, and uniquely externally addressed. The invariant rows
are only mechanically classified and all 830 still require owning-human approval across 32 owner ×
boundary batches. The census states its limit explicitly: it is complete for the currently declared
production source forms, not a mathematical universe of every possible generated or dynamic value.

## Module and plugin reality

Iteron no longer treats the nine internal `CoreSlot` consumers as the public module inventory. All
28 `ModuleId` values have independent definition/provider/consumer/lifecycle/observation contracts,
external process implementations, capability intersection, digest verification, deterministic
composition, and production consumption evidence. Modules that share one internal consumer execute
as a deterministic chain rather than erasing one another's identity.

Implementation protocol v2 adds snapshot, restore, migration, readiness, cancellation, and typed
failure contracts. The runtime hot-swap coordinator shadow-loads a verified generation, migrates
bounded state, checks readiness, atomically switches, drains, records a durable hash-chain ledger,
and relaunches/restores the old generation on post-switch failure. Platform service nodes marked
`replaceable_only` now require a real external protocol. Six platform services meet that rule; the
other 16 are explicitly `host_fixed_non_optimization` and name their delegated trainable modules or
closed host invariants. The graph contains no `replaceable_only + compiled_interface` claim.

DeepSeek Harness explicitly builds a Cordis plugin tree from layered profiles and patches. Its
architecture states that model adapters, tool registry, session log, and agent loop are plugins;
its generated capability graph lists 56 service rows (26 `seam`, 29 `core`, one `bundle`) with
explicit service-definition/provider/consumer roles, and its generated catalog documents 105
package configuration sections. Registrations are reversible effects and the plugin tree supports
dependency-aware unload/reload and configuration patching. This is materially more complete
runtime composability, although the project labels itself a developer preview and warns that
compatibility-breaking changes will occur.

## Training reality

Candidate Graph v3 represents profile values, direct-config paths, caller-input arguments,
implementation artifacts, topology, lineage, and experiment identity. The research protocol
supports capability-negotiated batch, asynchronous, population, bandit, multi-objective,
trajectory, checkpoint/resume, and opaque-artifact optimizer families. A pinned non-Rust adapter
can execute native materializations; an exact per-address receipt prevents an accepted-but-inert
dimension from being reported as complete.

The local qualification command executes 28 swaps plus 28 ablations as real external provider
process lifecycles, negotiates five optimizer families, and exercises state migration, all nine
hot-swap fault phases, rollback, and deterministic ledger replay. It deliberately emits a refusal,
not a proof manifest, because the installed Harbor/Terminal-Bench campaign and credentialed model
execution are absent. The 830 pending human invariant decisions and that missing external campaign
still prevent the final universal and performance claims.

The audited DeepSeek Harness tree contains session/runtime checkpoints, but no general trainer,
optimizer, backpropagation, reinforcement-learning, or reward-model implementation for harness
components. Its plugin architecture is a better substrate for module replacement, not evidence of
universal module training.

## Comparison

| Dimension | Iteron now | DeepSeek Harness reference | Lead |
|---|---|---|---|
| Typed, digest-pinned candidate values | Candidate Graph v3 across profile/config/caller/artifact/topology, with consumption proof | Layered typed plugin configuration and patches | Iteron on optimization identity/evidence |
| Optimization-module replacement | 28 independent external module identities and production chains | 56 generated service rows across seam/core/bundle categories | Not numerically comparable; Iteron has the explicit optimization-module contract |
| Dependency lifecycle / hot replacement | Protocol v2 state migration plus transactional switch, drain, durable ledger, rollback | Dependency-aware Cordis effects, unload/reload, isolation, HMR | Mixed; Iteron is stronger on transaction evidence |
| Replay and effective-run evidence | Immutable effective profile, registry digests, durable/historical replay contracts | Durable session event log and configuration dump | Iteron on optimization evidence |
| Safety and authority envelope | Capabilities, tighten-only ceilings, Pins, effect/durability/replay invariants | Policy services and guarded events, less optimization-specific governance | Iteron |
| External harness interoperability | Language-neutral research protocol, Python client, native adapter, exact Terminal-Bench 2.1 pin, local 56-cell lifecycle qualification | Headless/npm composition; no general trainer protocol found | Iteron on research protocol; official installed campaign pending |
| Native optimization | TPE/halving plus optimizer capability negotiation and v3 candidate materialization | No general component trainer found | Iteron, but incomplete |
| Universal trainability | Not complete | Not complete | Neither |

## Gaps and required order

### P0 — close the remaining evidence, not the already-addressed surface

1. Obtain owning-human GitHub approval for all 830 invariant rows across the 32 owner × boundary
   batches. Agent-authored or ledger-only assertions do not count.
2. Run the installed black-box campaign and retain its evidence bundle before publishing the
   universal-surface A or superiority claim.

### P1 — finish service-level dynamic replacement evidence

1. Preserve safety, authority, durability, replay, hard budgets, and the effect ledger as host
   ceilings that candidates may narrow but never widen.
2. Exercise every one of the 28 external module identities through the installed 28-swap plus
   28-ablation matrix, including shared-slot chains and stateful rollback.

### P2 — qualify the implemented research substrate

1. Run at least one non-Rust external optimizer and one independent agent harness against the
   installed binary, not just library fixtures.
2. Demonstrate multiple optimizer families, held-out isolation, checkpoint/resume, state migration,
   fault injection, rollback, and deterministic replay under the published protocol.
3. Publish performance comparisons only from that retained campaign; contract breadth alone is not
   benchmark superiority.

## Acceptance sentence

The full goal is complete only when an out-of-tree researcher can enumerate every admitted
quality-affecting value and module, replace or parameterize one module without rebuilding Iteron,
run a bounded trial through a language-neutral protocol, retrieve the exact effective candidate
and evidence, train/resume without touching held-out data, and cannot widen any host-owned safety
or durability invariant.

## Affected boundaries and invariants

Current milestone boundaries: `core/tunables`, `core/cli`, `core/context`, `core/tool_policy`,
`core/verification`, `core/evaluation`, and durable record/replay. Future module-loader work also
crosses `core/protocol`, `core/marketplace`, provider, workflow, scheduler, agents, and kernel effect
boundaries.

Invariant overlays retained throughout: bounded queues/retries/output/time/cost/concurrency;
immutable run-start candidate; unique terminal ownership; exact effective-profile evidence;
capability and operator authority cannot be widened by a candidate; unknown external effects are
never automatically retried; credentials are neither serialized nor recorded.

## Primary references

- DeepSeek Harness README: <https://github.com/deepseek-ai/deepseek-harness>
- Architecture and plugin tree: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/architecture.md>
- Generated capability seam graph: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/capability-seams.md>
- Generated config catalog: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/config-catalog.md>
- Event producer/consumer map: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/event-producer-consumer.md>
- Composition and HMR: <https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cordis-tutorial/06-composition-and-hmr.md>
