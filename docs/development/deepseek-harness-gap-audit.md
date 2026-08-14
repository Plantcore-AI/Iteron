# Iteron versus DeepSeek Harness: universal optimization gap audit

Audit date: 2026-08-14

DeepSeek reference: `deepseek-ai/deepseek-harness` commit
`47f943859bef60e4160492346772ded9b24f765a` (2026-08-13T19:38:46+08:00).

## Verdict

Iteron has not yet completed the full universal-harness goal.

The current branch closes a large parameter-addressability milestone: every declared searchable or
bounded Tier-2 parameter is applied, every lawful non-Pin Tier-1 family is profile-addressable, and
all built-in prompt and tool-description text has a stable override identity. It does not prove
that every optimizable production value was discovered, does not let an external researcher load
an arbitrary implementation for every runtime module, and does not train the whole exposed space
through one native or external trainer protocol.

DeepSeek Harness is ahead on runtime composition. Iteron is ahead on governed, digest-pinned
experiment inputs, immutable effective-profile evidence, authority ceilings, historical replay,
and bounded benchmark evidence. Neither system currently demonstrates end-to-end training of every
module. There is therefore no honest basis for saying Iteron is simply “better” overall or for
claiming benchmark-performance superiority.

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
- 1,870 Tier-2 entries: 454 searchable, 791 bounded, 625 structural, and all 1,245 searchable or
  bounded entries applied;
- 10/10 prompt artifacts and 26/26 built-in tool descriptions overridable;
- 28 optimization modules, each with at least one item in the unified profile surface;
- 1,400 unified profile-addressable items in total: 119 families + 1,245 Tier-2 parameters + 10
  prompt artifacts + 26 tool descriptions.

The broader optimization census reports 2,548 candidates: 1,923 `runtime_settable`/applied and 625
read-only invariants. Schema v2 makes clear that the larger number is not the unified external
profile size: 1,245 are `unified_profile`, 251 are `direct_config`, and 427 are
`caller_injected`. The latter 678 include serde defaults, Clap defaults, default constructors, and
fallback calls that an explicit configuration or Rust caller may replace but that are not
necessarily enumerated by `ProfileDocument`. Until those paths are unified or separately given a
stable external contract, 1,923 must not be presented as “any harness can pass all of these.”

The 625 read-only classifications also require adversarial review. Automatic syntax and structural
rules can identify candidates, but cannot decide whether a routing marker, tool-policy set, or
quality-affecting default is truly a non-learnable invariant.

## Module and plugin reality

Iteron has a useful object-safe `StrategySlot` seam for nine policy directions: context,
tool-policy, memory, router, planner, collaboration, scheduler, verifier, and model-router. The
current CLI composition root, however, uses a private registry of 19 compiled descriptors and a
hard-coded Rust constructor match. An external researcher cannot register a new strategy
implementation without changing and rebuilding Iteron.

Iteron's signed marketplace is real but narrower: its public contribution vocabulary is skill,
agent, hook, MCP server, and language server. It does not make provider, storage, session log,
agent loop, context engine, scheduler, verifier, or every other runtime capability an externally
replaceable implementation seam.

DeepSeek Harness explicitly builds a Cordis plugin tree from layered profiles and patches. Its
architecture states that model adapters, tool registry, session log, and agent loop are plugins;
its generated capability graph lists 56 service rows (26 `seam`, 29 `core`, one `bundle`) with
explicit service-definition/provider/consumer roles, and its generated catalog documents 105
package configuration sections. Registrations are reversible effects and the plugin tree supports
dependency-aware unload/reload and configuration patching. This is materially more complete
runtime composability, although the project labels itself a developer preview and warns that
compatibility-breaking changes will occur.

## Training reality

Iteron's offline TPE/successive-halving tuner is bounded and replayable, but `TunerCandidate.values`
is validated against the Tier-1 family registry. It does not yet represent Tier-2 parameters,
prompt/tool-text artifacts, external component implementations, per-module trainable state, or a
generic reward/trajectory/checkpoint protocol.

The evolve plane has strong dataset, assessment, evidence, and promotion contracts, and correctly
refuses adaptive activation that would violate authority. Those governance properties do not by
themselves make the entire runtime trainable.

The audited DeepSeek Harness tree contains session/runtime checkpoints, but no general trainer,
optimizer, backpropagation, reinforcement-learning, or reward-model implementation for harness
components. Its plugin architecture is a better substrate for module replacement, not evidence of
universal module training.

## Comparison

| Dimension | Iteron now | DeepSeek Harness reference | Lead |
|---|---|---|---|
| Typed, digest-pinned candidate values | Unified family/parameter/text profile with strict rejection | Layered typed plugin configuration and patches | Iteron on experiment identity |
| Whole-runtime module replacement | Nine internal strategy traits; private compiled registry; five marketplace contribution kinds | Plugin tree; model adapter, tools, log, loop, and capability providers replaceable | DeepSeek |
| Dependency lifecycle / hot replacement | Bounded install-time composition; no universal service lifecycle | Dependency-aware Cordis effects, unload/reload, isolation, HMR | DeepSeek |
| Replay and effective-run evidence | Immutable effective profile, registry digests, durable/historical replay contracts | Durable session event log and configuration dump | Iteron on optimization evidence |
| Safety and authority envelope | Capabilities, tighten-only ceilings, Pins, effect/durability/replay invariants | Policy services and guarded events, less optimization-specific governance | Iteron |
| External harness interoperability | Stable profile files/APIs and exact Terminal-Bench 2.1 Rust adapter; no neutral CLI/RPC | Headless/npm composition; no trainer protocol | Mixed |
| Native optimization | Offline TPE/halving plus evolve governance, currently Tier-1-centric | No general component trainer found | Iteron, but incomplete |
| Universal trainability | Not complete | Not complete | Neither |

## Gaps and required order

### P0 — make the parameter claim truthful

1. Separate `profile_addressable`, `direct_config`, `caller_injected`, and
   `invariant_read_only` in generated evidence.
2. Externalize or give a stable equivalent input to the 678 additional caller-settable defaults.
3. Human-review all 625 invariant dispositions; require a concrete invariant owner and behavioral
   counterexample for disputed entries.
4. Expand discovery beyond selected AST shapes to builders, runtime registries, bundled assets,
   configuration schemas, model-visible renderers, and dynamic plugin contributions.
5. Only then run installed black-box acceptance and claim the universal parameter surface A.

### P1 — make every legitimate module replaceable

1. Publish a complete capability graph. Every seam needs a versioned definition, provider,
   consumer, lifecycle, cancellation, error, observation, and compatibility contract.
2. Keep safety, authority, durability, replay, hard budgets, and the effect ledger in the host; an
   optimizer may narrow but never widen those ceilings.
3. Replace the private compiled strategy registry with an external, content-addressed process or
   WASM loader. Avoid a stable Rust dynamic-library ABI claim.
4. Extend marketplace contributions to strategy and capability providers, with deterministic
   dependency order, isolation, rollback, resource bounds, and quarantine.
5. Prove a single-module replacement and ablation for every seam from an out-of-tree package.

### P2 — make the surface trainable by any research harness

1. Define a benchmark-neutral, language-neutral protocol for surface enumeration, candidate
   validation, run/cancel, effective profile, result, trajectory, and evidence retrieval.
2. Add a benchmark-adapter registry; retain exact `terminal-bench/2.1` + schema-v1 pinning as one
   adapter rather than the universal protocol.
3. Generalize candidate identity across Tier-1, Tier-2, prompt/tool text, and module artifacts.
4. Define reward and multi-objective metrics, train/held-out partitions, checkpoint/resume,
   deterministic seeds where supported, resource budgets, and distributed trial ownership.
5. Qualify at least one non-Rust external optimizer and one independent agent harness against an
   installed binary.

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
