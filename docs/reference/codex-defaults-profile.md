# Codex comparison profile: r26 request retry

This profile is a **bounded comparison fixture** for Iteron's tunables registry revision 26. It adjusts the request retry base to 200 ms and the maximum to five physical attempts. It sets the provider circuit failure threshold to 10 so the circuit cannot stop a five-attempt retry trace first. The 30-second backoff cap and circuit recovery values remain their existing Iteron defaults. These settings do not reproduce Codex's separate stream reconnect policy or its retry predicate. A fresh r26 run has no default turn ceiling (`u32::MAX` is its wire-compatible unlimited sentinel). Explicit finite turn limits still apply, and the default wall ceiling remains 3,600 seconds.

Profile file SHA-256: `855e01c92bb994e7d78b9ed97d9c4e5561e44f137cb3fb1fd31cd73f82711ddd`. Registry revision 26 digest: `41d03740d482fe481c5425278c130b21492e75b38eae7178fd5d70e4487d76c2`. Pin both the file and registry through Iteron's profile validation:

```sh
iteron --tunables-profile docs/reference/codex-defaults-profile.json \
  --tunables-profile-digest 855e01c92bb994e7d78b9ed97d9c4e5561e44f137cb3fb1fd31cd73f82711ddd \
  --tunables-explain
```

Do not combine this profile with another `user_config` declaration for the same retry or circuit family. The profile is pinned to r26; a later registry revision requires a new reviewed profile.

## Existing r25 sessions

Resuming an r25 session keeps its sealed 64-turn default and any explicit finite limit. Its V2 checkpoint and original value provenance stay unchanged. To remove the turn limit, start that session with `--max-turns unlimited` or enter `/budget unlimited` in the TUI; the runtime appends a durable turn-ceiling change before using the new limit.

An r25 project setting of `max_turns=64` was flattened to the same builtin provenance and effective value as the old default. The historical checkpoint therefore cannot distinguish that explicit equal-valued project cap from no project cap. Iteron preserves the recorded 64-turn limit on resume and requires an explicit change to unlimited.

## Effective comparison on a concrete local route

The selected values below came from an **r26 debug-binary fixture** using this exact profile, fresh production composition, `config explain --effective --format json`, a local loopback provider request, a V2 rollout snapshot, and a resumed process. It declared a 272,000-token model window and used an explicit CLI wall limit of 30 seconds, with no turn-limit override. The table is **route-specific runtime evidence**. It compares Iteron behavior with pinned Codex source `fe74a774532af67b5a4a3dec03ce9469e17f89af`; it is not a claim that arbitrary provider models have identical defaults.

| Effective family | Iteron fixture value and source | Pinned Codex counterpart / decision |
| --- | --- | --- |
| `provider` | `fixture`, CLI selected | Provider selection is configuration and account dependent; no universal equal value. |
| `model` | `fixture-model`, CLI selected | Model metadata and route selection are dynamic; compare the same admitted model before a parity claim. |
| `effort` | `medium`, Iteron literal default | Codex takes `default_reasoning_level` from known model metadata; unknown-model fallback is unset. `medium` here is an Iteron default, not demonstrated model parity. |
| `max_turns` | Unlimited (`4294967295` wire sentinel), r26 literal default, verified in the actual run and resumed checkpoint | No matching universal Codex turn cap established. |
| `max_wall_secs` | `30`, explicit fixture CLI limit | No matching universal Codex task wall cap established. |
| `permission_mode` | `acceptEdits`, Iteron default | Codex resolves sandbox and approval from trust/configuration. Compare concrete edit, shell and approval behavior; enum names do not establish equivalence. |
| `bypass_permissions` | `false`, Iteron default | No bypass was requested in either ordinary route; authorization rules differ by operation and trust. |
| `compaction_trigger` | `adaptive`, 82% usable-window ratio, 120,000-token blind fallback, 8,192-token output reserve; resolver default | Codex model default auto-compact threshold is 90% of resolved context with a 95% effective hard cap. These formulas differ; 82% is not a Codex-equivalent raw-window percentage. |
| `compaction_keep_recent` | `0`, Iteron recent-tail policy default | Codex's history trim/compact logic has no matching numeric keep-recent parameter. |
| `retry_backoff_base` | `200` ms, profile | Codex request retry base is 200 ms. Same starting delay does not imply same jitter, predicate or stream behavior. |
| `retry_backoff_cap` | `30,000` ms, Iteron default | No exact equal request-cap value established from the inspected Codex path. |
| `retry_max_attempts` | `5`, profile | Codex default is four request retries after the initial attempt, up to five physical requests. Retry eligibility remains provider and error dependent. |
| `provider_health_circuit_breaker_state_policy` | threshold `10`, open `30` s, half-open probes `1`, success threshold `1`; profile | Iteron circuit guard for this fixture. No direct Codex family counterpart established. |
| `request_output_cap` | `8,192`, route resolver fallback | The request sent `max_tokens=8192`. Codex tool-result truncation is a different setting; no universal Codex request cap is established. |
| `prompt_cache` | `false`, selected custom route | Codex normally supplies a request prompt-cache key where supported. The fixture request cannot prove cross-provider cache parity. |
| `conversation_history_budget` | `65,952` tokens, nominal default allocation; the default-derived transcript can borrow unused text-input space | Codex tracks aggregate context; no one-to-one partition value is established. Explicit Iteron partition caps remain hard limits. |
| `context_window_override_reserve` | model window `272,000`, output reserve `8,192`, task `26,380`, memory `26,380`, instruction/attachment/tool schema `13,190` each, verification `0`; route resolver | The window is the synthetic model declaration. Codex uses model metadata and a 95% effective limit, without these Iteron partition fields. |
| `provider_service_tier` | `provider_default`, route resolver | The custom request omitted `service_tier`. Codex service tier is config/route dependent; no universal label equivalence. |
| `pure_overlap` | `true`, Iteron resolver default | Codex enables parallel tool calls where the model and tool support them. Scheduler settings are not direct protocol equivalents. |
| `pure_concurrency` | `16`, Iteron resolver default | No matching Codex global pure-tool concurrency value established. |
| `session_isolation_profile` | `interactive`, Iteron resolver default | Both systems have local persistent sessions, but storage and resume contracts differ. |

The selected output was verified through `runtime_tunables::composition`, the resolved-family decoders and actual CLI runtime. This r26 profile changes only the three marked retry/circuit families; the remaining effective values are controlled by the route and Iteron defaults. Source points in Iteron include `crates/cli/src/runtime_tunables/effective_core.rs`, `effective_provider.rs`, `main.rs`, and `crates/ctx/src/runtime_policy.rs`. Pinned Codex points include `codex-rs/core/src/session/step_settings.rs`, `codex-rs/models-manager/src/model_info.rs`, `codex-rs/protocol/src/openai_models.rs`, `codex-rs/core/src/session/context_window.rs`, and `codex-rs/model-provider-info/src/lib.rs`.

## Bounded runtime evidence

An r26 debug binary with SHA-256 `078b3878afc59471e525fc85f2186d2433e9c2b83b06c03dadbd2a72b3fd5050` ran against `127.0.0.1` with a synthetic credential and no external model call. With this profile, the provider returned four typed HTTP 529 overloads before semantic output, then a successful streamed answer on request five. Fresh exit was zero. A new process resumed the recorded session and completed on one more request with exit zero. Fresh and resumed explain output agreed on all 21 listed family values and provenance, also matching the actual rollout snapshot. The fresh runtime snapshot and resumed full effective digest were both `58a1c03ddd2d59a67d5dd67d6ebd18be92115f28546ae998718c1b901cfbf138`. Environment-dependent evidence can make independent fresh processes have different full digests; equality is required against the actual saved session. The request used streaming and `max_tokens=8192`; it omitted `reasoning_effort` and `service_tier` for this custom route.

The same binary passed two actual r25-to-r26 resume cases: a default-64 session and an explicitly limited-64 session created by the earlier binary. Both resumed successfully with their original checkpoint and 64-turn ceiling intact; an explicit `--max-turns unlimited` then completed successfully and appended the unlimited ceiling. The compatibility path requires the exact historical registry and complete agent catalog identity. This fixture covers the two built-in agents, not arbitrary historical custom catalogs.

Three further loopback cases passed on this binary: partial-text continuation, command execution during provider streaming, and command completion followed by disconnect and continuation without repeating the write. Separate regression tests cover the 64,492-token transcript with a nominal 63,488 allocation, explicit-cap compaction, bounded session-picker completion/retry, and optional cache-breakpoint projection when switching models. Record tests cover buffered observations, asynchronous index publication, crash markers and a concurrent append/page race. Required authoritative log acknowledgements and projection construction/validation remain synchronous; this is not an all-asynchronous storage implementation.

These are scoped Linux/local-fixture results. Mac, live Ark/Kimi calls, all tunable families and complete product acceptance are not certified. The profile does not create Codex's separate stream reconnect budget, model-specific effort default, aggregate context algorithm, or identical permission decisions.

Affected boundary: `documentation-site`. Relevant overlays: `boundedness`, `provider-routing`, `durability-replay`, and `tcb-authority`. Boundary and generated-document checks passed for this change.
