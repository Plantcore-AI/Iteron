# Production readiness and regression coverage

This is the acceptance matrix for standalone Iteron. A source implementation, a
passing synthetic test, and a successful live model journey are separate facts.
An unchecked row is not a passing test. This matrix does not certify a release.

## Supported envelope

Record the exact source commit, installed binary hash, OS/architecture, adapter,
endpoint, model version, enabled capabilities, and test result for each supported
route. Credentials stay outside receipts. Recheck a route when any of these
change. Catalog membership and a successful greeting establish neither reliable
tool use nor account-wide model compatibility.

Current native wire adapters are OpenAI Responses, OpenAI-compatible Chat
Completions, and Anthropic Messages. See the [provider matrix](../reference/providers.md).
There is no native Gemini adapter in this source. A compatible endpoint requires
its own capability and continuation tests before support can be claimed.

| Protocol | Required continuation checks | Authoritative contract |
| --- | --- | --- |
| Responses | Preserve reasoning/output items and tool-call identities across tool results, retry and resume | [OpenAI reasoning](https://developers.openai.com/api/docs/guides/reasoning) |
| Messages | Parse block indices, partial JSON, thinking signatures, in-band errors and terminal stop events | [Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming) |
| DeepSeek Chat | Preserve route-scoped `reasoning_content` across subsequent tool-enabled requests, including assistant answers without tool calls | [DeepSeek thinking mode](https://api-docs.deepseek.com/guides/thinking_mode/) |
| Gemini | Preserve required thought signatures and tool/result ordering; generic Chat compatibility alone is insufficient | [Google thought signatures](https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures) |

These contracts were checked on 2026-10-13. They explain required behavior, not
which live accounts or model versions have passed it.

## Boundary-case matrix

The locations below are existing regression homes or the place to add missing
fixtures. They are not claims that every listed scenario already has an executed
test. Each scenario needs an observable assertion, a bounded deadline, isolated
state, and cleanup. Exercise bounds at zero, one, limit minus one, limit and limit
plus one where meaningful. Combine interacting dimensions using pairwise cases,
then add adversarial combinations for storage, cancellation and external effects.

| Area | Cases to exercise | Required result | Regression home |
| --- | --- | --- | --- |
| Startup | No config; missing/invalid credential; unknown model; unavailable route; cold cache | Actionable bounded failure or ready listener; no request before admission | `runtime/route_controls_tests.rs`, `tests/headless_serve.rs` |
| Client protocol | Wrong version; malformed/oversized/truncated frames; invalid token; observer tries mutation | Closed refusal, no credential disclosure or authority increase | `tests/headless_serve.rs` |
| Reconnect | Disconnect before/after submission; stale replay cursor; process restart; dropped response | Stable session identity, bounded replay, no invented acceptance | `tests/headless_serve.rs` |
| Submission identity | Duplicate key with same/different request; pending crash; expiry; clock rollback | At most one admission for a valid key; deterministic conflict/unknown | Issue #416 acceptance; implementation remains separately owned |
| Turn lifecycle | Success; provider failure; terminal append failure; answer before finalization | One factual terminal; usable input after settled failure; uncertain effects retained | `runtime/provider_turn_driver_tests.rs` |
| Concurrent control | Cancel/steer/queue during stream or tool; repeated interrupt; client detach | No lost drafts or duplicate execution; owned processes stop within a bound | `tui/tests.rs`, `tests/workflow_interrupt_pty.rs` |
| Service lifecycle | Drain while idle/busy; reconnect during drain; listener/session limits | Readiness and admission agree; no unowned worker after shutdown | `tests/headless_serve.rs` |
| Stream framing | Every UTF-8/SSE split point; empty/comment frames; unknown event; oversized frame | Bounded decoder, identical semantic output for valid fragmentation | `provider/src/openai.rs`, `provider/src/anthropic.rs`, `provider/src/responses.rs` |
| Stream terminal | EOF before terminal; missing/contradictory stop reason; HTTP 200 error envelope | Typed failure and preserved partial output; no fabricated success/usage | Provider adapter tests, `runtime/provider_turn_driver_tests.rs` |
| Tool stream | Parallel/interleaved tool IDs; missing/repeated IDs; partial or invalid JSON; token truncation | Only complete validated calls execute, once per admitted identity | Provider adapter tests and runtime tool-turn tests |
| Continuation | Reasoning/signature preservation; route switch; restart; missing opaque payload | Correct exact-route continuation; no cross-route private payload leakage | Provider adapter continuation tests |
| Usage | Absent/zero/repeated/conflicting usage; cache usage; failed stream | Unknown differs from zero; no double charging or cleared uncertainty | Provider adapter tests, `provider/tests/provider_governor.rs` |
| Transport errors | DNS/connect/TLS failure; timeout before/after send; 401/403/429/5xx; Retry-After | Bounded classified retry; no automatic duplicate uncertain effect | `provider/tests/provider_governor.rs`, runtime provider tests |
| Route controls | Cache modes; TTL; reasoning effort; disabled capability; stale model metadata | Unsupported required control refuses before dispatch; optional policy adapts | `runtime/route_controls_tests.rs` |
| Context budget | Missing/declared output limit; custom default; large CJK task; 120k allocation | Request output and context reserve agree; valid UTF-8 selection | `runtime_tunables/composition.rs` |
| Context failure | Selection/materialization/partition failure; unavailable file; budget saturation | Stage-specific safe diagnostic; no input text leaked through error | `runtime/kernel_error.rs` |
| Long sessions | Repeated compaction; tool-result references; resumed context; model switch | Required tool continuations retained; limits remain bounded | Context/runtime compaction and replay tests |
| Child agents | Restricted profile; invalid profile; sibling concurrency; recursive budget | Child tools narrow parent authority; profiles do not mutate siblings | `runtime/workflow_spawner.rs`, `runtime/kernel_special_execution_tests.rs` |
| Child outcomes | Tool error; empty answer; timeout; cancellation; unknown side effect | Surface bounded actual outcome; completed execution does not imply task quality | Runtime child execution/accounting tests |
| Native files | macOS default confinement; relative/absolute paths; missing parent; deny rules | Authorized write succeeds; denied/escaping write has no side effect | `tools/src/confined_helper.rs`, `tools/tests/operation_admission.rs` |
| Workspace authority | Symlink replacement; sibling/additional root; Git boundary; read-only profile | No accidental widening through path spelling or tool choice | Tools confinement and authority tests |
| Process tools | Output flood; child outlives parent; timeout; PTY EOF; Ctrl-C | Bounded capture and owned-process cleanup; unknown cleanup is visible | `tests/workflow_interrupt_pty.rs`, tools execution tests |
| Store failure | Disk full; permission denied; transient lock; broken pipe; interrupted fsync | No success before durable commit; recoverable error distinguishes uncertainty | Record fault fixtures and prompt-history tests |
| History | Consecutive identical prompts; final draft; adoption; busy save; unavailable writer | Correct restore and honest bounded shutdown outcome | `prompt_history.rs`, `app_server/client_bootstrap/tests.rs` |
| Recovery | Crash before/after append/rename; partial final record; corrupted/missing artifact | Verify stored identity; no duplicate tool effects or fabricated terminal | `record/tests/streaming_replay.rs`, `record/tests/artifact_replay.rs` |
| Revocation | Revoked source while derivative exists; stale manifest; cross-session history | Revoked content cannot be restored; unrelated entries remain usable | `record/tests/erasure_operations.rs`, prompt-history tests |
| Input | CJK/emoji/combining characters; multiline paste; huge paste; IME; image attachment | Correct text and bounded work; draft survives refusal/navigation | `tui/tests.rs`, `tests/image_input.rs` |
| Layout | Narrow/short terminal; repeated resize; long tool/diff blocks; scroll while streaming | Logo and composer remain usable; no stale rows or scroll jumps | `tests/tui_pty.rs`, block and transcript render tests |
| Terminal exit | Ctrl-D; repeated Ctrl-C; signal; provider error; rejected submission | Cursor, alternate screen, mouse and paste modes restored | Installed PTY acceptance and `tests/tui_pty.rs` |
| Clipboard | Selection copy; multiline/CJK; unavailable clipboard; terminal interception | Copy selected text or explain unsupported action without losing draft | TUI selection/input tests and actual terminal exercise |
| Configuration | Missing/default effort; unknown key; legacy config; bad capability override | Stable defaults and visible useful warnings; no silent guessed capability | `tests/operator_config.rs`, config and catalog tests |
| Skills/extensions | Disabled/unknown skill; duplicate names; malformed schema; MCP drop/cancel | One exposed catalog, bounded errors, no privilege increase | `tests/mcp_commands.rs`, extension and skill tests |
| Installation | Clean supported machine; update from stable version; broken artifact; rollback | Documented command works; installed identity matches build; data survives rollback | Build/release validation and install smoke |
| Platforms | macOS ARM64; supported Linux targets; Windows/ConPTY | Native build and installed terminal journey for each advertised target | Platform-specific CI; `tests/windows_conpty.rs` |
| Resources | Queue/concurrency saturation; long tool output; huge graph; repeated sessions | Enforced memory/byte/time/cost bounds and no growing orphan inventory | Bounded-minimum, governor and service tests |
| Secret handling | Credential-shaped provider error/tool output; malformed diagnostic injection | Redacted output; Keychain consumption succeeds without value logging | Provider redaction tests and installed credential-helper smoke |
| Coding quality | Read→edit→run check→inspect diff→second turn→restart/resume | Correct expected file/test outcome; no unrelated changes; truthful final answer | Small fixed coding fixtures per live supported route |

## Fast bug-fix verification

Finish disjoint source changes before compiling. Build the application and selected
test targets once on the delivery platform, run exact regressions for each changed
path, then exercise the installed binary. Do not rerun unrelated passing tests
without a concrete risk. Record skipped coverage explicitly.

Examples of focused selectors (run from the repository root):

```sh
cargo test --locked -p iteron-cli --bin iteron normal_exit_distinguishes_storage_failure_and_unavailable_writer
cargo test --locked -p iteron-cli --bin iteron consecutive_identical_prompts_flush_and_restore_with_live_record_owner
cargo test --locked -p iteron-cli --bin iteron exhausted_semantic_recovery_preserves_exact_observed_prefix_before_error_and_reopen
cargo test --locked -p iteron-tools --lib macos_default_registry_writes_without_dangerous_bypass
cargo run --locked -p iteron-xtask -- boundaries check
```

The macOS case must run on macOS. A target that contains zero matching cases is
not a pass. Tests above are focused regression examples, not a full release gate.

## Production promotion criteria

1. Every known critical/major defect in the advertised envelope has a matching
   regression and passing evidence on the candidate source. Historical issue
   closure alone is insufficient. Unreproduced reports remain explicitly open.
2. Every advertised model route passes a real coding fixture with tool use,
   second turn and resume, plus deterministic stream/error/continuation tests.
   Unsupported capabilities are refused or accurately shown as unavailable.
3. App-server admission, reconnect and restart semantics are implemented and
   tested, including the separately owned #416 work before claiming those
   guarantees. UI responsiveness cannot substitute for durable recovery.
4. The supported OS matrix passes native install, terminal cleanup, permissions
   and rollback. A macOS-only delivery does not certify Windows or Linux.
5. Repeated representative tasks and injected failures show bounded resources,
   no lost committed work, and no duplicate uncertain tool effects. Measure
   completion quality, crash rate and latency against the stable baseline on
   the same fixtures; define acceptable thresholds before comparing results.
6. The candidate has independent code/evidence review, clear known limitations,
   and a tested rollback path. Release only the envelope actually verified.

No finite suite proves all possible edge cases or zero future bugs. Stateful
property tests, fuzzing parsers and crash-boundary fault injection extend the
matrix; production failures become new minimized regressions.

## External implementations

Reuse a mature dependency only after checking its fit, maintenance, license and
test coverage. Keep required dependency notices. If the project decision is to
avoid copying third-party source, use documented protocols and observable
behavior to implement independently. Reusing a module does not transfer another
product's correctness proof to Iteron's app-server, storage or permission wiring.
