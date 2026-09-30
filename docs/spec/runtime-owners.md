# Runtime owner and port map

This map describes the maintained source boundaries. An immutable event or receipt conveys
observation; it does not grant permission or acquire mutable ownership of another domain.

| Source | Owner/responsibility | Directional interface |
| --- | --- | --- |
| `runtime.rs` / `Agent` | Session composition and current journal/provider turn coordinator | Owns durable admission/settlement; calls execution and projection ports |
| `runtime/tool_turn.rs` | Single mutable tool declaration/routing/failure/task-retention owner | Validated declaration → typed index and immutable policy draft; owned early/deferred/replayed work released once to physical settlement phase |
| `runtime/stream_tool_admission.rs` | Actual streamed declaration admission coordinator | ToolTurnOwner plus concrete policy/journal/ledger ports and frozen trusted scope → durable policy/hook/tool/source receipts before an owned captured executor task |
| `runtime/stream_tool_journal.rs` | Physical streamed decision, intent and source barriers | Actual PolicyEvidenceRecorder/EffectJournalOwner/Rollout/Ledger borrows; no execution or permission-grant port |
| `runtime/stream_tools.rs` | Pure operation-specific overlap eligibility | Registered operation effects plus real immutable operator/task/manifest ceilings and cancellation/deadline observations → optional early capability; read deny cannot bypass through Pure metadata |
| `runtime/stream_tool_events.rs` | Immutable shared tool frontend/lifecycle projection | Actual shared bounded frontend/emitter ports; observes declaration/admission/terminal/process/projection evidence, preserves queue saturation lifecycle and never creates a process |
| `runtime/early_tool_executor.rs` | Physical streamed task, fair execution lock and governor permit owner | Already-admitted call plus immutable execution/hook/cancellation/publication scope → owned task and actual receipt; drop revokes task without claiming physical effect truth |
| `runtime/deferred_tool_batch.rs` | Actual admitted batch coordinator and ticket/result lifetime owner | Concrete journal/ledger/cache + frozen registry/hook/cancel/publication/projection ports; all intents before execution, physical settlement before publication status, all post observers before ToolEnd |
| `runtime/deferred_batch_executor.rs` | Physical futures, governor permits and cancellation scope for an already-admitted batch | Accepts `ToolIntent`, immutable registry/governor/cancellation ports; returns declaration-ordered `DeferredToolReceipt` |
| `runtime/artifact_publication.rs` | Trusted full-output publication adapter | `ToolOutputPublicationPort` receives repaired raw `ToolResult` and actual effect-known flag before spill/truncation |
| `runtime/tool_output_spill.rs` | Private raw overflow leases and bounded model-visible projection | Managed results retain explicit spill ownership; cleanup follows actual settlement |
| `runtime/tool_presentation.rs` | Pure bounded/redacted UI and approval-evidence projection | Immutable `ToolUse`/`ToolResult` → frontend values; no journal/process state |
| `runtime/stream_progress.rs` | Sole output/thinking counters and emission cadence | Observes stream deltas, emits bounded latest progress through `try_send` |
| `runtime/hook_execution.rs` | Actual configured hook dispatch and ticket settlement coordinator | Concrete Hooks/command journal/cancellation/activity plus EffectJournalOwner/Rollout/Ledger ports; pretool denials return typed calls for durable ToolDone, actual tools are terminal before post observers start |
| `runtime/early_tool_gate.rs` | Bounded operator-configured hook predispatch coordinator | Immutable gate context → typed complete-allow summary or refusal; no provider/Agent borrow |
| `runtime/kernel_effect_bridge.rs` | Single non-registry kernel broker adapter | Typed descriptor plus disjoint journal/admission ports → observed/unknown outcome; executor never gets mutable Agent |
| `runtime/effect_descriptor.rs` | Pure effect identity, audit and terminal vocabulary | Immutable typed descriptor → bounded scrubbed audit values; no owner/writer/executor dependency |
| `runtime/effect_journal_owner.rs` | Single actual effect identity, unknown, recovery and workspace mutation owner | Disjoint Rollout/Ledger ports → durable open/settle/broker receipts; canonical WAL folded once per adoption; bounded parent settlement observation distinguishes unknown physical effects from operator admission policy |
| `runtime/submitted_turn_state.rs` | Single invocation-local error/recovery/continuation owner | Private counters and immutable recovered receipts; typed context/candidate continuation mutations, no Agent/provider/journal access |
| `runtime/provider_stream_observer.rs` | Actual stream item presentation and activity span owner | Frozen frontend/lifecycle/activity ports plus StreamItem → typed tool/quota/notice disposition; never provider dispatch, journal admission or budget authority |
| `runtime/request_context_evidence.rs` | Single bounded materialized/recorded context source state and request evidence builder | Immutable actual effective system/messages/tools/images and estimator scope → content-free ledger; precise length-framed schema commitments, governing trust floor, explicit dropped source evidence |
| `runtime/provider_turn_evidence.rs` | Single logical provider-turn observation owner | Header/semantic token evidence, timing, quota and bounded text/thinking prefixes; no dispatch or budget authority |
| `runtime/terminal_record.rs` | Single mutable turn cost/counter/verifier evidence owner and durable terminal adapter | Actual recorder/rollout/ledger ports → policy terminal and one-barrier Idle/Done receipt; physical append failure never reports success |
| `runtime/turn_publication.rs` | Record-sourced answer and finalization recovery | Actual non-tool EndTurn Message join; confirmed existing Done sequence; verified current-run scope, bounded recent facts and provenance refusal; frontend observers grant no authority |
| `runtime/frontend_events.rs` | Immutable frontend/control-resolution vocabulary | Explicit public type re-exports preserve existing runtime API |
| `runtime/persistent_agents.rs` | Actual resident execution host | Controller command/completion ports; runtime returns physical typed terminal/usage proof |
| `workflow/live_session/registry.rs` | Durable graph admission and retained scheduler instances | Owns registry CAS/reservations; invokes scheduler commands and proof coordinator |
| `workflow/live_session/pump.rs` | Stateless bounded graph/controller coordinator | Exact persisted task/epoch/terminal evidence → scheduler settlement |
| `workflow/live_session/store.rs` | Private registry filesystem/CAS adapter | Pinned namespace → bounded byte publication; no mutable agent state |
| `crates/workflow/src/live_scheduler/owner.rs` | Sole graph/revision/attempt owner | Directional controller and journal ports |
| `crates/agents/src/controller.rs` | Sole durable identity/mailbox/epoch owner | Domain commands and immutable views; no scheduler/provider dependency |

```mermaid
flowchart LR
    Journal[Journal admission owner] -->|already admitted ToolIntent| Batch[DeferredBatchExecutor]
    Batch -->|retain permits and cancellation scope| Registry[Registry execution]
    Registry -->|actual raw terminal| Batch
    Batch -->|repaired full result| Publisher[ToolOutputPublicationPort]
    Batch -->|raw execution| Spill[Overflow/projection owner]
    Batch -->|ordered receipt plus publication status| Journal
    Journal -->|physical settlement first| Record[Durable journal]
    Journal -->|bounded immutable projection| UI[Frontend events]
```

A batch opens every effect intent before dispatch. Its physical executor cannot manufacture
admission, mutate the journal or widen the inherited authority. Execution results repair the
structural tool-use ID before publication. Full-output publication precedes spill/model-visible
truncation. Publication failure travels separately from physical effect truth; the caller settles
known execution first, then reports unavailable retention. It must not turn a failed artifact write
into an unknown tool execution or automatically replay the tool.

These modules are independent owners/adapters with explicit imports, not `Agent` implementation
text fragments. Their size/import guards and source inventory run through the maintained xtask.
The remaining `Agent` field aggregate and provider/ordered effect coordinator are unfinished
architecture work; these extractions alone do not close the giant-runtime requirement. Final
acceptance needs the integrated default/optional profiles and actual concurrent tool, cancellation,
raw-artifact, frontend and restart journeys.
