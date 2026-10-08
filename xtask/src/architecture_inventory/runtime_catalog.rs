//! Maintained responsibility specifications for the coding runtime owners.
use super::Surface;

pub(super) const SURFACES: &[Surface] = &[
    Surface {
        path: "crates/cli/src/runtime/context_injection.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain historical or live stable prefix materialization until the actual context publication receipt",
            "read live world only through the existing bounded ContextPort and immutable frozen strategies",
        ],
        next_seams: &[
            "same-candidate native replay, poison and integration evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/context_injection_gate.rs",
        boundary: "cli-host",
        responsibilities: &[
            "consume existing context and optional memory hook gates through the real hook execution owner",
        ],
        next_seams: &[
            "same-candidate native replay, poison and integration evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/context_injection_journal.rs",
        boundary: "cli-host",
        responsibilities: &[
            "publish actual context and frozen policy decisions through the sole transcript writer",
        ],
        next_seams: &[
            "same-candidate native replay, poison and integration evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_run_coordinator.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain finite pending external IO, hedge, kernel and completion handoffs with consumed private phases",
            "delegate actual transcript, tickets and paid obligations to the sole coding driver",
        ],
        next_seams: &["same-candidate compiler, native and real client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_run_composition.rs",
        boundary: "cli-host",
        responsibilities: &[
            "capture actual current immutable scope and concrete IO ports for each pending handoff",
        ],
        next_seams: &["same-candidate compiler, native and real client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_response_phase.rs",
        boundary: "cli-host",
        responsibilities: &[
            "own actual post-provider phase clock, projection allowance and settled tool message",
        ],
        next_seams: &["same-candidate compiler, native and real client evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/persistent_native_generations.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain bounded immutable actual native provider generations and exact resident bindings",
            "quarantine failed refresh and reconstruct only from held routes plus exact verified publication",
        ],
        next_seams: &[
            "same-candidate model switch, resident and native restart evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/workflow_spawner/native_policy_source.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain original validated source policy independently of current operator model selection",
        ],
        next_seams: &[
            "same-candidate model switch, resident and native restart evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_execution_journal.rs",
        boundary: "cli-host",
        responsibilities: &[
            "sequentially reborrow the sole actual invocation WAL, effects, ledger and terminal owners",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_provider_session.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain actual admitted provider obligation and resident native route slots through physical pump",
            "return hedged dispatch as typed suspension after journal borrows end",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_request_session.rs",
        boundary: "cli-host",
        responsibilities: &[
            "run actual request gate, hook and ordered control polling before media and native projection",
            "retain exact request source until admitted transcript and recovery handoff",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_image_admission.rs",
        boundary: "cli-host",
        responsibilities: &[
            "admit confirmed tool image receipts against actual route and pinned aggregate decoder budget",
        ],
        next_seams: &["same-candidate compiler and native integrated evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/turn_advance.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain a prepared turn transition only after real tool and MCP private-content cleanup",
            "commit actual policy terminal before retiring evidence and advancing the checked sequence",
        ],
        next_seams: &[
            "same-candidate cleanup, record refusal and integrated loop evidence remain required",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_request_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "retain actual working transcript, recovery and admission state across fallible host work",
            "consume a single native request projection while preserving its original source",
        ],
        next_seams: &["same-candidate compiler, refusal and cancellation evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/invocation_admission.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual invocation recovery, policy, control, media, memory reset and deadline lifetime",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/invocation_funding.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual write-ahead monetary policy and signed physical charge recovery before installation",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/invocation_cleanup.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual private tool and MCP output stores settle before parent terminal",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/persistent_writer_settlement.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual resident writer discard, merge, and durable workspace witness settlement",
        ],
        next_seams: &["same-candidate executed and native evidence remain required"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_execution_scope.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual per-round governor, queue, gate and cancellation resources",
            "physical pump and settled terminal/governor/permit ordering",
        ],
        next_seams: &["route selection and monetary journals remain distinct owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_followup.rs",
        boundary: "cli-host",
        responsibilities: &["settled physical retry waits, bounded refusal and fallback proposals"],
        next_seams: &[
            "replacement proposals require independent durable selection and physical admission",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_response.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single declaration-ordered result/error/image working set",
            "complete slot and identity check before transcript/recovery publication",
        ],
        next_seams: &["actual executors retain their independent physical effect truth"],
    },
    Surface {
        path: "crates/cli/src/runtime/session_transcript.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private restored and resident working transcript state",
            "actual durable input receipt before consuming restored projection",
        ],
        next_seams: &[
            "cold adoption requires independently verified replay; no new retry key behavior",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_usage_reservation.rs",
        boundary: "cli-host",
        responsibilities: &["checked native mutually exclusive usage-partition monetary ceiling"],
        next_seams: &[
            "physical route bounds and shared price book supply authority, not prompt estimates",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/persistent_agents/prepared_mailbox.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private exact host-rendered commitments to native full user-text inclusion",
            "same mailbox durable Consumed after retained prepared manifest before transport",
        ],
        next_seams: &[
            "prepared inclusion does not attest remote processing or successful transport",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_dispatch.rs",
        boundary: "cli-host",
        responsibilities: &[
            "consumed concrete physical admission journal and authenticated dispatch scope",
            "actual intent, logical start and mailbox barriers before transport",
        ],
        next_seams: &["transport, route selection and monetary state retain independent owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/model_response.rs",
        boundary: "cli-host",
        responsibilities: &[
            "no-tool stop reason and existing invocation recovery decision",
            "bounded continuation, candidate, terminal or typed refusal without execution authority",
        ],
        next_seams: &[
            "actual answer publication and explicit operator verification remain host ports",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/approval_wait.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual approval wait over the single resident inbox without moving its receiver",
            "deadline/control observations and physical policy verdict journal",
        ],
        next_seams: &["remembered policy changes remain a separate write-ahead transaction"],
    },
    Surface {
        path: "crates/cli/src/runtime/control_terminal.rs",
        boundary: "cli-host",
        responsibilities: &[
            "requested control settlement and actual retained process cleanup receipt",
            "confirmed terminal before cooperative control reset",
        ],
        next_seams: &["unknown or failed recording never becomes a successful cleanup claim"],
    },
    Surface {
        path: "crates/cli/src/runtime/run_finalization.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual run finalization through physical terminal and bounded publication ports",
            "single confirmed terminal receipt with downstream controller settlement",
        ],
        next_seams: &[
            "physical cleanup proof remains with its owner; presentation loss cannot reverse terminal",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/ordinary_extensions.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single optional ordinary SDK host and same-owner read-only event/status ports",
            "native metadata route resolution without provider invocation or selection authority",
        ],
        next_seams: &[
            "public API and TUI read the same host instance; observer capacity remains bounded",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/request_preparation.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual undispatched request and bounded compaction candidate",
            "candidate installs only after matching committed transcript receipt",
        ],
        next_seams: &["host retains physical summary IO, real hook gates and control safe points"],
    },
    Surface {
        path: "crates/cli/src/runtime/request_accounting.rs",
        boundary: "cli-host",
        responsibilities: &[
            "source-separated context accounting over immutable admitted evidence",
            "calibration and component budget projection",
        ],
        next_seams: &["physical provider usage remains owned by the calibration journal"],
    },
    Surface {
        path: "crates/cli/src/runtime/optional_tool_round.rs",
        boundary: "cli-host",
        responsibilities: &[
            "optional proposal classification, candidate path and completed-result state for one round",
            "ticket-only localization and typed repair receipt projection; existing explicit verifier observes changed paths",
        ],
        next_seams: &[
            "ordinary coding returns no tracker before registry/path scans; no tool admission or completion gate",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime.rs",
        boundary: "cli-host",
        responsibilities: &[
            "turn admission and ordered control",
            "provider/tool orchestration and accounting",
            "operation authorization and effect dispatch",
            "context packing and compaction",
            "verification and ticket policy adaptation",
        ],
        next_seams: &[
            "turn state owner and typed command handler",
            "provider/tool supervisors with narrow receipts",
            "default-off ticket strategy adapter",
            "independent candidate workspace baseline",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/frontend_events.rs",
        boundary: "cli-host",
        responsibilities: &["immutable frontend event/control-resolution contract"],
        next_seams: &["never treat presentation values as execution authority"],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_presentation.rs",
        boundary: "cli-host",
        responsibilities: &["pure bounded tool/UI output and approval evidence projection"],
        next_seams: &["canonical raw output belongs to publication/spill owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_progress.rs",
        boundary: "cli-host",
        responsibilities: &["single output/thinking counter and coalesced emission owner"],
        next_seams: &["immutable stream timing evidence"],
    },
    Surface {
        path: "crates/cli/src/runtime/deferred_batch_executor.rs",
        boundary: "cli-host",
        responsibilities: &[
            "already-admitted physical tool futures and governor permits",
            "cancellation, structural correlation and ordered execution receipts",
            "raw publication before spill/model projection",
        ],
        next_seams: &["WAL admission/settlement stay with the journal owner"],
    },
    Surface {
        path: "crates/cli/src/runtime/early_tool_gate.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bounded operator-configured hook predispatch coordinator",
            "immutable gate context and typed summary/refusal",
        ],
        next_seams: &["hook journal and kernel effect admission remain independent owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/kernel_effect_bridge.rs",
        boundary: "cli-host",
        responsibilities: &[
            "typed non-registry effect descriptor and single kernel broker adapter",
            "bounded terminal/workspace evidence projection",
        ],
        next_seams: &["disjoint journal/admission ports; no executor receives mutable Agent"],
    },
    Surface {
        path: "crates/cli/src/runtime/session_control.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single cooperative control latches and inherited signal owner",
            "actual predispatch refusal and bounded retry-wait observations",
        ],
        next_seams: &[
            "only actual terminal composition clears controls; no journal/provider authority",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/session_inbox.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single SQ receiver, product epoch and bounded pending-steer owner",
            "FIFO ingress observations, stale identities and exact reclaim evidence",
        ],
        next_seams: &[
            "durable message/control projection remains a distinct physical journal port",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/submitted_turn_state.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single submission recovery receipt/error/continuation owner",
            "encoded receipt identity/count/byte bounds and immutable first receipts",
        ],
        next_seams: &["private state; typed context/recovery mutations only"],
    },
    Surface {
        path: "crates/cli/src/runtime/request_context_evidence.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single bounded materialized/recorded source evidence state",
            "exact prepared request commitments and token/classification construction",
        ],
        next_seams: &[
            "per-material locator versions and durable physical request manifest evidence remain pending",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_stream_attempt.rs",
        boundary: "cli-host",
        responsibilities: &["actual physical provider stream pump and quota receipt"],
        next_seams: &[
            "concrete observation/tool admission ports; no mutable Agent or financial authority",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_transport_attempt.rs",
        boundary: "cli-host",
        responsibilities: &["actual admitted transport controls, cancellation and deadline"],
        next_seams: &["retries, durable intent and financial accounting remain separate owners"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_output_request.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual adapter-attested physical request output bound",
            "policy requested tokens distinct from serialized cap; hard unknown refusal",
        ],
        next_seams: &["immutable provider proof port only; no budget or route selection mutation"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_charge_evidence.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single exact physical charge ledger and signed receipt/replay evidence",
        ],
        next_seams: &["read-only proof validation; mutation remains in the shared monetary owner"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_financial_context.rs",
        boundary: "cli-host",
        responsibilities: &[
            "immutable authenticated route pricing/scope and actual USD/cohort admission/settlement ports",
        ],
        next_seams: &[
            "physical WAL must settle before controller finance; no Agent/session proxy or new budget state",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_attempt_journal.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual provider physical intent/terminal and downstream financial CAS adapter",
        ],
        next_seams: &[
            "single effect owner and physical writer; terminal always precedes finance, no executor authority",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_attempt_pump.rs",
        boundary: "cli-host",
        responsibilities: &["single observed physical attempt stream-to-terminal phase owner"],
        next_seams: &[
            "native stream/tool owner ports then physical terminal/controller/PlantCore/USD order; inclusion observer between phases",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_route_admission.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual same-governor permit queue, cancellation and physical quota/circuit observation",
        ],
        next_seams: &[
            "single ProviderGovernor Arc state; real leases/queue activity, no second snapshot or provider execution",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_route_journal.rs",
        boundary: "cli-host",
        responsibilities: &["closed quota/circuit Notice durable projection adapter"],
        next_seams: &[
            "same Rollout/measurement/record fault ports; no model selection, intent or terminal authority",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_selection.rs",
        boundary: "cli-host",
        responsibilities: &[
            "sole executable selection epoch, exact provider binding and authenticated pricing card",
        ],
        next_seams: &[
            "durable barrier before live swap; opaque unpriced verified adoption; public proposals checked against private binding",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_selection_journal.rs",
        boundary: "cli-host",
        responsibilities: &["closed ModelSelected and RateCardBound durable writer"],
        next_seams: &[
            "same Rollout, fault, latency and diagnostic ports; no provider dispatch or policy grant",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_route_turn.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single actual request/route/retry/ticket/permit/physical identity owner",
            "typed next step from real settled attempts and normalized fallback geometry",
        ],
        next_seams: &[
            "actual journal, signed finance and durable route selection remain separate authorities",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_route_events.rs",
        boundary: "cli-host",
        responsibilities: &[
            "concrete immutable lifecycle/activity projection and actual bounded retry wait",
            "completed wait ledger evidence; cancellation never reports completed retry",
        ],
        next_seams: &[
            "read-only controls plus actual Ledger; no request admission or route permission",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_turn_evidence.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single transport/semantic/timing/quota observation owner",
            "bounded interrupted text/thinking prefix retention",
        ],
        next_seams: &["physical provider dispatch and monetary admission remain independent"],
    },
    Surface {
        path: "crates/cli/src/runtime/early_tool_executor.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual streamed tool task, lock queue and governor permit owner",
            "hook/cancellation/raw-publication/spill terminal execution receipts",
        ],
        next_seams: &["admission/journal ownership remains disjoint; no mutable Agent"],
    },
    Surface {
        path: "crates/cli/src/runtime/terminal_record.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single mutable turn cost/counter/verifier terminal evidence owner",
            "physical policy-terminal and visible Idle/Done durable append adapters",
        ],
        next_seams: &["typed disjoint recorder/rollout/ledger ports; no mutable Agent"],
    },
    Surface {
        path: "crates/cli/src/runtime/turn_publication.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual non-tool EndTurn answer Message join and confirmed Done sequence projection",
            "single retained verified publication projection with incremental receipts and no IO on read",
        ],
        next_seams: &["readonly frontend facts; no terminal or ancestor scope inference"],
    },
    Surface {
        path: "crates/cli/src/runtime/workspace_checkpoint.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single confirmed workspace checkpoint and cadence state",
            "actual scoped snapshot intent/event/terminal ordering through concrete journal ports",
        ],
        next_seams: &["failed snapshot publication retains previous confirmed rollback point"],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_round.rs",
        boundary: "cli-host",
        responsibilities: &[
            "one model round's actual stream/declaration/physical pump lifetime and settlement-dependent route phase owner",
        ],
        next_seams: &[
            "temporary typed stream/WAL/finance/route ports; pending terminal blocks redispatch; exact completed tool projection; native inclusion remains between run and settlement",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/provider_stream_observer.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual provider-item activity/frontend/lifecycle observation owner",
            "metadata-versus-semantic attribution and owned stream phase settlement",
        ],
        next_seams: &[
            "tool WAL and physical provider dispatch/budget remain directional independent owners",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_turn.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single mutable tool declaration/identity/failure/routing owner",
            "owned early tasks and ordered deferred/recovery stage transfer",
        ],
        next_seams: &[
            "policy draft is not admission; actual WAL and settlement stay concrete directional ports",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/effect_journal_owner.rs",
        boundary: "cli-host",
        responsibilities: &[
            "single mutable admission/unknown/recovery/workspace-effect owner",
            "actual open/settle/broker and once-per-adoption canonical WAL recovery",
            "bounded pending/unknown/barrier observation distinct from admission-blocking policy",
        ],
        next_seams: &[
            "disjoint physical Rollout/Ledger ports; provider monetary admission stays independent",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/effect_descriptor.rs",
        boundary: "cli-host",
        responsibilities: &["pure typed effect identity/audit/terminal projections"],
        next_seams: &["no mutable state or execution/writer port"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_tool_admission.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual structural/policy/operation/hook/tool streamed admission coordinator",
            "durable source receipt before captured executor/task retention",
        ],
        next_seams: &["disjoint actual owners and immutable trusted scopes; no mutable Agent"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_tool_journal.rs",
        boundary: "cli-host",
        responsibilities: &["physical policy decision/hook/tool/ToolReady durable admission ports"],
        next_seams: &["concrete borrowed recorder/journal/ledger owners; no execution authority"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_tool_events.rs",
        boundary: "cli-host",
        responsibilities: &["immutable shared tool frontend/lifecycle/process/projection evidence"],
        next_seams: &["observations neither execute processes nor grant operation authority"],
    },
    Surface {
        path: "crates/cli/src/runtime/stream_tools.rs",
        boundary: "cli-host",
        responsibilities: &[
            "pure operation-specific overlap eligibility and actual cancellation snapshot",
        ],
        next_seams: &["pure reads cannot bypass explicit deny/request or admitted ceilings"],
    },
    Surface {
        path: "crates/cli/src/runtime/deferred_tools.rs",
        boundary: "cli-host",
        responsibilities: &["pure auto/authority/repeat/conflict leading-batch selection"],
        next_seams: &["frozen actual registry/operator ceilings; no approval or effect writer"],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_execution_journal.rs",
        boundary: "cli-host",
        responsibilities: &[
            "physical registry intent/known terminal/refused terminal append and ledger ports",
        ],
        next_seams: &[
            "single EffectJournalOwner remains authoritative; no provider or execution access",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/early_tool_collection.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual streamed task join/abort/reap and hook/tool ordered settlement",
            "managed result/spill lifetime until actual post observers settle",
        ],
        next_seams: &[
            "frozen deadline/projection observations and concrete tool journal/hook ports",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/ordered_tool_call.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual ordered registry intent, captured execution future, physical terminal, spill and post observer lifetime owner",
        ],
        next_seams: &[
            "disjoint journal plus frozen registry/cancel/publication/hook/event ports; no permission or provider authority; Unknown settles before control return",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/deferred_tool_batch.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual admitted batch intent/executor/ordered terminal/post-hook coordinator",
            "single ownership of physical pending tickets and managed result lifetimes",
        ],
        next_seams: &[
            "disjoint journal/cache/executor/hook and frozen publication/projection ports",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/hook_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual configured hook dispatch, universal ticket retention and settlement",
            "bounded concurrent pre-tool decisions and post-tool observer reports",
        ],
        next_seams: &[
            "concrete hook/journal/ledger ports; denied calls return to the tool result owner",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_run_driver.rs",
        boundary: "cli-host",
        responsibilities: &[
            "private working transcript and current submitted-turn/request/response/tool phases",
            "retained physical provider obligation and exact pending kernel tool lease",
        ],
        next_seams: &[
            "final coding coordinator and invocation admission/completion integration still in progress",
        ],
    },
    Surface {
        path: "crates/cli/src/runtime/coding_provider_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "physical provider driver and USD obligation lifetime",
            "bounded native hedge and completion handoff",
        ],
        next_seams: &["same-candidate native stream/cancellation/usage evidence remains pending"],
    },
    Surface {
        path: "crates/cli/src/runtime/kernel_special_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "exact Plan/direct-child/Workflow special declaration execution",
            "known outer tool terminal before independent accounting observation",
        ],
        next_seams: &["storage uncertainty and accounting unavailability remain separate facts"],
    },
    Surface {
        path: "crates/cli/src/runtime/kernel_child_accounting.rs",
        boundary: "cli-host",
        responsibilities: &[
            "real owned native ledger or controller receipt observation",
            "exact pending/resolved WAL pair for finite budget admission",
        ],
        next_seams: &["same-candidate restart/fault/child attribution evidence remains pending"],
    },
    Surface {
        path: "crates/cli/src/runtime/direct_child_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual native or controller direct investigation",
            "known child cleanup and physical terminal before returning accounting source",
        ],
        next_seams: &["current-parent native route binding and cleanup proof remain under review"],
    },
    Surface {
        path: "crates/cli/src/runtime/workflow_execution.rs",
        boundary: "cli-host",
        responsibilities: &[
            "actual bounded native/controller workflow invocation",
            "physical cleanup proof separate from subsequent ledger observation",
        ],
        next_seams: &["held script reads and native writer cleanup source remain in progress"],
    },
    Surface {
        path: "crates/cli/src/runtime/workflow_preparation.rs",
        boundary: "cli-host",
        responsibilities: &[
            "bounded workflow specification and actual child source composition",
            "writer-first parent turn/token allocations and inherited absolute deadline",
        ],
        next_seams: &["held script capability/FIFO source fix remains in progress"],
    },
    Surface {
        path: "crates/cli/src/runtime/tool_image_projection.rs",
        boundary: "cli-host",
        responsibilities: &[
            "post-terminal raw captured pixel retention",
            "authenticated private artifact and model observation projection",
        ],
        next_seams: &["missing vision retains all raw pixels without inventing model observations"],
    },
];
