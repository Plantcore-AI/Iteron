//! The App Server: the runtime lives here, reachable only through a versioned SQ/EQ wire.
//!
//! # What this replaces
//!
//! The interactive frontend used to *co-compose the runtime*. It held the kernel [`Agent`] in an
//! `Option<Agent>`, moved it into a `tokio::spawn` for each turn, and got it back through the
//! `JoinHandle` — so "is a run in flight" was encoded as "is the slot empty", and every
//! configuration path (`/model`, `/effort`, `/mode`, `/compact`) was reachable only because the
//! borrow checker made it so. Task start and follow-up never touched the submission queue at all;
//! only `Interrupt`, `ApprovalResponse`, `Drain` and `Steer` did. A frontend that starts work by
//! moving the runtime into a task it owns is not a client of a server.
//!
//! Here the runtime is resident. One long-lived task owns the `Agent`, drains the SQ, and publishes
//! the EQ. The frontend holds queue endpoints and a negotiated protocol version, nothing else.
//!
//! # Why the EQ does not carry `iteron_protocol::Event`
//!
//! This is the one design decision in this module that is not obvious, so it is recorded rather
//! than left to be rediscovered.
//!
//! `iteron_protocol::EqEnvelope` carries `iteron_protocol::Event`, and translating the kernel's
//! [`UiEvent`] into `EventKind` is **lossy in four places the frontend actually renders**:
//!
//! - `UiEvent::TurnEnd` carries seven fields; `EventKind::TurnEnd` carries one (`usage`). The cost
//!   state, context estimate, model window, reserved output tokens, compaction trigger and effort
//!   application have no durable counterpart — and the status bar renders all of them.
//! - `UiEvent::SteerApplied { count }` has no `EventKind` counterpart at all.
//! - `UiEvent::ToolEnd.diff` has no `EventKind` home; the durable record is deliberately terse.
//! - `UiEvent::ApprovalRequest.reason` — the operator-facing justification — has no field to go in.
//!
//! Closing those would mean adding variants and fields to `iteron_protocol`, and this issue's
//! acceptance criteria forbid changing the frozen wire types: WS1 owns them, this lane only
//! consumes them. Carrying `UiEvent` in a versioned envelope of our own satisfies both — the wire
//! is version-negotiated in both directions, and no frozen type moves.
//!
//! The SQ carries the unchanged `iteron_protocol::SqEnvelope` inside a host-only
//! `TurnSubmission` with the optional Product V1 turn epoch, because `Op` expresses
//! everything the frontend submits.
//!
//! # Backpressure
//!
//! Both queues are bounded. The policies are deliberately asymmetric, because the two directions
//! fail differently:
//!
//! - **SQ**: submissions never block the UI thread. A full queue returns
//!   [`SubmitError::Busy`] so the frontend can tell the operator their keystroke did not land,
//!   rather than freezing the render loop behind an unbounded queue that grows until the process
//!   dies.
//! - **EQ**: a slow reader must never cost the operator the *authoritative* answer. Streamed text
//!   and thinking are coalesced cumulatively under pressure, with both event and byte ceilings;
//!   reaching the side-buffer ceiling applies backpressure rather than losing bytes. Everything
//!   else, and `Done` above all, is delivered even if that means waiting for the reader.

/// Content-free activity snapshots are independently bounded before they reach the EQ. A stalled
/// frontend may delay a status tick, but can never let runtime activity telemetry grow without a
/// ceiling or block the runtime's work path.
const ACTIVITY_CHANNEL_CAPACITY: usize = 256;
const KERNEL_INBOUND_CAPACITY: usize = 64;
const RUNTIME_UI_CAPACITY: usize = 256;
const WORKFLOW_PROGRESS_CAPACITY: usize = 256;
const WORKFLOW_SETTLED_CAPACITY: usize = 64;

mod activity_control;
mod ordinary_extensions;
mod plugin_control;
mod session_factory;
mod session_host;
mod workspace_rewind_control;
pub(crate) use session_host::AppServer;

mod submission_settlement;
use submission_settlement::{
    discard_expired_product_steers, expire_pending_turns, expire_queued_after_drain,
    forward_runtime_notifications, product_turn_accepts, publish_submission, queue_population,
    receive_next_submission, reject_replayed_submission, settle_kernel_submission_events,
    settle_kernel_submissions_at_turn_end,
};
mod lifecycle_control;
use lifecycle_control::{
    HookExecution, legacy_user_prompt_context, run_legacy_hook, run_lifecycle_gate,
};
mod workflow_projection;
use workflow_projection::{publish_settled, publish_workflow_progress};

pub(crate) use crate::model_route::HostModelSelection as ModelSelection;
mod messages;
use messages::event_heap_bytes;
pub(crate) use messages::{
    AdoptRun, Control, ControlReply, ControlRequest, EventEnvelope, EventEnvelopeError, JobControl,
    McpControl, McpControlReply, MemoryControl, MemoryControlReply, NavigatedSession,
    ProviderCatalogControl, ServerEvent, SessionSnapshot, SideRequest, TerminalAuthority,
    TerminalSummary, WorkflowControl, WorkflowControlReply, WorkspaceRewound,
};
mod text_spill;
mod turn_pump;
use text_spill::AssistantTextSpill;
mod queue_client;
pub(crate) use queue_client::{AppServerClient, QueuedSubmission, SubmitError};
use queue_client::{
    KernelSubmissionKind, PendingKernelSubmission, SubmissionDeduplicator,
    SubmissionIdentityAdmission, kernel_submission_kind,
};
#[cfg(test)]
use queue_client::{SubmissionSender, submission_weight};
mod client_bootstrap;
pub(crate) use client_bootstrap::{ClientBootstrapFactory, PromptHistoryWriterPort};
mod session_attachment;
mod session_hooks;
mod session_services;
#[cfg(feature = "legacy-plantcore")]
pub(crate) use session_attachment::attach_plantcore;
pub(crate) use session_attachment::{AppServerHandle, Attached, SessionFacts, ToolFact, attach};
mod event_publisher;
pub(crate) use event_publisher::EventPublisher;

mod queue_wiring;
#[cfg(test)]
pub(crate) use queue_wiring::wire;
use queue_wiring::wire_with_queue_policy;
pub(crate) use queue_wiring::{ServerEnds, advertised_version};

mod advisory_maintenance;
mod agent_control;
mod client_artifacts;
mod runtime_ingress;
mod turn_publication;
use runtime_ingress::publish_runtime_event;
mod control;
mod inventory_control;
mod live_workflow_control;
mod mcp_control;
mod mcp_input;
mod model_control;
mod operator_status;
#[cfg(feature = "legacy-plantcore")]
mod plantcore;
#[cfg(not(feature = "legacy-plantcore"))]
#[path = "app_server/plantcore_disabled.rs"]
mod plantcore;
mod product_contract;
#[cfg(feature = "legacy-plantcore")]
mod recording_fault;
#[cfg(not(feature = "legacy-plantcore"))]
#[path = "app_server/recording_fault_disabled.rs"]
mod recording_fault;
mod thread_inspection;
mod thread_lifecycle;
pub(crate) mod thread_presentation;

pub(crate) use crate::queue_policy::{
    AuthoritativeOverflow, CosmeticOverflow, FrontendQueuePolicy as AppServerQueuePolicy,
};

use self::control::{
    apply_control, apply_immediate_control, is_immediate_control, is_plantcore_admitted_control,
    snapshot_of,
};
#[cfg(test)]
use self::control::{apply_immediate_workflow_control, apply_side};
use self::mcp_control::apply_mcp_control;
#[cfg(test)]
pub(crate) use self::mcp_input::McpInputField;
pub(crate) use self::mcp_input::capacity as mcp_input_capacity;
pub(crate) use self::mcp_input::{McpInputAnswer, McpInputPrompt, McpInputResponse};
use self::operator_status::OperatorStatusSources;
pub(crate) use self::operator_status::{
    LanguageServerStatus, OperatorStatusSnapshot, WorkflowHealth,
};
use self::plantcore::PlantcoreAdmission;
pub(crate) use self::recording_fault::RecordingAppServerFault;
use crate::runtime::{Agent, TurnSubmission, UiEvent};
use iteron_protocol::{
    Capability, ContentSegments, LifecyclePayload, LifecycleState, Op, Outcome, PROTOCOL_VERSION,
    ProtocolVersionError, RunId, RunLifecycleState, SessionId, SessionLifecycleState, SubmissionId,
    SubmissionLifecycleState, TurnId, TurnLifecycleState,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// One bounded binding shared by frontend/client emitters and the server-side publisher. The
/// dispatcher itself owns the bounded hook queue; this slot only makes its single handle visible
/// after the session has installed hooks.
type LifecycleHookRoute =
    Arc<std::sync::Mutex<Option<crate::runtime::lifecycle_hooks::LifecycleHookDispatcher>>>;

fn bound_lifecycle_hook(
    route: &LifecycleHookRoute,
) -> Option<crate::runtime::lifecycle_hooks::LifecycleHookDispatcher> {
    route
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn dispatch_lifecycle_hook(
    route: &LifecycleHookRoute,
    event: iteron_protocol::LifecycleEventEnvelope,
) {
    // Never hold the route lock while enqueueing. Dispatch is non-blocking, but keeping the two
    // synchronization domains separate also makes bind/unbind independent of hook queue pressure.
    if let Some(dispatcher) = bound_lifecycle_hook(route) {
        dispatcher.dispatch(event);
    }
}

use crate::queue_policy::{SQ_BYTE_CAPACITY, SQ_ENTRY_OVERHEAD_BYTES, sq_control_reserve_bytes};
#[cfg(test)]
use crate::queue_policy::{SQ_CAPACITY, SQ_CONTROL_RESERVE_BYTES, SQ_PRIORITY_CAPACITY};
#[cfg(test)]
const SQ_DATA_CAPACITY: usize = SQ_CAPACITY - SQ_PRIORITY_CAPACITY;

/// Where a submission goes once the server has classified it.
///
/// Split out so the routing is testable without a live `Agent`: the classification is the part that
/// decides whether an operation reaches the kernel at all, and it is the part an unknown `Op` must
/// not slip through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunInput {
    Text(String),
    Content(ContentSegments),
    /// One text prompt plus first-class file references, and optionally images beside them.
    /// Carried untouched from the operation so the kernel, not the router, decides admission.
    Files {
        text: String,
        images: Vec<iteron_protocol::ImageContent>,
        files: Vec<iteron_protocol::FileContent>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Routed {
    /// Start a turn. The server owns "is a run in flight", not the frontend.
    StartTurn(RunInput),
    /// Hand to the kernel's inbound queue: it consumes these at its own safe points.
    ToKernel,
    /// Refuse, and tell the operator why.
    ///
    /// An `Op` this build does not understand degrades here via `#[serde(other)]`. It is never
    /// replayed, never guessed at, and never auto-acted.
    Refuse(&'static str),
}

/// Classify one submission.
pub(crate) fn route(op: &Op) -> Routed {
    match op {
        Op::UserInput { text } => Routed::StartTurn(RunInput::Text(text.clone())),
        Op::UserInputV2 { segments } => Routed::StartTurn(RunInput::Content(segments.clone())),
        Op::UserInputV3 {
            text,
            images,
            files,
        } => Routed::StartTurn(RunInput::Files {
            text: text.clone(),
            images: images.clone(),
            files: files.clone(),
        }),
        Op::Steer { .. }
        | Op::Interrupt
        | Op::ForceCancel
        | Op::Drain
        | Op::ApprovalResponse { .. } => Routed::ToKernel,
        Op::Unknown => Routed::Refuse(
            "the runtime received a submission this build does not understand; it was discarded \
             rather than guessed at. Check that the client and server are the same version.",
        ),
    }
}

/// Settle every persistent tool owner captured from this session's registry.
///
/// Success is intentionally silent. Returned lines are bounded, content-free failure summaries
/// suitable for the terminal shutdown report; process commands and LSP workspace paths never
/// cross this seam.
async fn clean_session_owned_tools(
    processes: Option<&iteron_tools::ProcessControl>,
    language_servers: Option<&iteron_tools::LspControl>,
) -> Vec<String> {
    let mut failures = Vec::with_capacity(2);
    if let Some(processes) = processes
        && let Err(error) = processes.clean().await
    {
        failures.push(if error.unknown {
            "persistent process cleanup outcome is unknown".to_owned()
        } else {
            "persistent process cleanup failed before full reconciliation".to_owned()
        });
    }
    if let Some(language_servers) = language_servers {
        let unconfirmed = language_servers
            .clean()
            .await
            .into_iter()
            .filter(|(_, confirmed)| !confirmed)
            .count();
        if unconfirmed > 0 {
            failures.push(format!(
                "{unconfirmed} language-server cleanup outcome(s) are unknown"
            ));
        }
    }
    failures
}

async fn receive_stop_hook_observation(
    observer: &mut Option<crate::runtime::hooks::StopHookObserverRuntime>,
) -> Option<crate::runtime::hooks::StopHookObservation> {
    match observer {
        Some(observer) => observer.observations.recv().await,
        None => std::future::pending().await,
    }
}

async fn publish_stop_hook_observation(
    events: &mut EventPublisher,
    observation: crate::runtime::hooks::StopHookObservation,
) {
    use crate::runtime::hooks::StopHookTerminal;

    let terminal_event = match observation.terminal {
        StopHookTerminal::Completed => "hook.completed",
        StopHookTerminal::TimedOut => "hook.timed_out",
        StopHookTerminal::Failed | StopHookTerminal::Cancelled => "hook.failed",
    };
    let reason_code = match observation.terminal {
        StopHookTerminal::Completed => "compatibility_stop_completed",
        StopHookTerminal::Failed => "compatibility_stop_failed",
        StopHookTerminal::TimedOut => "stop_terminal_budget",
        StopHookTerminal::Cancelled => "stop_observer_cancelled",
    };
    events.record_lifecycle(
        terminal_event,
        Some(observation.identity.turn),
        None,
        LifecyclePayload {
            count: Some(u64::from(match observation.terminal {
                StopHookTerminal::Completed => observation.report.completed,
                StopHookTerminal::TimedOut => observation.report.timed_out.max(1),
                StopHookTerminal::Failed | StopHookTerminal::Cancelled => {
                    observation.report.failed.max(1)
                }
            })),
            reason_code: Some(reason_code.into()),
            ..LifecyclePayload::default()
        },
    );
    let _ = events
        .publish(ServerEvent::Activity(
            observation
                .identity
                .activity(observation.terminal.activity_state()),
        ))
        .await;
    if observation.terminal != StopHookTerminal::Completed {
        let _ = events
            .publish(ServerEvent::Notice(format!(
                "Stop hook observer {reason_code}; the completed answer and input readiness are unaffected"
            )))
            .await;
    }
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Done => "done",
        Outcome::Drained => "drained",
        Outcome::Interrupted => "interrupted",
        Outcome::Stuck => "stuck",
        Outcome::BudgetExhausted(_) => "budget_exhausted",
        Outcome::HarnessError => "harness_error",
    }
}

fn input_ready_activity(turn: TurnId) -> iteron_protocol::ActivityEvent {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    iteron_protocol::ActivityEvent {
        schema_version: iteron_protocol::ACTIVITY_SCHEMA_VERSION,
        id: format!("turn-{}:input-ready", turn.0),
        parent_id: Some(format!("turn-{}", turn.0)),
        kind: iteron_protocol::ActivityKind::Finalization,
        state: iteron_protocol::ActivityState::Succeeded,
        owner: iteron_protocol::ActivityOwner::Runtime,
        started_at_unix_ms: now,
        updated_at_unix_ms: now,
        attempt: 0,
        limit: 0,
        next_retry_at_unix_ms: None,
        deadline_unix_ms: None,
        cancelability: iteron_protocol::ActivityCancelability::None,
        detail_code: Some(iteron_protocol::ActivityDetailCode::InputReady),
        progress: None,
    }
}

fn first_prompt_title(input: &RunInput) -> String {
    let text = match input {
        RunInput::Text(text) | RunInput::Files { text, .. } => text.as_str(),
        RunInput::Content(segments) => segments.text(),
    };
    iteron_record::session::title_from_text(text)
}

/// The heaviest admissible submission still fits the queue.
///
/// Admission caps text plus framed files at `MAX_TASK_TEXT_BYTES`, which is exactly what the
/// capacity reserves. A `const` assertion rather than a runtime one: every term is a compile-time
/// constant, so `assert!` over them is optimised out and would pass even if the relation broke.
const _: () = assert!(
    SQ_ENTRY_OVERHEAD_BYTES
        + iteron_protocol::task::MAX_TASK_TEXT_BYTES
        + iteron_protocol::input::MAX_TOTAL_IMAGE_BASE64_BYTES
        <= SQ_BYTE_CAPACITY
);

#[cfg(test)]
#[path = "app_server/tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::navigation_agent;
