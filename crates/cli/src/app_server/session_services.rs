//! Actual session service composition: single queue, supervisor and observation owners.

use super::{
    Agent, Arc, AtomicBool, EventPublisher, LifecyclePayload, OperatorStatusSources,
    RUNTIME_UI_CAPACITY, WORKFLOW_PROGRESS_CAPACITY, WORKFLOW_SETTLED_CAPACITY,
    dispatch_lifecycle_hook, mpsc,
};

pub(super) struct SessionServices {
    pub(super) runtime_ui_rx: mpsc::Receiver<crate::runtime::RuntimeFrontendEvent>,
    pub(super) frontend_channels: crate::runtime::FrontendChannelHealth,
    pub(super) workflow_rx: mpsc::Receiver<crate::workflow::WorkflowRunUiEvent>,
    pub(super) settled_rx: mpsc::Receiver<crate::workflow::RunSettled>,
    pub(super) workflows: Arc<crate::workflow::WorkflowSupervisor>,
    pub(super) processes: Option<iteron_tools::ProcessControl>,
    pub(super) mcp_runtime: Option<crate::mcp::McpRuntimeControl>,
    pub(super) language_servers: Option<iteron_tools::LspControl>,
    pub(super) operator_status: OperatorStatusSources,
    pub(super) hook_cancel: Option<Arc<AtomicBool>>,
    pub(super) drain_signal: Arc<AtomicBool>,
    pub(super) lifecycle_gate_hooks: crate::runtime::hooks::Hooks,
}

impl SessionServices {
    pub(super) fn install(agent: &mut Agent, events: &EventPublisher) -> Self {
        // Runtime emitters never await presentation. The finite bridge makes a stopped frontend a
        // counted/coalesced presentation gap instead of an unbounded heap; terminal authority is
        // reconciled from `RunEnded` after the turn.
        let (runtime_ui_tx, runtime_ui_rx) = mpsc::channel::<crate::runtime::RuntimeFrontendEvent>(
            iteron_tunables::param_integer(
                "cli.app_server.runtime_ui_capacity",
                RUNTIME_UI_CAPACITY,
            )
            .clamp(1, RUNTIME_UI_CAPACITY),
        );
        agent.set_resident_ui(runtime_ui_tx);
        // Shared with the runtime emitter so structural events that meet a full cosmetic lane have
        // a separately bounded, backpressured path the server can drain while `agent` is borrowed
        // by the running turn. Text/thinking alone may be omitted and later reconciled.
        let frontend_channels = agent.frontend_channel_port();

        // Runtime and composition-root refreshes share the bounded Activity ingress created by
        // `wire_with_queue_policy`; neither producer can block model/tool work or bypass the EQ.

        // Engine progress is best-effort and non-blocking, but never unbounded. Background terminal
        // state travels separately through the awaited settled channel below.
        let (workflow_tx, workflow_rx) = mpsc::channel::<crate::workflow::WorkflowRunUiEvent>(
            iteron_tunables::param_integer(
                "cli.app_server.workflow_progress_capacity",
                WORKFLOW_PROGRESS_CAPACITY,
            )
            .clamp(1, WORKFLOW_PROGRESS_CAPACITY),
        );
        agent.set_workflow_progress(workflow_tx);
        // Runtime and frontend project the same canonical lifecycle stream. Installing this before
        // any session-owned worker starts prevents model/tool/context events from becoming an
        // uncorrelated second telemetry island.
        agent.set_lifecycle_emitter(events.lifecycle_emitter());

        // The session-scoped owner for `Workflow({background: true})` runs. Installed OUTSIDE the
        // turn's borrow — that placement is the whole point, not an implementation detail. Unlike
        // cosmetic progress, every settled message is terminal authority, so its bounded sender
        // awaits capacity rather than dropping.
        let (settled_tx, settled_rx) = mpsc::channel::<crate::workflow::RunSettled>(
            iteron_tunables::param_integer(
                "cli.app_server.workflow_settled_capacity",
                WORKFLOW_SETTLED_CAPACITY,
            )
            .clamp(1, WORKFLOW_SETTLED_CAPACITY),
        );
        let workflows = crate::workflow::WorkflowSupervisor::new(settled_tx);
        if let Some(activity) = agent.activity_sender() {
            workflows.set_activity(activity);
        }
        agent.set_workflow_launcher(workflows.clone());
        // Clone the job control port before a turn borrows `&mut agent`. It owns no second job
        // table: every operation reaches the supervisor captured by this registry's process tools.
        let processes = agent.registry.process_control();
        // MCP cancellation/restart/stop must remain reachable while the turn is blocked in an MCP
        // request. This clone addresses the same session-owned actors as the registry proxies.
        let mcp_runtime = agent.mcp_runtime_control();
        // The same ownership rule applies to language servers: drain/exit must address the exact
        // bounded pool that served this session, never reconstruct a best-effort client list.
        let language_servers = agent.registry.lsp_control();
        let operator_status = OperatorStatusSources::capture(
            agent,
            processes.clone(),
            language_servers.clone(),
            mcp_runtime.clone(),
            workflows.clone(),
        );
        let hook_cancel = agent.interrupt_handle();
        let drain_signal = agent.drain_handle();

        // Canonical Hook observation is bounded and off the turn path. Gate hooks remain at their
        // owning admission sites below; the dispatcher deliberately skips the fixed Gate set.
        let lifecycle_gate_hooks = agent.hooks.clone();
        if let Some(processes) = &processes {
            let emitter = events.lifecycle_emitter();
            let base_correlation = events.lifecycle_correlation(None, None);
            let lifecycle_hooks = events.lifecycle_hooks.clone();
            processes.bind_lifecycle_observer(std::sync::Arc::new(move |notice| {
                let outcome = match notice.kind {
                    iteron_tools::ProcessLifecycleKind::Spawned => "spawned",
                    iteron_tools::ProcessLifecycleKind::Exited => "exited",
                    iteron_tools::ProcessLifecycleKind::Stopped => "stopped",
                    iteron_tools::ProcessLifecycleKind::TimedOut => "timed_out",
                    iteron_tools::ProcessLifecycleKind::IdleStalled => "idle_stalled",
                    iteron_tools::ProcessLifecycleKind::OutputLimitExceeded => "output_limit",
                    iteron_tools::ProcessLifecycleKind::IoFailed => "io_failed",
                    iteron_tools::ProcessLifecycleKind::CleanupUnknown => "cleanup_unknown",
                };
                let event_ids: &[&str] = match notice.kind {
                    iteron_tools::ProcessLifecycleKind::Spawned => {
                        &["process.spawned", "background.detached"]
                    }
                    iteron_tools::ProcessLifecycleKind::Exited => {
                        &["process.kill_sent", "process.reaped", "background.stopped"]
                    }
                    iteron_tools::ProcessLifecycleKind::CleanupUnknown => &[
                        "process.kill_sent",
                        "process.reap_failed",
                        "background.orphan_detected",
                    ],
                    iteron_tools::ProcessLifecycleKind::Stopped
                    | iteron_tools::ProcessLifecycleKind::TimedOut
                    | iteron_tools::ProcessLifecycleKind::IdleStalled
                    | iteron_tools::ProcessLifecycleKind::OutputLimitExceeded
                    | iteron_tools::ProcessLifecycleKind::IoFailed => &[
                        "process.term_sent",
                        "process.kill_sent",
                        "process.reaped",
                        "background.stopped",
                    ],
                };
                for event_id in event_ids {
                    let mut correlation = base_correlation.clone();
                    correlation.job_id = Some(iteron_protocol::JobId(notice.job_id.clone()));
                    if let Ok(event) = emitter.emit(
                        event_id,
                        correlation,
                        LifecyclePayload {
                            outcome_code: Some(outcome.to_owned()),
                            ..LifecyclePayload::default()
                        },
                    ) {
                        dispatch_lifecycle_hook(&lifecycle_hooks, event);
                    }
                }
            }));
        }
        Self {
            runtime_ui_rx,
            frontend_channels,
            workflow_rx,
            settled_rx,
            workflows,
            processes,
            mcp_runtime,
            language_servers,
            operator_status,
            hook_cancel,
            drain_signal,
            lifecycle_gate_hooks,
        }
    }
}
