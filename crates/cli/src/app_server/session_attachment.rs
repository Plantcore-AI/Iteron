//! Runtime-to-client composition: immutable facts and actual queue attachment.

use super::{
    Agent, AppServer, AppServerClient, Arc, AtomicBool, ControlRequest, EventEnvelope,
    McpInputResponse, PlantcoreAdmission, ProtocolVersionError, SessionId, SessionSnapshot, mpsc,
    snapshot_of, wire_with_queue_policy,
};

/// The frontend's end of the wire: a client to submit through and a queue to read.
/// A registered tool, reduced to the three fields a client renders. `iteron_tools::ToolSpec` is not
/// public, so this is what crosses the attach boundary instead of the spec.
pub(crate) struct ToolFact {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) capability: iteron_protocol::Capability,
}

/// What a client is handed once, at attach time, and may read for the life of the session.
///
/// These are the shapes a co-composing frontend used to read straight off an idle `Agent`. They are
/// invariants — nothing here changes while the session runs — which is exactly why they can be
/// copied across the boundary instead of being asked for on every keystroke.
pub(crate) struct SessionFacts {
    pub(crate) session_id: SessionId,
    pub(crate) context_ledgers: iteron_ctx::ContextLedgerStore,
    pub(crate) memory_traces: iteron_ctx::MemoryTraceStore,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
    pub(crate) telemetry_health: Option<crate::runtime::telemetry::TelemetryHealth>,
    pub(crate) workspace: std::path::PathBuf,
    pub(crate) memory_workspace: Option<std::path::PathBuf>,
    pub(crate) rollout_path: std::path::PathBuf,
    pub(crate) compaction_trigger_tokens: usize,
    /// The window of the model selected at startup. Only an initial value: `/model` replaces it,
    /// and the client tracks the current one itself.
    pub(crate) initial_model_context_window: Option<u64>,
    /// Whether the capability gate is replaced by blanket auto-approval for this session. A
    /// startup fact, not runtime state: nothing changes it after `wire`. It is carried here so the
    /// permission surfaces can say so — a `/permissions` screen listing "ask every time" rows while
    /// nothing asks would be a lie, and one this project's own truth overlay exists to prevent.
    pub(crate) bypass_permissions: bool,
    pub(crate) registry_tools: Vec<ToolFact>,
    /// Exact verified dependency skill roots pinned into the runtime at composition time.
    pub(crate) dependency_skill_dirs: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    /// The exact immutable `Arc` the runtime resolves child definitions against. Keeping object
    /// identity across the attach boundary prevents `/agents` from presenting filesystem drift as
    /// executable state while the resident runtime continues using its pinned catalog.
    pub(crate) agent_catalog: Arc<iteron_agents::AgentCatalog>,
    /// Exact immutable runtime checkpoint. Production composition always supplies V2; Option is
    /// retained only for narrow wire tests that construct an unbound Agent.
    pub(crate) tunables_checkpoint: Option<iteron_record::TunablesCheckpoint>,
    pub(crate) client_inventory_digest: Option<String>,
}

/// Everything a client needs to talk to a running App Server, and nothing more.
pub(crate) struct Attached {
    pub(crate) handle: AppServerHandle,
    /// The server task. Awaiting it after dropping the client is how a client waits for the
    /// runtime's own shutdown — the final rollout flush happens in there, and so does cancelling
    /// and recording any workflow run the session still owned. It yields what it did with those
    /// runs; a client that renders to a terminal prints it after restoring the terminal, because
    /// the event queue's reader is gone by the time this resolves.
    pub(crate) task: tokio::task::JoinHandle<crate::workflow::ShutdownReport>,
    pub(crate) facts: SessionFacts,
    pub(crate) initial_state: SessionSnapshot,
    /// Ctrl-C: cancel the in-flight provider turn at the next safe point.
    pub(crate) interrupt: Arc<AtomicBool>,
    /// Ctrl-D: quiesce active work and settle the session record.
    pub(crate) drain: Arc<AtomicBool>,
    /// Present only for `serve --plantcore`; shared with the loopback command transport.
    pub(crate) dispatch_gate: Option<Arc<crate::runtime::DispatchGate>>,
    pub(crate) machine_schema_version: u32,
}

/// **The composition root.** The one place an `Agent` is handed to an App Server, and the one place
/// the wire's version, capacities and ownership are decided.
///
/// The interactive TUI attaches here today; the one-shot path and the headless `iteron serve` (#44)
/// attach to this same function rather than building a second wire of their own. That is the point
/// of it being a function: a client that constructs its own transport is a client that can drift
/// from the protocol the server speaks, which is the failure this lane exists to remove.
///
/// It is a function here rather than statements in `main.rs` because the schema-compatibility
/// authority freezes `main` and `run_cli` token-for-token, along with `main.rs`'s module list
/// (`xtask/src/schema_compat_rust_semantics_functions.rs`). Single-sourcing the wire does not
/// require the call to be written in the composition root's file; it requires there to be exactly
/// one of it, which is what this is.
pub(crate) fn attach(
    agent: Agent,
    interactive_approvals: bool,
    lossless_events: bool,
) -> Result<Attached, ProtocolVersionError> {
    attach_with_plantcore(
        agent,
        interactive_approvals,
        lossless_events,
        PlantcoreAdmission::disabled(),
    )
}

#[cfg(feature = "legacy-plantcore")]
pub(crate) fn attach_plantcore(
    agent: Agent,
    interactive_approvals: bool,
    lossless_events: bool,
    provider_api_origin: String,
) -> Result<Attached, ProtocolVersionError> {
    attach_with_plantcore(
        agent,
        interactive_approvals,
        lossless_events,
        PlantcoreAdmission::required(provider_api_origin),
    )
}

pub(super) fn attach_with_plantcore(
    mut agent: Agent,
    interactive_approvals: bool,
    lossless_events: bool,
    plantcore: PlantcoreAdmission,
) -> Result<Attached, ProtocolVersionError> {
    let machine_schema_version = if plantcore.is_enabled() {
        crate::machine_projection::V7_SCHEMA_VERSION
    } else {
        crate::machine_projection::SCHEMA_VERSION
    };
    let dispatch_gate = plantcore.dispatch_gate();
    if let Some(gate) = &dispatch_gate {
        agent.install_plantcore_dispatch_gate(gate.clone());
    }
    let queue_policy = agent.app_server_queue_policy();
    let (mut handle, mut ends) = wire_with_queue_policy(lossless_events, queue_policy)?;
    ends.plantcore = plantcore;

    let interrupt = Arc::new(AtomicBool::new(false));
    agent.set_interrupt(interrupt.clone());
    let drain = Arc::new(AtomicBool::new(false));
    agent.set_drain(drain.clone());
    let lifecycle_run_id = agent.rollout.run_id().clone();
    let lifecycle_session_id = SessionId(format!("session-{}", lifecycle_run_id.0));
    handle
        .client
        .bind_lifecycle_identity(lifecycle_session_id.clone(), lifecycle_run_id);

    // Attach needs three light frontend fields, not owned copies of every full JSON schema.
    let tool_specs = agent.registry.spec_snapshot();
    let facts = SessionFacts {
        session_id: lifecycle_session_id,
        context_ledgers: agent.context_ledgers.clone(),
        memory_traces: agent.memory_traces.clone(),
        hook_health: handle.hook_health.clone(),
        telemetry_health: agent.telemetry.as_ref().map(|sink| sink.health()),
        workspace: agent.workspace.clone(),
        memory_workspace: agent.memory_workspace.clone(),
        rollout_path: agent.rollout.path().to_path_buf(),
        compaction_trigger_tokens: agent.compaction.trigger_tokens,
        initial_model_context_window: agent.model_context_window,
        bypass_permissions: agent.bypass_permissions,
        registry_tools: tool_specs
            .specs()
            .iter()
            .map(|spec| ToolFact {
                name: spec.name.clone(),
                description: spec.description.clone(),
                capability: spec.capability,
            })
            .collect(),
        dependency_skill_dirs: agent.dependency_skill_dirs().to_vec(),
        agent_catalog: agent.agent_catalog_snapshot(),
        tunables_checkpoint: agent.tunables_checkpoint().ok().cloned(),
        client_inventory_digest: agent
            .client_inventory_owner()
            .map(|owner| owner.digest().to_owned()),
    };
    let initial_state = snapshot_of(&mut agent);
    if let Some(telemetry) = handle.lifecycle_otel.clone() {
        agent.set_lifecycle_telemetry(telemetry);
    }
    agent.set_activity(handle.activity.clone());

    // The `Agent` moves in here and never comes back. "A run is in flight" becomes the server's
    // fact to report, not a slot a client can inspect.
    let session_factory = super::session_factory::SessionFactory::capture(&agent, &handle.client);
    let task = tokio::spawn(
        AppServer::new_with_session_factory(agent, ends, interactive_approvals, session_factory)
            .serve(),
    );

    Ok(Attached {
        handle,
        task,
        facts,
        initial_state,
        interrupt,
        drain,
        dispatch_gate,
        machine_schema_version,
    })
}

pub(crate) struct AppServerHandle {
    pub(crate) client: AppServerClient,
    pub(crate) events: mpsc::Receiver<EventEnvelope>,
    /// Content-free, bounded local lifecycle evidence. Reading it never asks the runtime actor or
    /// an exporter to stop what it is doing.
    pub(crate) lifecycle: iteron_obs::lifecycle::LifecycleBus,
    pub(crate) lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
    /// Shared bounded activity ingress. Runtime and composition-root background refreshes publish
    /// the same content-free vocabulary; the server is the sole EQ projector.
    pub(crate) activity: mpsc::Sender<iteron_protocol::ActivityEvent>,
    /// The control plane. See [`Control`] for why it is not the SQ.
    pub(crate) control: mpsc::Sender<ControlRequest>,
    /// Dedicated response lane for 2026 MCP input. It cannot submit model text or permissions.
    pub(crate) mcp_input: mpsc::Sender<McpInputResponse>,
}
