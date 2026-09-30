//! Bounded queue construction and the server-facing endpoint owner.

use super::*;

/// Build the wire and hand back both ends.
///
/// The frontend gets [`AppServerHandle`]; the server side gets the SQ receiver and the EQ
/// publisher. Both sides are constructed here so the capacities and the negotiated version have a
/// single source.
pub(crate) struct ServerEnds {
    pub(crate) submissions: mpsc::Receiver<QueuedSubmission>,
    pub(crate) priority_submissions: mpsc::Receiver<QueuedSubmission>,
    pub(crate) control: mpsc::Receiver<ControlRequest>,
    pub(crate) events: EventPublisher,
    pub(crate) hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth,
    pub(crate) activity: mpsc::Receiver<iteron_protocol::ActivityEvent>,
    pub(super) mcp_input: mcp_input::ServerPort,
    pub(super) plantcore: PlantcoreAdmission,
}

/// The protocol version the in-process runtime advertises to a connecting frontend.
///
/// Overridable only so a process-level test can point the frontend at a server that does not speak
/// its protocol. `iteron-cli` is a managed binary-only package — the boundary authority forbids it a
/// library target — so a skewed server cannot be injected any other way, and the refusal path would
/// otherwise be unreachable in every test that can actually run the frontend. A user who sets it
/// gets a refusal to attach and a diagnostic; there is nothing else behind the door.
pub(crate) fn advertised_version() -> u32 {
    std::env::var("ITERON_APP_SERVER_PROTOCOL_VERSION")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(PROTOCOL_VERSION)
}

#[cfg(test)]
pub(crate) fn wire() -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    wire_with_policy(false)
}

#[cfg(test)]
pub(super) fn wire_with_policy(
    lossless_events: bool,
) -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    wire_with_queue_policy(lossless_events, AppServerQueuePolicy::owner())
}

pub(super) fn wire_with_queue_policy(
    lossless_events: bool,
    queue_policy: AppServerQueuePolicy,
) -> Result<(AppServerHandle, ServerEnds), ProtocolVersionError> {
    let (sq_tx, sq_rx) = mpsc::channel::<QueuedSubmission>(queue_policy.data_entries());
    let (priority_sq_tx, priority_sq_rx) =
        mpsc::channel::<QueuedSubmission>(queue_policy.priority_entries());
    let sq_budget = Arc::new(Semaphore::new(queue_policy.submission_bytes()));
    let (eq_tx, eq_rx) = mpsc::channel::<EventEnvelope>(queue_policy.event_entries());
    // The control plane is deliberately shallow: these are operator commands, one at a time, and a
    // backlog of them would mean the frontend is issuing config changes faster than a human can.
    let (control_tx, control_rx) = mpsc::channel::<ControlRequest>(8);
    let (mcp_input_tx, mcp_input) = mcp_input::wire();
    let (activity_tx, activity_rx) = mpsc::channel::<iteron_protocol::ActivityEvent>(
        iteron_tunables::param_integer(
            "cli.app_server.activity_channel_capacity",
            ACTIVITY_CHANNEL_CAPACITY,
        )
        .max(1),
    );
    let lifecycle = iteron_obs::lifecycle::LifecycleBus::default();
    let lifecycle_emitter = iteron_obs::lifecycle::LifecycleEmitter::new(lifecycle.clone());
    let lifecycle_hooks = Arc::new(std::sync::Mutex::new(None));
    let lifecycle_otel =
        iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime::attach(&lifecycle).ok();
    let hook_health = crate::runtime::lifecycle_hooks::LifecycleHookHealth::default();
    let mut client = AppServerClient::connect_weighted_with_policy(
        advertised_version(),
        sq_tx,
        priority_sq_tx,
        sq_budget,
        lifecycle_emitter.clone(),
        queue_policy,
        lifecycle_hooks.clone(),
    )?;
    let publisher = EventPublisher::new_with_policy_and_hooks(
        eq_tx,
        lossless_events,
        lifecycle_emitter,
        queue_policy,
        lifecycle_hooks,
    );
    client.contract = publisher.contract.clone();
    Ok((
        AppServerHandle {
            client,
            events: eq_rx,
            lifecycle,
            lifecycle_otel,
            hook_health: hook_health.clone(),
            control: control_tx,
            mcp_input: mcp_input_tx,
            activity: activity_tx,
        },
        ServerEnds {
            submissions: sq_rx,
            priority_submissions: priority_sq_rx,
            control: control_rx,
            events: publisher,
            hook_health,
            activity: activity_rx,
            mcp_input,
            plantcore: PlantcoreAdmission::disabled(),
        },
    ))
}
