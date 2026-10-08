//! Public client session, immutable attach facts and runtime state mirrors.

use super::{Effort, Op, PermissionMode, PermissionRules, SubmissionId, app_server};
#[cfg(test)]
use std::sync::Arc;

pub(crate) struct Session {
    /// The versioned SQ client. Every `Op` the frontend sends goes through this and nothing else.
    pub(super) client: app_server::AppServerClient,
    /// The control plane. See `app_server::Control` for why these are not `Op`s.
    pub(super) control: tokio::sync::mpsc::Sender<app_server::ControlRequest>,
    pub(super) mcp_input: tokio::sync::mpsc::Sender<app_server::McpInputResponse>,
    /// Shared bounded content-free lifecycle flight recorder.
    pub(super) lifecycle: iteron_obs::lifecycle::LifecycleBus,
    pub(super) lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
    /// Runtime state the status line mirrors. Refreshed from every control reply and from the
    /// terminal event of every turn — the frontend never reads it off an `Agent` again.
    pub(super) state: app_server::SessionSnapshot,
    /// Facts fixed for the session, captured once at composition. Reading these used to require the
    /// `Agent` to be idle in the frontend's hands.
    pub(super) facts: app_server::SessionFacts,
}

impl Session {
    pub(super) fn new(
        handle_client: app_server::AppServerClient,
        control: tokio::sync::mpsc::Sender<app_server::ControlRequest>,
        mcp_input: tokio::sync::mpsc::Sender<app_server::McpInputResponse>,
        lifecycle: iteron_obs::lifecycle::LifecycleBus,
        lifecycle_otel: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
        state: app_server::SessionSnapshot,
        facts: app_server::SessionFacts,
    ) -> Self {
        Self {
            client: handle_client,
            control,
            mcp_input,
            lifecycle,
            lifecycle_otel,
            state,
            facts,
        }
    }

    pub(super) fn operator_shell_request(
        &self,
        command: String,
    ) -> Option<super::transcript_effect::Request> {
        let scope = self.client.thread_snapshot_v1()?;
        Some(super::transcript_effect::Request::Shell {
            sender: self.control.clone(),
            command: app_server::OperatorShellV1 {
                thread_id: scope.thread_id,
                run_id: scope.run_id,
                command,
            },
        })
    }

    pub(super) fn answer_mcp_input(
        &self,
        response: app_server::McpInputResponse,
    ) -> Result<(), String> {
        self.mcp_input
            .try_send(response)
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    "MCP input response channel is busy; the form was preserved".into()
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    "MCP input response channel is closed".into()
                }
            })
    }

    // Accessors mirroring the shapes the frontend used to read straight off the `Agent`. Keeping
    // the names lets the call sites stay readable; what changed is where the value comes from —
    // a snapshot the server published, or a fact captured once at composition.
    pub(crate) fn workspace(&self) -> &std::path::Path {
        &self.facts.workspace
    }

    pub(crate) fn session_id(&self) -> &iteron_protocol::SessionId {
        &self.facts.session_id
    }

    pub(crate) fn lifecycle_snapshot(&self) -> iteron_obs::lifecycle::FlightRecorderSnapshot {
        self.lifecycle.snapshot()
    }

    pub(crate) fn lifecycle_otel_snapshot(
        &self,
    ) -> Option<iteron_obs::otel::lifecycle::LifecycleTelemetrySnapshot> {
        self.lifecycle_otel
            .as_ref()
            .map(|runtime| runtime.snapshot())
    }

    pub(crate) fn context_ledger_snapshot(&self) -> iteron_ctx::ContextLedgerSnapshot {
        self.facts.context_ledgers.snapshot()
    }

    pub(crate) fn memory_trace_snapshot(&self) -> iteron_ctx::MemoryTraceSnapshot {
        self.facts.memory_traces.snapshot()
    }

    pub(crate) fn hook_health_snapshot(
        &self,
    ) -> crate::runtime::lifecycle_hooks::LifecycleHookHealthSnapshot {
        self.facts.hook_health.snapshot()
    }

    pub(crate) fn telemetry_export_health_snapshot(
        &self,
    ) -> Option<crate::runtime::telemetry::TelemetryHealthSnapshot> {
        self.facts
            .telemetry_health
            .as_ref()
            .map(|health| health.snapshot())
    }

    pub(crate) fn memory_workspace(&self) -> Option<&std::path::Path> {
        self.facts.memory_workspace.as_deref()
    }

    pub(crate) fn rollout_path(&self) -> &std::path::Path {
        &self.facts.rollout_path
    }

    pub(crate) fn tunables_checkpoint(&self) -> Option<&iteron_record::TunablesCheckpoint> {
        self.facts.tunables_checkpoint.as_ref()
    }

    pub(crate) fn tunables_effective_digest(&self) -> Option<&str> {
        match self.tunables_checkpoint()? {
            iteron_record::TunablesCheckpoint::V1(snapshot) => {
                Some(&snapshot.effective_digest_sha256)
            }
            iteron_record::TunablesCheckpoint::V2(snapshot) => {
                Some(&snapshot.effective_digest_sha256)
            }
        }
    }

    pub(crate) fn runtime_profile_id(&self) -> Option<&'static str> {
        crate::runtime_tunables::effective_view::checkpoint_runtime_profile(
            self.tunables_checkpoint()?,
        )
        .map(iteron_tunables::RuntimeProfile::id)
    }

    pub(crate) fn model(&self) -> &str {
        &self.state.model
    }

    pub(crate) fn effort(&self) -> Effort {
        self.state.effort
    }

    pub(crate) fn permission_mode(&self) -> PermissionMode {
        self.state.mode
    }

    pub(crate) fn bypass_permissions(&self) -> bool {
        self.facts.bypass_permissions
    }

    pub(crate) fn permission_rules(&self) -> &PermissionRules {
        &self.state.permission_rules
    }

    /// Ordered, durable provenance for the mutable policy fields projected beside the immutable
    /// run-genesis tunables checkpoint. `None` is reserved for legacy or unsealed runtimes and is
    /// never interpreted as "the genesis value is still current".
    pub(crate) fn runtime_policy(&self) -> Option<&crate::runtime::RuntimePolicyOverlaySnapshot> {
        self.state.runtime_policy.as_ref()
    }

    pub(crate) fn ledger_summary(&self) -> &str {
        &self.state.ledger_summary
    }

    /// Provider quota from the last response's headers, if the route publishes any (I-53).
    pub(crate) fn rate_limit(&self) -> Option<&str> {
        self.state.rate_limit.as_deref()
    }

    pub(crate) fn compaction_trigger_tokens(&self) -> usize {
        self.facts.compaction_trigger_tokens
    }

    /// A session wired to a bare SQ, for tests that assert on what the frontend submits. Test-only
    /// so that production code has exactly one way to obtain a `Session`: `app_server::wire`.
    #[cfg(test)]
    pub(crate) fn for_test(
        submissions: tokio::sync::mpsc::Sender<crate::runtime::TurnSubmission>,
    ) -> Self {
        let (control, _control_rx) = tokio::sync::mpsc::channel(1);
        let (mcp_input, _mcp_input_rx) = tokio::sync::mpsc::channel(1);
        let client =
            app_server::AppServerClient::connect(iteron_protocol::PROTOCOL_VERSION, submissions)
                .expect("the in-process server speaks the current protocol");
        client.seed_contract_turn_for_test(
            iteron_protocol::SessionId("session-test".into()),
            iteron_protocol::RunId("run-test".into()),
            iteron_protocol::product_contract::ProductTurnId(1),
        );
        Self {
            client,
            control,
            mcp_input,
            lifecycle: iteron_obs::lifecycle::LifecycleBus::default(),
            lifecycle_otel: None,
            state: app_server::SessionSnapshot {
                mode: iteron_protocol::PermissionMode::default(),
                effort: iteron_protocol::Effort::default(),
                model: "test-model".into(),
                provider_id: "test-provider".into(),
                cost: iteron_obs::CostState::default(),
                last_turn_usage: None,
                unadmitted_steers: Vec::new(),
                unadmitted_internal_notifications: Vec::new(),
                unadmitted_client_steers: 0,
                unadmitted_steer_submission_ids: Vec::new(),
                permission_rules: PermissionRules::new(),
                runtime_policy: None,
                ledger_summary: String::new(),
                rate_limit: None,
                mcp_health: Vec::new(),
            },
            facts: app_server::SessionFacts {
                session_id: iteron_protocol::SessionId("session-test".into()),
                context_ledgers: iteron_ctx::ContextLedgerStore::default(),
                memory_traces: iteron_ctx::MemoryTraceStore::default(),
                hook_health: crate::runtime::lifecycle_hooks::LifecycleHookHealth::default(),
                telemetry_health: None,
                workspace: std::path::PathBuf::new(),
                memory_workspace: None,
                rollout_path: std::path::PathBuf::new(),
                compaction_trigger_tokens: 0,
                bypass_permissions: false,
                initial_model_context_window: None,
                registry_tools: Vec::new(),
                dependency_skill_dirs: Vec::new(),
                agent_catalog: Arc::new(iteron_agents::AgentCatalog::builtin_only()),
                tunables_checkpoint: None,
                client_inventory_digest: None,
                provider_catalog: None,
                client_bootstrap: None,
            },
        }
    }

    pub(crate) fn registry_tools(&self) -> &[app_server::ToolFact] {
        &self.facts.registry_tools
    }

    pub(crate) fn dependency_skill_dirs(&self) -> &[(std::path::PathBuf, std::path::PathBuf)] {
        &self.facts.dependency_skill_dirs
    }

    /// The execution catalog captured by the App Server at attach time. This is deliberately not
    /// reconstructed from `workspace` or an ambient operator home: those paths may drift while the
    /// resident runtime continues resolving children against this immutable snapshot.
    pub(crate) fn agent_catalog(&self) -> &iteron_agents::AgentCatalog {
        &self.facts.agent_catalog
    }

    /// Adopt the runtime state carried by a terminal event.
    pub(crate) fn adopt(&mut self, snapshot: app_server::SessionSnapshot) {
        self.state = snapshot;
    }

    /// Follow the runtime onto another run.
    ///
    /// `rollout_path` is the one session fact that is NOT a session invariant once a session can
    /// change runs in place. Everything else in `SessionFacts` is per-process — the workspace, the
    /// pinned agent catalog, the registered tools — and deliberately survives. Leaving the old path
    /// here would point `/sessions`, `/rewind` and the transcript export at the run this session
    /// just left.
    pub(crate) fn adopt_run(
        &mut self,
        rollout_path: std::path::PathBuf,
        tunables_checkpoint: iteron_record::TunablesCheckpoint,
        compaction_trigger_tokens: usize,
        snapshot: app_server::SessionSnapshot,
    ) {
        self.facts.rollout_path = rollout_path;
        self.facts.tunables_checkpoint = Some(tunables_checkpoint);
        self.facts.compaction_trigger_tokens = compaction_trigger_tokens;
        self.state = snapshot;
    }

    pub(crate) fn submit_identified(
        &self,
        op: Op,
    ) -> Result<SubmissionId, app_server::SubmitError> {
        self.client.submit_identified(op)
    }

    /// Bind an active-turn control to the product turn observed at admission. The App Server
    /// checks the same epoch again when it consumes the SQ entry, so a late keyboard event cannot
    /// be carried into the next turn. `None` means the operator must keep the input locally.
    pub(crate) fn submit_for_running_turn(
        &self,
        op: Op,
    ) -> Option<Result<SubmissionId, app_server::SubmitError>> {
        let turn = self.client.thread_snapshot_v1()?.turn?;
        (turn.state == iteron_protocol::product_contract::TurnStateV1::Running)
            .then(|| self.client.submit_identified_for_turn(op, turn.turn_id))
    }

    pub(crate) fn control_sender(&self) -> tokio::sync::mpsc::Sender<app_server::ControlRequest> {
        self.control.clone()
    }
}
