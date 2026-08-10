use super::*;

impl Agent {
    /// Spawn a READ-ONLY subagent to investigate a subtask, returning its compressed summary
    /// (ADR-001: a subagent is a context-management device, not a teammate; it explores an
    /// isolated slice and returns ~1-2k tokens to the single writer). The subagent shares the
    /// provider, gets read-only tools (no edit, no bash), and its own bounded budget. Its
    /// detailed context stays isolated; only the summary enters the parent transcript.
    pub(super) fn subagent_run_id(
        &self,
        kind: &str,
        turn: u32,
        ordinal: usize,
    ) -> iteron_protocol::RunId {
        let mut digest = Sha256::new();
        for value in [
            self.rollout.tenant().0.as_bytes(),
            self.rollout.run_id().0.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        let digest = digest.finalize();
        let namespace = digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        iteron_protocol::RunId(format!("{kind}-{namespace}-t{turn:08x}-n{ordinal:04x}"))
    }

    pub(super) fn subagent_directory(&self) -> std::path::PathBuf {
        self.rollout
            .path()
            .parent()
            .map(|parent| parent.join("subagents"))
            .unwrap_or_else(|| std::env::temp_dir().join("core-subagents-refused"))
    }

    /// Await one already-admitted child while continuing to observe the parent SQ. Drain is
    /// propagated through the shared flag but never cancels the child mid-effect; the child exits
    /// only at its own safe point, after which the parent records the child terminal before it can
    /// checkpoint itself. Polling is fixed and bounded just like verification cancellation.
    ///
    /// An interrupt, unlike drain, IS a cancel: it is republished onto a call-scoped stop flag the
    /// child observes mid-stream, so an operator stop drops the child's in-flight provider stream
    /// within one poll interval. Same defect and same fix as the fan — see
    /// [`Self::pump_child_stop`]. The flag is scoped to this call because this child is one the turn
    /// is awaiting; a detached run or a background agent is never reachable from here.
    pub(super) async fn run_child_with_control(
        &mut self,
        child: &mut Agent,
        task: &str,
    ) -> Result<Outcome, KernelError> {
        const CHILD_CONTROL_POLL: Duration = Duration::from_millis(25);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Seed before the child starts: a stop the operator raised while the parent was still
        // admitting must make the child refuse at its first safe point, not one poll interval in.
        self.pump_child_stop(&stop);
        child.set_interrupt(stop.clone());
        // A dispatched subagent is read-only + SingleAgent effort, so it never orchestrates:
        // `run_leaf` is behavior-identical to `run` here and keeps `run_orchestrated` OUT of every
        // child's call graph, so a caller may own/spawn the child without pulling the parent writer
        // into a recursive `Send` obligation.
        let mut execution = Box::pin(child.run_leaf(task));
        loop {
            match tokio::time::timeout(CHILD_CONTROL_POLL, &mut execution).await {
                Ok(outcome) => {
                    drop(execution);
                    let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
                    return outcome;
                }
                Err(_) => {
                    self.pump_child_stop(&stop);
                }
            }
        }
    }

    /// Build the one production child-spawner context shared by user-authored workflows and the
    /// built-in Ultracode fan. Route evidence, policy generation, permission posture, accounting,
    /// workspace and catalog are copied once here so the two callers cannot grow different child
    /// semantics while both claim to use `WorkflowEngine`.
    pub(super) fn kernel_spawner_context(
        &self,
        route: &PricingRoute,
        workflow_id: &str,
    ) -> KernelSpawnerContext {
        let mut cx = KernelSpawnerContext::new(
            self.provider.clone(),
            route.model_id.clone(),
            route.provider_id.clone(),
            route.catalog_digest.clone(),
            route.capability_digest.clone(),
            self.workspace.clone(),
            self.runtime_state_dir.clone(),
            self.rollout.tenant().clone(),
            self.rollout.run_id().0.clone(),
            workflow_id.to_string(),
        );
        cx.model_context_window = self.model_context_window;
        cx.model_max_output_tokens = self.model_max_output_tokens;
        cx.sensitive_env_names = self.sensitive_env_names.clone();
        cx.pricing_port = self.pricing_port.clone();
        cx.usd_budget = self.usd_budget.clone();
        cx.budget.max_usd = self.effective_max_usd();
        cx.default_effort = self.effort;
        cx.permission_mode = self.permission_mode;
        cx.permission_rules = self.permission_rules.clone();
        cx.authority_ceiling = self.authority_ceiling;
        cx.policy_capabilities = self.policy_capabilities;
        cx.bypass_permissions = self.bypass_permissions;
        cx.context_strategy = self.context_strategy.clone();
        cx.tool_policy = self.tool_policy.clone();
        cx.memory_strategy = self.memory_strategy.clone();
        cx.router = self.router.clone();
        cx.planner = self.planner.clone();
        cx.collaboration = self.collaboration.clone();
        cx.scheduler = self.scheduler.clone();
        cx.verifier = self.verifier.clone();
        cx.model_router = self.model_router.clone();
        cx.context_port = self.context_port.clone();
        cx.context_home_dir = self.context_home_dir.clone();
        cx.dependency_skill_dirs = self.dependency_skill_dirs.clone();
        cx.agent_catalog = self.agent_catalog.clone();
        cx.boot_bundle = self.boot_bundle.clone();
        cx.drain = Some(self.drain.clone());
        cx.lifecycle_emitter = self.lifecycle_emitter.clone();
        cx.lifecycle_telemetry = self.lifecycle_telemetry.clone();
        cx.lifecycle_hooks = self.lifecycle_hooks.clone();
        cx.hooks = self.hooks.clone();
        cx.hook_effect_journal = self.hook_effect_journal.clone();
        cx
    }
}
