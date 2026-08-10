use super::*;

impl Agent {
    pub fn new(
        provider: std::sync::Arc<dyn Provider>,
        registry: Registry,
        rollout: Rollout,
        model: String,
        system: String,
        budget: Budget,
    ) -> Self {
        let usd_budget = budget
            .max_usd
            .map(SharedUsdBudget::from_usd)
            .map(std::sync::Arc::new);
        let runtime_state_dir = rollout
            .path()
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        let all_capabilities = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ]);
        Agent {
            provider,
            registry,
            rollout,
            runtime_state_dir,
            ledger: Ledger::new(),
            budget,
            model,
            selected_route: None,
            selected_provider: None,
            last_rate_limit: None,
            pricing_port: None,
            pricing: None,
            usd_budget,
            usd_budget_persisted_microusd: None,
            projection_attribution: None,
            model_context_window: None,
            model_max_output_tokens: None,
            system,
            system_trust: Trust::Trusted,
            instruction_context: None,
            composition_instruction_context: None,
            environment_context: None,
            compaction: CompactionPolicy::default(),
            compacted_in_run: false,
            context_estimator: iteron_ctx::RequestEstimator::new(),
            context_source_evidence: Vec::new(),
            input_file_evidence: None,
            context_ledgers: iteron_ctx::ContextLedgerStore::default(),
            memory_traces: iteron_ctx::MemoryTraceStore::default(),
            session_memory_visibility: std::collections::VecDeque::new(),
            lifecycle_emitter: None,
            lifecycle_telemetry: None,
            lifecycle_hooks: None,
            workspace_file_count: None,
            workspace: std::path::PathBuf::from("."),
            verify_command: None,
            bypass_permissions: false,
            sensitive_env_names: Vec::new(),
            #[cfg(test)]
            pricing_now_unix_secs: None,
            resumed: None,
            working_set: None,
            committed_provider_run_notices: std::collections::BTreeSet::new(),
            verify_attempts: 0,
            drain_requested: false,
            drain: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            owns_drain: true,
            #[cfg(test)]
            verify_oracle: None,
            #[cfg(test)]
            fail_next_durable_append: None,
            diagnostics: DiagnosticEmitter::default(),
            record_failed: false,
            effect_admissions: effect_admission::EffectAdmissions::default(),
            interrupt: None,
            interrupt_requested: false,
            max_tool_concurrency: 16,
            ui_tx: None,
            workflow_progress_tx: None,
            workflow_launcher: None,
            effort: iteron_protocol::Effort::default(),
            memory_workspace: None,
            context_strategy: std::sync::Arc::new(iteron_ctx::ContextStrategy::default()),
            tool_policy: std::sync::Arc::new(iteron_tools::ToolPolicy::default()),
            memory_strategy: std::sync::Arc::new(iteron_ctx::MemoryRecallStrategy::default()),
            router: std::sync::Arc::new(iteron_agents::RouterStrategy::default()),
            planner: std::sync::Arc::new(iteron_agents::PlannerStrategy::default()),
            collaboration: std::sync::Arc::new(iteron_workflow::CollaborationStrategy::default()),
            scheduler: std::sync::Arc::new(iteron_sched::SchedulerStrategy::default()),
            verifier: std::sync::Arc::new(iteron_verify::VerifierStrategy::default()),
            model_router: std::sync::Arc::new(
                iteron_provider::catalog::ModelRouterStrategy::default(),
            ),
            context_port: std::sync::Arc::new(iteron_ctx::DefaultContextPort),
            context_home_dir: None,
            dependency_skill_dirs: Vec::new(),
            agent_catalog: std::sync::Arc::new(iteron_agents::AgentCatalog::builtin_only()),
            agent_catalog_pinned: false,
            boot_bundle: crate::bundle_adapter::resolve_boot_bundle(),
            injected: None,
            injected_trust: None,
            observed_trust: Trust::Trusted,
            last_assistant_text: String::new(),
            seq_turn: 0,
            permission_mode: PermissionMode::default(),
            permission_rules: PermissionRules::new(),
            authority_ceiling: all_capabilities,
            policy_capabilities: all_capabilities,
            approvals_rx: None,
            pending_steers: std::collections::VecDeque::new(),
            approval_seq: 0,
            orchestrating: false,
            delegation_depth: 0,
            side_conversations_opened: 0,
            failed_actions: std::collections::HashMap::new(),
            hooks: Hooks::default(),
            hook_effect_journal: None,
            telemetry: None,
            run_deadline: None,
        }
    }

    /// Effective effort projected in memory. Runtime callers should use [`Self::transition_effort`]
    /// rather than writing the compatibility field directly.
    pub fn effort(&self) -> Effort {
        self.effort
    }

    /// Effective permission mode. Runtime callers should use the durable transition APIs below.
    pub fn permission_mode(&self) -> PermissionMode {
        self.permission_mode
    }

    /// Effective full rule snapshot.
    pub fn permission_rules(&self) -> &PermissionRules {
        &self.permission_rules
    }

    /// Pin the exact discovered catalog before this process can spawn a child. A second pin is
    /// refused. Existing rollouts are allowed because a resumed process must reconstruct its
    /// immutable execution inputs before doing new work.
    pub fn pin_agent_catalog(
        &mut self,
        catalog: iteron_agents::AgentCatalog,
    ) -> Result<(), KernelError> {
        if self.agent_catalog_pinned {
            return Err(KernelError::AgentCatalogAlreadyResolved);
        }
        for def in catalog.defs() {
            def.validate()
                .map_err(|_| KernelError::InvalidRouteMetadata {
                    field: "agent_catalog",
                    reason: "contains an invalid executable agent definition",
                })?;
        }
        self.agent_catalog = std::sync::Arc::new(catalog);
        self.agent_catalog_pinned = true;
        Ok(())
    }

    pub fn agent_catalog_digest(&self) -> String {
        self.agent_catalog.execution_digest()
    }

    /// Clone the exact immutable catalog pinned for this runtime. Frontends receive this once at
    /// attach time; they must never rediscover definitions from a filesystem that may have changed
    /// after execution inputs were resolved.
    pub(crate) fn agent_catalog_snapshot(&self) -> std::sync::Arc<iteron_agents::AgentCatalog> {
        self.agent_catalog.clone()
    }

    /// The quota the provider last published on its response headers, or `None` when this route
    /// publishes none. Read before the first token of the answer, so a frontend can show a
    /// shrinking budget before the rejection rather than after it (I-53).
    pub fn last_rate_limit(&self) -> Option<iteron_provider::RateLimitSnapshot> {
        self.last_rate_limit
    }

    /// The posture the kernel's admission layer is asked to apply.
    ///
    /// A bypassed session is the operator's own authority, so the trust-egress conjunct does not
    /// apply to it; `--ask-permissions` and `--mode plan` both put the constrained posture back.
    /// Plan is included because Plan is a hard denial of everything above read-only, and a posture
    /// that quietly relaxed one of its conjuncts would be the exact "quiet lie" the permission
    /// surface is built to avoid.
    pub(super) fn operator_authority(&self) -> iteron_kernel::admission::OperatorAuthority {
        if self.bypass_permissions && self.permission_mode != PermissionMode::Plan {
            iteron_kernel::admission::OperatorAuthority::Operator
        } else {
            iteron_kernel::admission::OperatorAuthority::Constrained
        }
    }

    /// Bind an admitted task envelope. Repeated calls only narrow the previous ceiling.
    pub fn narrow_authority_ceiling(&mut self, ceiling: CapabilitySet) {
        self.authority_ceiling = self.authority_ceiling.intersect(ceiling);
    }

    /// Bind the capabilities declared by a verified immutable policy manifest. Repeated calls only
    /// narrow; a planner-produced manifest can never grant itself a new capability.
    pub fn narrow_policy_capabilities(&mut self, capabilities: CapabilitySet) {
        self.policy_capabilities = self.policy_capabilities.intersect(capabilities);
    }

    /// Configure the coherent policy that `record_genesis` will durably snapshot for a fresh run.
    /// This is intentionally unavailable once any event exists; every later change must cross one
    /// of the write-ahead transition methods below.
    pub fn configure_initial_runtime_policy(
        &mut self,
        effort: Effort,
        permission_mode: PermissionMode,
        permission_rules: PermissionRules,
    ) -> Result<(), KernelError> {
        if !self.rollout.is_empty() {
            return Err(KernelError::RuntimePolicyAlreadyRecorded);
        }
        self.effort = effort;
        self.permission_mode = permission_mode;
        self.permission_rules = permission_rules;
        Ok(())
    }

    /// Write-ahead transition of effort. A true result means exactly one event was appended and
    /// fsynced before memory changed; false is a no-op and writes nothing. An append error poisons
    /// turn admission and leaves the previous value active.
    pub fn transition_effort(
        &mut self,
        next: Effort,
        source: RuntimePolicySource,
    ) -> Result<bool, KernelError> {
        let result = commit_effort_transition(
            &mut self.rollout,
            TurnId(self.seq_turn),
            &mut self.effort,
            next,
            source,
        );
        match result {
            Ok(changed) => Ok(changed),
            Err(error) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                Err(KernelError::Record(error))
            }
        }
    }

    /// Write-ahead replacement of the coherent permission-policy snapshot. Mode and rules are
    /// never journaled or committed separately.
    pub fn transition_permission_policy(
        &mut self,
        next_mode: PermissionMode,
        next_rules: PermissionRules,
        source: RuntimePolicySource,
    ) -> Result<bool, KernelError> {
        let result = commit_permission_policy_transition(
            &mut self.rollout,
            TurnId(self.seq_turn),
            &mut self.permission_mode,
            &mut self.permission_rules,
            next_mode,
            next_rules,
            source,
        );
        match result {
            Ok(changed) => Ok(changed),
            Err(error) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                Err(KernelError::Record(error))
            }
        }
    }

    pub fn transition_permission_mode(
        &mut self,
        next_mode: PermissionMode,
        source: RuntimePolicySource,
    ) -> Result<bool, KernelError> {
        self.transition_permission_policy(next_mode, self.permission_rules.clone(), source)
    }

    pub fn transition_permission_rules(
        &mut self,
        next_rules: PermissionRules,
        source: RuntimePolicySource,
    ) -> Result<bool, KernelError> {
        self.transition_permission_policy(self.permission_mode, next_rules, source)
    }

    /// Validate and durably replace one capability rule as a full policy snapshot.
    pub fn transition_permission_capability_rule(
        &mut self,
        capability: Capability,
        verdict: Verdict,
        source: RuntimePolicySource,
    ) -> Result<bool, KernelError> {
        let mut next = self.permission_rules.clone();
        next.try_set_cap(capability, verdict)
            .map_err(KernelError::InvalidPermissionPolicy)?;
        self.transition_permission_rules(next, source)
    }
}
