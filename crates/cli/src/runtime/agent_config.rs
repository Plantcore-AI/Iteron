use super::*;

#[allow(
    dead_code,
    reason = "used by public pre-run tunables pinning seams outside the CLI binary path"
)]
fn create_tool_output_spill_store(
    pin: &tunables_pin::TunablesPin,
) -> Result<std::sync::Arc<tool_output_spill::ToolOutputSpillStore>, KernelError> {
    let view = crate::runtime_tunables::effective_view::EffectiveTunablesView::from_checkpoint(
        pin.checkpoint(),
    )
    .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
    let policy = crate::runtime_tunables::effective_tooling::decode_tool_output_spill_policy(&view)
        .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
    Ok(std::sync::Arc::new(
        tool_output_spill::ToolOutputSpillStore::create(policy)
            .map_err(|_| KernelError::ToolOutputSpill("private store creation failed"))?,
    ))
}

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
        let compiled_policy_bundle = crate::bundle_adapter::baseline_compiled_bundle();
        let context_estimator =
            core_ctx::RequestEstimator::for_route(provider.provider_instance_id(), &model);
        Agent {
            provider,
            registry,
            tool_output_spill: None,
            rollout,
            runtime_state_dir,
            ledger: Ledger::new(),
            budget,
            model,
            selected_route: None,
            selected_provider: None,
            last_rate_limit: None,
            provider_controls: core_provider::ProviderRequestControls::default(),
            provider_governor: None,
            fallback_provider_routes: Vec::new(),
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
            last_compaction_turn: None,
            context_estimator,
            deferred_tool_eager_limit: None,
            context_budget_policy: core_ctx::ContextBudgetPolicy::default(),
            context_materialization_policy: core_ctx::ContextMaterializationPolicy::default(),
            context_source_evidence: Vec::new(),
            input_file_evidence: None,
            context_ledgers: core_ctx::ContextLedgerStore::default(),
            memory_traces: core_ctx::MemoryTraceStore::default(),
            session_memory_visibility: std::collections::VecDeque::new(),
            lifecycle_emitter: None,
            lifecycle_telemetry: None,
            lifecycle_hooks: None,
            workspace_file_count: None,
            workspace: std::path::PathBuf::from("."),
            verify_command: None,
            verification_policy: core_verify::VerificationRuntimePolicy::default(),
            verification_quarantine: std::collections::BTreeMap::new(),
            latest_workspace_checkpoint: None,
            last_workspace_checkpoint_turn: None,
            verification_rollback_point: None,
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
            session_spawn_ledger: std::sync::Arc::new(SessionSpawnLedger::default()),
            ui_tx: None,
            workflow_progress_tx: None,
            workflow_launcher: None,
            mcp_runtime: None,
            effort: core_protocol::Effort::default(),
            memory_workspace: None,
            memory_benchmark_scope: None,
            context_strategy: compiled_policy_bundle.slots().context.clone(),
            tool_policy: compiled_policy_bundle.slots().tool_policy.clone(),
            memory_strategy: compiled_policy_bundle.slots().memory.clone(),
            router: compiled_policy_bundle.slots().router.clone(),
            planner: compiled_policy_bundle.slots().planner.clone(),
            collaboration: compiled_policy_bundle.slots().collaboration.clone(),
            scheduler: compiled_policy_bundle.slots().scheduler.clone(),
            retry_policy: core_sched::BackoffPolicy::default(),
            verifier: compiled_policy_bundle.slots().verifier.clone(),
            model_router: compiled_policy_bundle.slots().model_router.clone(),
            context_port: std::sync::Arc::new(core_ctx::DefaultContextPort),
            context_home_dir: None,
            dependency_skill_dirs: Vec::new(),
            agent_catalog: std::sync::Arc::new(core_agents::AgentCatalog::builtin_only()),
            agent_catalog_pinned: false,
            boot_bundle: compiled_policy_bundle.boot_bundle(),
            compiled_policy_bundle,
            policy_evidence: None,
            policy_turn_cost_baseline: None,
            policy_turn_counter_baseline: None,
            policy_verifier_outcome: core_protocol::PolicyVerifierOutcome::NotRun,
            tunables_pin: None,
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
            failed_actions: super::failed_action_cache::FailedActionCache::default(),
            hooks: Hooks::default(),
            hook_effect_journal: None,
            telemetry: None,
            run_deadline: None,
        }
    }

    /// Construct a fresh production agent from the composition root's atomic resolver result.
    ///
    /// Keeping the unbound constructor above is useful for narrow kernel tests, but no live root or
    /// child is allowed to rediscover defaults after its rollout has been opened. The result is
    /// projected once into a V2 checkpoint; children inherit the resulting pin, not this resolver
    /// input.
    pub fn new_with_resolved_tunables(
        provider: std::sync::Arc<dyn Provider>,
        registry: Registry,
        rollout: Rollout,
        model: String,
        system: String,
        budget: Budget,
        resolved_tunables: std::sync::Arc<core_tunables::ResolvedTunableSet>,
    ) -> Result<Self, KernelError> {
        let pin = tunables_pin::TunablesPin::from_resolved(&resolved_tunables)?;
        Self::new_with_tunables_pin(provider, registry, rollout, model, system, budget, pin)
    }

    /// Construct a resumed production agent from the exact V1/V2 checkpoint read while holding
    /// the rollout writer lock. Current defaults and the resolver are intentionally absent.
    pub fn new_with_tunables_checkpoint(
        provider: std::sync::Arc<dyn Provider>,
        registry: Registry,
        rollout: Rollout,
        model: String,
        system: String,
        budget: Budget,
        checkpoint: core_record::TunablesCheckpoint,
    ) -> Result<Self, KernelError> {
        let pin = tunables_pin::TunablesPin::from_checkpoint(checkpoint)?;
        Self::new_with_tunables_pin(provider, registry, rollout, model, system, budget, pin)
    }

    pub(crate) fn new_with_tunables_pin(
        provider: std::sync::Arc<dyn Provider>,
        registry: Registry,
        rollout: Rollout,
        model: String,
        system: String,
        budget: Budget,
        pin: tunables_pin::TunablesPin,
    ) -> Result<Self, KernelError> {
        let view = crate::runtime_tunables::effective_view::EffectiveTunablesView::from_checkpoint(
            pin.checkpoint(),
        )
        .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
        let tooling =
            crate::runtime_tunables::effective_tooling::EffectiveToolingSettings::decode(&view)
                .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
        let tool_output_spill = std::sync::Arc::new(
            tool_output_spill::ToolOutputSpillStore::create(tooling.tool_output_spill)
                .map_err(|_| KernelError::ToolOutputSpill("private store creation failed"))?,
        );
        tooling
            .install(&registry)
            .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
        let mut agent = Self::new(provider, registry, rollout, model, system, budget);
        agent.tool_output_spill = Some(tool_output_spill);
        agent.tunables_pin = Some(pin);
        Ok(agent)
    }

    /// Install the session owner resolved before this fresh Agent was created. This is accepted
    /// only before a child has been admitted, so replacing the Arc cannot refill a live session.
    pub(crate) fn install_session_spawn_ledger(
        &mut self,
        ledger: std::sync::Arc<SessionSpawnLedger>,
    ) -> Result<(), KernelError> {
        if self.session_spawn_ledger.admitted() != 0 || ledger.admitted() != 0 {
            return Err(KernelError::InvalidRouteMetadata {
                field: "session_spawn_ledger",
                reason: "cannot replace a ledger after child admission",
            });
        }
        self.session_spawn_ledger = ledger;
        Ok(())
    }

    pub(crate) fn session_spawn_ledger(&self) -> &SessionSpawnLedger {
        self.session_spawn_ledger.as_ref()
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
        catalog: core_agents::AgentCatalog,
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
    pub(crate) fn agent_catalog_snapshot(&self) -> std::sync::Arc<core_agents::AgentCatalog> {
        self.agent_catalog.clone()
    }

    /// Pin a fresh composition root's one atomic tunables result as a V2 checkpoint.
    pub fn pin_resolved_tunables(
        &mut self,
        resolved: std::sync::Arc<core_tunables::ResolvedTunableSet>,
    ) -> Result<(), KernelError> {
        if self.tunables_pin.is_some() {
            return Err(KernelError::TunablesAlreadyResolved);
        }
        let pin = tunables_pin::TunablesPin::from_resolved(&resolved)?;
        let tool_output_spill = create_tool_output_spill_store(&pin)?;
        self.tool_output_spill = Some(tool_output_spill);
        self.tunables_pin = Some(pin);
        Ok(())
    }

    /// Pin the exact historical checkpoint recovered from this rollout. V1 remains V1.
    pub fn pin_tunables_checkpoint(
        &mut self,
        checkpoint: core_record::TunablesCheckpoint,
    ) -> Result<(), KernelError> {
        if self.tunables_pin.is_some() {
            return Err(KernelError::TunablesAlreadyResolved);
        }
        let pin = tunables_pin::TunablesPin::from_checkpoint(checkpoint)?;
        let tool_output_spill = create_tool_output_spill_store(&pin)?;
        self.tool_output_spill = Some(tool_output_spill);
        self.tunables_pin = Some(pin);
        Ok(())
    }

    pub fn tunables_checkpoint(&self) -> Result<&core_record::TunablesCheckpoint, KernelError> {
        self.tunables_pin
            .as_ref()
            .map(tunables_pin::TunablesPin::checkpoint)
            .ok_or(KernelError::TunablesNotResolved)
    }

    pub(crate) fn tunables_pin_snapshot(&self) -> Result<tunables_pin::TunablesPin, KernelError> {
        self.tunables_pin
            .clone()
            .ok_or(KernelError::TunablesNotResolved)
    }

    /// The quota the provider last published on its response headers, or `None` when this route
    /// publishes none. Read before the first token of the answer, so a frontend can show a
    /// shrinking budget before the rejection rather than after it (I-53).
    pub fn last_rate_limit(&self) -> Option<core_provider::RateLimitSnapshot> {
        self.last_rate_limit
    }

    /// The posture the kernel's admission layer is asked to apply.
    ///
    /// A bypassed session is the operator's own authority, so the trust-egress conjunct does not
    /// apply to it; `--ask-permissions` and `--mode plan` both put the constrained posture back.
    /// Plan is included because Plan is a hard denial of everything above read-only, and a posture
    /// that quietly relaxed one of its conjuncts would be the exact "quiet lie" the permission
    /// surface is built to avoid.
    pub(super) fn operator_authority(&self) -> core_kernel::admission::OperatorAuthority {
        if self.bypass_permissions && self.permission_mode != PermissionMode::Plan {
            core_kernel::admission::OperatorAuthority::Operator
        } else {
            core_kernel::admission::OperatorAuthority::Constrained
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
