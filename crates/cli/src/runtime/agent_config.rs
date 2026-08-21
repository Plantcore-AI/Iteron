use super::*;

/// Decode the pinned tunables into tooling policy, install it into the registry, and open the
/// private spill store.
///
/// Both ways of pinning must leave the agent in the same state. They did not: the constructor
/// installed the tooling policy while the post-construction pin only opened the spill store, so an
/// agent pinned that way failed later with `ToolingPolicy` at its first tool call. One function is
/// now the only place that answers "what does a pinned agent owe its registry".
struct AppliedPinnedRuntime {
    tool_output_spill: std::sync::Arc<tool_output_spill::ToolOutputSpillStore>,
    token_estimator: iteron_ctx::TokenEstimatorPolicy,
    execution: crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy,
    verification_feedback: iteron_verify::VerificationFeedbackTailPolicy,
    content: crate::runtime_tunables::effective_content::EffectiveContentIdentities,
    app_server_queue: crate::app_server::AppServerQueuePolicy,
    binary_media: crate::image_input::BinaryMediaInspectionPolicy,
    multimodal_decode: crate::image_input::MultimodalDecodeEnvelope,
    effort_policy: crate::runtime_tunables::effective_core::EffortRuntimePolicy,
    compaction_failure: crate::runtime_tunables::effective_core::CompactionFailurePolicy,
    pure_overlap: bool,
    pure_concurrency: usize,
    failed_action_dedup: super::failed_action_cache::FailedActionPolicy,
}

fn apply_pinned_tooling(
    pin: &tunables_pin::TunablesPin,
    registry: &Registry,
    rollout: &Rollout,
) -> Result<AppliedPinnedRuntime, KernelError> {
    let effective =
        crate::runtime_tunables::effective_runtime::decode_checkpoint(pin.checkpoint(), None)
            .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
    let tooling = effective.tooling;
    let pure_overlap = tooling.pure_overlap;
    let pure_concurrency = tooling.pure_concurrency;
    let failed_action_dedup = tooling.failed_action_dedup;
    let core = effective.core;
    let token_estimator = core.token_estimator;
    let execution = core.execution;
    let verification_feedback = core.verification.feedback;
    let content = effective.content;
    let app_server_queue = core.app_server_queue;
    let binary_media = core.binary_media;
    let multimodal_decode = core.multimodal_decode;
    let effort_policy = core.effort_policy;
    let compaction_failure = core.compaction_failure;
    let runs_dir = rollout.path().parent().ok_or(KernelError::ToolOutputSpill(
        "record store resolution failed",
    ))?;
    let store = std::sync::Arc::new(
        tool_output_spill::ToolOutputSpillStore::create_for_run(
            tooling.tool_output_spill,
            runs_dir,
            rollout.tenant().clone(),
            rollout.run_id().clone(),
        )
        .map_err(|_| KernelError::ToolOutputSpill("private store creation failed"))?,
    );
    tooling
        .install(registry)
        .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
    Ok(AppliedPinnedRuntime {
        tool_output_spill: store,
        token_estimator,
        execution,
        verification_feedback,
        content,
        app_server_queue,
        binary_media,
        multimodal_decode,
        effort_policy,
        compaction_failure,
        pure_overlap,
        pure_concurrency,
        failed_action_dedup,
    })
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
        let context_estimator = iteron_ctx::RequestEstimator::new();
        let token_calibration = super::context_runtime::load_token_calibration(&runtime_state_dir);
        #[cfg(test)]
        let context_budget_policy = {
            // Bare-Agent tests deliberately exercise the unbound constructor, but the coding
            // registry is a real physical input: its schemas currently need about 14.6k tokens.
            // Reallocate a fixed 20k slice from transcript to schemas without widening the 120k
            // default window or changing production composition, which always installs the
            // checkpoint-derived policy before its first effect.
            let mut policy = iteron_ctx::ContextBudgetPolicy::default();
            let moved = 20_000usize
                .checked_sub(policy.tool_schema_tokens)
                .expect("default tool-schema slice stays below the test ceiling");
            policy.tool_schema_tokens = 20_000;
            policy.transcript_tokens = policy
                .transcript_tokens
                .checked_sub(moved)
                .expect("default transcript slice covers the test schema reallocation");
            debug_assert!(policy.validate_for_window(120_000).is_ok());
            policy
        };
        #[cfg(not(test))]
        let context_budget_policy = iteron_ctx::ContextBudgetPolicy::default();
        let force_cancel_seam = registry
            .process_control()
            .and_then(super::force_cancel::ForceCancelSeam::for_process_control);
        Agent {
            provider,
            registry,
            tool_output_spill: None,
            rollout,
            runtime_state_dir,
            last_success_route_path: None,
            ledger: Ledger::new(),
            budget,
            model,
            selected_route: None,
            selected_provider: None,
            last_rate_limit: None,
            provider_controls: iteron_provider::ProviderRequestControls::default(),
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
            composition_environment_context: None,
            compaction: CompactionPolicy::default(),
            compaction_failure_policy:
                crate::runtime_tunables::effective_core::CompactionFailurePolicy::RetainOriginal,
            compaction_failed_closed: false,
            compaction_summary_prompt: None,
            compacted_in_run: false,
            last_compaction_turn: None,
            context_estimator,
            token_calibration,
            token_estimate_baselines: std::collections::VecDeque::new(),
            context_refresh_requested: false,
            deferred_tool_eager_limit: None,
            advertised_tool_specs_cache: None,
            context_budget_policy,
            context_materialization_policy: iteron_ctx::ContextMaterializationPolicy::default(),
            context_source_evidence: Vec::new(),
            input_file_evidence: None,
            context_ledgers: iteron_ctx::ContextLedgerStore::default(),
            memory_traces: iteron_ctx::MemoryTraceStore::default(),
            session_memory_visibility: std::collections::VecDeque::new(),
            lifecycle_emitter: None,
            lifecycle_telemetry: None,
            lifecycle_hooks: None,
            workspace: std::path::PathBuf::from("."),
            verify_command: None,
            verification_policy: iteron_verify::VerificationRuntimePolicy::default(),
            execution_policy:
                crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy::fail_closed(),
            app_server_queue_policy: crate::app_server::AppServerQueuePolicy::owner(),
            binary_media_policy: crate::image_input::BinaryMediaInspectionPolicy::owner(),
            multimodal_decode_envelope: crate::image_input::multimodal_decode_envelope(),
            effective_content: None,
            verification_quarantine: std::collections::BTreeMap::new(),
            verification_quarantine_restored: false,
            latest_workspace_checkpoint: None,
            last_workspace_checkpoint_turn: None,
            turn_mutated_workspace: false,
            turn_orchestration_requested: false,
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
            live_unresolved_effects: 0,
            recovery_effect_replay_required: true,
            interrupt: None,
            interrupt_requested: false,
            force_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            force_cancel_requested: false,
            force_cancel_seam,
            max_tool_concurrency: iteron_tunables::param_integer(
                "cli.runtime.default_max_tool_concurrency",
                DEFAULT_MAX_TOOL_CONCURRENCY,
            ),
            pure_overlap_enabled: iteron_tools::Registry::pure_overlap_owner(),
            pure_tool_concurrency: iteron_tunables::param_integer(
                "cli.runtime.default_max_tool_concurrency",
                DEFAULT_MAX_TOOL_CONCURRENCY,
            ),
            session_spawn_ledger: std::sync::Arc::new(SessionSpawnLedger::default()),
            ui_tx: None,
            frontend_saturation: super::frontend::FrontendChannelHealth::default(),
            activity: super::turn_activity::ActivitySink::default(),
            workflow_progress_tx: None,
            workflow_launcher: None,
            mcp_runtime: None,
            effort: iteron_protocol::Effort::default(),
            effort_policy: crate::runtime_tunables::effective_core::EffortRuntimePolicy::compiled(),
            runtime_policy_provenance: runtime_policy_overlay::RuntimePolicyProvenance::default(),
            memory_workspace: None,
            memory_benchmark_scope: None,
            context_strategy: compiled_policy_bundle.slots().context.clone(),
            tool_policy: compiled_policy_bundle.slots().tool_policy.clone(),
            memory_strategy: compiled_policy_bundle.slots().memory.clone(),
            router: compiled_policy_bundle.slots().router.clone(),
            planner: compiled_policy_bundle.slots().planner.clone(),
            collaboration: compiled_policy_bundle.slots().collaboration.clone(),
            scheduler: compiled_policy_bundle.slots().scheduler.clone(),
            retry_policy: iteron_sched::BackoffPolicy::default(),
            verifier: compiled_policy_bundle.slots().verifier.clone(),
            model_router: compiled_policy_bundle.slots().model_router.clone(),
            context_port: std::sync::Arc::new(iteron_ctx::DefaultContextPort),
            context_home_dir: None,
            dependency_skill_dirs: Vec::new(),
            agent_catalog: std::sync::Arc::new(iteron_agents::AgentCatalog::builtin_only()),
            agent_catalog_pinned: false,
            boot_bundle: compiled_policy_bundle.boot_bundle(),
            compiled_policy_bundle,
            policy_evidence: None,
            policy_turn_cost_baseline: None,
            policy_turn_counter_baseline: None,
            policy_verifier_outcome: iteron_protocol::PolicyVerifierOutcome::NotRun,
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
            hooks_runtime_installed: false,
            hook_effect_journal: None,
            telemetry: None,
            run_deadline: None,
            tunables_profile: None,
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
        resolved_tunables: std::sync::Arc<iteron_tunables::ResolvedTunableSet>,
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
        checkpoint: iteron_record::TunablesCheckpoint,
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
        let applied = apply_pinned_tooling(&pin, &registry, &rollout)?;
        let mut agent = Self::new(provider, registry, rollout, model, system, budget);
        agent.tool_output_spill = Some(applied.tool_output_spill);
        agent.context_estimator.pin_policy(applied.token_estimator);
        agent.execution_policy = applied.execution;
        agent.verification_policy.feedback = applied.verification_feedback;
        agent.effective_content = Some(applied.content);
        agent.app_server_queue_policy = applied.app_server_queue;
        agent.binary_media_policy = applied.binary_media;
        agent.multimodal_decode_envelope = applied.multimodal_decode;
        agent.effort_policy = applied.effort_policy;
        agent.compaction_failure_policy = applied.compaction_failure;
        agent.pure_overlap_enabled = applied.pure_overlap;
        agent.pure_tool_concurrency = applied.pure_concurrency;
        agent.failed_actions =
            super::failed_action_cache::FailedActionCache::new(applied.failed_action_dedup);
        agent.tunables_pin = Some(pin);
        Ok(agent)
    }

    /// Install the operator tunables profile this session resolved under.
    ///
    /// Prompt artifacts it carries are model-visible text and only that: the base system prompt is
    /// already replaced this way at the composition root, and a workflow started by this agent
    /// reads `prompt/recovery@v1` from the same document. Capability sets, tool schemas, and every
    /// budget are resolved elsewhere and are not reachable from here.
    pub(crate) fn install_tunables_profile(
        &mut self,
        profile: Option<std::sync::Arc<iteron_tunables::ProfileDocument>>,
    ) {
        self.tunables_profile = profile;
    }

    /// The operator profile a run this agent starts should be resolved under.
    pub(crate) fn tunables_profile(
        &self,
    ) -> Option<std::sync::Arc<iteron_tunables::ProfileDocument>> {
        self.tunables_profile.clone()
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

    /// Effective effort projected in memory. Runtime callers should use [`Self::transition_effort`]
    /// rather than writing the compatibility field directly.
    pub fn effort(&self) -> Effort {
        self.effort
    }

    pub(super) fn effort_thinking_budget(&self, effort: Effort) -> u32 {
        self.effort_policy.thinking_budget(effort)
    }

    pub(super) fn effort_reasoning(&self, effort: Effort) -> iteron_protocol::ReasoningEffort {
        self.effort_policy.reasoning(effort)
    }

    pub(super) fn effort_orchestration(
        &self,
        effort: Effort,
    ) -> iteron_protocol::OrchestrationMode {
        self.effort_policy.orchestration(effort)
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
        let identity = catalog.runtime_identity();
        if let Some(expected) = self
            .effective_content
            .as_ref()
            .map(|content| &content.agent_catalog)
            && expected != &identity
        {
            return Err(KernelError::ExecutionPolicy(
                "executable agent catalog differs from the immutable checkpoint".into(),
            ));
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

    /// Pin a fresh composition root's one atomic tunables result as a V2 checkpoint.
    #[cfg(test)]
    pub fn pin_resolved_tunables(
        &mut self,
        resolved: std::sync::Arc<iteron_tunables::ResolvedTunableSet>,
    ) -> Result<(), KernelError> {
        if self.tunables_pin.is_some() {
            return Err(KernelError::TunablesAlreadyResolved);
        }
        let pin = tunables_pin::TunablesPin::from_resolved(&resolved)?;
        let applied = apply_pinned_tooling(&pin, &self.registry, &self.rollout)?;
        self.tool_output_spill = Some(applied.tool_output_spill);
        self.context_estimator.pin_policy(applied.token_estimator);
        self.execution_policy = applied.execution;
        self.verification_policy.feedback = applied.verification_feedback;
        self.effective_content = Some(applied.content);
        self.app_server_queue_policy = applied.app_server_queue;
        self.binary_media_policy = applied.binary_media;
        self.multimodal_decode_envelope = applied.multimodal_decode;
        self.effort_policy = applied.effort_policy;
        self.compaction_failure_policy = applied.compaction_failure;
        self.pure_overlap_enabled = applied.pure_overlap;
        self.pure_tool_concurrency = applied.pure_concurrency;
        self.failed_actions =
            super::failed_action_cache::FailedActionCache::new(applied.failed_action_dedup);
        self.tunables_pin = Some(pin);
        Ok(())
    }

    pub fn tunables_checkpoint(&self) -> Result<&iteron_record::TunablesCheckpoint, KernelError> {
        self.tunables_pin
            .as_ref()
            .map(tunables_pin::TunablesPin::checkpoint)
            .ok_or(KernelError::TunablesNotResolved)
    }

    pub(crate) const fn app_server_queue_policy(&self) -> crate::app_server::AppServerQueuePolicy {
        self.app_server_queue_policy
    }

    pub(crate) fn tunables_pin_snapshot(&self) -> Result<tunables_pin::TunablesPin, KernelError> {
        self.tunables_pin
            .clone()
            .ok_or(KernelError::TunablesNotResolved)
    }

    pub(super) fn validate_environment_identity(
        &self,
        context: Option<&iteron_protocol::DurableEnvironmentContext>,
    ) -> Result<(), KernelError> {
        let Some(expected) = self
            .effective_content
            .as_ref()
            .map(|content| &content.environment)
        else {
            return Ok(());
        };
        if !expected.matches(context) {
            return Err(KernelError::ExecutionPolicy(
                "runtime environment differs from the immutable environment_snapshot identity"
                    .into(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_workflow_graph_identity(&self) -> Result<(), KernelError> {
        let Some(expected) = self
            .effective_content
            .as_ref()
            .map(|content| &content.workflow_graph)
        else {
            return Ok(());
        };
        if expected != &iteron_workflow::workflow_graph_runtime_identity() {
            return Err(KernelError::ExecutionPolicy(
                "workflow graph runtime differs from the immutable workflow_graph identity".into(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn clear_content_identity_expectations_for_fixture(&mut self) {
        self.effective_content = None;
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
        let sequence = self.rollout.next_sequence();
        let result = commit_effort_transition(
            &mut self.rollout,
            TurnId(self.seq_turn),
            &mut self.effort,
            next,
            source,
        );
        match result {
            Ok(changed) => {
                if changed {
                    self.observe_runtime_policy_commit(
                        &EventKind::EffortChanged {
                            version: RuntimePolicyEventVersion::V1,
                            source,
                            effort: next,
                        },
                        sequence,
                        RuntimePolicyObservation::LiveCommit,
                    );
                }
                Ok(changed)
            }
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
        let sequence = self.rollout.next_sequence();
        let event_kind = EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            mode: next_mode,
            rules: next_rules.clone(),
        };
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
            Ok(changed) => {
                if changed {
                    self.observe_runtime_policy_commit(
                        &event_kind,
                        sequence,
                        RuntimePolicyObservation::LiveCommit,
                    );
                }
                Ok(changed)
            }
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
