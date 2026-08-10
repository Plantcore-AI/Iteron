use super::*;

impl Agent {
    /// Replace the world-facing context adapter before context becomes durable for this run.
    // Pinning seam for the W1 strategy slots. `Agent::new` installs the built-in strategies and
    // every child/workflow agent inherits them by direct field copy.
    #[allow(dead_code)]
    pub fn set_context_port(
        &mut self,
        port: std::sync::Arc<dyn core_ctx::ContextPort>,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        self.context_port = port;
        Ok(())
    }

    /// Install a pinned replacement for `core/context` before the run resolves live context.
    // Pinning seam for the W1 strategy slots. `Agent::new` installs the built-in
    // strategies and every child/workflow agent inherits them by direct field copy, so the
    // override is exercised by conformance tests rather than the composition root. It was a
    // library-public method before the runtime moved into this binary.
    #[allow(dead_code)]
    pub fn set_context_strategy(
        &mut self,
        strategy: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if strategy.slot().as_persisted_str() != "core/context" {
            return Err(KernelError::ContextResolution(
                "context strategy has the wrong slot identity".into(),
            ));
        }
        self.context_strategy = strategy;
        Ok(())
    }

    /// Install a pinned replacement for `core/tool_policy` before provider execution starts.
    // Pinning seam for the W1 strategy slots. `Agent::new` installs the built-in
    // strategies and every child/workflow agent inherits them by direct field copy, so the
    // override is exercised by conformance tests rather than the composition root. It was a
    // library-public method before the runtime moved into this binary.
    #[allow(dead_code)]
    pub fn set_tool_policy(
        &mut self,
        policy: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if policy.slot().as_persisted_str() != "core/tool_policy" {
            return Err(KernelError::ContextResolution(
                "tool policy has the wrong slot identity".into(),
            ));
        }
        self.tool_policy = policy;
        Ok(())
    }

    /// Install a pinned replacement for `core/memory` before context is resolved.
    #[allow(dead_code)]
    pub fn set_memory_strategy(
        &mut self,
        strategy: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if strategy.slot().as_persisted_str() != "core/memory" {
            return Err(KernelError::ContextResolution(
                "memory strategy has the wrong slot identity".into(),
            ));
        }
        self.memory_strategy = strategy;
        Ok(())
    }

    /// Give the resident control plane the exact workspace, policy object and current turn that
    /// own a memory mutation; the frontend never receives or reimplements this authority.
    pub(crate) fn memory_control_context(
        &self,
    ) -> Option<(
        std::path::PathBuf,
        std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
        core_protocol::TurnId,
    )> {
        self.memory_workspace.clone().map(|workspace| {
            (
                workspace,
                self.memory_strategy.clone(),
                core_protocol::TurnId(self.seq_turn),
            )
        })
    }

    /// Install a pinned replacement for `core/router` before any submission is routed.
    ///
    /// The same pinning seam the sibling slots use: `Agent::new` installs the built-in baseline and
    /// every child/workflow agent inherits it by direct field copy, so a replacement classifier
    /// (ADR-011) arrives here rather than by editing the heuristic.
    #[allow(dead_code)]
    pub fn set_router(
        &mut self,
        router: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if router.slot().as_persisted_str() != "core/router" {
            return Err(KernelError::ContextResolution(
                "router has the wrong slot identity".into(),
            ));
        }
        self.router = router;
        Ok(())
    }

    /// Install a pinned replacement for `core/planner` before any fan plan is materialized.
    #[allow(dead_code)]
    pub fn set_planner(
        &mut self,
        planner: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if planner.slot().as_persisted_str() != "core/planner" {
            return Err(KernelError::ContextResolution(
                "planner has the wrong slot identity".into(),
            ));
        }
        self.planner = planner;
        Ok(())
    }

    /// Install a pinned replacement for `core/collaboration` before fan execution is admitted.
    #[allow(dead_code)]
    pub fn set_collaboration(
        &mut self,
        collaboration: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if collaboration.slot().as_persisted_str() != "core/collaboration" {
            return Err(KernelError::ContextResolution(
                "collaboration strategy has the wrong slot identity".into(),
            ));
        }
        self.collaboration = collaboration;
        Ok(())
    }

    /// Install a pinned replacement for `core/scheduler` before concurrent work is dispatched.
    #[allow(dead_code)]
    pub fn set_scheduler(
        &mut self,
        scheduler: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if scheduler.slot().as_persisted_str() != "core/scheduler" {
            return Err(KernelError::ContextResolution(
                "scheduler has the wrong slot identity".into(),
            ));
        }
        self.scheduler = scheduler;
        Ok(())
    }

    /// Install a pinned replacement for `core/verifier` before the completion gate is reached.
    #[allow(dead_code)]
    pub fn set_verifier(
        &mut self,
        verifier: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if verifier.slot().as_persisted_str() != "core/verifier" {
            return Err(KernelError::ContextResolution(
                "verifier has the wrong slot identity".into(),
            ));
        }
        self.verifier = verifier;
        Ok(())
    }

    /// Install a pinned replacement for `core/model_router` before any delegated route is chosen.
    #[allow(dead_code)]
    pub fn set_model_router(
        &mut self,
        router: std::sync::Arc<dyn core_protocol::slot::StrategySlot>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if router.slot().as_persisted_str() != "core/model_router" {
            return Err(KernelError::ContextResolution(
                "model router has the wrong slot identity".into(),
            ));
        }
        self.model_router = router;
        Ok(())
    }

    /// Supply the operator home explicitly from the composition root; no ambient lookup occurs in
    /// either the kernel or the context port.
    pub fn set_context_home_dir(
        &mut self,
        home_dir: Option<std::path::PathBuf>,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        self.context_home_dir = home_dir;
        Ok(())
    }

    /// Activate strict memory isolation for one benchmark attempt. Only the digest crosses into
    /// runtime evidence; the corpus identifier itself is not retained in session state.
    pub fn set_memory_benchmark_scope(&mut self, scope: &str) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        if scope.is_empty() || scope.len() > 1_024 {
            return Err(KernelError::ContextResolution(
                "benchmark memory scope must contain 1..=1024 bytes".into(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(scope.as_bytes());
        self.memory_benchmark_scope = Some(hasher.finalize().into());
        Ok(())
    }

    pub(crate) fn has_memory_benchmark_scope(&self) -> bool {
        self.memory_benchmark_scope.is_some()
    }

    pub fn set_retry_policy(&mut self, policy: core_sched::BackoffPolicy) {
        self.retry_policy = policy;
    }

    pub fn set_dependency_skill_dirs(
        &mut self,
        directories: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        self.dependency_skill_dirs = directories;
        Ok(())
    }

    pub(crate) fn dependency_skill_dirs(&self) -> &[(std::path::PathBuf, std::path::PathBuf)] {
        &self.dependency_skill_dirs
    }

    /// Atomically install one compiler-validated nine-slot policy generation before turn zero.
    /// Validation happens before the first assignment, so an invalid checkpoint or a late caller
    /// cannot leave a mixture of old and new strategy Arcs on the agent.
    pub(crate) fn install_compiled_policy_bundle(
        &mut self,
        compiled: std::sync::Arc<crate::bundle_adapter::CompiledPolicyBundle>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        let slots = compiled.slots();
        for (strategy, expected) in [
            (&slots.context, "core/context"),
            (&slots.tool_policy, "core/tool_policy"),
            (&slots.memory, "core/memory"),
            (&slots.router, "core/router"),
            (&slots.planner, "core/planner"),
            (&slots.collaboration, "core/collaboration"),
            (&slots.scheduler, "core/scheduler"),
            (&slots.verifier, "core/verifier"),
            (&slots.model_router, "core/model_router"),
        ] {
            if strategy.slot().as_persisted_str() != expected {
                return Err(KernelError::ContextResolution(format!(
                    "compiled policy strategy has the wrong slot identity: expected {expected}"
                )));
            }
        }
        self.context_strategy = slots.context.clone();
        self.tool_policy = slots.tool_policy.clone();
        self.memory_strategy = slots.memory.clone();
        self.router = slots.router.clone();
        self.planner = slots.planner.clone();
        self.collaboration = slots.collaboration.clone();
        self.scheduler = slots.scheduler.clone();
        self.verifier = slots.verifier.clone();
        self.model_router = slots.model_router.clone();
        self.boot_bundle = compiled.boot_bundle();
        self.compiled_policy_bundle = compiled;
        Ok(())
    }

    pub(crate) fn policy_runtime_bindings(
        &self,
    ) -> &[super::policy_evidence_recorder::FrozenSlotPolicyBinding] {
        self.compiled_policy_bundle.policy_runtime_bindings()
    }

    /// Install the already-discovered, already-framed instruction bytes proposed by the context
    /// strategy. The kernel never walks instruction files itself; it bounds and applies the same
    /// record-safe redaction used by the durable chokepoint before admitting the value, so fresh
    /// and replayed provider bytes cannot diverge around a credential-shaped token. On resume a
    /// recorded ContextInjection is authoritative; this proposal is only a legacy fallback.
    pub fn set_instruction_context(
        &mut self,
        text: String,
        trust: Trust,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::InstructionContextAlreadyResolved);
        }
        let max = core_ctx::MAX_MERGED_INSTRUCTION_BYTES;
        if text.len() > max {
            return Err(KernelError::InstructionContextTooLarge {
                bytes: text.len(),
                max,
            });
        }
        let text = core_record::redact::scrub(&text);
        if text.len() > max {
            return Err(KernelError::InstructionContextTooLarge {
                bytes: text.len(),
                max,
            });
        }
        let trust = if text.is_empty() {
            Trust::Trusted
        } else {
            trust
        };
        // Retained beyond the first resolution so [`Self::adopt_run`] can re-propose it. The live
        // proposal is consumed and cleared once the run records its ContextInjection; a session that
        // then adopts a run whose record has no injection of its own (a session that never took a
        // turn) would otherwise resolve with no operator instructions at all, silently weaker than
        // what `--resume` gives the same record in a fresh process.
        self.composition_instruction_context = Some((text.clone(), trust));
        self.instruction_context = Some((text, trust));
        Ok(())
    }

    /// Install a frontend-observed, already-framed fresh-start environment snapshot. The kernel
    /// never reads the wall clock or spawns Git: it only bounds, scrubs, durably records, and later
    /// replays the proposal. Resume frontends must omit this call; recorded context is authoritative
    /// even if a caller nevertheless supplies a live proposal.
    pub fn set_environment_context(
        &mut self,
        text: String,
        trust: Trust,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Err(KernelError::EnvironmentContextAlreadyResolved);
        }
        let max = MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES;
        if text.len() > max {
            return Err(KernelError::EnvironmentContextTooLarge {
                bytes: text.len(),
                max,
            });
        }
        let text = core_record::redact::scrub(&text);
        if text.len() > max {
            return Err(KernelError::EnvironmentContextTooLarge {
                bytes: text.len(),
                max,
            });
        }
        let trust = if text.is_empty() {
            Trust::Trusted
        } else {
            trust
        };
        self.environment_context = Some((text, trust));
        Ok(())
    }
}
