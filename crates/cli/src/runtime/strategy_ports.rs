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

    /// Install the operator-selected active bundle before any child registry is constructed.
    pub fn set_boot_bundle(
        &mut self,
        bundle: std::sync::Arc<core_agents::BootBundle>,
    ) -> Result<(), KernelError> {
        if self.seq_turn != 0 || self.injected.is_some() {
            return Err(KernelError::ContextAlreadyResolved);
        }
        self.boot_bundle = bundle;
        Ok(())
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
