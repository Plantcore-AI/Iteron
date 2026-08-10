use super::*;

impl Agent {
    /// Ask the installed owner about a run, or say plainly that there is no owner.
    ///
    /// `Agent` deliberately holds no run state of its own: a second copy of "which runs are live"
    /// inside the turn's `&mut` borrow is exactly the coupling this slice removes.
    pub(super) fn owned_workflow(&self, run_id: &str, stop: bool) -> crate::workflow::Collected {
        let owner: &dyn crate::workflow::WorkflowLauncher = match self.workflow_launcher.as_ref() {
            Some(owner) => owner.as_ref(),
            None => &crate::workflow::InTurnWorkflowLauncher,
        };
        if stop {
            owner.cancel(run_id)
        } else {
            owner.collect(run_id)
        }
    }

    /// Render one owner answer as a tool result. `Failed` is the only error arm: an unknown id and a
    /// still-running run are both true answers to the question the model asked.
    pub(super) fn collected_workflow(
        &self,
        collected: crate::workflow::Collected,
    ) -> Result<String, String> {
        match collected {
            crate::workflow::Collected::Unknown(message) => Ok(message),
            crate::workflow::Collected::Running {
                run_id,
                name,
                elapsed_ms,
            } => Ok(format!(
                "Workflow `{name}` (run {run_id}) is still RUNNING after {}s. It has produced no \
                 result yet. Do other work and call Workflow({{\"collect\":\"{run_id}\"}}) again; \
                 do not treat this as an outcome.",
                elapsed_ms / 1000
            )),
            crate::workflow::Collected::Settled { summary } => Ok(summary),
            // The only error arm, and it names the run: an error that does not say WHICH run failed
            // is unusable once more than one is in flight.
            crate::workflow::Collected::Failed { run_id, error } => {
                Err(format!("Workflow run {run_id}: {error}"))
            }
        }
    }

    pub(super) async fn spawn_subagent(
        &mut self,
        subtask: &str,
        ordinal: usize,
    ) -> Result<String, String> {
        if self.delegation_depth >= MAX_DELEGATION_DEPTH {
            return Err(KernelError::DelegationDepthExceeded.public_summary());
        }
        if let Some(reason) = self
            .inference_budget_exhaustion()
            .map_err(|error| error.public_summary())?
        {
            return Err(format!(
                "subagent was not started: parent inference budget exhausted ({reason})"
            ));
        }
        if self.run_deadline_exhausted() {
            return Err("subagent was not started: parent run wall deadline exhausted".into());
        }
        // Prove the child budget before creating its rollout or recording SubagentSpawned.  A
        // durable spawn event is a statement that a child was admitted, not merely attempted.
        let remaining_wall = self
            .run_time_remaining()
            .map(|remaining| remaining.as_secs().max(1))
            .unwrap_or(300);
        let remaining_turns = self.remaining_inference_turns();
        let Some(budget) = core_agents::subagent_budget(
            remaining_turns,
            remaining_wall,
            self.remaining_provider_tokens(),
        ) else {
            return Err(
                "subagent was not started: writer-first reserve left no safe child budget".into(),
            );
        };
        let spawn_turn = TurnId(self.seq_turn);
        let sub_run = self.subagent_run_id("direct", self.seq_turn, ordinal);
        let gate = self
            .brokered_child_lifecycle_gate(
                spawn_turn,
                "workflow.child_proposed",
                &sub_run.0,
                LifecyclePayload::default(),
            )
            .await
            .map_err(|error| error.public_summary())?;
        if let hooks::HookDecision::Deny(reason) = gate.decision {
            return Err(format!("subagent was not started: {reason}"));
        }
        let _session_admission = self
            .session_spawn_ledger
            .admit()
            .map_err(|error| format!("subagent was not started: {error}"))?;
        let mut registry = match Registry::read_only(&self.workspace) {
            Ok(r) => r,
            Err(e) => return Err(format!("subagent setup failed: {e}")),
        };
        let _effective_tools = crate::bundle_adapter::narrow_child_registry(
            &mut registry,
            &core_agents::ToolFilter::All,
            &self.boot_bundle,
        );
        let tunables_pin = self
            .tunables_pin_snapshot()
            .map_err(|error| error.public_summary())?;
        let tunables_resolution_digest = tunables_pin.resolution_digest_sha256().to_owned();
        let sub_dir = self.subagent_directory();
        let rollout = match Rollout::open(&sub_dir, &sub_run, self.rollout.tenant().clone()) {
            Ok(r) => r,
            Err(e) => return Err(format!("subagent rollout failed: {e}")),
        };
        if self
            .emit_durable(
                TurnId(self.seq_turn),
                EventKind::SubagentSpawned {
                    sub_run: sub_run.0.clone(),
                    agent: "direct-investigator".into(),
                },
            )
            .is_err()
        {
            return Err("subagent was not started: parent record failed".into());
        }
        let agent_def = core_agents::AgentDef::generic();
        let agent_definition_tag = agent_def.execution_tag();
        let child_deadline = self.child_run_deadline(&budget);
        let mut sub = Agent::new_with_tunables_pin(
            self.provider.clone(),
            registry,
            rollout,
            self.model.clone(),
            agent_def.system,
            budget,
            tunables_pin,
        )
        .map_err(|error| error.public_summary())?;
        sub.projection_attribution = Some(CostAttribution::DirectSubagent {
            parent_run_id: self.rollout.run_id().0.clone(),
            sub_run: sub_run.0.clone(),
        });
        sub.runtime_state_dir = self.runtime_state_dir.clone();
        sub.session_spawn_ledger = self.session_spawn_ledger.clone();
        sub.lifecycle_emitter = self.lifecycle_emitter.clone();
        sub.lifecycle_telemetry = self.lifecycle_telemetry.clone();
        sub.lifecycle_hooks = self.lifecycle_hooks.clone();
        sub.workspace = self.workspace.clone();
        sub.install_compiled_policy_bundle(self.compiled_policy_bundle.clone())
            .map_err(|error| error.public_summary())?;
        sub.context_port = self.context_port.clone();
        sub.deferred_tool_eager_limit = self.deferred_tool_eager_limit;
        sub.context_budget_policy = self.context_budget_policy;
        sub.context_materialization_policy = self.context_materialization_policy;
        sub.compaction = self.compaction;
        sub.context_home_dir = self.context_home_dir.clone();
        sub.dependency_skill_dirs = self.dependency_skill_dirs.clone();
        sub.model_context_window = self.model_context_window;
        sub.model_max_output_tokens = self.model_max_output_tokens;
        sub.sensitive_env_names = self.sensitive_env_names.clone();
        // Hooks are resolved once from trusted operator configuration at the composition root.
        // Children inherit that exact value; they never re-read ambient or repository config.
        sub.hooks = self.hooks.clone();
        sub.hook_effect_journal = self.hook_effect_journal.clone();
        sub.delegation_depth = self.delegation_depth.saturating_add(1);
        let child_effort = if self.effort == core_protocol::Effort::Ultracode {
            core_protocol::Effort::Max
        } else {
            self.effort
        };
        sub.bypass_permissions = self.bypass_permissions;
        sub.configure_initial_runtime_policy(
            child_effort,
            self.permission_mode,
            self.permission_rules.clone(),
        )
        .map_err(|error| error.public_summary())?;
        sub.run_deadline = Some(child_deadline);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let parent_run = self.rollout.run_id().clone();
        sub.record_child_genesis_with_tunables(
            &parent_run,
            self.workspace.display().to_string(),
            created_at,
            tunables_resolution_digest,
            Some(agent_definition_tag),
        )
        .map_err(|error| error.public_summary())?;
        self.inherit_route_and_pricing(&mut sub)
            .map_err(|error| error.public_summary())?;
        // No interrupt flag is installed here on purpose. `run_child_with_control` below owns the
        // child's stop surface: it mints a call-scoped flag and republishes BOTH of the parent's
        // stop surfaces onto it. Inheriting the parent's optional atomic here as well would give
        // the child two flags, only one of which the queued-`Op::Interrupt` operator can ever set.
        sub.drain = self.drain.clone();
        sub.owns_drain = false;
        let prompt = format!(
            "{subtask}\n\nReturn a concise summary with file:line references. Do not attempt to edit anything."
        );
        // Spawning a subagent starts a process that makes its own paid calls and its own tool
        // dispatches. It is an effect of the parent even though every effect the child performs is
        // brokered in the child's own journal, so the parent's write-ahead intent is opened here —
        // after every admission check, so no early return can drop the ticket, and immediately
        // before the only line that actually runs the child.
        let spawn_class = effect_class::EffectClass::Subagent;
        let spawn_ordinal = self.next_effect_ordinal(spawn_turn, spawn_class);
        let ticket = self
            .open_kernel_effect(
                spawn_turn,
                spawn_class,
                spawn_ordinal,
                Capability::CodeExecuting,
                serde_json::json!({ "sub_run": sub_run.0.clone() }),
            )
            .map_err(|error| error.public_summary())?;
        self.child_lifecycle_event(
            "workflow.child_started",
            spawn_turn,
            &sub_run.0,
            LifecyclePayload::default(),
        );
        // The recursive child future is boxed inside `run_child_with_control`. One level only: a
        // subagent has no dispatch_agent tool, so this cannot recurse unboundedly.
        let outcome = self.run_child_with_control(&mut sub, &prompt).await;
        // The child returned, so the spawn's terminal is proven either way: a failed child is a
        // failed effect, not an unobservable one.
        let spawn_settlement = match &outcome {
            Ok(_) => effects::Settlement::Definite(effect_done_terminal(
                spawn_turn,
                spawn_class,
                spawn_ordinal,
            )),
            Err(error) => effects::Settlement::Definite(effect_failed_terminal(
                spawn_turn,
                spawn_class,
                spawn_ordinal,
                &error.public_summary(),
            )),
        };
        self.settle_kernel_effect(ticket, spawn_settlement)
            .map_err(|error| error.public_summary())?;
        let (result, child_outcome, error_code, error_detail) = match outcome {
            Ok(Outcome::Done) => {
                let s = strict_utf8_head(sub.last_assistant_text.trim(), 16 * 1024);
                if s.is_empty() {
                    (
                        Err("subagent completed without a summary".into()),
                        core_protocol::WorkflowChildOutcome::Failed,
                        Some("empty_report".into()),
                        Some("direct investigator completed without a report".into()),
                    )
                } else {
                    (Ok(s), core_protocol::WorkflowChildOutcome::Done, None, None)
                }
            }
            Ok(Outcome::Interrupted) => (
                Err("subagent interrupted at a safe point".into()),
                core_protocol::WorkflowChildOutcome::Interrupted,
                Some("operator_stop".into()),
                Some("direct investigator interrupted at a safe point".into()),
            ),
            Ok(Outcome::Drained) => (
                Err("subagent drained after a checkpoint".into()),
                core_protocol::WorkflowChildOutcome::Drained,
                Some("operator_drain".into()),
                Some("direct investigator drained after a durable checkpoint".into()),
            ),
            Ok(Outcome::BudgetExhausted(_)) => (
                Err("subagent exhausted its bounded budget".into()),
                core_protocol::WorkflowChildOutcome::Failed,
                Some("child_budget_exhausted".into()),
                Some("direct investigator exhausted its bounded budget".into()),
            ),
            Ok(Outcome::Stuck) => (
                Err("subagent reached the tool-error limit".into()),
                core_protocol::WorkflowChildOutcome::Failed,
                Some("child_tool_error_limit".into()),
                Some("direct investigator reached the tool-error limit".into()),
            ),
            Ok(Outcome::HarnessError) => (
                Err("subagent stopped on a harness error".into()),
                core_protocol::WorkflowChildOutcome::Failed,
                Some("child_harness_error".into()),
                Some("direct investigator stopped on a harness error".into()),
            ),
            Err(error) => {
                let detail = error.public_summary();
                (
                    Err(format!("subagent error: {detail}")),
                    core_protocol::WorkflowChildOutcome::Failed,
                    Some("child_kernel_error".into()),
                    Some(detail),
                )
            }
        };
        let metrics = sub.ledger.workflow_metrics();
        let (summary_digest, evidence_bytes) = match &result {
            Ok(summary) => (
                Some(sha256_hex(summary)),
                summary.len().min(u32::MAX as usize) as u32,
            ),
            Err(_) => (None, 0),
        };
        let child_succeeded = matches!(&child_outcome, core_protocol::WorkflowChildOutcome::Done);
        let child_outcome_code = format!("{child_outcome:?}").to_ascii_lowercase();
        let child_run_id = sub_run.0.clone();
        self.emit_durable(
            TurnId(self.seq_turn),
            EventKind::SubagentFinishedV2 {
                version: core_protocol::WorkflowEventVersion::V2,
                sub_run: sub_run.0,
                outcome: child_outcome,
                metrics,
                error_code,
                error_detail,
                summary_digest,
                evidence_bytes,
            },
        )
        .map_err(|_| "subagent finished but parent terminal record failed".to_string())?;
        self.child_lifecycle_event(
            if child_succeeded {
                "workflow.child_completed"
            } else {
                "workflow.child_failed"
            },
            spawn_turn,
            &child_run_id,
            LifecyclePayload {
                outcome_code: Some(child_outcome_code),
                ..LifecyclePayload::default()
            },
        );
        self.merge_child_ledger(&sub.ledger);
        result
    }
}
