use super::*;

const SYSTEM: &str = "You are answering a question on the side of a coding session. You have \
read-only tools: you can read files, glob, search, and inspect the repository, but you cannot edit \
files, run commands, or delegate. Answer the operator directly and cite file:line when you looked \
something up. This conversation is separate from the operator's main session — nothing you say \
enters that transcript — so do not assume you can see what happened there, and ask for the \
context you need instead of guessing.";

/// Child-genesis `created_at` written when the host clock reads before the Unix epoch; the side
/// conversation still opens, with an unusable stamp.
const CLOCK_BEFORE_EPOCH_SECS: u64 = 0;

/// An operator-opened conversation with its own context, cost ledger and append-only record.
pub struct SideConversation {
    pub(super) agent: Agent,
    run_id: iteron_protocol::RunId,
    record_path: std::path::PathBuf,
    asks: u32,
}

#[derive(Debug, Clone)]
pub struct SideAnswer {
    pub text: String,
    pub outcome: Outcome,
    pub status: SideStatus,
}

#[derive(Debug, Clone)]
pub struct SideStatus {
    pub run_id: String,
    pub record_path: std::path::PathBuf,
    pub asks: u32,
    pub turns: u32,
    pub cost: CostState,
    pub ledger_summary: String,
}

impl SideConversation {
    pub fn status(&self) -> SideStatus {
        SideStatus {
            run_id: self.run_id.0.clone(),
            record_path: self.record_path.clone(),
            asks: self.asks,
            turns: self.agent.ledger.turns,
            cost: self.agent.ledger.cost_state(),
            ledger_summary: self.agent.ledger.summary(),
        }
    }

    pub async fn ask(&mut self, text: &str) -> Result<SideAnswer, String> {
        if text.trim().is_empty() {
            return Err("a side conversation needs a question".into());
        }
        if self.asks > 0 {
            self.agent
                .stage_follow_up_transcript()
                .await
                .map_err(|error| error.public_summary())?;
            self.agent.verify_attempts = 0;
        }
        let outcome = self
            .agent
            .run_leaf(text)
            .await
            .map_err(|error| error.public_summary())?;
        self.asks = self.asks.saturating_add(1);
        Ok(SideAnswer {
            text: self.agent.last_assistant_text().to_owned(),
            outcome,
            status: self.status(),
        })
    }

    pub(crate) fn finalize_policy_run(&mut self) -> Result<(), KernelError> {
        self.agent.finalize_policy_run()
    }
}

impl Agent {
    /// Side records are siblings of `subagents/`, never candidates for `--continue`.
    pub fn side_conversation_directory(&self) -> std::path::PathBuf {
        self.rollout
            .path()
            .parent()
            .map(|parent| parent.join("side"))
            .unwrap_or_else(|| std::env::temp_dir().join("core-side-refused"))
    }

    pub fn open_side_conversation(&mut self) -> Result<SideConversation, String> {
        if self.delegation_depth
            >= iteron_tunables::param_integer(
                "cli.runtime.max_delegation_depth",
                MAX_DELEGATION_DEPTH,
            )
        {
            return Err(KernelError::DelegationDepthExceeded.public_summary());
        }
        let registry = Registry::read_only(&self.workspace)
            .map_err(|error| format!("side conversation setup failed: {error}"))?;
        let directory = self.side_conversation_directory();
        let run_id = self.subagent_run_id("side", 0, self.side_conversations_opened as usize);
        let tunables_pin = self
            .tunables_pin_snapshot()
            .map_err(|error| error.public_summary())?;
        let tunables_config_digest = format!("sha256:{}", tunables_pin.resolution_digest_sha256());
        let rollout = Rollout::open(&directory, &run_id, self.rollout.tenant().clone())
            .map_err(|error| format!("side conversation record failed: {error}"))?;
        let record_path = rollout.path().to_path_buf();
        let mut side = Agent::new_with_tunables_pin(
            self.provider.clone(),
            registry,
            rollout,
            self.model.clone(),
            iteron_tunables::param_str("cli.runtime.side_conversation.system", SYSTEM).into(),
            // A side conversation owns a separate ledger, so it does not consume the main
            // session's allowance. Its *ceilings* must nevertheless be the exact values named by
            // the inherited immutable tunables checkpoint. Installing a second local default here
            // would make the child record claim one budget while enforcing another one.
            self.budget.clone(),
            tunables_pin,
        )
        .map_err(|error| error.public_summary())?;
        side.runtime_state_dir = self.runtime_state_dir.clone();
        side.lifecycle_emitter = self.lifecycle_emitter.clone();
        side.lifecycle_telemetry = self.lifecycle_telemetry.clone();
        side.lifecycle_hooks = self.lifecycle_hooks.clone();
        side.workspace = self.workspace.clone();
        side.install_compiled_policy_bundle(self.compiled_policy_bundle.clone())
            .map_err(|error| error.public_summary())?;
        side.context_port = self.context_port.clone();
        side.deferred_tool_eager_limit = self.deferred_tool_eager_limit;
        side.context_budget_policy = self.context_budget_policy;
        side.context_materialization_policy = self.context_materialization_policy;
        side.compaction = self.compaction;
        side.context_home_dir = self.context_home_dir.clone();
        side.dependency_skill_dirs = self.dependency_skill_dirs.clone();
        side.model_context_window = self.model_context_window;
        side.model_max_output_tokens = self.model_max_output_tokens;
        side.sensitive_env_names = self.sensitive_env_names.clone();
        side.install_hooks(self.hooks.clone())
            .map_err(|error| error.public_summary())?;
        side.hook_effect_journal = self.hook_effect_journal.clone();
        side.composition_environment_context = self.composition_environment_context.clone();
        side.environment_context = self.composition_environment_context.clone();
        side.delegation_depth = self.delegation_depth.saturating_add(1);
        let child_effort = self.execution_policy.subagent_effort;
        side.bypass_permissions = self.bypass_permissions;
        side.configure_initial_runtime_policy(
            child_effort,
            self.permission_mode,
            self.permission_rules.clone(),
        )
        .map_err(|error| error.public_summary())?;
        if let Some(interrupt) = &self.interrupt {
            side.set_interrupt(interrupt.clone());
        }
        side.drain = self.drain.clone();
        side.owns_drain = false;
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.side_conversation.clock_before_epoch_secs",
                CLOCK_BEFORE_EPOCH_SECS,
            ));
        let parent_run = self.rollout.run_id().clone();
        side.record_child_genesis_with_tunables(
            &parent_run,
            self.workspace.display().to_string(),
            created_at,
            tunables_config_digest,
            None,
        )
        .map_err(|error| error.public_summary())?;
        self.inherit_route_and_pricing(&mut side)
            .map_err(|error| error.public_summary())?;
        self.side_conversations_opened = self.side_conversations_opened.saturating_add(1);
        Ok(SideConversation {
            agent: side,
            run_id,
            record_path,
            asks: 0,
        })
    }
}
