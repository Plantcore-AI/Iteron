use super::*;

/// Ceiling for one side conversation. Deliberately independent from the parent's remaining turn
/// budget; a side conversation must not silently consume the main session's allowance.
const MAX_TURNS: u32 = 24;
const MAX_WALL_SECS: u64 = 300;
const MAX_CONSECUTIVE_TOOL_ERRORS: u32 = 3;

const SYSTEM: &str = "You are answering a question on the side of a coding session. You have \
read-only tools: you can read files, glob, search, and inspect the repository, but you cannot edit \
files, run commands, or delegate. Answer the operator directly and cite file:line when you looked \
something up. This conversation is separate from the operator's main session — nothing you say \
enters that transcript — so do not assume you can see what happened there, and ask for the \
context you need instead of guessing.";

/// An operator-opened conversation with its own context, cost ledger and append-only record.
pub struct SideConversation {
    pub(super) agent: Agent,
    run_id: core_protocol::RunId,
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
        if self.delegation_depth >= MAX_DELEGATION_DEPTH {
            return Err(KernelError::DelegationDepthExceeded.public_summary());
        }
        let registry = Registry::read_only(&self.workspace)
            .map_err(|error| format!("side conversation setup failed: {error}"))?;
        let directory = self.side_conversation_directory();
        let run_id = self.subagent_run_id("side", 0, self.side_conversations_opened as usize);
        let rollout = Rollout::open(&directory, &run_id, self.rollout.tenant().clone())
            .map_err(|error| format!("side conversation record failed: {error}"))?;
        let record_path = rollout.path().to_path_buf();
        let mut side = Agent::new(
            self.provider.clone(),
            registry,
            rollout,
            self.model.clone(),
            SYSTEM.into(),
            Budget {
                max_turns: MAX_TURNS,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: MAX_WALL_SECS,
                max_consecutive_tool_errors: MAX_CONSECUTIVE_TOOL_ERRORS,
            },
        );
        side.runtime_state_dir = self.runtime_state_dir.clone();
        side.lifecycle_emitter = self.lifecycle_emitter.clone();
        side.lifecycle_telemetry = self.lifecycle_telemetry.clone();
        side.lifecycle_hooks = self.lifecycle_hooks.clone();
        side.workspace = self.workspace.clone();
        side.context_strategy = self.context_strategy.clone();
        side.tool_policy = self.tool_policy.clone();
        side.context_port = self.context_port.clone();
        side.context_home_dir = self.context_home_dir.clone();
        side.dependency_skill_dirs = self.dependency_skill_dirs.clone();
        side.model_context_window = self.model_context_window;
        side.model_max_output_tokens = self.model_max_output_tokens;
        side.sensitive_env_names = self.sensitive_env_names.clone();
        side.hooks = self.hooks.clone();
        side.hook_effect_journal = self.hook_effect_journal.clone();
        side.delegation_depth = self.delegation_depth.saturating_add(1);
        side.effort = if self.effort == core_protocol::Effort::Ultracode {
            core_protocol::Effort::Max
        } else {
            self.effort
        };
        if let Some(interrupt) = &self.interrupt {
            side.set_interrupt(interrupt.clone());
        }
        side.drain = self.drain.clone();
        side.owns_drain = false;
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
