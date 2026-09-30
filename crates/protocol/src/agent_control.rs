//! Versioned persistent-agent control vocabulary. Authority is bound by the host transport;
//! commands deliberately contain no sender identity or controller privilege field.

use crate::capability_set::CapabilitySet;
use serde::{Deserialize, Serialize};

pub const AGENT_CONTROL_VERSION: u32 = 1;
pub const MAX_AGENT_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_AGENT_LABEL_BYTES: usize = 128;
pub const MAX_AGENT_WRITE_PATHS: usize = 64;
pub const MAX_AGENT_WRITE_PATH_BYTES: usize = 2_048;
pub const MAX_AGENT_REQUEST_ID_BYTES: usize = 128;

/// Durable persistent agent identity. Explicit declaration is visible to protocol source census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentIdV1(pub u64);

/// Durable mailbox identity; it is distinct from an agent or provider request identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentMessageIdV1(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEpochV1 {
    pub incarnation: u64,
    pub turn: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBudgetV1 {
    pub turns: u32,
    pub tokens: u64,
    pub cost_microusd: u64,
    pub wall_ms: u64,
}

impl AgentBudgetV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.turns == 0 || self.tokens == 0 || self.wall_ms == 0 {
            return Err("agent turn, token and wall budgets must be positive and bounded");
        }
        if self.turns > 1_000_000
            || self.tokens > 100_000_000_000
            || self.cost_microusd > 100_000_000_000_000
            || self.wall_ms > 2_592_000_000
        {
            return Err("agent budget exceeds a hard envelope");
        }
        Ok(())
    }

    pub fn fits_within(self, parent: Self) -> bool {
        self.turns <= parent.turns
            && self.tokens <= parent.tokens
            && self.cost_microusd <= parent.cost_microusd
            && self.wall_ms <= parent.wall_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentCommandV1 {
    Spawn {
        parent_id: AgentIdV1,
        label: String,
        task: String,
        capabilities: CapabilitySet,
        budget: AgentBudgetV1,
        #[serde(default)]
        write_paths: Vec<String>,
    },
    SendMessage {
        agent_id: AgentIdV1,
        text: String,
    },
    FollowupTask {
        agent_id: AgentIdV1,
        text: String,
    },
    Steer {
        agent_id: AgentIdV1,
        epoch: AgentEpochV1,
        text: String,
    },
    Interrupt {
        agent_id: AgentIdV1,
        epoch: AgentEpochV1,
    },
    Close {
        agent_id: AgentIdV1,
        include_descendants: bool,
    },
}

impl AgentCommandV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        let target = match self {
            Self::Spawn {
                parent_id,
                label,
                task,
                budget,
                write_paths,
                ..
            } => {
                validate_label(label)?;
                validate_text(task)?;
                budget.validate()?;
                validate_write_paths(write_paths)?;
                *parent_id
            }
            Self::SendMessage { agent_id, text } | Self::FollowupTask { agent_id, text } => {
                validate_text(text)?;
                *agent_id
            }
            Self::Steer {
                agent_id,
                epoch,
                text,
            } => {
                validate_epoch(*epoch)?;
                validate_text(text)?;
                *agent_id
            }
            Self::Interrupt { agent_id, epoch } => {
                validate_epoch(*epoch)?;
                *agent_id
            }
            Self::Close { agent_id, .. } => *agent_id,
        };
        if target.0 == 0 {
            return Err("agent identity must be non-zero");
        }
        Ok(())
    }
}

pub fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty()
        || label.len() > MAX_AGENT_LABEL_BYTES
        || label.chars().any(char::is_control)
    {
        Err("agent label is empty, oversized or contains control characters")
    } else {
        Ok(())
    }
}

pub fn validate_write_paths(paths: &[String]) -> Result<(), &'static str> {
    if paths.len() > MAX_AGENT_WRITE_PATHS
        || paths.iter().any(|path| {
            path.is_empty()
                || path.len() > MAX_AGENT_WRITE_PATH_BYTES
                || path.chars().any(char::is_control)
                || path.starts_with(['/', '\\'])
                || path.contains(':')
                || path
                    .split(['/', '\\'])
                    .any(|part| matches!(part, ".." | "." | ""))
        })
    {
        Err("agent write paths must be bounded workspace-relative paths")
    } else {
        Ok(())
    }
}

pub fn validate_text(text: &str) -> Result<(), &'static str> {
    if text.trim().is_empty() || text.len() > MAX_AGENT_TEXT_BYTES || text.contains('\0') {
        Err("agent text is empty, oversized or contains NUL")
    } else {
        Ok(())
    }
}

pub fn validate_epoch(epoch: AgentEpochV1) -> Result<(), &'static str> {
    if epoch.incarnation == 0 || epoch.turn == 0 {
        Err("agent incarnation and turn must be non-zero")
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentStateV1 {
    Idle,
    Running { epoch: AgentEpochV1 },
    Interrupting { epoch: AgentEpochV1 },
    Closing { epoch: AgentEpochV1 },
    RecoveryRequired { epoch: AgentEpochV1 },
    Closed,
}

impl AgentStateV1 {
    pub fn epoch(self) -> Option<AgentEpochV1> {
        match self {
            Self::Running { epoch }
            | Self::Interrupting { epoch }
            | Self::Closing { epoch }
            | Self::RecoveryRequired { epoch } => Some(epoch),
            Self::Idle | Self::Closed => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentMessageStateV1 {
    Accepted,
    Delivered { epoch: AgentEpochV1 },
    Consumed { epoch: AgentEpochV1 },
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMessageKindV1 {
    Message,
    Task,
    Steer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentViewV1 {
    pub agent_id: AgentIdV1,
    pub parent_id: Option<AgentIdV1>,
    pub label: String,
    pub workspace_scope: String,
    pub incarnation: u64,
    pub state: AgentStateV1,
    pub capabilities: CapabilitySet,
    pub budget: AgentBudgetV1,
    pub write_paths: Vec<String>,
    pub queued_messages: usize,
    pub last_summary: Option<String>,
    #[serde(default)]
    pub usage: AgentUsageV1,
    /// Lifetime budget reserved for admitted descendants, unavailable to this agent itself.
    #[serde(default)]
    pub reserved: AgentUsageV1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUsageV1 {
    pub turns: u32,
    pub tokens: u64,
    pub cost_microusd: u64,
    pub wall_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentControlReplyV1 {
    pub version: u32,
    pub revision: u64,
    pub agent_id: AgentIdV1,
    pub message_id: Option<AgentMessageIdV1>,
    /// A durable acceptance receipt; it makes no claim of delivery or model consumption.
    pub state: AgentStateV1,
    pub replayed: bool,
}
