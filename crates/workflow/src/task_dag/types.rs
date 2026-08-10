use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const HARD_MAX_TASKS: usize = 1_024;
pub const HARD_MAX_ATTEMPTS: usize = 4_096;
pub const HARD_MAX_EDGES: usize = 4_096;
pub const HARD_MAX_MESSAGES: usize = 8_192;
pub const HARD_MAX_JOINS: usize = 512;
pub const HARD_MAX_EVENTS: usize = 65_536;
pub const HARD_MAX_DEPTH: usize = 64;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_REASON_BYTES: usize = 2_048;
pub const MAX_GRAPH_ID_BYTES: usize = 128;
pub const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

pub const HARD_MAX_TURNS: u32 = 1_000_000;
pub const HARD_MAX_TOKENS: u64 = 100_000_000_000;
pub const HARD_MAX_COST_MICROUSD: u64 = 100_000_000_000_000;
pub const HARD_MAX_WALL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, &'static str> {
                (value != 0)
                    .then_some(Self(value))
                    .ok_or(concat!(stringify!($name), " must be non-zero"))
            }
        }
    };
}

numeric_id!(TaskId);
numeric_id!(AttemptId);
numeric_id!(CommandId);
numeric_id!(MessageId);
numeric_id!(JoinId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Controller,
    Task(TaskId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_tasks: usize,
    pub max_edges: usize,
    pub max_messages: usize,
    pub max_joins: usize,
    pub max_events: usize,
    pub max_dependency_depth: usize,
    pub max_hierarchy_depth: usize,
}

impl Limits {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_limit(self.max_tasks, HARD_MAX_TASKS, "task")?;
        validate_limit(self.max_edges, HARD_MAX_EDGES, "edge")?;
        validate_limit(self.max_messages, HARD_MAX_MESSAGES, "message")?;
        validate_limit(self.max_joins, HARD_MAX_JOINS, "join")?;
        validate_limit(self.max_events, HARD_MAX_EVENTS, "event")?;
        validate_limit(
            self.max_dependency_depth,
            HARD_MAX_DEPTH,
            "dependency depth",
        )?;
        validate_limit(self.max_hierarchy_depth, HARD_MAX_DEPTH, "hierarchy depth")?;
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tasks: 256,
            max_edges: 2_048,
            max_messages: 4_096,
            max_joins: 256,
            max_events: 32_768,
            max_dependency_depth: 32,
            max_hierarchy_depth: 16,
        }
    }
}

fn validate_limit(value: usize, hard: usize, name: &'static str) -> Result<(), &'static str> {
    if value == 0 {
        return Err(match name {
            "task" => "task limit must be non-zero",
            "edge" => "edge limit must be non-zero",
            "message" => "message limit must be non-zero",
            "join" => "join limit must be non-zero",
            "event" => "event limit must be non-zero",
            "dependency depth" => "dependency-depth limit must be non-zero",
            _ => "hierarchy-depth limit must be non-zero",
        });
    }
    if value > hard {
        return Err(match name {
            "task" => "task limit exceeds the hard ceiling",
            "edge" => "edge limit exceeds the hard ceiling",
            "message" => "message limit exceeds the hard ceiling",
            "join" => "join limit exceeds the hard ceiling",
            "event" => "event limit exceeds the hard ceiling",
            "dependency depth" => "dependency-depth limit exceeds the hard ceiling",
            _ => "hierarchy-depth limit exceeds the hard ceiling",
        });
    }
    Ok(())
}

/// Aggregate ceilings reserved before work is admitted. Integer micro-dollars avoid floating-point
/// NaN and rounding bypasses at the authority boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    pub max_turns: u32,
    pub max_tokens: u64,
    pub max_cost_microusd: u64,
    pub max_wall_ms: u64,
}

impl TaskBudget {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.max_turns > HARD_MAX_TURNS {
            return Err("turn budget exceeds the hard ceiling");
        }
        if self.max_tokens > HARD_MAX_TOKENS {
            return Err("token budget exceeds the hard ceiling");
        }
        if self.max_cost_microusd > HARD_MAX_COST_MICROUSD {
            return Err("cost budget exceeds the hard ceiling");
        }
        if self.max_wall_ms > HARD_MAX_WALL_MS {
            return Err("wall-clock budget exceeds the hard ceiling");
        }
        Ok(())
    }

    pub(crate) fn reservable(self) -> BudgetReservation {
        BudgetReservation {
            turns: u64::from(self.max_turns),
            tokens: self.max_tokens,
            cost_microusd: self.max_cost_microusd,
        }
    }

    pub(crate) fn remaining(self, usage: BudgetUsage, reserved: BudgetReservation) -> Option<Self> {
        let turns = u64::from(self.max_turns)
            .checked_sub(usage.turns)?
            .checked_sub(reserved.turns)?;
        Some(Self {
            max_turns: u32::try_from(turns).ok()?,
            max_tokens: self
                .max_tokens
                .checked_sub(usage.tokens)?
                .checked_sub(reserved.tokens)?,
            max_cost_microusd: self
                .max_cost_microusd
                .checked_sub(usage.cost_microusd)?
                .checked_sub(reserved.cost_microusd)?,
            max_wall_ms: self.max_wall_ms.checked_sub(usage.wall_ms)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsage {
    pub turns: u64,
    pub tokens: u64,
    pub cost_microusd: u64,
    pub wall_ms: u64,
}

impl BudgetUsage {
    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            turns: self.turns.checked_add(other.turns)?,
            tokens: self.tokens.checked_add(other.tokens)?,
            cost_microusd: self.cost_microusd.checked_add(other.cost_microusd)?,
            wall_ms: self.wall_ms.checked_add(other.wall_ms)?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BudgetReservation {
    pub(crate) turns: u64,
    pub(crate) tokens: u64,
    pub(crate) cost_microusd: u64,
}

impl BudgetReservation {
    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            turns: self.turns.checked_add(other.turns)?,
            tokens: self.tokens.checked_add(other.tokens)?,
            cost_microusd: self.cost_microusd.checked_add(other.cost_microusd)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub id: TaskId,
    pub parent: Option<TaskId>,
    pub dependencies: Vec<TaskId>,
    pub label: String,
    pub budget: TaskBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskState {
    Blocked,
    Ready,
    Running,
    Cancelling { reason: String },
    Succeeded { result_digest: String },
    Failed { code: String, detail: String },
    Cancelled { reason: String },
    SkippedDependency { dependency: TaskId },
}

impl TaskState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded { .. }
                | Self::Failed { .. }
                | Self::Cancelled { .. }
                | Self::SkippedDependency { .. }
        )
    }

    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub spec: TaskSpec,
    pub state: TaskState,
    pub usage: BudgetUsage,
    pub hierarchy_depth: usize,
    pub dependency_depth: usize,
    pub inbox: Vec<MessageId>,
    pub(crate) child_reservations: BudgetReservation,
}

/// One physical child dispatch belonging to a logical [`Task`]. Retries and speculative siblings
/// receive distinct ids so a selected result can never erase the consumed budget or terminal of
/// another dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptSpec {
    pub id: AttemptId,
    pub task: TaskId,
    pub retry_ordinal: u32,
    pub sibling_ordinal: u32,
    pub input_digest: String,
}

/// Why a physical attempt was (or was not) selected by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptDisposition {
    /// The task had exactly one physical candidate in this attempt group.
    Sole,
    /// The first verified positive candidate selected from a speculative group.
    Winner,
    /// A sibling that was not selected, including a positively-completed late sibling.
    Loser,
    /// A definite negative terminal; no positive result was selected from it.
    Negative,
    /// Cleanup ended without evidence that the external child effect reached a terminal.
    UnknownEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptCompletion {
    Succeeded,
    Failed,
    Cancelled,
    UnknownEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttemptState {
    Registered,
    Running,
    Succeeded {
        result_digest: String,
        disposition: AttemptDisposition,
    },
    Failed {
        code: String,
        detail: String,
        disposition: AttemptDisposition,
    },
    Cancelled {
        reason: String,
        disposition: AttemptDisposition,
    },
    UnknownEffect {
        reason: String,
    },
}

impl AttemptState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded { .. }
                | Self::Failed { .. }
                | Self::Cancelled { .. }
                | Self::UnknownEffect { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub spec: AttemptSpec,
    pub state: AttemptState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Instruction,
    Steering,
    Observation,
    Result,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMessage {
    pub id: MessageId,
    pub from: Option<TaskId>,
    pub to: TaskId,
    pub kind: MessageKind,
    pub payload: String,
    pub delivery: DeliveryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicy {
    AllTerminal,
    AllSucceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinSpec {
    pub id: JoinId,
    pub owner: Option<TaskId>,
    pub members: Vec<TaskId>,
    pub policy: JoinPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinState {
    Pending { remaining: Vec<TaskId> },
    Ready,
    Failed { members: Vec<TaskId> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    CreateTask {
        actor: Actor,
        spec: TaskSpec,
    },
    StartTask {
        actor: Actor,
        task: TaskId,
    },
    RegisterAttempt {
        actor: Actor,
        attempt: AttemptSpec,
    },
    StartAttempt {
        actor: Actor,
        attempt: AttemptId,
    },
    CompleteAttempt {
        actor: Actor,
        attempt: AttemptId,
        completion: AttemptCompletion,
        disposition: AttemptDisposition,
        result_digest: Option<String>,
        code: Option<String>,
        detail: Option<String>,
    },
    ChargeBudget {
        actor: Actor,
        task: TaskId,
        delta: BudgetUsage,
    },
    SendMessage {
        actor: Actor,
        message: TaskMessage,
    },
    AcknowledgeMessage {
        actor: Actor,
        message: MessageId,
    },
    RegisterJoin {
        actor: Actor,
        join: JoinSpec,
    },
    RequestCancel {
        actor: Actor,
        task: TaskId,
        reason: String,
    },
    CompleteTask {
        actor: Actor,
        task: TaskId,
        completion: Completion,
        result_digest: Option<String>,
        code: Option<String>,
        detail: Option<String>,
    },
}

impl Command {
    pub(crate) fn dependency_set(spec: &TaskSpec) -> BTreeSet<TaskId> {
        spec.dependencies.iter().copied().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub graph_id: String,
    pub limits: Limits,
    pub budget: TaskBudget,
}

impl Config {
    pub fn new(
        graph_id: impl Into<String>,
        limits: Limits,
        budget: TaskBudget,
    ) -> Result<Self, &'static str> {
        let config = Self {
            graph_id: graph_id.into(),
            limits,
            budget,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        validate_identifier(&self.graph_id, MAX_GRAPH_ID_BYTES, "graph id")?;
        self.limits.validate()?;
        self.budget.validate()
    }
}

pub(crate) fn validate_identifier(
    value: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(match name {
            "graph id" => "graph id is empty or over its byte limit",
            "label" => "task label is empty or over its byte limit",
            "code" => "completion code is empty or over its byte limit",
            _ => "identifier is empty or over its byte limit",
        });
    }
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '\u{202a}'..='\u{202e}'))
    {
        return Err(match name {
            "graph id" => "graph id contains terminal-control or bidi-override characters",
            "label" => "task label contains terminal-control or bidi-override characters",
            "code" => "completion code contains terminal-control or bidi-override characters",
            _ => "identifier contains terminal-control or bidi-override characters",
        });
    }
    Ok(())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
