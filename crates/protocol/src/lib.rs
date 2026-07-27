//! core-protocol — the core vocabulary.
//!
//! The design decisions this file encodes as *types* (not conventions):
//!   - Trust tier (ADR-007 R11): every context segment and tool result carries one.
//!   - Purity (ADR-004 R4 / ADR-007 R16): licenses early dispatch, memoization, speculation.
//!   - Capability class (ADR-007 R12): tier by what a tool can do, not by textual reversibility.
//!   - The SQ/EQ shape (ADR-010): one id-correlated submission/event protocol; the core has
//!     exactly one input channel and one output channel, both correlated by `id`.
//!
//! Keep this crate small. Codex's 220 KB kitchen-sink protocol is a named defect
//! (`docs/intake/codex-deep-dive-ii.md`); we take the shape, not the sprawl.

use serde::{Deserialize, Serialize};

pub mod capability_set;
pub mod diff;
pub mod effect;
pub mod event;
pub mod ids;
pub mod intent;
pub mod message;
pub mod permission;
pub mod pricing;
pub mod slot;
pub mod task;
pub mod tool;
pub mod trust;
pub mod wire;

pub mod home;
pub mod text;

pub use diff::{DiffLine, DiffTag, FileDiff, Hunk};
pub use event::{
    DurableEnvironmentContext, DurableInstructionContext, Event, EventKind,
    MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES, Phase, RuntimePolicyEventVersion, RuntimePolicySource,
    RuntimePolicyState, SubmissionRejectionReason, WorkflowChildOutcome, WorkflowCostEvidence,
    WorkflowEvent, WorkflowEventVersion, WorkflowExecutionMode, WorkflowMetrics, WorkflowOutcome,
    WorkflowPhase, WorkflowTaskEvidence,
};
pub use ids::{EffectId, RunId, Seq, SubmissionId, TenantId, TurnId};
pub use message::{
    Block, MAX_STOP_REASON_CODE_BYTES, Message, ProviderState, ProviderStateFormat, Role,
    StopReason, StopReasonCode, Usage,
};
pub use permission::{PermissionMode, PermissionRules, Verdict, gate};
pub use pricing::{
    CostAttribution, CostProjection, CostProjectionIdentity, MAX_WORKFLOW_COST_PROJECTIONS,
    PricingRoute, PricingVersion, RateCard, SignedRateCard, TokenRateCard,
};
pub use tool::{Capability, Purity, ToolResult, ToolSpec, ToolUse};
pub use trust::Trust;
pub use wire::{EqEnvelope, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope};

/// A submission on the SQ. The core consumes these; every frontend (CLI first) produces
/// them. Approvals, interrupts, and steering are all submissions on the same queue, which
/// preserves caller order for free — exactly what the ADR-006 determinism boundary needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Start a turn from operator input.
    UserInput { text: String },
    /// Operator answer to an approval request (ADR-007 capability gate). `remember` = "always
    /// allow this capability for the session" (the `a` answer), which the kernel records as a
    /// session rule so the gate auto-approves the class thereafter.
    ApprovalResponse {
        id: SubmissionId,
        approved: bool,
        /// Missing in the first SQ shape. Defaulting it keeps those legacy submissions readable.
        #[serde(default)]
        remember: bool,
    },
    /// Async steering: inject a message at the top of the next loop iteration.
    Steer { text: String },
    /// Cooperative interrupt. Bounded (invariant #1): the loop checks it at safe points.
    Interrupt,
    /// Stop admitting turns, quiesce, sync-checkpoint, exit (the `drain` verb; ADR-008 safe-point).
    Drain,
    /// Forward-compatible rejection sentinel. Deserialization deliberately discards the unknown
    /// tag and every accompanying field, so a newer client's opaque payload cannot enter logs,
    /// errors, UI, or the durable record through this value.
    #[serde(other)]
    Unknown,
}

/// Effort level (session setting). Maps to (a) the model's reasoning/thinking budget and
/// (b) the orchestration strategy — `Ultracode` enables core's internal workflow/subagent
/// orchestration for substantive tasks (designed in R5). Mirrors the leading agent's effort UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// No extended thinking; fastest, cheapest.
    Low,
    #[default]
    Medium,
    High,
    XHigh,
    Max,
    /// Max thinking + internal workflow/subagent orchestration (the ultracode feature).
    Ultracode,
}

impl Effort {
    /// The extended-thinking token budget for this effort (0 = thinking off).
    pub fn thinking_budget(self) -> u32 {
        match self {
            Effort::Low => 0,
            Effort::Medium => 4_096,
            Effort::High => 8_192,
            Effort::XHigh => 16_384,
            Effort::Max | Effort::Ultracode => 32_768,
        }
    }
    /// Does this effort enable internal orchestration (parallel subagent fan-out)?
    pub fn orchestrates(self) -> bool {
        self == Effort::Ultracode
    }
    /// Parse from a CLI/command string.
    pub fn parse(s: &str) -> Option<Effort> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Effort::Low),
            "medium" | "med" => Some(Effort::Medium),
            "high" => Some(Effort::High),
            "xhigh" | "x-high" => Some(Effort::XHigh),
            "max" => Some(Effort::Max),
            "ultracode" | "ultra" => Some(Effort::Ultracode),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::XHigh => "xhigh",
            Effort::Max => "max",
            Effort::Ultracode => "ultracode",
        }
    }
    /// All effort levels in order, low → ultracode — the choice set for the TUI `/effort` picker.
    pub const ALL: [Effort; 6] = [
        Effort::Low,
        Effort::Medium,
        Effort::High,
        Effort::XHigh,
        Effort::Max,
        Effort::Ultracode,
    ];
    /// A one-line description of what each level does (shown as the picker row hint).
    pub fn hint(self) -> &'static str {
        match self {
            Effort::Low => "fastest, minimal thinking",
            Effort::Medium => "balanced (default)",
            Effort::High => "more thinking budget",
            Effort::XHigh => "deep thinking",
            Effort::Max => "maximum thinking budget",
            Effort::Ultracode => "max thinking + internal fan-out orchestration",
        }
    }
    /// Resolve to the two-knob profile (ADR-012): the thinking budget AND the orchestration mode.
    /// Per the R5 review, ultracode's orchestration is `Fan`+`Reduce` only (the DAG vocabulary is
    /// deferred) and is justified on context-management, not a wall-clock speedup.
    pub fn profile(self) -> EffortProfile {
        EffortProfile {
            reasoning: self.reasoning_effort(),
            thinking_budget: self.thinking_budget(),
            orchestration: if self == Effort::Ultracode {
                OrchestrationMode::Orchestrated
            } else {
                OrchestrationMode::SingleAgent
            },
        }
    }

    /// The provider-facing semantic reasoning level. This is deliberately independent of the
    /// token budget: APIs such as Anthropic Messages expose `output_config.effort` and thinking as
    /// orthogonal controls, while OpenAI reasoning models accept an effort enum directly.
    pub const fn reasoning_effort(self) -> ReasoningEffort {
        match self {
            Effort::Low => ReasoningEffort::Low,
            Effort::Medium => ReasoningEffort::Medium,
            Effort::High => ReasoningEffort::High,
            Effort::XHigh => ReasoningEffort::XHigh,
            Effort::Max | Effort::Ultracode => ReasoningEffort::Max,
        }
    }
}

/// Provider-facing model reasoning effort. `Ultracode` is intentionally absent: it is a harness
/// orchestration mode, not a model API value. Adapters must consume this field directly and must
/// not reconstruct semantic intent from a token-budget threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl ReasoningEffort {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
        }
    }
}

/// The resolved two-knob effort setting (ADR-012). Kept a separate type — rather than scattering
/// `match effort` across the kernel — so the orchestration mode is a swappable strategy behind the
/// effort dial (the ADR-011 pluggable seam made concrete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffortProfile {
    pub reasoning: ReasoningEffort,
    pub thinking_budget: u32,
    pub orchestration: OrchestrationMode,
}

/// How a substantive task is executed. `SingleAgent` is the plain bounded loop; `Orchestrated`
/// engages the read-only fan-out + declaration-order reduce into the single writer (ultracode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestrationMode {
    SingleAgent,
    Orchestrated,
}

/// The bounded-loop ceilings (invariant #1: everything has a declared ceiling).
/// A run that hits any of these stops deterministically at a turn-atomic safe-point
/// (ADR-008 budget hard-stop), never mid-effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_turns: u32,
    /// Optional operator-requested USD ceiling. `None` is honest absence of a monetary guarantee;
    /// a positive ceiling requires a verified route-bound rate card, while zero is universally
    /// enforceable without admitting a provider request.
    pub max_usd: Option<f64>,
    pub max_wall_secs: u64,
    pub max_consecutive_tool_errors: u32,
}

impl Default for Budget {
    fn default() -> Self {
        // Turn and wall ceilings are always enforceable. Monetary control is opt-in because a
        // guessed universal price table is worse than no dollar claim at all.
        Self {
            max_turns: 60,
            max_usd: None,
            max_wall_secs: 900,
            max_consecutive_tool_errors: 3,
        }
    }
}

impl Budget {
    /// Validate values that integer types alone cannot make safe.  In particular, IEEE NaN makes
    /// every `cost >= max_usd` comparison false and would silently disable the monetary ceiling.
    /// Zero remains a valid explicit ceiling: the controller will terminate before admitting
    /// work.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(max_usd) = self.max_usd {
            if !max_usd.is_finite() {
                return Err("max_usd must be finite");
            }
            if max_usd < 0.0 {
                return Err("max_usd must be non-negative");
            }
        }
        Ok(())
    }
}

/// Why a run ended. Explicit, because a stop condition is a stability guarantee, not a
/// heuristic (ADR-005, kernel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The agent declared the task complete.
    Done,
    /// The operator requested an orderly quiesce; all admitted work reached a safe point and a
    /// durable workspace checkpoint was committed before exit.
    Drained,
    /// A budget ceiling was reached (invariant #1).
    BudgetExhausted(&'static str),
    /// The operator interrupted at a safe point without requesting a workspace checkpoint.
    Interrupted,
    /// Too many consecutive tool errors — a stability floor tripped.
    Stuck,
    /// An unrecoverable error in the harness itself.
    HarnessError,
}

#[cfg(test)]
mod op_tests {
    use super::{Op, SubmissionId};

    #[test]
    fn d1_01_g1_unknown_op_round_trips_as_an_opaque_typed_sentinel() {
        let marker = "secret-marker-must-not-survive-op-decoding";
        let op: Op = serde_json::from_value(serde_json::json!({
            "op": "future_remote_control",
            "text": marker,
            "nested": {"credential": marker}
        }))
        .expect("an unknown op tag must not fail the SQ deserializer");
        assert!(matches!(op, Op::Unknown));
        assert!(!format!("{op:?}").contains(marker));

        let encoded = serde_json::to_value(&op).unwrap();
        assert_eq!(encoded, serde_json::json!({"op": "unknown"}));
        assert!(!encoded.to_string().contains(marker));
        assert!(matches!(
            serde_json::from_value::<Op>(encoded).unwrap(),
            Op::Unknown
        ));
    }

    #[test]
    fn d1_01_g3_legacy_op_defaults_new_fields_and_ignores_future_fields() {
        // Exact approval shape from before `remember` was added.
        let legacy: Op = serde_json::from_value(serde_json::json!({
            "op": "approval_response",
            "id": 7,
            "approved": true
        }))
        .unwrap();
        assert!(matches!(
            legacy,
            Op::ApprovalResponse {
                id: SubmissionId(7),
                approved: true,
                remember: false
            }
        ));

        // Conversely, an older field set tolerates additions emitted by a newer client.
        let extended: Op = serde_json::from_value(serde_json::json!({
            "op": "user_input",
            "text": "hello",
            "future_trace_context": {"version": 2}
        }))
        .unwrap();
        assert!(matches!(extended, Op::UserInput { text } if text == "hello"));
    }
}

#[cfg(test)]
mod effort_tests {
    use super::{Budget, Effort, ReasoningEffort};
    #[test]
    fn effort_parse_and_budget() {
        assert_eq!(Effort::parse("ultracode"), Some(Effort::Ultracode));
        assert_eq!(Effort::parse("HIGH"), Some(Effort::High));
        assert_eq!(Effort::parse("bogus"), None);
        assert_eq!(Effort::Low.thinking_budget(), 0);
        assert!(Effort::Max.thinking_budget() > Effort::Medium.thinking_budget());
        assert!(Effort::Ultracode.orchestrates());
        assert!(!Effort::High.orchestrates());
        assert_eq!(Effort::Low.reasoning_effort(), ReasoningEffort::Low);
        assert_eq!(Effort::Ultracode.reasoning_effort(), ReasoningEffort::Max);
        assert_eq!(Effort::Low.profile().thinking_budget, 0);
        assert_eq!(Effort::Low.profile().reasoning, ReasoningEffort::Low);
    }

    #[test]
    fn monetary_budget_cannot_disable_itself_with_non_finite_values() {
        let mut budget = Budget {
            max_usd: Some(f64::NAN),
            ..Budget::default()
        };
        assert_eq!(budget.validate(), Err("max_usd must be finite"));
        budget.max_usd = Some(f64::INFINITY);
        assert_eq!(budget.validate(), Err("max_usd must be finite"));
        budget.max_usd = Some(-0.01);
        assert_eq!(budget.validate(), Err("max_usd must be non-negative"));
        budget.max_usd = Some(0.0);
        assert_eq!(budget.validate(), Ok(()));
    }
}
