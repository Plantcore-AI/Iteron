//! Events on the EQ. Every phase transition, token class, and tool latency is emitted here
//! (invariant #4, observable). The phase is the point: the harness is the only layer that
//! knows what phase it is in (the phase-oracle thesis).

use crate::ids::{EffectId, Seq, SubmissionId, TurnId};
use crate::message::{Message, Usage};
use crate::permission::Verdict;
use crate::tool::{Capability, ToolResult, ToolUse};
use serde::{Deserialize, Serialize};

/// Schema version for durable runtime-policy snapshots. This is an enum rather than an open
/// integer so writers cannot accidentally emit an unreviewed wire format under a familiar event
/// kind. A future format gets a new variant and an explicit replay migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePolicyEventVersion {
    V1,
}

/// Auditable origin of a runtime-policy transition. Sources are deliberately protocol vocabulary,
/// not frontend-controlled strings: a model or plugin cannot forge an arbitrary provenance label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePolicySource {
    /// Effective configuration captured when a fresh run is created.
    Startup,
    /// An explicit live operator action (command, picker, or embedding API).
    Operator,
    /// The operator selected a session-scoped "remember" action while approving one operation.
    ApprovalRemember,
    /// A bounded harness-owned policy choice, such as a constrained child agent.
    Harness,
    /// A child journal materialized the effective state at its exact fork point.
    Fork,
}

/// Versioned durable vocabulary for harness-owned workflows. The workflow journal is deliberately
/// separate from free-form notices: resume, session projection, and frontends must be able to
/// reconstruct child attribution without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowEventVersion {
    V1,
}

/// The execution topology that was actually admitted, not the topology a planner merely proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowExecutionMode {
    Direct,
    SequentialFan,
}

/// Durable workflow phases. `Writing` is distinct from `Reducing`: deterministic bundle assembly
/// is harness work, while writing admits model/tool effects through the ordinary controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowPhase {
    Planning,
    Exploring,
    Reducing,
    Writing,
    Direct,
}

/// Authoritative terminal disposition for one declared workflow task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowChildOutcome {
    Done,
    Failed,
    Interrupted,
    SkippedBudget,
    NotStarted,
}

/// Authoritative terminal disposition for the workflow as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowOutcome {
    Done,
    Degraded,
    Interrupted,
    BudgetExhausted,
    Stuck,
    HarnessError,
    Failed,
}

/// Content-minimal evidence for a declared task. The full delegation remains in the child rollout;
/// the parent stores only a bounded display label and a digest for correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowTaskEvidence {
    pub task_id: u32,
    pub label: String,
    pub prompt_digest: String,
}

/// Additive metrics for exactly one child, or a terminal snapshot for the whole workflow. A
/// `Finished` snapshot is informational; projections add only `ChildFinished` metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowMetrics {
    pub provider_attempts: u32,
    pub completed_turns: u32,
    pub usage: Usage,
    pub tool_calls: u64,
    pub tool_errors: u64,
    pub model_ms: u64,
    pub tools_ms: u64,
}

/// Typed workflow journal carried by [`EventKind::Workflow`]. Activity chatter is intentionally
/// absent: the durable boundary records decisions, budgets, attribution, adoption, and terminals;
/// high-frequency current-tool updates remain a coalescible frontend projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WorkflowEvent {
    Started {
        name: String,
        class: String,
    },
    Planned {
        mode: WorkflowExecutionMode,
        tasks: Vec<WorkflowTaskEvidence>,
        dropped: u32,
        duplicates_removed: u32,
        invalid_removed: u32,
        fan_turn_budget: u32,
        writer_turn_reserve: u32,
        fan_wall_secs: u64,
        writer_wall_reserve_secs: u64,
    },
    PhaseChanged {
        phase: WorkflowPhase,
    },
    ChildStarted {
        task_id: u32,
        sub_run: String,
        spawn_seq: Seq,
        budget: crate::Budget,
    },
    ChildFinished {
        task_id: u32,
        sub_run: Option<String>,
        outcome: WorkflowChildOutcome,
        metrics: WorkflowMetrics,
        error_code: Option<String>,
        error_detail: Option<String>,
        summary_digest: Option<String>,
        evidence_bytes: u32,
    },
    Reduced {
        evidence_message_seq: Option<Seq>,
        done: u32,
        failed: u32,
        skipped: u32,
        elapsed_ms: u64,
    },
    Finished {
        outcome: WorkflowOutcome,
        metrics: WorkflowMetrics,
        elapsed_ms: u64,
        error_code: Option<String>,
        error_detail: Option<String>,
    },
}

/// Canonical pure projection of runtime policy from a logical rollout. Keeping this reducer beside
/// the wire vocabulary gives the kernel, session index, and fork code one interpretation of legacy
/// genesis events and v1 snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePolicyState {
    pub effort: crate::Effort,
    pub permission_mode: crate::PermissionMode,
    pub permission_rules: crate::PermissionRules,
}

impl Default for RuntimePolicyState {
    fn default() -> Self {
        Self {
            effort: crate::Effort::default(),
            permission_mode: crate::PermissionMode::default(),
            permission_rules: crate::PermissionRules::new(),
        }
    }
}

impl RuntimePolicyState {
    /// Apply one event to the projection. Legacy records get effort from `RunStart` and the safest
    /// default permission policy; newer full snapshots then replace the relevant state atomically.
    pub fn apply(&mut self, kind: &EventKind) {
        match kind {
            EventKind::RunStart { effort, .. } => self.effort = *effort,
            EventKind::EffortChanged {
                version: RuntimePolicyEventVersion::V1,
                effort,
                ..
            } => self.effort = *effort,
            EventKind::PolicyChanged {
                version: RuntimePolicyEventVersion::V1,
                mode,
                rules,
                ..
            } => {
                self.permission_mode = *mode;
                self.permission_rules = rules.clone();
            }
            _ => {}
        }
    }

    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a Event>) -> Self {
        let mut state = Self::default();
        for event in events {
            state.apply(&event.kind);
        }
        state
    }
}

/// The phase a turn is in. The harness *declares* this; nothing else in the stack can.
/// (ADR-002: this is what makes the run observable, attributable, and priceable.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Assembling the context projection c(s_t) for the model.
    Context,
    /// Waiting on / streaming the model response (prefill + decode).
    Model,
    /// Executing tool calls.
    Tools,
    /// Verifying / selecting (the crown; a separate phase so its cost is attributable).
    Verify,
    /// Idle between turns.
    Idle,
}

impl Phase {
    /// A human status word for the TUI status line (never the raw Debug variant — TUI v3 §7).
    pub fn label(self) -> &'static str {
        match self {
            Phase::Context => "reading context",
            Phase::Model => "thinking",
            Phase::Tools => "running tools",
            Phase::Verify => "verifying",
            Phase::Idle => "idle",
        }
    }
}

/// An event with its place in the run's total order. `seq` is per-run (ADR-008).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: Seq,
    pub turn: TurnId,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A phase transition. The load-bearing telemetry.
    Phase { phase: Phase },
    /// A turn began.
    TurnStart,
    /// A full transcript message was committed (append-only). Recording these makes the rollout
    /// a complete, resumable record of the conversation (ADR-006 (a)+(b): the decisions and the
    /// recorded outputs replay) and completes the audit trail (every message is on the record).
    Message { message: Message },
    /// Compaction rewrote the working message set (a rare "cache bomb"). Recorded as a full
    /// snapshot so resume reconstructs the in-memory compacted state exactly rather than the
    /// pre-compaction history (code review: without this, resume diverges from what ran).
    Compaction { messages: Vec<Message> },
    /// The model produced streamed text (surfaced incrementally to the operator).
    Text { delta: String },
    /// The model's reasoning delta (extended thinking).
    Thinking { delta: String },
    /// A tool_use block completed mid-stream — the dispatch point for pure tools (ADR-004).
    ToolReady { tool: ToolUse, purity_pure: bool },
    /// A tool finished. `latency_ms` is measured tau_wall contribution. Effecting registry tools
    /// carry the harness-minted id of their preceding `EffectIntent`; legacy and non-effecting
    /// results omit it.
    ToolDone {
        result: ToolResult,
        #[serde(default)]
        effect_id: Option<EffectId>,
    },
    /// Write-ahead admission for one effecting tool call. This event must be fsynced before the
    /// registry executor is entered. `(turn, id)` is the correlation key; arguments/workspace are
    /// a scrubbed audit projection, not an ambient capability handle.
    EffectIntent {
        id: EffectId,
        /// Provider/model correlation metadata. Empty only for the first experimental WAL format,
        /// where `id` itself contained the model-controlled tool-use id.
        #[serde(default)]
        tool_use_id: String,
        tool: String,
        capability: Capability,
        arguments: serde_json::Value,
        workspace: String,
    },
    /// Runtime dispatch or recovery could not prove a terminal outcome for an admitted intent.
    /// It is never retried automatically. A future authenticated broker reconciliation may append
    /// a distinct reconciliation event; an ordinary `ToolDone` cannot erase this state.
    EffectUnknown {
        id: EffectId,
        tool: String,
        reason: String,
    },
    /// The model turn completed, with usage by cache class.
    TurnEnd { usage: Usage },
    /// A message for the operator (not part of the transcript).
    Notice { text: String },
    /// A capability-gate decision (ADR-007 §3): the request (`verdict: Ask`) and then the
    /// resolution (`Auto` = approved, `Deny` = refused). Recording both makes the approval the
    /// replay decision-log — a deterministic replay reads the recorded verdict and does not
    /// re-prompt (the operator is not in the replay; ADR-006 boundary).
    Approval {
        id: SubmissionId,
        /// Correlates the human decision with one concrete model invocation, not merely a tool
        /// class. Empty only when replaying a legacy record written before this field existed.
        #[serde(default)]
        tool_use_id: String,
        tool: String,
        capability: Capability,
        /// Secret-scrubbed, bounded operation projection shown to the operator. This is audit
        /// evidence; future opaque secret handles must be bound separately by the effect broker.
        #[serde(default)]
        arguments: serde_json::Value,
        /// Workspace/resource provenance at the decision boundary.
        #[serde(default)]
        workspace: String,
        verdict: Verdict,
    },
    /// The session genesis header (seq-0). Carries the wall-clock `created_at` ONCE, crossing the
    /// nondeterminism boundary (ADR-006 rule 1) so it is read from the record on replay, never
    /// re-read at list time. `parent_*` set on a fork/rewind child; `parent_hash_at_seq` is the
    /// parent chain's hash at the fork point (ADR-008 §4 tamper-evidence — R5-review Risk 3).
    RunStart {
        cwd: String,
        model: String,
        effort: crate::Effort,
        created_at: u64,
        parent_run: Option<String>,
        forked_at: Option<u64>,
        parent_hash_at_seq: Option<String>,
        config_digest: String,
    },
    /// The exact provider/model routing pair selected for subsequent turns. Provider identity is
    /// separate from model identity because the same model id can exist behind several accounts or
    /// gateways. Digests pin the catalog/capability evidence used at selection time; empty means
    /// the frontend had no stronger provenance and must not invent one during replay.
    ModelSelected {
        provider_id: String,
        model_id: String,
        catalog_digest: String,
        capability_digest: String,
    },
    /// Full snapshot of the effective reasoning/orchestration policy. The rollout is write-ahead:
    /// the kernel fsyncs this event before changing the in-memory value. Full snapshots avoid
    /// replay depending on frontend-specific commands such as "cycle to next effort".
    EffortChanged {
        version: RuntimePolicyEventVersion,
        source: RuntimePolicySource,
        effort: crate::Effort,
    },
    /// Full snapshot of the capability gate policy. Both mode and rules travel together so replay,
    /// resume, and fork reconstruct exactly one coherent gate state rather than a partial update.
    PolicyChanged {
        version: RuntimePolicyEventVersion,
        source: RuntimePolicySource,
        mode: crate::PermissionMode,
        rules: crate::PermissionRules,
    },
    /// The exact context (memory + instructions) injected into the stable prefix this run
    /// (REC-INJECT, R5-review item 1). Replay re-materializes context FROM this record, never from
    /// disk, so a mid-run on-disk edit cannot alter a replay and post-compaction facts do not drop.
    /// Stored protocol-native (the rendered text + its trust) to avoid a dep on the ctx crate.
    ContextInjection { text: String, trust: crate::Trust },
    /// A workspace checkpoint (files) keyed to a record `Seq` — the snapshot ledger in the rollout.
    Checkpoint { at: Seq, tree_ref: String },
    /// A read-only subagent was spawned; links its child rollout to the parent (single-writer
    /// fan-out, ADR-001) for the `/sessions` tree view.
    SubagentSpawned { sub_run: String, agent: String },
    /// Terminal attribution for a directly-dispatched read-only child. Ultracode children use the
    /// richer correlated `Workflow::ChildFinished` event instead; projections add exactly one of
    /// these terminal forms per spawned child.
    SubagentFinished {
        sub_run: String,
        outcome: WorkflowChildOutcome,
        metrics: WorkflowMetrics,
        error_code: Option<String>,
        error_detail: Option<String>,
        summary_digest: Option<String>,
        evidence_bytes: u32,
    },
    /// Versioned, typed workflow lifecycle. This is the parent WAL source of truth for child
    /// attribution and terminal reconstruction; `SubagentSpawned` remains for legacy tree views.
    Workflow {
        version: WorkflowEventVersion,
        workflow_id: String,
        event: WorkflowEvent,
    },
    /// The run ended.
    Done { outcome: String },
    /// Forward-compatibility: an event kind this build does not recognize (written by a newer
    /// version). Deserializes here instead of failing the whole replay (R5-review Risk 6).
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_route_run_start_event_remains_readable() {
        // Exact shape written before `model_selected` existed. Adding a new tagged variant must
        // not require a provider field in legacy genesis records.
        let event: Event = serde_json::from_value(serde_json::json!({
            "seq": 0,
            "turn": 0,
            "kind": {
                "kind": "run_start",
                "cwd": "/repo/legacy",
                "model": "claude-legacy",
                "effort": "medium",
                "created_at": 1,
                "parent_run": null,
                "forked_at": null,
                "parent_hash_at_seq": null,
                "config_digest": ""
            }
        }))
        .unwrap();
        assert!(matches!(
            event.kind,
            EventKind::RunStart { model, .. } if model == "claude-legacy"
        ));
    }

    #[test]
    fn model_selection_schema_contains_identity_and_digests_not_credentials() {
        let value = serde_json::to_value(EventKind::ModelSelected {
            provider_id: "openai-work".into(),
            model_id: "gpt-5-codex".into(),
            catalog_digest: "sha256:catalog".into(),
            capability_digest: "sha256:capability".into(),
        })
        .unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.get("kind").and_then(|value| value.as_str()),
            Some("model_selected")
        );
        for forbidden in ["api_key", "credential", "key_env", "api_root"] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn runtime_policy_events_are_versioned_full_snapshots_with_fixed_sources() {
        let effort = serde_json::to_value(EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Operator,
            effort: crate::Effort::High,
        })
        .unwrap();
        assert_eq!(effort["kind"], "effort_changed");
        assert_eq!(effort["version"], "v1");
        assert_eq!(effort["source"], "operator");
        assert_eq!(effort["effort"], "high");

        let mut rules = crate::PermissionRules::new();
        rules.set_cap(crate::Capability::CodeExecuting, Verdict::Deny);
        let policy = serde_json::to_value(EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::ApprovalRemember,
            mode: crate::PermissionMode::AcceptEdits,
            rules,
        })
        .unwrap();
        assert_eq!(policy["kind"], "policy_changed");
        assert_eq!(policy["version"], "v1");
        assert_eq!(policy["source"], "approval_remember");
        assert_eq!(policy["mode"], "acceptEdits");
        assert_eq!(policy["rules"]["by_cap"]["code_executing"], "deny");
    }

    #[test]
    fn runtime_policy_projection_uses_last_full_snapshot() {
        let mut denied = crate::PermissionRules::new();
        denied.set_cap(crate::Capability::CodeExecuting, Verdict::Deny);
        let events = vec![
            Event {
                seq: Seq(0),
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: "/repo".into(),
                    model: "model".into(),
                    effort: crate::Effort::Medium,
                    created_at: 1,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                },
            },
            Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    effort: crate::Effort::Max,
                },
            },
            Event {
                seq: Seq(2),
                turn: TurnId(0),
                kind: EventKind::PolicyChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    mode: crate::PermissionMode::Plan,
                    rules: denied.clone(),
                },
            },
        ];
        let projected = RuntimePolicyState::from_events(&events);
        assert_eq!(projected.effort, crate::Effort::Max);
        assert_eq!(projected.permission_mode, crate::PermissionMode::Plan);
        assert_eq!(projected.permission_rules, denied);
    }

    #[test]
    fn legacy_capability_only_approval_remains_readable() {
        let event: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "approval",
            "id": 7,
            "tool": "edit",
            "capability": "reversible_local",
            "verdict": "ask"
        }))
        .unwrap();
        assert!(matches!(
            event,
            EventKind::Approval {
                tool_use_id,
                arguments: serde_json::Value::Null,
                workspace,
                ..
            } if tool_use_id.is_empty() && workspace.is_empty()
        ));
    }

    #[test]
    fn approval_record_binds_one_operation_and_workspace() {
        let value = serde_json::to_value(EventKind::Approval {
            id: SubmissionId(9),
            tool_use_id: "call-42".into(),
            tool: "bash".into(),
            capability: Capability::CodeExecuting,
            arguments: serde_json::json!({"command": "cargo test"}),
            workspace: "/repo".into(),
            verdict: Verdict::Ask,
        })
        .unwrap();
        assert_eq!(value["tool_use_id"], "call-42");
        assert_eq!(value["arguments"]["command"], "cargo test");
        assert_eq!(value["workspace"], "/repo");
    }

    #[test]
    fn legacy_effect_events_remain_readable_without_new_correlation_fields() {
        let intent: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "effect_intent",
            "id": "legacy-model-call",
            "tool": "edit",
            "capability": "reversible_local",
            "arguments": {"path":"f"},
            "workspace": "/repo"
        }))
        .unwrap();
        assert!(matches!(
            intent,
            EventKind::EffectIntent { id, tool_use_id, .. }
                if id.0 == "legacy-model-call" && tool_use_id.is_empty()
        ));

        let terminal: EventKind = serde_json::from_value(serde_json::json!({
            "kind": "tool_done",
            "result": {
                "tool_use_id": "legacy-model-call",
                "content": "ok",
                "is_error": false,
                "trust": "workspace",
                "latency_ms": 1
            }
        }))
        .unwrap();
        assert!(matches!(
            terminal,
            EventKind::ToolDone {
                effect_id: None,
                ..
            }
        ));
    }

    #[test]
    fn workflow_child_terminal_round_trips_with_additive_metrics() {
        let kind = EventKind::Workflow {
            version: WorkflowEventVersion::V1,
            workflow_id: "workflow-7".into(),
            event: WorkflowEvent::ChildFinished {
                task_id: 2,
                sub_run: Some("fan-parent-t00000001-n0002".into()),
                outcome: WorkflowChildOutcome::Failed,
                metrics: WorkflowMetrics {
                    provider_attempts: 3,
                    completed_turns: 2,
                    usage: Usage {
                        input: 100,
                        output: 20,
                        cache_creation: 4,
                        cache_read: 80,
                        thinking: 5,
                    },
                    tool_calls: 4,
                    tool_errors: 1,
                    model_ms: 90,
                    tools_ms: 12,
                },
                error_code: Some("child_budget_exhausted".into()),
                error_detail: Some("bounded child stopped".into()),
                summary_digest: Some("a".repeat(64)),
                evidence_bytes: 128,
            },
        };
        let encoded = serde_json::to_value(&kind).unwrap();
        let decoded: EventKind = serde_json::from_value(encoded).unwrap();
        assert!(matches!(
            decoded,
            EventKind::Workflow {
                version: WorkflowEventVersion::V1,
                workflow_id,
                event: WorkflowEvent::ChildFinished {
                    task_id: 2,
                    outcome: WorkflowChildOutcome::Failed,
                    metrics: WorkflowMetrics {
                        provider_attempts: 3,
                        tool_calls: 4,
                        ..
                    },
                    ..
                },
            } if workflow_id == "workflow-7"
        ));
    }
}
