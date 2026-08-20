//! iteron-protocol — the iteron vocabulary.
//!
//! The design decisions this file encodes as *types* (not conventions):
//!   - Trust tier (ADR-007 R11): every context segment and tool result carries one.
//!   - Purity (ADR-004 R4 / ADR-007 R16): licenses early dispatch, memoization, speculation.
//!   - Capability class (ADR-007 R12): tier by what a tool can do, not by textual reversibility.
//!   - The SQ/EQ shape (ADR-010): one id-correlated submission/event protocol; the iteron has
//!     exactly one input channel and one output channel, both correlated by `id`.
//!
//! Keep this crate small. Codex's 220 KB kitchen-sink protocol is a named defect
//! (`docs/intake/codex-deep-dive-ii.md`); we take the shape, not the sprawl.

use serde::{Deserialize, Serialize};

/// Immutable process-level parameter lookup shared with low-level crates that already depend on
/// the protocol vocabulary. In particular, this preserves the kernel's deliberately narrow
/// dependency boundary while giving its bounded resource controls the same resolved profile.
#[doc(hidden)]
pub use iteron_tunables::param_integer;

pub mod activity;
pub mod artifact;
pub mod bundle;
pub mod capability_set;
pub mod context;
pub mod diff;
pub mod effect;
pub mod erasure;
pub mod event;
pub mod ids;
pub mod intent;
pub mod lifecycle;
pub mod message;
pub mod permission;
pub mod policy_bundle_checkpoint;
pub mod policy_evidence;
pub mod pricing;
pub mod slot;
pub mod task;
pub mod tool;
pub mod trust;
pub mod tunables_snapshot;
pub mod wire;

pub mod home;
pub mod input;
pub mod text;

pub use activity::{
    ACTIVITY_SCHEMA_VERSION, ActivityCancelability, ActivityDetailCode, ActivityEvent,
    ActivityKind, ActivityOwner, ActivityProgress, ActivityState, ActivityValidationError,
    MAX_ACTIVITY_ATTEMPTS, MAX_ACTIVITY_ID_BYTES, MAX_ACTIVITY_PROGRESS_UNITS,
};
pub use diff::{DiffLine, DiffTag, FileDiff, Hunk};
pub use erasure::ids::{
    ErasureAuthorityId, ErasureContentDigest, ErasureOperationId, ErasureScopeId, ErasureTargetId,
    MAX_ERASURE_AUTHORITY_ID_BYTES, MAX_ERASURE_OPERATION_ID_BYTES, MAX_ERASURE_SCOPE_ID_BYTES,
    MAX_ERASURE_TARGET_ID_BYTES,
};
pub use erasure::{
    ERASURE_RECEIPT_SCHEMA_VERSION, ErasureFailureCode, ErasureOperationKind,
    ErasurePropagationCoverage, ErasureReceipt, ErasureRequest, ErasureState, ErasureTarget,
    ErasureValidationError, ErasureVerification, MAX_ERASURE_RECEIPT_BYTES, MAX_RETENTION_AGE_SECS,
    MAX_RETENTION_KEEP_LAST,
};
pub use event::{
    DurableEnvironmentContext, DurableInstructionContext, EnvironmentSnapshotIdentity, Event,
    EventKind, MAX_AGENT_DEFINITION_TAG_BYTES, MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES, Phase,
    ProviderGovernorDecision, ProviderGovernorDecisionVersion, ProviderHedgeSuppressionReason,
    ProviderRouteAttemptAccounting, ProviderRouteAttemptAccountingVersion,
    ProviderRouteAttemptIdentity, ProviderRouteCostTruth, ProviderRouteCostUnknownReason,
    ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason, RuntimePolicyEventVersion,
    RuntimePolicySource, RuntimePolicyState, SubmissionRejectionReason,
    VerificationConsensusEvidence, VerificationOutcomeEvidence, VerificationPolicyEvent,
    VerificationPolicyEventVersion, VerificationRollbackEvidence, VerificationSelectionEvidence,
    WorkflowChildOutcome, WorkflowCostEvidence, WorkflowEvent, WorkflowEventVersion,
    WorkflowExecutionMode, WorkflowMetrics, WorkflowOutcome, WorkflowPhase, WorkflowTaskEvidence,
};
pub use ids::{
    EffectId, JobId, RunId, Seq, SessionId, SubagentId, SubmissionId, TenantId, TurnId, WorkflowId,
};
pub use lifecycle::state::{
    AgentLoopState, ControlIntent, EffectLifecycleState, JobLifecycleState, LifecycleState,
    ProcessLifecycleState, RunLifecycleState, SessionLifecycleState, SubagentLifecycleState,
    SubmissionLifecycleState, TransitionError, TurnLifecycleState, WorkflowLifecycleState,
};
pub use lifecycle::{
    CardinalityClass, DurabilityClass, ExportPolicy, HookCapability, LifecycleAvailability,
    LifecycleCatalogVersion, LifecycleDomain, LifecycleEventEnvelope, LifecycleEventId,
    LifecycleEventRef, LifecycleEventSpec, LifecyclePayload, LifecyclePhase, LifecycleReservation,
    PrivacyClass,
};
pub use message::{
    Block, MAX_STOP_REASON_CODE_BYTES, Message, ProviderState, ProviderStateFormat, Role,
    StopReason, StopReasonCode, Usage,
};
pub use permission::{PermissionMode, PermissionRules, Verdict, gate};
pub use policy_bundle_checkpoint::{
    MAX_POLICY_IMPLEMENTATION_ID_BYTES, PolicyBundleCoverage, PolicySlotApplicationStatus,
    RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION, RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT,
    RunGenesisPolicyBundleInheritance, RunGenesisPolicyBundleSnapshot,
    RunGenesisPolicyBundleVersion, RunGenesisPolicySlotBinding,
};
pub use policy_evidence::{
    MAX_POLICY_ACTIONS, MAX_POLICY_MACHINE_ID_BYTES, POLICY_ACTION_VOCABULARY_VERSION,
    POLICY_DECISION_EVIDENCE_SCHEMA_VERSION, POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
    PolicyActionId, PolicyActionV1, PolicyDecisionDisposition, PolicyDecisionEvidence,
    PolicyEvidenceError, PolicyHarnessErrorCode, PolicyHarnessErrorJoinDigest,
    PolicyHarnessOutcomeId, PolicyOpportunityId, PolicyOpportunityJoinDigest,
    PolicyOutcomeEvidence, PolicyOutcomeScope, PolicyRuntimeIdentity, PolicyTerminalOutcome,
    PolicyVerifierOutcome,
};
pub use pricing::{
    CostAttribution, CostProjection, CostProjectionIdentity, MAX_WORKFLOW_COST_PROJECTIONS,
    PricingRoute, PricingVersion, RateCard, SignedRateCard, TokenRateCard,
};
pub use tool::{Capability, Purity, ToolResult, ToolSpec, ToolUse};
pub use trust::Trust;
pub use tunables_snapshot::{
    EXTENSION_SERVER_BINDING_PREFIX, MAX_EXTENSION_SERVER_NAME_BYTES,
    MAX_RUN_GENESIS_TUNABLE_CEILINGS, MAX_RUN_GENESIS_TUNABLE_ENTRIES,
    MAX_RUN_GENESIS_TUNABLE_ID_BYTES, MAX_RUN_GENESIS_TUNABLES_V2_BYTES,
    MAX_RUN_GENESIS_TUNABLES_V2_DEPTH, MAX_RUN_GENESIS_TUNABLES_V2_NODES,
    RUN_GENESIS_TUNABLES_CANONICALIZATION, RUN_GENESIS_TUNABLES_V2_CANONICALIZATION,
    RunGenesisFixedAuthorityBindingV2, RunGenesisFixedAuthorityIdV2, RunGenesisTunableEntryV2,
    RunGenesisTunablesSnapshotV2, RunGenesisTunablesVersionV2, is_extension_server_binding_id,
};
pub use wire::{EqEnvelope, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope};

/// Schema version for [`EventKind::TunablesSnapshot`].
/// A future format must use a new top-level event tag so an older reader can skip it safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunGenesisTunablesVersion {
    V1,
}

/// The only entry states an atomically successful resolver result may persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunGenesisTunableState {
    Effective,
    Inactive,
    Unavailable,
}

/// Bounded per-family identity and resolution state. Effective values and per-family value hashes
/// remain outside the protocol: raw hashes of low-entropy booleans, paths, providers, or model ids
/// would be dictionary-enumerable. Exact comparison uses the aggregate resolver commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisTunableEntry {
    pub ordinal: u16,
    pub family_id: String,
    pub semantic_key: String,
    pub state: RunGenesisTunableState,
}

/// Immutable identity of the complete, atomically resolved set admitted for a run.
///
/// `snapshot_digest_sha256` is recomputed at record read/write boundaries from every preceding
/// field and all entries. The three resolver digests retain their distinct meanings: frozen input,
/// effective values, and full resolution/provenance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisTunablesSnapshot {
    pub version: RunGenesisTunablesVersion,
    pub canonicalization: String,
    pub resolution_schema_version: u16,
    pub registry_id: String,
    pub registry_schema_version: u16,
    pub family_schema_version: u16,
    pub registry_revision: u16,
    pub registry_digest_sha256: String,
    pub input_digest_sha256: String,
    pub effective_digest_sha256: String,
    pub resolution_digest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest_sha256: Option<String>,
    pub entries: Vec<RunGenesisTunableEntry>,
    pub snapshot_digest_sha256: String,
}

/// Child-genesis binding to the exact parent snapshot inherited across a fork or rewind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisTunablesInheritance {
    pub parent_run: String,
    pub parent_snapshot_digest_sha256: String,
}

/// The image media types the neutral SQ contract admits.
///
/// SVG is intentionally absent: it is active document content rather than a raster image block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/gif")]
    Gif,
    #[serde(rename = "image/webp")]
    Webp,
}

/// A bounded, canonical, padded RFC 4648 base64 payload.
///
/// The inner string is private so callers cannot construct an unchecked payload. Its `Debug`
/// implementation is intentionally content-free: image bytes must not leak through diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ImageBase64(String);

/// One admitted raster image, still neutral with respect to model providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageContent {
    pub media_type: ImageMediaType,
    pub data: ImageBase64,
}

/// One attached workspace file, carried as a first-class reference beside the prompt.
///
/// The payload is UTF-8 text rather than base64: a file chip attaches something a model reads, and
/// a file that is not text has no reading. `path` is workspace-relative provenance for display and
/// for the model's benefit — nothing downstream re-opens it, so this type never becomes a
/// read-anything primitive by being decoded.
///
/// Bounds live on [`FileContent::validate`] and [`input::validate_file_submission`]. A file too
/// large to carry is refused there and never truncated: half a file answered confidently is a
/// wrong answer wearing the shape of a right one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileContent {
    /// Workspace-relative, forward-slash path. Never absolute, never containing a `..` component.
    pub path: String,
    /// The complete file text, bounded and NUL-free.
    pub text: String,
}

/// One provider-neutral user-input segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentSegment {
    Text {
        text: String,
    },
    Image {
        image: ImageContent,
    },
    /// An unknown nested segment is safe to decode and inspect, but
    /// [`input::ContentSegments::validate`] refuses to admit it. The foreign payload is discarded
    /// by serde.
    #[serde(other)]
    Unknown,
}

/// A validated text-plus-image segment list.
///
/// The wrapper keeps the vector private and validates deserialized values immediately, so an
/// `Op::UserInputV2` cannot carry an unchecked segment list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ContentSegments(Vec<ContentSegment>);

/// A submission on the SQ. The iteron consumes these; every frontend (CLI first) produces
/// them. Approvals, interrupts, and steering are all submissions on the same queue, which
/// preserves caller order for free — exactly what the ADR-006 determinism boundary needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Start a turn from operator input.
    UserInput { text: String },
    /// Start a turn from one text prompt plus bounded, provider-neutral image segments.
    ///
    /// This is a new top-level tag rather than a field added to `UserInput`, so readers predating
    /// multimodal input degrade it to [`Op::Unknown`] without changing legacy text-only bytes.
    UserInputV2 { segments: ContentSegments },
    /// Start a turn from one text prompt plus bounded, first-class file references, and optionally
    /// the same images `UserInputV2` carries.
    ///
    /// A third top-level tag rather than a field added to `UserInputV2`, because
    /// [`ContentSegments`] is frozen at "exactly one text segment and at least one image": a
    /// files-only submission has no legal shape inside it, and widening that type would change
    /// what an older reader already accepts. A reader predating this tag degrades the whole
    /// operation to [`Op::Unknown`] and refuses it, which is the outcome we want — such a build
    /// cannot show the operator the files they attached, so guessing at a text-only turn would
    /// answer a question nobody asked.
    ///
    /// `files` is never empty: a submission with no files belongs on `UserInput` or
    /// `UserInputV2`. [`input::validate_file_submission`] is the admission check.
    UserInputV3 {
        text: String,
        #[serde(default)]
        images: Vec<ImageContent>,
        files: Vec<FileContent>,
    },
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
    /// Escalated turn cancellation. The resident session drops the in-flight turn future after a
    /// cooperative interrupt grace without draining the session or cleaning background jobs.
    ForceCancel,
    /// Stop admitting work, quiesce, commit a durable workspace checkpoint, then exit (the
    /// `drain` verb; ADR-008 safe-point).
    Drain,
    /// Forward-compatible rejection sentinel. Deserialization deliberately discards the unknown
    /// tag and every accompanying field, so a newer client's opaque payload cannot enter logs,
    /// errors, UI, or the durable record through this value.
    #[serde(other)]
    Unknown,
}

/// Effort level (session setting). Maps to (a) the model's reasoning/thinking budget and
/// (b) the orchestration strategy — `Ultracode` enables iteron's internal workflow/subagent
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
// No `Eq`: `max_usd` is an f64. `PartialEq` is what `TaskEnvelope` needs to derive its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub max_turns: u32,
    /// Optional operator-requested USD ceiling. `None` is honest absence of a monetary guarantee;
    /// a positive ceiling requires a verified route-bound rate card, while zero is universally
    /// enforceable without admitting a provider request.
    pub max_usd: Option<f64>,
    /// Optional aggregate provider-token ceiling across the run and all descendants. This was
    /// appended after the ABI freeze, so absence retains the exact pre-append wire bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    pub max_wall_secs: u64,
    pub max_consecutive_tool_errors: u32,
}

impl Default for Budget {
    fn default() -> Self {
        // Turn and wall ceilings are always enforceable. Monetary control is opt-in because a
        // guessed universal price table is worse than no dollar claim at all.
        //
        // Owner-directed 2026-08-05: the ceilings were raised, not removed — invariant #1 is that
        // everything HAS a ceiling, not that the ceiling is small. Each old value was reached in
        // ordinary use and read as the agent giving up rather than as a declared bound.
        Self {
            max_turns: 600,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 14_400,
            // Three consecutive tool errors used to end a run. That interacted badly with the
            // path rules removed in this change: an absolute path failed, the model retried with
            // another absolute path, and the third failure killed a run that had nothing wrong
            // with it. A stability floor should catch a model that cannot make progress, which
            // takes more than three tries to establish.
            max_consecutive_tool_errors: 25,
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
    use crate::input::{ContentSegment, ContentSegments, ImageContent, ImageMediaType};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case")]
    enum LegacyOp {
        UserInput {
            text: String,
        },
        ApprovalResponse {
            id: SubmissionId,
            approved: bool,
            #[serde(default)]
            remember: bool,
        },
        Steer {
            text: String,
        },
        Interrupt,
        Drain,
        #[serde(other)]
        Unknown,
    }

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

    #[test]
    fn text_only_bytes_are_frozen_and_old_readers_drop_multimodal_payloads() {
        let legacy = Op::UserInput {
            text: "Retain every public SQ field.".into(),
        };
        assert_eq!(
            serde_json::to_string(&legacy).unwrap(),
            r#"{"op":"user_input","text":"Retain every public SQ field."}"#
        );

        let marker = "c2VjcmV0LWltYWdlLWJ5dGVz";
        let multimodal = Op::UserInputV2 {
            segments: ContentSegments::new(vec![
                ContentSegment::Text {
                    text: "describe".into(),
                },
                ContentSegment::Image {
                    image: ImageContent::new(ImageMediaType::Png, marker).unwrap(),
                },
            ])
            .unwrap(),
        };
        assert_eq!(
            serde_json::to_value(&multimodal).unwrap(),
            serde_json::json!({
                "op": "user_input_v2",
                "segments": [
                    {"type": "text", "text": "describe"},
                    {
                        "type": "image",
                        "image": {"media_type": "image/png", "data": marker}
                    }
                ]
            })
        );

        let old: LegacyOp =
            serde_json::from_value(serde_json::to_value(&multimodal).unwrap()).unwrap();
        assert!(matches!(old, LegacyOp::Unknown));
        assert!(!format!("{old:?}").contains(marker));
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::json!({"op": "unknown"})
        );
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
            max_tokens: None,
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
