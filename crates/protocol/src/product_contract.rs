//! Public, bounded Thread/Turn/Item view of the resident App Server.
//!
//! Version 1 exposes a bounded, cursor-addressed content stream alongside read and control.
//! Its resident replay is not a durable rollout; an expired cursor reports a gap explicitly.
//! A queued control receipt never claims execution or an authorized effect.

use crate::{
    Capability, PolicyHarnessErrorCode, RunId, SessionId, SubmissionId, SubmissionLifecycleState,
};
use serde::{Deserialize, Serialize};

pub const PRODUCT_CONTRACT_VERSION: u32 = 1;
pub const MAX_THREAD_ITEMS: usize = 256;
pub const MAX_THREAD_SUBMISSIONS: usize = 256;
pub const MAX_PRODUCT_EVENTS: usize = 512;
pub const MAX_PRODUCT_EVENT_BYTES: usize = 1024 * 1024;
pub const MAX_PRODUCT_CONTENT_CHUNK_BYTES: usize = 8 * 1024;
/// A single source EQ event cannot inject unbounded text into the public projection.
pub const MAX_PRODUCT_SOURCE_CONTENT_BYTES: usize = 256 * 1024;
pub const MAX_PRODUCT_APPROVAL_FIELD_BYTES: usize = 1024;
pub const MAX_PRODUCT_APPROVAL_ARGUMENTS_BYTES: usize = 4 * 1024;
pub const MAX_PRODUCT_READ_EVENTS: usize = 64;
pub const MAX_PRODUCT_READ_BYTES: usize = 64 * 1024;

/// One user-facing App Server turn. This is distinct from the kernel `TurnId`, which names one
/// model call; a user-facing turn can contain several model calls and tool executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProductTurnId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadSnapshotV1 {
    pub contract_version: u32,
    pub thread_id: SessionId,
    pub run_id: RunId,
    /// Last in-process EQ event incorporated here. It is neither a durable rollout cursor nor
    /// the headless presentation cursor (which excludes some EQ variants).
    pub source_event_seq: u64,
    /// The active or most recently completed runtime turn. Older turns are read from the rollout.
    pub turn: Option<TurnSnapshotV1>,
    /// Recent submission lifecycles, keyed by submission ID. Older entries are explicitly counted
    /// when this bounded window fills; queued is not equivalent to applied.
    pub submissions: Vec<SubmissionReceiptV1>,
    pub evicted_submissions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnSnapshotV1 {
    pub turn_id: ProductTurnId,
    pub submission_id: Option<SubmissionId>,
    pub state: TurnStateV1,
    pub items: Vec<ItemSnapshotV1>,
    /// Further items were omitted after the fixed retention ceiling, never silently renumbered.
    pub omitted_items: u32,
    pub pending_approval: Option<SubmissionId>,
    pub terminal_reason_code: Option<String>,
    /// Set exactly once when the resident runtime publishes its terminal authority.
    pub terminal_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStateV1 {
    Running,
    Completed,
    Interrupted,
    Drained,
    BudgetExhausted,
    Stuck,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSnapshotV1 {
    /// App Server minted; provider tool-call IDs are never treated as product authority.
    pub item_id: String,
    pub kind: ItemKindV1,
    pub state: ItemStateV1,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKindV1 {
    AssistantMessage,
    Reasoning,
    ToolCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStateV1 {
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionReceiptV1 {
    pub submission_id: SubmissionId,
    pub state: SubmissionLifecycleState,
    pub reason_code: Option<String>,
}

/// An App Server projected event cursor, independent of both EQ and headless presentation cursors.
/// Event IDs increase within one resident thread and survive headless client reconnects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEventV1 {
    pub event_seq: u64,
    /// `None` for App Server turn admission, which has no EQ event of its own.
    pub source_event_seq: Option<u64>,
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub turn_id: Option<ProductTurnId>,
    pub item_id: Option<String>,
    pub event: ProductEventKindV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductEventKindV1 {
    TurnStarted {
        submission_id: Option<SubmissionId>,
    },
    ItemStarted {
        kind: ItemKindV1,
        title: Option<String>,
    },
    ItemContent {
        channel: ItemContentChannelV1,
        content: String,
    },
    /// Redacted source content exceeded the per-event capture bound. The omitted bytes are never
    /// represented as successfully delivered item content.
    ContentOmitted {
        channel: ItemContentChannelV1,
        omitted_redacted_bytes: usize,
    },
    ItemEnded {
        state: ItemStateV1,
    },
    Submission {
        receipt: SubmissionReceiptV1,
    },
    ApprovalRequested {
        approval_id: SubmissionId,
        tool: String,
        capability: Capability,
        reason: String,
        arguments_json: Option<String>,
        workspace: String,
        /// False if any displayed field exceeded its public bound; approval is then refused.
        prompt_complete: bool,
    },
    ApprovalResolved {
        approval_id: SubmissionId,
        resolution: ApprovalResolutionV1,
        reason_code: String,
    },
    SourceGap {
        dropped: usize,
    },
    TerminalTextUnavailable {
        reason_code: String,
    },
    TurnEnded {
        state: TurnStateV1,
        reason_code: Option<String>,
        error: Option<String>,
        /// True only when the exact terminal assistant text was emitted as `final_answer`.
        terminal_text_exact: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemContentChannelV1 {
    Assistant,
    /// Replaces streamed assistant deltas as the terminal's authoritative final text.
    FinalAnswer,
    Reasoning,
    ToolInputJson,
    ToolOutput,
}

/// A permission decision. `Approved` is not evidence that a tool ran or had an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResolutionV1 {
    Approved,
    Denied,
    Cancelled,
    TimedOut,
}

/// The terminal authority is retained separately from the bounded content ring so a reconnect
/// can still see the latest terminal after an explicit content gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductTerminalV1 {
    pub event_seq: u64,
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub turn_id: ProductTurnId,
    pub state: TurnStateV1,
    pub reason_code: Option<String>,
    pub error: Option<String>,
    pub terminal_text_exact: bool,
}

/// What the runtime can prove about external effects in one user-facing turn. `AllSettled`
/// means every admitted effect has a durable terminal; it does not mean those effects succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalEffectStateV1 {
    NotDispatched,
    AllSettled,
    Unknown,
    /// The runtime could not provide a trustworthy aggregate, including when its journal failed.
    Unavailable,
}

/// Content-free terminal classification. Neither field may be inferred from an error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalEvidenceV1 {
    pub failure_code: Option<PolicyHarnessErrorCode>,
    pub effect_state: TerminalEffectStateV1,
}

impl TerminalEvidenceV1 {
    pub const fn unavailable() -> Self {
        Self {
            failure_code: None,
            effect_state: TerminalEffectStateV1::Unavailable,
        }
    }
}

/// Explicitly requested terminal diagnostics. Keeping this outside the existing V1 event and
/// snapshot shapes preserves strict old V1 deserializers while retaining reconnect evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductTerminalDiagnosticsV1 {
    pub contract_version: u32,
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub turn_id: ProductTurnId,
    pub terminal_event_seq: u64,
    pub evidence: TerminalEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEventGapV1 {
    pub requested_after: u64,
    pub oldest_available: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEventsPageV1 {
    pub contract_version: u32,
    pub thread_id: SessionId,
    pub requested_after: u64,
    /// Resume with this cursor after processing every returned event.
    pub next_cursor: u64,
    pub latest_cursor: u64,
    pub oldest_available: u64,
    pub gap: Option<ProductEventGapV1>,
    pub events: Vec<ProductEventV1>,
    pub latest_terminal: Option<ProductTerminalV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductEventsReadErrorV1 {
    CursorAhead {
        requested_after: u64,
        latest_cursor: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductControlV1 {
    ThreadRead {
        thread_id: SessionId,
    },
    TerminalDiagnosticsRead {
        thread_id: SessionId,
        turn_id: ProductTurnId,
    },
    EventsRead {
        thread_id: SessionId,
        after: u64,
    },
    TurnStart {
        thread_id: SessionId,
        text: String,
    },
    TurnSteer {
        thread_id: SessionId,
        turn_id: ProductTurnId,
        text: String,
    },
    TurnInterrupt {
        thread_id: SessionId,
        turn_id: ProductTurnId,
    },
    TurnDrain {
        thread_id: SessionId,
        turn_id: ProductTurnId,
    },
    ApprovalRespond {
        thread_id: SessionId,
        turn_id: ProductTurnId,
        approval_id: SubmissionId,
        approved: bool,
        #[serde(default)]
        remember: bool,
    },
}

impl ProductControlV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::ThreadRead { thread_id }
            | Self::TerminalDiagnosticsRead { thread_id, .. }
            | Self::EventsRead { thread_id, .. }
            | Self::TurnStart { thread_id, .. }
            | Self::TurnSteer { thread_id, .. }
            | Self::TurnInterrupt { thread_id, .. }
            | Self::TurnDrain { thread_id, .. }
            | Self::ApprovalRespond { thread_id, .. } => thread_id,
        }
    }

    pub fn turn_id(&self) -> Option<ProductTurnId> {
        match self {
            Self::ThreadRead { .. } | Self::EventsRead { .. } | Self::TurnStart { .. } => None,
            Self::TerminalDiagnosticsRead { turn_id, .. }
            | Self::TurnSteer { turn_id, .. }
            | Self::TurnInterrupt { turn_id, .. }
            | Self::TurnDrain { turn_id, .. }
            | Self::ApprovalRespond { turn_id, .. } => Some(*turn_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn control_shape_is_versioned_and_rejects_unknown_fields() {
        let command: ProductControlV1 = serde_json::from_value(json!({
            "type": "turn_interrupt", "thread_id": "session-r1", "turn_id": 3
        }))
        .unwrap();
        assert_eq!(command.thread_id().0, "session-r1");
        assert_eq!(command.turn_id(), Some(ProductTurnId(3)));
        assert!(
            serde_json::from_value::<ProductControlV1>(json!({
                "type": "turn_interrupt", "thread_id": "session-r1", "turn_id": 3,
                "force": true
            }))
            .is_err()
        );
        let read: ProductControlV1 = serde_json::from_value(json!({
            "type": "events_read", "thread_id": "session-r1", "after": 12
        }))
        .unwrap();
        assert_eq!(read.thread_id().0, "session-r1");
        assert!(matches!(
            read,
            ProductControlV1::EventsRead { after: 12, .. }
        ));
        assert_eq!(
            serde_json::to_value(ProductEventsReadErrorV1::CursorAhead {
                requested_after: 12,
                latest_cursor: 10,
            })
            .unwrap(),
            json!({
                "type": "cursor_ahead", "requested_after": 12, "latest_cursor": 10
            })
        );
    }

    #[test]
    fn terminal_diagnostics_are_opt_in_and_old_v1_frames_stay_exact() {
        let old = ProductControlV1::ThreadRead {
            thread_id: SessionId("session-r1".into()),
        };
        assert_eq!(
            serde_json::to_value(old).unwrap(),
            json!({"type": "thread_read", "thread_id": "session-r1"})
        );
        let command: ProductControlV1 = serde_json::from_value(json!({
            "type": "terminal_diagnostics_read", "thread_id": "session-r1", "turn_id": 3
        }))
        .unwrap();
        assert_eq!(command.turn_id(), Some(ProductTurnId(3)));
        assert!(
            serde_json::from_value::<ProductControlV1>(json!({
                "type": "terminal_diagnostics_read", "thread_id": "session-r1",
                "turn_id": 3, "extra": true
            }))
            .is_err()
        );
        let diagnostics = ProductTerminalDiagnosticsV1 {
            contract_version: PRODUCT_CONTRACT_VERSION,
            thread_id: SessionId("session-r1".into()),
            run_id: RunId("r1".into()),
            turn_id: ProductTurnId(3),
            terminal_event_seq: 9,
            evidence: TerminalEvidenceV1 {
                failure_code: Some(PolicyHarnessErrorCode::ProviderError),
                effect_state: TerminalEffectStateV1::Unknown,
            },
        };
        let encoded = serde_json::to_value(&diagnostics).unwrap();
        assert_eq!(encoded["evidence"]["failure_code"], "provider_error");
        assert_eq!(encoded["evidence"]["effect_state"], "unknown");
        assert_eq!(
            serde_json::from_value::<ProductTerminalDiagnosticsV1>(encoded).unwrap(),
            diagnostics
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_turn_and_item_identity() {
        let snapshot = ThreadSnapshotV1 {
            contract_version: PRODUCT_CONTRACT_VERSION,
            thread_id: SessionId("session-r1".into()),
            run_id: RunId("r1".into()),
            source_event_seq: 9,
            turn: Some(TurnSnapshotV1 {
                turn_id: ProductTurnId(3),
                submission_id: Some(SubmissionId(7)),
                state: TurnStateV1::Running,
                items: vec![ItemSnapshotV1 {
                    item_id: "item-1".into(),
                    kind: ItemKindV1::AssistantMessage,
                    state: ItemStateV1::InProgress,
                    title: None,
                }],
                omitted_items: 0,
                pending_approval: None,
                terminal_reason_code: None,
                terminal_error: None,
            }),
            submissions: Vec::new(),
            evicted_submissions: 0,
        };
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<ThreadSnapshotV1>(&encoded).unwrap(),
            snapshot
        );
    }
}
