//! Registry-tool effect admission and recovery invariants.
//!
//! This is deliberately narrower than a universal effect broker: it covers only tool calls that
//! pass through `core_tools::Registry`. Provider requests, hooks, MCP lifecycle, checkpoints,
//! memory writes, and subagents still need the same boundary before Core can claim full coverage.
//! The code here is constitutional mechanism, never a learnable/evolvable strategy slot.

use core_protocol::{Capability, EffectId, Event, EventKind, Seq, ToolUse, TurnId};
use core_tools::ToolExecution;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

pub const MAX_TOOL_CALLS_PER_TURN: usize = 128;
pub const MAX_TOOL_USE_ID_BYTES: usize = 512;
pub const MAX_TOOL_NAME_BYTES: usize = 256;
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;

/// Admission state for model-emitted tool calls in one provider turn. Validation happens before a
/// call crosses the UI, record, or registry boundary. The count ceiling is a hard resource guard,
/// not a scheduler policy.
#[derive(Debug, Default)]
pub struct ToolCallAdmission {
    ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ToolCallContractError {
    #[error("provider emitted more than the hard per-turn tool-call ceiling")]
    TooMany,
    #[error("provider emitted an empty or oversized tool-use id")]
    InvalidId,
    #[error("provider emitted a control/invisible character in tool identity")]
    UnsafeIdentity,
    #[error("provider emitted a secret-shaped tool identity")]
    SecretShapedIdentity,
    #[error("provider emitted a duplicate tool-use id in one turn")]
    DuplicateId,
    #[error("provider emitted an empty or oversized tool name")]
    InvalidName,
    #[error("provider emitted tool arguments past the hard byte ceiling")]
    ArgumentsTooLarge,
}

impl ToolCallAdmission {
    pub fn admit(&mut self, tool: &ToolUse) -> Result<(), ToolCallContractError> {
        if self.ids.len() >= MAX_TOOL_CALLS_PER_TURN {
            return Err(ToolCallContractError::TooMany);
        }
        if tool.id.trim().is_empty() || tool.id.len() > MAX_TOOL_USE_ID_BYTES {
            return Err(ToolCallContractError::InvalidId);
        }
        if tool.name.trim().is_empty() || tool.name.len() > MAX_TOOL_NAME_BYTES {
            return Err(ToolCallContractError::InvalidName);
        }
        if unsafe_identity(&tool.id) || unsafe_identity(&tool.name) {
            return Err(ToolCallContractError::UnsafeIdentity);
        }
        if core_record::redact::scrub(&tool.id) != tool.id
            || core_record::redact::scrub(&tool.name) != tool.name
        {
            return Err(ToolCallContractError::SecretShapedIdentity);
        }
        if !self.ids.insert(tool.id.clone()) {
            return Err(ToolCallContractError::DuplicateId);
        }
        if serde_json::to_vec(&tool.input)
            .map(|bytes| bytes.len() > MAX_TOOL_ARGUMENT_BYTES)
            .unwrap_or(true)
        {
            return Err(ToolCallContractError::ArgumentsTooLarge);
        }
        Ok(())
    }
}

fn unsafe_identity(value: &str) -> bool {
    value.chars().any(|character| {
        character.is_control()
            || matches!(
                character as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x00AD | 0xFEFF
            )
    })
}

/// Mint a deterministic, harness-owned effect identity. Turn ids are recovered monotonically from
/// the complete fork-aware durable history; `ordinal` is the provider's bounded tool order.
pub fn effect_id(turn: TurnId, ordinal: usize) -> EffectId {
    EffectId(format!("fx1-{:08x}-{ordinal:04x}", turn.0))
}

/// Fully admitted registry call. Constructing this value does not grant authority; the caller must
/// already have completed the constitutional capability/taint/approval checks. The boundary owns
/// only the non-negotiable WAL ordering from this point onward.
pub(crate) struct AdmittedRegistryTool {
    pub turn: TurnId,
    pub effect_id: EffectId,
    pub call: ToolUse,
    pub capability: Capability,
    pub audit_arguments: serde_json::Value,
    pub workspace: String,
}

pub(crate) trait DurableEffectLog {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, core_record::RecordError>;
}

impl DurableEffectLog for core_record::Rollout {
    fn append_effect(&mut self, event: &Event) -> Result<Seq, core_record::RecordError> {
        self.append(event)
    }
}

/// The only registry-effect dispatch sequence: durable intent, exactly one executor invocation,
/// durable terminal. It returns no result until the terminal append/fsync succeeds, keeping every
/// UI/transcript/ledger projection downstream of canonical state.
pub(crate) async fn execute_registry_tool<L, Execute, ExecuteFuture, Execution>(
    log: &mut L,
    admitted: AdmittedRegistryTool,
    execute: Execute,
) -> Result<ToolExecution, core_record::RecordError>
where
    L: DurableEffectLog,
    Execute: FnOnce(ToolUse) -> ExecuteFuture,
    ExecuteFuture: Future<Output = Execution>,
    Execution: Into<ToolExecution>,
{
    let AdmittedRegistryTool {
        turn,
        effect_id,
        call,
        capability,
        audit_arguments,
        workspace,
    } = admitted;
    let provider_tool_use_id = call.id.clone();
    let tool_name = call.name.clone();
    log.append_effect(&Event {
        seq: Seq::ZERO,
        turn,
        kind: EventKind::EffectIntent {
            id: effect_id.clone(),
            tool_use_id: provider_tool_use_id.clone(),
            tool: call.name.clone(),
            capability,
            arguments: audit_arguments,
            workspace,
        },
    })?;

    let mut outcome = execute(call).await.into();
    // Correlation identity belongs to the admitted call, never to plugin-returned data. Registry
    // already enforces this; repeating it here protects future executors behind the same boundary.
    let result = match &mut outcome {
        ToolExecution::Definite(result) | ToolExecution::Unknown(result) => result,
    };
    result.tool_use_id = provider_tool_use_id;
    match &outcome {
        ToolExecution::Definite(result) => {
            log.append_effect(&Event {
                seq: Seq::ZERO,
                turn,
                kind: EventKind::ToolDone {
                    result: result.clone(),
                    effect_id: Some(effect_id),
                },
            })?;
        }
        ToolExecution::Unknown(_) => {
            log.append_effect(&Event {
                seq: Seq::ZERO,
                turn,
                kind: EventKind::EffectUnknown {
                    id: effect_id,
                    tool: tool_name,
                    reason: "executor dispatched the operation but did not observe an authoritative terminal outcome; automatic retry is forbidden".into(),
                },
            })?;
        }
    }
    Ok(outcome)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEffect {
    pub turn: TurnId,
    pub id: EffectId,
    pub tool: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EffectJournalError {
    #[error("effect journal contains a duplicate intent identity")]
    DuplicateIntent,
    #[error("effect journal contains a terminal result without its intent")]
    TerminalWithoutIntent,
    #[error("effect journal contains more than one terminal state for an intent")]
    DuplicateTerminal,
    #[error("effect journal contains an unknown marker without its intent")]
    UnknownWithoutIntent,
    #[error("effect journal tries to resolve an unknown outcome without reconciliation evidence")]
    TerminalAfterUnknown,
    #[error("effect journal marks a completed attempt as unknown")]
    UnknownAfterTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Completed,
    Unknown,
}

#[derive(Debug, Clone)]
struct Entry {
    turn: TurnId,
    id: EffectId,
    tool: String,
    legacy_tool_use_id: Option<String>,
    state: State,
}

/// Pure fold of the durable effect sub-log. It never executes, retries, approves, or reconciles an
/// effect; it only reports the state implied by canonical events.
#[derive(Debug, Default)]
pub struct EffectJournal {
    entries: BTreeMap<(u32, String), Entry>,
}

impl EffectJournal {
    pub fn replay(events: &[Event]) -> Result<Self, EffectJournalError> {
        let mut journal = Self::default();
        for event in events {
            journal.apply(event)?;
        }
        Ok(journal)
    }

    fn apply(&mut self, event: &Event) -> Result<(), EffectJournalError> {
        match &event.kind {
            EventKind::EffectIntent {
                id,
                tool_use_id,
                tool,
                ..
            } => {
                let key = (event.turn.0, id.0.clone());
                if self.entries.contains_key(&key) {
                    return Err(EffectJournalError::DuplicateIntent);
                }
                self.entries.insert(
                    key,
                    Entry {
                        turn: event.turn,
                        id: id.clone(),
                        tool: tool.clone(),
                        legacy_tool_use_id: tool_use_id.is_empty().then(|| id.0.clone()),
                        state: State::Pending,
                    },
                );
            }
            EventKind::ToolDone { result, effect_id } => {
                let key = if let Some(id) = effect_id {
                    Some((event.turn.0, id.0.clone()))
                } else {
                    self.entries.iter().find_map(|(key, entry)| {
                        (entry.turn == event.turn
                            && entry.legacy_tool_use_id.as_deref()
                                == Some(result.tool_use_id.as_str()))
                        .then(|| key.clone())
                    })
                };
                let Some(key) = key else {
                    // Pure tools and gate-denied calls intentionally have no EffectIntent.
                    return Ok(());
                };
                let Some(entry) = self.entries.get_mut(&key) else {
                    return Err(EffectJournalError::TerminalWithoutIntent);
                };
                entry.state = match entry.state {
                    State::Pending => State::Completed,
                    State::Completed => return Err(EffectJournalError::DuplicateTerminal),
                    State::Unknown => return Err(EffectJournalError::TerminalAfterUnknown),
                };
            }
            EventKind::EffectUnknown { id, .. } => {
                let key = (event.turn.0, id.0.clone());
                let Some(entry) = self.entries.get_mut(&key) else {
                    return Err(EffectJournalError::UnknownWithoutIntent);
                };
                entry.state = match entry.state {
                    State::Pending => State::Unknown,
                    State::Completed => return Err(EffectJournalError::UnknownAfterTerminal),
                    State::Unknown => return Err(EffectJournalError::DuplicateTerminal),
                };
            }
            _ => {}
        }
        Ok(())
    }

    pub fn pending(&self) -> Vec<PendingEffect> {
        self.entries
            .values()
            .filter(|entry| entry.state == State::Pending)
            .map(|entry| PendingEffect {
                turn: entry.turn,
                id: entry.id.clone(),
                tool: entry.tool.clone(),
            })
            .collect()
    }

    pub fn unknown_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.state == State::Unknown)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{Capability, Seq, ToolResult, Trust};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn intent(turn: u32, id: &str, tool_use_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(turn),
            kind: EventKind::EffectIntent {
                id: EffectId(id.into()),
                tool_use_id: tool_use_id.into(),
                tool: "edit".into(),
                capability: Capability::ReversibleLocal,
                arguments: serde_json::json!({"path":"f"}),
                workspace: "/repo".into(),
            },
        }
    }

    fn done(turn: u32, id: Option<&str>, tool_use_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(turn),
            kind: EventKind::ToolDone {
                result: ToolResult {
                    tool_use_id: tool_use_id.into(),
                    content: "ok".into(),
                    is_error: false,
                    trust: Trust::Workspace,
                    latency_ms: 1,
                },
                effect_id: id.map(|value| EffectId(value.into())),
            },
        }
    }

    #[test]
    fn admission_rejects_duplicates_secrets_bidi_and_unbounded_arguments() {
        let mut admission = ToolCallAdmission::default();
        let base = ToolUse {
            id: "call-1".into(),
            name: "edit".into(),
            input: serde_json::json!({"path":"f"}),
        };
        admission.admit(&base).unwrap();
        assert_eq!(
            admission.admit(&base),
            Err(ToolCallContractError::DuplicateId)
        );
        let mut secret = base.clone();
        secret.id = "sk-\
proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
            .into();
        assert_eq!(
            ToolCallAdmission::default().admit(&secret),
            Err(ToolCallContractError::SecretShapedIdentity)
        );
        let mut bidi = base.clone();
        bidi.id = "call-\u{202e}1".into();
        assert_eq!(
            ToolCallAdmission::default().admit(&bidi),
            Err(ToolCallContractError::UnsafeIdentity)
        );
        let mut huge = base;
        huge.input = serde_json::Value::String("x".repeat(MAX_TOOL_ARGUMENT_BYTES + 1));
        assert_eq!(
            ToolCallAdmission::default().admit(&huge),
            Err(ToolCallContractError::ArgumentsTooLarge)
        );
    }

    #[test]
    fn modern_terminal_correlates_by_harness_id_not_model_id() {
        let events = vec![
            intent(2, "fx1-00000002-0001", "model-id"),
            done(
                2,
                Some("fx1-00000002-0001"),
                "executor-returned-a-different-id",
            ),
        ];
        let journal = EffectJournal::replay(&events).unwrap();
        assert!(journal.pending().is_empty());
        assert_eq!(journal.unknown_count(), 0);
    }

    #[test]
    fn legacy_intent_still_correlates_with_tool_done() {
        let events = vec![
            intent(3, "legacy-tool-id", ""),
            done(3, None, "legacy-tool-id"),
        ];
        assert!(EffectJournal::replay(&events).unwrap().pending().is_empty());
    }

    #[test]
    fn duplicates_and_unauthenticated_unknown_resolution_fail_closed() {
        let i = intent(1, "fx1-00000001-0000", "call");
        assert_eq!(
            EffectJournal::replay(&[i.clone(), i.clone()]).unwrap_err(),
            EffectJournalError::DuplicateIntent
        );
        let unknown = Event {
            seq: Seq::ZERO,
            turn: TurnId(1),
            kind: EventKind::EffectUnknown {
                id: EffectId("fx1-00000001-0000".into()),
                tool: "edit".into(),
                reason: "crash window".into(),
            },
        };
        assert_eq!(
            EffectJournal::replay(&[i, unknown, done(1, Some("fx1-00000001-0000"), "call"),])
                .unwrap_err(),
            EffectJournalError::TerminalAfterUnknown
        );
    }

    #[derive(Default)]
    struct FakeLog {
        events: Vec<Event>,
        fail_on_append: Option<usize>,
    }

    impl DurableEffectLog for FakeLog {
        fn append_effect(&mut self, event: &Event) -> Result<Seq, core_record::RecordError> {
            if self.fail_on_append == Some(self.events.len()) {
                return Err(std::io::Error::other("injected append failure").into());
            }
            self.events.push(event.clone());
            Ok(Seq((self.events.len() - 1) as u64))
        }
    }

    fn admitted() -> AdmittedRegistryTool {
        AdmittedRegistryTool {
            turn: TurnId(7),
            effect_id: effect_id(TurnId(7), 2),
            call: ToolUse {
                id: "provider-call".into(),
                name: "edit".into(),
                input: serde_json::json!({"path":"f"}),
            },
            capability: Capability::ReversibleLocal,
            audit_arguments: serde_json::json!({"path":"f"}),
            workspace: "/repo".into(),
        }
    }

    #[tokio::test]
    async fn boundary_never_executes_before_a_durable_intent() {
        let mut log = FakeLog {
            fail_on_append: Some(0),
            ..FakeLog::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let result = execute_registry_tool(&mut log, admitted(), move |call| async move {
            executor_calls.fetch_add(1, Ordering::SeqCst);
            ToolResult {
                tool_use_id: call.id,
                content: "ran".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 0,
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(log.events.is_empty());
    }

    #[tokio::test]
    async fn terminal_failure_leaves_one_recoverable_pending_intent() {
        let mut log = FakeLog {
            fail_on_append: Some(1),
            ..FakeLog::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let result = execute_registry_tool(&mut log, admitted(), move |call| async move {
            executor_calls.fetch_add(1, Ordering::SeqCst);
            ToolResult {
                // A plugin cannot replace the admitted provider correlation id.
                tool_use_id: "wrong-id".into(),
                content: format!("ran {}", call.name),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 0,
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let journal = EffectJournal::replay(&log.events).unwrap();
        assert_eq!(journal.pending().len(), 1);
    }

    #[tokio::test]
    async fn successful_boundary_is_intent_then_terminal_and_normalizes_result_id() {
        let mut log = FakeLog::default();
        let result = execute_registry_tool(&mut log, admitted(), |_| async {
            ToolResult {
                tool_use_id: "plugin-controlled".into(),
                content: "ok".into(),
                is_error: false,
                trust: Trust::Workspace,
                latency_ms: 0,
            }
        })
        .await
        .unwrap()
        .into_result();
        assert_eq!(result.tool_use_id, "provider-call");
        assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
        assert!(matches!(
            log.events[1].kind,
            EventKind::ToolDone {
                effect_id: Some(_),
                ..
            }
        ));
        assert!(
            EffectJournal::replay(&log.events)
                .unwrap()
                .pending()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn runtime_unknown_is_durable_and_never_fabricates_tool_done() {
        let mut log = FakeLog::default();
        let outcome = execute_registry_tool(&mut log, admitted(), |_| async {
            ToolExecution::Unknown(ToolResult {
                tool_use_id: "plugin-controlled".into(),
                content: "remote state unknown".into(),
                is_error: true,
                trust: Trust::Untrusted,
                latency_ms: 0,
            })
        })
        .await
        .unwrap();
        assert!(matches!(outcome, ToolExecution::Unknown(_)));
        assert!(matches!(log.events[0].kind, EventKind::EffectIntent { .. }));
        assert!(matches!(
            log.events[1].kind,
            EventKind::EffectUnknown { .. }
        ));
        assert!(
            !log.events
                .iter()
                .any(|event| matches!(event.kind, EventKind::ToolDone { .. }))
        );
        let journal = EffectJournal::replay(&log.events).unwrap();
        assert_eq!(journal.unknown_count(), 1);
        assert!(journal.pending().is_empty());
    }
}
