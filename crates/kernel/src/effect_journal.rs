//! Pure replay fold of the durable effect sub-log.
//!
//! This module never executes, retries, approves, or reconciles an effect. It answers exactly one
//! question from canonical events: which admitted intents are still pending, and which ended in a
//! state no one could prove. Recovery reads that answer; it does not get a second opinion.
//!
//! Split out of `crate::effects` when the boundary went universal (#16): the dispatch sequence and
//! the replay fold are different concerns with different risks, and `AGENTS.md` asks for a new
//! module rather than a longer one.

use crate::effect_class::EffectClass;
use iteron_protocol::{EffectId, Event, EventKind, ProviderRouteAttemptIdentity, TurnId};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEffect {
    pub turn: TurnId,
    pub id: EffectId,
    pub tool: String,
    pub provider_route_attempt: Option<ProviderRouteAttemptIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EffectJournalError {
    #[error("record replay policy does not require fail-closed effect-terminal verification")]
    ReplayPolicyDisabled,
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
    provider_route_attempt: Option<ProviderRouteAttemptIdentity>,
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
        let replay_policy = iteron_record::replay_divergence_detection_policy();
        if !replay_policy.verify_effect_terminals() || !replay_policy.fail_closed() {
            return Err(EffectJournalError::ReplayPolicyDisabled);
        }
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
                provider_route_attempt,
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
                        provider_route_attempt: provider_route_attempt.clone(),
                        state: State::Pending,
                    },
                );
            }
            EventKind::ToolDone {
                result, effect_id, ..
            } => {
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
            // The terminals for every class that is not a registry tool call. They correlate by
            // `(turn, id)` only: there is no model tool-use id to fall back on, and no legacy form
            // to be compatible with, because both tags were introduced with the universal boundary.
            EventKind::EffectDone { id, .. } | EventKind::EffectFailed { id, .. } => {
                let key = (event.turn.0, id.0.clone());
                let Some(entry) = self.entries.get_mut(&key) else {
                    return Err(EffectJournalError::TerminalWithoutIntent);
                };
                entry.state = match entry.state {
                    State::Pending => State::Completed,
                    State::Completed => return Err(EffectJournalError::DuplicateTerminal),
                    State::Unknown => return Err(EffectJournalError::TerminalAfterUnknown),
                };
            }
            _ => {}
        }
        Ok(())
    }

    /// Every identity this journal has seen admitted, in whatever state it ended.
    ///
    /// `EffectAdmissions` seeds the live at-most-once ledger from this on resume. It deliberately
    /// includes completed and unknown entries: an identity that already reached a terminal must
    /// still never be minted twice.
    pub fn admitted(&self) -> impl Iterator<Item = (TurnId, &EffectId)> {
        self.entries.values().map(|entry| (entry.turn, &entry.id))
    }

    pub fn pending(&self) -> Vec<PendingEffect> {
        self.entries
            .values()
            .filter(|entry| entry.state == State::Pending)
            .map(|entry| PendingEffect {
                turn: entry.turn,
                id: entry.id.clone(),
                tool: entry.tool.clone(),
                provider_route_attempt: entry.provider_route_attempt.clone(),
            })
            .collect()
    }

    pub fn unknown_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.state == State::Unknown)
            .count()
    }

    /// Unknown effects that halt the run until a human reconciles them.
    ///
    /// # Why this is narrower than [`EffectJournal::unknown_count`]
    ///
    /// Two different guarantees are easy to conflate here, and #16 only asks for the first:
    ///
    /// * **Never auto-replay an unprovable dispatch.** That holds for every class, unconditionally
    ///   — nothing in the kernel re-executes a recorded intent, and recovery converts a dangling one
    ///   into `EffectUnknown` rather than retrying it.
    /// * **Halt the run until a human reconciles.** That is a pre-existing kernel *policy*, and it
    ///   has only ever applied to registry tool calls, whose unknown outcome means the model may
    ///   have half-applied an edit or a command the transcript will nevertheless claim happened.
    ///
    /// Extending the halt to the newly brokered classes would have been a regression wearing the
    /// costume of an invariant: an interrupt during a provider stream or a verifier run is the
    /// normal, documented D1-16 behaviour, and wedging the next run behind a reconciliation nobody
    /// can perform would make Ctrl-C a session-ending key. So harness classes are recorded, never
    /// replayed, counted by `unknown_count`, and not a gate.
    pub fn unknown_requiring_reconciliation(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.state == State::Unknown && kind_blocks_resume(&entry.tool))
            .count()
    }
}

/// Does an unknown outcome for this recorded kind halt the next run?
///
/// Keyed on the durable kind string, so the decision is reproducible from the record alone by a
/// process several versions removed from the one that wrote it. A registry tool records its tool
/// *name* here; every harness-dispatched class records its class label, and those are the ones the
/// halt policy has never covered.
pub fn kind_blocks_resume(kind: &str) -> bool {
    !EffectClass::ALL
        .iter()
        .filter_map(|class| class.label())
        .any(|label| label == kind)
}
