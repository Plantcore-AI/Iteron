//! At-most-once admission for effect identities.
//!
//! The write-ahead log makes an effect *recoverable*; this makes it *singular*. Without a live
//! guard the only thing standing between a caller and a double dispatch is `EffectJournal::replay`,
//! which is a post-hoc read: by the time it reports `DuplicateIntent` the executor has already run
//! twice. So the boundary consults this ledger before the intent append, and a repeat identity is
//! refused without entering the executor at all.
//!
//! # Why this is bounded, and how
//!
//! A run-lifetime set of every identity ever admitted grows without limit, which `AGENTS.md`
//! forbids. It is also unnecessary: identities are minted per turn (`crate::effect_class`), and
//! turn ids advance monotonically, so an identity from an older turn can never be minted again by
//! any honest caller. The ledger therefore keeps only the current turn's identities and requires
//! the turn to be non-decreasing — a request for an older turn is itself a contract violation and
//! is refused rather than silently admitted. Memory is bounded by one turn's effect count, and that
//! count is bounded in turn by [`MAX_EFFECTS_PER_TURN`].

use crate::effect_class::EffectClass;
use crate::effect_journal::EffectJournal;
use iteron_protocol::{EffectId, TurnId};
use std::collections::{BTreeMap, BTreeSet};

/// Hard ceiling on distinct effects admitted inside one turn.
///
/// `MAX_TOOL_CALLS_PER_TURN` (128) already bounds the registry class. This bounds the sum of every
/// class, leaving generous headroom for the provider request, its hooks, subagents, verifier runs
/// and checkpoints while still refusing an unbounded dispatch loop.
pub const MAX_EFFECTS_PER_TURN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EffectAdmissionError {
    #[error(
        "effect identity {0} was already admitted in this turn; at-most-once dispatch forbids a second"
    )]
    Duplicate(String),
    #[error(
        "effect admission for turn {requested} arrived after turn {current}; effect identities are \
         minted per turn and never revisited"
    )]
    NonMonotonicTurn { requested: u32, current: u32 },
    #[error("turn {turn} admitted the per-turn effect ceiling of {ceiling}")]
    TooManyEffects { turn: u32, ceiling: usize },
}

/// The live at-most-once ledger for one run.
#[derive(Debug, Default)]
pub struct EffectAdmissions {
    turn: Option<TurnId>,
    ids: BTreeSet<String>,
    ordinals: BTreeMap<EffectClass, usize>,
}

impl EffectAdmissions {
    /// Hand out the next ordinal for one class inside one turn.
    ///
    /// Registry tools do NOT use this: their ordinal is the model's own tool index, which is what
    /// keeps a tool's identity tied to its position in the provider's transcript. Every other class
    /// counts its own dispatches, so the sequence is a pure function of the dispatch order and
    /// replays identically — which is the property #15's pure reducer will need from it.
    pub fn next_ordinal(&mut self, turn: TurnId, class: EffectClass) -> usize {
        self.enter_turn(turn);
        let next = self.ordinals.entry(class).or_default();
        let ordinal = *next;
        *next = next.saturating_add(1);
        ordinal
    }

    /// Roll the per-turn state forward if this is a later turn. A backwards turn is left alone
    /// here and refused by [`EffectAdmissions::admit`], which is the one place that can fail loudly.
    fn enter_turn(&mut self, turn: TurnId) {
        if self.turn.is_none_or(|current| turn.0 > current.0) {
            self.turn = Some(turn);
            self.ids.clear();
            self.ordinals.clear();
        }
    }
    /// Seed the ledger from a replayed journal so a resumed run cannot re-mint an identity the
    /// previous process already put on disk.
    ///
    /// Only the highest turn present is retained, for the same reason the live ledger keeps one
    /// turn: nothing may mint into an older one.
    pub fn from_journal(journal: &EffectJournal) -> Self {
        let mut ledger = Self::default();
        // `TurnId` is a newtype over `u32` and deliberately not `Ord`; compare the number.
        let Some(highest) = journal.admitted().map(|(turn, _)| turn.0).max() else {
            return ledger;
        };
        ledger.turn = Some(TurnId(highest));
        ledger.ids = journal
            .admitted()
            .filter(|(turn, _)| turn.0 == highest)
            .map(|(_, id)| id.0.clone())
            .collect();
        ledger
    }

    /// Claim an identity. Returns an error — and claims nothing — if the identity is a repeat, if
    /// the turn moved backwards, or if the turn is already at its ceiling.
    pub fn admit(&mut self, turn: TurnId, id: &EffectId) -> Result<(), EffectAdmissionError> {
        if let Some(current) = self.turn
            && turn.0 < current.0
        {
            return Err(EffectAdmissionError::NonMonotonicTurn {
                requested: turn.0,
                current: current.0,
            });
        }
        // A new turn cannot collide with an old one: the identity carries the turn.
        self.enter_turn(turn);
        if self.ids.len() >= MAX_EFFECTS_PER_TURN {
            return Err(EffectAdmissionError::TooManyEffects {
                turn: turn.0,
                ceiling: MAX_EFFECTS_PER_TURN,
            });
        }
        if !self.ids.insert(id.0.clone()) {
            return Err(EffectAdmissionError::Duplicate(id.0.clone()));
        }
        Ok(())
    }

    /// How many identities the current turn holds. Present so a test can prove the ledger does not
    /// accumulate across turns rather than trusting the comment that says so.
    pub fn live_len(&self) -> usize {
        self.ids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect_class::{EffectClass, effect_id};

    #[test]
    fn a_repeat_identity_is_refused() {
        let mut ledger = EffectAdmissions::default();
        let id = effect_id(TurnId(1), EffectClass::Provider, 0);
        ledger.admit(TurnId(1), &id).expect("first admission");
        assert_eq!(
            ledger.admit(TurnId(1), &id),
            Err(EffectAdmissionError::Duplicate(id.0.clone()))
        );
    }

    #[test]
    fn advancing_the_turn_releases_the_previous_turns_identities() {
        let mut ledger = EffectAdmissions::default();
        for ordinal in 0..8 {
            ledger
                .admit(TurnId(1), &effect_id(TurnId(1), EffectClass::Hook, ordinal))
                .expect("turn 1 admissions");
        }
        assert_eq!(ledger.live_len(), 8);
        ledger
            .admit(TurnId(2), &effect_id(TurnId(2), EffectClass::Hook, 0))
            .expect("turn 2 admission");
        assert_eq!(ledger.live_len(), 1, "the ledger must not accumulate turns");
    }

    #[test]
    fn a_backwards_turn_is_refused_rather_than_silently_admitted() {
        let mut ledger = EffectAdmissions::default();
        ledger
            .admit(TurnId(4), &effect_id(TurnId(4), EffectClass::Verify, 0))
            .expect("turn 4");
        assert_eq!(
            ledger.admit(TurnId(3), &effect_id(TurnId(3), EffectClass::Verify, 0)),
            Err(EffectAdmissionError::NonMonotonicTurn {
                requested: 3,
                current: 4
            })
        );
    }

    #[test]
    fn the_per_turn_ceiling_is_a_hard_refusal_not_a_silent_drop() {
        let mut ledger = EffectAdmissions::default();
        for ordinal in 0..MAX_EFFECTS_PER_TURN {
            ledger
                .admit(
                    TurnId(1),
                    &effect_id(TurnId(1), EffectClass::RegistryTool, ordinal),
                )
                .expect("under the ceiling");
        }
        assert_eq!(
            ledger.admit(
                TurnId(1),
                &effect_id(TurnId(1), EffectClass::RegistryTool, MAX_EFFECTS_PER_TURN)
            ),
            Err(EffectAdmissionError::TooManyEffects {
                turn: 1,
                ceiling: MAX_EFFECTS_PER_TURN
            })
        );
    }
}
