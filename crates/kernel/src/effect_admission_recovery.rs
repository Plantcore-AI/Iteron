//! Recover bounded class counters from the actual highest-turn admission identities. Counters
//! skip durable gaps; no unknown effect is replayed or inferred complete by this projection.
use crate::effect_class::{EffectClass, effect_id};
use iteron_protocol::TurnId;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn next_ordinals(turn: TurnId, ids: &BTreeSet<String>) -> BTreeMap<EffectClass, usize> {
    let mut result = BTreeMap::new();
    for class in EffectClass::ALL {
        let prefix = match class.code() {
            Some(code) => format!("fx1-{:08x}-{code}-", turn.0),
            None => format!("fx1-{:08x}-", turn.0),
        };
        let mut next = None;
        for id in ids {
            let Some(raw) = id.strip_prefix(&prefix) else {
                continue;
            };
            if raw.len() > std::mem::size_of::<usize>() * 2 {
                continue;
            }
            let Ok(ordinal) = usize::from_str_radix(raw, 16) else {
                continue;
            };
            // Require the exact host mint spelling. A model correlation or legacy arbitrary id
            // does not become counter authority merely because it shares a string prefix.
            if effect_id(turn, class, ordinal).0 != *id {
                continue;
            }
            next = Some(next.map_or(ordinal.saturating_add(1), |prior: usize| {
                prior.max(ordinal.saturating_add(1))
            }));
        }
        if let Some(next) = next {
            result.insert(class, next);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::effect_admission::EffectAdmissions;
    use crate::effect_class::{EffectClass, effect_id, harness_correlation_id};
    use crate::effect_journal::EffectJournal;
    use iteron_protocol::{Capability, Event, EventKind, Seq, TurnId};

    fn intent(turn: TurnId, class: EffectClass, ordinal: usize) -> Event {
        Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::EffectIntent {
                id: effect_id(turn, class, ordinal),
                tool_use_id: harness_correlation_id(turn, class, ordinal),
                tool: class.label().unwrap().into(),
                capability: Capability::IrreversibleExternal,
                arguments: serde_json::json!({}),
                workspace: "/repo".into(),
                provider_route_attempt: None,
            },
        }
    }
    #[test]
    fn actual_journal_recovery_resumes_all_harness_classes_beyond_durable_gaps() {
        let turn = TurnId(7);
        let events = vec![
            intent(turn, EffectClass::Provider, 0),
            intent(turn, EffectClass::Provider, 3),
            intent(turn, EffectClass::Verify, 5),
        ];
        let journal = EffectJournal::replay(&events).unwrap();
        let mut admissions = EffectAdmissions::from_journal(&journal);
        let provider = admissions.next_ordinal(turn, EffectClass::Provider);
        assert_eq!(provider, 4);
        admissions
            .admit(turn, &effect_id(turn, EffectClass::Provider, provider))
            .unwrap();
        assert_eq!(admissions.next_ordinal(turn, EffectClass::Verify), 6);
        assert_eq!(
            journal.pending().len(),
            3,
            "counter recovery does not close unknown execution"
        );
        assert_eq!(admissions.next_ordinal(TurnId(8), EffectClass::Provider), 0);
    }
    #[test]
    fn old_turns_and_noncanonical_lookalikes_cannot_advance_the_current_counter() {
        let events = vec![
            intent(TurnId(1), EffectClass::Provider, 99),
            intent(TurnId(2), EffectClass::Provider, 1),
        ];
        let journal = EffectJournal::replay(&events).unwrap();
        let mut admissions = EffectAdmissions::from_journal(&journal);
        assert_eq!(admissions.next_ordinal(TurnId(2), EffectClass::Provider), 2);
        let mut ids = std::collections::BTreeSet::new();
        ids.insert("fx1-00000002-pv-00001".into());
        ids.insert("fx1-00000002-pv-ffff-ignored".into());
        assert!(super::next_ordinals(TurnId(2), &ids).is_empty());
    }
}
