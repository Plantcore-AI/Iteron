//! Bounded current-run observations shared by authenticated public and terminal clients.
//!
//! Recovery is supplied by the runtime's verified record owner. This reader has no filesystem,
//! executor, mutation, or terminal inference port.

use iteron_protocol::turn_publication::{
    MAX_TURN_PUBLICATION_EVENTS, PublicationRecoveryV1, TURN_PUBLICATION_VERSION,
    TurnPublicationEventV1, TurnPublicationReadV1, TurnPublicationSnapshotV1,
};
use iteron_protocol::{RunId, SessionId};
use serde_json::{Value, json};
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct PublicationReader {
    identity: Option<(SessionId, RunId)>,
    recovery: Option<PublicationRecoveryV1>,
    events: VecDeque<TurnPublicationEventV1>,
    evictions: u64,
}

impl PublicationReader {
    pub(super) fn bind(&mut self, thread_id: SessionId, run_id: RunId) {
        if self.identity.as_ref() == Some(&(thread_id.clone(), run_id.clone())) {
            return;
        }
        self.identity = Some((thread_id, run_id));
        self.recovery = Some(PublicationRecoveryV1::LiveOnly);
        self.events.clear();
        self.evictions = 0;
    }

    pub(super) fn recover(
        &mut self,
        run_id: &RunId,
        recovered: Result<Vec<TurnPublicationEventV1>, ()>,
    ) {
        if self.identity.as_ref().map(|(_, run)| run) != Some(run_id) {
            return;
        }
        let Ok(events) = recovered else {
            self.recovery = Some(PublicationRecoveryV1::Unavailable);
            return;
        };
        // Validate the whole captured prefix before replacing retained state. A malformed or
        // foreign fact never becomes a successful recovery merely because earlier rows were valid.
        let valid = events.len() <= MAX_TURN_PUBLICATION_EVENTS
            && events
                .iter()
                .all(|event| event.run_id == *run_id && event.validate().is_ok())
            && events
                .windows(2)
                .all(|pair| pair[0].source_seq < pair[1].source_seq);
        if !valid {
            self.recovery = Some(PublicationRecoveryV1::Unavailable);
            return;
        }
        self.events = events.into();
        self.evictions = 0;
        self.recovery = Some(PublicationRecoveryV1::VerifiedRecord);
    }

    pub(super) fn observe(&mut self, event: &TurnPublicationEventV1) -> bool {
        if event.validate().is_err()
            || self.identity.as_ref().map(|(_, run)| run) != Some(&event.run_id)
        {
            return false;
        }
        if let Some(last) = self.events.back()
            && event.source_seq <= last.source_seq
        {
            // Replay is idempotent only for an exact retained fact. No newer receipt is fabricated.
            return self.events.iter().any(|known| known == event);
        }
        self.events.push_back(event.clone());
        if self.events.len() > MAX_TURN_PUBLICATION_EVENTS {
            self.events.pop_front();
            self.evictions = self.evictions.saturating_add(1);
        }
        true
    }

    pub(super) fn read(&self, command: TurnPublicationReadV1) -> Value {
        let Some((thread_id, run_id)) = &self.identity else {
            return refused("thread_unavailable");
        };
        if command.thread_id() != thread_id {
            return refused("thread_mismatch");
        }
        let snapshot = TurnPublicationSnapshotV1 {
            contract_version: TURN_PUBLICATION_VERSION,
            thread_id: thread_id.clone(),
            run_id: run_id.clone(),
            recovery: self.recovery.unwrap_or(PublicationRecoveryV1::LiveOnly),
            events: self.events.iter().cloned().collect(),
            resident_evictions: self.evictions,
        };
        json!({"type":"turn_publications_v1", "contract_version":TURN_PUBLICATION_VERSION, "snapshot":snapshot})
    }
}

fn refused(reason: &'static str) -> Value {
    json!({"type":"turn_publications_refused_v1", "contract_version":TURN_PUBLICATION_VERSION, "reason_code":reason})
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::TurnId;
    use iteron_protocol::turn_publication::{TurnFinalOutcomeV1, TurnPublicationFactV1};

    fn event(seq: u64, fact: TurnPublicationFactV1) -> TurnPublicationEventV1 {
        TurnPublicationEventV1 {
            contract_version: TURN_PUBLICATION_VERSION,
            run_id: RunId("run".into()),
            turn_id: TurnId(2),
            source_seq: seq,
            fact,
        }
    }

    fn read(reader: &PublicationReader) -> Value {
        reader.read(TurnPublicationReadV1::Read {
            thread_id: SessionId("thread".into()),
        })
    }

    #[test]
    fn answer_is_available_before_terminal_and_failed_terminal_remains_failed() {
        let mut reader = PublicationReader::default();
        reader.bind(SessionId("thread".into()), RunId("run".into()));
        let answer = event(8, TurnPublicationFactV1::AnswerAvailable { message_seq: 7 });
        assert!(reader.observe(&answer));
        let answer_snapshot = read(&reader);
        assert_eq!(
            answer_snapshot["snapshot"]["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            answer_snapshot["snapshot"]["events"][0]["fact"]["type"],
            "answer_available"
        );
        let terminal = event(
            10,
            TurnPublicationFactV1::TurnFinalized {
                outcome: TurnFinalOutcomeV1::HarnessError,
                budget_limit: None,
            },
        );
        assert!(reader.observe(&terminal));
        assert!(reader.observe(&answer));
        let snapshot = read(&reader);
        assert_eq!(snapshot["snapshot"]["events"].as_array().unwrap().len(), 2);
        assert_eq!(
            snapshot["snapshot"]["events"][1]["fact"]["outcome"],
            "harness_error"
        );
        let mut forged = answer;
        forged.fact = TurnPublicationFactV1::AnswerAvailable { message_seq: 6 };
        assert!(!reader.observe(&forged));
    }

    #[test]
    fn recovery_refuses_foreign_or_conflicting_prefix_without_partial_success() {
        let mut reader = PublicationReader::default();
        reader.bind(SessionId("thread".into()), RunId("run".into()));
        let terminal = event(
            20,
            TurnPublicationFactV1::TurnFinalized {
                outcome: TurnFinalOutcomeV1::Done,
                budget_limit: None,
            },
        );
        reader.recover(&RunId("run".into()), Ok(vec![terminal.clone()]));
        assert_eq!(read(&reader)["snapshot"]["recovery"], "verified_record");
        let mut foreign = terminal.clone();
        foreign.run_id = RunId("foreign".into());
        reader.recover(&RunId("run".into()), Ok(vec![terminal.clone(), foreign]));
        assert_eq!(read(&reader)["snapshot"]["recovery"], "unavailable");
        assert_eq!(
            read(&reader)["snapshot"]["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            reader.read(TurnPublicationReadV1::Read {
                thread_id: SessionId("foreign".into())
            })["reason_code"],
            "thread_mismatch"
        );
        reader.bind(SessionId("thread".into()), RunId("adopted".into()));
        assert!(!reader.observe(&terminal));
        assert!(
            read(&reader)["snapshot"]["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn late_reader_observes_a_bounded_prefix_with_explicit_resident_evictions() {
        let mut reader = PublicationReader::default();
        reader.bind(SessionId("thread".into()), RunId("run".into()));
        for seq in 1..=MAX_TURN_PUBLICATION_EVENTS as u64 + 3 {
            assert!(reader.observe(&event(
                seq,
                TurnPublicationFactV1::TurnFinalized {
                    outcome: TurnFinalOutcomeV1::Interrupted,
                    budget_limit: None,
                }
            )));
        }
        let snapshot = read(&reader);
        assert_eq!(snapshot["snapshot"]["resident_evictions"], 3);
        assert_eq!(
            snapshot["snapshot"]["events"].as_array().unwrap().len(),
            MAX_TURN_PUBLICATION_EVENTS
        );
    }
}
