//! Actual verifier task ownership. Activity text never grants cancellation authority.

use iteron_protocol::{EffectId, Event, EventKind, RunId, Seq, TurnId};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

const MAX_TASKS: usize = 64;
const MAX_STREAM_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationTaskState {
    Admitted,
    Running,
    Settled,
    ReconciliationNeeded,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct VerificationTaskView {
    pub task_id: String,
    pub run_id: RunId,
    pub turn_id: TurnId,
    pub intent_seq: Seq,
    pub state: VerificationTaskState,
    pub cancel_requested: bool,
    /// None on recovery: EffectDone closes the effect but does not encode pass versus test failure.
    pub observed_outcome: Option<String>,
    pub evidence_source: &'static str,
    pub output_available: bool,
    pub output_omitted: bool,
}

struct Entry {
    view: VerificationTaskView,
    effect_id: EffectId,
    cancel: Arc<AtomicBool>,
    served: Option<String>,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<String, Entry>,
    order: VecDeque<String>,
    dropped: u64,
}
#[derive(Default)]
pub(crate) struct VerificationTaskRegistry {
    state: Mutex<State>,
}

/// The producer owns this sealed handle from an actual committed Verify intent through settlement.
/// Its Drop is conservative: an abandoned admitted/active task cannot remain falsely live.
pub(super) struct VerificationTask {
    owner: Arc<VerificationTaskRegistry>,
    id: String,
    cancel: Arc<AtomicBool>,
    settled: bool,
}

impl VerificationTaskRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(super) fn begin(
        self: &Arc<Self>,
        run: &RunId,
        ticket: &iteron_kernel::effects::EffectTicket,
    ) -> Result<VerificationTask, &'static str> {
        let id = task_id(run, ticket.intent_sequence());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only settled tasks are evicted. An active task is never turned into a different handle.
        trim(&mut state);
        if state.order.len() >= MAX_TASKS {
            return Err("verifier_task_capacity");
        }
        if state.entries.contains_key(&id) {
            return Err("verifier_task_duplicate");
        }
        state.order.push_back(id.clone());
        state.entries.insert(
            id.clone(),
            Entry {
                view: VerificationTaskView {
                    task_id: id.clone(),
                    run_id: run.clone(),
                    turn_id: ticket.turn(),
                    intent_seq: ticket.intent_sequence(),
                    state: VerificationTaskState::Admitted,
                    cancel_requested: false,
                    observed_outcome: None,
                    evidence_source: "committed_verify_intent",
                    output_available: false,
                    output_omitted: false,
                },
                effect_id: ticket.effect_id().clone(),
                cancel: cancel.clone(),
                served: None,
            },
        );
        Ok(VerificationTask {
            owner: self.clone(),
            id,
            cancel,
            settled: false,
        })
    }

    pub(crate) fn list(&self, run: &RunId) -> serde_json::Value {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tasks: Vec<_> = state
            .order
            .iter()
            .filter_map(|id| state.entries.get(id))
            .filter(|entry| &entry.view.run_id == run)
            .map(|entry| entry.view.clone())
            .collect();
        serde_json::json!({"source":"actual_verifier_tasks", "tasks":tasks, "dropped_tasks":state.dropped})
    }

    pub(crate) fn inspect(&self, run: &RunId, id: &str) -> Result<serde_json::Value, &'static str> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .entries
            .get(id)
            .filter(|entry| &entry.view.run_id == run)
            .ok_or("task_not_in_scope")?;
        // Output is exposed only after an authoritative oracle verdict AND confirmed effect settlement.
        // Oracle feedback is scrubbed in full before the display byte bound; progress is lossy
        // and never advertised as a complete process log.
        Ok(
            serde_json::json!({"task":entry.view,"output":entry.served.as_ref().map(|output|
            serde_json::json!({"verdict_detail":output,"source":"observed_oracle_feedback", "full_process_output":false}))}),
        )
    }

    pub(crate) fn cancel(&self, run: &RunId, id: &str) -> Result<serde_json::Value, &'static str> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .entries
            .get_mut(id)
            .filter(|entry| &entry.view.run_id == run)
            .ok_or("task_not_in_scope")?;
        if !matches!(
            entry.view.state,
            VerificationTaskState::Admitted | VerificationTaskState::Running
        ) {
            return Err("task_is_not_live");
        }
        entry.cancel.store(true, Ordering::Release);
        entry.view.cancel_requested = true;
        Ok(serde_json::json!({"task":entry.view,"stop_requested":true,"terminal_observed":false}))
    }

    /// Called once from the host's verified physical record at construction/adoption.
    /// No filesystem access, process resurrection, automatic rerun or pass inference.
    pub(crate) fn recover<'a>(&self, run: &RunId, verified: impl IntoIterator<Item = &'a Event>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for event in verified {
            match &event.kind {
                EventKind::EffectIntent { id, tool, .. } if tool == "verify" => {
                    let task_id = task_id(run, event.seq);
                    if state.entries.contains_key(&task_id) {
                        continue;
                    }
                    trim(&mut state);
                    state.order.push_back(task_id.clone());
                    state.entries.insert(
                        task_id.clone(),
                        Entry {
                            view: VerificationTaskView {
                                task_id,
                                run_id: run.clone(),
                                turn_id: event.turn,
                                intent_seq: event.seq,
                                state: VerificationTaskState::ReconciliationNeeded,
                                cancel_requested: false,
                                observed_outcome: None,
                                evidence_source: "verified_verify_effect_record",
                                output_available: false,
                                output_omitted: true,
                            },
                            effect_id: id.clone(),
                            cancel: Arc::new(AtomicBool::new(false)),
                            served: None,
                        },
                    );
                }
                EventKind::EffectDone { id, tool, .. }
                | EventKind::EffectFailed { id, tool, .. }
                    if tool == "verify" =>
                {
                    if let Some(entry) = state.entries.values_mut().find(|entry| {
                        entry.view.run_id == *run
                            && entry.view.turn_id == event.turn
                            && entry.effect_id == *id
                    }) {
                        entry.view.state = VerificationTaskState::Settled;
                    }
                }
                EventKind::EffectUnknown { id, tool, .. } if tool == "verify" => {
                    if let Some(entry) = state.entries.values_mut().find(|entry| {
                        entry.view.run_id == *run
                            && entry.view.turn_id == event.turn
                            && entry.effect_id == *id
                    }) {
                        entry.view.state = VerificationTaskState::ReconciliationNeeded;
                    }
                }
                _ => {}
            }
        }
    }
}

impl VerificationTask {
    pub(super) fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
    pub(super) fn dispatched(&self) {
        self.mutate(|entry| entry.view.state = VerificationTaskState::Running);
    }
    /// Caller invokes this only after settle_kernel_effect returned success.
    pub(super) fn settled(
        mut self,
        known_terminal: bool,
        verdict: &iteron_verify::Verdict,
        observed: bool,
    ) {
        self.mutate(|entry| {
            entry.view.state = if known_terminal {
                VerificationTaskState::Settled
            } else {
                VerificationTaskState::ReconciliationNeeded
            };
            entry.view.evidence_source = "confirmed_verify_effect_settlement";
            entry.view.observed_outcome =
                known_terminal.then(|| verdict.outcome.label().to_string());
            entry.view.output_omitted = !observed;
            if observed {
                let scrubbed = iteron_record::redact::scrub(&verdict.detail);
                let mut take = scrubbed.len().min(MAX_STREAM_BYTES);
                while !scrubbed.is_char_boundary(take) {
                    take -= 1;
                }
                entry.view.output_omitted = take < scrubbed.len();
                entry.served = Some(scrubbed[..take].to_string());
                entry.view.output_available = true;
            }
        });
        self.settled = true;
    }
    fn mutate(&self, update: impl FnOnce(&mut Entry)) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&self.id) {
            update(entry);
        }
    }
}
impl Drop for VerificationTask {
    fn drop(&mut self) {
        if !self.settled {
            self.mutate(|entry| {
                entry.view.state = VerificationTaskState::ReconciliationNeeded;
                entry.view.output_omitted = true;
            });
        }
    }
}
fn trim(state: &mut State) {
    while state.order.len() >= MAX_TASKS {
        let Some(index) = state.order.iter().position(|id| {
            state.entries.get(id).is_some_and(|entry| {
                !matches!(
                    entry.view.state,
                    VerificationTaskState::Admitted | VerificationTaskState::Running
                )
            })
        }) else {
            break;
        };
        if let Some(id) = state.order.remove(index) {
            state.entries.remove(&id);
            state.dropped += 1;
        }
    }
}
fn task_id(run: &RunId, seq: Seq) -> String {
    let digest = hex::encode(Sha256::digest(run.0.as_bytes()));
    format!(
        "vfy-{}-{}-{}-{}-{}",
        &digest[..16],
        &digest[16..32],
        &digest[32..48],
        &digest[48..],
        seq.0
    )
}

impl super::Agent {
    pub(crate) fn verification_task_port(&self) -> Arc<VerificationTaskRegistry> {
        self.verification_tasks.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{VerificationTaskRegistry, VerificationTaskState, task_id};
    use iteron_protocol::{Capability, EffectId, Event, EventKind, RunId, Seq, TurnId};
    use serde_json::json;

    fn intent(seq: u64) -> Event {
        Event {
            seq: Seq(seq),
            turn: TurnId(0),
            kind: EventKind::EffectIntent {
                id: EffectId("vf-0-0".into()),
                tool_use_id: String::new(),
                tool: "verify".into(),
                capability: Capability::CodeExecuting,
                arguments: json!({"command":"echo safe"}),
                workspace: "/workspace".into(),
                provider_route_attempt: None,
            },
        }
    }
    #[test]
    fn verified_intent_restores_unknown_and_only_matching_terminal_closes_without_pass_claim() {
        let owner = VerificationTaskRegistry::new();
        let run = RunId("run-a".into());
        owner.recover(&run, &[intent(9)]);
        let id = task_id(&run, Seq(9));
        let view = owner.inspect(&run, &id).unwrap();
        assert_eq!(view["task"]["state"], "reconciliation_needed");
        assert!(owner.cancel(&run, &id).is_err());
        let terminal = Event {
            seq: Seq(10),
            turn: TurnId(1),
            kind: EventKind::EffectDone {
                id: EffectId("vf-0-0".into()),
                tool: "verify".into(),
                duration_ms: None,
                provider_route_attempt: None,
            },
        };
        owner.recover(&run, std::slice::from_ref(&terminal));
        assert_eq!(
            owner.inspect(&run, &id).unwrap()["task"]["state"],
            "reconciliation_needed"
        );
        owner.recover(
            &run,
            &[Event {
                turn: TurnId(0),
                ..terminal
            }],
        );
        let view = owner.inspect(&run, &id).unwrap();
        assert_eq!(
            view["task"]["state"],
            serde_json::to_value(VerificationTaskState::Settled).unwrap()
        );
        assert!(view["task"]["observed_outcome"].is_null());
        assert!(view["output"].is_null());
        assert!(owner.inspect(&RunId("run-b".into()), &id).is_err());
        assert_ne!(task_id(&RunId("run-b".into()), Seq(9)), id);
        assert_ne!(task_id(&run, Seq(10)), id);
    }
    #[test]
    fn recovery_is_finite_and_never_resurrects_a_process() {
        let owner = VerificationTaskRegistry::new();
        let run = RunId("run".into());
        for seq in 1..100 {
            owner.recover(&run, &[intent(seq)]);
        }
        let view = owner.list(&run);
        assert_eq!(view["tasks"].as_array().unwrap().len(), 64);
        assert_eq!(view["dropped_tasks"], 35);
        assert!(
            view["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|task| task["state"] == "reconciliation_needed")
        );
    }
}
