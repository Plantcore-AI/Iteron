//! Single SQ receiver, product epoch and pending-steer owner. Polling returns actual ingress
//! observations; the journal/frontend/process ports decide their durable projections separately.
use super::inbound_control::{PendingSteer, TurnSubmission, UnadmittedSteer, stale_product_epoch};
use super::session_control::{InboundControl, SessionControlState};
use iteron_protocol::product_contract::ProductTurnId;
use iteron_protocol::{Op, SubmissionId};
use std::collections::VecDeque;
use tokio::sync::mpsc::Receiver;

const MAX_PENDING_STEERS: usize = 256;
const MAX_PENDING_STEER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(super) struct SessionSubmissionInbox {
    receiver: Option<Receiver<TurnSubmission>>,
    active_product_turn: Option<ProductTurnId>,
    pending: VecDeque<PendingSteer>,
    pending_bytes: usize,
}
#[derive(Default)]
pub(super) struct ControlPollReceipt {
    pub(super) control: InboundControl,
    pub(super) control_submission: Option<SubmissionId>,
    pub(super) stale: Vec<SubmissionId>,
    pub(super) unknown: usize,
    pub(super) versions: usize,
    pub(super) saturated: Vec<SubmissionId>,
}
impl SessionSubmissionInbox {
    pub(super) fn bind_receiver(&mut self, receiver: Receiver<TurnSubmission>) {
        self.receiver = Some(receiver);
    }
    pub(super) fn receiver(&mut self) -> Option<&mut Receiver<TurnSubmission>> {
        self.receiver.as_mut()
    }
    /// Await ingress without moving its unique receiver out of the resident owner. Dropping an
    /// approval/provider future cancels only this recv borrow and cannot erase future input.
    pub(super) async fn recv(&mut self) -> Option<TurnSubmission> {
        match self.receiver.as_mut() {
            Some(receiver) => receiver.recv().await,
            None => None,
        }
    }
    pub(super) fn take_receiver(&mut self) -> Option<Receiver<TurnSubmission>> {
        self.receiver.take()
    }
    pub(super) fn has_receiver(&self) -> bool {
        self.receiver.is_some()
    }
    pub(super) fn bind_product_turn(&mut self, turn: Option<ProductTurnId>) {
        self.active_product_turn = turn;
    }
    pub(super) fn product_turn(&self) -> Option<ProductTurnId> {
        self.active_product_turn
    }
    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub(super) fn push(&mut self, steer: PendingSteer) -> Result<(), PendingSteer> {
        let bytes = steer.text.len();
        if self.pending.len() >= MAX_PENDING_STEERS
            || self.pending_bytes.saturating_add(bytes) > MAX_PENDING_STEER_BYTES
        {
            return Err(steer);
        }
        self.pending_bytes += bytes;
        self.pending.push_back(steer);
        Ok(())
    }
    pub(super) fn pop(&mut self) -> Option<PendingSteer> {
        let steer = self.pending.pop_front()?;
        self.pending_bytes = self.pending_bytes.saturating_sub(steer.text.len());
        Some(steer)
    }
    /// A rejected durable append returns the identical already-admitted steer to the front.
    /// The caller has exclusive ownership, so no other producer can consume its reserved slot.
    pub(super) fn restore_front(&mut self, steer: PendingSteer) {
        self.pending_bytes += steer.text.len();
        self.pending.push_front(steer);
    }
    pub(super) fn clear(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
    }
    pub(super) fn retire_memory(&mut self, id: &str) {
        self.pending.retain(|steer| {
            !steer
                .memory
                .as_ref()
                .is_some_and(|activation| activation.id() == id)
        });
        self.pending_bytes = self.pending.iter().map(|steer| steer.text.len()).sum();
    }
    pub(super) fn reclaim(&mut self) -> (Vec<UnadmittedSteer>, usize) {
        let mut entries = Vec::new();
        let mut retained = std::collections::VecDeque::new();
        while let Some(steer) = self.pending.pop_front() {
            if steer.memory.is_some() {
                // A sealed host receipt survives as typed state in the same Agent. Exporting it
                // as an ordinary text notification would lose scope/version admission proof.
                retained.push_back(steer);
            } else if steer.agent_input.is_some() {
                // This controller epoch did not admit the input. Never export its sealed source
                // as an ordinary operator submission in a later epoch; controller owns expiry.
                continue;
            } else {
                entries.push(UnadmittedSteer {
                    text: steer.text,
                    client_visible: steer.client_visible,
                    submission_id: steer.submission_id,
                });
            }
        }
        self.pending = retained;
        self.pending_bytes = self.pending.iter().map(|steer| steer.text.len()).sum();
        let visible = entries.iter().filter(|steer| steer.client_visible).count();
        (entries, visible)
    }
    pub(super) fn poll(
        &mut self,
        controls: &mut SessionControlState,
        limit: usize,
        reclaim: bool,
    ) -> ControlPollReceipt {
        let mut receipt = ControlPollReceipt::default();
        for _ in 0..limit.clamp(1, MAX_PENDING_STEERS) {
            let Some(receiver) = self.receiver.as_mut() else {
                break;
            };
            let Ok(mut envelope) = receiver.try_recv() else {
                break;
            };
            if stale_product_epoch(self.active_product_turn, &envelope) {
                receipt.stale.push(envelope.submission_id);
                continue;
            }
            let agent_input = envelope.take_agent_input();
            let Ok((id, op)) = envelope.into_current_identified() else {
                receipt.versions += 1;
                continue;
            };
            match op {
                Op::Steer { text } => {
                    let steer = match agent_input {
                        Some(activation) => PendingSteer::agent(text, activation),
                        None => PendingSteer::from_steer(text, id),
                    };
                    if self.push(steer).is_err() {
                        receipt.saturated.push(id);
                    }
                }
                Op::UserInput { text } => {
                    if self.push(PendingSteer::user(text)).is_err() {
                        receipt.saturated.push(id);
                    }
                }
                Op::Interrupt | Op::ForceCancel | Op::Drain if !reclaim => {
                    receipt.control = match op {
                        Op::Interrupt => InboundControl::Interrupt,
                        Op::ForceCancel => InboundControl::ForceCancel,
                        _ => InboundControl::Drain,
                    };
                    receipt.control_submission = (id.0 != 0).then_some(id);
                    controls.request(receipt.control);
                    break;
                }
                Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
                    receipt.unknown += 1
                }
                Op::ApprovalResponse { .. } | Op::Interrupt | Op::ForceCancel | Op::Drain => {}
            }
        }
        receipt
    }
}
