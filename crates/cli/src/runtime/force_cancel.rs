//! Typed escalation seam between the agent loop and process-owning executors.
//!
//! Dropping a provider/tool future proves only that this runtime stopped awaiting it. It does not
//! prove an already-spawned OS process group was killed and reaped. The process owner therefore
//! receives a non-blocking request and returns separate evidence; until then effecting calls stay
//! Unknown and the terminal explicitly says reaping is unproven.

use iteron_protocol::TurnId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForceCancelRequest {
    pub turn: TurnId,
    pub requested_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessReapProof {
    NoTrackedProcesses,
    Reaped { process_groups: u32 },
    Partial { reaped: u32, unresolved: u32 },
    Unavailable,
}

impl ProcessReapProof {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::NoTrackedProcesses => "force_no_tracked_processes",
            Self::Reaped { .. } => "force_process_groups_reaped",
            Self::Partial { .. } => "force_process_reap_partial",
            Self::Unavailable => "force_process_reap_unproven",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForceCancelEvidence {
    pub turn: TurnId,
    pub proof: ProcessReapProof,
}

pub(crate) struct ForceCancelSeam {
    request_tx: tokio::sync::mpsc::Sender<ForceCancelRequest>,
    evidence_rx: tokio::sync::mpsc::Receiver<ForceCancelEvidence>,
    saturated: u64,
}

impl ForceCancelSeam {
    pub(crate) fn new(
        request_tx: tokio::sync::mpsc::Sender<ForceCancelRequest>,
        evidence_rx: tokio::sync::mpsc::Receiver<ForceCancelEvidence>,
    ) -> Self {
        Self {
            request_tx,
            evidence_rx,
            saturated: 0,
        }
    }

    /// Queue-only: no process operation or channel wait is permitted on the control path.
    pub(crate) fn request(&mut self, turn: TurnId) -> bool {
        let sent = self
            .request_tx
            .try_send(ForceCancelRequest {
                turn,
                requested_at_unix_ms: unix_ms(),
            })
            .is_ok();
        if !sent {
            self.saturated = self.saturated.saturating_add(1);
        }
        sent
    }

    #[cfg(test)]
    pub(crate) const fn saturated_count(&self) -> u64 {
        self.saturated
    }

    pub(crate) fn latest_proof(&mut self, turn: TurnId) -> ProcessReapProof {
        let mut proof = ProcessReapProof::Unavailable;
        while let Ok(evidence) = self.evidence_rx.try_recv() {
            if evidence.turn == turn {
                proof = evidence.proof;
            }
        }
        proof
    }

    /// Wait only at the terminal settlement boundary for the process owner to prove cleanup.
    ///
    /// The control acknowledgement remains queue-only in [`Self::request`]. This bounded wait is
    /// deliberately separate: publishing `cancel.completed` before the process supervisor has
    /// killed and reaped every retained group would turn a dropped future into false evidence.
    pub(crate) async fn await_proof(
        &mut self,
        turn: TurnId,
        budget: std::time::Duration,
    ) -> ProcessReapProof {
        let immediate = self.latest_proof(turn);
        if !matches!(immediate, ProcessReapProof::Unavailable) {
            return immediate;
        }
        tokio::time::timeout(budget, async {
            loop {
                match self.evidence_rx.recv().await {
                    Some(evidence) if evidence.turn == turn => return evidence.proof,
                    Some(_) => continue,
                    None => return ProcessReapProof::Unavailable,
                }
            }
        })
        .await
        .unwrap_or(ProcessReapProof::Unavailable)
    }

    /// Bind the agent's exact process-tool supervisor. The worker is session-local, the request
    /// path is queue-only, and `ProcessControl::clean` is the existing authority that terminates
    /// every retained process group and waits for authoritative reap state.
    pub(crate) fn for_process_control(control: iteron_tools::ProcessControl) -> Option<Self> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let (request_tx, mut request_rx) = tokio::sync::mpsc::channel::<ForceCancelRequest>(1);
        let (evidence_tx, evidence_rx) = tokio::sync::mpsc::channel::<ForceCancelEvidence>(4);
        runtime.spawn(async move {
            while let Some(request) = request_rx.recv().await {
                let before = control.health();
                let cleaned = control.clean().await;
                let after = control.health();
                let proof = if cleaned.is_ok()
                    && after.active_jobs == 0
                    && after.cleanup_unknown_jobs == 0
                {
                    if before.active_jobs == 0 {
                        ProcessReapProof::NoTrackedProcesses
                    } else {
                        ProcessReapProof::Reaped {
                            process_groups: u32::try_from(before.active_jobs).unwrap_or(u32::MAX),
                        }
                    }
                } else {
                    let reaped = before.active_jobs.saturating_sub(after.active_jobs);
                    let unresolved = after.active_jobs.saturating_add(after.cleanup_unknown_jobs);
                    if reaped == 0 && unresolved == 0 {
                        ProcessReapProof::Unavailable
                    } else {
                        ProcessReapProof::Partial {
                            reaped: u32::try_from(reaped).unwrap_or(u32::MAX),
                            unresolved: u32::try_from(unresolved).unwrap_or(u32::MAX),
                        }
                    }
                };
                // Evidence is bounded and terminal. A full queue is fail-closed: the runtime will
                // report reaping as unproven rather than manufacturing success.
                let _ = evidence_tx.try_send(ForceCancelEvidence {
                    turn: request.turn,
                    proof,
                });
            }
        });
        Some(Self::new(request_tx, evidence_rx))
    }
}

fn unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_request_is_non_blocking_and_proof_is_separate() {
        let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(1);
        let (evidence_tx, evidence_rx) = tokio::sync::mpsc::channel(1);
        let mut seam = ForceCancelSeam::new(request_tx, evidence_rx);
        assert!(seam.request(TurnId(3)));
        assert_eq!(request_rx.try_recv().unwrap().turn, TurnId(3));
        assert_eq!(seam.latest_proof(TurnId(3)), ProcessReapProof::Unavailable);
        evidence_tx
            .try_send(ForceCancelEvidence {
                turn: TurnId(3),
                proof: ProcessReapProof::Reaped { process_groups: 2 },
            })
            .unwrap();
        assert_eq!(
            seam.latest_proof(TurnId(3)),
            ProcessReapProof::Reaped { process_groups: 2 }
        );
    }

    #[test]
    fn escalation_queue_is_bounded_and_saturation_is_explicit() {
        let (request_tx, _request_rx) = tokio::sync::mpsc::channel(1);
        let (_evidence_tx, evidence_rx) = tokio::sync::mpsc::channel(1);
        let mut seam = ForceCancelSeam::new(request_tx, evidence_rx);
        assert!(seam.request(TurnId(1)));
        assert!(!seam.request(TurnId(2)));
        assert_eq!(seam.saturated_count(), 1);
    }

    #[tokio::test]
    async fn terminal_wait_consumes_authoritative_reap_proof() {
        let (request_tx, _request_rx) = tokio::sync::mpsc::channel(1);
        let (evidence_tx, evidence_rx) = tokio::sync::mpsc::channel(1);
        let mut seam = ForceCancelSeam::new(request_tx, evidence_rx);
        evidence_tx
            .try_send(ForceCancelEvidence {
                turn: TurnId(9),
                proof: ProcessReapProof::NoTrackedProcesses,
            })
            .unwrap();
        assert_eq!(
            seam.await_proof(TurnId(9), std::time::Duration::from_millis(10))
                .await,
            ProcessReapProof::NoTrackedProcesses
        );
    }
}
