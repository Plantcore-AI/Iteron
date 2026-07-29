//! Conformance for the bounded K9 driver (#15).
//!
//! The boundedness claims are the ones worth testing hard, because their failure mode is silent:
//! an unbounded queue looks perfect until the day it eats the machine, and a dropping queue looks
//! perfect until the day the dropped thing mattered. Each test below fills a queue and then asserts
//! on what happened to the item that did not fit.

use crate::driver::{
    DriverError, DriverEvent, MAX_PENDING_REPLIES, PortFault, ProviderReply, RejectReason,
    TurnDriver, TurnPorts, bounded_queues,
};
use crate::turn_action::{ActionRequest, ContinueReason, NoticeKind};
use crate::turn_command::Command;
use crate::turn_protocol::{
    BudgetCeiling, ControlSignal, ProviderFailure, ProviderTermination, VerifyOutcome,
};
use crate::turn_state::{TurnLimits, TurnState};
use core_protocol::Outcome;
use core_protocol::context::{ContextGrant, ContextSegment, ContextSource, RequestId};
use core_protocol::trust::Trust;
use std::time::Duration;

/// The grant the stub context port answers with.
fn stub_grant() -> ContextGrant {
    ContextGrant {
        request_id: RequestId(1),
        segments: vec![ContextSegment {
            text: "stub instructions".into(),
            trust: Trust::Workspace,
            source: ContextSource::Instructions,
        }],
        bytes: "stub instructions".len() as u32,
    }
}

/// The SQ and EQ bounds would be worth little if the driver's private reply queue could grow
/// without limit. Checked at compile time, because a bound is a constant claim: a `bound` large
/// enough never to bind is not a bound.
const _: () = assert!(MAX_PENDING_REPLIES > 0 && MAX_PENDING_REPLIES <= 4096);

/// In-memory ports. Every world module the loop would reach is a scripted value here, which is what
/// issue #15 means by "the reducer and driver compile and test against in-memory fake ports".
#[derive(Default)]
struct StubPorts {
    provider_calls: usize,
    tool_dispatches: usize,
    verify_runs: usize,
    checkpoints: usize,
    contexts: usize,
    notices: Vec<NoticeKind>,
    continuations: Vec<ContinueReason>,
    /// Replies handed out in order; the last one repeats once exhausted.
    provider_script: Vec<ProviderTermination>,
    verify_script: Vec<VerifyOutcome>,
    control: ControlSignal,
    ceiling: Option<BudgetCeiling>,
    steers: u32,
    provider_failure: Option<ProviderFailure>,
    checkpoint_error: Option<PortFault>,
    /// Simulates the durable append that resolving context performs.
    context_error: Option<PortFault>,
}

impl StubPorts {
    fn answering(termination: ProviderTermination) -> Self {
        Self {
            provider_script: vec![termination],
            ..Self::default()
        }
    }
}

#[async_trait::async_trait]
impl TurnPorts for StubPorts {
    async fn select_context(&mut self) -> Result<ContextGrant, PortFault> {
        self.contexts += 1;
        match &self.context_error {
            Some(fault) => Err(fault.clone()),
            None => Ok(stub_grant()),
        }
    }
    async fn sample_budget(&mut self) -> Option<BudgetCeiling> {
        self.ceiling
    }
    async fn observe_control(&mut self) -> ControlSignal {
        self.control
    }
    async fn admit_steers(&mut self, _turn: u32) -> u32 {
        std::mem::take(&mut self.steers)
    }
    async fn call_provider(&mut self, _turn: u32) -> ProviderReply {
        self.provider_calls += 1;
        if let Some(failure) = self.provider_failure {
            return ProviderReply::Failed(failure);
        }
        let index = (self.provider_calls - 1).min(self.provider_script.len().saturating_sub(1));
        let termination = self
            .provider_script
            .get(index)
            .copied()
            .unwrap_or(ProviderTermination::EndTurn);
        let tool_calls = u32::from(termination == ProviderTermination::ToolUse);
        ProviderReply::Completed {
            termination,
            tool_calls,
        }
    }
    async fn dispatch_tools(&mut self, _turn: u32, _calls: u32) -> bool {
        self.tool_dispatches += 1;
        false
    }
    async fn run_verify(&mut self, _turn: u32, _attempt: u32) -> VerifyOutcome {
        self.verify_runs += 1;
        let index = (self.verify_runs - 1).min(self.verify_script.len().saturating_sub(1));
        self.verify_script
            .get(index)
            .copied()
            .unwrap_or(VerifyOutcome::Pass)
    }
    async fn checkpoint(&mut self, _turn: u32) -> Result<(), PortFault> {
        self.checkpoints += 1;
        match &self.checkpoint_error {
            Some(fault) => Err(fault.clone()),
            None => Ok(()),
        }
    }
    async fn notice(&mut self, kind: NoticeKind) {
        self.notices.push(kind);
    }
    async fn continuation(&mut self, _turn: u32, reason: ContinueReason) {
        self.continuations.push(reason);
    }
    async fn advance_turn(&mut self, _turn: u32) -> Result<(), PortFault> {
        Ok(())
    }
}

/// Drain an event receiver without blocking, so a test can assert on what was emitted.
fn drain(rx: &mut tokio::sync::mpsc::Receiver<DriverEvent>) -> Vec<DriverEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

// ---------------------------------------------------------------------------------------------
// Bounded submission queue
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_full_submission_queue_rejects_explicitly_and_hands_the_command_back() {
    let (sq, _sq_rx, _eq, _eq_rx) = bounded_queues(2, 8);
    sq.try_submit(Command::Admitted).expect("first slot");
    sq.try_submit(Command::ContextResolved {
        grant: Box::new(stub_grant()),
    })
    .expect("second slot");
    assert_eq!(sq.capacity_remaining(), 0);

    let refused = sq
        .try_submit(Command::RecordFailed)
        .expect_err("a full queue must refuse");
    assert_eq!(refused.reason, RejectReason::QueueFull);
    assert_eq!(
        refused.command,
        Command::RecordFailed,
        "the refused submission must come back intact, or a caller that did not keep a copy has \
         silently lost it — which is the drop this bound exists to prevent"
    );
}

#[tokio::test]
async fn a_full_submission_queue_blocks_a_producer_rather_than_growing() {
    let (sq, mut sq_rx, _eq, _eq_rx) = bounded_queues(1, 8);
    sq.try_submit(Command::Admitted).expect("first slot");

    // The queue is full: an awaiting producer must not complete.
    let blocked = tokio::time::timeout(
        Duration::from_millis(80),
        sq.submit(Command::ContextResolved {
            grant: Box::new(stub_grant()),
        }),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a full queue must apply backpressure, not accept an unbounded second item"
    );

    // Draining one slot lets the producer through, and nothing was lost on the way.
    let pending = sq.clone();
    let producer = tokio::spawn(async move {
        pending
            .submit(Command::ContextResolved {
                grant: Box::new(stub_grant()),
            })
            .await
    });
    assert_eq!(sq_rx.recv().await, Some(Command::Admitted));
    producer
        .await
        .expect("producer task")
        .expect("a drained slot admits the waiting producer");
    assert_eq!(
        sq_rx.recv().await,
        Some(Command::ContextResolved {
            grant: Box::new(stub_grant())
        })
    );
}

// ---------------------------------------------------------------------------------------------
// Bounded event queue
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_full_event_queue_applies_backpressure_and_drops_nothing() {
    let (_sq, _sq_rx, eq, mut eq_rx) = bounded_queues(4, 2);
    eq.emit(DriverEvent::Routed(ActionRequest::SelectContext))
        .await
        .expect("first slot");
    eq.emit(DriverEvent::Routed(ActionRequest::SampleBudget))
        .await
        .expect("second slot");
    assert_eq!(eq.capacity_remaining(), 0);

    let blocked = tokio::time::timeout(
        Duration::from_millis(80),
        eq.emit(DriverEvent::Routed(ActionRequest::ObserveControl)),
    )
    .await;
    assert!(
        blocked.is_err(),
        "a full event queue must block the emitter; the alternative is a dropped event"
    );

    // Drain, then let the blocked emission land: all three events survive, in order.
    let third = eq.clone();
    let emitter = tokio::spawn(async move {
        third
            .emit(DriverEvent::Routed(ActionRequest::ObserveControl))
            .await
    });
    assert_eq!(
        eq_rx.recv().await,
        Some(DriverEvent::Routed(ActionRequest::SelectContext))
    );
    emitter.await.expect("emitter task").expect("slot freed");
    assert_eq!(
        eq_rx.recv().await,
        Some(DriverEvent::Routed(ActionRequest::SampleBudget))
    );
    assert_eq!(
        eq_rx.recv().await,
        Some(DriverEvent::Routed(ActionRequest::ObserveControl)),
        "the event that did not fit must arrive once a slot frees, never be discarded"
    );
}

// ---------------------------------------------------------------------------------------------
// The loop, end to end, against stubs
// ---------------------------------------------------------------------------------------------

async fn run_to_completion(
    ports: StubPorts,
    state: TurnState,
) -> (Result<Outcome, DriverError>, StubPorts, Vec<DriverEvent>) {
    // The event queue is sized for the whole run so the test asserts on routing, not on scheduling.
    let (sq, mut sq_rx, eq, mut eq_rx) = bounded_queues(4, 1024);
    sq.try_submit(Command::Admitted).expect("admission fits");
    let mut driver = TurnDriver::new(state, ports, eq);
    let outcome = driver.run(&mut sq_rx).await;
    let events = drain(&mut eq_rx);
    (outcome, driver.into_ports(), events)
}

#[tokio::test]
async fn the_driver_runs_a_whole_turn_against_stubbed_ports() {
    let (outcome, ports, events) = run_to_completion(
        StubPorts::answering(ProviderTermination::EndTurn),
        TurnState::new(TurnLimits::default(), false),
    )
    .await;

    assert_eq!(outcome.expect("the run completes"), Outcome::Done);
    assert_eq!(ports.contexts, 1, "context is resolved exactly once");
    assert_eq!(ports.provider_calls, 1);
    assert_eq!(ports.tool_dispatches, 0);
    assert_eq!(ports.checkpoints, 0);
    assert!(
        events.last() == Some(&DriverEvent::Finished(Outcome::Done)),
        "the terminal outcome must be the last thing on the event queue"
    );
    // Every routed action is on the event queue in the order the reducer asked for it.
    let routed: Vec<&ActionRequest> = events
        .iter()
        .filter_map(|event| match event {
            DriverEvent::Routed(action) => Some(action),
            DriverEvent::Finished(_) => None,
        })
        .collect();
    assert_eq!(routed.first(), Some(&&ActionRequest::SelectContext));
    assert!(
        routed
            .iter()
            .any(|action| matches!(action, ActionRequest::CallProvider { .. }))
    );
}

#[tokio::test]
async fn the_driver_drives_a_tool_turn_then_answers() {
    let ports = StubPorts {
        provider_script: vec![ProviderTermination::ToolUse, ProviderTermination::EndTurn],
        ..StubPorts::default()
    };
    let (outcome, ports, _) =
        run_to_completion(ports, TurnState::new(TurnLimits::default(), false)).await;
    assert_eq!(outcome.expect("completes"), Outcome::Done);
    assert_eq!(ports.tool_dispatches, 1);
    assert_eq!(ports.provider_calls, 2);
}

#[tokio::test]
async fn the_driver_checkpoints_before_a_drained_terminal_and_never_otherwise() {
    let drained = StubPorts {
        control: ControlSignal::Drain,
        ..StubPorts::answering(ProviderTermination::EndTurn)
    };
    let (outcome, ports, _) =
        run_to_completion(drained, TurnState::new(TurnLimits::default(), false)).await;
    assert_eq!(outcome.expect("completes"), Outcome::Drained);
    assert_eq!(ports.checkpoints, 1);
    assert_eq!(
        ports.provider_calls, 0,
        "a drain observed at the first boundary must stop before any inference is dispatched"
    );

    let interrupted = StubPorts {
        control: ControlSignal::Interrupt,
        ..StubPorts::answering(ProviderTermination::EndTurn)
    };
    let (outcome, ports, _) =
        run_to_completion(interrupted, TurnState::new(TurnLimits::default(), false)).await;
    assert_eq!(outcome.expect("completes"), Outcome::Interrupted);
    assert_eq!(ports.checkpoints, 0);
}

#[tokio::test]
async fn a_run_whose_record_is_broken_dispatches_nothing() {
    // The driver-level counterpart of the reducer's zero-provider-calls invariant, and the same
    // shape the imperative test used: the first durable append fails, so the loop must halt before
    // any inference is dispatched. The property is now visible as "the port was never called",
    // with a real loop in between.
    let ports = StubPorts {
        context_error: Some(PortFault::Record("intent append refused".into())),
        ..StubPorts::answering(ProviderTermination::EndTurn)
    };
    let (outcome, ports, _) =
        run_to_completion(ports, TurnState::new(TurnLimits::default(), false)).await;
    let outcome = outcome.expect("the run halts rather than erroring out of the loop");

    assert_eq!(outcome, Outcome::HarnessError);
    assert_eq!(
        ports.provider_calls, 0,
        "a run that cannot write its audit record must make zero provider calls"
    );
    assert_eq!(ports.tool_dispatches, 0);
    assert_eq!(ports.checkpoints, 0);
    assert_eq!(ports.notices, vec![NoticeKind::RecordUnhealthy]);
}

#[tokio::test]
async fn a_failed_checkpoint_is_surfaced_rather_than_reported_as_a_clean_drain() {
    let ports = StubPorts {
        control: ControlSignal::Drain,
        checkpoint_error: Some(PortFault::Port(
            "workspace is outside the runtime-state root".into(),
        )),
        ..StubPorts::answering(ProviderTermination::EndTurn)
    };
    let (outcome, ports, _) =
        run_to_completion(ports, TurnState::new(TurnLimits::default(), false)).await;
    assert!(
        matches!(outcome, Err(DriverError::Port(_))),
        "a drain whose checkpoint failed must not be reported as Drained"
    );
    assert_eq!(ports.checkpoints, 1);
}

#[tokio::test]
async fn a_deadline_reached_mid_stream_ends_the_run_at_its_wall_ceiling() {
    let ports = StubPorts {
        provider_failure: Some(ProviderFailure::DeadlineExceeded),
        ..StubPorts::default()
    };
    let (outcome, ports, _) =
        run_to_completion(ports, TurnState::new(TurnLimits::default(), false)).await;
    assert_eq!(
        outcome.expect("completes"),
        Outcome::BudgetExhausted("max_wall_secs")
    );
    assert_eq!(ports.provider_calls, 1, "and it is not retried");
}

#[tokio::test]
async fn late_operator_guidance_takes_another_turn_instead_of_committing_done() {
    let ports = StubPorts {
        steers: 1,
        ..StubPorts::answering(ProviderTermination::EndTurn)
    };
    let (outcome, ports, _) =
        run_to_completion(ports, TurnState::new(TurnLimits::default(), false)).await;
    assert_eq!(outcome.expect("completes"), Outcome::Done);
    assert_eq!(
        ports.continuations,
        vec![ContinueReason::Steered],
        "guidance admitted at the safe point must produce another turn, not be committed over"
    );
    assert_eq!(
        ports.provider_calls, 2,
        "the steered turn must actually reach the provider"
    );
}

#[tokio::test]
async fn the_drivers_own_reply_queue_is_bounded_too() {
    let (sq, mut sq_rx, eq, _eq_rx) = bounded_queues(4, 64);
    drop(sq);
    let mut driver = TurnDriver::new(
        TurnState::new(TurnLimits::default(), false),
        StubPorts::answering(ProviderTermination::EndTurn),
        eq,
    );
    // With no submissions and a closed queue, the loop reports the closure rather than spinning.
    assert_eq!(
        driver.run(&mut sq_rx).await,
        Err(DriverError::SubmissionsClosed)
    );
}
