//! Actual sandbox verifier dispatch, bounded control pumping and honest physical settlement.
use super::KernelError;
use super::control_ingress::ControlIngress;
use super::effect_descriptor::{effect_done_terminal, effect_failed_terminal};
use super::frontend_events::UiEvent;
use super::inbound_control::inbound_poll_limit;
use super::session_control::InboundControl;
use super::strong_verification::StrongVerificationGate;
use super::tool_presentation::strict_utf8_head;
use super::turn_activity;
use iteron_kernel::{effect_class, effects};
use iteron_protocol::{Capability, LifecyclePayload, TurnId};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
const VERIFY_CANCEL_POLL: Duration = Duration::from_millis(25);
pub(super) enum VerifyDispatch {
    /// The oracle produced this verdict itself. Proven terminal.
    Observed(iteron_verify::Verdict),
    /// The oracle future was polled at least once and then dropped. No terminal is observable.
    Dropped(iteron_verify::Verdict),
    /// The oracle future was never polled, so no process was started. Proven non-event.
    NotDispatched(iteron_verify::Verdict),
}

impl VerifyDispatch {
    pub(super) fn from_drop(dispatched: bool, verdict: iteron_verify::Verdict) -> Self {
        if dispatched {
            VerifyDispatch::Dropped(verdict)
        } else {
            VerifyDispatch::NotDispatched(verdict)
        }
    }

    #[cfg(test)]
    pub(super) fn verdict(&self) -> &iteron_verify::Verdict {
        match self {
            VerifyDispatch::Observed(verdict)
            | VerifyDispatch::Dropped(verdict)
            | VerifyDispatch::NotDispatched(verdict) => verdict,
        }
    }
}

impl StrongVerificationGate<'_> {
    pub(super) async fn run_verify(
        &mut self,
        command: &str,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        let class = effect_class::EffectClass::Verify;
        let turn = self.scope.turn;
        self.lifecycle_event(
            "verification.planned",
            Some(turn),
            LifecyclePayload::default(),
        );
        let ordinal = self.journal.effects.next_ordinal(turn, class);
        let ticket = self.journal.open(
            self.scope.workspace,
            turn,
            class,
            ordinal,
            Capability::CodeExecuting,
            serde_json::json!({ "command": command }),
        )?;
        let task = match self.tasks.begin(self.journal.rollout.run_id(), &ticket) {
            Ok(task) => task,
            Err(reason) => {
                self.journal.settle(
                    ticket,
                    effects::Settlement::Definite(effect_failed_terminal(
                        turn, class, ordinal, reason,
                    )),
                )?;
                return Err(KernelError::ContextResolution(reason.into()));
            }
        };
        self.lifecycle_event(
            "verification.check_started",
            Some(turn),
            LifecyclePayload::default(),
        );
        let attempt = self.state.attempts().saturating_add(1);
        let limit = self.state.policy().retry.max_attempts;
        let timeout = Duration::from_secs(self.state.policy().verifier_timeout_secs);
        let verification_activity = self.scope.activity.span_attempt(
            turn_activity::ActivityStage::Verification,
            turn,
            attempt,
            limit,
            timeout,
        );
        self.ui(UiEvent::Notice(format!(
            "verify: `{}` · attempt {attempt}/{limit} · timeout {}s",
            iteron_protocol::text::head(command, 240),
            timeout.as_secs()
        )));
        let started = Instant::now();
        let dispatch = self.dispatch_verify_task(command, Some(&task)).await;
        let known_terminal = !matches!(&dispatch, VerifyDispatch::Dropped(_));
        let observed = matches!(&dispatch, VerifyDispatch::Observed(_));
        let (settlement, verdict) = match dispatch {
            // The oracle future was never polled, so no sandboxed process was ever started. The
            // effect provably did not happen; saying "unknown" here would strand the session over
            // a command that was cancelled before it could run.
            VerifyDispatch::NotDispatched(verdict) => (
                effects::Settlement::Definite(effect_failed_terminal(
                    turn,
                    class,
                    ordinal,
                    "verification was cancelled before the oracle was dispatched",
                )),
                verdict,
            ),
            // The oracle future was dropped mid-run. The sandboxed command was started, may have
            // touched the workspace, and produced no authoritative verdict. This is the honest
            // unknown: recovery reports it and never re-runs it.
            VerifyDispatch::Dropped(verdict) => (
                effects::Settlement::Unknown(
                    "verification was dropped after dispatch and before the oracle produced a \
                     verdict; automatic retry is forbidden"
                        .into(),
                ),
                verdict,
            ),
            // The oracle answered. Every graded outcome is a proven terminal, including its own
            // timeout and infrastructure failure — those are observations, not lost dispatches.
            VerifyDispatch::Observed(verdict) => {
                let terminal = if verdict.outcome
                    == iteron_verify::VerificationOutcome::InfrastructureFailure
                {
                    effect_failed_terminal(turn, class, ordinal, &verdict.detail)
                } else {
                    effect_done_terminal(turn, class, ordinal)
                };
                (effects::Settlement::Definite(terminal), verdict)
            }
        };
        self.journal.settle(ticket, settlement)?;
        task.settled(known_terminal, &verdict, observed);
        self.lifecycle_event(
            if verdict.passed() {
                "verification.check_completed"
            } else {
                "verification.check_failed"
            },
            Some(turn),
            LifecyclePayload {
                outcome_code: Some(verdict.outcome.label().replace('-', "_")),
                duration_us: Some(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        if verdict.passed() {
            verification_activity.complete();
        } else if verdict.outcome == iteron_verify::VerificationOutcome::TimedOut {
            verification_activity.timeout(iteron_protocol::ActivityDetailCode::Verification);
        } else {
            verification_activity.fail(iteron_protocol::ActivityDetailCode::Verification);
        }
        Ok(verdict)
    }

    async fn dispatch_verify_task(
        &mut self,
        command: &str,
        task: Option<&super::bounded_verify::VerificationTask>,
    ) -> VerifyDispatch {
        #[cfg(test)]
        if let Some(oracle) = self.scope.oracle.clone() {
            return self
                .run_bounded_verify_observed(oracle, None, None, task)
                .await;
        }

        let attempt = self.state.attempts().saturating_add(1);
        let command_identity = format!("verify:{}", &verification_command_digest(command)[..16]);
        let (output_observer, output_receiver) = iteron_sandbox::OutputObserver::bounded(
            command_identity,
            attempt,
            iteron_sandbox::OutputObserver::DEFAULT_QUEUE_CAPACITY,
        );

        let mut oracle = iteron_verify::TestOracle::new(
            iteron_sandbox::platform_sandbox(),
            self.scope.workspace.to_path_buf(),
            command.to_string(),
        )
        .with_sensitive_env_names(self.scope.sensitive_env_names.to_vec())
        .with_output_tail_bytes(self.state.policy().feedback.oracle_output_bytes)
        .with_timeout_secs(self.state.policy().verifier_timeout_secs)
        .with_output_observer(output_observer.clone());
        if self.scope.preconfined {
            oracle = oracle.with_preconfined_outer_sandbox();
        }
        if let Some(remaining) = self.run_time_remaining() {
            // The sandbox API uses whole seconds. Round its cleanup-aware process timeout up,
            // then enforce the exact (possibly sub-second) deadline in `run_bounded_verify`.
            // Flooring here used to fire the oracle early; relying only on the rounded value could
            // overrun the run deadline by almost a second.
            let rounded_up_secs = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .max(1);
            oracle = oracle
                .with_timeout_secs(rounded_up_secs.min(self.state.policy().verifier_timeout_secs));
        }
        self.run_bounded_verify_observed(
            std::sync::Arc::new(oracle),
            Some(output_observer),
            Some(output_receiver),
            task,
        )
        .await
    }

    /// Evaluate one oracle under the run's exact absolute deadline and cooperative cancellation.
    /// A short poll interval also lets the ordered submission queue surface `Interrupt`/`Drain`
    /// while a verification command is active. The injected oracle exists only in test builds;
    /// production always reaches this through the sandbox-backed `TestOracle` above.
    #[cfg(test)]
    pub(super) async fn run_bounded_verify(
        &mut self,
        oracle: std::sync::Arc<dyn iteron_verify::Oracle>,
    ) -> VerifyDispatch {
        self.run_bounded_verify_observed(oracle, None, None, None)
            .await
    }

    async fn run_bounded_verify_observed(
        &mut self,
        oracle: std::sync::Arc<dyn iteron_verify::Oracle>,
        output_observer: Option<iteron_sandbox::OutputObserver>,
        mut output_receiver: Option<iteron_sandbox::OutputObserverReceiver>,
        task: Option<&super::bounded_verify::VerificationTask>,
    ) -> VerifyDispatch {
        enum VerifyPoll {
            Verdict(iteron_verify::Verdict),
            Output(Option<iteron_sandbox::OutputObservation>),
            Tick,
        }

        let verification_started = Instant::now();
        let verifier_deadline = verification_started
            .checked_add(Duration::from_secs(
                self.state.policy().verifier_timeout_secs,
            ))
            .unwrap_or_else(Instant::now);

        // Whether the oracle future has ever been polled, which is exactly whether a sandboxed
        // process can exist. The boundary needs this distinction: a cancellation before the first
        // poll provably dispatched nothing, while one after it leaves an unobservable outcome.
        let mut dispatched = false;
        let mut next_visible_heartbeat = Duration::from_secs(1);
        let mut last_output_notice = verification_started;
        let mut visible_output_bytes = [0_usize; 2];
        let output_limit = self
            .state
            .policy()
            .feedback
            .command_output_bytes
            .min(1_048_576);
        let mut evaluation = Box::pin(async move { oracle.evaluate().await });
        loop {
            let _ = self.poll_control(self.scope.turn);
            let control = self.control.requested();
            let flag_cancelled = self
                .control
                .interrupt()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
            // Drain is quiescence, not cancellation. An already-admitted verifier must produce
            // its authoritative verdict before the drain checkpoint is taken; only interactive
            // interrupt/force-cancel may drop the oracle mid-dispatch.
            if matches!(
                control,
                InboundControl::Interrupt | InboundControl::ForceCancel
            ) || flag_cancelled
                || task.is_some_and(|task| task.cancelled())
            {
                if let Some(observer) = &output_observer {
                    observer.cancel();
                }
                let verdict = iteron_verify::Verdict::cancelled(
                    "verification cancelled by the operator before a verdict",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }

            let verifier_remaining = verifier_deadline.saturating_duration_since(Instant::now());
            let run_remaining = self.run_time_remaining();
            if run_remaining.is_some_and(|duration| duration.is_zero()) {
                if let Some(observer) = &output_observer {
                    observer.cancel();
                }
                let verdict = iteron_verify::Verdict::timed_out(
                    "verification exceeded the absolute run deadline",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }
            if verifier_remaining.is_zero() {
                if let Some(observer) = &output_observer {
                    observer.cancel();
                }
                let verdict = iteron_verify::Verdict::timed_out(
                    "verification exceeded its configured verifier timeout",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }
            let remaining = run_remaining
                .map(|duration| duration.min(verifier_remaining))
                .unwrap_or(verifier_remaining);
            let poll_for = remaining.min(iteron_tunables::param_duration(
                "cli.runtime.verification.verify_cancel_poll",
                VERIFY_CANCEL_POLL,
            ));

            dispatched = true;
            if let Some(task) = task {
                task.dispatched();
            }
            let observation = async {
                match output_receiver.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            };
            let polled = tokio::select! {
                biased;
                verdict = &mut evaluation => VerifyPoll::Verdict(verdict),
                observation = observation => VerifyPoll::Output(observation),
                () = tokio::time::sleep(poll_for) => VerifyPoll::Tick,
            };
            match polled {
                VerifyPoll::Verdict(verdict) => {
                    // Cancellation wins a boundary race with a just-completed oracle. This keeps
                    // an operator stop from being converted into Done merely because both became
                    // ready in the same scheduler tick.
                    let _ = self.poll_control(self.scope.turn);
                    let control = self.control.requested();
                    let flag_cancelled = self
                        .control
                        .interrupt()
                        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
                    if matches!(
                        control,
                        InboundControl::Interrupt | InboundControl::ForceCancel
                    ) || flag_cancelled
                        || task.is_some_and(|task| task.cancelled())
                    {
                        // The oracle completed; only its verdict is being discarded in favour of
                        // the operator's stop. The sandboxed process demonstrably ended, so the
                        // effect terminal is observed even though the caller sees Cancelled.
                        return VerifyDispatch::Observed(iteron_verify::Verdict::cancelled(
                            "verification cancelled by the operator at the verdict boundary",
                        ));
                    }
                    return VerifyDispatch::Observed(verdict);
                }
                VerifyPoll::Output(Some(iteron_sandbox::OutputObservation::Chunk(chunk))) => {
                    let stream_index = match chunk.stream {
                        iteron_sandbox::OutputStream::Stdout => 0,
                        iteron_sandbox::OutputStream::Stderr => 1,
                    };
                    let remaining_capacity =
                        output_limit.saturating_sub(visible_output_bytes[stream_index]);
                    if remaining_capacity > 0 {
                        let take = chunk.bytes.len().min(remaining_capacity);
                        visible_output_bytes[stream_index] =
                            visible_output_bytes[stream_index].saturating_add(take);
                        let decoded = String::from_utf8_lossy(&chunk.bytes[..take]);
                        let scrubbed = iteron_record::redact::scrub(&decoded);
                        let bounded = strict_utf8_head(&scrubbed, 8 * 1024);
                        let stream = match chunk.stream {
                            iteron_sandbox::OutputStream::Stdout => "stdout",
                            iteron_sandbox::OutputStream::Stderr => "stderr",
                        };
                        self.ui(UiEvent::Notice(format!(
                            "verify {stream} · attempt {}/{}: {bounded}",
                            chunk.attempt,
                            self.state.policy().retry.max_attempts,
                        )));
                        let elapsed = verification_started.elapsed();
                        self.scope.activity.heartbeat(
                            turn_activity::ActivityStage::Verification,
                            self.scope.turn,
                            elapsed.as_secs().max(1),
                            self.state.policy().verifier_timeout_secs.max(1),
                            remaining,
                        );
                        last_output_notice = Instant::now();
                    }
                }
                VerifyPoll::Output(Some(iteron_sandbox::OutputObservation::Terminal(_)))
                | VerifyPoll::Output(None) => {
                    // The verdict remains authoritative. Stop polling progress as soon as its
                    // independent terminal watch fires so queued lossy chunks cannot resurrect a
                    // stale verification status after completion.
                    output_receiver = None;
                }
                VerifyPoll::Tick => {
                    // The pinned oracle future remains alive across polling ticks. On an absolute
                    // deadline or cancellation return it is dropped; platform sandbox children
                    // are configured kill-on-drop, while their own rounded timeout remains the
                    // cleanup-aware backstop.
                    let elapsed = verification_started.elapsed();
                    if elapsed >= next_visible_heartbeat
                        && last_output_notice.elapsed() >= Duration::from_secs(1)
                    {
                        let elapsed_secs = elapsed.as_secs().max(1);
                        let total_secs = self.state.policy().verifier_timeout_secs.max(1);
                        self.scope.activity.heartbeat(
                            turn_activity::ActivityStage::Verification,
                            self.scope.turn,
                            elapsed_secs,
                            total_secs,
                            remaining,
                        );
                        self.ui(UiEvent::Notice(format!(
                            "verify: attempt {}/{} · {}s elapsed · {}s remaining",
                            self.state.attempts().saturating_add(1),
                            self.state.policy().retry.max_attempts,
                            elapsed_secs,
                            remaining.as_secs()
                        )));
                        next_visible_heartbeat =
                            next_visible_heartbeat.saturating_add(Duration::from_secs(1));
                    }
                }
            }
        }
    }
    fn poll_control(&mut self, turn: TurnId) -> InboundControl {
        ControlIngress {
            journal: self.journal.approval(),
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            events: self.scope.events.clone(),
        }
        .poll(turn, inbound_poll_limit())
    }
}
pub(super) fn verification_command_digest(command: &str) -> String {
    hex::encode(Sha256::digest(command.as_bytes()))
}
