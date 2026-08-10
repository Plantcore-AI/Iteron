use super::*;

impl Agent {
    pub(super) fn verification_repair_started(&self, turn: TurnId) {
        self.lifecycle_event(
            "verification.repair_started",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::from(self.verify_attempts)),
                ..LifecyclePayload::default()
            },
        );
    }

    pub(super) fn verification_repair_completed(&self, turn: TurnId) {
        if self.verify_attempts > 0 {
            self.lifecycle_event(
                "verification.repair_completed",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(self.verify_attempts)),
                    ..LifecyclePayload::default()
                },
            );
        }
    }

    pub(super) fn verification_repair_exhausted(&self, turn: TurnId) {
        self.lifecycle_event(
            "verification.repair_exhausted",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::from(self.verify_attempts)),
                ..LifecyclePayload::default()
            },
        );
    }

    /// Execute every attempt the pinned verifier plan requires. The default asks once; a stronger
    /// replacement can require a second clean pass. Repeats stop at the first non-pass, and
    /// disagreement is surfaced as the concrete later outcome rather than averaged into green.
    pub(super) async fn run_verifier_plan(
        &mut self,
        command: &str,
        plan: iteron_verify::VerifierPlan,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        let mut verdict = self.run_verify(command).await?;
        for _ in 1..plan.attempts {
            if !verdict.passed() {
                break;
            }
            let next = self.run_verify(command).await?;
            if next.outcome != verdict.outcome {
                return Ok(iteron_verify::Verdict::new(
                    plan.strength,
                    next.outcome,
                    format!(
                        "verification attempts disagreed (first {}, later {}): {}",
                        verdict.outcome.label(),
                        next.outcome.label(),
                        next.detail
                    ),
                ));
            }
            verdict = next;
        }
        Ok(verdict)
    }

    /// Run the strong verification oracle: the configured test command, in the egress-off
    /// sandbox. The harness's own ground-truth check on the model's "done".
    ///
    /// The oracle runs repository-controlled code in a sandbox, so it is an effect and crosses the
    /// boundary (#16). Its verdict vocabulary maps onto the terminal vocabulary exactly:
    /// `Cancelled` and `TimedOut` mean the oracle process was dispatched and dropped without a
    /// verdict — no terminal was observed — so they settle as `EffectUnknown`, while every graded
    /// outcome (pass, test failure, infrastructure failure) is a proven terminal.
    pub(super) async fn run_verify(
        &mut self,
        command: &str,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        let class = effect_class::EffectClass::Verify;
        let turn = TurnId(self.seq_turn);
        self.lifecycle_event(
            "verification.planned",
            Some(turn),
            LifecyclePayload::default(),
        );
        let ordinal = self.next_effect_ordinal(turn, class);
        let ticket = self.open_kernel_effect(
            turn,
            class,
            ordinal,
            Capability::CodeExecuting,
            serde_json::json!({ "command": command }),
        )?;
        self.lifecycle_event(
            "verification.check_started",
            Some(turn),
            LifecyclePayload::default(),
        );
        let started = Instant::now();
        let dispatch = self.dispatch_verify(command).await;
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
        self.settle_kernel_effect(ticket, settlement)?;
        self.lifecycle_event(
            if verdict.passed() {
                "verification.check_completed"
            } else {
                "verification.check_failed"
            },
            Some(turn),
            LifecyclePayload {
                outcome_code: Some(verdict.outcome.label().replace('-', "_")),
                duration_us: Some(elapsed_us(started)),
                ..LifecyclePayload::default()
            },
        );
        Ok(verdict)
    }

    /// Build and run the oracle. Split from [`Agent::run_verify`] so the boundary owns the
    /// intent/terminal pair and this owns only the dispatch.
    pub(super) async fn dispatch_verify(&mut self, command: &str) -> VerifyDispatch {
        #[cfg(test)]
        if let Some(oracle) = self.verify_oracle.clone() {
            return self.run_bounded_verify(oracle).await;
        }

        let mut oracle = iteron_verify::TestOracle::new(
            iteron_sandbox::platform_sandbox(),
            self.workspace.clone(),
            command.to_string(),
        )
        .with_sensitive_env_names(self.sensitive_env_names.clone());
        if let Some(remaining) = self.run_time_remaining() {
            // The sandbox API uses whole seconds. Round its cleanup-aware process timeout up,
            // then enforce the exact (possibly sub-second) deadline in `run_bounded_verify`.
            // Flooring here used to fire the oracle early; relying only on the rounded value could
            // overrun the run deadline by almost a second.
            let rounded_up_secs = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .max(1);
            oracle = oracle.with_timeout_secs(rounded_up_secs);
        }
        self.run_bounded_verify(std::sync::Arc::new(oracle)).await
    }

    /// Evaluate one oracle under the run's exact absolute deadline and cooperative cancellation.
    /// A short poll interval also lets the ordered submission queue surface `Interrupt`/`Drain`
    /// while a verification command is active. The injected oracle exists only in test builds;
    /// production always reaches this through the sandbox-backed `TestOracle` above.
    pub(super) async fn run_bounded_verify(
        &mut self,
        oracle: std::sync::Arc<dyn iteron_verify::Oracle>,
    ) -> VerifyDispatch {
        const VERIFY_CANCEL_POLL: Duration = Duration::from_millis(25);

        // Whether the oracle future has ever been polled, which is exactly whether a sandboxed
        // process can exist. The boundary needs this distinction: a cancellation before the first
        // poll provably dispatched nothing, while one after it leaves an unobservable outcome.
        let mut dispatched = false;
        let mut evaluation = Box::pin(async move { oracle.evaluate().await });
        loop {
            let queue_cancelled = self.collect_inbound_ops(TurnId(self.seq_turn));
            let flag_cancelled = self
                .interrupt
                .as_ref()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
            if queue_cancelled.interrupts() || flag_cancelled {
                let verdict = iteron_verify::Verdict::cancelled(
                    "verification cancelled by the operator before a verdict",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }

            let remaining = self.run_time_remaining();
            if remaining.is_some_and(|duration| duration.is_zero()) {
                let verdict = iteron_verify::Verdict::timed_out(
                    "verification exceeded the absolute run deadline",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }
            let poll_for = remaining
                .map(|duration| duration.min(VERIFY_CANCEL_POLL))
                .unwrap_or(VERIFY_CANCEL_POLL);

            dispatched = true;
            match tokio::time::timeout(poll_for, &mut evaluation).await {
                Ok(verdict) => {
                    // Cancellation wins a boundary race with a just-completed oracle. This keeps
                    // an operator stop from being converted into Done merely because both became
                    // ready in the same scheduler tick.
                    let queue_cancelled = self.collect_inbound_ops(TurnId(self.seq_turn));
                    let flag_cancelled = self
                        .interrupt
                        .as_ref()
                        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
                    if queue_cancelled.interrupts() || flag_cancelled {
                        // The oracle completed; only its verdict is being discarded in favour of
                        // the operator's stop. The sandboxed process demonstrably ended, so the
                        // effect terminal is observed even though the caller sees Cancelled.
                        return VerifyDispatch::Observed(iteron_verify::Verdict::cancelled(
                            "verification cancelled by the operator at the verdict boundary",
                        ));
                    }
                    return VerifyDispatch::Observed(verdict);
                }
                Err(_) => {
                    // The pinned oracle future remains alive across polling ticks. On an absolute
                    // deadline or cancellation return it is dropped; platform sandbox children
                    // are configured kill-on-drop, while their own rounded timeout remains the
                    // cleanup-aware backstop.
                }
            }
        }
    }
}
