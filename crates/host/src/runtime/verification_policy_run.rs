//! Bounded command/quorum reduction over individual physical verifier receipts.
use super::KernelError;
use super::provider_accounting::unix_now_secs;
use super::session_control::InboundControl;
use super::strong_verification::StrongVerificationGate;
use super::tool_presentation::truncate_tail;
use super::verification_execution::verification_command_digest;
use iteron_protocol::{EventKind, LifecyclePayload};
impl StrongVerificationGate<'_> {
    pub(super) async fn run_verification_policy(
        &mut self,
        fallback_command: &str,
        plan: iteron_verify::VerifierPlan,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        self.state.restore_quarantine(self.journal.rollout)?;
        let now = unix_now_secs();
        self.state.prune_quarantine(now);
        let configured = if self.state.policy().required_commands.is_empty() {
            vec![fallback_command.to_owned()]
        } else {
            self.state.policy().selected_commands().to_vec()
        };
        if configured.is_empty() {
            return Err(KernelError::ContextResolution(
                "verification selection produced no admitted command".into(),
            ));
        }
        let command_digests = configured
            .iter()
            .map(|command| verification_command_digest(command))
            .collect::<Vec<_>>();
        for digest in &command_digests {
            if let Some(expires_at_unix_secs) = self.state.quarantined_until(digest) {
                self.emit_durable(
                    self.scope.turn,
                    EventKind::VerificationPolicy {
                        version: iteron_protocol::VerificationPolicyEventVersion::V1,
                        event: iteron_protocol::VerificationPolicyEvent::QuarantineRefused {
                            command_digest_sha256: digest.clone(),
                            expires_at_unix_secs,
                        },
                    },
                )?;
                return Ok(iteron_verify::Verdict::new(
                    plan.strength,
                    iteron_verify::VerificationOutcome::InfrastructureFailure,
                    format!(
                        "verification evidence {digest} remains quarantined after contradictory outcomes"
                    ),
                ));
            }
        }

        let repeat_limit = usize::from(
            self.state
                .policy()
                .flaky
                .repeat_count
                .max(u8::try_from(plan.attempts).unwrap_or(u8::MAX)),
        );
        let verifier_count = usize::from(self.state.policy().quorum.verifiers);
        let physical_run_limit = configured
            .len()
            .saturating_mul(repeat_limit)
            .saturating_mul(verifier_count);
        if physical_run_limit > iteron_verify::MAX_PHYSICAL_VERIFIER_RUNS {
            return Err(KernelError::ContextResolution(
                "verification physical-run product exceeds its immutable ceiling".into(),
            ));
        }
        // Repeats are a diagnostic tail, not a tax on every healthy verification. Run the whole
        // selected/quorum rectangle once; only a non-pass in that first round admits the bounded
        // follow-up round(s). Keeping the decision at a round boundary preserves rectangular,
        // exactly accountable receipts even with multiple commands or verifier lanes.
        let mut outcomes =
            vec![vec![Vec::with_capacity(repeat_limit); configured.len()]; verifier_count];
        let mut last_details = vec![vec![String::new(); configured.len()]; verifier_count];
        let mut first_round_non_pass = false;
        let mut repeat_count = 0usize;
        for repeat_index in 0..repeat_limit {
            if repeat_index > 0 && !first_round_non_pass {
                break;
            }
            repeat_count = repeat_count.saturating_add(1);
            for verifier_index in 0..verifier_count {
                for (command_index, command) in configured.iter().enumerate() {
                    let verdict = self.run_verify(command).await?;
                    // Operator cancellation is control flow, not verifier evidence. Folding it
                    // into quorum would turn the typed cancellation into `Indeterminate`, then
                    // into `InfrastructureFailure`, and admit the remaining physical verifier
                    // runs after the operator already stopped the gate.
                    if verdict.outcome == iteron_verify::VerificationOutcome::Cancelled {
                        return Ok(verdict);
                    }
                    // Drain admits the physical verifier that was already running, not the rest
                    // of a repeat/quorum batch. Once that verifier has supplied an authoritative
                    // terminal verdict, return it to the run loop so the checkpoint can be made
                    // before another external command is dispatched.
                    if self.control.requested() == InboundControl::Drain {
                        return Ok(verdict);
                    }
                    last_details[verifier_index][command_index] = truncate_tail(
                        &verdict.detail,
                        self.state.policy().feedback.command_output_bytes,
                    );
                    if repeat_index == 0
                        && verdict.outcome != iteron_verify::VerificationOutcome::Pass
                    {
                        first_round_non_pass = true;
                    }
                    outcomes[verifier_index][command_index].push(verdict.outcome);
                }
            }
        }
        let physical_runs = configured
            .len()
            .saturating_mul(repeat_count)
            .saturating_mul(verifier_count);
        let mut representative_outcomes = Vec::with_capacity(verifier_count);
        let mut details = Vec::with_capacity(physical_runs);
        let mut observed_flake = false;
        let mut observed_disagreements = 0usize;
        for (lane_outcomes, lane_details) in outcomes.iter().zip(&last_details) {
            let mut lane_outcome = iteron_verify::VerificationOutcome::Pass;
            for (command_outcomes, last_detail) in lane_outcomes.iter().zip(lane_details) {
                let first = command_outcomes[0];
                let disagreements = command_outcomes
                    .iter()
                    .filter(|outcome| **outcome != first)
                    .count();
                observed_disagreements = observed_disagreements.saturating_add(disagreements);
                if disagreements >= usize::from(self.state.policy().flaky.minimum_disagreements) {
                    observed_flake = true;
                }
                // Repeats below the configured quarantine threshold still may not disappear. A
                // later definite test failure vetoes an earlier pass; any other non-pass keeps the
                // lane indeterminate instead of manufacturing green from `outcomes[0]`.
                let command_outcome = command_outcomes
                    .iter()
                    .copied()
                    .find(|outcome| *outcome == iteron_verify::VerificationOutcome::TestFailure)
                    .or_else(|| {
                        command_outcomes
                            .iter()
                            .copied()
                            .find(|outcome| *outcome != iteron_verify::VerificationOutcome::Pass)
                    })
                    .unwrap_or(iteron_verify::VerificationOutcome::Pass);
                lane_outcome = match (lane_outcome, command_outcome) {
                    (_, iteron_verify::VerificationOutcome::TestFailure) => {
                        iteron_verify::VerificationOutcome::TestFailure
                    }
                    (iteron_verify::VerificationOutcome::TestFailure, _) => {
                        iteron_verify::VerificationOutcome::TestFailure
                    }
                    (iteron_verify::VerificationOutcome::Pass, other) => other,
                    (current, iteron_verify::VerificationOutcome::Pass) => current,
                    (current, _) => current,
                };
                details.push(last_detail.clone());
            }
            representative_outcomes.push(lane_outcome);
        }

        // Independent verifier lanes can contradict each other even when every lane is internally
        // repeat-stable. Treat that as the same physical-evidence flake as an intra-lane repeat
        // disagreement: persist the quarantine before the command digest enters the in-memory
        // refusal map, so restart cannot silently rerun contradictory evidence.
        if let Some(first) = representative_outcomes.first().copied() {
            let lane_disagreements = representative_outcomes
                .iter()
                .filter(|outcome| **outcome != first)
                .count();
            observed_disagreements = observed_disagreements.saturating_add(lane_disagreements);
            if lane_disagreements >= usize::from(self.state.policy().flaky.minimum_disagreements) {
                observed_flake = true;
            }
        }

        if observed_flake {
            let expires_at_unix_secs = unix_now_secs()
                .saturating_add(u64::from(self.state.policy().flaky.quarantine_seconds));
            self.emit_durable(
                self.scope.turn,
                EventKind::VerificationPolicy {
                    version: iteron_protocol::VerificationPolicyEventVersion::V1,
                    event: iteron_protocol::VerificationPolicyEvent::Quarantined {
                        selection: verification_selection_evidence(self.state.policy().selection),
                        command_digests_sha256: command_digests.clone(),
                        repeat_count: u8::try_from(repeat_count).map_err(|_| {
                            KernelError::ContextResolution(
                                "verification repeat count exceeded its receipt bound".into(),
                            )
                        })?,
                        verifier_count: self.state.policy().quorum.verifiers,
                        physical_runs: u16::try_from(physical_runs).map_err(|_| {
                            KernelError::ContextResolution(
                                "verification physical-run count exceeded its receipt bound".into(),
                            )
                        })?,
                        disagreements: u16::try_from(observed_disagreements).unwrap_or(u16::MAX),
                        expires_at_unix_secs,
                    },
                },
            )?;
            if self.state.policy().flaky.quarantine_seconds > 0 {
                self.state
                    .publish_quarantine(&command_digests, expires_at_unix_secs)?;
            }
            self.lifecycle_event(
                "verification.check_failed",
                Some(self.scope.turn),
                LifecyclePayload {
                    reason_code: Some("flaky_quarantined".into()),
                    count: Some(u64::try_from(physical_runs).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            );
            return Ok(iteron_verify::Verdict::new(
                plan.strength,
                iteron_verify::VerificationOutcome::InfrastructureFailure,
                if self.state.policy().flaky.report_disagreement {
                    format!(
                        "verification attempts disagreed; evidence is quarantined for {} seconds",
                        self.state.policy().flaky.quarantine_seconds
                    )
                } else {
                    "verification evidence was quarantined by policy".into()
                },
            ));
        }

        let consensus = iteron_verify::verification_consensus(
            self.state.policy().quorum,
            self.state.policy().flaky.minimum_disagreements,
            &representative_outcomes,
        );
        let outcome = match consensus {
            iteron_verify::VerificationConsensus::Accepted => {
                iteron_verify::VerificationOutcome::Pass
            }
            iteron_verify::VerificationConsensus::Rejected => {
                iteron_verify::VerificationOutcome::TestFailure
            }
            iteron_verify::VerificationConsensus::Flaky
            | iteron_verify::VerificationConsensus::Indeterminate => {
                iteron_verify::VerificationOutcome::InfrastructureFailure
            }
        };
        let pass_lanes = representative_outcomes
            .iter()
            .filter(|outcome| **outcome == iteron_verify::VerificationOutcome::Pass)
            .count();
        let test_failure_lanes = representative_outcomes
            .iter()
            .filter(|outcome| **outcome == iteron_verify::VerificationOutcome::TestFailure)
            .count();
        let other_lanes = representative_outcomes
            .len()
            .saturating_sub(pass_lanes)
            .saturating_sub(test_failure_lanes);
        self.emit_durable(
            self.scope.turn,
            EventKind::VerificationPolicy {
                version: iteron_protocol::VerificationPolicyEventVersion::V1,
                event: iteron_protocol::VerificationPolicyEvent::Reduced {
                    selection: verification_selection_evidence(self.state.policy().selection),
                    command_digests_sha256: command_digests,
                    repeat_count: u8::try_from(repeat_count).map_err(|_| {
                        KernelError::ContextResolution(
                            "verification repeat count exceeded its receipt bound".into(),
                        )
                    })?,
                    verifier_count: self.state.policy().quorum.verifiers,
                    physical_runs: u16::try_from(physical_runs).map_err(|_| {
                        KernelError::ContextResolution(
                            "verification physical-run count exceeded its receipt bound".into(),
                        )
                    })?,
                    pass_lanes: u8::try_from(pass_lanes).unwrap_or(u8::MAX),
                    test_failure_lanes: u8::try_from(test_failure_lanes).unwrap_or(u8::MAX),
                    other_lanes: u8::try_from(other_lanes).unwrap_or(u8::MAX),
                    consensus: verification_consensus_evidence(consensus),
                    outcome: verification_outcome_evidence(outcome),
                },
            },
        )?;
        let detail = truncate_tail(
            &details.join("\n--- verifier ---\n"),
            self.state.policy().feedback.total_bytes,
        );
        Ok(iteron_verify::Verdict::new(plan.strength, outcome, detail))
    }
}
fn verification_selection_evidence(
    selection: iteron_verify::VerificationSelectionMode,
) -> iteron_protocol::VerificationSelectionEvidence {
    match selection {
        iteron_verify::VerificationSelectionMode::Incremental => {
            iteron_protocol::VerificationSelectionEvidence::Incremental
        }
        iteron_verify::VerificationSelectionMode::Impacted => {
            iteron_protocol::VerificationSelectionEvidence::Impacted
        }
        iteron_verify::VerificationSelectionMode::Full => {
            iteron_protocol::VerificationSelectionEvidence::Full
        }
    }
}

fn verification_consensus_evidence(
    consensus: iteron_verify::VerificationConsensus,
) -> iteron_protocol::VerificationConsensusEvidence {
    match consensus {
        iteron_verify::VerificationConsensus::Accepted => {
            iteron_protocol::VerificationConsensusEvidence::Accepted
        }
        iteron_verify::VerificationConsensus::Rejected => {
            iteron_protocol::VerificationConsensusEvidence::Rejected
        }
        iteron_verify::VerificationConsensus::Flaky => {
            iteron_protocol::VerificationConsensusEvidence::Flaky
        }
        iteron_verify::VerificationConsensus::Indeterminate => {
            iteron_protocol::VerificationConsensusEvidence::Indeterminate
        }
    }
}

fn verification_outcome_evidence(
    outcome: iteron_verify::VerificationOutcome,
) -> iteron_protocol::VerificationOutcomeEvidence {
    match outcome {
        iteron_verify::VerificationOutcome::Pass => {
            iteron_protocol::VerificationOutcomeEvidence::Pass
        }
        iteron_verify::VerificationOutcome::TestFailure => {
            iteron_protocol::VerificationOutcomeEvidence::TestFailure
        }
        iteron_verify::VerificationOutcome::TimedOut
        | iteron_verify::VerificationOutcome::InfrastructureFailure
        | iteron_verify::VerificationOutcome::Cancelled => {
            iteron_protocol::VerificationOutcomeEvidence::InfrastructureFailure
        }
    }
}
