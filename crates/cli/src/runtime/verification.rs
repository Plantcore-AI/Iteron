use super::*;

impl Agent {
    pub fn set_verification_policy(
        &mut self,
        policy: iteron_verify::VerificationRuntimePolicy,
    ) -> Result<(), KernelError> {
        policy.validate().map_err(|error| {
            KernelError::ContextResolution(format!("verification policy refused: {error}"))
        })?;
        match self.verify_command.as_deref() {
            Some(full_command)
                if policy.required_commands.last().map(String::as_str) != Some(full_command) =>
            {
                return Err(KernelError::ContextResolution(
                    "verification policy must end with the exact operator-owned full command"
                        .into(),
                ));
            }
            None if !policy.required_commands.is_empty() => {
                return Err(KernelError::ContextResolution(
                    "verification commands have no operator-owned full workspace gate".into(),
                ));
            }
            _ => {}
        }
        self.verification_policy = policy;
        self.verification_quarantine.clear();
        // The same setter is used while reopening an existing run. Mark replay pending so the
        // immutable policy is paired with any still-live quarantine receipts in that rollout.
        self.verification_quarantine_restored = false;
        Ok(())
    }

    /// Restore unexpired typed quarantine receipts from the currently-owned physical rollout.
    /// Absolute deadlines keep resume from granting contradictory evidence another try or from
    /// restarting the quarantine duration on every process launch.
    fn restore_verification_quarantine(&mut self) -> Result<(), KernelError> {
        if self.verification_quarantine_restored {
            return Ok(());
        }
        let now = unix_now_secs();
        let mut restored = std::collections::BTreeMap::<String, u64>::new();
        for timed in iteron_record::replay_timed(self.rollout.path())? {
            let EventKind::VerificationPolicy {
                version: iteron_protocol::VerificationPolicyEventVersion::V1,
                event:
                    iteron_protocol::VerificationPolicyEvent::Quarantined {
                        command_digests_sha256,
                        expires_at_unix_secs,
                        ..
                    },
            } = timed.event.kind
            else {
                continue;
            };
            if command_digests_sha256.len() > iteron_verify::MAX_VERIFICATION_COMMANDS
                || command_digests_sha256
                    .iter()
                    .any(|digest| !is_sha256_digest(digest))
            {
                return Err(KernelError::ContextResolution(
                    "durable verification quarantine receipt is outside its closed bounds".into(),
                ));
            }
            if expires_at_unix_secs <= now {
                continue;
            }
            for digest in command_digests_sha256 {
                restored
                    .entry(digest)
                    .and_modify(|deadline| *deadline = (*deadline).max(expires_at_unix_secs))
                    .or_insert(expires_at_unix_secs);
            }
        }
        self.verification_quarantine = restored;
        self.verification_quarantine_restored = true;
        Ok(())
    }

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

    pub(super) fn prepare_verification_rollback_point(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        if self.verification_policy.restore.mode == iteron_verify::VerificationRollbackMode::Off {
            return Ok(());
        }
        // A rollback must point to state from before this submission's model/tool effects. An
        // end-of-turn checkpoint is useful for resume, but taking it after a failing candidate and
        // calling that "rollback" would restore the failure to itself.
        self.checkpoint_at_turn_end(turn, true)?;
        self.verification_rollback_point = self.latest_workspace_checkpoint.clone();
        Ok(())
    }

    pub(super) fn checkpoint_before_verification(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        if !self.verification_policy.checkpoint.before_verification
            || !self.verification_checkpoint_interval_elapsed(turn)
        {
            return Ok(());
        }
        self.checkpoint_at_turn_end(turn, true)
    }

    pub(super) fn verification_checkpoint_interval_elapsed(&self, turn: TurnId) -> bool {
        let interval = self.verification_policy.checkpoint.minimum_turn_interval;
        self.last_workspace_checkpoint_turn
            .is_none_or(|previous| turn.0.saturating_sub(previous) >= interval)
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

    /// Execute the immutable command-selection, flake, and quorum policy around the strategy's
    /// strength/scope plan. Every physical invocation still crosses `run_verify`, so a consensus
    /// never collapses several external effects into one journal entry.
    pub(super) async fn run_verification_policy(
        &mut self,
        fallback_command: &str,
        plan: iteron_verify::VerifierPlan,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        self.restore_verification_quarantine()?;
        let now = unix_now_secs();
        self.verification_quarantine
            .retain(|_, expires_at| *expires_at > now);
        let configured = if self.verification_policy.required_commands.is_empty() {
            vec![fallback_command.to_owned()]
        } else {
            self.verification_policy.selected_commands().to_vec()
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
            if let Some(expires_at_unix_secs) = self.verification_quarantine.get(digest).copied() {
                self.emit_durable(
                    TurnId(self.seq_turn),
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

        let repeat_count = usize::from(
            self.verification_policy
                .flaky
                .repeat_count
                .max(u8::try_from(plan.attempts).unwrap_or(u8::MAX)),
        );
        let verifier_count = usize::from(self.verification_policy.quorum.verifiers);
        let physical_runs = configured
            .len()
            .saturating_mul(repeat_count)
            .saturating_mul(verifier_count);
        if physical_runs > iteron_verify::MAX_PHYSICAL_VERIFIER_RUNS {
            return Err(KernelError::ContextResolution(
                "verification physical-run product exceeds its immutable ceiling".into(),
            ));
        }
        let mut representative_outcomes = Vec::with_capacity(verifier_count);
        let mut details = Vec::with_capacity(physical_runs);
        let mut observed_flake = false;
        let mut observed_disagreements = 0usize;
        for _ in 0..verifier_count {
            let mut lane_outcome = iteron_verify::VerificationOutcome::Pass;
            for command in &configured {
                let mut outcomes = Vec::with_capacity(repeat_count);
                let mut last_detail = String::new();
                for _ in 0..repeat_count {
                    let verdict = self.run_verify(command).await?;
                    // Operator cancellation is control flow, not verifier evidence. Folding it
                    // into quorum would turn the typed cancellation into `Indeterminate`, then
                    // into `InfrastructureFailure`, and admit the remaining physical verifier
                    // runs after the operator already stopped the gate.
                    if verdict.outcome == iteron_verify::VerificationOutcome::Cancelled {
                        return Ok(verdict);
                    }
                    last_detail = truncate_tail(
                        &verdict.detail,
                        self.verification_policy.feedback.command_output_bytes,
                    );
                    outcomes.push(verdict.outcome);
                }
                let first = outcomes[0];
                let disagreements = outcomes.iter().filter(|outcome| **outcome != first).count();
                observed_disagreements = observed_disagreements.saturating_add(disagreements);
                if disagreements
                    >= usize::from(self.verification_policy.flaky.minimum_disagreements)
                {
                    observed_flake = true;
                }
                // Repeats below the configured quarantine threshold still may not disappear. A
                // later definite test failure vetoes an earlier pass; any other non-pass keeps the
                // lane indeterminate instead of manufacturing green from `outcomes[0]`.
                let command_outcome = outcomes
                    .iter()
                    .copied()
                    .find(|outcome| *outcome == iteron_verify::VerificationOutcome::TestFailure)
                    .or_else(|| {
                        outcomes
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
                details.push(last_detail);
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
            if lane_disagreements
                >= usize::from(self.verification_policy.flaky.minimum_disagreements)
            {
                observed_flake = true;
            }
        }

        if observed_flake {
            let expires_at_unix_secs = unix_now_secs()
                .saturating_add(u64::from(self.verification_policy.flaky.quarantine_seconds));
            self.emit_durable(
                TurnId(self.seq_turn),
                EventKind::VerificationPolicy {
                    version: iteron_protocol::VerificationPolicyEventVersion::V1,
                    event: iteron_protocol::VerificationPolicyEvent::Quarantined {
                        selection: verification_selection_evidence(
                            self.verification_policy.selection,
                        ),
                        command_digests_sha256: command_digests.clone(),
                        repeat_count: u8::try_from(repeat_count).map_err(|_| {
                            KernelError::ContextResolution(
                                "verification repeat count exceeded its receipt bound".into(),
                            )
                        })?,
                        verifier_count: self.verification_policy.quorum.verifiers,
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
            if self.verification_policy.flaky.quarantine_seconds > 0 {
                for digest in &command_digests {
                    if self.verification_quarantine.len()
                        >= iteron_verify::MAX_VERIFICATION_COMMANDS
                    {
                        break;
                    }
                    self.verification_quarantine
                        .insert(digest.clone(), expires_at_unix_secs);
                }
            }
            self.lifecycle_event(
                "verification.check_failed",
                Some(TurnId(self.seq_turn)),
                LifecyclePayload {
                    reason_code: Some("flaky_quarantined".into()),
                    count: Some(u64::try_from(physical_runs).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            );
            return Ok(iteron_verify::Verdict::new(
                plan.strength,
                iteron_verify::VerificationOutcome::InfrastructureFailure,
                if self.verification_policy.flaky.report_disagreement {
                    format!(
                        "verification attempts disagreed; evidence is quarantined for {} seconds",
                        self.verification_policy.flaky.quarantine_seconds
                    )
                } else {
                    "verification evidence was quarantined by policy".into()
                },
            ));
        }

        let consensus = iteron_verify::verification_consensus(
            self.verification_policy.quorum,
            self.verification_policy.flaky.minimum_disagreements,
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
            TurnId(self.seq_turn),
            EventKind::VerificationPolicy {
                version: iteron_protocol::VerificationPolicyEventVersion::V1,
                event: iteron_protocol::VerificationPolicyEvent::Reduced {
                    selection: verification_selection_evidence(self.verification_policy.selection),
                    command_digests_sha256: command_digests,
                    repeat_count: u8::try_from(repeat_count).map_err(|_| {
                        KernelError::ContextResolution(
                            "verification repeat count exceeded its receipt bound".into(),
                        )
                    })?,
                    verifier_count: self.verification_policy.quorum.verifiers,
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
            self.verification_policy.feedback.total_bytes,
        );
        Ok(iteron_verify::Verdict::new(plan.strength, outcome, detail))
    }

    pub(super) async fn rollback_after_verification_failure(
        &mut self,
    ) -> Result<bool, KernelError> {
        use iteron_verify::VerificationRollbackMode;

        let mode = self.verification_policy.restore.mode;
        if mode == VerificationRollbackMode::Off {
            return Ok(false);
        }
        if !self
            .verification_policy
            .restore
            .require_operator_confirmation
        {
            return Err(KernelError::ContextResolution(
                "verification rollback policy attempted to disable its operator confirmation invariant"
                    .into(),
            ));
        }
        let snapshot = self.verification_rollback_point.clone().ok_or_else(|| {
            KernelError::ContextResolution(
                "verification rollback was authorised but no pre-submission checkpoint exists"
                    .into(),
            )
        })?;
        let approval_turn = TurnId(self.seq_turn);
        // Bind the human decision to the exact live workspace that would be overwritten, not
        // merely to the older rollback target.  The checkpoint uses the same hook-free isolated
        // Git inventory as the rewind and excludes Core's runtime-state directory.  It is durable
        // before the request is shown, so a crash cannot leave an unaccounted inventory read.
        self.checkpoint_at_turn_end(approval_turn, true)?;
        let approved_live_tree_ref = self
            .latest_workspace_checkpoint
            .as_ref()
            .ok_or_else(|| {
                KernelError::ContextResolution(
                    "verification rollback approval could not bind the live workspace tree".into(),
                )
            })?
            .tree_ref
            .clone();
        let receipt_mode = verification_rollback_evidence(mode)
            .expect("off rollback returned before receipt construction");
        let path_count =
            u32::try_from(self.verification_policy.restore.paths.len()).unwrap_or(u32::MAX);
        let mode_label = match mode {
            VerificationRollbackMode::Off => "off",
            VerificationRollbackMode::SelectedPaths => "selected_paths",
            VerificationRollbackMode::Workspace => "workspace",
        };
        let policy_digest_sha256 =
            digest_json(&("verification-runtime-policy-v1", &self.verification_policy))?;
        let scope_digest_sha256 = digest_json(&(
            "verification-rollback-scope-v1",
            self.rollout.run_id(),
            snapshot.at,
            &snapshot.tree_ref,
            mode_label,
            &self.verification_policy.restore.paths,
        ))?;
        let approval_arguments = serde_json::json!({
            "policy_id": "verification-runtime-policy-v1",
            "policy_digest_sha256": policy_digest_sha256,
            "scope_digest_sha256": scope_digest_sha256,
            "run_id": &self.rollout.run_id().0,
            "checkpoint_seq": snapshot.at.0,
            "checkpoint_tree_ref": &snapshot.tree_ref,
            "live_workspace_tree_ref": &approved_live_tree_ref,
            "mode": mode_label,
            "path_count": path_count,
            "paths": &self.verification_policy.restore.paths,
        });
        let approval_binding =
            digest_json(&("verification-rollback-approval-v1", &approval_arguments))?;
        // Keep the exact binding inside the record layer's structural correlation-id alphabet.
        // A colon would send the digest through generic secret scrubbing and make the durable
        // Ask/Allow pair impossible to correlate to this exact scope after replay.
        let approval = ToolUse {
            id: format!("verification_rollback_v1_{approval_binding}"),
            name: "verification_rollback".into(),
            input: approval_arguments,
        };
        if !self
            .await_approval(approval_turn, &approval, Capability::TrustMutating)
            .await?
        {
            return Err(KernelError::ContextResolution(
                "verification rollback was not approved for this exact checkpoint and scope".into(),
            ));
        }
        // Approval may remain open while another terminal or editor changes the worktree.  Take
        // the same complete inventory again immediately before the destructive restore and refuse
        // on any drift.  This is intentionally conservative for selected-path rollback: unrelated
        // edits also require a fresh approval rather than risking an incomplete scope preview.
        self.checkpoint_at_turn_end(approval_turn, true)?;
        let revalidated_live_tree_ref = self
            .latest_workspace_checkpoint
            .as_ref()
            .ok_or_else(|| {
                KernelError::ContextResolution(
                    "verification rollback could not revalidate the live workspace tree".into(),
                )
            })?
            .tree_ref
            .clone();
        if revalidated_live_tree_ref != approved_live_tree_ref {
            return Err(KernelError::ContextResolution(
                "workspace changed while verification rollback approval was pending; a fresh exact approval is required"
                    .into(),
            ));
        }
        self.emit_durable(
            approval_turn,
            EventKind::VerificationPolicy {
                version: iteron_protocol::VerificationPolicyEventVersion::V1,
                event: iteron_protocol::VerificationPolicyEvent::RollbackAuthorized {
                    mode: receipt_mode,
                    checkpoint_seq: snapshot.at,
                    path_count,
                },
            },
        )?;
        // The authorisation is durable before this potentially blocking read gate. Keep the
        // shared owner lease through the Git restore so content revocation cannot tombstone the
        // checkpoint after replay validation but before `read-tree`/`checkout-index` consumes it.
        let _checkpoint_owner = iteron_record::acquire_verified_rollout_owner(self.rollout.path())?;
        match mode {
            VerificationRollbackMode::Off => return Ok(false),
            VerificationRollbackMode::Workspace => {
                iteron_record::rewind_workspace(&snapshot, &self.workspace)?;
            }
            VerificationRollbackMode::SelectedPaths => {
                iteron_record::checkpoint::rewind_workspace_paths(
                    &snapshot,
                    &self.workspace,
                    &self.verification_policy.restore.paths,
                )?;
            }
        }
        self.emit_durable(
            approval_turn,
            EventKind::VerificationPolicy {
                version: iteron_protocol::VerificationPolicyEventVersion::V1,
                event: iteron_protocol::VerificationPolicyEvent::RollbackApplied {
                    mode: receipt_mode,
                    checkpoint_seq: snapshot.at,
                    path_count,
                },
            },
        )?;
        self.lifecycle_event(
            "checkpoint.created",
            Some(approval_turn),
            LifecyclePayload {
                reason_code: Some("verification_rollback_applied".into()),
                count: Some(
                    u64::try_from(self.verification_policy.restore.paths.len()).unwrap_or(u64::MAX),
                ),
                ..LifecyclePayload::default()
            },
        );
        Ok(true)
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
        .with_sensitive_env_names(self.sensitive_env_names.clone())
        .with_output_tail_bytes(self.verification_policy.feedback.oracle_output_bytes)
        .with_timeout_secs(self.verification_policy.verifier_timeout_secs);
        if let Some(remaining) = self.run_time_remaining() {
            // The sandbox API uses whole seconds. Round its cleanup-aware process timeout up,
            // then enforce the exact (possibly sub-second) deadline in `run_bounded_verify`.
            // Flooring here used to fire the oracle early; relying only on the rounded value could
            // overrun the run deadline by almost a second.
            let rounded_up_secs = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .max(1);
            oracle = oracle.with_timeout_secs(
                rounded_up_secs.min(self.verification_policy.verifier_timeout_secs),
            );
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
        let verifier_deadline = Instant::now()
            .checked_add(Duration::from_secs(
                self.verification_policy.verifier_timeout_secs,
            ))
            .unwrap_or_else(Instant::now);

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

            let verifier_remaining = verifier_deadline.saturating_duration_since(Instant::now());
            let run_remaining = self.run_time_remaining();
            if run_remaining.is_some_and(|duration| duration.is_zero()) {
                let verdict = iteron_verify::Verdict::timed_out(
                    "verification exceeded the absolute run deadline",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }
            if verifier_remaining.is_zero() {
                let verdict = iteron_verify::Verdict::timed_out(
                    "verification exceeded its configured verifier timeout",
                );
                return VerifyDispatch::from_drop(dispatched, verdict);
            }
            let remaining = run_remaining
                .map(|duration| duration.min(verifier_remaining))
                .unwrap_or(verifier_remaining);
            let poll_for = remaining.min(VERIFY_CANCEL_POLL);

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

fn digest_json(value: &impl serde::Serialize) -> Result<String, KernelError> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        KernelError::ContextResolution(
            "verification rollback approval identity could not be encoded".into(),
        )
    })?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn verification_command_digest(command: &str) -> String {
    hex::encode(Sha256::digest(command.as_bytes()))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
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

fn verification_rollback_evidence(
    mode: iteron_verify::VerificationRollbackMode,
) -> Option<iteron_protocol::VerificationRollbackEvidence> {
    match mode {
        iteron_verify::VerificationRollbackMode::Off => None,
        iteron_verify::VerificationRollbackMode::SelectedPaths => {
            Some(iteron_protocol::VerificationRollbackEvidence::SelectedPaths)
        }
        iteron_verify::VerificationRollbackMode::Workspace => {
            Some(iteron_protocol::VerificationRollbackEvidence::Workspace)
        }
    }
}
