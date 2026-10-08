//! Existing operator-authorised rollback, bound to an exact pre-submission checkpoint and live tree.
use super::KernelError;
use super::approval_wait::{ApprovalRequest, ApprovalWait};
use super::strong_verification::StrongVerificationGate;
use super::tool_presentation::{strict_utf8_head, ui_verification_rollback_arguments};
use iteron_protocol::{Capability, EventKind, LifecyclePayload, SubmissionId, ToolUse, TurnId};
use sha2::{Digest, Sha256};
impl StrongVerificationGate<'_> {
    pub(super) async fn rollback_after_verification_failure(
        &mut self,
    ) -> Result<bool, KernelError> {
        use iteron_verify::VerificationRollbackMode;

        let mode = self.state.policy().restore.mode;
        if mode == VerificationRollbackMode::Off {
            return Ok(false);
        }
        if !self.state.policy().restore.require_operator_confirmation {
            return Err(KernelError::ContextResolution(
                "verification rollback policy attempted to disable its operator confirmation invariant"
                    .into(),
            ));
        }
        let snapshot = self.state.rollback_snapshot().cloned().ok_or_else(|| {
            KernelError::ContextResolution(
                "verification rollback was authorised but no pre-submission checkpoint exists"
                    .into(),
            )
        })?;
        let approval_turn = self.scope.turn;
        // Bind the human decision to the exact live workspace that would be overwritten, not
        // merely to the older rollback target.  The checkpoint uses the same hook-free isolated
        // Git inventory as the rewind and excludes Core's runtime-state directory.  It is durable
        // before the request is shown, so a crash cannot leave an unaccounted inventory read.
        self.checkpoint_at_turn_end(approval_turn, true)?;
        let approved_live_tree_ref = self
            .checkpoints
            .latest()
            .ok_or_else(|| {
                KernelError::ContextResolution(
                    "verification rollback approval could not bind the live workspace tree".into(),
                )
            })?
            .tree_ref
            .clone();
        let receipt_mode = verification_rollback_evidence(mode)
            .expect("off rollback returned before receipt construction");
        let path_count = u32::try_from(self.state.policy().restore.paths.len()).unwrap_or(u32::MAX);
        let mode_label = match mode {
            VerificationRollbackMode::Off => "off",
            VerificationRollbackMode::SelectedPaths => "selected_paths",
            VerificationRollbackMode::Workspace => "workspace",
        };
        let policy_digest_sha256 =
            digest_json(&("verification-runtime-policy-v1", &self.state.policy()))?;
        let scope_digest_sha256 = digest_json(&(
            "verification-rollback-scope-v1",
            self.journal.rollout.run_id(),
            snapshot.at,
            &snapshot.tree_ref,
            mode_label,
            &self.state.policy().restore.paths,
        ))?;
        let approval_arguments = serde_json::json!({
            "policy_id": "verification-runtime-policy-v1",
            "policy_digest_sha256": policy_digest_sha256,
            "scope_digest_sha256": scope_digest_sha256,
            "run_id": &self.journal.rollout.run_id().0,
            "checkpoint_seq": snapshot.at.0,
            "checkpoint_tree_ref": &snapshot.tree_ref,
            "live_workspace_tree_ref": &approved_live_tree_ref,
            "mode": mode_label,
            "path_count": path_count,
            "paths": &self.state.policy().restore.paths,
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
        if !self.approve_rollback(approval_turn, &approval).await? {
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
            .checkpoints
            .latest()
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
        let _checkpoint_owner =
            iteron_record::acquire_verified_rollout_owner(self.journal.rollout.path())?;
        match mode {
            VerificationRollbackMode::Off => return Ok(false),
            VerificationRollbackMode::Workspace => {
                iteron_record::rewind_workspace(&snapshot, self.scope.workspace)?;
            }
            VerificationRollbackMode::SelectedPaths => {
                iteron_record::checkpoint::rewind_workspace_paths(
                    &snapshot,
                    self.scope.workspace,
                    &self.state.policy().restore.paths,
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
                    u64::try_from(self.state.policy().restore.paths.len()).unwrap_or(u64::MAX),
                ),
                ..LifecyclePayload::default()
            },
        );
        Ok(true)
    }

    async fn approve_rollback(
        &mut self,
        turn: TurnId,
        call: &ToolUse,
    ) -> Result<bool, KernelError> {
        *self.approval_seq = self
            .approval_seq
            .checked_add(1)
            .ok_or(KernelError::IdentityExhausted("approval"))?;
        let arguments = ui_verification_rollback_arguments(&call.input).ok_or_else(|| {
            KernelError::ContextResolution(
                "verification rollback approval carried an invalid structural binding".into(),
            )
        })?;
        let events = self.scope.events.clone();
        let request = ApprovalRequest {
            turn,
            id: SubmissionId(*self.approval_seq),
            call_id: strict_utf8_head(&call.id, 2048),
            tool: call.name.clone(),
            capability: Capability::TrustMutating,
            arguments,
            workspace: strict_utf8_head(
                &iteron_record::redact::scrub(&self.scope.workspace.display().to_string()),
                2048,
            ),
            reason: "session policy requires an explicit operator decision before this effect"
                .into(),
            interactive: self.scope.interactive,
            deadline: self.scope.deadline,
            poll: iteron_tunables::param_duration(
                "cli.runtime.inbound_drain_poll_interval",
                super::INBOUND_DRAIN_POLL_INTERVAL,
            ),
        };
        let decision = ApprovalWait {
            journal: self.journal.approval(),
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            activity: self.scope.activity.clone(),
            events: events.clone(),
        }
        .run(request)
        .await?;
        if decision.remember
            && let Err(error) = self.permission.remember(
                &mut self.journal.approval(),
                turn,
                Capability::TrustMutating,
            )
        {
            decision.policy_persist_failed(&events);
            return Err(error);
        }
        decision.publish(&events)
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
