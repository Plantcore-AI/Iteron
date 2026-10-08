//! Composition of the existing operator verification gate. Mutable verification state, physical
//! execution, journal, control, checkpoint and approval ownership live in concrete independent ports.
use super::permission_transaction::PermissionTransaction;
use super::strong_verification::{StrongVerificationGate, VerificationScope};
use super::verification_journal::{VerificationJournal, VerificationPolicyBootstrap};
use super::{Agent, KernelError};
use iteron_protocol::TurnId;

impl Agent {
    pub fn set_verification_policy(
        &mut self,
        policy: iteron_verify::VerificationRuntimePolicy,
    ) -> Result<(), KernelError> {
        self.verification_state
            .set_policy(policy, self.verify_command.as_deref())
    }
    /// Compose only the existing verification dependencies. The asynchronous gate cannot reach
    /// provider, transcript, routing, registry mutation, or arbitrary session methods.
    pub(super) fn strong_verification_gate(&mut self, turn: TurnId) -> StrongVerificationGate<'_> {
        let events = self.tool_events(turn);
        let bootstrap = if self.policy_evidence.is_none() {
            self.tunables_pin
                .as_ref()
                .map(|pin| VerificationPolicyBootstrap {
                    digest: pin.resolution_digest_sha256().to_owned(),
                    bindings: self.policy_runtime_bindings().to_vec(),
                })
        } else {
            None
        };
        StrongVerificationGate {
            scope: VerificationScope {
                turn,
                workspace: &self.workspace,
                runtime_state: &self.runtime_state_dir,
                deadline: self.run_deadline.current(),
                authority_ceiling: self.authority_ceiling,
                verifier: self.compiled_policy_bundle.slots().verifier.as_ref(),
                preconfined: self.verify_preconfined,
                sensitive_env_names: &self.sensitive_env_names,
                interactive: self.interactive_approvals,
                events,
                activity: self.activity.clone(),
                #[cfg(test)]
                oracle: self.verify_oracle.clone(),
            },
            state: &mut self.verification_state,
            journal: VerificationJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                effects: &mut self.effect_journal,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                policy: &mut self.policy_evidence,
                bootstrap,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            inbox: &mut self.inbox,
            control: &mut self.control,
            force_cancel: self.force_cancel_seam.as_mut(),
            checkpoints: &mut self.workspace_checkpoints,
            terminal: &mut self.terminal_record,
            tasks: self.verification_tasks.clone(),
            approval_seq: &mut self.approval_seq,
            permission: PermissionTransaction {
                mode: &mut self.permission_mode,
                rules: &mut self.permission_rules,
                provenance: &mut self.runtime_policy_provenance,
                effort: self.effort,
                max_turns: self.budget.max_turns,
            },
        }
    }
    pub(super) fn prepare_verification_rollback_point(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        if self.verification_state.policy().restore.mode
            == iteron_verify::VerificationRollbackMode::Off
        {
            return Ok(());
        }
        self.strong_verification_gate(turn)
            .prepare_rollback_point(turn)
    }
    pub(super) fn verification_checkpoint_interval_elapsed(&self, turn: TurnId) -> bool {
        self.workspace_checkpoints.interval_elapsed(
            turn,
            self.verification_state
                .policy()
                .checkpoint
                .minimum_turn_interval,
        )
    }
    #[cfg(test)]
    pub(super) async fn run_verification_policy(
        &mut self,
        command: &str,
        plan: iteron_verify::VerifierPlan,
    ) -> Result<iteron_verify::Verdict, KernelError> {
        self.strong_verification_gate(TurnId(self.seq_turn))
            .run_verification_policy(command, plan)
            .await
    }
    #[cfg(test)]
    pub(super) async fn rollback_after_verification_failure(
        &mut self,
    ) -> Result<bool, KernelError> {
        self.strong_verification_gate(TurnId(self.seq_turn))
            .rollback_after_verification_failure()
            .await
    }
    #[cfg(test)]
    pub(super) async fn run_bounded_verify(
        &mut self,
        oracle: std::sync::Arc<dyn iteron_verify::Oracle>,
    ) -> super::verification_execution::VerifyDispatch {
        self.strong_verification_gate(TurnId(self.seq_turn))
            .run_bounded_verify(oracle)
            .await
    }
}

#[cfg(test)]
#[path = "verification_owner_tests.rs"]
mod owner_tests;
