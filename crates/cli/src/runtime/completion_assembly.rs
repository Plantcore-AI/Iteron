//! Trusted composition of the actual transcript/control completion controller. Verification
//! dependencies are captured only for the existing explicitly configured operator command.
use super::Agent;
use super::completion_session::{
    CompletionBudget, CompletionInput, CompletionJournal, CompletionSession, CompletionVerification,
};
use super::permission_transaction::PermissionTransaction;
use super::session_transcript::TranscriptAdmissionJournal;
use super::steering_admission::SteeringScope;
use super::strong_verification::VerificationScope;
use super::turn_completion::TurnCompletion;
use super::verification_journal::VerificationPolicyBootstrap;
use iteron_protocol::TurnId;

impl Agent {
    pub(super) fn turn_completion(&mut self, turn: TurnId) -> TurnCompletion<'_> {
        let events = self.tool_events(turn);
        let command = self.verify_command.clone();
        let bootstrap = if command.is_some() && self.policy_evidence.is_none() {
            self.tunables_pin
                .as_ref()
                .map(|pin| VerificationPolicyBootstrap {
                    digest: pin.resolution_digest_sha256().to_owned(),
                    bindings: self.policy_runtime_bindings().to_vec(),
                })
        } else {
            None
        };
        let verification = match command {
            Some(command) => Some(CompletionVerification {
                command,
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
                    events: events.clone(),
                    activity: self.activity.clone(),
                    #[cfg(test)]
                    oracle: self.verify_oracle.clone(),
                },
                state: &mut self.verification_state,
                tasks: self.verification_tasks.clone(),
                approval_sequence: &mut self.approval_seq,
                permission: PermissionTransaction {
                    mode: &mut self.permission_mode,
                    rules: &mut self.permission_rules,
                    provenance: &mut self.runtime_policy_provenance,
                    effort: self.effort,
                    max_turns: self.budget.max_turns,
                },
                bootstrap,
            }),
            None => None,
        };
        TurnCompletion::new(CompletionSession {
            journal: CompletionJournal {
                transcript: TranscriptAdmissionJournal {
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    publications: &mut self.turn_publications,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                effects: &mut self.effect_journal,
                policy: &mut self.policy_evidence,
                terminal: &mut self.terminal_record,
                checkpoints: &mut self.workspace_checkpoints,
            },
            input: CompletionInput {
                scope: SteeringScope {
                    turn,
                    registry: &self.registry,
                    mailbox: self.persistent_mailbox.as_ref(),
                    memory_workspace: self.memory_workspace.as_deref(),
                    max_bytes: iteron_tunables::param_integer(
                        "cli.runtime.max_steer_bytes",
                        super::MAX_STEER_BYTES,
                    ),
                    events,
                },
                inbox: &mut self.inbox,
                control: &mut self.control,
                force_cancel: self.force_cancel_seam.as_mut(),
                estimator: &mut self.context_estimator,
                plan: &mut self.task_plan,
                trust: &mut self.observed_trust,
                visibility: &mut self.session_memory_visibility,
            },
            verification,
            budget: CompletionBudget {
                tokens: self.budget.max_tokens,
                usd: self.usd_budget.clone(),
                deadline: self.run_deadline.current(),
            },
        })
    }
}
