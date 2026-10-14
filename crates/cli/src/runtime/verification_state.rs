//! State retained by the configured operator verification gate. No executor or transport owns it.
use super::KernelError;
use iteron_protocol::EventKind;
use iteron_record::{Rollout, Snapshot};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct VerificationStateOwner {
    policy: iteron_verify::VerificationRuntimePolicy,
    quarantine: BTreeMap<String, u64>,
    quarantine_restored: bool,
    rollback_point: Option<Snapshot>,
    attempts: u32,
}
impl VerificationStateOwner {
    pub(super) fn policy(&self) -> &iteron_verify::VerificationRuntimePolicy {
        &self.policy
    }
    pub(super) fn attempts(&self) -> u32 {
        self.attempts
    }
    pub(super) fn reset_attempts(&mut self) {
        self.attempts = 0;
    }
    /// Only a real graded test failure consumes the model's repair allowance.
    pub(super) fn consume_test_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
    pub(super) fn rollback_snapshot(&self) -> Option<&Snapshot> {
        self.rollback_point.as_ref()
    }
    pub(super) fn capture_pre_submission(
        &mut self,
        checkpoints: &super::workspace_checkpoint::WorkspaceCheckpointOwner,
    ) {
        self.rollback_point = checkpoints.latest().cloned();
    }
    pub(super) fn apply_feedback(
        &mut self,
        feedback: iteron_verify::VerificationFeedbackTailPolicy,
    ) -> Result<(), KernelError> {
        let mut policy = self.policy.clone();
        policy.feedback = feedback;
        policy.validate().map_err(|error| {
            KernelError::ContextResolution(format!("verification feedback refused: {error}"))
        })?;
        self.policy = policy;
        Ok(())
    }
    /// Trusted genesis recovery supplies its already resolved immutable policy through this port.
    pub(super) fn install_resolved_policy(
        &mut self,
        policy: iteron_verify::VerificationRuntimePolicy,
    ) -> Result<(), KernelError> {
        policy.validate().map_err(|error| {
            KernelError::ContextResolution(format!("resolved verification policy refused: {error}"))
        })?;
        self.policy = policy;
        Ok(())
    }
    pub(super) fn prune_quarantine(&mut self, now: u64) {
        self.quarantine.retain(|_, expires| *expires > now);
    }
    pub(super) fn quarantined_until(&self, digest: &str) -> Option<u64> {
        self.quarantine.get(digest).copied()
    }
    /// Called only after the actual Quarantined receipt has crossed the writer barrier.
    pub(super) fn publish_quarantine(
        &mut self,
        digests: &[String],
        expires: u64,
    ) -> Result<(), KernelError> {
        // The receipt is already durable. Any refusal must force a fresh validated fold rather
        // than leaving a stale live map that would allow contradictory evidence to rerun.
        self.quarantine_restored = false;
        if digests.len() > iteron_verify::MAX_VERIFICATION_COMMANDS
            || digests.iter().any(|digest| !is_sha256_digest(digest))
        {
            return Err(KernelError::ContextResolution(
                "verification quarantine publication exceeds its closed receipt bound".into(),
            ));
        }
        let missing = digests
            .iter()
            .filter(|digest| !self.quarantine.contains_key(*digest))
            .count();
        if self.quarantine.len().saturating_add(missing) > iteron_verify::MAX_VERIFICATION_COMMANDS
        {
            return Err(KernelError::ContextResolution(
                "verification quarantine exceeds its retained command bound".into(),
            ));
        }
        for digest in digests {
            self.quarantine.insert(digest.clone(), expires);
        }
        self.quarantine_restored = true;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn policy_for_test_mut(&mut self) -> &mut iteron_verify::VerificationRuntimePolicy {
        &mut self.policy
    }
    #[cfg(test)]
    pub(super) fn set_attempts_for_test(&mut self, attempts: u32) {
        self.attempts = attempts;
    }
    pub(super) fn set_policy(
        &mut self,
        policy: iteron_verify::VerificationRuntimePolicy,
        operator_command: Option<&str>,
    ) -> Result<(), KernelError> {
        policy.validate().map_err(|error| {
            KernelError::ContextResolution(format!("verification policy refused: {error}"))
        })?;
        match operator_command {
            Some(full) if policy.required_commands.last().map(String::as_str) != Some(full) => {
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
        self.policy = policy;
        self.quarantine.clear();
        self.quarantine_restored = false;
        Ok(())
    }
    pub(super) fn adopt(&mut self) {
        self.attempts = 0;
        self.quarantine.clear();
        self.quarantine_restored = false;
        self.rollback_point = None;
    }
    pub(super) fn restore_quarantine(&mut self, rollout: &Rollout) -> Result<(), KernelError> {
        if self.quarantine_restored {
            return Ok(());
        }
        let now = super::provider_accounting::unix_now_secs();
        let mut restored = BTreeMap::<String, u64>::new();
        for timed in iteron_record::replay_timed(rollout.path())? {
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
                if !restored.contains_key(&digest)
                    && restored.len() >= iteron_verify::MAX_VERIFICATION_COMMANDS
                {
                    return Err(KernelError::ContextResolution(
                        "durable verification quarantine exceeds its retained command bound".into(),
                    ));
                }
                restored
                    .entry(digest)
                    .and_modify(|deadline| *deadline = (*deadline).max(expires_at_unix_secs))
                    .or_insert(expires_at_unix_secs);
            }
        }
        self.quarantine = restored;
        self.quarantine_restored = true;
        Ok(())
    }
}
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte,b'0'..=b'9'|b'a'..=b'f'))
}
