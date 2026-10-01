//! State retained by the configured operator verification gate. No executor or transport owns it.
use super::KernelError;
use iteron_protocol::EventKind;
use iteron_record::{Rollout, Snapshot};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct VerificationStateOwner {
    pub(super) policy: iteron_verify::VerificationRuntimePolicy,
    pub(super) quarantine: BTreeMap<String, u64>,
    pub(super) quarantine_restored: bool,
    pub(super) rollback_point: Option<Snapshot>,
    pub(super) attempts: u32,
}
impl VerificationStateOwner {
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
