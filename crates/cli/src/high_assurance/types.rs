//! Explicit operator enrollment and signed operation authorization. No connection ID is an identity.
use ed25519_dalek::VerifyingKey;
use iteron_protocol::{RunId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) const CONTRACT_VERSION: u32 = 1;
pub(crate) const MAX_PENDING: usize = 64;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HumanEnrollmentV1 {
    /// Operator-attested human identity, independent of the requesting client/session.
    pub subject: String,
    pub public_key_hex: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HighAssuranceProfileV1 {
    pub version: u32,
    pub profile_id: String,
    pub humans: Vec<HumanEnrollmentV1>,
    pub approval_ttl_secs: u32,
    pub max_cost_microusd: u64,
    pub verifier_commands: Vec<String>,
    pub verifier_timeout_secs: u32,
    pub max_verifier_runs: u32,
}
pub(crate) struct HighAssurancePolicy {
    pub(super) configuration: HighAssuranceProfileV1,
    pub(super) humans: BTreeMap<String, VerifyingKey>,
    pub(super) digest: String,
}
impl HighAssurancePolicy {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    /// This entry is for a trusted operator configuration reader. Public controls cannot install
    /// or change enrollment. The operator is responsible for attesting distinct human subjects.
    pub(crate) fn from_operator(
        configuration: HighAssuranceProfileV1,
    ) -> Result<Self, &'static str> {
        if configuration.version != CONTRACT_VERSION
            || !identifier(&configuration.profile_id)
            || !(2..=16).contains(&configuration.humans.len())
            || !(1..=300).contains(&configuration.approval_ttl_secs)
            || configuration.max_cost_microusd == 0
            || !(1..=2).contains(&configuration.verifier_commands.len())
            || !(1..=300).contains(&configuration.verifier_timeout_secs)
            || !(1..=4).contains(&configuration.max_verifier_runs)
            || configuration.verifier_commands.iter().any(|command| {
                command.trim().is_empty() || command.len() > 4096 || command.contains('\0')
            })
        {
            return Err("high_assurance_profile_bounds");
        }
        let mut humans = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for human in &configuration.humans {
            if !identifier(&human.subject) {
                return Err("human_enrollment_identity");
            }
            let key = fixed_hex::<32>(&human.public_key_hex).ok_or("human_enrollment_key")?;
            let verifier = VerifyingKey::from_bytes(&key).map_err(|_| "human_enrollment_key")?;
            if verifier.is_weak()
                || !keys.insert(key)
                || humans.insert(human.subject.clone(), verifier).is_some()
            {
                return Err("human_enrollment_duplicate_or_weak");
            }
        }
        // Framed closed policy digest, including ordered enrollment, verifier and actual ceilings.
        let mut digest = Sha256::new();
        digest.update(b"iteron.high-assurance-policy.v1\0");
        for value in [
            &configuration.profile_id,
            &configuration.max_cost_microusd.to_string(),
            &configuration.approval_ttl_secs.to_string(),
            &configuration.verifier_timeout_secs.to_string(),
            &configuration.max_verifier_runs.to_string(),
        ] {
            frame(&mut digest, value.as_bytes());
        }
        for (subject, key) in &humans {
            frame(&mut digest, subject.as_bytes());
            frame(&mut digest, key.as_bytes());
        }
        for command in &configuration.verifier_commands {
            frame(&mut digest, command.as_bytes());
        }
        Ok(Self {
            configuration,
            humans,
            digest: hex::encode(digest.finalize()),
        })
    }
    pub(crate) fn configuration(&self) -> &HighAssuranceProfileV1 {
        &self.configuration
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct HighAssuranceScope {
    pub(super) tenant_id: TenantId,
    pub(super) run_id: RunId,
    pub(super) workspace_sha256: String,
}
impl HighAssuranceScope {
    pub(crate) fn commitment(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"iteron.high-assurance-scope.v1\0");
        frame(&mut hash, self.tenant_id.0.as_bytes());
        frame(&mut hash, self.run_id.0.as_bytes());
        frame(&mut hash, self.workspace_sha256.as_bytes());
        hex::encode(hash.finalize())
    }
    pub(crate) fn from_host(
        tenant: TenantId,
        run: RunId,
        workspace: &Path,
    ) -> Result<Self, &'static str> {
        let workspace = workspace
            .canonicalize()
            .map_err(|_| "high_assurance_workspace_scope")?;
        let path = workspace.to_str().ok_or("high_assurance_workspace_scope")?;
        Ok(Self {
            tenant_id: tenant,
            run_id: run,
            workspace_sha256: hex::encode(Sha256::digest(path.as_bytes())),
        })
    }
}

pub(crate) use iteron_protocol::high_assurance::HumanApprovalChallengeV1;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedHumanApprovalV1 {
    pub version: u32,
    pub subject: String,
    pub challenge: HumanApprovalChallengeV1,
    pub signature_hex: String,
}
impl std::fmt::Debug for SignedHumanApprovalV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedHumanApprovalV1")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HighAssuranceCommandV1 {
    Read,
    Approve { approval: SignedHumanApprovalV1 },
}
impl HighAssuranceCommandV1 {
    pub(crate) fn is_read_only(&self) -> bool {
        matches!(self, Self::Read)
    }
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if let Self::Approve { approval } = self {
            if approval.version != CONTRACT_VERSION
                || !identifier(&approval.subject)
                || fixed_hex::<64>(&approval.signature_hex).is_none()
            {
                return Err("human_approval_input_bounds");
            }
            approval.challenge.signing_bytes()?;
        }
        Ok(())
    }
}
#[derive(Clone, Serialize)]
pub(crate) struct HighAssuranceViewV1 {
    pub version: u32,
    pub profile_id: String,
    pub policy_sha256: String,
    pub scope_sha256: String,
    pub required_humans: u32,
    pub pending: Vec<HumanApprovalChallengeV1>,
    pub volatile_approvals: u64,
    pub authorized_operations: u64,
    pub refused_operations: u64,
    pub signature_verification_us: u64,
    pub configured_max_cost_microusd: u64,
    pub extra_verifier_commands: u32,
    pub verifier_timeout_secs: u32,
    pub max_verifier_runs: u32,
    pub verifier_admissions: u32,
    pub verifier_terminal_observations: u32,
    pub verifier_wall_ms: Option<u64>,
}

pub(super) fn fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}
pub(super) fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}
pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}
