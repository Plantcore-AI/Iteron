//! Closed public high-assurance proof vocabulary. Signatures/public keys are evidence, never
//! credentials or a replayed permission grant. Display labels are independently scrubbed.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HumanApprovalChallengeV1 {
    pub version: u32,
    pub challenge_id: String,
    pub policy_sha256: String,
    pub scope_sha256: String,
    pub operation_sha256: String,
    pub expires_at_unix_secs: u64,
}
impl HumanApprovalChallengeV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, &'static str> {
        if self.version != 1
            || [
                &self.challenge_id,
                &self.policy_sha256,
                &self.scope_sha256,
                &self.operation_sha256,
            ]
            .iter()
            .any(|value| fixed_hex::<32>(value).is_none())
            || self.expires_at_unix_secs == 0
        {
            return Err("human_approval_challenge_bounds");
        }
        let mut bytes = b"iteron.authenticated-human-operation.v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| "human_approval_challenge_encoding")?);
        Ok(bytes)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HumanSignatureProofV1 {
    pub subject_sha256: String,
    pub subject_display: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub proof_sha256: String,
}
impl HumanSignatureProofV1 {
    pub fn commitment(subject_sha256: &str, public_key: &[u8; 32], signature: &[u8; 64]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"iteron.human-signature-proof.v1\0");
        frame(&mut hash, subject_sha256.as_bytes());
        frame(&mut hash, public_key);
        frame(&mut hash, signature);
        format!("{:x}", hash.finalize())
    }
    fn verify(&self, challenge: &HumanApprovalChallengeV1) -> Result<(), &'static str> {
        if fixed_hex::<32>(&self.subject_sha256).is_none()
            || self.subject_display.is_empty()
            || self.subject_display.len() > 512
            || self.subject_display.chars().any(char::is_control)
        {
            return Err("human_signature_subject_bounds");
        }
        let key = fixed_hex::<32>(&self.public_key_hex).ok_or("human_signature_key_bounds")?;
        let signature = fixed_hex::<64>(&self.signature_hex).ok_or("human_signature_bounds")?;
        if self.proof_sha256 != Self::commitment(&self.subject_sha256, &key, &signature) {
            return Err("human_signature_commitment_mismatch");
        }
        let key = VerifyingKey::from_bytes(&key).map_err(|_| "human_signature_key_invalid")?;
        if key.is_weak() {
            return Err("human_signature_key_weak");
        }
        key.verify_strict(
            &challenge.signing_bytes()?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "human_signature_not_verified")
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HighAssuranceAuthorizationV1 {
    pub version: u32,
    pub challenge: HumanApprovalChallengeV1,
    pub authorized_at_unix_secs: u64,
    pub signers: Vec<HumanSignatureProofV1>,
    pub signature_verification_us: u64,
}
impl HighAssuranceAuthorizationV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.signers.len() != 2
            || self.authorized_at_unix_secs == 0
            || self.authorized_at_unix_secs >= self.challenge.expires_at_unix_secs
        {
            return Err("high_assurance_authorization_bounds");
        }
        self.challenge.signing_bytes()?;
        let mut subjects = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for signer in &self.signers {
            signer.verify(&self.challenge)?;
            if !subjects.insert(&signer.subject_sha256) || !keys.insert(&signer.public_key_hex) {
                return Err("high_assurance_signers_not_distinct");
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrolledHumanEvidenceV1 {
    pub subject_sha256: String,
    pub subject_display: String,
    pub public_key_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HighAssuranceProfileEvidenceV1 {
    pub version: u32,
    pub policy_sha256: String,
    pub scope_sha256: String,
    pub profile_display: String,
    pub enrolled_humans: Vec<EnrolledHumanEvidenceV1>,
    pub configured_max_cost_microusd: u64,
    pub verifier_command_sha256: Vec<String>,
    pub verifier_timeout_secs: u32,
    pub max_verifier_runs: u32,
}
impl HighAssuranceProfileEvidenceV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || !(2..=16).contains(&self.enrolled_humans.len())
            || fixed_hex::<32>(&self.policy_sha256).is_none()
            || fixed_hex::<32>(&self.scope_sha256).is_none()
            || self.profile_display.is_empty()
            || self.profile_display.len() > 512
            || self.profile_display.chars().any(char::is_control)
            || self.configured_max_cost_microusd == 0
            || !(1..=2).contains(&self.verifier_command_sha256.len())
            || self
                .verifier_command_sha256
                .iter()
                .any(|digest| fixed_hex::<32>(digest).is_none())
            || !(1..=300).contains(&self.verifier_timeout_secs)
            || !(1..=4).contains(&self.max_verifier_runs)
        {
            return Err("high_assurance_profile_evidence_bounds");
        }
        let mut subjects = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for enrolled in &self.enrolled_humans {
            let key = fixed_hex::<32>(&enrolled.public_key_hex)
                .ok_or("high_assurance_enrollment_key_bounds")?;
            let key = VerifyingKey::from_bytes(&key)
                .map_err(|_| "high_assurance_enrollment_key_invalid")?;
            if key.is_weak()
                || fixed_hex::<32>(&enrolled.subject_sha256).is_none()
                || enrolled.subject_display.is_empty()
                || enrolled.subject_display.len() > 512
                || enrolled.subject_display.chars().any(char::is_control)
                || !subjects.insert(&enrolled.subject_sha256)
                || !keys.insert(&enrolled.public_key_hex)
            {
                return Err("high_assurance_enrollment_evidence_bounds");
            }
        }
        Ok(())
    }
    /// A proof's cryptographic correctness is distinct from enrollment authority. A verified run
    /// must pair it with this actual operator-installed policy/scope roster, never an arbitrary key.
    pub fn authenticates(
        &self,
        authorization: &HighAssuranceAuthorizationV1,
    ) -> Result<(), &'static str> {
        self.validate()?;
        authorization.validate()?;
        if self.policy_sha256 != authorization.challenge.policy_sha256
            || self.scope_sha256 != authorization.challenge.scope_sha256
        {
            return Err("high_assurance_profile_scope_mismatch");
        }
        if authorization.signers.iter().any(|signer| {
            !self.enrolled_humans.iter().any(|enrolled| {
                enrolled.subject_sha256 == signer.subject_sha256
                    && enrolled.public_key_hex == signer.public_key_hex
            })
        }) {
            return Err("high_assurance_signer_not_enrolled");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HighAssuranceAuditV1 {
    Configured {
        evidence: HighAssuranceProfileEvidenceV1,
    },
    Authorized {
        evidence: HighAssuranceAuthorizationV1,
    },
}
impl HighAssuranceAuditV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Configured { evidence } => evidence.validate(),
            Self::Authorized { evidence } => evidence.validate(),
        }
    }
    pub fn scrub_displays(&mut self, scrub: impl Fn(&str) -> String) {
        match self {
            Self::Configured { evidence } => {
                evidence.profile_display = scrub(&evidence.profile_display);
                for human in &mut evidence.enrolled_humans {
                    human.subject_display = scrub(&human.subject_display);
                }
            }
            Self::Authorized { evidence } => {
                for human in &mut evidence.signers {
                    human.subject_display = scrub(&human.subject_display);
                }
            }
        }
    }
}
fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}
fn fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != 2 * N {
        return None;
    }
    let mut output = [0; N];
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    for (out, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *out = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    Some(output)
}
