//! Bounded ephemeral two-human authorization owner. Restart/adoption creates a fresh owner;
//! historical approval receipts cannot reinstall permission or recover transient approvals.
use super::journal::HighAssuranceJournal;
use super::types::{
    CONTRACT_VERSION, HighAssurancePolicy, HighAssuranceScope, HighAssuranceViewV1,
    HumanApprovalChallengeV1, MAX_PENDING, SignedHumanApprovalV1, fixed_hex, frame, identifier,
};
use ed25519_dalek::Signature;
use iteron_protocol::high_assurance::{
    EnrolledHumanEvidenceV1, HighAssuranceAuthorizationV1, HighAssuranceProfileEvidenceV1,
    HumanSignatureProofV1,
};
use iteron_protocol::{
    Capability, EffectId, Event, EventKind, ToolUse, TurnId, capability_set::CapabilitySet,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Pending {
    challenge: HumanApprovalChallengeV1,
    signers: BTreeMap<String, HumanSignatureProofV1>,
    monotonic_expires: Instant,
}
#[derive(Default)]
struct State {
    pending: BTreeMap<String, Pending>,
    approved: u64,
    authorized: u64,
    refused: u64,
    verification_us: u64,
    verifier_admissions: u32,
    verifier_terminal_observations: u32,
    verifier_wall_ms: u64,
    verifier_timing_unknown: bool,
    verifiers: BTreeMap<EffectId, bool>,
}
pub(crate) struct HighAssuranceOwner {
    policy: Arc<HighAssurancePolicy>,
    scope: HighAssuranceScope,
    scope_digest: String,
    state: Mutex<State>,
}
#[derive(Debug, Serialize)]
pub(crate) enum HighAssuranceAdmission {
    UnrestrictedRead,
    Authorized {
        audit_seq: u64,
    },
    Pending {
        challenge: HumanApprovalChallengeV1,
        authenticated_humans: u32,
    },
}
impl HighAssuranceOwner {
    pub(crate) fn from_host(
        policy: Arc<HighAssurancePolicy>,
        scope: HighAssuranceScope,
    ) -> Arc<Self> {
        let scope_digest = scope.commitment();
        Arc::new(Self {
            policy,
            scope,
            scope_digest,
            state: Mutex::new(State::default()),
        })
    }
    pub(crate) fn profile_evidence(&self) -> HighAssuranceProfileEvidenceV1 {
        let configuration = &self.policy.configuration;
        HighAssuranceProfileEvidenceV1 {
            version: CONTRACT_VERSION,
            policy_sha256: self.policy.digest.clone(),
            scope_sha256: self.scope_digest.clone(),
            profile_display: configuration.profile_id.clone(),
            enrolled_humans: self
                .policy
                .humans
                .iter()
                .map(|(subject, key)| EnrolledHumanEvidenceV1 {
                    subject_sha256: hex::encode(Sha256::digest(subject.as_bytes())),
                    subject_display: subject.clone(),
                    public_key_hex: hex::encode(key.as_bytes()),
                })
                .collect(),
            configured_max_cost_microusd: configuration.max_cost_microusd,
            verifier_command_sha256: configuration
                .verifier_commands
                .iter()
                .map(|command| hex::encode(Sha256::digest(command.as_bytes())))
                .collect(),
            verifier_timeout_secs: configuration.verifier_timeout_secs,
            max_verifier_runs: configuration.max_verifier_runs,
        }
    }
    pub(crate) fn policy(&self) -> &Arc<HighAssurancePolicy> {
        &self.policy
    }
    pub(crate) fn in_scope(&self, scope: &HighAssuranceScope) -> bool {
        &self.scope == scope
    }
    pub(crate) fn approve(
        &self,
        approval: SignedHumanApprovalV1,
        now: u64,
    ) -> Result<(), &'static str> {
        if now == 0
            || approval.version != CONTRACT_VERSION
            || !identifier(&approval.subject)
            || approval.challenge.expires_at_unix_secs <= now
        {
            return Err("human_approval_bounds_or_expired");
        }
        let key = self
            .policy
            .humans
            .get(&approval.subject)
            .ok_or("human_not_enrolled")?;
        let signature = Signature::from_bytes(
            &fixed_hex::<64>(&approval.signature_hex).ok_or("human_approval_signature_shape")?,
        );
        let bytes = approval.challenge.signing_bytes()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        trim(&mut state, now);
        let pending = state
            .pending
            .get(&approval.challenge.operation_sha256)
            .ok_or("human_approval_not_pending")?;
        if pending.challenge != approval.challenge {
            return Err("human_approval_scope_or_challenge_mismatch");
        }
        // An authenticated subject is counted once. Different clients replaying one signed
        // envelope cannot provide another human or extend the challenge lifetime.
        if pending.signers.contains_key(&approval.subject) {
            return Ok(());
        }
        let started = Instant::now();
        let verified = key.verify_strict(&bytes, &signature);
        state.verification_us = state
            .verification_us
            .saturating_add(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX));
        verified.map_err(|_| "human_approval_signature_invalid")?;
        let subject_sha256 = hex::encode(Sha256::digest(approval.subject.as_bytes()));
        let proof = HumanSignatureProofV1 {
            proof_sha256: HumanSignatureProofV1::commitment(
                &subject_sha256,
                key.as_bytes(),
                &signature.to_bytes(),
            ),
            subject_sha256,
            subject_display: approval.subject.clone(),
            public_key_hex: hex::encode(key.as_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        state
            .pending
            .get_mut(&approval.challenge.operation_sha256)
            .expect("same locked pending challenge")
            .signers
            .insert(approval.subject, proof);
        state.approved = state.approved.saturating_add(1);
        Ok(())
    }
    pub(crate) fn authorize(
        &self,
        call: &ToolUse,
        required: CapabilitySet,
        turn: TurnId,
        now: u64,
        journal: &mut HighAssuranceJournal<'_>,
    ) -> Result<HighAssuranceAdmission, &'static str> {
        if required.is_empty() {
            return Err("high_assurance_missing_operation_authority");
        }
        if !required
            .iter()
            .any(|capability| capability != Capability::ReadOnly)
        {
            return Ok(HighAssuranceAdmission::UnrestrictedRead);
        }
        // The caller passes actual operation-specific classes after normal authority checks.
        // This extra gate only narrows an already permitted operation; it never grants classes.
        if now == 0 {
            return Err("high_assurance_clock_unavailable");
        }
        let operation = operation_digest(call, required)?;
        if !journal.in_scope(&self.scope) {
            return Err("high_assurance_journal_scope_mismatch");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        trim(&mut state, now);
        if !state.pending.contains_key(&operation) {
            if state.pending.len() >= MAX_PENDING {
                return Err("high_assurance_pending_capacity");
            }
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_| "high_assurance_nonce_unavailable")?;
            let challenge = HumanApprovalChallengeV1 {
                version: CONTRACT_VERSION,
                challenge_id: hex::encode(Sha256::digest(nonce)),
                policy_sha256: self.policy.digest.clone(),
                scope_sha256: self.scope_digest.clone(),
                operation_sha256: operation.clone(),
                expires_at_unix_secs: now
                    .checked_add(u64::from(self.policy.configuration.approval_ttl_secs))
                    .ok_or("high_assurance_deadline_overflow")?,
            };
            state.pending.insert(
                operation.clone(),
                Pending {
                    challenge,
                    signers: BTreeMap::new(),
                    monotonic_expires: Instant::now()
                        + Duration::from_secs(u64::from(
                            self.policy.configuration.approval_ttl_secs,
                        )),
                },
            );
        }
        let pending = state
            .pending
            .get(&operation)
            .expect("created in same owner lock");
        if pending.signers.len() < 2 {
            let answer = HighAssuranceAdmission::Pending {
                challenge: pending.challenge.clone(),
                authenticated_humans: pending.signers.len() as u32,
            };
            state.refused = state.refused.saturating_add(1);
            return Ok(answer);
        }
        let signers: Vec<_> = pending.signers.values().take(2).cloned().collect();
        let evidence = HighAssuranceAuthorizationV1 {
            version: CONTRACT_VERSION,
            challenge: pending.challenge.clone(),
            authorized_at_unix_secs: now,
            signers,
            signature_verification_us: state.verification_us,
        };
        self.profile_evidence().authenticates(&evidence)?;
        let seq = journal
            .authorized(turn, evidence)
            .map_err(|_| "high_assurance_authorization_record_unavailable")?;
        // Consume only after the real audit barrier. Keeping the owner lock through that sync
        // prevents concurrent retries from spending the same two signed approvals twice.
        state.pending.remove(&operation);
        state.authorized = state.authorized.saturating_add(1);
        Ok(HighAssuranceAdmission::Authorized { audit_seq: seq.0 })
    }
    pub(crate) fn view(&self, now: u64) -> Result<HighAssuranceViewV1, &'static str> {
        let state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        let configuration = &self.policy.configuration;
        Ok(HighAssuranceViewV1 {
            version: CONTRACT_VERSION,
            profile_id: configuration.profile_id.clone(),
            policy_sha256: self.policy.digest.clone(),
            scope_sha256: self.scope_digest.clone(),
            required_humans: 2,
            pending: state
                .pending
                .values()
                .filter(|pending| {
                    pending.challenge.expires_at_unix_secs > now
                        && Instant::now() < pending.monotonic_expires
                })
                .map(|pending| pending.challenge.clone())
                .collect(),
            volatile_approvals: state.approved,
            authorized_operations: state.authorized,
            refused_operations: state.refused,
            signature_verification_us: state.verification_us,
            configured_max_cost_microusd: configuration.max_cost_microusd,
            extra_verifier_commands: configuration.verifier_commands.len() as u32,
            verifier_timeout_secs: configuration.verifier_timeout_secs,
            max_verifier_runs: configuration.max_verifier_runs,
            verifier_admissions: state.verifier_admissions,
            verifier_terminal_observations: state.verifier_terminal_observations,
            verifier_wall_ms: (!state.verifier_timing_unknown).then_some(state.verifier_wall_ms),
        })
    }
    /// Called only at the real extra-verifier admission boundary. Admissions remain consumed on
    /// failure/cancellation, so no unknown subprocess can obtain a replacement budget slot.
    pub(crate) fn preflight_verifier_capacity(&self) -> Result<(), &'static str> {
        let state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        if state.verifier_admissions >= self.policy.configuration.max_verifier_runs {
            return Err("high_assurance_verifier_ceiling");
        }
        Ok(())
    }
    pub(crate) fn admit_verifier(
        &self,
        ticket: &iteron_kernel::effects::EffectTicket,
    ) -> Result<(), &'static str> {
        if ticket.verification_profile_identity()
            != Some((self.policy.digest.as_str(), self.scope_digest.as_str()))
        {
            return Err("high_assurance_verifier_intent_scope_mismatch");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        if state.verifier_admissions >= self.policy.configuration.max_verifier_runs {
            return Err("high_assurance_verifier_ceiling");
        }
        if state.verifiers.contains_key(ticket.effect_id()) {
            return Err("high_assurance_duplicate_verifier_intent");
        }
        state.verifiers.insert(ticket.effect_id().clone(), false);
        state.verifier_admissions += 1;
        Ok(())
    }
    /// Actual producer observation only. It reports completed supervised time and never labels
    /// an oracle as passing merely because the effect is known or the process exited.
    pub(crate) fn observe_verifier_terminal(
        &self,
        effect: &EffectId,
        elapsed_ms: Option<u64>,
    ) -> Result<(), &'static str> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        let Some(observed) = state.verifiers.get_mut(effect) else {
            return Err("high_assurance_verifier_terminal_without_admission");
        };
        if *observed {
            return Err("high_assurance_duplicate_verifier_terminal");
        }
        *observed = true;
        state.verifier_terminal_observations += 1;
        if let Some(elapsed_ms) = elapsed_ms {
            state.verifier_wall_ms = state.verifier_wall_ms.saturating_add(elapsed_ms);
        } else {
            state.verifier_timing_unknown = true;
        }
        Ok(())
    }
    /// Once per authenticated physical-run recovery. Count real Verify intents conservatively,
    /// including unknown/cancelled attempts; historical terminals are never reconstructed as pass.
    pub(crate) fn recover_verified_verifiers(&self, events: &[Event]) -> Result<(), &'static str> {
        let mut recovered = BTreeMap::new();
        for event in events {
            match &event.kind {
                EventKind::EffectIntent {
                    id,
                    tool,
                    arguments,
                    ..
                } if tool == "verify"
                    && arguments
                        .get("high_assurance_policy_sha256")
                        .and_then(serde_json::Value::as_str)
                        == Some(self.policy.digest.as_str())
                    && arguments
                        .get("high_assurance_scope_sha256")
                        .and_then(serde_json::Value::as_str)
                        == Some(self.scope_digest.as_str()) =>
                {
                    if recovered.contains_key(id) {
                        return Err("high_assurance_duplicate_verify_record");
                    }
                    if recovered.len() >= self.policy.configuration.max_verifier_runs as usize {
                        return Err("high_assurance_recovered_verifier_ceiling");
                    }
                    recovered.insert(id.clone(), false);
                }
                EventKind::EffectDone { id, tool, .. }
                | EventKind::EffectFailed { id, tool, .. }
                    if recovered.contains_key(id) =>
                {
                    if tool != "verify" {
                        return Err("high_assurance_unmatched_verify_terminal");
                    }
                    let observed = recovered.get_mut(id).expect("actual scoped intent");
                    if *observed {
                        return Err("high_assurance_duplicate_verify_terminal");
                    }
                    *observed = true;
                }
                _ => {}
            }
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "high_assurance_owner_unavailable")?;
        if !state.verifiers.is_empty() {
            return Err("high_assurance_verifier_recovery_not_fresh");
        }
        state.verifier_admissions = recovered.len() as u32;
        state.verifier_terminal_observations =
            recovered.values().filter(|observed| **observed).count() as u32;
        state.verifiers = recovered;
        // This projection authenticates terminal identities, not measured process timing.
        state.verifier_timing_unknown = !state.verifiers.is_empty();
        Ok(())
    }
}
fn trim(state: &mut State, now: u64) {
    state.pending.retain(|_, pending| {
        pending.challenge.expires_at_unix_secs > now && Instant::now() < pending.monotonic_expires
    });
}
fn operation_digest(call: &ToolUse, required: CapabilitySet) -> Result<String, &'static str> {
    if call.name.is_empty() || call.name.len() > 128 {
        return Err("high_assurance_tool_bounds");
    }
    let arguments =
        serde_json::to_vec(&call.input).map_err(|_| "high_assurance_operation_encoding")?;
    if arguments.len() > iteron_protocol::effect::MAX_EFFECT_ARGUMENTS_BYTES {
        return Err("high_assurance_operation_bounds");
    }
    let mut digest = Sha256::new();
    digest.update(b"iteron.high-assurance-operation.v1\0");
    frame(&mut digest, call.name.as_bytes());
    frame(&mut digest, &arguments);
    for capability in required.iter() {
        frame(&mut digest, format!("{capability:?}").as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}
