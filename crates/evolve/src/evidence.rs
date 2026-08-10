//! Content binding at the evolution evidence-recording boundary.
//!
//! Persisted evolution contracts remain untrusted assertions. `EvidenceRecorder` is the explicit
//! boundary a future trusted capture path can call while it still has the action bytes: recording
//! overwrites any caller-supplied digest, while verification recomputes it from the bounded,
//! canonical action encoding.

use crate::{
    ContractError, MAX_ACTION_JSON_BYTES, MAX_DECISIONS_PER_TRAJECTORY, PolicyBundle,
    StrategyDecision, TrajectoryEnvelope, validate_action_json, validate_collection,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum EvidenceRecordError {
    #[error("evolution evidence contract is invalid: {0}")]
    InvalidContract(#[from] ContractError),
    #[error("canonical action JSON could not be encoded: {0}")]
    CanonicalActionEncoding(#[source] serde_json::Error),
    #[error("recorded action digest does not match canonical action bytes")]
    ActionDigestMismatch { expected: String, found: String },
}

/// Stateless action-binding boundary for trajectory evidence.
///
/// This type does not make the surrounding evolution crate authoritative. A future evolution TCB
/// must own the recorder instance and call it at capture/ingest time. In particular, deserializing
/// a [`StrategyDecision`] and calling its structural `validate` method is not evidence that its
/// self-reported digest matches its action.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvidenceRecorder;

impl EvidenceRecorder {
    pub const fn new() -> Self {
        Self
    }

    /// Append one decision after deriving its digest from canonical action bytes.
    ///
    /// The supplied `action_digest` is deliberately ignored and replaced. Existing decisions are
    /// verified first, so the recorder never extends a trajectory whose action evidence has
    /// already been altered. The envelope is unchanged on error.
    pub fn record_decision<'a>(
        &self,
        envelope: &'a mut TrajectoryEnvelope,
        mut decision: StrategyDecision,
    ) -> Result<&'a StrategyDecision, EvidenceRecordError> {
        self.verify_trajectory(envelope)?;
        validate_collection(
            "trajectory.decisions",
            envelope.decisions.len().saturating_add(1),
            MAX_DECISIONS_PER_TRAJECTORY,
        )?;

        decision.action_digest = canonical_action_digest(&decision.action)?;
        decision.validate(&envelope.bundle)?;

        let recorded_index = envelope.decisions.len();
        envelope.decisions.push(decision);
        Ok(&envelope.decisions[recorded_index])
    }

    /// Recompute and verify one previously recorded decision's canonical action binding.
    pub fn verify_decision(
        &self,
        bundle: &PolicyBundle,
        decision: &StrategyDecision,
    ) -> Result<(), EvidenceRecordError> {
        decision.validate(bundle)?;
        let expected = canonical_action_digest(&decision.action)?;
        if digest_matches(&expected, &decision.action_digest) {
            Ok(())
        } else {
            Err(EvidenceRecordError::ActionDigestMismatch {
                expected,
                found: decision.action_digest.clone(),
            })
        }
    }

    /// Validate an offline trajectory contract and independently verify every action binding.
    pub fn verify_trajectory(
        &self,
        envelope: &TrajectoryEnvelope,
    ) -> Result<(), EvidenceRecordError> {
        envelope.validate()?;
        for decision in &envelope.decisions {
            self.verify_decision(&envelope.bundle, decision)?;
        }
        Ok(())
    }
}

fn canonical_action_digest(action: &Value) -> Result<String, EvidenceRecordError> {
    let bytes = canonical_action_bytes(action)?;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

/// Canonical action JSON v1 is compact JSON with object keys sorted by their UTF-8 bytes and
/// serde_json's deterministic scalar representation. The structural pass runs first, bounding
/// recursion, node count, allocation, and output bytes before encoding begins.
fn canonical_action_bytes(action: &Value) -> Result<Vec<u8>, EvidenceRecordError> {
    validate_action_json(action)?;
    let mut output = Vec::new();
    write_canonical_action(action, &mut output)?;
    if output.len() > MAX_ACTION_JSON_BYTES {
        return Err(ContractError::ActionJsonTooLarge {
            limit: MAX_ACTION_JSON_BYTES,
        }
        .into());
    }
    Ok(output)
}

fn write_canonical_action(value: &Value, output: &mut Vec<u8>) -> Result<(), EvidenceRecordError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => serde_json::to_writer(output, number)
            .map_err(EvidenceRecordError::CanonicalActionEncoding)?,
        Value::String(string) => serde_json::to_writer(output, string)
            .map_err(EvidenceRecordError::CanonicalActionEncoding)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_action(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(EvidenceRecordError::CanonicalActionEncoding)?;
                output.push(b':');
                write_canonical_action(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn digest_matches(expected: &str, found: &str) -> bool {
    expected.len() == found.len()
        && expected
            .bytes()
            .zip(found.bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DataClass, DataGovernance, EVOLUTION_SCHEMA_VERSION, PolicyRef, RewardVector, StrategySlot,
        TrainingConsent,
    };
    use iteron_protocol::{RunId, TenantId};
    use serde_json::json;
    use std::collections::BTreeMap;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy() -> PolicyRef {
        PolicyRef {
            slot: StrategySlot::router(),
            policy_id: "router-a".into(),
            version: "1.0.0".into(),
            digest: D.into(),
        }
    }

    fn envelope() -> TrajectoryEnvelope {
        TrajectoryEnvelope {
            schema_version: EVOLUTION_SCHEMA_VERSION,
            run_id: RunId("run-action-binding".into()),
            tenant_id: TenantId::default(),
            task_id: "task-action-binding".into(),
            domain: "coding".into(),
            environment_digest: D.into(),
            bundle: PolicyBundle {
                bundle_id: "bundle-a".into(),
                digest: D.into(),
                policies: vec![policy()],
                rollback_to: None,
            },
            decisions: Vec::new(),
            terminal_outcome: "completed".into(),
            reward: RewardVector {
                task_score: 1.0,
                correctness: 1.0,
                safety_violations: 0,
                policy_violations: 0,
                cost_usd: 0.01,
                wall_time_ms: 10,
                human_acceptance: None,
                domain: BTreeMap::new(),
            },
            governance: DataGovernance {
                class: DataClass::Public,
                consent: TrainingConsent::Allowed,
                content_license: Some("apache-2.0".into()),
                contains_secret_material: false,
                retention_policy: "training-v1".into(),
            },
        }
    }

    fn decision(action: Value) -> StrategyDecision {
        StrategyDecision {
            decision_id: "decision-a".into(),
            ordinal: 0,
            policy: policy(),
            observation_digest: D.into(),
            candidate_set_digest: D.into(),
            action,
            action_digest: D.into(),
            propensity: Some(1.0),
        }
    }

    #[test]
    fn recorder_overwrites_self_reported_digest_with_canonical_action_sha256() {
        let action: Value = serde_json::from_str(r#"{"b":[true,null],"a":1}"#).unwrap();
        assert_eq!(
            canonical_action_bytes(&action).unwrap(),
            br#"{"a":1,"b":[true,null]}"#
        );

        let mut envelope = envelope();
        let recorded = EvidenceRecorder::new()
            .record_decision(&mut envelope, decision(action))
            .unwrap();
        assert_eq!(
            recorded.action_digest,
            "1cc69c7fa23616ca2ec3ee70d24390a6225c8832db8a4c814c7e0e7f942f8668"
        );
        assert_ne!(recorded.action_digest, D);
        EvidenceRecorder::new()
            .verify_trajectory(&envelope)
            .unwrap();
    }

    #[test]
    fn tampered_action_with_retained_digest_passes_contract_but_fails_recording_boundary() {
        let recorder = EvidenceRecorder::new();
        let mut envelope = envelope();
        recorder
            .record_decision(&mut envelope, decision(json!({"tool": "read"})))
            .unwrap();

        envelope.decisions[0].action = json!({"tool": "write"});
        assert!(
            envelope.validate().is_ok(),
            "contract validation is structural only"
        );
        assert!(matches!(
            recorder.verify_trajectory(&envelope),
            Err(EvidenceRecordError::ActionDigestMismatch { .. })
        ));

        let before = envelope.decisions.len();
        assert!(matches!(
            recorder.record_decision(&mut envelope, decision(Value::Null)),
            Err(EvidenceRecordError::ActionDigestMismatch { .. })
        ));
        assert_eq!(
            envelope.decisions.len(),
            before,
            "failed recording is atomic"
        );
    }

    #[test]
    fn recorder_bounds_action_before_canonical_encoding() {
        let mut envelope = envelope();
        let oversized = decision(Value::String("x".repeat(MAX_ACTION_JSON_BYTES + 1)));
        assert!(matches!(
            EvidenceRecorder::new().record_decision(&mut envelope, oversized),
            Err(EvidenceRecordError::InvalidContract(
                ContractError::ActionJsonTooLarge { .. }
            ))
        ));
        assert!(envelope.decisions.is_empty());
    }
}
