//! Validation and projection for the immutable run-genesis policy checkpoint.

use core_protocol::{
    Event, EventKind, PolicyBundleCoverage, PolicySlotApplicationStatus,
    RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION, RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT,
    RunGenesisPolicyBundleSnapshot, RunGenesisPolicyBundleVersion,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SLOT_NAMES: [&str; RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT] = [
    "core/context",
    "core/tool_policy",
    "core/memory",
    "core/router",
    "core/planner",
    "core/collaboration",
    "core/scheduler",
    "core/verifier",
    "core/model_router",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyBundleCheckpointError {
    #[error("invalid policy-bundle checkpoint: {0}")]
    Invalid(&'static str),
    #[error("invalid policy-bundle genesis placement: {0}")]
    GenesisOrder(&'static str),
}

#[derive(Serialize)]
struct DigestPayload<'a> {
    version: RunGenesisPolicyBundleVersion,
    canonicalization: &'a str,
    bundle_id: &'a str,
    bundle_digest_sha256: &'a str,
    coverage: PolicyBundleCoverage,
    slots: &'a [core_protocol::RunGenesisPolicySlotBinding],
}

pub fn seal_policy_bundle_snapshot(
    mut snapshot: RunGenesisPolicyBundleSnapshot,
) -> Result<RunGenesisPolicyBundleSnapshot, PolicyBundleCheckpointError> {
    snapshot.receipt_digest_sha256 = digest(&snapshot)?;
    validate_policy_bundle_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub fn validate_policy_bundle_snapshot(
    snapshot: &RunGenesisPolicyBundleSnapshot,
) -> Result<(), PolicyBundleCheckpointError> {
    if snapshot.version != RunGenesisPolicyBundleVersion::V1 {
        return invalid("unsupported version");
    }
    if snapshot.canonicalization != RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION {
        return invalid("unknown canonicalization");
    }
    if snapshot.slots.len() != RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT {
        return invalid("checkpoint must contain exactly nine slots");
    }
    if !is_digest(&snapshot.bundle_digest_sha256) || !is_digest(&snapshot.receipt_digest_sha256) {
        return invalid("checkpoint digest is malformed");
    }

    let mut requested = 0_usize;
    for (index, (row, expected_slot)) in snapshot.slots.iter().zip(SLOT_NAMES).enumerate() {
        if usize::from(row.ordinal) != index + 1
            || row.slot.as_persisted_str() != expected_slot
            || row.slot.validate().is_err()
        {
            return invalid("slot order or identity is invalid");
        }
        if row.implementation.is_empty()
            || row.implementation.len() > core_protocol::MAX_POLICY_IMPLEMENTATION_ID_BYTES
            || row.implementation.chars().any(char::is_control)
        {
            return invalid("implementation identity is invalid");
        }
        row.policy
            .validate()
            .map_err(|_| PolicyBundleCheckpointError::Invalid("policy identity is invalid"))?;
        if row.policy.bundle_id != snapshot.bundle_id
            || row.policy.bundle_digest_sha256 != snapshot.bundle_digest_sha256
        {
            return invalid("slot and checkpoint bundle identities differ");
        }
        if row.requested {
            requested += 1;
        }
        match row.status {
            PolicySlotApplicationStatus::Applied if !row.requested => {
                return invalid("an applied slot must have been requested");
            }
            PolicySlotApplicationStatus::Applied | PolicySlotApplicationStatus::Baseline => {}
        }
    }
    let coverage_is_exact = match snapshot.coverage {
        PolicyBundleCoverage::Baseline => requested == 0,
        PolicyBundleCoverage::Partial => {
            (1..RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT).contains(&requested)
        }
        PolicyBundleCoverage::Full => requested == RUN_GENESIS_POLICY_BUNDLE_SLOT_COUNT,
    };
    if !coverage_is_exact {
        return invalid("coverage does not match requested slots");
    }
    if digest(snapshot)? != snapshot.receipt_digest_sha256 {
        return invalid("receipt digest mismatch");
    }
    Ok(())
}

/// Read the unique physical-sequence-two checkpoint. Logical fork expansion is intentionally not
/// accepted here: a child must carry its own independently verifiable genesis copy.
pub fn policy_bundle_checkpoint_from_events(
    events: &[Event],
) -> Result<Option<RunGenesisPolicyBundleSnapshot>, PolicyBundleCheckpointError> {
    let mut found = None;
    for event in events {
        let EventKind::PolicyBundleSnapshot { snapshot, .. } = &event.kind else {
            continue;
        };
        if event.seq.0 != 2 {
            return Err(PolicyBundleCheckpointError::GenesisOrder(
                "policy checkpoint must be physical sequence two",
            ));
        }
        if found.is_some() {
            return Err(PolicyBundleCheckpointError::GenesisOrder(
                "policy checkpoint must be unique",
            ));
        }
        validate_policy_bundle_snapshot(snapshot)?;
        found = Some(snapshot.clone());
    }
    if found.is_some()
        && (!matches!(
            events.first().map(|event| &event.kind),
            Some(EventKind::RunStart { .. })
        ) || !matches!(
            events.get(1).map(|event| &event.kind),
            Some(EventKind::TunablesSnapshot { .. } | EventKind::TunablesSnapshotV2 { .. })
        ))
    {
        return Err(PolicyBundleCheckpointError::GenesisOrder(
            "policy checkpoint must follow run_start and tunables checkpoint",
        ));
    }
    Ok(found)
}

fn digest(
    snapshot: &RunGenesisPolicyBundleSnapshot,
) -> Result<String, PolicyBundleCheckpointError> {
    let payload = DigestPayload {
        version: snapshot.version,
        canonicalization: &snapshot.canonicalization,
        bundle_id: &snapshot.bundle_id,
        bundle_digest_sha256: &snapshot.bundle_digest_sha256,
        coverage: snapshot.coverage,
        slots: &snapshot.slots,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|_| PolicyBundleCheckpointError::Invalid("checkpoint is not serializable"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid<T>(reason: &'static str) -> Result<T, PolicyBundleCheckpointError> {
    Err(PolicyBundleCheckpointError::Invalid(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{
        PolicyRuntimeIdentity, RunGenesisPolicySlotBinding, Seq, TurnId, slot::SlotId,
    };

    fn fixture() -> RunGenesisPolicyBundleSnapshot {
        let bundle_id = "core-baseline-v1".to_owned();
        let bundle_digest = "a".repeat(64);
        seal_policy_bundle_snapshot(RunGenesisPolicyBundleSnapshot {
            version: RunGenesisPolicyBundleVersion::V1,
            canonicalization: RUN_GENESIS_POLICY_BUNDLE_CANONICALIZATION.to_owned(),
            bundle_id: bundle_id.clone(),
            bundle_digest_sha256: bundle_digest.clone(),
            coverage: PolicyBundleCoverage::Baseline,
            slots: SLOT_NAMES
                .iter()
                .enumerate()
                .map(|(index, slot)| RunGenesisPolicySlotBinding {
                    ordinal: u8::try_from(index + 1).unwrap(),
                    slot: SlotId((*slot).to_owned()),
                    requested: false,
                    status: PolicySlotApplicationStatus::Baseline,
                    implementation: format!("{slot}/baseline"),
                    policy: PolicyRuntimeIdentity {
                        bundle_id: bundle_id.clone(),
                        bundle_digest_sha256: bundle_digest.clone(),
                        policy_id: "baseline".into(),
                        policy_version: "1".into(),
                        policy_digest_sha256: format!("{index:064x}"),
                    },
                })
                .collect(),
            receipt_digest_sha256: String::new(),
        })
        .unwrap()
    }

    fn checkpoint_event(seq: u64, snapshot: RunGenesisPolicyBundleSnapshot) -> Event {
        Event {
            seq: Seq(seq),
            turn: TurnId(0),
            kind: EventKind::PolicyBundleSnapshot {
                version: RunGenesisPolicyBundleVersion::V1,
                snapshot,
                inherited_from: None,
            },
        }
    }

    #[test]
    fn sealed_checkpoint_detects_any_identity_tampering() {
        let snapshot = fixture();
        validate_policy_bundle_snapshot(&snapshot).unwrap();

        let mut changed = snapshot;
        changed.slots[0].policy.policy_version = "future".into();
        assert_eq!(
            validate_policy_bundle_snapshot(&changed),
            Err(PolicyBundleCheckpointError::Invalid(
                "receipt digest mismatch"
            ))
        );
    }

    #[test]
    fn checkpoint_projection_refuses_wrong_sequence_and_duplicates() {
        let snapshot = fixture();
        assert!(matches!(
            policy_bundle_checkpoint_from_events(&[checkpoint_event(1, snapshot.clone())]),
            Err(PolicyBundleCheckpointError::GenesisOrder(_))
        ));
        assert!(matches!(
            policy_bundle_checkpoint_from_events(&[
                checkpoint_event(2, snapshot.clone()),
                checkpoint_event(2, snapshot),
            ]),
            Err(PolicyBundleCheckpointError::GenesisOrder(_))
        ));
    }
}
