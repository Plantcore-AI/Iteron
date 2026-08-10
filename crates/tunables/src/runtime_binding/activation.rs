use super::RuntimeResolutionError;
use super::authority::validate_digest;
use super::evidence::evidence_digest;
use crate::{ActivationEvidence, ActivationPredicate, families};
use std::collections::BTreeMap;

pub(super) type EvidenceMap = BTreeMap<String, ActivationEvidence>;

pub(super) fn observe(
    evidence: &mut EvidenceMap,
    family_id: &str,
    seam: &str,
    active: bool,
    subject_digest_sha256: impl Into<String>,
) -> Result<(), RuntimeResolutionError> {
    let family = families()
        .iter()
        .find(|family| family.id == family_id || family.aliases.contains(&family_id))
        .ok_or_else(|| RuntimeResolutionError::UnknownFamily(family_id.to_owned()))?;
    let expected = match family.activation.predicate {
        ActivationPredicate::RuntimeDerived { seam } => seam,
        ActivationPredicate::Always
        | ActivationPredicate::Configured { .. }
        | ActivationPredicate::Unavailable => {
            return Err(RuntimeResolutionError::NonRuntimeActivation(
                family.id.to_owned(),
            ));
        }
    };
    if seam != expected {
        return Err(RuntimeResolutionError::MismatchedActivation {
            family: family.id.to_owned(),
            expected: expected.to_owned(),
            observed: seam.to_owned(),
        });
    }
    if evidence.contains_key(family.id) {
        return Err(RuntimeResolutionError::DuplicateActivation(
            family.id.to_owned(),
        ));
    }

    let subject_digest_sha256 = subject_digest_sha256.into();
    validate_digest("runtime_activation", &subject_digest_sha256)?;
    evidence.insert(
        family.id.to_owned(),
        ActivationEvidence {
            family: family.id.to_owned(),
            seam: expected.to_owned(),
            subject_digest_sha256: subject_digest_sha256.clone(),
            evidence_digest_sha256: evidence_digest(
                "runtime-family-activation-state-v2",
                &(family.id, expected, active, &subject_digest_sha256),
            )?,
            active,
        },
    );
    Ok(())
}

pub(super) fn require_complete(evidence: &EvidenceMap) -> Result<(), RuntimeResolutionError> {
    for family in families() {
        if let ActivationPredicate::RuntimeDerived { seam } = family.activation.predicate
            && !evidence.contains_key(family.id)
        {
            return Err(RuntimeResolutionError::MissingActivation {
                family: family.id.to_owned(),
                seam: seam.to_owned(),
            });
        }
    }
    Ok(())
}
