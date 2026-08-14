use super::*;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::BTreeSet;

pub fn verify_evidence_bundle(
    directory: &Path,
    trusted_public_key: &str,
) -> Result<VerifiedEvidenceBundle, EvidenceBundleError> {
    let directory_metadata =
        std::fs::symlink_metadata(directory).map_err(|error| io(directory, error))?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(EvidenceBundleError::Artifact {
            path: directory.display().to_string(),
            reason: "evidence bundle must be a regular non-symlink directory".into(),
        });
    }
    let index_path = directory.join("bundle.index.json");
    let index: EvidenceBundleIndex = decode(&read_regular(
        &index_path,
        iteron_tunables::param_integer("eval.evidence_bundle.max_index_bytes", MAX_INDEX_BYTES),
    )?)?;
    if index.schema_version != 1
        || index.bundle_type != "iteron-eval-signed-evidence"
        || index.public_key != trusted_public_key
        || index.comparison.baseline_id == index.comparison.candidate_id
        || index.files.is_empty()
        || index.files.len()
            > iteron_tunables::param_integer(
                "eval.evidence_bundle.max_bundle_files",
                MAX_BUNDLE_FILES,
            )
    {
        return Err(EvidenceBundleError::Signature);
    }
    validate_label(&index.comparison.baseline_id)?;
    validate_label(&index.comparison.candidate_id)?;
    validate_label(&index.comparison.baseline_arm)?;
    validate_label(&index.comparison.candidate_arm)?;
    index.evidence_rows.validate()?;
    verify_index(&index)?;
    verify_file_set(directory, &index)?;

    let baseline_bytes = read_role(directory, &index, "baseline_manifest")?;
    let candidate_bytes = read_role(directory, &index, "candidate_manifest")?;
    let baseline: EvaluationManifest = decode(&baseline_bytes)?;
    let candidate: EvaluationManifest = decode(&candidate_bytes)?;
    let baseline_attestation: RunAttestation =
        decode(&read_role(directory, &index, "baseline_attestation")?)?;
    let candidate_attestation: RunAttestation =
        decode(&read_role(directory, &index, "candidate_attestation")?)?;
    validate_attestation(&baseline_attestation, &baseline, &baseline_bytes)?;
    validate_attestation(&candidate_attestation, &candidate, &candidate_bytes)?;

    let paired: PairedEvaluationReport = decode(&read_role(directory, &index, "paired_report")?)?;
    let expected_paired = compare_manifests(
        &baseline,
        &index.comparison.baseline_arm,
        &candidate,
        &index.comparison.candidate_arm,
        index.comparison.minimum_pairs,
        "signed_evidence_bundle",
        KernelTaxLine::reserved(),
    )?;
    let pareto: ParetoReport = decode(&read_role(directory, &index, "pareto_report")?)?;
    let expected_pareto = pareto_frontier(vec![
        ParetoPoint::from_manifest_arm(
            &index.comparison.baseline_id,
            &baseline,
            &index.comparison.baseline_arm,
        )?,
        ParetoPoint::from_manifest_arm(
            &index.comparison.candidate_id,
            &candidate,
            &index.comparison.candidate_arm,
        )?,
    ])?;
    let expected_evidence_rows = emit_evidence_rows(
        &baseline,
        &index.comparison.baseline_id,
        &index.comparison.baseline_arm,
        &candidate,
        &index.comparison.candidate_id,
        &index.comparison.candidate_arm,
    )?;
    // Measured rows are reproducible projections of the attested manifests. The committed
    // synthetic acceptance fixture intentionally exercises train and held-out isolation in one
    // signed envelope, so it is authenticated by the index signature/digest but never claimed to
    // be a projection of its inert comparison artifacts.
    let rows_match_measured_inputs = index.evidence_rows.provenance
        == EvidenceRowsProvenance::SyntheticFixture
        || index.evidence_rows == expected_evidence_rows;
    if paired != expected_paired || pareto != expected_pareto || !rows_match_measured_inputs {
        return Err(EvidenceBundleError::Digest);
    }
    let evidence_rows = index.evidence_rows.clone();
    let verified_seal = VerifiedEvidenceSeal {
        index_sha256: index.index_sha256.clone(),
        evidence_rows_sha256: evidence_rows.document_sha256.clone(),
    };
    Ok(VerifiedEvidenceBundle {
        index,
        evidence_rows,
        paired,
        pareto,
        _verified: verified_seal,
    })
}

fn verify_file_set(
    directory: &Path,
    index: &EvidenceBundleIndex,
) -> Result<(), EvidenceBundleError> {
    let expected = index
        .files
        .iter()
        .map(|file| file.file_name.clone())
        .chain(std::iter::once("bundle.index.json".into()))
        .collect::<BTreeSet<_>>();
    let actual = std::fs::read_dir(directory)
        .map_err(|error| io(directory, error))?
        .map(|entry| {
            entry
                .map_err(|error| io(directory, error))
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let names = index
        .files
        .iter()
        .map(|file| file.file_name.as_str())
        .collect::<BTreeSet<_>>();
    let roles = index
        .files
        .iter()
        .map(|file| file.role.as_str())
        .collect::<BTreeSet<_>>();
    let required_roles = BTreeSet::from([
        "baseline_manifest",
        "candidate_manifest",
        "baseline_attestation",
        "candidate_attestation",
        "paired_report",
        "pareto_report",
    ]);
    if expected != actual || names.len() != index.files.len() || roles != required_roles {
        return Err(EvidenceBundleError::Digest);
    }
    let mut total = 0_u64;
    for expected_file in &index.files {
        validate_file_name(&expected_file.file_name)?;
        let bytes = read_regular(
            &directory.join(&expected_file.file_name),
            maximum_for_role(&expected_file.role)?,
        )?;
        total = total.saturating_add(bytes.len() as u64);
        if bytes.len() as u64 != expected_file.bytes
            || hex::encode(Sha256::digest(&bytes)) != expected_file.sha256
        {
            return Err(EvidenceBundleError::Digest);
        }
    }
    if total > super::max_bundle_bytes() {
        return Err(EvidenceBundleError::Digest);
    }
    Ok(())
}

fn verify_index(index: &EvidenceBundleIndex) -> Result<(), EvidenceBundleError> {
    let unsigned = UnsignedBundleIndex {
        schema_version: index.schema_version,
        bundle_type: index.bundle_type.clone(),
        public_key: index.public_key.clone(),
        comparison: index.comparison.clone(),
        evidence_rows: index.evidence_rows.clone(),
        files: index.files.clone(),
    };
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
    if index.index_sha256 != index_digest(&bytes) {
        return Err(EvidenceBundleError::Digest);
    }
    let public_bytes =
        hex::decode(&index.public_key).map_err(|_| EvidenceBundleError::Signature)?;
    let public: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| EvidenceBundleError::Signature)?;
    let signature_bytes =
        hex::decode(&index.signature).map_err(|_| EvidenceBundleError::Signature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| EvidenceBundleError::Signature)?;
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&bytes);
    VerifyingKey::from_bytes(&public)
        .map_err(|_| EvidenceBundleError::Signature)?
        .verify(&preimage, &signature)
        .map_err(|_| EvidenceBundleError::Signature)
}

fn file_for_role<'a>(
    index: &'a EvidenceBundleIndex,
    role: &str,
) -> Result<&'a str, EvidenceBundleError> {
    let matches = index
        .files
        .iter()
        .filter(|file| file.role == role)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(EvidenceBundleError::Digest);
    }
    Ok(&matches[0].file_name)
}

fn read_role(
    directory: &Path,
    index: &EvidenceBundleIndex,
    role: &str,
) -> Result<Vec<u8>, EvidenceBundleError> {
    read_regular(
        &directory.join(file_for_role(index, role)?),
        maximum_for_role(role)?,
    )
}

fn maximum_for_role(role: &str) -> Result<u64, EvidenceBundleError> {
    match role {
        "baseline_manifest" | "candidate_manifest" => Ok(MAX_MANIFEST_BYTES),
        "baseline_attestation" | "candidate_attestation" => Ok(MAX_ATTESTATION_BYTES),
        "paired_report" | "pareto_report" => Ok(MAX_GENERATED_BYTES),
        _ => Err(EvidenceBundleError::Digest),
    }
}

fn validate_file_name(value: &str) -> Result<(), EvidenceBundleError> {
    let mut components = Path::new(value).components();
    if value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || matches!(value, "." | ".." | "bundle.index.json")
        || !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(EvidenceBundleError::Digest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_file_name;

    #[test]
    fn bundle_file_names_use_the_same_bounded_ascii_grammar_as_the_schema() {
        assert!(validate_file_name("baseline.attestation.json").is_ok());
        for invalid in ["é.json", "../escape.json", "bundle.index.json", ""] {
            assert!(validate_file_name(invalid).is_err());
        }
        assert!(validate_file_name(&format!("{}.json", "a".repeat(252))).is_err());
    }
}
