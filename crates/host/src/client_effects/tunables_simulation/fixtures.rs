pub fn request_bytes() -> Vec<u8> {
    let activation = iteron_tunables::families()
        .iter()
        .filter_map(|family| match family.activation.predicate {
            iteron_tunables::ActivationPredicate::RuntimeDerived { seam } => {
                Some(serde_json::json!({
                    "family":family.id,"seam":seam,"subject_digest_sha256":"a".repeat(64),
                    "evidence_digest_sha256":"b".repeat(64),"active":true,
                }))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "schema_version":iteron_tunables::RESOLUTION_SCHEMA_VERSION,
        "registry_id":iteron_tunables::REGISTRY_ID,"registry_revision":iteron_tunables::REGISTRY_REVISION,
        "registry_digest":iteron_tunables::REGISTRY_DIGEST_SHA256,
        "declared_values":[],"default_evidence":[],"activation_evidence":activation,
        "constraint_evidence":[],"runtime":{},
    })).unwrap()
}
