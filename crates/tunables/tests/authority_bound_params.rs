//! Composite owners admit coherent independent overrides before publishing any process state.
use iteron_tunables::{
    ParamAssignment, ParamInstallError, ProfileDocument, ProfileLoadError, ResolutionValue,
    install_param_overrides, installed_param_count, load_profile, param_i128, validate_profile,
};

fn document(values: &[(&str, i64)]) -> ProfileDocument {
    ProfileDocument {
        schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: "test/authority-bound-parameters".into(),
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        param_registry_digest: None,
        module_scope: None,
        values: Vec::new(),
        params: values
            .iter()
            .map(|(id, value)| ParamAssignment {
                param: (*id).into(),
                value: ResolutionValue::Integer { value: *value },
            })
            .collect(),
        artifacts: Vec::new(),
    }
}

#[test]
fn six_owner_parameters_admit_independently_and_reject_invalid_batches_atomically() {
    let frames = "cli.image_input.decode.max_animation_frames";
    let single = "cli.image_input.max_image_file_bytes";
    let total = "cli.image_input.max_total_image_file_bytes";
    let base = "cli.providers.probe_backoff_base_secs";
    let cap = "cli.providers.probe_backoff_cap_secs";
    let ttl = "cli.providers.probe_cache_ttl_secs";
    let supported = "provider.lib.transport_stream_idle_secs";
    for values in [
        vec![(frames, 0)],
        vec![(single, 0)],
        vec![(total, 0)],
        vec![(base, 0)],
        vec![(base, 86_401)],
        vec![(cap, 0)],
        vec![(ttl, -1)],
        vec![(ttl, 86_401)],
        vec![(single, 1024), (total, 512)],
        vec![(base, 60), (cap, 30)],
    ] {
        let mut profile = document(&values);
        profile.params.insert(
            0,
            ParamAssignment {
                param: supported.into(),
                value: ResolutionValue::Integer { value: 17 },
            },
        );
        assert!(validate_profile(&profile).is_err(), "{values:?}");
        let result = install_param_overrides(
            profile
                .params
                .into_iter()
                .map(|assignment| (assignment.param, assignment.value)),
        );
        assert!(
            matches!(
                result,
                Err(ParamInstallError::OwnerConstraint { .. })
                    | Err(ParamInstallError::Domain { .. })
            ),
            "{values:?}: {result:?}"
        );
        assert_eq!(installed_param_count(), 0);
        assert_eq!(
            param_i128(supported, 60),
            60,
            "failed batches publish nothing"
        );
    }
    // Total-only and cap-only values smaller than the dependent compiled default remain useful.
    for id in [frames, single, total, base, cap, ttl] {
        let profile = document(&[(id, 1)]);
        validate_profile(&profile).unwrap();
        let encoded = serde_json::to_string(&profile).unwrap();
        load_profile(
            encoded.as_bytes(),
            &iteron_tunables::document_digest(&encoded),
        )
        .unwrap();
    }
    validate_profile(&document(&[(ttl, 0)])).expect("zero disables positive cache reuse");
    let invalid = document(&[(single, 1024), (total, 512)]);
    assert!(matches!(
        validate_profile(&invalid),
        Err(ProfileLoadError::ParamOwnerConstraint { .. })
    ));
    let values = [
        (frames, 1),
        (single, 512),
        (total, 1024),
        (base, 7),
        (cap, 28),
        (ttl, 9),
    ];
    let profile = document(&values);
    assert_eq!(
        install_param_overrides(
            profile
                .params
                .into_iter()
                .map(|assignment| (assignment.param, assignment.value))
        )
        .unwrap(),
        6
    );
    for (id, value) in values {
        assert_eq!(param_i128(id, -1), i128::from(value), "{id}");
    }
}
