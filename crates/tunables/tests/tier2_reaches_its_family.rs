//! Sampled owner defaults preserve both independent parameters and immutable checkpoint identity.
#[test]
fn image_and_probe_parameters_reach_sampled_defaults() {
    for (family, params) in [
        (
            "multimodal_input_admission_decode_envelope",
            [
                "cli.image_input.decode.max_animation_frames",
                "cli.image_input.max_image_file_bytes",
                "cli.image_input.max_total_image_file_bytes",
            ],
        ),
        (
            "provider_discovery_account_probe_cache_policy",
            [
                "cli.providers.probe_backoff_base_secs",
                "cli.providers.probe_backoff_cap_secs",
                "cli.providers.probe_cache_ttl_secs",
            ],
        ),
    ] {
        let owner = iteron_tunables::families()
            .iter()
            .find(|entry| entry.id == family)
            .unwrap();
        assert!(matches!(
            owner.default.resolver,
            iteron_tunables::DefaultResolver::Builtin { .. }
        ));
        assert!(
            owner.default.value.is_some(),
            "canonical unconfigured value remains documented"
        );
        for param in params {
            let entry = iteron_tunables::param(param).unwrap();
            assert!(entry.is_settable() && entry.applied, "{param}");
            entry
                .admits_value(&iteron_tunables::ResolutionValue::Integer { value: 1 })
                .unwrap();
        }
    }
}
