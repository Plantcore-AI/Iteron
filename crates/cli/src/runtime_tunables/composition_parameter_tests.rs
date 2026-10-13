//! Isolate the real once-per-process installation, then exercise bootstrap and checkpoint readers.
use super::tests::assert_fresh_composition;
use crate::runtime_tunables::{effective_binary_media, effective_runtime, effective_view};
use iteron_tunables::ResolutionValue;
use std::collections::BTreeMap;

pub(super) const PARAMETER_IDS: [&str; 6] = [
    "cli.image_input.decode.max_animation_frames",
    "cli.image_input.max_image_file_bytes",
    "cli.image_input.max_total_image_file_bytes",
    "cli.providers.probe_backoff_base_secs",
    "cli.providers.probe_backoff_cap_secs",
    "cli.providers.probe_cache_ttl_secs",
];

#[test]
fn independent_owner_parameters_reach_startup_genesis_and_resume() {
    use clap::Parser;
    const CHILD: &str = "ITERON_TEST_OWNER_PARAMETER_CHILD";
    let values = [1, 128, 128, 7, 7, 7];
    let Some(index) = std::env::var_os(CHILD) else {
        for (index, param) in PARAMETER_IDS.iter().enumerate() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "runtime_tunables::composition::parameter_tests::independent_owner_parameters_reach_startup_genesis_and_resume", "--nocapture"])
                .env(CHILD, index.to_string()).output().unwrap();
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{param}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let index = index.to_str().unwrap().parse::<usize>().unwrap();
    let param = PARAMETER_IDS[index];
    let value = values[index];
    let cli =
        crate::cli_entry::Cli::try_parse_from(["iteron", "--set", &format!("{param}={value}")])
            .unwrap();
    assert!(matches!(
        crate::cli_entry::preflight::validate(&cli).unwrap(),
        crate::cli_entry::preflight::PreflightOutcome::Run(_)
    ));
    assert_eq!(iteron_tunables::param_i128(param, -1), i128::from(value));
    crate::providers::assert_installed_probe_policy_controls_cache();
    let image = crate::image_input::multimodal_decode_envelope();
    let probe = crate::providers::ProviderDiscoveryPolicy::owner();
    let actual = [
        i64::from(image.max_frames),
        image.per_image_raw_bytes as i64,
        image.aggregate_raw_bytes as i64,
        probe.failure_backoff_base_seconds() as i64,
        probe.failure_backoff_cap_seconds() as i64,
        probe.positive_ttl_seconds() as i64,
    ];
    assert_eq!(actual[index], value);
    let checkpoint = assert_fresh_composition(None, 8_192);
    let projection = effective_runtime::decode_checkpoint(&checkpoint, None).unwrap();
    assert_eq!(projection.core.multimodal_decode, image);
    if index < 3 {
        assert_image_reader(index);
        // Explicit parameters cannot silently disappear behind a contradictory immutable pin.
        let mut pinned = serde_json::from_value::<ResolutionValue>(
            checkpoint
                .as_v2()
                .unwrap()
                .entries
                .iter()
                .find(|entry| entry.family_id == "multimodal_input_admission_decode_envelope")
                .unwrap()
                .effective_value
                .clone()
                .unwrap(),
        )
        .unwrap();
        let ResolutionValue::Object { fields } = &mut pinned else {
            unreachable!()
        };
        let field = ["max_frames", "per_image_raw_bytes", "aggregate_raw_bytes"][index];
        fields.insert(
            field.into(),
            ResolutionValue::Integer {
                value: if index == 0 { 2 } else { 127 },
            },
        );
        if index == 2 {
            fields.insert(
                "per_image_raw_bytes".into(),
                ResolutionValue::Integer { value: 127 },
            );
        }
        let view = effective_view::EffectiveTunablesView::from_test_values(BTreeMap::from([(
            "multimodal_input_admission_decode_envelope".into(),
            pinned,
        )]));
        assert!(matches!(
            effective_binary_media::decode_multimodal(&view),
            Err(effective_binary_media::EffectiveBinaryMediaError::ParameterCheckpointMismatch(_))
        ));
    } else {
        let iteron_record::TunablesCheckpoint::V2(mut snapshot) = checkpoint else {
            unreachable!()
        };
        let entry = snapshot
            .entries
            .iter_mut()
            .find(|entry| entry.family_id == "provider_discovery_account_probe_cache_policy")
            .unwrap();
        let field = [
            "failure_backoff_base_seconds",
            "failure_backoff_cap_seconds",
            "positive_ttl_seconds",
        ][index - 3];
        entry.effective_value.as_mut().unwrap()["fields"][field] =
            serde_json::json!({"type": "integer", "value": value + 1});
        reseal_fixture(&mut snapshot);
        let result = effective_runtime::decode_checkpoint(
            &iteron_record::TunablesCheckpoint::V2(snapshot),
            None,
        );
        assert!(matches!(
            result,
            Err(effective_runtime::EffectiveRuntimeError::View(
                effective_view::EffectiveViewError::FixedAuthorityRuntimeMismatch(_)
            ))
        ));
    }
}

fn assert_image_reader(index: usize) {
    use crate::image_input::{ImageAttachments, ImageInputErrorKind};
    use base64::Engine as _;
    let mut attachments = ImageAttachments::default();
    let png = base64::engine::general_purpose::STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=").unwrap();
    attachments.attach_bytes("pixel.png", &png).unwrap();
    if index == 1 {
        assert_eq!(
            attachments
                .attach_bytes("large.png", &[0; 129])
                .unwrap_err()
                .kind(),
            ImageInputErrorKind::FileTooLarge
        );
    } else if index == 2 {
        assert_eq!(
            crate::image_input::multimodal_decode_envelope().per_image_raw_bytes,
            128
        );
        assert_eq!(
            attachments
                .attach_bytes("second.png", &png)
                .unwrap_err()
                .kind(),
            ImageInputErrorKind::AggregateTooLarge
        );
    } else {
        let mut animation = Vec::new();
        {
            let mut encoder =
                gif::Encoder::new(&mut animation, 1, 1, &[0, 0, 0, 255, 255, 255]).unwrap();
            let frame = gif::Frame {
                width: 1,
                height: 1,
                buffer: std::borrow::Cow::Borrowed(&[0]),
                ..Default::default()
            };
            encoder.write_frame(&frame).unwrap();
            encoder.write_frame(&frame).unwrap();
        }
        assert_eq!(
            attachments
                .attach_bytes("animation.gif", &animation)
                .unwrap_err()
                .kind(),
            ImageInputErrorKind::DecodeLimitExceeded
        );
    }
}

#[test]
fn historical_r29_default_checkpoint_keeps_literal_provenance_and_resumes() {
    let iteron_record::TunablesCheckpoint::V2(mut snapshot) = assert_fresh_composition(None, 8_192)
    else {
        unreachable!()
    };
    snapshot.registry_revision = 29;
    snapshot.registry_digest_sha256 =
        "860a7618e4d7c69b77a55ba0856673cf618bef5cc6fde9f98a5aac58aaa31f3b".into();
    for entry in &mut snapshot.entries {
        if matches!(
            entry.family_id.as_str(),
            "multimodal_input_admission_decode_envelope"
                | "provider_discovery_account_probe_cache_policy"
        ) {
            entry.provenance = Some(serde_json::json!({ "source": {
                "type": "default", "resolver_id": "iteron://tunables/resolvers/literal-v1",
                "evidence_digest_sha256": null, "subject": null, "fallback": false,
            }}));
        }
    }
    reseal_fixture(&mut snapshot);
    let checkpoint = iteron_record::TunablesCheckpoint::V2(snapshot);
    let resumed = effective_runtime::decode_checkpoint(&checkpoint, None)
        .expect("r29 default owner values and literal provenance remain executable");
    assert_eq!(
        resumed.core.multimodal_decode,
        crate::image_input::multimodal_decode_envelope()
    );
}

/// Recompute a synthetic fixture's commitments after changing its exact registry/owner values.
/// The production snapshot validator independently verifies this encoding before any getter runs.
fn reseal_fixture(snapshot: &mut iteron_protocol::RunGenesisTunablesSnapshotV2) {
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};
    #[derive(Serialize)]
    struct Entry<'a> {
        ordinal: u16,
        family_id: &'a str,
        state: iteron_protocol::RunGenesisTunableState,
        effective: Option<ResolutionValue>,
    }
    #[derive(Serialize)]
    struct Effective<'a> {
        canonicalization: &'static str,
        registry_id: &'a str,
        registry_revision: u16,
        registry_digest: &'a str,
        entries: Vec<Entry<'a>>,
    }
    for entry in &mut snapshot.entries {
        if let Some(binding) = &mut entry.fixed_authority_binding {
            let family = iteron_tunables::families()
                .iter()
                .find(|family| family.id == entry.family_id)
                .unwrap();
            let iteron_tunables::RuntimeBindingSpec::Fixed { authority, .. } =
                family.runtime_binding
            else {
                unreachable!()
            };
            let value = serde_json::from_value(entry.effective_value.clone().unwrap()).unwrap();
            binding.owner_value_digest_sha256 =
                iteron_tunables::fixed_authority_value_digest_sha256_at_registry(
                    &snapshot.registry_id,
                    snapshot.registry_revision,
                    &snapshot.registry_digest_sha256,
                    family.id,
                    authority,
                    &value,
                )
                .unwrap();
        }
    }
    let payload = Effective {
        canonicalization: "iteron-tunables-effective-json-v1",
        registry_id: &snapshot.registry_id,
        registry_revision: snapshot.registry_revision,
        registry_digest: &snapshot.registry_digest_sha256,
        entries: snapshot
            .entries
            .iter()
            .map(|entry| Entry {
                ordinal: entry.ordinal,
                family_id: &entry.family_id,
                state: entry.state,
                effective: entry
                    .effective_value
                    .clone()
                    .map(serde_json::from_value)
                    .transpose()
                    .unwrap(),
            })
            .collect(),
    };
    snapshot.effective_digest_sha256 =
        hex::encode(Sha256::digest(serde_json::to_vec(&payload).unwrap()));
    // These fresh-composition fixtures all carry a profile, so the protocol serializer and
    // canonical payload have the same fields up to the excluded final self-commitment.
    assert!(snapshot.profile_digest_sha256.is_some());
    let encoded = serde_json::to_string(snapshot).unwrap();
    let (payload, _) = encoded.rsplit_once(",\"snapshot_digest_sha256\":").unwrap();
    snapshot.snapshot_digest_sha256 =
        hex::encode(Sha256::digest(format!("{payload}}}").as_bytes()));
    iteron_record::validate_tunables_snapshot_v2(snapshot).unwrap();
}
