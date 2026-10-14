//! Validate composite owners before publishing the immutable parameter table.

use crate::{ResolutionValue, resolution_value};
use std::collections::BTreeMap;

// Ordered by dependent field first: an omitted per-item/default backoff is narrowed by its
// explicit aggregate/cap, while two explicit, contradictory values are always refused.
const OWNERS: &[(&str, &[(&str, &str)])] = &[
    (
        "multimodal_input_admission_decode_envelope",
        &[
            (
                "cli.image_input.max_image_file_bytes",
                "per_image_raw_bytes",
            ),
            (
                "cli.image_input.max_total_image_file_bytes",
                "aggregate_raw_bytes",
            ),
            ("cli.image_input.decode.max_animation_frames", "max_frames"),
        ],
    ),
    (
        "provider_discovery_account_probe_cache_policy",
        &[
            (
                "cli.providers.probe_backoff_base_secs",
                "failure_backoff_base_seconds",
            ),
            (
                "cli.providers.probe_backoff_cap_secs",
                "failure_backoff_cap_seconds",
            ),
            ("cli.providers.probe_cache_ttl_secs", "positive_ttl_seconds"),
        ],
    ),
];

pub(crate) fn validate<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a ResolutionValue)>,
) -> Result<(), (&'static str, String)> {
    let values = values.into_iter().collect::<BTreeMap<_, _>>();
    for &(family_id, mappings) in OWNERS {
        if !mappings.iter().any(|(param, _)| values.contains_key(param)) {
            continue;
        }
        let family = crate::families()
            .iter()
            .find(|family| family.id == family_id)
            .expect("parameter owner is registered");
        let mut owner = resolution_value::owned(
            family
                .default
                .value
                .expect("parameter owner retains its canonical default"),
        );
        let ResolutionValue::Object { fields } = &mut owner else {
            unreachable!("parameter owner has an object schema")
        };
        for &(param, field) in mappings {
            if let Some(value) = values.get(param) {
                fields.insert(field.to_owned(), (*value).clone());
            }
        }
        let (dependent_param, dependent_field) = mappings[0];
        let (_, ceiling_field) = mappings[1];
        if !values.contains_key(dependent_param)
            && let (
                Some(ResolutionValue::Integer { value: dependent }),
                Some(ResolutionValue::Integer { value: ceiling }),
            ) = (fields.get(dependent_field), fields.get(ceiling_field))
        {
            fields.insert(
                dependent_field.to_owned(),
                ResolutionValue::Integer {
                    value: (*dependent).min(*ceiling),
                },
            );
        }
        resolution_value::validate(&owner, family.value_schema, &BTreeMap::new())
            .map_err(|reason| (family_id, reason))?;
    }
    Ok(())
}
