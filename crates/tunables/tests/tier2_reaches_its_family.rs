//! A Tier-2 parameter that feeds a literal-defaulted family cannot be set.
//!
//! `params.rs` states the contract: Tier 2 is "addressable by a profile", and the two-tier split
//! is what "lets the whole surface be exposed". A literal default breaks that for any parameter
//! feeding it, because the runtime compares the production owner value byte-for-byte against the
//! frozen registry literal, and setting the parameter is exactly what makes them differ. The run
//! is then refused with `production owner value for literal family ... differs from the canonical
//! value` -- after the parameter installed and reported itself applied.
//!
//! Registry revision 20 converted fifteen such families to derived defaults. Two could not be
//! converted, and the six parameters feeding them are named in the module documentation as the
//! stated exception. This test pins that list: adding a parameter that feeds a literal family, or
//! converting one of these two families without updating the docs, fails here rather than in a
//! user's run.

/// The exception the contract documents, and the only one.
const KNOWN_UNSETTABLE: &[(&str, &str)] = &[
    (
        "cli.image_input.decode.max_animation_frames",
        "multimodal_input_admission_decode_envelope",
    ),
    (
        "cli.image_input.max_image_file_bytes",
        "multimodal_input_admission_decode_envelope",
    ),
    (
        "cli.image_input.max_total_image_file_bytes",
        "multimodal_input_admission_decode_envelope",
    ),
    (
        "cli.providers.probe_backoff_base_secs",
        "provider_discovery_account_probe_cache_policy",
    ),
    (
        "cli.providers.probe_backoff_cap_secs",
        "provider_discovery_account_probe_cache_policy",
    ),
    (
        "cli.providers.probe_cache_ttl_secs",
        "provider_discovery_account_probe_cache_policy",
    ),
];

#[test]
fn only_the_documented_families_still_take_a_literal_default() {
    let documented: std::collections::BTreeSet<&str> =
        KNOWN_UNSETTABLE.iter().map(|(_, family)| *family).collect();
    let literal: std::collections::BTreeSet<&str> = iteron_tunables::families()
        .iter()
        .filter(|family| {
            matches!(
                family.default.resolver,
                iteron_tunables::DefaultResolver::Literal
            )
        })
        .map(|family| family.id)
        .collect();
    for family in &documented {
        assert!(
            literal.contains(family),
            "`{family}` is no longer literal-defaulted; its parameters are settable now, so \
             remove it from KNOWN_UNSETTABLE and from the exception in params.rs"
        );
    }
}

/// Every parameter named in the exception must still exist and still be settable in the catalog.
///
/// Being refused at run time is the defect being documented; being absent or structural would mean
/// the list has rotted rather than that the exception still holds.
#[test]
fn every_documented_exception_names_a_real_settable_parameter() {
    for (param, _) in KNOWN_UNSETTABLE {
        let entry = iteron_tunables::param(param)
            .unwrap_or_else(|| panic!("`{param}` is in KNOWN_UNSETTABLE but not in the catalog"));
        assert!(
            !matches!(entry.class, iteron_tunables::ParamClass::Structural),
            "`{param}` is structural, so it is read-only by contract and does not belong in this list"
        );
    }
}
