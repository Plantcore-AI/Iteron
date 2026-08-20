//! Tightening a `bounded` parameter to its declared minimum must not abort the process.
//!
//! Nine parameters in this crate aborted with exit 101. Seven of them reached the one `.expect()`
//! that parsed the metadata document this build ships: that parse consults twelve operator-settable
//! bounds, and the shipped document does not fit them once tightened. Two more reached
//! `clamp(1, ceiling)` with a ceiling of 0, which is a panic in the standard library.

use iteron_tunables::ResolutionValue;

#[test]
fn zero_ceilings_still_yield_provider_metadata_and_a_health_store() {
    let zeroed = [
        "provider.static_metadata.max_document_bytes",
        "provider.static_metadata.max_revision_bytes",
        "provider.static_metadata.max_models",
        "provider.static_metadata.max_model_id_bytes",
        "provider.static_metadata.max_header_bytes",
        "provider.static_metadata.max_source_bytes",
        "provider.static_metadata.max_capability_routes",
        "provider.catalog.max_health_entries",
        "provider.catalog.max_model_health_entries",
    ];
    iteron_tunables::install_param_overrides(
        zeroed
            .iter()
            .map(|id| ((*id).to_owned(), ResolutionValue::Integer { value: 0 })),
    )
    .expect("every id is settable and 0 is each declared minimum");

    // Before the fix each of these aborted the process.
    // Reaching this line at all is the assertion: `embedded()` has no error channel, so before
    // the fix it aborted the process rather than returning.
    let _metadata = iteron_provider::StaticProviderMetadata::embedded();
    let _store = iteron_provider::ProviderHealthStore::new(8);
}
