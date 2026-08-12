//! The exposure surface and the boundaries it must never cross.
//!
//! These are deliberately few. The point is not coverage of the loader's parsing, it is that the
//! four things which must stay true stay true: the axis is total, the export does not overstate
//! itself, a sealed family is unreachable, and a bound cannot be loosened past what shipped.

use iteron_tunables::{
    ImplementationStatus, ModuleId, ParamClass, ProfileDocument, ProfileLoadError, ResolutionValue,
    SourceKind, families, load_profile, params, surface, validate_profile,
};

fn document(values: Vec<iteron_tunables::ProfileValue>) -> ProfileDocument {
    ProfileDocument {
        schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: "test/profile".to_owned(),
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.to_owned(),
        param_registry_digest: None,
        module_scope: None,
        values,
        params: Vec::new(),
    }
}

#[test]
fn the_module_axis_is_total_and_has_no_empty_module() {
    let surface = surface();
    assert_eq!(surface.counts.modules, 28);
    assert_eq!(ModuleId::ALL.len(), 28);
    // Every family and every parameter is assigned, so a module-scoped ablation can never silently
    // leave part of the surface unmoved.
    let assigned_families: usize = surface.modules.iter().map(|entry| entry.families).sum();
    let assigned_params: usize = surface.modules.iter().map(|entry| entry.params).sum();
    assert_eq!(assigned_families, surface.counts.families);
    assert_eq!(assigned_params, surface.counts.params);
    let empty: Vec<&str> = surface
        .modules
        .iter()
        .filter(|entry| entry.families == 0 && entry.params == 0 && entry.artifacts == 0)
        .map(|entry| entry.id)
        .collect();
    assert!(empty.is_empty(), "modules with no members: {empty:?}");
}

#[test]
fn the_export_does_not_claim_more_than_the_loader_accepts() {
    // The honesty property. Every family the export marks addressable must survive validation as a
    // profile value; an export that overstates its surface would burn a tuner's whole budget on
    // candidates that are refused.
    let surface = surface();
    let addressable: Vec<_> = surface
        .families
        .iter()
        .filter(|entry| entry.profile_addressable)
        .collect();
    assert_eq!(
        addressable.len(),
        surface.counts.families_profile_addressable
    );
    for entry in addressable {
        let family = families()
            .iter()
            .find(|family| family.id == entry.id)
            .expect("exported family exists");
        let source = family
            .source
            .bindings
            .iter()
            .map(|binding| binding.kind)
            .find(|kind| matches!(kind, SourceKind::UserConfig | SourceKind::ProjectConfig))
            .expect("addressable means it declares a profile-usable source");
        let document = document(vec![iteron_tunables::ProfileValue {
            family: family.id.to_owned(),
            as_declared_source: source,
            value: ResolutionValue::Integer { value: 1 },
        }]);
        // Only the admission path is under test here; the value's own schema is checked by the
        // resolver, which this deliberately does not stand in for.
        assert!(
            !matches!(
                validate_profile(&document),
                Err(ProfileLoadError::UnauthorizedSource { .. })
                    | Err(ProfileLoadError::SealedFamily(_))
                    | Err(ProfileLoadError::UnknownFamily(_))
            ),
            "export marks `{}` addressable but the loader refuses it",
            family.id
        );
    }
}

#[test]
fn a_sealed_family_can_never_be_set_by_a_profile() {
    let sealed = families()
        .iter()
        .find(|family| family.implementation_status == ImplementationStatus::FixedHidden)
        .expect("the registry has fixed-authority families");
    let document = document(vec![iteron_tunables::ProfileValue {
        family: sealed.id.to_owned(),
        as_declared_source: SourceKind::UserConfig,
        value: ResolutionValue::Integer { value: 1 },
    }]);
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::SealedFamily(_))
    ));
    // And no sealed family is ever advertised as addressable in the first place.
    let surface = surface();
    assert!(
        surface
            .families
            .iter()
            .filter(|entry| entry.implementation_status == "FixedHidden")
            .all(|entry| !entry.profile_addressable)
    );
}

#[test]
fn a_bound_may_be_tightened_but_not_loosened_past_what_shipped() {
    let bounded = params()
        .iter()
        .find(|param| {
            matches!(param.class, ParamClass::Bounded)
                && param.domain.max.is_some_and(|max| max > 2)
        })
        .expect("the catalog exposes bounded parameters");
    let ceiling = bounded.domain.max.expect("bounded implies a ceiling");
    assert!(
        bounded.admits_integer(ceiling - 1).is_ok(),
        "tightening is allowed"
    );
    assert!(
        bounded.admits_integer(ceiling).is_ok(),
        "the shipped value itself is allowed"
    );
    assert!(
        bounded.admits_integer(ceiling + 1).is_err(),
        "loosening past the shipped ceiling must be refused"
    );
}

#[test]
fn a_structural_parameter_is_read_only() {
    let structural = params()
        .iter()
        .find(|param| matches!(param.class, ParamClass::Structural))
        .expect("the catalog exposes structural parameters");
    assert!(!structural.is_settable());
    let mut document = document(Vec::new());
    document.params.push(iteron_tunables::ParamAssignment {
        param: structural.id.clone(),
        value: ResolutionValue::Integer { value: 1 },
    });
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::StructuralParam(_))
    ));
}

#[test]
fn a_profile_is_pinned_to_the_bytes_it_was_computed_against() {
    let document = document(Vec::new());
    let rendered = iteron_tunables::render_profile(&document).expect("renders");
    let digest = iteron_tunables::document_digest(&rendered);
    assert!(load_profile(rendered.as_bytes(), &digest).is_ok());
    assert!(matches!(
        load_profile(rendered.as_bytes(), &"0".repeat(64)),
        Err(ProfileLoadError::DigestMismatch { .. })
    ));
}
