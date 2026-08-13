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
        artifacts: Vec::new(),
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
fn a_parameter_refuses_the_wrong_value_type_instead_of_dropping_it() {
    let integer = params()
        .iter()
        .find(|param| {
            param.is_settable() && matches!(param.ty, iteron_tunables::ParamType::Integer)
        })
        .expect("the catalog exposes a settable integer parameter");
    let mut profile = document(Vec::new());
    profile.params.push(iteron_tunables::ParamAssignment {
        param: integer.id.clone(),
        value: ResolutionValue::Boolean { value: true },
    });
    assert!(matches!(
        validate_profile(&profile),
        Err(ProfileLoadError::ParamType { .. })
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

/// Six families are operator-settable and deliberately NOT reachable by a profile.
///
/// Two of them — `permission_mode` and `bypass_permissions` — decide what the agent is allowed to
/// do at all. A tuner that could set them could widen its own authority as a side effect of
/// searching for a better score, which is the exact failure `Principal.md` forbids. The other four
/// are excluded for consistency: they are CLI/environment controls whose value belongs to the
/// invocation, not to a stored candidate.
///
/// This test exists because that decision otherwise lives only in prose. Widening the profile
/// surface to include any of them must be a deliberate act that fails here first.
#[test]
fn the_six_deliberately_unreachable_families_stay_unreachable() {
    const EXCLUDED: [&str; 6] = [
        "max_tokens",
        "permission_mode",
        "bypass_permissions",
        "verify_command",
        "memory_enable",
        "max_consecutive_tool_errors",
    ];
    let surface = surface();
    for id in EXCLUDED {
        let entry = surface
            .families
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("family `{id}` no longer exists; revisit this exclusion"));
        assert!(
            !entry.profile_addressable,
            "`{id}` became profile-addressable. For `permission_mode` and `bypass_permissions` \
             that is an authority widening and must never land; for the others, update this test \
             in the same change that makes it deliberate."
        );
    }
}

/// A prompt artifact replacement is text and only text.
///
/// The reason an untrusted optimizer may rewrite a tool description at all is that a description
/// carries no authority: replacing it cannot change what the tool may do, what arguments it takes,
/// or what it is called. These assertions pin the shape of that channel; the enforcement that a
/// replacement never reaches a capability lives at the point of use.
#[test]
fn a_prompt_artifact_override_is_bounded_named_and_non_empty() {
    use iteron_tunables::{ArtifactOverride, MAX_ARTIFACT_TEXT_BYTES};

    let known = iteron_tunables::PROMPT_ARTIFACTS[0].id;
    let mut document = document(Vec::new());

    document.artifacts = vec![ArtifactOverride {
        artifact: known.to_owned(),
        text: "You are a careful agent.".to_owned(),
    }];
    assert!(validate_profile(&document).is_ok());
    assert_eq!(
        iteron_tunables::artifact_override(&document, known),
        Some("You are a careful agent.")
    );
    assert_eq!(
        iteron_tunables::artifact_override(&document, "prompt/nope@v1"),
        None
    );

    document.artifacts = vec![ArtifactOverride {
        artifact: "prompt/not-a-real-artifact@v1".to_owned(),
        text: "x".to_owned(),
    }];
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::UnknownArtifact(_))
    ));

    // A blank replacement is refused rather than treated as deletion: silently dropping the
    // instructions a runtime depends on is not a thing an optimizer should be able to do by
    // submitting whitespace.
    document.artifacts = vec![ArtifactOverride {
        artifact: known.to_owned(),
        text: "   \n".to_owned(),
    }];
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::EmptyArtifact(_))
    ));

    document.artifacts = vec![ArtifactOverride {
        artifact: known.to_owned(),
        text: "x".repeat(MAX_ARTIFACT_TEXT_BYTES + 1),
    }];
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::ArtifactTooLarge { .. })
    ));

    document.artifacts = vec![
        ArtifactOverride {
            artifact: known.to_owned(),
            text: "a".to_owned(),
        },
        ArtifactOverride {
            artifact: known.to_owned(),
            text: "b".to_owned(),
        },
    ];
    assert!(matches!(
        validate_profile(&document),
        Err(ProfileLoadError::DuplicateArtifact(_))
    ));
}

/// Every published artifact id is addressable, and every one names a distinct module member.
#[test]
fn every_prompt_artifact_is_addressable_and_uniquely_identified() {
    use std::collections::BTreeSet;
    let ids: BTreeSet<&str> = iteron_tunables::PROMPT_ARTIFACTS
        .iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(ids.len(), 10, "artifact ids must be unique");
    for artifact in iteron_tunables::PROMPT_ARTIFACTS {
        let mut document = document(Vec::new());
        document.artifacts = vec![iteron_tunables::ArtifactOverride {
            artifact: artifact.id.to_owned(),
            text: "replacement".to_owned(),
        }];
        assert!(
            validate_profile(&document).is_ok(),
            "published artifact `{}` is not actually addressable",
            artifact.id
        );
    }
}

/// Every addressable tier-2 parameter must actually move.
///
/// Both halves of this were learned the hard way. Tier-2 parameters and prompt artifacts were once
/// published before all of their production reads existed. An optimizer cannot tell an inert knob
/// from a live one by trying it — a value that changes nothing looks exactly like a value that did
/// not help — so the export has to say which is which and this gate must require exact equality.
#[test]
fn every_settable_parameter_is_actually_applied() {
    let surface = surface();

    // Whatever the counts are, they must be derived from the entries rather than asserted
    // independently, so the summary can never disagree with the rows it summarises.
    assert_eq!(
        surface.counts.params_applied,
        surface.params.iter().filter(|param| param.applied).count()
    );
    assert_eq!(
        surface.counts.prompt_artifacts_overridable,
        iteron_tunables::PROMPT_ARTIFACTS
            .iter()
            .filter(|artifact| artifact.overridable)
            .count()
    );

    // The implication must hold in both directions. A structural value with a read site would be a
    // bypass, while a settable value without one would be a fake optimization knob.
    for param in surface.params {
        assert!(
            param.applied == param.is_settable(),
            "`{}` disagrees: applied={}, settable={}",
            param.id,
            param.applied,
            param.is_settable()
        );
    }
    assert_eq!(
        surface.counts.params_applied,
        surface
            .params
            .iter()
            .filter(|param| param.is_settable())
            .count(),
        "the live surface must have zero inert settable parameters"
    );
    assert!(
        surface
            .params
            .iter()
            .filter(|param| matches!(param.class, ParamClass::Bounded))
            .all(|param| param.domain.max.is_some()),
        "every tighten-only safety bound must publish its shipped ceiling"
    );
    assert_eq!(
        surface.counts.prompt_artifacts_overridable, surface.counts.prompt_artifacts,
        "every published prompt artifact must have a real runtime resolution site"
    );
}
