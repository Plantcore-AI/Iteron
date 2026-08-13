//! What the override boundary refuses.
//!
//! Separate binary from `param_runtime` because the installer is once-per-process: these cases all
//! fail before installing, so they can share one process, but they cannot share with a test that
//! succeeds.

use iteron_tunables::{
    ParamClass, ParamInstallError, ResolutionValue, install_param_overrides, params,
};

#[test]
fn the_boundary_refuses_unknown_structural_and_out_of_clamp_values() {
    assert!(matches!(
        install_param_overrides([(
            "not.a.real.parameter".to_owned(),
            ResolutionValue::Integer { value: 1 },
        )]),
        Err(ParamInstallError::UnknownParam(_))
    ));

    let structural = params()
        .iter()
        .find(|param| matches!(param.class, ParamClass::Structural))
        .expect("the catalog exposes structural parameters");
    assert!(matches!(
        install_param_overrides([(structural.id.clone(), ResolutionValue::Integer { value: 1 },)]),
        Err(ParamInstallError::NotSettable(_))
    ));

    // A safety bound may be tightened and may not be loosened past what the build shipped with, so
    // exposing it cannot make a running system less bounded than the audited one.
    let bounded = params()
        .iter()
        .find(|param| {
            matches!(param.class, ParamClass::Bounded)
                && param.domain.max.is_some_and(|max| max > 4)
        })
        .expect("the catalog exposes bounded parameters");
    let ceiling = bounded.domain.max.expect("bounded implies a ceiling");
    assert!(matches!(
        install_param_overrides([(
            bounded.id.clone(),
            ResolutionValue::Integer {
                value: i64::try_from(ceiling + 1).unwrap(),
            },
        )]),
        Err(ParamInstallError::Domain { .. })
    ));

    let integer = params()
        .iter()
        .find(|param| {
            param.is_settable() && matches!(param.ty, iteron_tunables::ParamType::Integer)
        })
        .expect("the catalog exposes a settable integer parameter");
    assert!(matches!(
        install_param_overrides([(integer.id.clone(), ResolutionValue::Boolean { value: true },)]),
        Err(ParamInstallError::WrongType { .. })
    ));

    assert!(matches!(
        install_param_overrides([(
            "cli.theme.capabilities.levels".to_owned(),
            ResolutionValue::List {
                items: vec![ResolutionValue::Integer { value: 1 }],
            },
        )]),
        Err(ParamInstallError::WrongType { .. })
    ));

    assert!(matches!(
        install_param_overrides([(
            "agents.decompose.broad_verbs".to_owned(),
            ResolutionValue::List {
                items: vec![ResolutionValue::Boolean { value: true }],
            },
        )]),
        Err(ParamInstallError::WrongType { .. })
    ));
    // Nothing above installed anything, so the table is still empty and a later caller could use it.
    assert_eq!(iteron_tunables::installed_param_count(), 0);
}
