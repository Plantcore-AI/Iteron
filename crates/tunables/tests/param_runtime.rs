//! The tier-2 override boundary.
//!
//! One test binary per process is what makes this testable at all: the override table installs
//! exactly once and is immutable afterwards, so a second install in the same process must be
//! refused rather than silently winning. That immutability is not a convenience — a parameter that
//! could change mid-run would make the run's own evidence describe something that did not happen.

use iteron_tunables::{
    ParamClass, ParamInstallError, ResolutionValue, install_param_overrides, param_usize, params,
};

#[test]
fn an_override_replaces_the_compiled_default_and_installs_only_once() {
    let bounded = params()
        .iter()
        .find(|param| {
            matches!(param.class, ParamClass::Bounded)
                && param.domain.max.is_some_and(|max| max > 4)
                && param.default.parse::<i128>().is_ok()
        })
        .expect("the catalog exposes bounded integral parameters");
    let ceiling = bounded.domain.max.expect("bounded implies a ceiling");

    // Before installation the helper returns exactly what the caller passed, so a build with no
    // profile behaves identically to one compiled before any of this existed.
    assert_eq!(param_usize(&bounded.id, 7), 7);
    assert_eq!(param_usize("no.such.parameter", 11), 11);

    let installed = install_param_overrides([(
        bounded.id.clone(),
        ResolutionValue::Integer {
            value: i64::try_from(ceiling - 1).unwrap(),
        },
    )])
    .expect("a value inside the clamp installs");
    assert_eq!(installed, 1);
    assert_eq!(
        param_usize(&bounded.id, 7),
        usize::try_from(ceiling - 1).unwrap(),
        "the override must win over the compiled default"
    );
    assert_eq!(
        param_usize("no.such.parameter", 11),
        11,
        "an unrelated parameter keeps its compiled default"
    );

    // Installing twice would silently discard one of the two sets, so it is refused.
    assert!(matches!(
        install_param_overrides([(bounded.id.clone(), ResolutionValue::Integer { value: 1 },)]),
        Err(ParamInstallError::AlreadyInstalled)
    ));
}
