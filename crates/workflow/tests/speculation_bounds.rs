//! A legal profile must never abort the process.
//!
//! `workflow.execution_policy.max_speculative_cleanup_timeout` and
//! `...max_speculative_siblings` are `bounded` parameters, and the catalog documents a bounded
//! parameter as one an operator may tighten freely. Tightening either of them below the built-in
//! default used to leave `SpeculativeSiblingPolicy::default()` outside its own window, and the
//! `.expect()` there aborted the process with exit 101 rather than honouring the ceiling.
//!
//! Overrides install once per process, so this lives in its own test binary.

use iteron_tunables::ResolutionValue;
use iteron_workflow::SpeculativeSiblingPolicy;
use std::time::Duration;

#[test]
fn tightening_a_bound_below_the_built_in_default_does_not_abort() {
    let installed = iteron_tunables::install_param_overrides([
        (
            "workflow.execution_policy.max_speculative_cleanup_timeout".to_owned(),
            ResolutionValue::Integer { value: 1 },
        ),
        (
            "workflow.execution_policy.max_speculative_siblings".to_owned(),
            ResolutionValue::Integer { value: 1 },
        ),
    ])
    .expect("both parameters are settable and both values are inside their declared domains");
    assert_eq!(installed, 2);

    // Before the fix this line aborted the process; the assertions below never ran.
    let policy = SpeculativeSiblingPolicy::default();

    assert!(
        policy.cleanup_timeout() <= Duration::from_secs(1),
        "the operator's ceiling must be honoured, got {:?}",
        policy.cleanup_timeout()
    );
    assert!(
        policy.max_siblings() <= 1,
        "the operator's sibling ceiling must be honoured, got {}",
        policy.max_siblings()
    );
}
