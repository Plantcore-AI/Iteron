//! Tightening a `bounded` parameter to its declared minimum must not abort the process.
//!
//! Six parameters in this crate aborted with exit 101: the built-in LSP policy was asserted to
//! satisfy ceilings the operator had just lowered underneath it, and a ceiling of 0 additionally
//! made `1..=ceiling` empty so every value was refused.

use iteron_tunables::ResolutionValue;

#[test]
fn zero_ceilings_produce_a_policy_rather_than_an_abort() {
    let zeroed = [
        "tools.lsp.policy.max_lsp_routes",
        "tools.lsp.policy.max_lsp_arguments",
        "tools.lsp.policy.max_lsp_request_timeout_milliseconds",
        "tools.lsp.policy.max_lsp_restarts",
        "tools.lsp.policy.max_lsp_backoff_milliseconds",
        "tools.lsp.policy.default_lsp_backoff_cap_milliseconds",
    ];
    iteron_tunables::install_param_overrides(
        zeroed
            .iter()
            .map(|id| ((*id).to_owned(), ResolutionValue::Integer { value: 0 })),
    )
    .expect("every id is settable and 0 is each declared minimum");

    // Before the fix this aborted the process.
    let policy = iteron_tools::LspRuntimePolicy::default();
    assert!(
        !policy.routes.is_empty(),
        "a policy with no routes is not constructible, so one route must survive the ceiling"
    );
}
