//! Tightening a `bounded` parameter to its declared minimum must not abort the process.
//!
//! The catalog documents a bounded parameter as one an operator may tighten freely, and generates
//! its domain as `min: 0`. Nothing checked that the built-in policies survive that floor: three
//! parameters in this crate aborted with exit 101 because a `Default` impl asserted the built-in
//! value already fit a ceiling the operator had just lowered underneath it.
//!
//! Overrides install once per process, so this is its own test binary.

use iteron_tunables::ResolutionValue;

#[test]
fn zero_ceilings_produce_policies_rather_than_an_abort() {
    let zeroed = [
        "mcp.reconnect.max_reconnect_attempts",
        "mcp.reconnect.max_reconnect_base_ms",
        "mcp.reconnect.max_reconnect_cap_ms",
        "mcp.result_policy.max_mcp_spill_result_bytes",
    ];
    iteron_tunables::install_param_overrides(
        zeroed
            .iter()
            .map(|id| ((*id).to_owned(), ResolutionValue::Integer { value: 0 })),
    )
    .expect("every id is settable and 0 is each declared minimum");

    // Before the fix each of these aborted the process.
    let reconnect = iteron_mcp::reconnect::ReconnectPolicy::default();
    assert!(
        reconnect.base_ms() <= reconnect.cap_ms(),
        "base must not exceed cap"
    );

    let result = iteron_mcp::McpResultPolicy::default();
    assert!(
        result.visible_max_bytes() <= result.spill_max_bytes(),
        "visible must not exceed spill"
    );
}
