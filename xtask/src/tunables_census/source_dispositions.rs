//! Explicit declaration dispositions shared with Tier-2 and exact older invariant sources.
//! This is not a name heuristic or an exemption for arbitrary structural/unapplied rows.

use super::{CensusCandidateKind, CensusRow, InvariantKind, invariant_kind_for};
use crate::tunables_params::{InvariantReason, OwnerRow};

pub(super) fn reason(owner: &OwnerRow) -> Option<InvariantReason> {
    let name = owner.symbol.rsplit("::").next()?;
    if !owner
        .path
        .strip_prefix("crates/")?
        .starts_with(&format!("{}/src/", owner.krate))
    {
        return None;
    }
    crate::tunables_params::explicit_invariant_reason(&owner.path, name, &owner.symbol)
        .or_else(|| older_source_reason(&owner.path, name, &owner.symbol))
}

pub(super) fn kind(row: &CensusRow) -> Option<InvariantKind> {
    // A serde/builder/default row cannot borrow the disposition of a nearby constant. Keep the
    // actual Tier-2 declaration identity; discovered source forms have their own closed rules.
    if !matches!(
        row.candidate_kind,
        CensusCandidateKind::Const
            | CensusCandidateKind::Static
            | CensusCandidateKind::AssociatedConst
    ) || row.tier2_id.as_deref() != Some(row.id.as_str())
    {
        return None;
    }
    reason(&row.owner).map(|reason| invariant_kind_for(reason, &row.id))
}

fn older_source_reason(relative: &str, name: &str, owner: &str) -> Option<InvariantReason> {
    match (relative, name, owner) {
        // This sentinel has a reserved serialized meaning. Operator-specified finite turn
        // ceilings remain runtime inputs and are never made read-only by this rule.
        ("crates/protocol/src/lib.rs", "UNLIMITED_TURNS", "Budget::UNLIMITED_TURNS") => {
            return Some(InvariantReason::WireCompatibility);
        }
        // Existing bounded-query framing explicitly distinguishes omitted source bytes.
        (
            "crates/ctx/src/context_strategy.rs",
            "MARKER",
            "ContextSlotObservation::bounded_task_query::MARKER",
        ) => return Some(InvariantReason::Identity),
        // The actual native physical metadata cache never reads a tunable replacement. This is
        // its OnceLock state, not the independently selectable planning metadata document.
        (
            "crates/provider/src/static_metadata.rs",
            "SHIPPED",
            "StaticProviderMetadata::shipped_physical_input_ceiling::SHIPPED",
        ) => return Some(InvariantReason::RuntimeStateNotAValue),
        _ => {}
    }
    if owner != name {
        return None;
    }
    match (relative, name) {
        // The public producer/parser share these finite resident stream and request envelopes.
        // Tier-2 already marks these precise declarations WireCompatibility; census now retains
        // that explicit source evidence rather than inferring it from MAX_ or an unapplied bit.
        (
            "crates/protocol/src/product_contract.rs",
            "MAX_PRODUCT_APPROVAL_ARGUMENTS_BYTES"
            | "MAX_PRODUCT_APPROVAL_FIELD_BYTES"
            | "MAX_PRODUCT_CONTENT_CHUNK_BYTES"
            | "MAX_PRODUCT_EVENT_BYTES"
            | "MAX_PRODUCT_EVENTS"
            | "MAX_PRODUCT_READ_BYTES"
            | "MAX_PRODUCT_READ_EVENTS"
            | "MAX_PRODUCT_SOURCE_CONTENT_BYTES"
            | "MAX_THREAD_ITEMS"
            | "MAX_THREAD_SUBMISSIONS",
        ) => Some(InvariantReason::WireCompatibility),
        // Actual immutable disabled/empty fallback state and an AtomicUsize worker census are
        // observations, not configuration. Ordinary tool visibility still intersects admission;
        // the table cannot mint execution authority or replace tool-ranking controls.
        ("crates/cli/src/runtime/context_runtime.rs", "ORDINARY_CODING_TOOLS")
        | ("crates/cli/src/runtime/optional_tool_round.rs", "EMPTY_INDICES")
        | ("crates/cli/src/runtime/tool_image_projection.rs", "IMAGE_UNAVAILABLE")
        | ("crates/tools/src/contained_source.rs", "WORKERS") => {
            Some(InvariantReason::RuntimeStateNotAValue)
        }
        _ => None,
    }
}
