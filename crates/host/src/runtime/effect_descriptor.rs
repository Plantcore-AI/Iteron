//! Pure effect identity, audit projection and terminal vocabulary. No writer, executor or owner.
use super::tool_presentation::strict_utf8_head;
use iteron_kernel::effect_class;
use iteron_protocol::{Capability, EventKind, TurnId};

/// One non-registry effect, addressed to the boundary.
///
/// A descriptor rather than a parameter list because the dispatch helper needs disjoint mutable and
/// shared borrows of the agent at the same time, and because six positional arguments of which three
/// are integers is exactly the shape that gets mis-ordered silently.
pub(super) struct KernelEffect<'a> {
    pub(super) turn: TurnId,
    pub(super) class: effect_class::EffectClass,
    pub(super) ordinal: usize,
    /// The class this dispatch is *audited* as. Recording it grants nothing: the constitutional
    /// gate has already run, and the boundary only writes down what was admitted.
    pub(super) capability: Capability,
    pub(super) audit_arguments: serde_json::Value,
    pub(super) workspace: &'a std::path::Path,
}

/// The durable kind string for a non-registry class.
pub(super) fn effect_class_label(class: effect_class::EffectClass) -> &'static str {
    class
        .label()
        .expect("only registry tools have no durable label, and they record their tool name")
}

/// The proven-success terminal for a non-registry effect.
pub(super) fn effect_done_terminal(
    turn: TurnId,
    class: effect_class::EffectClass,
    ordinal: usize,
) -> EventKind {
    EventKind::EffectDone {
        id: effect_class::effect_id(turn, class, ordinal),
        tool: effect_class_label(class).to_string(),
        // `None`, deliberately: the effect boundary stamps the measurement in `settle_effect` so
        // all seven classes are timed at the same two points by the same clock. A number minted
        // here would be scoped to whatever this caller happened to wrap.
        duration_ms: None,
        provider_route_attempt: None,
    }
}

/// The proven-failure terminal for a non-registry effect. `reason` is executor-authored text: it is
/// bounded here and scrubbed by the record boundary before it becomes durable.
pub(super) fn effect_failed_terminal(
    turn: TurnId,
    class: effect_class::EffectClass,
    ordinal: usize,
    reason: &str,
) -> EventKind {
    EventKind::EffectFailed {
        id: effect_class::effect_id(turn, class, ordinal),
        tool: effect_class_label(class).to_string(),
        reason: strict_utf8_head(
            reason,
            iteron_tunables::param_integer(
                "cli.runtime.effect_reason_max_bytes",
                EFFECT_REASON_MAX_BYTES,
            ),
        ),
        // See `effect_done_terminal`: the boundary owns the measurement.
        duration_ms: None,
        provider_route_attempt: None,
    }
}

/// The scrubbed, bounded workspace projection every brokered effect records.
///
/// One helper rather than a repeated expression at each call site, because the shape is part of the
/// contract: `EffectProposal::validate` refuses an empty workspace and anything past 4 KiB. An agent
/// constructed with an empty workspace path is legal (subagents and one-shot runs do it), so a bare
/// `display()` would have made those effects unrecordable at exactly the moment they matter.
pub(super) fn effect_workspace(workspace: &std::path::Path) -> String {
    let rendered = strict_utf8_head(
        &iteron_record::redact::scrub(&workspace.display().to_string()),
        2_048,
    );
    if rendered.is_empty() {
        ".".to_string()
    } else {
        rendered
    }
}

/// Bound on the executor-authored reason recorded with a proven effect failure. Unbounded here
/// would let a chatty executor write megabytes into the long-retained audit log on every failure.
pub(super) const EFFECT_REASON_MAX_BYTES: usize = 4 * 1024;
