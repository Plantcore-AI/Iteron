//! Single typed non-registry effect bridge to the existing authoritative kernel broker.
//! It takes disjoint journal/admission ports, so no executor receives mutable Agent state.

use super::EFFECT_REASON_MAX_BYTES;
use super::tool_presentation::strict_utf8_head;
use iteron_kernel::{effect_admission, effect_class, effects};
use iteron_protocol::{Capability, EventKind, TurnId};
use iteron_record::Rollout;

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

/// Dispatch one non-registry effect across the single boundary.
///
/// Every class that is not a registry tool call goes through here, which is what makes the boundary
/// test enforceable: there is exactly one place in the kernel that builds a
/// [`effects::BrokeredEffect`] for them, so "no call site bypasses the broker" is a property of one
/// function rather than a promise about thirty call sites.
///
/// It is a free function, not a method, for a load-bearing reason: the executor almost always needs
/// to borrow *some* part of the agent (`hooks`, `provider`, `verify` state) while the boundary needs
/// `&mut rollout` and `&mut effect_admissions`. Taking the two ledgers explicitly lets the caller
/// destructure the agent into disjoint borrows, which a `&mut self` method could not.
///
/// Returning [`effects::EffectDisposition::Unknown`] from `execute` is not an error path. It is the
/// honest answer when a dispatch crossed the boundary and no terminal could be observed, and it is
/// what stops recovery from ever replaying it.
pub(super) async fn broker_kernel_effect<Execute, ExecuteFuture, T>(
    rollout: &mut Rollout,
    admissions: &mut effect_admission::EffectAdmissions,
    effect: KernelEffect<'_>,
    execute: Execute,
) -> Result<effects::BrokeredOutcome<T>, effects::BrokerError>
where
    Execute: FnOnce() -> ExecuteFuture,
    ExecuteFuture: std::future::Future<Output = effects::EffectDisposition<T>>,
{
    let KernelEffect {
        turn,
        class,
        ordinal,
        capability,
        audit_arguments,
        workspace,
    } = effect;
    let brokered = effects::BrokeredEffect {
        turn,
        effect_id: effect_class::effect_id(turn, class, ordinal),
        tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
        kind: effect_class_label(class).to_string(),
        capability,
        audit_arguments,
        workspace: effect_workspace(workspace),
        provider_route_attempt: None,
    };
    effects::broker_effect(rollout, admissions, brokered, execute).await
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
