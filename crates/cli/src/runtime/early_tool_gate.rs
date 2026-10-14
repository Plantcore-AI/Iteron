//! Bounded hook predispatch coordinator. Journal effect intents remain with the caller;
//! configured hook processes run only through the explicit immutable operator policy ports.

use super::hooks;
use super::hooks::{HookDecision, HookEvent, Hooks};

#[derive(Debug, Clone, Copy)]
pub(super) struct EarlyHookSummary {
    pub(super) completed: u32,
    pub(super) failed: u32,
    pub(super) timed_out: u32,
    pub(super) lifecycle_dispatch_failed: bool,
}

pub(super) struct EarlyHookRefusal {
    pub(super) reason: String,
    pub(super) summary: EarlyHookSummary,
}

pub(super) struct EarlyHookGateContext<'a> {
    pub(super) journal: Option<&'a hooks::journal::HookEffectJournal>,
    pub(super) compatibility_enabled: bool,
    pub(super) lifecycle_enabled: bool,
    pub(super) compatibility_json: &'a str,
    pub(super) lifecycle_json: &'a str,
    pub(super) interrupt: Option<&'a std::sync::atomic::AtomicBool>,
    pub(super) drain: &'a std::sync::atomic::AtomicBool,
}

/// Execute an early read's blocking tool gates only after the caller has fsynced the matching
/// kernel effect intents. This has the same role as the app-server gate of the same name: the
/// caller owns the universal effect tickets, while this helper owns the bounded journaled process
/// dispatch. Keeping it separate lets the provider callback start the future without lending the
/// spawned task mutable access to the rollout.
pub(super) async fn run_lifecycle_gate(
    hooks: &Hooks,
    context: EarlyHookGateContext<'_>,
) -> Result<Option<EarlyHookSummary>, EarlyHookRefusal> {
    if !context.compatibility_enabled && !context.lifecycle_enabled {
        return Ok(None);
    }
    let Some(journal) = context.journal else {
        return Err(EarlyHookRefusal {
            reason: "tool gate hook journal is unavailable; the read was not started".into(),
            summary: EarlyHookSummary {
                completed: 0,
                failed: 1,
                timed_out: 0,
                lifecycle_dispatch_failed: context.lifecycle_enabled,
            },
        });
    };
    let compatibility = if context.compatibility_enabled {
        Some(
            hooks
                .run_cancellable_journaled_report(
                    HookEvent::PreToolUse,
                    context.compatibility_json,
                    context.interrupt,
                    Some(context.drain),
                    journal,
                )
                .await,
        )
    } else {
        None
    };
    let lifecycle = if context.lifecycle_enabled {
        Some(
            hooks
                .run_lifecycle_cancellable_journaled(
                    "tool.call_proposed",
                    context.lifecycle_json,
                    context.interrupt,
                    Some(context.drain),
                    journal,
                )
                .await,
        )
    } else {
        None
    };
    let lifecycle_report = lifecycle.as_ref().and_then(|value| value.as_ref().ok());
    let summary = EarlyHookSummary {
        completed: compatibility
            .as_ref()
            .map_or(0, |report| report.completed)
            .saturating_add(lifecycle_report.map_or(0, |report| report.completed)),
        failed: compatibility
            .as_ref()
            .map_or(0, |report| report.failed)
            .saturating_add(lifecycle_report.map_or(0, |report| report.failed))
            .saturating_add(u32::from(lifecycle.as_ref().is_some_and(Result::is_err))),
        timed_out: compatibility
            .as_ref()
            .map_or(0, |report| report.timed_out)
            .saturating_add(lifecycle_report.map_or(0, |report| report.timed_out)),
        lifecycle_dispatch_failed: lifecycle.as_ref().is_some_and(Result::is_err),
    };
    let denial = compatibility
        .as_ref()
        .and_then(|report| match &report.decision {
            HookDecision::Allow => None,
            HookDecision::Deny(reason) => Some(reason.clone()),
        })
        .or_else(|| {
            lifecycle_report.and_then(|report| match &report.decision {
                HookDecision::Allow => None,
                HookDecision::Deny(reason) => Some(reason.clone()),
            })
        })
        .or_else(|| {
            lifecycle
                .as_ref()
                .and_then(|result| result.as_ref().err().map(|reason| (*reason).to_owned()))
        })
        .or_else(|| {
            (summary.failed > 0 || summary.timed_out > 0)
                .then(|| "tool gate hook did not produce a complete allow decision".to_owned())
        });
    match denial {
        Some(reason) => Err(EarlyHookRefusal { reason, summary }),
        None => Ok(Some(summary)),
    }
}
