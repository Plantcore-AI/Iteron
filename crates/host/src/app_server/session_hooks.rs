//! Durable session hook journal, bounded Stop observer and canonical dispatcher composition.

use super::{Agent, LifecyclePayload, ServerEnds};

pub(super) struct SessionHooks {
    pub(super) hook_journal: Option<crate::runtime::hooks::journal::HookEffectJournal>,
    pub(super) stop_hooks: Option<crate::runtime::hooks::StopHookObserverRuntime>,
    pub(super) lifecycle_hook_runtime: crate::runtime::lifecycle_hooks::LifecycleHookRuntime,
}

impl SessionHooks {
    pub(super) fn install(agent: &mut Agent, ends: &mut ServerEnds) -> Self {
        let lifecycle_gate_hooks = agent.hooks.clone();
        let requires_hook_journal = !lifecycle_gate_hooks.is_empty() || ends.plantcore.is_enabled();
        let mut recovered_unknown = 0;
        let hook_journal = if !requires_hook_journal {
            None
        } else {
            match crate::runtime::hooks::journal::HookEffectJournal::open(
                &agent.rollout.path().with_extension("hooks.jsonl"),
            ) {
                Ok(journal) => {
                    recovered_unknown = journal.recovered_unknown();
                    Some(journal)
                }
                Err(_) => {
                    ends.events.record_lifecycle(
                        "hook.failed",
                        None,
                        None,
                        LifecyclePayload {
                            reason_code: Some("durable_journal_unavailable".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    None
                }
            }
        };
        agent.set_hook_effect_journal(hook_journal.clone());
        let stop_hooks = hook_journal.clone().map(|journal| {
            crate::runtime::hooks::StopHookObserverRuntime::start(lifecycle_gate_hooks, journal)
        });
        if let Some(observer) = &stop_hooks {
            agent
                .hooks
                .install_stop_observer(observer.dispatcher.clone());
        }
        let (lifecycle_hooks, lifecycle_hook_runtime) =
            crate::runtime::lifecycle_hooks::LifecycleHookDispatcher::start(
                agent.hooks.clone(),
                ends.events.lifecycle_emitter(),
                ends.events.lifecycle_correlation(None, None),
                hook_journal.clone(),
                ends.hook_health.clone(),
            );
        ends.events.bind_lifecycle_hooks(lifecycle_hooks.clone());
        ends.events.record_lifecycle(
            "queue.capacity_resolved",
            None,
            None,
            LifecyclePayload {
                count: Some(
                    u64::try_from(ends.events.queue_policy.submission_entries())
                        .unwrap_or(u64::MAX),
                ),
                magnitude: Some(
                    u64::try_from(ends.events.queue_policy.submission_bytes()).unwrap_or(u64::MAX),
                ),
                ..LifecyclePayload::default()
            },
        );
        agent.set_lifecycle_hooks(lifecycle_hooks);
        if recovered_unknown > 0 {
            ends.events.record_lifecycle(
                "hook.failed",
                None,
                None,
                LifecyclePayload {
                    count: Some(recovered_unknown),
                    reason_code: Some("recovered_unknown_effect".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        Self {
            hook_journal,
            stop_hooks,
            lifecycle_hook_runtime,
        }
    }
}
