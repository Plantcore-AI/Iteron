//! Actual bounded memory visibility owner and native prepared-request exposure projection.
//! Only the same trusted request factory's opaque inclusion witness advances memory to Used.
use super::provider_route_events::ProviderRouteEvents;
use super::request_manifest::RequestManifestFactory;
use iteron_ctx::{MemoryTraceStore, MemoryVisibilityEvidence, MemoryVisibilityState};
use iteron_protocol::{LifecyclePayload, TurnId};
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct MemoryVisibilityOwner {
    entries: VecDeque<MemoryVisibilityEvidence>,
}
impl MemoryVisibilityOwner {
    pub(super) fn schedule(&mut self, evidence: MemoryVisibilityEvidence) {
        if self.entries.len() == iteron_ctx::MAX_MEMORY_TRACE_VISIBILITY {
            self.entries.pop_front();
        }
        self.entries.push_back(evidence);
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
    pub(super) fn activate(&mut self, turn: TurnId) -> Vec<MemoryVisibilityEvidence> {
        self.transition(
            turn,
            MemoryVisibilityState::Scheduled,
            MemoryVisibilityState::Activated,
        )
    }
    fn used(&mut self, turn: TurnId) -> Vec<MemoryVisibilityEvidence> {
        self.transition(
            turn,
            MemoryVisibilityState::Activated,
            MemoryVisibilityState::Used,
        )
    }
    fn unused(&mut self, turn: TurnId) -> Vec<MemoryVisibilityEvidence> {
        self.transition(
            turn,
            MemoryVisibilityState::Activated,
            MemoryVisibilityState::Unused,
        )
    }
    fn transition(
        &mut self,
        turn: TurnId,
        from: MemoryVisibilityState,
        to: MemoryVisibilityState,
    ) -> Vec<MemoryVisibilityEvidence> {
        self.entries
            .iter_mut()
            .filter(|e| e.destination_turn == turn && e.state == from)
            .map(|e| {
                e.state = to;
                e.clone()
            })
            .collect()
    }
    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &MemoryVisibilityEvidence> {
        self.entries.iter()
    }
}

pub(super) struct MemoryRequestExposure<'a> {
    pub(super) visibility: &'a mut MemoryVisibilityOwner,
    pub(super) memory_traces: &'a MemoryTraceStore,
    pub(super) events: ProviderRouteEvents,
}
impl MemoryRequestExposure<'_> {
    pub(super) fn prepared(&mut self, factory: &RequestManifestFactory) {
        if factory.context_inclusion_confirmed() {
            self.confirmed(self.events.turn);
        }
    }
    fn confirmed(&mut self, turn: TurnId) {
        let used = self.visibility.used(turn);
        for evidence in &used {
            iteron_ctx::MemoryObserver::observe(
                self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Visibility(evidence.clone()),
            );
            iteron_ctx::MemoryObserver::observe(
                self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Attribution(iteron_ctx::MemoryAttributionEvidence {
                    fact_id: evidence.fact_id,
                    cited: false,
                    used_by_tool: false,
                    later_turns_visible: 1,
                }),
            );
        }

        // Attribute stable recalled memory only after the actual prepared-buffer proof.
        let recalled = self
            .memory_traces
            .snapshot()
            .traces
            .into_iter()
            .find(|trace| trace.turn_id == turn)
            .filter(|trace| trace.injection.is_some() && trace.attribution.is_empty())
            .map(|trace| trace.selected)
            .unwrap_or_default();
        for selection in &recalled {
            iteron_ctx::MemoryObserver::observe(
                self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Attribution(iteron_ctx::MemoryAttributionEvidence {
                    fact_id: selection.fact_id,
                    cited: false,
                    used_by_tool: false,
                    later_turns_visible: 0,
                }),
            );
        }
        let count = u64::try_from(used.len().saturating_add(recalled.len())).unwrap_or(u64::MAX);
        if count > 0 {
            for event_id in ["memory.recall.used", "memory.attribution.recorded"] {
                self.events.emit(
                    event_id,
                    LifecyclePayload {
                        count: Some(count),
                        reason_code: Some("serialized_request_inclusion_confirmed".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }

    pub(super) fn refused(&mut self) {
        self.observe_memory_without_inclusion(self.events.turn, "provider_dispatch_refused");
    }

    pub(super) fn unconfirmed(&mut self) {
        self.observe_memory_without_inclusion(
            self.events.turn,
            "serialized_request_inclusion_unconfirmed",
        );
    }

    fn observe_memory_without_inclusion(&mut self, turn: TurnId, reason: &'static str) {
        let unused = self.visibility.unused(turn);
        let mut count = u64::try_from(unused.len()).unwrap_or(u64::MAX);
        for evidence in unused {
            iteron_ctx::MemoryObserver::observe(
                self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Visibility(evidence),
            );
        }
        let recalled = self
            .memory_traces
            .snapshot()
            .traces
            .into_iter()
            .find(|trace| trace.turn_id == turn)
            .and_then(|trace| trace.injection)
            .map(|injection| u64::from(injection.fact_count))
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.decision_observability.no_recalled_facts",
                0_u64,
            ));
        count = count.saturating_add(recalled);
        if count > 0 {
            self.events.emit(
                "memory.recall.unused",
                LifecyclePayload {
                    count: Some(count),
                    reason_code: Some(reason.into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }
}
