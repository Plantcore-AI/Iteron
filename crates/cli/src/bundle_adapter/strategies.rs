use super::schema::{CoreSlot, ImplementationFlavor};
use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot};
use std::sync::Arc;

pub(crate) struct CompiledSlots {
    pub context: Arc<dyn StrategySlot>,
    pub tool_policy: Arc<dyn StrategySlot>,
    pub memory: Arc<dyn StrategySlot>,
    pub router: Arc<dyn StrategySlot>,
    pub planner: Arc<dyn StrategySlot>,
    pub collaboration: Arc<dyn StrategySlot>,
    pub scheduler: Arc<dyn StrategySlot>,
    pub verifier: Arc<dyn StrategySlot>,
    pub model_router: Arc<dyn StrategySlot>,
}

impl CompiledSlots {
    pub(crate) fn baseline() -> Self {
        Self {
            context: instantiate(CoreSlot::Context, ImplementationFlavor::Baseline),
            tool_policy: instantiate(CoreSlot::ToolPolicy, ImplementationFlavor::Baseline),
            memory: instantiate(CoreSlot::Memory, ImplementationFlavor::Baseline),
            router: instantiate(CoreSlot::Router, ImplementationFlavor::Baseline),
            planner: instantiate(CoreSlot::Planner, ImplementationFlavor::Baseline),
            collaboration: instantiate(CoreSlot::Collaboration, ImplementationFlavor::Baseline),
            scheduler: instantiate(CoreSlot::Scheduler, ImplementationFlavor::Baseline),
            verifier: instantiate(CoreSlot::Verifier, ImplementationFlavor::Baseline),
            model_router: instantiate(CoreSlot::ModelRouter, ImplementationFlavor::Baseline),
        }
    }

    pub(crate) fn replace(&mut self, slot: CoreSlot, implementation: Arc<dyn StrategySlot>) {
        match slot {
            CoreSlot::Context => self.context = implementation,
            CoreSlot::ToolPolicy => self.tool_policy = implementation,
            CoreSlot::Memory => self.memory = implementation,
            CoreSlot::Router => self.router = implementation,
            CoreSlot::Planner => self.planner = implementation,
            CoreSlot::Collaboration => self.collaboration = implementation,
            CoreSlot::Scheduler => self.scheduler = implementation,
            CoreSlot::Verifier => self.verifier = implementation,
            CoreSlot::ModelRouter => self.model_router = implementation,
        }
    }
}

pub(crate) const fn implementation_name(
    slot: CoreSlot,
    flavor: ImplementationFlavor,
) -> &'static str {
    match (slot, flavor) {
        (CoreSlot::Context, ImplementationFlavor::Baseline) => "context.baseline.v1",
        (CoreSlot::Context, ImplementationFlavor::Alternative) => "context.minimal.v1",
        (CoreSlot::ToolPolicy, ImplementationFlavor::Baseline) => "tool_policy.baseline.v1",
        (CoreSlot::ToolPolicy, ImplementationFlavor::Alternative) => "tool_policy.read_only.v1",
        (CoreSlot::Memory, ImplementationFlavor::Baseline) => "memory.baseline.v1",
        (CoreSlot::Memory, ImplementationFlavor::Alternative) => "memory.single_recall.v1",
        (CoreSlot::Router, ImplementationFlavor::Baseline) => "router.baseline.v1",
        (CoreSlot::Router, ImplementationFlavor::Alternative) => "router.direct_only.v1",
        (CoreSlot::Planner, ImplementationFlavor::Baseline) => "planner.baseline.v1",
        (CoreSlot::Planner, ImplementationFlavor::Alternative) => "planner.single_leaf.v1",
        (CoreSlot::Collaboration, ImplementationFlavor::Baseline) => "collaboration.baseline.v1",
        (CoreSlot::Collaboration, ImplementationFlavor::Alternative) => "collaboration.serial.v1",
        (CoreSlot::Scheduler, ImplementationFlavor::Baseline) => "scheduler.baseline.v1",
        (CoreSlot::Scheduler, ImplementationFlavor::Alternative) => "scheduler.serial.v1",
        (CoreSlot::Verifier, ImplementationFlavor::Baseline) => "verifier.baseline.v1",
        (CoreSlot::Verifier, ImplementationFlavor::Alternative) => "verifier.workspace_gate.v1",
        (CoreSlot::ModelRouter, ImplementationFlavor::Baseline) => "model_router.baseline.v1",
        (CoreSlot::ModelRouter, ImplementationFlavor::Alternative) => "model_router.bound_route.v1",
    }
}

pub(crate) fn instantiate(slot: CoreSlot, flavor: ImplementationFlavor) -> Arc<dyn StrategySlot> {
    match (slot, flavor) {
        (CoreSlot::Context, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_ctx::ContextStrategy::default())
        }
        (CoreSlot::Context, ImplementationFlavor::Alternative) => Arc::new(MinimalContext),
        (CoreSlot::ToolPolicy, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_tools::ToolPolicy::default())
        }
        (CoreSlot::ToolPolicy, ImplementationFlavor::Alternative) => Arc::new(ReadOnlyToolPolicy),
        (CoreSlot::Memory, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_ctx::MemoryRecallStrategy::default())
        }
        (CoreSlot::Memory, ImplementationFlavor::Alternative) => Arc::new(SingleRecallMemory),
        (CoreSlot::Router, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_agents::RouterStrategy::default())
        }
        (CoreSlot::Router, ImplementationFlavor::Alternative) => Arc::new(DirectRouter),
        (CoreSlot::Planner, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_agents::PlannerStrategy::default())
        }
        (CoreSlot::Planner, ImplementationFlavor::Alternative) => Arc::new(SingleLeafPlanner),
        (CoreSlot::Collaboration, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_workflow::CollaborationStrategy::default())
        }
        (CoreSlot::Collaboration, ImplementationFlavor::Alternative) => {
            Arc::new(SerialCollaboration)
        }
        (CoreSlot::Scheduler, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_sched::SchedulerStrategy::default())
        }
        (CoreSlot::Scheduler, ImplementationFlavor::Alternative) => Arc::new(SerialScheduler),
        (CoreSlot::Verifier, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_verify::VerifierStrategy::default())
        }
        (CoreSlot::Verifier, ImplementationFlavor::Alternative) => Arc::new(StrictVerifier),
        (CoreSlot::ModelRouter, ImplementationFlavor::Baseline) => {
            Arc::new(iteron_provider::catalog::ModelRouterStrategy::default())
        }
        (CoreSlot::ModelRouter, ImplementationFlavor::Alternative) => Arc::new(BoundModelRouter),
    }
}

fn narrowed_baseline(
    baseline: &dyn StrategySlot,
    observation: &SlotObservation,
    payload: serde_json::Value,
) -> SlotOutcome {
    let narrowed = SlotObservation {
        slot: observation.slot.clone(),
        ceiling: observation.ceiling,
        payload,
    };
    let mut outcome = baseline.decide(&narrowed);
    outcome.admitted = outcome.admitted.intersect(observation.ceiling);
    outcome
}

fn baseline_is_decision(outcome: &SlotOutcome) -> bool {
    outcome.decision.get("kind").and_then(|kind| kind.as_str()) != Some("unknown")
}

macro_rules! unit_strategy {
    ($name:ident, $slot:expr) => {
        #[derive(Default)]
        struct $name;

        impl StrategySlot for $name {
            fn slot(&self) -> &SlotId {
                static SLOT: std::sync::OnceLock<SlotId> = std::sync::OnceLock::new();
                SLOT.get_or_init(|| SlotId($slot.to_owned()))
            }

            fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
                self.decide_narrowed(observation)
            }
        }
    };
}

unit_strategy!(MinimalContext, "core/context");
impl MinimalContext {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_ctx::ContextStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(mut input) =
            serde_json::from_value::<iteron_ctx::ContextSlotObservation>(observation.payload.clone())
        else {
            return first;
        };
        input.memory_keys.clear();
        input.transcript_turns = 0;
        input.include_environment = false;
        input.recall_memory = false;
        input.include_skills = false;
        narrowed_baseline(&baseline, observation, json(input, first))
    }
}

unit_strategy!(ReadOnlyToolPolicy, "core/tool_policy");
impl ReadOnlyToolPolicy {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_tools::ToolPolicy::default();
        let mut outcome = baseline.decide(observation);
        let Ok(input) = serde_json::from_value::<iteron_tools::ToolPolicyObservation>(
            observation.payload.clone(),
        ) else {
            return outcome;
        };
        if input.registered.capability != Capability::ReadOnly {
            outcome.admitted = CapabilitySet::none();
        }
        outcome.admitted = outcome.admitted.intersect(observation.ceiling);
        outcome
    }
}

unit_strategy!(SingleRecallMemory, "core/memory");
impl SingleRecallMemory {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_ctx::MemoryRecallStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(mut input) =
            serde_json::from_value::<iteron_ctx::MemorySlotObservation>(observation.payload.clone())
        else {
            return first;
        };
        if input.write.is_none() {
            input.max_recalled = input.max_recalled.min(1);
        }
        narrowed_baseline(&baseline, observation, json(input, first))
    }
}

unit_strategy!(DirectRouter, "core/router");
impl DirectRouter {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_agents::RouterStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(input) = serde_json::from_value::<iteron_agents::RouterSlotObservation>(
            observation.payload.clone(),
        ) else {
            return first;
        };
        narrowed_baseline(&baseline, observation, json(input.without_fan_out(), first))
    }
}

unit_strategy!(SingleLeafPlanner, "core/planner");
impl SingleLeafPlanner {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_agents::PlannerStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(mut input) =
            serde_json::from_value::<iteron_agents::PlannerObservation>(observation.payload.clone())
        else {
            return first;
        };
        input.max_leaves = input.max_leaves.min(1);
        narrowed_baseline(&baseline, observation, json(input, first))
    }
}

unit_strategy!(SerialCollaboration, "core/collaboration");
impl SerialCollaboration {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_workflow::CollaborationStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(mut input) = serde_json::from_value::<iteron_workflow::CollaborationObservation>(
            observation.payload.clone(),
        ) else {
            return first;
        };
        input.max_concurrency = 1;
        narrowed_baseline(&baseline, observation, json(input, first))
    }
}

unit_strategy!(SerialScheduler, "core/scheduler");
impl SerialScheduler {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_sched::SchedulerStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let Ok(mut input) = serde_json::from_value::<iteron_sched::SchedulerSlotObservation>(
            observation.payload.clone(),
        ) else {
            return first;
        };
        input.max_attempts = 1;
        input.max_concurrency = 1;
        narrowed_baseline(&baseline, observation, json(input, first))
    }
}

unit_strategy!(StrictVerifier, "core/verifier");
impl StrictVerifier {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_verify::VerifierStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let strict = iteron_verify::WorkspaceGateVerifier::default();
        let mut outcome = strict.decide(observation);
        outcome.admitted = outcome.admitted.intersect(observation.ceiling);
        outcome
    }
}

unit_strategy!(BoundModelRouter, "core/model_router");
impl BoundModelRouter {
    fn decide_narrowed(&self, observation: &SlotObservation) -> SlotOutcome {
        let baseline = iteron_provider::catalog::ModelRouterStrategy::default();
        let first = baseline.decide(observation);
        if !baseline_is_decision(&first) {
            return first;
        }
        let bound = iteron_provider::catalog::BoundRouteOnlyModelRouter::default();
        let mut outcome = bound.decide(observation);
        outcome.admitted = outcome.admitted.intersect(observation.ceiling);
        outcome
    }
}

fn json<T: serde::Serialize>(value: T, fallback: SlotOutcome) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(fallback.decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::slot::decide_narrowed;

    fn bound(slots: &CompiledSlots) -> Vec<(CoreSlot, &Arc<dyn StrategySlot>)> {
        vec![
            (CoreSlot::Context, &slots.context),
            (CoreSlot::ToolPolicy, &slots.tool_policy),
            (CoreSlot::Memory, &slots.memory),
            (CoreSlot::Router, &slots.router),
            (CoreSlot::Planner, &slots.planner),
            (CoreSlot::Collaboration, &slots.collaboration),
            (CoreSlot::Scheduler, &slots.scheduler),
            (CoreSlot::Verifier, &slots.verifier),
            (CoreSlot::ModelRouter, &slots.model_router),
        ]
    }

    /// Every iteron slot is bound, at the composition root, to an implementation that claims that
    /// same identity.
    ///
    /// This is the claim the replaceable-strategy design rests on, and nothing else asserted it.
    /// A slot quietly reverting to an unbound or mis-identified implementation would hollow out
    /// the seam while every other test kept passing, which is exactly how the specification came
    /// to describe this seam as empty long after it had been filled.
    #[test]
    fn every_core_slot_is_bound_to_an_implementation_claiming_that_slot() {
        let slots = CompiledSlots::baseline();
        let bound = bound(&slots);

        // Exhaustive over the registry, not over whichever fields someone remembered to list.
        let listed: Vec<_> = bound.iter().map(|(slot, _)| *slot).collect();
        assert_eq!(listed, CoreSlot::ALL.to_vec());

        for (slot, implementation) in bound {
            assert_eq!(
                implementation.slot(),
                &SlotId(slot.as_str().to_owned()),
                "`{}` is bound to an implementation that reports a different identity",
                slot.as_str()
            );
        }
    }

    /// The narrowing contract, exercised against the production implementations.
    ///
    /// Until now this was proven only against a test double written to over-reach on purpose. A
    /// slot is a policy and never a source of authority, so no production implementation may
    /// return more than the ceiling it was handed, including when that ceiling is empty.
    #[test]
    fn no_production_slot_widens_the_ceiling_it_was_given() {
        let slots = CompiledSlots::baseline();
        for (slot, implementation) in bound(&slots) {
            for ceiling in [
                CapabilitySet::none(),
                CapabilitySet::only(Capability::ReadOnly),
            ] {
                let outcome = decide_narrowed(
                    implementation.as_ref(),
                    &SlotObservation {
                        slot: SlotId(slot.as_str().to_owned()),
                        ceiling,
                        payload: serde_json::Value::Null,
                    },
                );
                assert!(
                    outcome.admitted.is_subset_of(ceiling),
                    "`{}` admitted capabilities outside its ceiling",
                    slot.as_str()
                );
            }
        }
    }
}
