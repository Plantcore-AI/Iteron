//! Total projection from optimization modules to production strategy slots.

use super::schema::CoreSlot;
use iteron_tunables::ModuleId;

pub(super) const fn core_slot(module: ModuleId) -> CoreSlot {
    match module {
        ModuleId::PromptSystem => CoreSlot::Context,
        ModuleId::PromptToolDescription => CoreSlot::ToolPolicy,
        ModuleId::PromptSubagent => CoreSlot::Router,
        ModuleId::PromptSkill => CoreSlot::Context,
        ModuleId::PromptCompaction => CoreSlot::Context,
        ModuleId::PromptVerification => CoreSlot::Verifier,
        ModuleId::PromptPlanner => CoreSlot::Planner,
        ModuleId::PromptReduce => CoreSlot::Collaboration,
        ModuleId::PromptMemoryWrite => CoreSlot::Memory,
        ModuleId::PromptRecovery => CoreSlot::Verifier,
        ModuleId::ContextAssembly | ModuleId::ContextCompaction => CoreSlot::Context,
        ModuleId::MemoryRecall => CoreSlot::Memory,
        ModuleId::ToolExposure
        | ModuleId::ToolArguments
        | ModuleId::ToolEditStrategy
        | ModuleId::ToolSearchStrategy => CoreSlot::ToolPolicy,
        ModuleId::ProviderRouting
        | ModuleId::ProviderSampling
        | ModuleId::ProviderRetry
        | ModuleId::ProviderPromptCache => CoreSlot::ModelRouter,
        ModuleId::SchedulerParallelism => CoreSlot::Scheduler,
        ModuleId::PlannerFanout => CoreSlot::Planner,
        ModuleId::VerificationQuorum => CoreSlot::Verifier,
        ModuleId::BudgetAllocation | ModuleId::SessionStop => CoreSlot::Router,
        ModuleId::SessionCheckpoint | ModuleId::SessionFork => CoreSlot::Collaboration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_module_has_a_slot() {
        let mapped = ModuleId::ALL.map(core_slot);
        assert_eq!(mapped.len(), ModuleId::ALL.len());
    }

    #[test]
    fn every_core_slot_is_used() {
        let used = ModuleId::ALL
            .map(core_slot)
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(used, CoreSlot::ALL.into_iter().collect());
    }
}
