//! Total one-to-one registry from public optimization modules to production consumer stages.
//!
//! Nine typed consumer ports remain the host composition boundary, but replacement identity is
//! never the port: all twenty-eight modules have their own ordered stage, provider lifecycle and
//! consumption evidence.

use super::schema::CoreSlot;
use iteron_tunables::{ModuleId, ProductionPortId, module_port};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ModulePort {
    pub module: ModuleId,
    pub production_port: ProductionPortId,
    pub core_slot: CoreSlot,
    /// Stable zero-based order among modules feeding the same typed consumer.
    pub stage: u8,
}

const fn core_slot_for_port(port: ProductionPortId) -> CoreSlot {
    match port {
        ProductionPortId::Context => CoreSlot::Context,
        ProductionPortId::ToolPolicy => CoreSlot::ToolPolicy,
        ProductionPortId::Memory => CoreSlot::Memory,
        ProductionPortId::Router => CoreSlot::Router,
        ProductionPortId::Planner => CoreSlot::Planner,
        ProductionPortId::Collaboration => CoreSlot::Collaboration,
        ProductionPortId::Scheduler => CoreSlot::Scheduler,
        ProductionPortId::Verifier => CoreSlot::Verifier,
        ProductionPortId::ModelRouter => CoreSlot::ModelRouter,
    }
}

pub(super) fn module_ports() -> Vec<ModulePort> {
    let mut next = BTreeMap::<ProductionPortId, u8>::new();
    ModuleId::ALL
        .into_iter()
        .map(|module| {
            let production_port = module_port(module);
            let stage = next.entry(production_port).or_default();
            let row = ModulePort {
                module,
                production_port,
                core_slot: core_slot_for_port(production_port),
                stage: *stage,
            };
            *stage = (*stage).saturating_add(1);
            row
        })
        .collect()
}

pub(super) fn module_port_for(module: ModuleId) -> ModulePort {
    module_ports()
        .into_iter()
        .find(|row| row.module == module)
        .expect("ModuleId::ALL has one total production port registry")
}

pub(super) fn core_slot(module: ModuleId) -> CoreSlot {
    module_port_for(module).core_slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_module_has_one_independent_ordered_port_stage() {
        let rows = module_ports();
        assert_eq!(rows.len(), ModuleId::ALL.len());
        assert_eq!(
            rows.iter().map(|row| row.module).collect::<Vec<_>>(),
            ModuleId::ALL
        );
        assert_eq!(
            rows.iter()
                .map(|row| (row.production_port, row.stage))
                .collect::<BTreeSet<_>>()
                .len(),
            ModuleId::ALL.len()
        );
    }

    #[test]
    fn all_typed_host_ports_are_consumed() {
        let used = module_ports()
            .into_iter()
            .map(|row| row.core_slot)
            .collect::<BTreeSet<_>>();
        assert_eq!(used, CoreSlot::ALL.into_iter().collect());
    }
}
