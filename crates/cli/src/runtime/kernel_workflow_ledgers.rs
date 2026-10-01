//! Bounded exact native accounting collected from actually constructed workflow children.
//! A missing observation is separate from an Unknown physical execution.
use iteron_obs::Ledger;
use iteron_protocol::{RunId, TenantId, WorkflowChildOutcome};
use std::{collections::BTreeMap, sync::Arc};
const PER_RECEIPT: usize = 1024 * 1024;
const AGGREGATE: usize = 8 * 1024 * 1024;
pub(super) struct NativeWorkflowLedger {
    ordinal: u64,
    tenant: TenantId,
    run: RunId,
    ledger: Arc<Ledger>,
    outcome: WorkflowChildOutcome,
}
impl NativeWorkflowLedger {
    pub(super) fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub(super) fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub(super) fn run(&self) -> &RunId {
        &self.run
    }
    pub(super) fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub(super) fn outcome(&self) -> WorkflowChildOutcome {
        self.outcome.clone()
    }
}
enum Observation {
    Running,
    Unknown,
    Unavailable,
    Known(NativeWorkflowLedger),
}
#[derive(Default)]
pub(super) struct KernelWorkflowLedgers {
    entries: BTreeMap<u64, Observation>,
    bytes: usize,
}
impl KernelWorkflowLedgers {
    pub(super) fn has_admissions(&self) -> bool {
        !self.entries.is_empty()
    }
    pub(super) fn begin(&mut self, ordinal: u64) -> Result<(), &'static str> {
        if self.entries.len() >= 1000 || self.entries.contains_key(&ordinal) {
            return Err("native workflow accounting capacity");
        }
        self.entries.insert(ordinal, Observation::Running);
        Ok(())
    }
    pub(super) fn complete(
        &mut self,
        ordinal: u64,
        tenant: &TenantId,
        run: &RunId,
        ledger: &Ledger,
        outcome: WorkflowChildOutcome,
        effects_known: bool,
    ) {
        let Some(current) = self.entries.get_mut(&ordinal) else {
            return;
        };
        if !matches!(current, Observation::Running) {
            return;
        }
        if !effects_known {
            *current = Observation::Unknown;
            return;
        }
        let weight = ledger
            .bounded_snapshot_bytes(PER_RECEIPT)
            .and_then(|value| value.checked_add(tenant.0.len()))
            .and_then(|value| value.checked_add(run.0.len()));
        let valid_scope = [&tenant.0, &run.0].iter().all(|text| {
            !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control)
        });
        let Some(weight) = weight.filter(|value| {
            valid_scope
                && *value <= PER_RECEIPT
                && self
                    .bytes
                    .checked_add(*value)
                    .is_some_and(|total| total <= AGGREGATE)
        }) else {
            *current = Observation::Unavailable;
            return;
        };
        *current = Observation::Known(NativeWorkflowLedger {
            ordinal,
            tenant: tenant.clone(),
            run: run.clone(),
            ledger: Arc::new(ledger.clone()),
            outcome,
        });
        self.bytes += weight;
    }
    pub(super) fn effects_known(&self) -> bool {
        self.entries
            .values()
            .all(|entry| matches!(entry, Observation::Known(_) | Observation::Unavailable))
    }
    pub(super) fn take_known(&mut self) -> Result<Vec<NativeWorkflowLedger>, &'static str> {
        if !self.effects_known() {
            return Err("native workflow physical cleanup is unresolved");
        }
        if self
            .entries
            .values()
            .any(|entry| matches!(entry, Observation::Unavailable))
        {
            return Err("native workflow accounting evidence is unavailable");
        }
        let entries = std::mem::take(&mut self.entries);
        self.bytes = 0;
        Ok(entries
            .into_values()
            .filter_map(|entry| match entry {
                Observation::Known(receipt) => Some(receipt),
                _ => None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_native_capture_keeps_unknown_and_unavailable_distinct() {
        let mut owner = KernelWorkflowLedgers::default();
        owner.begin(0).unwrap();
        assert!(!owner.effects_known());
        owner.complete(
            0,
            &TenantId("actual-tenant".into()),
            &RunId("actual-child".into()),
            &Ledger::default(),
            WorkflowChildOutcome::Failed,
            true,
        );
        assert!(owner.effects_known());
        let receipt = owner.take_known().unwrap().pop().unwrap();
        assert_eq!(receipt.ordinal(), 0);
        assert_eq!(receipt.run().0, "actual-child");
        owner.begin(1).unwrap();
        owner.complete(
            1,
            &TenantId("actual-tenant".into()),
            &RunId("actual-child".into()),
            &Ledger::default(),
            WorkflowChildOutcome::Failed,
            false,
        );
        assert!(!owner.effects_known());
        assert!(owner.take_known().is_err());
        let mut observation = KernelWorkflowLedgers::default();
        observation.begin(0).unwrap();
        observation.complete(
            0,
            &TenantId("bad\nlabel".into()),
            &RunId("actual-child".into()),
            &Ledger::default(),
            WorkflowChildOutcome::Failed,
            true,
        );
        assert!(observation.effects_known());
        assert!(observation.take_known().is_err());
    }
}
