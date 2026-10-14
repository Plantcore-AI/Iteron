//! Frozen native child accounting. Private host receipts correlate the exact physical tenant/run
//! and controller epoch after actual cleanup; no scalar completion or model text can mint a ledger.
use iteron_agents::ControllerError;
use iteron_obs::Ledger;
use iteron_protocol::agent_control::{AgentEpochV1, AgentIdV1};
use iteron_protocol::{RunId, TenantId};
use std::{collections::BTreeMap, sync::Arc};
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AgentRuntimeLedger {
    agent: AgentIdV1,
    epoch: AgentEpochV1,
    tenant: TenantId,
    run: RunId,
    ledger: Arc<Ledger>,
    retained_bytes: usize,
}
impl AgentRuntimeLedger {
    pub(super) fn agent(&self) -> AgentIdV1 {
        self.agent
    }
    pub(super) fn epoch(&self) -> AgentEpochV1 {
        self.epoch
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
}
#[derive(Default)]
pub(super) struct CompletedChildLedgers {
    snapshots: BTreeMap<AgentIdV1, AgentRuntimeLedger>,
    retained_bytes: usize,
}
impl CompletedChildLedgers {
    pub(super) fn capture(
        &mut self,
        agent: AgentIdV1,
        epoch: AgentEpochV1,
        tenant: &TenantId,
        run: &RunId,
        ledger: &Ledger,
    ) -> Result<(), ControllerError> {
        if agent.0 == 0
            || epoch.incarnation == 0
            || epoch.turn == 0
            || !valid_scope(&run.0)
            || !valid_scope(&tenant.0)
        {
            return Err(ControllerError::Invalid(
                "invalid native child ledger scope",
            ));
        }
        if !self.snapshots.contains_key(&agent) && self.snapshots.len() >= 64 {
            return Err(ControllerError::Capacity);
        }
        if let Some(old) = self.snapshots.get(&agent)
            && (epoch.incarnation < old.epoch.incarnation
                || (epoch.incarnation == old.epoch.incarnation && epoch.turn <= old.epoch.turn))
        {
            return Err(ControllerError::StaleEpoch);
        }
        let retained_bytes = ledger
            .bounded_snapshot_bytes(MAX_RECEIPT_BYTES)
            .ok_or(ControllerError::Capacity)?
            .checked_add(tenant.0.len())
            .and_then(|value| value.checked_add(run.0.len()))
            .ok_or(ControllerError::Capacity)?;
        if retained_bytes > MAX_RECEIPT_BYTES {
            return Err(ControllerError::Capacity);
        }
        let previous = self
            .snapshots
            .get(&agent)
            .map_or(0, |receipt| receipt.retained_bytes);
        let aggregate = self
            .retained_bytes
            .checked_sub(previous)
            .and_then(|value| value.checked_add(retained_bytes))
            .filter(|value| *value <= MAX_RETAINED_BYTES)
            .ok_or(ControllerError::Capacity)?;
        self.snapshots.insert(
            agent,
            AgentRuntimeLedger {
                agent,
                epoch,
                tenant: tenant.clone(),
                run: run.clone(),
                ledger: Arc::new(ledger.clone()),
                retained_bytes,
            },
        );
        self.retained_bytes = aggregate;
        Ok(())
    }
    pub(super) fn read(&self, agent: AgentIdV1, epoch: AgentEpochV1) -> Option<AgentRuntimeLedger> {
        self.snapshots
            .get(&agent)
            .filter(|receipt| receipt.epoch == epoch)
            .cloned()
    }
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_frozen_snapshot_requires_exact_epoch_and_scope() {
        let mut owner = CompletedChildLedgers::default();
        let epoch = AgentEpochV1 {
            incarnation: 1,
            turn: 1,
        };
        let tenant = TenantId("actual-tenant".into());
        let run = RunId("actual-child".into());
        let mut ledger = Ledger::new();
        owner
            .capture(AgentIdV1(2), epoch, &tenant, &run, &ledger)
            .unwrap();
        ledger.attempt();
        let receipt = owner.read(AgentIdV1(2), epoch).unwrap();
        assert_eq!(receipt.agent(), AgentIdV1(2));
        assert_eq!(receipt.epoch(), epoch);
        assert_eq!(receipt.tenant(), &tenant);
        assert_eq!(receipt.run(), &run);
        assert_eq!(receipt.ledger().provider_attempts, 0);
        assert!(owner.read(AgentIdV1(3), epoch).is_none());
        assert!(
            owner
                .read(AgentIdV1(2), AgentEpochV1 { turn: 2, ..epoch })
                .is_none()
        );
        assert_eq!(
            owner.capture(AgentIdV1(2), epoch, &tenant, &run, &ledger),
            Err(ControllerError::StaleEpoch)
        );
        owner
            .capture(
                AgentIdV1(2),
                AgentEpochV1 { turn: 2, ..epoch },
                &tenant,
                &run,
                &ledger,
            )
            .unwrap();
        assert!(owner.read(AgentIdV1(2), epoch).is_none());
    }
    #[test]
    fn malformed_scope_refuses_before_snapshot_clone() {
        let mut owner = CompletedChildLedgers::default();
        let epoch = AgentEpochV1 {
            incarnation: 1,
            turn: 1,
        };
        for run in ["x".repeat(513), "bad\nrun".into()] {
            assert!(
                owner
                    .capture(
                        AgentIdV1(2),
                        epoch,
                        &TenantId("tenant".into()),
                        &RunId(run),
                        &Ledger::new()
                    )
                    .is_err()
            );
        }
        assert!(owner.snapshots.is_empty());
        assert_eq!(owner.retained_bytes, 0);
    }
}
