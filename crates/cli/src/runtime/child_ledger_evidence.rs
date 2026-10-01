//! Frozen native child accounting. Private host receipts correlate the exact physical tenant/run
//! and controller epoch after actual cleanup; no scalar completion or model text can mint a ledger.
use iteron_agents::ControllerError;
use iteron_obs::Ledger;
use iteron_protocol::agent_control::{AgentEpochV1, AgentIdV1};
use iteron_protocol::{RunId, TenantId};
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct AgentRuntimeLedger {
    agent: AgentIdV1,
    epoch: AgentEpochV1,
    tenant: TenantId,
    run: RunId,
    ledger: Ledger,
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
            || run.0.is_empty()
            || tenant.0.is_empty()
        {
            return Err(ControllerError::Invalid(
                "invalid native child ledger scope",
            ));
        }
        if !self.snapshots.contains_key(&agent) && self.snapshots.len() >= 64 {
            return Err(ControllerError::Capacity);
        }
        if let Some(old) = self.snapshots.get(&agent) {
            if epoch.incarnation < old.epoch.incarnation
                || (epoch.incarnation == old.epoch.incarnation && epoch.turn <= old.epoch.turn)
            {
                return Err(ControllerError::StaleEpoch);
            }
        }
        self.snapshots.insert(
            agent,
            AgentRuntimeLedger {
                agent,
                epoch,
                tenant: tenant.clone(),
                run: run.clone(),
                ledger: ledger.clone(),
            },
        );
        Ok(())
    }
    pub(super) fn read(&self, agent: AgentIdV1, epoch: AgentEpochV1) -> Option<AgentRuntimeLedger> {
        self.snapshots
            .get(&agent)
            .filter(|receipt| receipt.epoch == epoch)
            .cloned()
    }
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
}
