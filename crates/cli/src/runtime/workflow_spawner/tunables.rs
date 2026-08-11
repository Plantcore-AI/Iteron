use super::KernelSpawnerContext;
use crate::runtime::{KernelError, tunables_pin::TunablesPin};

impl KernelSpawnerContext {
    /// Install the one session-wide spawn owner produced by the same atomic resolution.
    pub(crate) fn install_session_spawn_ledger(
        &mut self,
        ledger: std::sync::Arc<super::super::SessionSpawnLedger>,
    ) {
        self.session_spawn_ledger = ledger;
    }

    /// Bind a fresh standalone workflow to one atomic resolver result before any child can spawn.
    pub(crate) fn pin_resolved_tunables(
        &mut self,
        resolved: &iteron_tunables::ResolvedTunableSet,
    ) -> Result<(), KernelError> {
        if self.tunables_pin.is_some() {
            return Err(KernelError::TunablesAlreadyResolved);
        }
        self.tunables_pin = Some(TunablesPin::from_resolved(resolved)?);
        Ok(())
    }

    /// Bind a resumed standalone workflow to its exact historical V1/V2 checkpoint.
    pub(crate) fn pin_tunables_checkpoint(
        &mut self,
        checkpoint: iteron_record::TunablesCheckpoint,
    ) -> Result<(), KernelError> {
        if self.tunables_pin.is_some() {
            return Err(KernelError::TunablesAlreadyResolved);
        }
        self.tunables_pin = Some(TunablesPin::from_checkpoint(checkpoint)?);
        Ok(())
    }
}
