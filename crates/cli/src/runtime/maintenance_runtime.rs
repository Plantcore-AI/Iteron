//! Trusted run composition for the independent advisory journal. Paths and work closures originate
//! only in the host; public clients receive the exact captured read port and cannot reopen it.
use super::{
    Agent,
    advisory_maintenance::{AdvisoryMaintenanceReadPort, MaintenanceOwner},
};
use std::sync::Arc;

impl Agent {
    /// The fixture has stopped producing work and still owns this Agent through the rendezvous.
    /// Inspect only its already-installed owner; never initialize a new journal during cleanup.
    #[cfg(test)]
    pub(super) async fn finish_advisory_maintenance_for_test(
        &self,
    ) -> Result<(), super::advisory_maintenance::MaintenanceReadError> {
        let owner = self
            .advisory_maintenance
            .lock()
            .map_err(|_| super::advisory_maintenance::MaintenanceReadError::ReconciliationNeeded)?
            .clone();
        if let Some(owner) = owner {
            owner
                .finish_fixture_io(std::time::Duration::from_secs(30))
                .await?;
        }
        Ok(())
    }
    pub(crate) fn advisory_maintenance_port(&self) -> Option<Arc<dyn AdvisoryMaintenanceReadPort>> {
        self.advisory_maintenance_owner()
            .map(|owner| owner as Arc<dyn AdvisoryMaintenanceReadPort>)
    }
    pub(super) fn advisory_maintenance_owner(&self) -> Option<Arc<MaintenanceOwner>> {
        if self.runtime_state_dir.as_os_str().is_empty() {
            return None;
        }
        let scope = self.provider_scope();
        let mut installed = self.advisory_maintenance.lock().ok()?;
        if let Some(owner) = installed.as_ref().filter(|owner| owner.scope() == scope) {
            return Some(owner.clone());
        }
        let directory = self
            .runtime_state_dir
            .join("advisory-maintenance-v1")
            .join(&scope[7..]);
        let owner = MaintenanceOwner::new(directory, scope);
        // Memory submission is optional: a full queue means the read port honestly remains
        // Unavailable until an actual job opens its journal. No Rollout or parent answer waits.
        let _ = owner.initialize();
        *installed = Some(owner.clone());
        Some(owner)
    }
}
