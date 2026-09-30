//! Independent readonly maintenance observations bound to the actual adopted run's owner port.

use super::ServerEvent;
use super::product_contract::ContractReader;
use crate::runtime::advisory_maintenance::{AdvisoryMaintenanceReadPort, MaintenanceReadError};
use iteron_protocol::advisory_maintenance_control::{
    MaintenanceAvailabilityCodeV1, MaintenanceAvailabilityV1, MaintenanceEventV1, MaintenanceReadV1,
};
use iteron_protocol::{RunId, SessionId};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub(super) struct MaintenanceBinding {
    pub(super) thread_id: SessionId,
    pub(super) run_id: RunId,
    pub(super) port: Arc<dyn AdvisoryMaintenanceReadPort>,
}
impl MaintenanceBinding {
    fn is_current(&self, reader: &ContractReader) -> bool {
        reader.maintenance_binding().is_some_and(|current| {
            current.thread_id == self.thread_id
                && current.run_id == self.run_id
                && Arc::ptr_eq(&current.port, &self.port)
        })
    }
}

pub(super) fn read(reader: &ContractReader, command: MaintenanceReadV1) -> Value {
    if command.validate().is_err()
        || reader
            .snapshot()
            .is_none_or(|snapshot| snapshot.thread_id != *command.thread_id())
    {
        return json!({"type":"maintenance_refused_v1","reason_code":"thread_scope_mismatch"});
    }
    let Some(binding) = reader.maintenance_binding() else {
        return json!({"type":"maintenance_unavailable_v1","reason_code":"unavailable"});
    };
    let (after_revision, limit) = match command {
        MaintenanceReadV1::Read {
            after_revision,
            limit,
            ..
        } => (after_revision, limit as usize),
        MaintenanceReadV1::Subscribe { .. } => (0, 64),
    };
    // Clone the same actual port and release projection locks before its own journal barrier read.
    match binding.port.observe(after_revision, limit) {
        Ok(observation) if binding.is_current(reader) => {
            let event = MaintenanceEventV1 {
                thread_id: binding.thread_id,
                run_id: binding.run_id,
                observation,
            };
            if event.validate().is_err() {
                return json!({"type":"maintenance_unavailable_v1","reason_code":"invalid_observation"});
            }
            json!({"type":"maintenance_snapshot_v1","event":event,"presentation":reader.maintenance_gaps()})
        }
        Ok(_) => json!({"type":"maintenance_refused_v1","reason_code":"run_scope_changed"}),
        Err(error) => json!({"type":"maintenance_unavailable_v1","reason_code":error_code(error)}),
    }
}

fn error_code(error: MaintenanceReadError) -> &'static str {
    match error {
        MaintenanceReadError::InvalidBounds => "invalid_bounds",
        MaintenanceReadError::Unavailable => "unavailable",
        MaintenanceReadError::ReconciliationNeeded => "reconciliation_needed",
    }
}

pub(super) struct MaintenanceObserver {
    reader: ContractReader,
    scope: Option<(RunId, Arc<dyn AdvisoryMaintenanceReadPort>)>,
    revision: u64,
    error: Option<MaintenanceAvailabilityCodeV1>,
}
impl MaintenanceObserver {
    pub(super) fn new(reader: ContractReader) -> Self {
        Self {
            reader,
            scope: None,
            revision: 0,
            error: None,
        }
    }

    /// Waits for durable owner snapshots. Cancellation merely cancels this observer wait.
    /// Parent terminal publication and the optional writer never await each other.
    pub(super) async fn next(&mut self) -> ServerEvent {
        loop {
            let Some(binding) = self.reader.maintenance_binding() else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            if self.scope.as_ref().is_none_or(|(run, port)| {
                *run != binding.run_id || !Arc::ptr_eq(port, &binding.port)
            }) {
                self.scope = Some((binding.run_id.clone(), binding.port.clone()));
                self.revision = 0;
                self.error = None;
            }
            let reply = binding.port.wait(self.revision, 20_000).await;
            if !binding.is_current(&self.reader) {
                continue;
            }
            match reply {
                Ok(observation) => {
                    let event = MaintenanceEventV1 {
                        thread_id: binding.thread_id.clone(),
                        run_id: binding.run_id.clone(),
                        observation,
                    };
                    let code = if event.validate().is_err() {
                        Some(MaintenanceAvailabilityCodeV1::InvalidObservation)
                    } else {
                        None
                    };
                    if let Some(code) = code {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if self.error == Some(code) {
                            continue;
                        }
                        self.error = Some(code);
                        return ServerEvent::MaintenanceAvailability(MaintenanceAvailabilityV1 {
                            thread_id: binding.thread_id,
                            run_id: binding.run_id,
                            code,
                        });
                    }
                    if event.observation.journal_revision <= self.revision {
                        // No revision is not a new job event. A finite backoff also protects buggy
                        // ports which return an unchanged snapshot before the requested timeout.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    self.revision = event.observation.journal_revision;
                    self.error = None;
                    return ServerEvent::AdvisoryMaintenance(event);
                }
                Err(error) => {
                    let code = match error {
                        MaintenanceReadError::ReconciliationNeeded => {
                            MaintenanceAvailabilityCodeV1::ReconciliationNeeded
                        }
                        MaintenanceReadError::Unavailable => {
                            MaintenanceAvailabilityCodeV1::Unavailable
                        }
                        MaintenanceReadError::InvalidBounds => {
                            MaintenanceAvailabilityCodeV1::InvalidObservation
                        }
                    };
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if !binding.is_current(&self.reader) || self.error == Some(code) {
                        continue;
                    }
                    self.error = Some(code);
                    return ServerEvent::MaintenanceAvailability(MaintenanceAvailabilityV1 {
                        thread_id: binding.thread_id,
                        run_id: binding.run_id,
                        code,
                    });
                }
            }
        }
    }
}
