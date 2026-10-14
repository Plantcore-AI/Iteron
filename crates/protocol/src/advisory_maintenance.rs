//! Read-only public evidence for optional advisory writes. Job state comes from its independent
//! maintenance journal; an accepted in-memory submission never proves durable completion.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MaintenanceJobIdV1(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceKindV1 {
    LastSuccessfulRoute,
    TokenCalibration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceStateV1 {
    Queued,
    Running,
    Completed,
    Failed,
    ReconciliationNeeded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceEvidenceSourceV1 {
    MaintenanceJournal,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceJobV1 {
    pub job_id: MaintenanceJobIdV1,
    pub kind: MaintenanceKindV1,
    pub turn: u32,
    pub state: MaintenanceStateV1,
    pub input_sha256: String,
    pub queued_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub last_revision: u64,
    pub reason_code: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceObservationV1 {
    pub version: u32,
    pub scope_sha256: String,
    pub journal_revision: u64,
    pub journal_sha256: String,
    pub evidence_source: MaintenanceEvidenceSourceV1,
    pub jobs: Vec<MaintenanceJobV1>,
    pub dropped_jobs: u64,
    pub omitted_jobs: usize,
}
