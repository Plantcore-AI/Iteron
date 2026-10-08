//! Frozen-request simulation, never a live runtime configuration or an authority grant.
use crate::runtime::Agent;
use iteron_protocol::ToolUse;
use iteron_tunables::ResolutionReport;
use serde_json::Value;
use std::path::PathBuf;
const MAX_VIEW_BYTES: usize = 1024 * 1024;
#[derive(Debug, serde::Serialize)]
pub(crate) struct SimulationEntryV1 {
    pub(crate) family_id: String,
    pub(crate) explanation: Value,
}
#[derive(Debug, serde::Serialize)]
pub(crate) struct TunablesSimulationV1 {
    pub(crate) version: u32,
    pub(crate) registry_digest: String,
    pub(crate) status: &'static str,
    pub(crate) failure_count: usize,
    pub(crate) entries: Vec<SimulationEntryV1>,
}
pub(crate) struct NativeTunablesSimulation {
    workspace: PathBuf,
    request: String,
    #[cfg(test)]
    pause: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}
impl NativeTunablesSimulation {
    pub(crate) fn capture(agent: &Agent, request: String) -> Result<Self, &'static str> {
        super::workspace_read::validate_path(&request)?;
        let call = ToolUse {
            id: "operator-tunables-simulation".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":request,"max_bytes":iteron_tunables::RESOLUTION_INPUT_MAX_BYTES}),
        };
        if !agent.admit_operator_tool_call(&call) {
            return Err(
                "workspace request read is denied by the current policy or authority ceiling",
            );
        }
        Ok(Self {
            workspace: agent.workspace.clone(),
            request,
            #[cfg(test)]
            pause: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn pause_before_read(
        mut self,
        started: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        self.pause = Some((started, release));
        self
    }
    pub(crate) fn execute(self) -> Result<TunablesSimulationV1, &'static str> {
        #[cfg(test)]
        if let Some((started, release)) = self.pause {
            started
                .send(())
                .map_err(|_| "fixture observer unavailable")?;
            release
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| "fixture release unavailable")?;
        }
        let bytes = super::workspace_read::read(
            &self.workspace,
            &self.request,
            iteron_tunables::RESOLUTION_INPUT_MAX_BYTES,
        )?;
        simulate(&bytes)
    }
}
#[cfg(test)]
pub(crate) mod tests;
pub(crate) fn simulate(bytes: &[u8]) -> Result<TunablesSimulationV1, &'static str> {
    match iteron_tunables::resolve_json(bytes) {
        Ok(resolved) => project(resolved.report(), "resolved", 0),
        Err(failure) => {
            let report = failure
                .report
                .as_ref()
                .ok_or("request validation failed closed; no simulation report was produced")?;
            project(report, "active resolution failed", failure.failures.len())
        }
    }
}
fn project(
    report: &ResolutionReport,
    status: &'static str,
    failure_count: usize,
) -> Result<TunablesSimulationV1, &'static str> {
    let mut entries = Vec::with_capacity(iteron_tunables::families().len());
    let mut bytes = 0usize;
    for family in iteron_tunables::families() {
        // The canonical explain contract redacts values, routes, subjects and input provenance.
        // Raw request/report bytes never enter a frontend or public client reply.
        let encoded = iteron_tunables::explain_entry_json(report, family.id)
            .map_err(|_| "resolver explain refused the simulation report")?;
        bytes = bytes
            .checked_add(encoded.len())
            .filter(|n| *n <= MAX_VIEW_BYTES)
            .ok_or("simulation explanation exceeds its bounded public view")?;
        let document: Value = serde_json::from_str(&encoded)
            .map_err(|_| "resolver explain returned an unreadable document")?;
        let explanation = document
            .get("entry")
            .filter(|value| value.is_object())
            .cloned()
            .ok_or("resolver explain omitted the selected entry")?;
        entries.push(SimulationEntryV1 {
            family_id: family.id.to_owned(),
            explanation,
        });
    }
    Ok(TunablesSimulationV1 {
        version: 1,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.into(),
        status,
        failure_count,
        entries,
    })
}
