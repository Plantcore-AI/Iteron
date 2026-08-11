//! Content-free `/status` projection over the exact session-owned authorities.

use super::*;

const LSP_STATUS_DEADLINE: std::time::Duration = std::time::Duration::from_millis(100);

pub(super) struct OperatorStatusSources {
    runtime: crate::runtime::RuntimeOperatorStatusSources,
    processes: Option<iteron_tools::ProcessControl>,
    language_servers: Option<iteron_tools::LspControl>,
    mcp: Option<crate::mcp::McpRuntimeControl>,
    workflows: Arc<crate::workflow::WorkflowSupervisor>,
}

#[derive(Debug, Clone)]
pub(crate) struct OperatorStatusSnapshot {
    pub(crate) runtime: crate::runtime::RuntimeOperatorStatusSnapshot,
    pub(crate) processes: Option<iteron_tools::ProcessHealth>,
    pub(crate) language_servers: LanguageServerStatus,
    pub(crate) mcp: Vec<crate::mcp::McpServerHealth>,
    pub(crate) workflows: WorkflowHealth,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum LanguageServerStatus {
    Unavailable,
    Busy,
    Available(iteron_tools::LspHealth),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WorkflowHealth {
    pub(crate) retained: usize,
    pub(crate) running: usize,
    pub(crate) cancelling: usize,
    pub(crate) settled: usize,
    pub(crate) failed: usize,
    pub(crate) running_agents: usize,
}

impl OperatorStatusSources {
    pub(super) fn capture(
        agent: &Agent,
        processes: Option<iteron_tools::ProcessControl>,
        language_servers: Option<iteron_tools::LspControl>,
        mcp: Option<crate::mcp::McpRuntimeControl>,
        workflows: Arc<crate::workflow::WorkflowSupervisor>,
    ) -> Self {
        Self {
            runtime: agent.operator_status_sources(),
            processes,
            language_servers,
            mcp,
            workflows,
        }
    }

    /// Refresh identities that can change only at an idle control boundary (model/run adoption).
    /// The live owner handles remain the same Arcs and are intentionally retained.
    pub(super) fn refresh_runtime(&mut self, agent: &Agent) {
        self.runtime = agent.operator_status_sources();
    }

    pub(super) async fn snapshot(&self) -> OperatorStatusSnapshot {
        let language_servers = match &self.language_servers {
            None => LanguageServerStatus::Unavailable,
            Some(control) => {
                match tokio::time::timeout(LSP_STATUS_DEADLINE, control.health()).await {
                    Ok(health) => LanguageServerStatus::Available(health),
                    Err(_) => LanguageServerStatus::Busy,
                }
            }
        };
        let mut workflows = WorkflowHealth::default();
        for run in self.workflows.inventory() {
            workflows.retained = workflows.retained.saturating_add(1);
            workflows.running_agents = workflows.running_agents.saturating_add(run.running_agents);
            match run.status {
                crate::workflow::SupervisedRunStatus::Running => {
                    workflows.running = workflows.running.saturating_add(1)
                }
                crate::workflow::SupervisedRunStatus::Cancelling => {
                    workflows.cancelling = workflows.cancelling.saturating_add(1)
                }
                crate::workflow::SupervisedRunStatus::Settled => {
                    workflows.settled = workflows.settled.saturating_add(1)
                }
                crate::workflow::SupervisedRunStatus::Failed => {
                    workflows.failed = workflows.failed.saturating_add(1)
                }
            }
        }
        OperatorStatusSnapshot {
            runtime: self.runtime.snapshot(),
            processes: self
                .processes
                .as_ref()
                .map(iteron_tools::ProcessControl::health),
            language_servers,
            mcp: self
                .mcp
                .as_ref()
                .map_or_else(Vec::new, crate::mcp::McpRuntimeControl::health),
            workflows,
        }
    }
}
