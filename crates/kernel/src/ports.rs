//! Versioned injected ports at the microkernel/world boundary.
//!
//! A port is deliberately narrower than the concrete implementation behind it. The kernel owns
//! request/response semantics and versions; the CLI composition root owns adapters to concrete
//! provider, context, tool, scheduler, verifier, diagnostics, and workflow crates.

use crate::driver::{PortFault, ProviderReply};
use crate::turn_action::{ContinueReason, NoticeKind};
use crate::turn_protocol::{BudgetCeiling, ControlSignal, VerifyOutcome};
use iteron_protocol::context::ContextGrant;

pub const PROVIDER_PORT_VERSION: u32 = 1;
pub const SANDBOX_PORT_VERSION: u32 = 1;
pub const CONTEXT_PORT_VERSION: u32 = 1;
pub const SCHEDULER_PORT_VERSION: u32 = 1;
pub const DIAGNOSTICS_PORT_VERSION: u32 = 1;
pub const VERIFY_PORT_VERSION: u32 = 1;
pub const TOOL_PORT_VERSION: u32 = 1;
pub const WORKFLOW_PORT_VERSION: u32 = 1;
pub const RECORD_PORT_VERSION: u32 = 1;

#[async_trait::async_trait]
pub trait ProviderPort: Send {
    const VERSION: u32 = PROVIDER_PORT_VERSION;
    async fn call_provider(&mut self, turn: u32) -> ProviderReply;
}

#[async_trait::async_trait]
pub trait SandboxPort: Send {
    const VERSION: u32 = SANDBOX_PORT_VERSION;
    async fn checkpoint(&mut self, turn: u32) -> Result<(), PortFault>;
}

#[async_trait::async_trait]
pub trait ContextPort: Send {
    const VERSION: u32 = CONTEXT_PORT_VERSION;
    async fn select_context(&mut self) -> Result<ContextGrant, PortFault>;
}

#[async_trait::async_trait]
pub trait SchedulerPort: Send {
    const VERSION: u32 = SCHEDULER_PORT_VERSION;
    async fn sample_budget(&mut self) -> Option<BudgetCeiling>;
    async fn observe_control(&mut self) -> ControlSignal;
    async fn admit_steers(&mut self, turn: u32) -> u32;
}

#[async_trait::async_trait]
pub trait DiagnosticsPort: Send {
    const VERSION: u32 = DIAGNOSTICS_PORT_VERSION;
    async fn notice(&mut self, kind: NoticeKind);
    async fn continuation(&mut self, turn: u32, reason: ContinueReason);
    async fn advance_turn(&mut self, turn: u32) -> Result<(), PortFault>;
}

#[async_trait::async_trait]
pub trait VerifyPort: Send {
    const VERSION: u32 = VERIFY_PORT_VERSION;
    async fn run_verify(&mut self, turn: u32, attempt: u32) -> VerifyOutcome;
}

#[async_trait::async_trait]
pub trait ToolPort: Send {
    const VERSION: u32 = TOOL_PORT_VERSION;
    async fn dispatch_tools(&mut self, turn: u32, calls: u32) -> bool;
}

/// Durable record seam. Concrete JSONL storage and filesystem sync live in `iteron-record`; the
/// kernel asks only that a turn boundary be committed before admitting the next effect.
#[async_trait::async_trait]
pub trait RecordPort: Send {
    const VERSION: u32 = RECORD_PORT_VERSION;
    async fn commit_turn(&mut self, turn: u32) -> Result<(), PortFault>;
}

/// Workflow launches are effects. Script parsing, child construction, progress rendering, and
/// journal wire handling stay outside the TCB.
#[async_trait::async_trait]
pub trait WorkflowPort: Send {
    const VERSION: u32 = WORKFLOW_PORT_VERSION;
    async fn launch_workflow(
        &mut self,
        request: WorkflowRequest,
    ) -> Result<WorkflowOutcome, PortFault>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRequest {
    pub script_digest: String,
    pub budget: WorkflowRunBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowOutcome {
    Done,
    Failed,
    Interrupted,
}

/// Kernel-minted aggregate workflow limits. Every field is non-zero, and callers can only narrow
/// an existing value. There is intentionally no widening or union operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowRunBudget {
    max_concurrency: usize,
    max_agent_calls: usize,
}

impl WorkflowRunBudget {
    pub fn new(max_concurrency: usize, max_agent_calls: usize) -> Result<Self, &'static str> {
        if max_concurrency == 0 {
            return Err("workflow concurrency must be non-zero");
        }
        if max_agent_calls == 0 {
            return Err("workflow agent ceiling must be non-zero");
        }
        Ok(Self {
            max_concurrency,
            max_agent_calls,
        })
    }

    pub fn max_concurrency(self) -> usize {
        self.max_concurrency
    }

    pub fn max_agent_calls(self) -> usize {
        self.max_agent_calls
    }

    pub fn narrow(self, requested: Self) -> Self {
        Self {
            max_concurrency: self.max_concurrency.min(requested.max_concurrency),
            max_agent_calls: self.max_agent_calls.min(requested.max_agent_calls),
        }
    }
}

/// One adapter may satisfy several seams, but the traits stay separately versioned. This aggregate
/// is only the driver's generic bound; it does not merge authority.
pub trait TurnPorts:
    ProviderPort + SandboxPort + ContextPort + SchedulerPort + DiagnosticsPort + VerifyPort + ToolPort
{
}

impl<T> TurnPorts for T where
    T: ProviderPort
        + SandboxPort
        + ContextPort
        + SchedulerPort
        + DiagnosticsPort
        + VerifyPort
        + ToolPort
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct StubRecord {
        committed: Vec<u32>,
    }

    #[async_trait::async_trait]
    impl RecordPort for StubRecord {
        async fn commit_turn(&mut self, turn: u32) -> Result<(), PortFault> {
            self.committed.push(turn);
            Ok(())
        }
    }

    #[derive(Default)]
    struct StubWorkflow {
        launched: Vec<WorkflowRequest>,
    }

    #[async_trait::async_trait]
    impl WorkflowPort for StubWorkflow {
        async fn launch_workflow(
            &mut self,
            request: WorkflowRequest,
        ) -> Result<WorkflowOutcome, PortFault> {
            self.launched.push(request);
            Ok(WorkflowOutcome::Done)
        }
    }

    #[test]
    fn workflow_budget_can_only_narrow() {
        let parent = WorkflowRunBudget::new(8, 100).unwrap();
        let requested = WorkflowRunBudget::new(16, 20).unwrap();
        let admitted = parent.narrow(requested);
        assert_eq!(admitted.max_concurrency(), 8);
        assert_eq!(admitted.max_agent_calls(), 20);
    }

    #[test]
    fn every_port_version_is_explicit_and_non_zero() {
        assert_eq!(
            [
                PROVIDER_PORT_VERSION,
                SANDBOX_PORT_VERSION,
                CONTEXT_PORT_VERSION,
                SCHEDULER_PORT_VERSION,
                DIAGNOSTICS_PORT_VERSION,
                VERIFY_PORT_VERSION,
                TOOL_PORT_VERSION,
                WORKFLOW_PORT_VERSION,
                RECORD_PORT_VERSION,
            ],
            [1; 9]
        );
    }

    #[tokio::test]
    async fn record_and_workflow_ports_run_on_in_memory_fakes() {
        let mut record = StubRecord::default();
        record.commit_turn(7).await.unwrap();
        assert_eq!(record.committed, vec![7]);

        let mut workflow = StubWorkflow::default();
        let request = WorkflowRequest {
            script_digest: "sha256:fixture".into(),
            budget: WorkflowRunBudget::new(2, 4).unwrap(),
        };
        assert_eq!(
            workflow.launch_workflow(request.clone()).await.unwrap(),
            WorkflowOutcome::Done
        );
        assert_eq!(workflow.launched, vec![request]);
    }
}
