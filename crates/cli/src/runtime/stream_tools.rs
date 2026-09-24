//! Streaming admission for ordinary Auto-approved local tools.
//!
//! The execution gate follows Codex's tool policy: parallel-capable handlers share a
//! read guard, mutations requiring ordering retain an exclusive guard through execution.

use super::*;

pub(super) struct ExecutionGuard {
    _shared: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
    _exclusive: Option<tokio::sync::OwnedRwLockWriteGuard<()>>,
}

pub(super) async fn execution_guard(
    gate: std::sync::Arc<tokio::sync::RwLock<()>>,
    supports_parallel: bool,
) -> ExecutionGuard {
    if supports_parallel {
        ExecutionGuard {
            _shared: Some(gate.read_owned().await),
            _exclusive: None,
        }
    } else {
        ExecutionGuard {
            _shared: None,
            _exclusive: Some(gate.write_owned().await),
        }
    }
}

impl Agent {
    pub(super) fn early_local_tool_capability(
        &self,
        proposal: &iteron_tools::ToolPolicyProposal,
        governing_trust: Trust,
    ) -> Option<Capability> {
        let call = &proposal.intent.call;
        if self.record_failed
            || self.run_deadline_exhausted()
            || self.requested_control() != InboundControl::None
            || self.registry.is_mcp_effect(&call.name)
            || matches!(
                call.name.as_str(),
                iteron_tools::DISPATCH_AGENT
                    | iteron_tools::WORKFLOW_TOOL
                    | iteron_tools::REQUEST_USER_INPUT
            )
        {
            return None;
        }
        let base = proposal.eligible.iter().next()?;
        let capability = effective_capability(&call.input, base);
        if !matches!(
            capability,
            Capability::ReversibleLocal | Capability::CodeExecuting
        ) {
            return None;
        }
        let verdict = if self.bypass_permissions && self.permission_mode != PermissionMode::Plan {
            bypass_verdict(&self.permission_rules, &call.name, capability)
        } else {
            iteron_protocol::gate(
                self.permission_mode,
                &self.permission_rules,
                &call.name,
                capability,
            )
        };
        (iteron_kernel::admission::constrain_under_authority(
            verdict,
            capability,
            self.authority_ceiling,
            self.policy_capabilities,
            Some(governing_trust),
            self.operator_authority(),
        ) == Verdict::Auto)
            .then_some(capability)
    }
}

/// Poll once at declaration time: Tokio's fair lock queue then reflects model call
/// order even if spawned tasks are first polled in a different order.
pub(super) fn reserve_execution(
    gate: std::sync::Arc<tokio::sync::RwLock<()>>,
    supports_parallel: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ExecutionGuard> + Send>> {
    let mut future = Box::pin(execution_guard(gate, supports_parallel));
    let mut context = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
    match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(guard) => Box::pin(std::future::ready(guard)),
        std::task::Poll::Pending => future,
    }
}

/// A fallible record/projection path must never detach an already admitted tool.
/// Its durable intent stays unresolved if that path cannot append a terminal.
pub(super) struct EarlyToolTask(tokio::task::JoinHandle<EarlyPureToolOutcome>);

impl EarlyToolTask {
    pub(super) fn new(handle: tokio::task::JoinHandle<EarlyPureToolOutcome>) -> Self {
        Self(handle)
    }

    pub(super) fn abort(&self) {
        self.0.abort();
    }
}

impl std::future::Future for EarlyToolTask {
    type Output = Result<EarlyPureToolOutcome, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(context)
    }
}

impl Drop for EarlyToolTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
