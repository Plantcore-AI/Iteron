//! Read-only handles behind the operator status surface.
//!
//! The resident runtime remains the authority owner. These clones address the same bounded
//! governor, context ledger, and session-spawn ledger, so `/status` remains truthful while a turn
//! exclusively borrows the [`Agent`](super::Agent). No prompt, tool output, credential, memory
//! content, or policy body crosses this projection.

use super::{Agent, SessionSpawnLedger};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub(crate) struct RuntimeOperatorStatusSources {
    policy_bundle: iteron_protocol::RunGenesisPolicyBundleSnapshot,
    tunables: Option<iteron_record::TunablesCheckpoint>,
    governor: Option<iteron_provider::ProviderGovernor>,
    context_budget: iteron_ctx::ContextBudgetPolicy,
    context_ledgers: iteron_ctx::ContextLedgerStore,
    session_spawns: Arc<SessionSpawnLedger>,
    settled_budget: RuntimeBudgetHealth,
    runtime_policy: super::RuntimePolicyOverlayHandle,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeOperatorStatusSnapshot {
    pub(crate) policy_bundle: iteron_protocol::RunGenesisPolicyBundleSnapshot,
    pub(crate) tunables: Option<iteron_record::TunablesCheckpoint>,
    pub(crate) governor: Option<iteron_provider::ProviderGovernorSnapshot>,
    pub(crate) governor_policy: Option<iteron_provider::GovernorPolicy>,
    pub(crate) context_budget: iteron_ctx::ContextBudgetPolicy,
    pub(crate) context_ledger: iteron_ctx::ContextLedgerSnapshot,
    pub(crate) collaboration: CollaborationRuntimeHealth,
    /// Aggregate counters captured at the last turn/control boundary. Provider-governor and owner
    /// health above remain live while a turn runs; this field never pretends to race the Agent's
    /// exclusive ledger borrow.
    pub(crate) settled_budget: RuntimeBudgetHealth,
    /// Ordered current policy from the live resident owner. This is deliberately not copied from
    /// the frontend's last terminal-event cache.
    pub(crate) runtime_policy: Option<super::RuntimePolicyOverlaySnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollaborationRuntimeHealth {
    pub(crate) session_spawn_limit: usize,
    pub(crate) session_spawns_admitted: usize,
    pub(crate) session_spawns_remaining: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeBudgetHealth {
    pub(crate) ceiling: iteron_protocol::Budget,
    pub(crate) provider_attempts: u32,
    pub(crate) provider_attempts_remaining: u32,
    pub(crate) tokens_used: u64,
    pub(crate) tokens_remaining: Option<u64>,
    pub(crate) wall_remaining_ms: Option<u64>,
    pub(crate) tool_calls: u64,
    pub(crate) tool_errors: u64,
}

impl Agent {
    /// Capture authority-preserving read handles before a turn takes the runtime's mutable borrow.
    pub(crate) fn operator_status_sources(&self) -> RuntimeOperatorStatusSources {
        RuntimeOperatorStatusSources {
            policy_bundle: self.compiled_policy_bundle.genesis_snapshot().clone(),
            tunables: self.tunables_checkpoint().ok().cloned(),
            governor: self.provider_governor.clone(),
            context_budget: self.context_budget_policy,
            context_ledgers: self.context_ledgers.clone(),
            session_spawns: self.session_spawn_ledger.clone(),
            settled_budget: RuntimeBudgetHealth {
                ceiling: self.budget.clone(),
                provider_attempts: self.ledger.provider_attempts,
                provider_attempts_remaining: self.remaining_inference_turns(),
                tokens_used: super::ledger_tokens(&self.ledger),
                tokens_remaining: self.remaining_provider_tokens(),
                wall_remaining_ms: self
                    .run_time_remaining()
                    .map(|remaining| u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
                tool_calls: self.ledger.tool_calls,
                tool_errors: self.ledger.tool_errors,
            },
            runtime_policy: self.runtime_policy_overlay_handle(),
        }
    }
}

impl RuntimeOperatorStatusSources {
    pub(crate) fn snapshot(&self) -> RuntimeOperatorStatusSnapshot {
        let admitted = self.session_spawns.admitted();
        RuntimeOperatorStatusSnapshot {
            policy_bundle: self.policy_bundle.clone(),
            tunables: self.tunables.clone(),
            governor: self
                .governor
                .as_ref()
                .map(|governor| governor.snapshot(Instant::now())),
            governor_policy: self
                .governor
                .as_ref()
                .map(|governor| governor.policy().clone()),
            context_budget: self.context_budget,
            context_ledger: self.context_ledgers.snapshot(),
            collaboration: CollaborationRuntimeHealth {
                session_spawn_limit: self.session_spawns.limit(),
                session_spawns_admitted: admitted,
                session_spawns_remaining: self.session_spawns.limit().saturating_sub(admitted),
            },
            settled_budget: self.settled_budget.clone(),
            runtime_policy: self.runtime_policy.snapshot(),
        }
    }
}
