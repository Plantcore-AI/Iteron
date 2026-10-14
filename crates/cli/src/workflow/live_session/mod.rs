//! Provider-independent live graph service. The graph and registry have actual durable owners;
//! public commands carry no filesystem, budget, actor or completion-proof authority.

mod pump;
mod registry;
mod store;
mod types;

#[cfg(test)]
pub(crate) use types::LiveWorkflowViewV1;
pub(crate) use types::{
    LIVE_WORKFLOW_CONTRACT_VERSION, LiveWorkflowCommandV1, LiveWorkflowError, LiveWorkflowPolicy,
    LiveWorkflowReplyV1,
};
use types::{MAX_BACKGROUND_TICKS, MAX_REQUESTS, MAX_WORKFLOWS};

use crate::runtime::persistent_agents::{AgentControlPort, AgentHostLimits};
use async_trait::async_trait;
use iteron_protocol::agent_control::AgentBudgetV1;
use iteron_workflow::task_dag::TaskBudget;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

#[async_trait]
pub(crate) trait LiveWorkflowPort: Send + Sync {
    async fn command(
        &self,
        command: LiveWorkflowCommandV1,
    ) -> Result<LiveWorkflowReplyV1, LiveWorkflowError>;
}

impl LiveWorkflowPolicy {
    /// Mint admission only from the real parent controller/runtime's intersected limits. Missing
    /// price/money evidence disables admission. A persisted registry retains prior reservations.
    pub(crate) fn from_host_limits(limits: &AgentHostLimits) -> Result<Self, LiveWorkflowError> {
        let monetary = limits
            .monetary_remaining
            .ok_or(LiveWorkflowError::Controller)?;
        let mut remaining = limits.remaining;
        remaining.cost_microusd = remaining.cost_microusd.min(monetary);
        let policy = Self {
            root_agent_id: limits.root.agent_id.0,
            aggregate_budget: task_budget(limits.root.budget),
            graph_budget: task_budget(remaining),
            max_workflows: MAX_WORKFLOWS,
            max_nodes: iteron_workflow::live_scheduler::MAX_PLAN_NODES,
            max_edges: iteron_workflow::live_scheduler::MAX_PLAN_EDGES,
            max_concurrency: limits
                .max_concurrency
                .min(limits.max_agents)
                .min(iteron_workflow::live_scheduler::MAX_PLAN_NODES),
        };
        policy.validate()?;
        Ok(policy)
    }
}

fn task_budget(budget: AgentBudgetV1) -> TaskBudget {
    TaskBudget {
        max_turns: budget.turns,
        max_tokens: budget.tokens,
        max_cost_microusd: budget.cost_microusd,
        max_wall_ms: budget.wall_ms,
    }
}

pub(crate) struct LiveWorkflowSession {
    root: PathBuf,
    policy: LiveWorkflowPolicy,
    control: Arc<dyn AgentControlPort>,
    registry: Mutex<Option<registry::Registry>>,
    admission: Arc<Semaphore>,
    driver_running: AtomicBool,
    self_weak: Weak<Self>,
}

impl LiveWorkflowSession {
    /// The composition root owns this absolute private application-state path and installs one
    /// service per controller/session. Opening is lazy; disabled/unobserved sessions do no I/O.
    pub(crate) fn new(
        root: PathBuf,
        policy: LiveWorkflowPolicy,
        control: Arc<dyn AgentControlPort>,
    ) -> Result<Arc<Self>, LiveWorkflowError> {
        if !root.is_absolute() {
            return Err(LiveWorkflowError::Invalid(
                "state root must be host-absolute",
            ));
        }
        policy.validate()?;
        Ok(Arc::new_cyclic(|weak| Self {
            root,
            policy,
            control,
            registry: Mutex::new(None),
            admission: Arc::new(Semaphore::new(MAX_REQUESTS)),
            driver_running: AtomicBool::new(false),
            self_weak: weak.clone(),
        }))
    }

    fn start_driver(&self) {
        if self
            .driver_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let weak = self.self_weak.clone();
        tokio::spawn(async move {
            let mut ticks = 0;
            loop {
                let Some(owner) = weak.upgrade() else {
                    return;
                };
                let mut state = owner.registry.lock().await;
                let keep_running = if let Some(registry) = state.as_mut() {
                    registry.tick(owner.control.as_ref()).await
                } else {
                    false
                };
                ticks += 1;
                if !keep_running || ticks >= MAX_BACKGROUND_TICKS {
                    if ticks >= MAX_BACKGROUND_TICKS
                        && let Some(registry) = state.as_mut()
                    {
                        registry.exhaust_driver();
                    }
                    // Reset under the same owner lock used by command, preventing a lost wake.
                    owner.driver_running.store(false, Ordering::Release);
                    return;
                }
                drop(state);
                drop(owner);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    async fn admitted_command(
        self: Arc<Self>,
        command: LiveWorkflowCommandV1,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<LiveWorkflowReplyV1, LiveWorkflowError> {
        let mut state = tokio::time::timeout(Duration::from_secs(2), self.registry.lock())
            .await
            .map_err(|_| LiveWorkflowError::Busy)?;
        if state.is_none() && command.is_read_only() {
            return Err(LiveWorkflowError::NotFound);
        }
        if state.is_none() {
            *state = Some(registry::Registry::open(&self.root, self.policy.clone())?);
        }
        let registry = state.as_mut().ok_or(LiveWorkflowError::Controller)?;
        let drive = !command.is_read_only();
        let id = command.workflow_id().to_owned();
        if drive {
            registry.resume_driver(&id);
        }
        let reply = registry.command(command, self.control.as_ref()).await?;
        if drive {
            self.start_driver();
        }
        Ok(reply)
    }
}

#[async_trait]
impl LiveWorkflowPort for LiveWorkflowSession {
    async fn command(
        &self,
        command: LiveWorkflowCommandV1,
    ) -> Result<LiveWorkflowReplyV1, LiveWorkflowError> {
        command.validate()?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| LiveWorkflowError::Busy)?;
        let owner = self
            .self_weak
            .upgrade()
            .ok_or(LiveWorkflowError::Controller)?;
        // The owned worker survives a disconnected/timed-out observer, retains admission and
        // finishes write-ahead operations. Its controller calls have scheduler-owned deadlines.
        tokio::spawn(owner.admitted_command(command, permit))
            .await
            .map_err(|_| LiveWorkflowError::Controller)?
    }
}

#[cfg(test)]
mod tests;
