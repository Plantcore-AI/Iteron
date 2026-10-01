//! Real legacy Workflow/direct-investigator execution through the installed persistent controller.
//! The existing resident runtime owns model, tools, physical accounting and cleanup. This adapter
//! owns only the exact admitted child claim and bounded waits; it never creates another Agent.
use super::persistent_agents::{AgentControlPort, AgentEngineRequest};
use super::session_spawn_ledger::SessionSpawnLedger;
use async_trait::async_trait;
use iteron_agents::{
    AgentActor, AgentWorkflowChildBinding, AgentWorkflowClaim, AgentWorkflowTerminal,
    ControllerError,
};
use iteron_protocol::agent_control::{AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentStateV1};
use iteron_protocol::{Capability, Effort, capability_set::CapabilitySet};
use iteron_workflow::{
    AgentActivityReporter, AgentCall, AgentInvocationIdentity, AgentOutcome, AgentSpawner,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_CLAIMS: usize = 64;
const POLL_MS: u64 = 25;

/// Immutable host-minted scope. Model metadata may narrow a task; it cannot replace the selected
/// native model/profile, controller actor, ancestor, money ceiling or physical namespace.
pub(super) struct ControllerEngineChildren {
    control: Arc<dyn AgentControlPort>,
    parent: AgentIdV1,
    parent_source: iteron_agents::AgentEngineParentSource,
    workflow_id: String,
    model: String,
    effort: Effort,
    budget: AgentBudgetV1,
    deadline: Instant,
    deadline_unix_ms: u64,
    spawn_ledger: Arc<SessionSpawnLedger>,
    claims: Mutex<Vec<AgentWorkflowClaim>>,
    unresolved: Arc<AtomicBool>,
}
impl ControllerEngineChildren {
    pub(super) fn new(
        control: Arc<dyn AgentControlPort>,
        parent: AgentIdV1,
        workflow_id: String,
        model: String,
        effort: Effort,
        budget: AgentBudgetV1,
        deadline: Instant,
        spawn_ledger: Arc<SessionSpawnLedger>,
        parent_source: iteron_agents::AgentEngineParentSource,
    ) -> Result<Self, ControllerError> {
        budget.validate().map_err(ControllerError::Invalid)?;
        parent_source.validate()?;
        if workflow_id.is_empty()
            || workflow_id.len() > 128
            || workflow_id.chars().any(char::is_control)
        {
            return Err(ControllerError::Invalid("invalid engine controller scope"));
        }
        let admitted = control.inspect(AgentActor::Agent(parent), parent)?;
        if !admitted.capabilities.contains(Capability::ReadOnly)
            || matches!(
                admitted.state,
                AgentStateV1::Closed | AgentStateV1::RecoveryRequired { .. }
            )
        {
            return Err(ControllerError::Permission);
        }
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ControllerError::Invalid("engine child clock is before epoch"))?
                .as_millis(),
        )
        .map_err(|_| ControllerError::Capacity)?;
        let remaining = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| ControllerError::Capacity)?;
        let deadline_unix_ms = now
            .checked_add(remaining)
            .ok_or(ControllerError::Capacity)?;
        Ok(Self {
            control,
            parent,
            parent_source,
            workflow_id,
            model,
            effort,
            budget,
            deadline,
            deadline_unix_ms,
            spawn_ledger,
            claims: Mutex::new(Vec::new()),
            unresolved: Arc::new(AtomicBool::new(false)),
        })
    }
    pub(super) fn effects_known(&self) -> bool {
        if self.unresolved.load(Ordering::Acquire) {
            return false;
        }
        let Ok(claims) = self.claims.lock() else {
            return false;
        };
        claims.iter().all(|claim| matches!(self.control.engine_child_completion(claim), Ok(Some(done)) if done.effects_known))
    }
    pub(super) async fn direct(&self, prompt: String, node: u64) -> AgentOutcome {
        self.execute(
            AgentCall {
                prompt,
                label: Some("direct-investigator".into()),
                phase: None,
                model: None,
                effort: None,
                agent_type: Some("generic".into()),
                schema: None,
                cancel: Default::default(),
            },
            node,
            1,
            None,
            true,
        )
        .await
    }
    async fn execute(
        &self,
        call: AgentCall,
        node: u64,
        attempt: u64,
        activity: Option<AgentActivityReporter>,
        direct: bool,
    ) -> AgentOutcome {
        if call.validate_request_metadata().is_err() || node == 0 || attempt == 0 {
            return AgentOutcome::null(
                "engine child routing metadata or actual attempt identity is invalid",
            );
        }
        let origin = if direct {
            iteron_agents::AgentEngineOrigin::DirectSubagent {
                parent: self.parent_source.clone(),
            }
        } else {
            let Ok(task_id) = u32::try_from(node) else {
                return AgentOutcome::null("actual engine task identity exceeds the native domain");
            };
            iteron_agents::AgentEngineOrigin::WorkflowChild {
                parent: self.parent_source.clone(),
                workflow_id: self.workflow_id.clone(),
                task_id,
            }
        };
        let execution = match self.control.prepare_engine_child(
            AgentActor::Agent(self.parent),
            &AgentEngineRequest {
                profile: call.agent_type.clone(),
                model: call.model.clone().or_else(|| Some(self.model.clone())),
                effort: call.effort.or(Some(self.effort)),
            },
            origin,
        ) {
            Ok(execution) => execution,
            Err(_) => {
                return AgentOutcome::null(
                    "requested child profile/model/effort has no admitted native binding",
                );
            }
        };
        if call.cancel.is_cancelled() {
            return AgentOutcome::null("engine child cancelled before admission");
        }
        let (claim, request_id) = {
            let Ok(mut claims) = self.claims.lock() else {
                return AgentOutcome::null("controller engine claim owner is unavailable");
            };
            if claims.len() >= MAX_CLAIMS {
                return AgentOutcome::null("controller engine claim bound reached");
            }
            let remaining_wall = u64::try_from(
                self.deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u64::MAX);
            let budget = self.budget;
            if remaining_wall == 0 || budget.validate().is_err() {
                return AgentOutcome::null("engine child wall envelope expired before admission");
            }
            let input_digest = format!("{:x}", Sha256::digest(call.prompt.as_bytes()));
            let binding = AgentWorkflowChildBinding {
                workflow_id: self.workflow_id.clone(),
                node_id: node,
                attempt,
                input_digest,
                execution: Some(execution),
                deadline_unix_ms: self.deadline_unix_ms,
            };
            let request_id = format!(
                "engine:{}:{node}:{attempt}",
                &format!("{:x}", Sha256::digest(self.workflow_id.as_bytes()))[..24]
            );
            let label = call
                .label
                .as_deref()
                .filter(|value| {
                    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
                })
                .unwrap_or("workflow-investigator")
                .to_owned();
            if self.spawn_ledger.admit().is_err() {
                return AgentOutcome::null("session child admission ceiling reached");
            }
            let admitted = match self.control.spawn_engine_child(
                AgentActor::Agent(self.parent),
                &request_id,
                AgentCommandV1::Spawn {
                    parent_id: self.parent,
                    label,
                    task: call.prompt,
                    capabilities: CapabilitySet::only(Capability::ReadOnly),
                    budget,
                    write_paths: Vec::new(),
                },
                binding,
            ) {
                Ok(admitted) => admitted,
                Err(error) => {
                    if unknown(&error) {
                        self.unresolved.store(true, Ordering::Release);
                    }
                    return AgentOutcome::null(
                        "controller child was not admitted or needs reconciliation",
                    );
                }
            };
            let claim = admitted.claim;
            claims.push(claim.clone());
            (claim, request_id)
        };
        let mut stop = ChildStopGuard {
            control: self.control.clone(),
            actor: self.parent,
            child: claim.assigned_agent,
            request_id,
            unresolved: self.unresolved.clone(),
            settled: false,
        };
        let started = Instant::now();
        let mut cancelled = false;
        loop {
            match self.control.engine_child_completion(&claim) {
                Ok(Some(done)) => {
                    if !done.effects_known {
                        self.unresolved.store(true, Ordering::Release);
                        return AgentOutcome::null(
                            "controller child physical effects need reconciliation",
                        );
                    }
                    stop.settled = true;
                    stop.close();
                    if let Some(activity) = &activity {
                        activity.report(done.usage.tokens, 0, None);
                    }
                    return match done.terminal {
                        AgentWorkflowTerminal::Succeeded if !done.summary.is_empty() => {
                            AgentOutcome::text(done.summary, done.usage.tokens)
                        }
                        AgentWorkflowTerminal::Succeeded => {
                            AgentOutcome::null("controller child completed without a summary")
                        }
                        AgentWorkflowTerminal::Cancelled => {
                            AgentOutcome::null("controller child stopped at a safe point")
                        }
                        AgentWorkflowTerminal::Failed | AgentWorkflowTerminal::StoppedRecovery => {
                            AgentOutcome::null("controller child failed or stopped during recovery")
                        }
                    };
                }
                Err(_) => {
                    self.unresolved.store(true, Ordering::Release);
                    return AgentOutcome::null("controller child terminal evidence is unavailable");
                }
                Ok(None) => {}
            }
            if (call.cancel.is_cancelled() || Instant::now() >= self.deadline) && !cancelled {
                stop.close();
                cancelled = true;
            }
            // Cancellation remains a request; only the actual durable runtime terminal above can
            // claim cleanup. The engine's existing outer cleanup timeout may drop this waiter.
            if started.elapsed() > Duration::from_millis(claim.budget.wall_ms.saturating_add(1000))
            {
                self.unresolved.store(true, Ordering::Release);
                return AgentOutcome::null(
                    "controller child exceeded its terminal observation bound",
                );
            }
            tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
        }
    }
}
fn unknown(error: &ControllerError) -> bool {
    matches!(
        error,
        ControllerError::RecoveryRequired
            | ControllerError::Poisoned
            | ControllerError::Store(
                iteron_agents::ControllerStoreError::Conflict
                    | iteron_agents::ControllerStoreError::OutcomeUnknown
            )
    )
}
struct ChildStopGuard {
    control: Arc<dyn AgentControlPort>,
    actor: AgentIdV1,
    child: AgentIdV1,
    request_id: String,
    unresolved: Arc<AtomicBool>,
    settled: bool,
}
impl ChildStopGuard {
    fn close(&self) {
        if self
            .control
            .command(
                AgentActor::Agent(self.actor),
                &format!("{}:close", self.request_id),
                AgentCommandV1::Close {
                    agent_id: self.child,
                    include_descendants: true,
                },
            )
            .is_err()
        {
            self.unresolved.store(true, Ordering::Release);
        }
    }
}
impl Drop for ChildStopGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.unresolved.store(true, Ordering::Release);
            self.close();
        }
    }
}
#[async_trait]
impl AgentSpawner for ControllerEngineChildren {
    async fn spawn(&self, _: AgentCall) -> AgentOutcome {
        AgentOutcome::null("controller engine children require actual admitted engine identity")
    }
    async fn spawn_with_identity(
        &self,
        call: AgentCall,
        identity: AgentInvocationIdentity,
        activity: AgentActivityReporter,
    ) -> AgentOutcome {
        self.execute(
            call,
            identity.index(),
            identity.attempt(),
            Some(activity),
            false,
        )
        .await
    }
}
