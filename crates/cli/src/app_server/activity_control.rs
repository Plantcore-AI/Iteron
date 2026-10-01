//! Unified queries/control reach the same live process, controller, workflow, MCP and verifier owners.
use super::{ControlReply, product_contract::ContractReader};
use crate::runtime::{
    Agent, bounded_verify::VerificationTaskRegistry, persistent_agents::AgentControlPort,
};
use iteron_agents::AgentActor;
use iteron_protocol::agent_control::AgentCommandV1;
use iteron_protocol::{
    RunId,
    activity_control::{ActivityControlV1, ActivityTargetV1},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, Semaphore, oneshot};

#[derive(Clone)]
struct Binding {
    run: RunId,
    agents: Option<Arc<dyn AgentControlPort>>,
    verifier: Arc<VerificationTaskRegistry>,
}
pub(super) struct ActivitySurface {
    binding: Mutex<Binding>,
    processes: Option<iteron_tools::ProcessControl>,
    mcp: Option<crate::mcp::McpRuntimeControl>,
    workflows: Arc<crate::workflow::WorkflowSupervisor>,
    capacity: Arc<Semaphore>,
    scope_gate: Arc<RwLock<()>>,
}
impl ActivitySurface {
    pub(super) fn capture(
        agent: &Agent,
        processes: Option<iteron_tools::ProcessControl>,
        mcp: Option<crate::mcp::McpRuntimeControl>,
        workflows: Arc<crate::workflow::WorkflowSupervisor>,
    ) -> Self {
        Self {
            binding: Mutex::new(binding(agent)),
            processes,
            mcp,
            workflows,
            capacity: Arc::new(Semaphore::new(8)),
            scope_gate: Arc::new(RwLock::new(())),
        }
    }
    /// The sole runtime adoption path holds this exclusive lease before swapping journals.
    /// Admitted detached owner controls retain a read lease through their actual effects.
    pub(super) async fn adoption_barrier(&self) -> Result<OwnedRwLockWriteGuard<()>, &'static str> {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.scope_gate.clone().write_owned(),
        )
        .await
        .map_err(|_| "admitted owner control still running; retry adoption")
    }
    pub(super) fn scope_lease(
        &self,
        reader: &ContractReader,
        thread: &iteron_protocol::SessionId,
        run: &RunId,
    ) -> Result<OwnedRwLockReadGuard<()>, &'static str> {
        let lease = self
            .scope_gate
            .clone()
            .try_read_owned()
            .map_err(|_| "session adoption is pending")?;
        if reader
            .snapshot()
            .is_none_or(|snapshot| snapshot.thread_id != *thread || snapshot.run_id != *run)
        {
            return Err("activity scope mismatch");
        }
        Ok(lease)
    }
    pub(super) fn client_effect_gate(&self) -> Arc<RwLock<()>> {
        self.scope_gate.clone()
    }
    pub(super) fn refresh(&self, agent: &Agent) {
        *self
            .binding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = binding(agent);
    }
    pub(super) fn dispatch(
        &self,
        reader: ContractReader,
        command: ActivityControlV1,
        reply: oneshot::Sender<ControlReply>,
    ) {
        if let Err(reason) = command.validate() {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
        let scope = command.scope();
        let lease = match self.scope_lease(&reader, scope.0, scope.1) {
            Ok(lease) => lease,
            Err(reason) => {
                let _ = reply.send(ControlReply::Refused(reason.into()));
                return;
            }
        };
        let binding = self
            .binding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (thread, run) = command.scope();
        if binding.run != *run
            || reader
                .snapshot()
                .is_none_or(|snapshot| snapshot.thread_id != *thread || snapshot.run_id != *run)
        {
            let _ = reply.send(ControlReply::Refused("activity scope mismatch".into()));
            return;
        }
        let Ok(permit) = self.capacity.clone().try_acquire_owned() else {
            let _ = reply.send(ControlReply::Refused("activity owner busy".into()));
            return;
        };
        let processes = self.processes.clone();
        let mcp = self.mcp.clone();
        let workflows = self.workflows.clone();
        tokio::spawn(async move {
            let scope = command.scope();
            let thread = scope.0.clone();
            let run = scope.1.clone();
            let value = execute(
                &binding,
                processes.as_ref(),
                mcp.as_ref(),
                &workflows,
                command,
            )
            .await;
            let value = value.map(|mut value| {
                if let Some(activities)=value["activities"].as_array_mut() {
                    for activity in activities {
                        activity["owner_scope"] = match activity["target"]["kind"].as_str() {
                            Some("process"|"mcp"|"workflow")=>json!({"kind":"resident_session","thread_id":thread,"creation_run_id":null}),
                            _=>json!({"kind":"physical_run","run_id":run}),
                        };
                    }
                }
                value
            });
            let result = if reader
                .snapshot()
                .is_some_and(|snapshot| snapshot.thread_id == thread && snapshot.run_id == run)
            {
                match value {
                    Ok(value) => ControlReply::ActivityCenter(
                        json!({"type":"activity_center_v1","thread_id":thread,"run_id":run,"data":value}),
                    ),
                    Err(reason) => ControlReply::Refused(reason),
                }
            } else {
                ControlReply::Refused("activity scope changed".into())
            };
            let _ = reply.send(result);
            drop(permit);
            drop(lease);
        });
    }
}
fn binding(agent: &Agent) -> Binding {
    Binding {
        run: agent.rollout.run_id().clone(),
        agents: agent.persistent_agent_control_port(),
        verifier: agent.verification_task_port(),
    }
}
async fn execute(
    binding: &Binding,
    processes: Option<&iteron_tools::ProcessControl>,
    mcp: Option<&crate::mcp::McpRuntimeControl>,
    workflows: &crate::workflow::WorkflowSupervisor,
    command: ActivityControlV1,
) -> Result<Value, String> {
    match command {
        ActivityControlV1::List{..}=>{
            let agents=match &binding.agents {Some(port)=>Some(port.list(AgentActor::Operator).map_err(|_|"agent owner unavailable")?),None=>None};
            let mut activities=Vec::new(); let mut omitted=0_usize;
            if let Some(processes)=processes {
                let entries=processes.list().map_err(|error|error.message)?;
                if let Some(entries)=entries.as_array() { for entry in entries.iter().take(64) {
                    let id=entry["job_id"].as_str().or_else(||entry["id"].as_str()).ok_or("process owner identity unavailable")?;
                    activities.push(json!({"target":{"kind":"process","job_id":id},"source":"actual_process_supervisor","state":entry["state"],"details":scrub(entry),"stop_supported":true}));
                } omitted+=entries.len().saturating_sub(64); }
            }
            if let Some(agents)=&agents {for view in agents.iter().take(64) {
                activities.push(json!({"target":{"kind":"persistent_agent","agent_id":view.agent_id,"epoch":view.state.epoch()},"source":"durable_agent_controller","state":view.state,"details":{"label":iteron_record::redact::scrub(&view.label),"usage":view.usage,"summary":view.last_summary.as_deref().map(iteron_record::redact::scrub)},"stop_supported":view.state.epoch().is_some()}));
            } omitted+=agents.len().saturating_sub(64); }
            for run in workflows.inventory().into_iter().take(64) {
                activities.push(json!({"target":{"kind":"workflow","run_id":run.run_id},"source":"actual_session_workflow_supervisor","state":format!("{:?}",run.status).to_lowercase(),"details":{"name":iteron_record::redact::scrub(&run.name),"running_agents":run.running_agents,"finished_agents":run.finished_agents,"elapsed_ms":run.elapsed_ms},"stop_supported":matches!(run.status,crate::workflow::SupervisedRunStatus::Running|crate::workflow::SupervisedRunStatus::Cancelling)}));
            }
            if let Some(mcp)=mcp { let health=mcp.health(); for server in health.iter().take(64) {
                activities.push(json!({"target":{"kind":"mcp","name":server.name},"source":"actual_mcp_actor","state":server.phase,"details":{"busy":server.busy,"generation":server.generation,"origin":server.origin,"plugin_identity":server.plugin_identity,"last_failure":server.last_failure.as_deref().map(iteron_record::redact::scrub)},"stop_supported":true}));
            } omitted+=health.len().saturating_sub(64); }
            let verifier=binding.verifier.list(&binding.run);
            for task in verifier["tasks"].as_array().into_iter().flatten() {
                activities.push(json!({"target":{"kind":"verifier","task_id":task["task_id"]},"source":task["evidence_source"],"state":task["state"],"details":task,"stop_supported":matches!(task["state"].as_str(),Some("admitted"|"running"))}));
            }
            Ok(json!({"activities":activities,"omitted":omitted,"dropped_verifier_tasks":verifier["dropped_tasks"],"owners":{"processes":processes.is_some(),"persistent_agents":agents.is_some(),"mcp":mcp.is_some(),"workflows":true,"verifier":true},"recovery":"persistent controller and verified verifier effects retain state; process/MCP/session workflow entries describe only these captured live owners"}))
        }
        ActivityControlV1::Inspect{target,stdout_cursor,stderr_cursor,..}=>match target {
            ActivityTargetV1::Verifier{task_id}=>binding.verifier.inspect(&binding.run,&task_id).map_err(str::to_string),
            ActivityTargetV1::Process{job_id}=>processes.ok_or("process owner unavailable")?.poll(&job_id,stdout_cursor,stderr_cursor,0).await.map(|value|scrub(&value)).map_err(|error|error.message),
            ActivityTargetV1::PersistentAgent{agent_id,..}=>binding.agents.as_ref().ok_or("agent owner unavailable")?.inspect(AgentActor::Operator,agent_id).map(|view|json!({"source":"durable_agent_controller","view":scrub(&serde_json::to_value(view).unwrap_or(Value::Null))})).map_err(|_|"agent inspection refused".into()),
            ActivityTargetV1::Workflow{run_id}=>workflows.inventory().into_iter().find(|run|run.run_id==run_id).map(|run|json!({"run_id":run.run_id,"name":iteron_record::redact::scrub(&run.name),"state":format!("{:?}",run.status).to_lowercase(),"running_agents":run.running_agents,"finished_agents":run.finished_agents,"source":"actual_session_workflow_supervisor"})).ok_or("workflow not retained".into()),
            ActivityTargetV1::Mcp{name}=>mcp.ok_or("MCP owner unavailable")?.health().into_iter().find(|server|server.name==name).map(|server|scrub(&serde_json::to_value(server).unwrap_or(Value::Null))).ok_or("MCP server not retained".into()),
        },
        ActivityControlV1::Stop{target,request_id,..}=>match target {
            ActivityTargetV1::Verifier{task_id}=>binding.verifier.cancel(&binding.run,&task_id).map_err(str::to_string),
            ActivityTargetV1::Process{job_id}=>processes.ok_or("process owner unavailable")?.stop(&job_id).await.map(|value|scrub(&value)).map_err(|error|error.message),
            ActivityTargetV1::PersistentAgent{agent_id,epoch}=>binding.agents.as_ref().ok_or("agent owner unavailable")?.command(AgentActor::Operator,&request_id,AgentCommandV1::Interrupt{agent_id,epoch:epoch.ok_or("missing observed agent epoch")?}).map(|receipt|json!({"receipt":receipt,"stop_requested":true,"terminal_observed":false})).map_err(|_|"agent interruption refused".into()),
            ActivityTargetV1::Workflow{run_id}=>workflows.cancel_for_operator(&run_id).map(|run|json!({"run_id":run.run_id,"stop_requested":true,"terminal_observed":false})),
            ActivityTargetV1::Mcp{name}=>{ let mcp=mcp.ok_or("MCP owner unavailable")?; if !mcp.cancel(&name){return Err("MCP cancellation refused".into());} Ok(json!({"name":name,"stop_requested":true,"terminal_observed":false,"meaning":"cancel current actor operation"})) },
        }
    }
}
fn scrub(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(iteron_record::redact::scrub(text)),
        Value::Array(values) => Value::Array(values.iter().map(scrub).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), scrub(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}
