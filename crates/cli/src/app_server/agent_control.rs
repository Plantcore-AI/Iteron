//! Public persistent-agent control owner. One real host port, immutable transport actor, finite work.

use std::sync::{Arc, Mutex};

use iteron_agents::{AgentActor, AgentControllerConfig};
use iteron_protocol::client_agent_control::ClientAgentControlV1;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot};

use super::ControlReply;
use crate::runtime::Agent;
use crate::runtime::persistent_agents::AgentControlPort;

const MAX_PENDING_CONTROLS: usize = 8;

pub(super) struct AgentControlSurface {
    port: Mutex<Option<Arc<dyn AgentControlPort>>>,
    capacity: Mutex<Option<Arc<Semaphore>>>,
}

impl AgentControlSurface {
    pub(super) fn capture(agent: &Agent) -> Self {
        Self {
            port: Mutex::new(agent.persistent_agent_control_port()),
            capacity: Mutex::new(None),
        }
    }

    pub(super) fn refresh(&self, agent: &Agent) {
        *self
            .port
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            agent.persistent_agent_control_port();
    }

    /// The parent turn keeps being polled while an independent bounded controller wait is pending.
    pub(super) fn dispatch(
        &self,
        command: ClientAgentControlV1,
        reply: oneshot::Sender<ControlReply>,
    ) {
        if let Err(reason) = command.validate() {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
        if command.is_enable() {
            let _ = reply.send(ControlReply::Refused(
                "agent enable requires an idle runtime boundary".into(),
            ));
            return;
        }
        let Some(port) = self
            .port
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            let _ = reply.send(ControlReply::Refused(
                "persistent agents are disabled for this session".into(),
            ));
            return;
        };
        let capacity = self
            .capacity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| Arc::new(Semaphore::new(MAX_PENDING_CONTROLS)))
            .clone();
        let Ok(permit) = capacity.try_acquire_owned() else {
            let _ = reply.send(ControlReply::Refused(
                "persistent agent control is busy; retry after a pending request settles".into(),
            ));
            return;
        };
        tokio::spawn(async move {
            let value = execute_port(port.as_ref(), command).await;
            let _ = reply.send(value);
            drop(permit);
        });
    }
}

pub(super) fn enable(agent: &mut Agent, command: ClientAgentControlV1) -> ControlReply {
    if let Err(reason) = command.validate() {
        return ControlReply::Refused(reason.into());
    }
    let ClientAgentControlV1::Enable {
        capabilities,
        budget,
        max_agents,
        max_pending_per_agent,
        parallel,
    } = command
    else {
        return ControlReply::Refused("not an agent enable request".into());
    };
    let workspace_scope = match agent.persistent_agent_workspace_scope() {
        Ok(scope) => scope,
        Err(error) => return ControlReply::Refused(error.public_summary()),
    };
    let config = AgentControllerConfig {
        workspace_scope,
        root_capabilities: capabilities,
        root_budget: budget,
        max_agents: max_agents as usize,
        max_pending_per_agent: max_pending_per_agent as usize,
    };
    match agent.enable_persistent_agents(config, parallel as usize) {
        Ok(()) => match agent.list_persistent_agents() {
            Ok(agents) => ControlReply::PersistentAgents(
                json!({"type":"agents_enabled_v1","contract_version":1,"agents":agents}),
            ),
            Err(_) => ControlReply::PersistentAgents(
                json!({"type":"agents_enabled_v1","contract_version":1,"agents":[],"observation_unavailable":true}),
            ),
        },
        Err(error) => ControlReply::Refused(error.public_summary()),
    }
}

async fn execute_port(port: &dyn AgentControlPort, command: ClientAgentControlV1) -> ControlReply {
    let result: Result<Value, iteron_agents::ControllerError> = match command {
        ClientAgentControlV1::Command { request_id,command } => port.command(AgentActor::Operator,&request_id,command)
            .map(|receipt| json!({"type":"agent_receipt_v1","receipt":receipt})),
        ClientAgentControlV1::List => port.list(AgentActor::Operator)
            .map(|agents| json!({"type":"agents_v1","agents":agents})),
        ClientAgentControlV1::Inspect { agent_id } => port.inspect(AgentActor::Operator,agent_id)
            .map(|agent| json!({"type":"agent_v1","agent":agent})),
        ClientAgentControlV1::MessageReceipt { message_id } => port.message(AgentActor::Operator,message_id)
            .map(|message| json!({"type":"agent_message_v1","message":message})),
        ClientAgentControlV1::Wait { after_revision,timeout_ms } => port.wait(AgentActor::Operator,after_revision,timeout_ms).await
            .map(|observation| json!({"type":"agent_observation_v1","revision":observation.revision,"agents":observation.agents,"timed_out":observation.timed_out})),
        ClientAgentControlV1::Enable { .. } => return ControlReply::Refused("agent enable requires the resident runtime".into()),
    };
    match result {
        Ok(mut value) => {
            value["contract_version"] =
                json!(iteron_protocol::agent_control::AGENT_CONTROL_VERSION);
            ControlReply::PersistentAgents(value)
        }
        Err(error) => ControlReply::Refused(error.to_string()),
    }
}
