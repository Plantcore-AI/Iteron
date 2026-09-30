//! Host/controller integration; the production kernel/provider journey is a separate gate.

#[allow(dead_code)]
#[path = "../src/runtime/persistent_agents.rs"]
mod persistent_agents;

use async_trait::async_trait;
use iteron_agents::{
    AgentActor, AgentController, AgentControllerConfig, AgentControllerJournal,
    AgentControllerSnapshot, AgentMailboxMessage, ControllerError, ControllerStoreError,
};
use iteron_protocol::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentEpochV1, AgentIdV1, AgentMessageStateV1, AgentStateV1,
    AgentViewV1,
};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Capability, Message};
use persistent_agents::{
    AgentControlPort, AgentSettlement, LiveAgentMailbox, PersistentAgentHost,
    PersistentAgentRuntime,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Store(Option<AgentControllerSnapshot>);

impl AgentControllerJournal for Store {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        Ok(self.0.clone())
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        if self.0.as_ref().map(AgentControllerSnapshot::revision) != expected {
            return Err(ControllerStoreError::Conflict);
        }
        self.0 = Some(next.clone());
        Ok(())
    }
}

#[derive(Default)]
struct Runtime {
    contexts: Mutex<BTreeMap<AgentIdV1, Vec<String>>>,
    requests: Mutex<BTreeMap<AgentIdV1, usize>>,
    finish: Mutex<BTreeMap<AgentIdV1, bool>>,
}

impl Runtime {
    fn included_request(
        &self,
        id: AgentIdV1,
        mailbox: &LiveAgentMailbox,
        inputs: Vec<AgentMailboxMessage>,
    ) {
        let texts: Vec<_> = inputs
            .iter()
            .map(|input| mailbox.render(input).unwrap())
            .collect();
        self.contexts
            .lock()
            .unwrap()
            .entry(id)
            .or_default()
            .extend(texts.clone());
        let messages = texts
            .into_iter()
            .map(Message::user_text)
            .collect::<Vec<_>>();
        mailbox.confirm_request(&messages).unwrap();
        *self.requests.lock().unwrap().entry(id).or_default() += 1;
    }
}

#[async_trait]
impl PersistentAgentRuntime for Runtime {
    fn validate_spawn(&self, _: &AgentCommandV1) -> Result<(), ControllerError> {
        Ok(())
    }
    async fn execute(
        &self,
        agent: AgentViewV1,
        _: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        mailbox: LiveAgentMailbox,
    ) -> AgentSettlement {
        self.included_request(agent.agent_id, &mailbox, initial);
        for _ in 0..500 {
            if mailbox.stop_requested()
                || self.finish.lock().unwrap().get(&agent.agent_id) == Some(&true)
            {
                break;
            }
            let input = match mailbox.receive() {
                Ok(input) => input,
                Err(_) => break,
            };
            if !input.is_empty() {
                self.included_request(agent.agent_id, &mailbox, input);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        AgentSettlement {
            turns: 1,
            summary: "physically settled fixture".into(),
            tokens: 1,
            cost_microusd: 0,
            effects_known: true,
            terminal: iteron_agents::AgentWorkflowTerminal::Succeeded,
        }
    }
}

fn budget(turns: u32) -> AgentBudgetV1 {
    AgentBudgetV1 {
        turns,
        tokens: u64::from(turns) * 1_000,
        cost_microusd: u64::from(turns),
        wall_ms: 5_000,
    }
}

fn host(runtime: Arc<Runtime>) -> PersistentAgentHost<Store> {
    let config = AgentControllerConfig {
        workspace_scope: "host-integration".into(),
        root_capabilities: CapabilitySet::only(Capability::ReadOnly),
        root_budget: budget(20),
        max_agents: 8,
        max_pending_per_agent: 8,
    };
    PersistentAgentHost::new(
        AgentController::open(Store::default(), config).unwrap(),
        runtime,
        2,
    )
    .unwrap()
}

fn spawn(host: &PersistentAgentHost<Store>, label: &str) -> AgentIdV1 {
    host.command(
        AgentActor::Operator,
        label,
        AgentCommandV1::Spawn {
            parent_id: AgentIdV1(1),
            label: label.into(),
            task: format!("task {label}"),
            capabilities: CapabilitySet::only(Capability::ReadOnly),
            budget: budget(4),
            write_paths: vec![],
        },
    )
    .unwrap()
    .agent_id
}

async fn until(host: &PersistentAgentHost<Store>, predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..1_000 {
            if predicate() {
                return;
            }
            let observation = host.wait(AgentActor::Operator, 0, 20).await.unwrap();
            assert!(observation.revision > 0);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("bounded observation did not settle");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sibling_steer_interrupt_same_context_followup_and_idle_no_wake() {
    let runtime = Arc::new(Runtime::default());
    let host = host(runtime.clone());
    let a = spawn(&host, "a");
    let b = spawn(&host, "b");
    until(&host, || runtime.requests.lock().unwrap().len() == 2).await;
    let a_epoch = host
        .inspect(AgentActor::Operator, a)
        .unwrap()
        .state
        .epoch()
        .unwrap();
    let b_epoch = host
        .inspect(AgentActor::Operator, b)
        .unwrap()
        .state
        .epoch()
        .unwrap();
    let sibling = host
        .command(
            AgentActor::Agent(a),
            "sibling",
            AgentCommandV1::SendMessage {
                agent_id: b,
                text: "A reports an observation".into(),
            },
        )
        .unwrap();
    let steer = host
        .command(
            AgentActor::Operator,
            "steer-a",
            AgentCommandV1::Steer {
                agent_id: a,
                epoch: a_epoch,
                text: "Only A changes direction".into(),
            },
        )
        .unwrap();
    until(&host, || matches!(host.message(AgentActor::Operator, sibling.message_id.unwrap()).unwrap().state, AgentMessageStateV1::Consumed { epoch } if epoch == b_epoch)).await;
    until(&host, || matches!(host.message(AgentActor::Operator, steer.message_id.unwrap()).unwrap().state, AgentMessageStateV1::Consumed { epoch } if epoch == a_epoch)).await;
    assert!(
        runtime.contexts.lock().unwrap()[&a]
            .iter()
            .any(|text| text.contains("Only A changes direction"))
    );
    assert!(
        !runtime.contexts.lock().unwrap()[&b]
            .iter()
            .any(|text| text.contains("Only A changes direction"))
    );
    host.command(
        AgentActor::Operator,
        "interrupt-b",
        AgentCommandV1::Interrupt {
            agent_id: b,
            epoch: b_epoch,
        },
    )
    .unwrap();
    until(&host, || {
        host.inspect(AgentActor::Operator, b).unwrap().state == AgentStateV1::Idle
    })
    .await;
    let before = runtime.requests.lock().unwrap()[&b];
    let queued = host
        .command(
            AgentActor::Operator,
            "idle-b",
            AgentCommandV1::SendMessage {
                agent_id: b,
                text: "idle context".into(),
            },
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(runtime.requests.lock().unwrap()[&b], before);
    assert_eq!(
        host.message(AgentActor::Operator, queued.message_id.unwrap())
            .unwrap()
            .state,
        AgentMessageStateV1::Accepted
    );
    host.command(
        AgentActor::Operator,
        "followup-b",
        AgentCommandV1::FollowupTask {
            agent_id: b,
            text: "B continues same context".into(),
        },
    )
    .unwrap();
    until(&host, || runtime.requests.lock().unwrap()[&b] > before).await;
    assert!(
        runtime.contexts.lock().unwrap()[&b]
            .iter()
            .any(|text| text.contains("A reports an observation"))
    );
    assert!(
        runtime.contexts.lock().unwrap()[&b]
            .iter()
            .any(|text| text.contains("B continues same context"))
    );
    host.command(
        AgentActor::Operator,
        "close-all",
        AgentCommandV1::Close {
            agent_id: AgentIdV1(1),
            include_descendants: true,
        },
    )
    .unwrap();
    until(&host, || {
        host.list(AgentActor::Operator)
            .unwrap()
            .iter()
            .all(|agent| agent.state == AgentStateV1::Closed)
    })
    .await;
}

#[tokio::test]
async fn wait_has_no_model_work_and_future_cursor_is_refused() {
    let runtime = Arc::new(Runtime::default());
    let host = host(runtime.clone());
    let observation = host.wait(AgentActor::Operator, 0, 5).await.unwrap();
    assert!(observation.timed_out);
    assert_eq!(observation.revision, 0);
    assert_eq!(observation.agents.len(), 1);
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(matches!(
        host.wait(AgentActor::Operator, 1, 5).await,
        Err(ControllerError::Invalid(_))
    ));
    assert!(matches!(
        host.wait(AgentActor::Operator, 0, 60_001).await,
        Err(ControllerError::Invalid(_))
    ));
}
