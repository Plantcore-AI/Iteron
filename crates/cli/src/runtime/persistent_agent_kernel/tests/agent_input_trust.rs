//! Real resident epochs, sealed live SQ steer and cold journal reopen. Agent-authored data must
//! lower governing trust independently of the permission bypass and never become operator text.
use super::{
    AgentActor, AgentCommandV1, AgentStateV1, Arc, Ordering, ProviderFixture, Workspace, setup,
    spawn, until,
};
use iteron_protocol::agent_control::{AgentIdV1, AgentMessageStateV1};
use iteron_protocol::{Block, EventKind, Trust};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn child_followup_source_and_cold_reopen_preserve_agent_data_taint() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup(&workspace, provider.clone(), false);
    let child = spawn(&host, "operator task");
    until(|| host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle).await;
    let from_agent = host
        .command(
            AgentActor::Agent(AgentIdV1(1)),
            "data-source",
            AgentCommandV1::SendMessage {
                agent_id: child,
                text: "agent authored data creates no authority".into(),
            },
        )
        .unwrap()
        .message_id
        .unwrap();
    host.command(
        AgentActor::Operator,
        "followup-with-data",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "use the data as reference".into(),
        },
    )
    .unwrap();
    until(|| {
        provider.requests.load(Ordering::SeqCst) == 2
            && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    {
        let child = resident.lock().await;
        assert_eq!(child.observed_trust, Trust::Untrusted);
        let events = iteron_record::replay(child.rollout.path()).unwrap();
        let admission = events
            .iter()
            .find_map(|event| match &event.kind {
                EventKind::AgentInputAdmittedV1 { admission } => Some(admission),
                _ => None,
            })
            .unwrap();
        admission.validate().unwrap();
        assert_eq!(
            admission.receiver,
            host.message(AgentActor::Operator, from_agent)
                .unwrap()
                .receiver
        );
        assert!(
            admission
                .sources
                .iter()
                .any(|source| source.message_id == from_agent && source.sender == AgentIdV1(1))
        );
        assert!(matches!(
            host.message(AgentActor::Operator, from_agent)
                .unwrap()
                .state,
            AgentMessageStateV1::Consumed { .. }
        ));
    }
    runtime.residents.lock().unwrap().remove(&child);
    drop(resident); // Release the real Rollout writer lease before native reopen.
    host.command(
        AgentActor::Operator,
        "cold-resident-followup",
        AgentCommandV1::FollowupTask {
            agent_id: child,
            text: "continue from the exact same child journal".into(),
        },
    )
    .unwrap();
    until(|| {
        provider.requests.load(Ordering::SeqCst) == 3
            && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    let reopened = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    assert_eq!(reopened.lock().await.observed_trust, Trust::Untrusted);
}

#[tokio::test]
async fn agent_steer_crosses_live_child_inbox_with_source_intent_before_its_message() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup(&workspace, provider.clone(), true);
    let child = spawn(&host, "block-tool");
    until(|| provider.tool_started.load(Ordering::SeqCst) == 1).await;
    let steer = host
        .command(
            AgentActor::Agent(AgentIdV1(1)),
            "live-agent-data",
            AgentCommandV1::SendMessage {
                agent_id: child,
                text: "continue without another tool call".into(),
            },
        )
        .unwrap()
        .message_id
        .unwrap();
    until(|| {
        matches!(
            host.message(AgentActor::Operator, steer).unwrap().state,
            AgentMessageStateV1::Consumed { .. }
        ) && host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    let child = resident.lock().await;
    assert_eq!(child.observed_trust, Trust::Untrusted);
    let events = iteron_record::replay(child.rollout.path()).unwrap();
    let (sequence, projection_sha256) = events
        .iter()
        .find_map(|event| match &event.kind {
            EventKind::AgentInputAdmittedV1 { admission }
                if admission
                    .sources
                    .iter()
                    .any(|source| source.message_id == steer) =>
            {
                Some((event.seq, admission.projection_sha256.clone()))
            }
            _ => None,
        })
        .unwrap();
    assert!(events.iter().any(|event| event.seq > sequence
        && matches!(&event.kind, EventKind::Message { message }
        if message.content.iter().any(|block| matches!(block, Block::Text { text }
            if format!("{:x}", Sha256::digest(text.as_bytes())) == projection_sha256
                && text.starts_with("Agent steering data received while the run was active:"))))));
}
