//! Real resident epochs, sealed live SQ steer and cold journal reopen. Agent-authored data must
//! lower governing trust independently of the permission bypass and never become operator text.
use super::{
    AgentActor, AgentCommandV1, AgentStateV1, Arc, Ordering, ProviderFixture, Workspace,
    resident_observation, setup, spawn, until, until_observed, until_resident_observed,
};
use crate::runtime::persistent_agents::AgentControlPort;
use iteron_protocol::agent_control::{AgentIdV1, AgentMessageStateV1};
use iteron_protocol::{Block, EventKind, Trust};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn child_followup_source_and_cold_reopen_preserve_agent_data_taint() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup(&workspace, provider.clone(), false);
    let child = spawn(&host, "operator task");
    until_resident_observed(&host, child, &provider, || {
        host.inspect(AgentActor::Operator, child).unwrap().state == AgentStateV1::Idle
    })
    .await;
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
    until_resident_observed(&host, child, &provider, || {
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
    let (original_run, original_policy, original_attempts, original_prefix) = {
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
        (
            child.rollout.run_id().clone(),
            (
                child.effort,
                child.permission_mode,
                child.permission_rules.clone(),
            ),
            child.ledger.provider_attempts,
            std::fs::read(child.rollout.path()).unwrap(),
        )
    };
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
    until_resident_observed(&host, child, &provider, || {
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
    let reopened = reopened.lock().await;
    assert_eq!(reopened.observed_trust, Trust::Untrusted);
    assert_eq!(reopened.rollout.run_id(), &original_run);
    assert_eq!(
        (
            reopened.effort,
            reopened.permission_mode,
            reopened.permission_rules.clone()
        ),
        original_policy
    );
    assert_eq!(reopened.ledger.provider_attempts, original_attempts + 1);
    assert!(
        std::fs::read(reopened.rollout.path())
            .unwrap()
            .starts_with(&original_prefix)
    );
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
    // Durable acceptance precedes the live mailbox pump's next poll. Keep the real tool
    // running until delivery, so a fast response cannot settle and reject the queued steer.
    until_observed(
        || {
            matches!(
                host.message(AgentActor::Operator, steer).unwrap().state,
                AgentMessageStateV1::Delivered { .. }
            )
        },
        || {
            format!(
                "steer={:?}; {}",
                host.message(AgentActor::Operator, steer),
                resident_observation(&host, child, &provider)
            )
        },
    )
    .await;
    provider.tool_release.notify_one();
    until_resident_observed(&host, child, &provider, || {
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
