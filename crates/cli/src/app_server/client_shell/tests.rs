use super::*;
#[cfg(unix)]
use crate::app_server::{SubmitError, queue_wiring};
#[cfg(unix)]
use crate::client_effects::shell::ShellOutcome;
#[cfg(unix)]
use iteron_protocol::capability_set::CapabilitySet;
#[cfg(unix)]
use iteron_protocol::{Budget, Effort, Op, PermissionMode, PermissionRules, TenantId};
#[cfg(unix)]
struct IdleProvider;
#[cfg(unix)]
#[async_trait::async_trait]
impl iteron_provider::Provider for IdleProvider {
    async fn turn(
        &self,
        _: &iteron_provider::TurnRequest,
        _: &mut (dyn FnMut(iteron_provider::StreamItem) + Send),
    ) -> Result<iteron_provider::TurnResult, iteron_provider::ProviderError> {
        panic!("ordinary operator shell cannot perform provider IO")
    }
}
#[cfg(unix)]
struct Fixture {
    root: std::path::PathBuf,
    agent: Agent,
    reader: ContractReader,
    activity: ActivitySurface,
    handle: crate::app_server::AppServerHandle,
    _ends: crate::app_server::ServerEnds,
}
#[cfg(unix)]
impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-host-shell-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let run = RunId("shell-owned-run".into());
        let rollout =
            iteron_record::Rollout::open(&root.join("runs"), &run, TenantId::default()).unwrap();
        let mut agent = Agent::new(
            Arc::new(IdleProvider),
            iteron_tools::Registry::coding_agent(&root).unwrap(),
            rollout,
            "unused-model".into(),
            "test".into(),
            Budget::default(),
        );
        agent.workspace = root.clone();
        let (handle, ends) = queue_wiring::wire().unwrap();
        let reader = ends.events.contract.clone();
        reader.bind_identity(SessionId("shell-thread".into()), run);
        let (settled, _rx) = tokio::sync::mpsc::channel(4);
        let workflows = crate::workflow::WorkflowSupervisor::new(settled);
        let activity = ActivitySurface::capture(&agent, None, None, workflows);
        Self {
            root,
            agent,
            reader,
            activity,
            handle,
            _ends: ends,
        }
    }
    fn command(&self, text: &str) -> OperatorShellV1 {
        let scope = self.reader.snapshot().unwrap();
        OperatorShellV1 {
            thread_id: scope.thread_id,
            run_id: scope.run_id,
            command: text.into(),
        }
    }
    fn start(
        &self,
        text: &str,
        cancel: Option<watch::Receiver<bool>>,
    ) -> oneshot::Receiver<ControlReply> {
        let (send, receive) = oneshot::channel();
        dispatch(
            &self.agent,
            self.reader.clone(),
            &self.activity,
            self.command(text),
            cancel,
            send,
        );
        receive
    }
}
#[cfg(unix)]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn strict_shell_request_cannot_supply_host_policy_or_native_locator() {
    let input = serde_json::json!({"thread_id":"t","run_id":"r","command":"printf hello"});
    assert!(
        serde_json::from_value::<OperatorShellV1>(input.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    for field in [
        "workspace",
        "mode",
        "rules",
        "tenant",
        "credential_env_names",
        "actor",
        "stdin",
    ] {
        let mut forged = input.clone();
        forged[field] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<OperatorShellV1>(forged).is_err());
    }
}
#[cfg(unix)]
#[tokio::test]
async fn actual_host_plan_and_authority_ceiling_refuse_before_marker_or_provider_io() {
    let mut fixture = Fixture::new("permission");
    fixture
        .agent
        .configure_initial_runtime_policy(Effort::Low, PermissionMode::Plan, PermissionRules::new())
        .unwrap();
    let ControlReply::OperatorShell(refused) = fixture
        .start("printf forbidden > marker", None)
        .await
        .unwrap()
    else {
        panic!("shell receipt expected");
    };
    assert_eq!(refused.outcome, ShellOutcome::NotStarted);
    assert!(!fixture.root.join("marker").exists());
    fixture
        .agent
        .configure_initial_runtime_policy(
            Effort::Low,
            PermissionMode::Default,
            PermissionRules::new(),
        )
        .unwrap();
    fixture
        .agent
        .narrow_authority_ceiling(CapabilitySet::none());
    let ControlReply::OperatorShell(refused) = fixture
        .start("printf forbidden > marker", None)
        .await
        .unwrap()
    else {
        panic!("shell receipt expected");
    };
    assert_eq!(refused.outcome, ShellOutcome::NotStarted);
    assert!(!fixture.root.join("marker").exists());
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_observer_keeps_actual_sq_and_adoption_exclusions_until_native_cancel_reaps() {
    let fixture = Fixture::new("lost-observer");
    let (cancel, cancelled) = watch::channel(false);
    let reply = fixture.start("printf started > marker; sleep 30", Some(cancelled));
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !fixture.root.join("marker").exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(reply);
    assert!(matches!(
        fixture.handle.client.submit(Op::UserInput {
            text: "must wait".into()
        }),
        Err(SubmitError::Busy)
    ));
    assert!(fixture.activity.client_effect_gate().try_write().is_err());
    let second = fixture
        .start("printf duplicate > duplicate", None)
        .await
        .unwrap();
    assert!(matches!(second, ControlReply::Refused(_)));
    assert!(!fixture.root.join("duplicate").exists());
    cancel.send(true).unwrap();
    assert!(fixture.reader.shutdown_shell().await);
    assert_eq!(
        std::fs::read(fixture.root.join("marker")).unwrap(),
        b"started"
    );
    assert!(fixture.activity.client_effect_gate().try_write().is_ok());
    assert!(
        fixture
            .handle
            .client
            .submit(Op::UserInput {
                text: "actual owner finished".into()
            })
            .is_ok()
    );
}
#[cfg(unix)]
#[tokio::test]
async fn stale_thread_refuses_before_any_native_marker() {
    let fixture = Fixture::new("stale");
    let mut command = fixture.command("printf foreign > marker");
    command.thread_id = SessionId("another-thread".into());
    let (send, receive) = oneshot::channel();
    dispatch(
        &fixture.agent,
        fixture.reader.clone(),
        &fixture.activity,
        command,
        None,
        send,
    );
    assert!(matches!(receive.await.unwrap(), ControlReply::Refused(_)));
    assert!(!fixture.root.join("marker").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn explicit_external_and_trust_alias_denies_still_bind_authenticated_operator_commands() {
    let mut fixture = Fixture::new("operation-aliases");
    let mut rules = PermissionRules::new();
    rules.set_tool("bash", iteron_protocol::Verdict::Auto);
    rules.set_tool("bash:external", iteron_protocol::Verdict::Deny);
    rules.set_tool("bash:trust_mutating", iteron_protocol::Verdict::Deny);
    fixture
        .agent
        .configure_initial_runtime_policy(Effort::Low, PermissionMode::Default, rules)
        .unwrap();
    // Interpreter/substitution effects are genuinely unknown, so the actual operation classifier
    // retains both classes. Broad primitive Auto cannot erase a required alias Deny.
    let ControlReply::OperatorShell(refused) = fixture
        .start("printf forbidden > marker; echo $(printf opaque)", None)
        .await
        .unwrap()
    else {
        panic!("shell receipt expected");
    };
    assert_eq!(refused.outcome, ShellOutcome::NotStarted);
    assert!(!fixture.root.join("marker").exists());
}
