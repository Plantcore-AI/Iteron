//! Actual Agent→driver→observed-provider→physical-WAL fault journeys. No fabricated terminal or
//! copied phase state is supplied to the driver.
use crate::runtime::{Agent, DurableAppendFault, KernelError, Outcome, gate_integration_tests};
use iteron_protocol::turn_publication::TurnPublicationFactV1;
use iteron_protocol::{Block, Budget, EventKind, RunId, StopReason, TenantId, ToolUse, Usage};
use iteron_provider::request_capture::{ProviderRequestObserver, ProviderWireRequest};
use iteron_provider::{
    AdapterKind, Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport,
};
use iteron_record::Rollout;
use iteron_tools::Registry;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct ObservedProvider {
    attempts: AtomicUsize,
    sent: AtomicUsize,
    connect_failure_once: bool,
    refuse_capture: bool,
    stream_failure_once: bool,
    tool_round: bool,
    follow_up: bool,
    cache_creation_unreported: bool,
}
#[async_trait::async_trait]
impl Provider for ObservedProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("driver-fixture")
    }
    fn physical_input_token_ceiling(&self, _: &str) -> Option<u64> {
        Some(4096)
    }
    fn physical_output_token_ceiling(
        &self,
        budget: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        Ok(Some(budget.requested_max_tokens))
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("driver must enter the actual observed adapter port")
    }
    async fn turn_observed(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 && self.connect_failure_once {
            return Err(ProviderError::ConnectFailed);
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "model":request.model, "messages":request.messages,
            "system":request.system, "max_tokens":request.max_tokens,
        }))
        .unwrap();
        observer
            .prepared(ProviderWireRequest {
                adapter: AdapterKind::OpenAiCompatibleChat,
                method: "POST",
                endpoint: "https://driver-fixture.invalid/v1",
                content_type: "application/json",
                body: &bytes,
                serialized_output_tokens: request.max_tokens,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        if self.refuse_capture {
            return Err(ProviderError::RequestCaptureRefusedBeforeDispatch);
        }
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        self.sent.fetch_add(1, Ordering::SeqCst);
        if self.tool_round && attempt < 2 {
            if attempt == 0 {
                let calls = ["alpha", "beta"]
                    .into_iter()
                    .map(|name| ToolUse {
                        id: format!("observed-{name}"),
                        name: "read_file".into(),
                        input: serde_json::json!({"path":format!("{name}.txt")}),
                    })
                    .collect::<Vec<_>>();
                for call in &calls {
                    on_item(StreamItem::ToolUseComplete(call.clone()));
                }
                return Ok(TurnResult {
                    blocks: calls.into_iter().map(Block::ToolUse).collect(),
                    stop_reason: StopReason::ToolUse,
                    usage: UsageReport::complete(Usage::default()),
                });
            }
            let results = request
                .messages
                .last()
                .expect("settled tool response")
                .content
                .iter()
                .filter_map(|block| match block {
                    Block::ToolResult(result) => Some(result),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(results.len(), 2);
            for (result, name) in results.iter().zip(["alpha", "beta"]) {
                assert_eq!(result.tool_use_id, format!("observed-{name}"));
                assert!(
                    result
                        .content
                        .contains(&format!("actual native {name} bytes"))
                );
                assert!(!result.is_error);
            }
        }
        if self.follow_up && attempt == 2 {
            let mut results = 0;
            let mut initial = 0;
            let mut follow_up = 0;
            for block in request.messages.iter().flat_map(|message| &message.content) {
                match block {
                    Block::ToolResult(_) => results += 1,
                    Block::Text { text } if text == "read the two real files" => initial += 1,
                    Block::Text { text }
                        if text == "continue using the same settled observations" =>
                    {
                        follow_up += 1
                    }
                    _ => {}
                }
            }
            assert_eq!((results, initial, follow_up), (2, 1, 1));
        }
        if attempt == 0 && self.stream_failure_once {
            on_item(StreamItem::TextDelta("observed partial output".into()));
            return Err(ProviderError::Http("fixture response disconnect".into()));
        }
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "driver journey complete".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: if self.cache_creation_unreported {
                UsageReport::CacheCreationUnreported(Usage {
                    input: 100,
                    output: 10,
                    thinking: 5,
                    ..Usage::default()
                })
            } else {
                UsageReport::complete(Usage::default())
            },
        })
    }
}

#[tokio::test]
async fn actual_native_tool_round_is_complete_ordered_and_counted_once_after_reopen() {
    let provider = Arc::new(ObservedProvider {
        tool_round: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-native-tool-round");
    owner.pure_overlap_enabled = false;
    for name in ["alpha", "beta"] {
        std::fs::write(
            owner.workspace.join(format!("{name}.txt")),
            format!("actual native {name} bytes"),
        )
        .unwrap();
    }
    assert_eq!(
        owner.run("read the two real files").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(owner.ledger.tool_calls, 2);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 2);
    let path = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    let ids = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::ToolDone {
                tool: Some(tool),
                result,
                ..
            } if tool == "read_file" => Some(result.tool_use_id.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["observed-alpha", "observed-beta"]);
}
fn agent(provider: Arc<ObservedProvider>, label: &str) -> Agent {
    let workspace = gate_integration_tests::temp_ws(label);
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId(label.into()),
        TenantId::default(),
    )
    .unwrap();
    let mut owner = Agent::new(
        provider.clone(),
        Registry::read_only(&workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        "driver fixture".into(),
        Budget::default(),
    );
    owner.workspace = workspace;
    gate_integration_tests::pin_test_tunables_with_edits(&mut owner, []);
    owner
        .record_operator_model_selection(
            provider,
            "driver-fixture".into(),
            "fixture-model".into(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
    owner.retry_policy = iteron_sched::BackoffPolicy {
        base_ms: 0,
        cap_ms: 0,
        max_attempts: 2,
    };
    owner
}
#[tokio::test]
async fn settled_zero_connect_retry_opens_two_distinct_physical_intents_and_reopens() {
    let provider = Arc::new(ObservedProvider {
        connect_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-settled-retry");
    assert_eq!(
        owner.run("complete the fixture").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 2);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 1);
    let path = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    let physical = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::EffectIntent {
                tool,
                provider_route_attempt: Some(identity),
                ..
            } if tool == "provider" => Some(identity.physical_attempt),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(physical, vec![1, 2]);
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::EffectFailed {
        tool, provider_route_attempt:Some(accounting), ..
    } if tool == "provider" && accounting.usage == iteron_protocol::ProviderRouteUsageTruth::NotDispatched)));
    assert!(events.iter().any(
        |event| matches!(&event.kind, EventKind::EffectDone { tool, .. } if tool == "provider")
    ));
}
#[tokio::test]
async fn local_capture_refusal_is_not_retried_and_retains_a_zero_physical_terminal() {
    let provider = Arc::new(ObservedProvider {
        refuse_capture: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-capture-zero");
    assert!(matches!(
        owner.run("complete the fixture").await,
        Err(KernelError::Provider(
            ProviderError::RequestCaptureRefusedBeforeDispatch
        ))
    ));
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 0);
    let events = iteron_record::replay(owner.rollout.path()).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectIntent {tool,..} if tool == "provider")).count(),1);
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::EffectFailed {
        tool, provider_route_attempt:Some(accounting), ..
    } if tool == "provider" && accounting.cost == iteron_protocol::ProviderRouteCostTruth::NotDispatched)));
}
#[tokio::test]
async fn refused_actual_intent_cannot_enter_the_adapter() {
    let provider = Arc::new(ObservedProvider::default());
    let mut owner = agent(provider.clone(), "driver-intent-refused");
    owner.fail_next_durable_append = Some(DurableAppendFault::EffectIntent);
    assert!(matches!(
        owner.run("complete the fixture").await,
        Err(KernelError::Record(_))
    ));
    assert_eq!(provider.attempts.load(Ordering::SeqCst), 0);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn actual_semantic_disconnect_continues_only_from_retained_output_and_keeps_unknown_charge() {
    let provider = Arc::new(ObservedProvider {
        stream_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-response-salvage");
    assert_eq!(
        owner.run("complete the fixture").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(provider.sent.load(Ordering::SeqCst), 2);
    let path = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectUnknown { tool,.. } if tool=="provider")).count(),1);
    assert_eq!(
        events
            .iter()
            .filter(
                |event| matches!(&event.kind, EventKind::EffectDone {tool,..} if tool=="provider")
            )
            .count(),
        1
    );
    assert!(events.iter().any(|event| matches!(&event.kind, EventKind::Message {message}
        if message.role==iteron_protocol::Role::Assistant && message.content.iter().any(|block| matches!(block, Block::Text {text} if text.contains(crate::runtime::provider_response_recovery::INTERRUPTED_STREAM_MARKER))))));
}
#[tokio::test]
async fn exhausted_semantic_recovery_preserves_exact_observed_prefix_before_error_and_reopen() {
    let provider = Arc::new(ObservedProvider {
        stream_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-response-prefix");
    owner.retry_policy.max_attempts = 1;
    assert!(matches!(
        owner.run("complete the fixture").await,
        Err(KernelError::Provider(ProviderError::Http(_)))
    ));
    assert_eq!(provider.sent.load(Ordering::SeqCst), 1);
    assert!(!owner.effect_journal.parent_settlement_known());
    let facts = owner.recovered_turn_publications_v1().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(
        facts[0].fact,
        TurnPublicationFactV1::finalized(&Outcome::HarnessError).unwrap()
    );
    let path = owner.rollout.path().to_owned();
    let workspace = owner.workspace.clone();
    let run_id = owner.rollout.run_id().clone();
    owner.finish_advisory_maintenance_for_test().await.unwrap();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    let prefix = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::Text { delta } => Some(delta.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(prefix, vec!["observed partial output"]);
    assert!(
        events.iter().any(
            |event| matches!(&event.kind,EventKind::EffectUnknown {tool,..} if tool=="provider")
        )
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(&event.kind, EventKind::TurnEnd { .. }))
    );
    let terminals = events
        .iter()
        .filter(|event| matches!(&event.kind, EventKind::Done { .. }))
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 1);
    assert!(matches!(&terminals[0].kind, EventKind::Done { outcome } if outcome == "HarnessError"));
    assert_eq!(facts[0].source_seq, terminals[0].seq.0);
    assert_eq!(facts[0].turn_id, terminals[0].turn);
    let policy = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::PolicyOutcome { evidence }
                if evidence.scope == iteron_protocol::PolicyOutcomeScope::Turn =>
            {
                Some(evidence)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(policy.len(), 1);
    assert_eq!(
        policy[0].harness_error_code.as_deref(),
        Some("provider_error")
    );
    let reopened = Agent::new(
        provider.clone(),
        Registry::read_only(&workspace).unwrap(),
        Rollout::open_existing(
            &workspace.join(".iteron/runs"),
            &run_id,
            TenantId::default(),
        )
        .unwrap(),
        "fixture-model".into(),
        "driver fixture".into(),
        Budget::default(),
    );
    assert_eq!(reopened.recovered_turn_publications_v1().unwrap(), facts);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 1);
    reopened
        .finish_advisory_maintenance_for_test()
        .await
        .unwrap();
    drop(reopened);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn priced_stream_failure_keeps_budget_closed_after_failed_terminal() {
    let provider = Arc::new(ObservedProvider {
        stream_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-priced-response-failure");
    owner.budget.max_usd = Some(1.0);
    let fixture_key = [42; 32];
    let card = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route: iteron_protocol::PricingRoute {
                provider_id: "driver-fixture".into(),
                model_id: "fixture-model".into(),
                catalog_digest: format!("sha256:{}", "a".repeat(64)),
                capability_digest: format!("sha256:{}", "b".repeat(64)),
            },
            provenance: "driver-fixture@v1".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            rates: iteron_protocol::TokenRateCard {
                input_microusd_per_million: 1_000_000,
                output_microusd_per_million: 2_000_000,
                cache_creation_microusd_per_million: 1_250_000,
                cache_read_microusd_per_million: 100_000,
                thinking_microusd_per_million: 3_000_000,
            },
        },
        "driver-pricing-fixture",
        fixture_key,
    )
    .unwrap();
    owner.set_pricing_port(Arc::new(
        iteron_obs::HmacPricingAuthority::new(vec![(
            card,
            iteron_obs::HmacPricingKey::from_bytes(fixture_key),
        )])
        .unwrap(),
    ));
    assert!(owner.bind_selected_rate_card().unwrap());
    assert!(matches!(
        owner.run("complete the fixture").await,
        Err(KernelError::UnpricedUsdCeiling)
    ));
    assert!(owner.usd_budget_exhausted());
    assert!(!owner.effect_journal.parent_settlement_known());
    let facts = owner.recovered_turn_publications_v1().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(
        facts[0].fact,
        TurnPublicationFactV1::finalized(&Outcome::HarnessError).unwrap()
    );
    assert!(matches!(
        owner.run("must remain quarantined").await,
        Err(KernelError::UnpricedUsdCeiling)
    ));
    assert_eq!(provider.sent.load(Ordering::SeqCst), 1);
    assert_eq!(owner.recovered_turn_publications_v1().unwrap(), facts);
    let events = iteron_record::replay(owner.rollout.path()).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectUnknown { tool, .. } if tool == "provider")).count(), 1);
    assert!(!events.iter().any(|event| matches!(
        &event.kind,
        EventKind::TurnEnd { .. } | EventKind::EffectDone { .. }
    )));
    let workspace = owner.workspace.clone();
    owner.finish_advisory_maintenance_for_test().await.unwrap();
    drop(owner);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn failed_provider_terminal_append_refusal_retains_unknown_without_inventing_done() {
    let provider = Arc::new(ObservedProvider {
        stream_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "driver-response-terminal-refusal");
    owner.retry_policy.max_attempts = 1;
    owner.fail_next_durable_append = Some(DurableAppendFault::RunTerminal);
    assert!(matches!(
        owner.run("complete the fixture").await,
        Err(KernelError::Record(_))
    ));
    assert!(owner.record_failed);
    assert!(!owner.effect_journal.parent_settlement_known());
    assert!(owner.recovered_turn_publications_v1().unwrap().is_empty());
    let events = iteron_record::replay(owner.rollout.path()).unwrap();
    assert_eq!(provider.sent.load(Ordering::SeqCst), 1);
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectUnknown { tool, .. } if tool == "provider")).count(), 1);
    assert!(!events.iter().any(|event| matches!(
        &event.kind,
        EventKind::Done { .. } | EventKind::TurnEnd { .. }
    )));
    let workspace = owner.workspace.clone();
    drop(owner);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn resident_stream_failure_releases_input_and_accepts_one_explicit_follow_up() {
    use crate::app_server::{AppServerHandle, Attached, ServerEvent, attach};
    use crate::runtime::UiEvent;
    use iteron_protocol::{ActivityDetailCode, Op};
    use std::time::Duration;

    let provider = Arc::new(ObservedProvider {
        stream_failure_once: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "resident-stream-failure");
    owner.retry_policy.max_attempts = 1;
    let workspace = owner.workspace.clone();
    let path = owner.rollout.path().to_owned();
    let Attached { handle, task, .. } = attach(owner, false, true).unwrap();
    let AppServerHandle {
        client,
        mut events,
        control,
        ..
    } = handle;
    for (index, prompt) in ["complete the fixture", "answer this new explicit prompt"]
        .into_iter()
        .enumerate()
    {
        // The second dispatch requires a new operator submission after the first terminal.
        assert_eq!(provider.sent.load(Ordering::SeqCst), index);
        client
            .submit(Op::UserInput {
                text: prompt.into(),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut summary = None;
            let mut finalized = Vec::new();
            let mut provider_turn_ends = 0;
            loop {
                match events
                    .recv()
                    .await
                    .expect("resident session stays open")
                    .into_current()
                    .unwrap()
                {
                    ServerEvent::TurnPublication(event)
                        if matches!(event.fact, TurnPublicationFactV1::TurnFinalized { .. }) =>
                    {
                        finalized.push(event)
                    }
                    ServerEvent::Ui(UiEvent::TurnEnd { .. }) => provider_turn_ends += 1,
                    ServerEvent::RunEnded {
                        summary: terminal, ..
                    } => {
                        assert!(summary.is_none(), "one runtime release per submission");
                        summary = Some(terminal);
                    }
                    ServerEvent::Activity(activity)
                        if activity.detail_code == Some(ActivityDetailCode::InputReady) =>
                    {
                        let summary = summary.expect("input becomes ready only after RunEnded");
                        let expected = if index == 0 {
                            Outcome::HarnessError
                        } else {
                            Outcome::Done
                        };
                        assert_eq!(summary.terminal.outcome(), expected);
                        assert_eq!(summary.error.is_some(), index == 0);
                        assert_eq!(finalized.len(), 1);
                        assert_eq!(
                            finalized[0].fact,
                            TurnPublicationFactV1::finalized(&expected).unwrap()
                        );
                        assert_eq!(
                            provider_turn_ends, index,
                            "a disconnected provider never supplies invented usage"
                        );
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("failed response settles and releases the resident input within a bounded wait");
        assert_eq!(provider.sent.load(Ordering::SeqCst), index + 1);
    }
    drop(control);
    drop(client);
    drop(events);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("resident session shuts down after its clients close")
        .unwrap();
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")).count(), 2);
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectDone { tool, .. } if tool == "provider")).count(), 1);
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectUnknown { tool, .. } if tool == "provider")).count(), 1);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind, EventKind::Done { .. }))
            .count(),
        2
    );
    assert_eq!(provider.sent.load(Ordering::SeqCst), 2);
    std::fs::remove_dir_all(workspace).unwrap();
}

#[tokio::test]
async fn coding_run_returns_the_actual_tool_transcript_to_a_follow_up_without_reexecution() {
    let provider = Arc::new(ObservedProvider {
        tool_round: true,
        follow_up: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "coding-run-owned-follow-up");
    owner.pure_overlap_enabled = false;
    for name in ["alpha", "beta"] {
        std::fs::write(
            owner.workspace.join(format!("{name}.txt")),
            format!("actual native {name} bytes"),
        )
        .unwrap();
    }
    assert_eq!(
        owner.run("read the two real files").await.unwrap(),
        Outcome::Done
    );
    owner.stage_follow_up_transcript().await.unwrap();
    assert_eq!(
        owner
            .run("continue using the same settled observations")
            .await
            .unwrap(),
        Outcome::Done
    );
    assert_eq!(provider.sent.load(Ordering::SeqCst), 3);
    assert_eq!(owner.ledger.tool_calls, 2);
    let path = owner.rollout.path().to_owned();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::ToolDone { tool: Some(tool), .. } if tool == "read_file")).count(), 2);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind, EventKind::Done { .. }))
            .count(),
        2
    );
}

#[tokio::test]
async fn consecutive_no_tool_submissions_keep_the_live_writer_after_unreported_cache_usage() {
    use std::os::unix::fs::PermissionsExt;

    let provider = Arc::new(ObservedProvider {
        cache_creation_unreported: true,
        ..Default::default()
    });
    let mut owner = agent(provider.clone(), "consecutive-no-tool-submissions");
    std::fs::set_permissions(&owner.workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    owner.set_last_success_route_path(Some(owner.runtime_state_dir.join("last-route.json")));
    assert!(owner.advisory_maintenance_port().is_some());
    assert_eq!(owner.run("hi").await.unwrap(), Outcome::Done);
    assert!(!owner.record_failed);
    assert!(owner.transcript_state.working().is_some());
    assert_eq!(owner.follow_up("hi").await.unwrap(), Outcome::Done);
    assert!(!owner.record_failed);
    assert_eq!(provider.sent.load(Ordering::SeqCst), 2);
    assert_eq!(owner.ledger.tool_calls, 0);
    owner.finish_advisory_maintenance_for_test().await.unwrap();
    let path = owner.rollout.path().to_owned();
    let workspace = owner.workspace.clone();
    drop(owner);
    let events = iteron_record::replay(&path).unwrap();
    let turns = events
        .iter()
        .filter_map(|event| {
            matches!(&event.kind, EventKind::Done { outcome } if outcome == "Done")
                .then_some(event.turn)
        })
        .collect::<Vec<_>>();
    assert_eq!(turns.len(), 2);
    assert!(turns[1].0 > turns[0].0);
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider")).count(), 2);
    let journal = iteron_kernel::effects::EffectJournal::replay(&events).unwrap();
    assert!(journal.pending().is_empty());
    assert_eq!(journal.unknown_count(), 0);
    assert_eq!(events.iter().filter(|event| matches!(&event.kind, EventKind::Message { message } | EventKind::MessageV2 { message, .. }
        if message.role == iteron_protocol::Role::User && message.content.iter().any(|block| matches!(block, Block::Text { text } if text == "hi")))).count(), 2);
    std::fs::remove_dir_all(workspace).unwrap();
}
