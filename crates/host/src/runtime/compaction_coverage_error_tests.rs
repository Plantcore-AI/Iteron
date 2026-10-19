struct CoverageFailureProvider {
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl Provider for CoverageFailureProvider {
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
        panic!("coverage fixture must cross native prepared proof")
    }
    async fn turn_observed(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        observer: &dyn iteron_provider::request_capture::ProviderRequestObserver,
    ) -> Result<TurnResult, ProviderError> {
        let body = serde_json::to_vec(&serde_json::json!({"model":request.model,"messages":request.messages,"system":request.system,"max_tokens":request.max_tokens})).unwrap();
        observer
            .prepared(iteron_provider::request_capture::ProviderWireRequest {
                adapter: iteron_provider::AdapterKind::OpenAiCompatibleChat,
                method: "POST",
                endpoint: "https://coverage-fixture.invalid/v1",
                content_type: "application/json",
                body: &body,
                serialized_output_tokens: request.max_tokens,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if request.system.contains("transcript-compaction auditor") {
            return Err(ProviderError::Refusal);
        }
        let text = "Preserve exact operator task and all unresolved requirements.";
        on_item(StreamItem::TextDelta(text.into()));
        Ok(TurnResult {
            blocks: vec![Block::Text { text: text.into() }],
            stop_reason: iteron_protocol::StopReason::EndTurn,
            usage: iteron_provider::UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
}

#[tokio::test]
async fn actual_coverage_failure_cannot_install_or_record_a_verified_summary() {
    let (directory, mut agent, messages) = fixture();
    let provider = Arc::new(CoverageFailureProvider {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    agent.provider = provider.clone();
    agent.compaction.coverage_check = true;
    agent
        .transcript_state
        .replace_restored(Some(messages.clone()));
    assert!(agent.run("").await.is_err());
    assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(
        serde_json::to_value(agent.transcript_state.working().as_ref().unwrap()).unwrap(),
        serde_json::to_value(&messages).unwrap()
    );
    assert!(!agent.compaction_state.compacted());
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let rows = iteron_record::replay(&path).unwrap();
    assert!(
        !rows
            .iter()
            .any(|event| matches!(event.kind, EventKind::Compaction { .. }))
    );
    assert!(
        rows.iter().any(
            |event| matches!(&event.kind, EventKind::EffectFailed {tool,..} if tool=="provider")
        )
    );
    std::fs::remove_dir_all(directory).unwrap();
}
