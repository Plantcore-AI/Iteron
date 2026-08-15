use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use iteron_protocol::Phase;
use iteron_workflow::{AgentActivityReporter, AgentCall, AgentOutcome, AgentSpawner};

use super::worktree::WriterWorktree;
use super::{KernelSpawner, safe_agent_refusal};
use crate::runtime::{UiEvent, bounded_child_report, ui_workflow_label, usage_tokens};

fn workflow_child_activity(event: &UiEvent) -> Option<String> {
    match event {
        UiEvent::ToolStart { name, args, .. } => {
            let detail = ["path", "pattern", "query", "key"]
                .into_iter()
                .find_map(|key| args.get(key).and_then(|value| value.as_str()))
                .map(ui_workflow_label)
                .filter(|detail| !detail.is_empty());
            Some(match detail {
                Some(detail) => format!("{name} · {detail}"),
                None => name.clone(),
            })
        }
        UiEvent::Phase(Phase::Model) => Some("reasoning over evidence".into()),
        UiEvent::Phase(Phase::Tools) => Some("reading repository".into()),
        UiEvent::Phase(Phase::Verify) => Some("checking evidence".into()),
        UiEvent::TurnEnd { .. } => Some("organizing findings".into()),
        UiEvent::ToolEnd { .. }
        | UiEvent::Phase(Phase::Context | Phase::Idle)
        | UiEvent::Text(_)
        | UiEvent::Thinking(_)
        | UiEvent::Workflow(_)
        | UiEvent::SteerApplied { .. }
        | UiEvent::Notice(_)
        | UiEvent::ApprovalRequest { .. }
        | UiEvent::Done(_) => None,
    }
}

impl KernelSpawner {
    pub(super) async fn spawn_reporting(
        &self,
        call: AgentCall,
        activity: Option<AgentActivityReporter>,
    ) -> AgentOutcome {
        let _session_admission = match self.cx.session_spawn_ledger.admit() {
            Ok(admission) => admission,
            Err(error) => return AgentOutcome::null(error.to_string()),
        };
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::Relaxed);
        // Authority comes from the pinned catalog definition, never from one magic display name.
        // Keep this identical to the pre-speculation classification so every definition carrying
        // write authority receives a host-owned worktree and no read-only alias can obtain one.
        let writer_requested = matches!(
            <KernelSpawner as AgentSpawner>::execution_class(self, &call),
            iteron_workflow::AgentExecutionClass::IsolatedWriter
        );
        // Hold one session-wide lane for the complete writer transaction. A second writer cannot
        // observe or merge across the first one's partially settled state.
        let _writer_lane = if writer_requested {
            Some(self.cx.writer_merge_lock.lock().await)
        } else {
            None
        };
        let mut writer_worktree = if writer_requested {
            let child_id = self.mint_run_id(ordinal).0;
            match WriterWorktree::provision(
                self.cx.workspace.clone(),
                self.cx.runtime_state_dir.clone(),
                child_id,
            )
            .await
            {
                Ok(worktree) => Some(worktree),
                Err(error) => return AgentOutcome::null(error.public_summary()),
            }
        } else {
            None
        };
        let mut child = match self.build_child_in(
            &call,
            ordinal,
            writer_worktree.as_ref().map(WriterWorktree::path),
        ) {
            Ok(child) => child,
            Err(reason) => {
                return AgentOutcome::Null {
                    reason: Some(safe_agent_refusal(&reason)),
                };
            }
        };

        // `run_leaf` owns `&mut child` until completion, so its already-existing UI seam is the
        // live per-turn observation point. Drain it alongside the child future: TurnEnd carries
        // authoritative provider usage and ToolStart carries the tool count + bounded human label.
        let (ui_tx, mut ui_rx) = tokio::sync::mpsc::channel(8);
        child.set_ui(ui_tx);
        let mut live = LiveAgentActivity::default();

        // Cooperate with the run's cancellation token (trait §B3): bridge it onto the child's
        // cooperative interrupt flag, which `run_leaf` polls at every turn-atomic safe point. A
        // cancelled run then stops the child cleanly (durable safe point) rather than relying solely
        // on the engine's hard task-abort backstop.
        let interrupt = Arc::new(AtomicBool::new(false));
        child.set_interrupt(interrupt.clone());
        let cancel = call.cancel.clone();
        let cancel_bridge = tokio::spawn(async move {
            cancel.cancelled().await;
            interrupt.store(true, Ordering::SeqCst);
        });

        // `run_leaf` (not `run`): a leaf owns its context and tool loop but never orchestrates, so
        // its future is `Send + 'static` — exactly what lets the engine `tokio::spawn` this.
        let outcome = {
            let mut execution = Box::pin(child.run_leaf(&call.prompt));
            loop {
                tokio::select! {
                    outcome = &mut execution => break outcome,
                    event = ui_rx.recv() => {
                        if let Some(event) = event {
                            live.observe(event, activity.as_ref());
                        }
                    }
                }
            }
        };
        // If completion and the final TurnEnd were ready together, the select may observe completion
        // first. Drain the finite tail before reading the authoritative terminal ledger.
        while let Ok(event) = ui_rx.try_recv() {
            live.observe(event, activity.as_ref());
        }
        cancel_bridge.abort();
        let terminal = outcome
            .as_ref()
            .map(|outcome| (*outcome).clone())
            .map_err(|error| safe_agent_refusal(&error.public_summary()));
        let child_done = matches!(&outcome, Ok(iteron_protocol::Outcome::Done));
        let mut result = match outcome {
            // Any terminal with a non-empty final report becomes the JS string value (real model
            // output). This mirrors the kernel's own investigator distillation, which treats every
            // `Ok(_)` outcome as carrying a report and only degrades on an empty one.
            Ok(iteron_protocol::Outcome::Done) => {
                let text =
                    bounded_child_report(child.execution_policy, child.last_assistant_text());
                if text.is_empty() {
                    AgentOutcome::Null {
                        reason: Some("subagent completed without a report".into()),
                    }
                } else {
                    AgentOutcome::Text {
                        text,
                        tokens: usage_tokens(&child.ledger.usage),
                        tool_calls: child.ledger.tool_calls,
                        last_tool_summary: live.last_tool_summary,
                    }
                }
            }
            Ok(iteron_protocol::Outcome::Drained) => AgentOutcome::Null {
                reason: Some("subagent drained after a durable checkpoint".into()),
            },
            Ok(iteron_protocol::Outcome::Interrupted) => AgentOutcome::Null {
                reason: Some("subagent interrupted at a safe point".into()),
            },
            Ok(iteron_protocol::Outcome::BudgetExhausted(_)) => AgentOutcome::Null {
                reason: Some("subagent exhausted its bounded budget".into()),
            },
            Ok(iteron_protocol::Outcome::Stuck) => AgentOutcome::Null {
                reason: Some("subagent reached the tool-error limit".into()),
            },
            Ok(iteron_protocol::Outcome::HarnessError) => AgentOutcome::Null {
                reason: Some("subagent stopped on a harness error".into()),
            },
            // A harness/provider/budget error resolves to JS `null` (never a thrown rejection) so a
            // surrounding `parallel`/`pipeline` keeps its other items flowing.
            Err(error) => AgentOutcome::Null {
                reason: Some(safe_agent_refusal(&error.public_summary())),
            },
        };
        let terminal = match child.finalize_policy_run() {
            Ok(()) => terminal,
            Err(error) => {
                let summary = safe_agent_refusal(&error.public_summary());
                result = AgentOutcome::null(summary.clone());
                Err(summary)
            }
        };
        if let Some(worktree) = writer_worktree.as_mut() {
            self.settle_writer_worktree(worktree, child_done, &mut result)
                .await;
        }
        if let Some(collector) = &self.cx.child_outcomes {
            collector.lock().unwrap().push((ordinal, terminal));
        }
        if let Some(collector) = &self.cx.child_ledgers {
            collector
                .lock()
                .unwrap()
                .push((ordinal, std::mem::take(&mut child.ledger)));
        }
        result
    }

    async fn settle_writer_worktree(
        &self,
        worktree: &mut WriterWorktree,
        child_done: bool,
        result: &mut AgentOutcome,
    ) {
        if !child_done || !matches!(result, AgentOutcome::Text { .. }) {
            if let Err(error) = self.discard_writer_worktree(worktree).await {
                *result = AgentOutcome::null(error.public_summary());
            }
            return;
        }

        let preparing = self.cx.activity.span(
            crate::runtime::activity::ActivityStage::PreparingPatch,
            None,
        );
        let receipt = match worktree.prepare_patch().await {
            Ok(receipt) => receipt,
            Err(error) => {
                preparing.fail(iteron_protocol::ActivityDetailCode::Checkpoint);
                let _ = self.discard_writer_worktree(worktree).await;
                *result = AgentOutcome::null(error.public_summary());
                return;
            }
        };
        preparing.complete();
        if receipt.patch_bytes == 0 {
            match self.discard_writer_worktree(worktree).await {
                Ok(()) => {
                    if let AgentOutcome::Text {
                        last_tool_summary, ..
                    } = result
                    {
                        *last_tool_summary = Some("isolated writer produced no patch".into());
                    }
                }
                Err(error) => *result = AgentOutcome::null(error.public_summary()),
            }
            return;
        }

        let verification = self.cx.activity.span(
            crate::runtime::activity::ActivityStage::HostVerification,
            None,
        );
        if let Err(error) = worktree
            .verify(
                &receipt,
                self.cx.verify_command.as_deref(),
                &self.cx.sensitive_env_names,
                self.cx.verification_feedback.oracle_output_bytes,
            )
            .await
        {
            verification.fail(iteron_protocol::ActivityDetailCode::Verification);
            let _ = self.discard_writer_worktree(worktree).await;
            *result = AgentOutcome::null(error.public_summary());
            return;
        }
        verification.complete();
        let merging = self
            .cx
            .activity
            .span(crate::runtime::activity::ActivityStage::Merging, None);
        match worktree.merge(&receipt).await {
            Ok(()) => {
                merging.complete();
                if let AgentOutcome::Text {
                    last_tool_summary, ..
                } = result
                {
                    let digest = receipt
                        .patch_digest_sha256
                        .as_deref()
                        .unwrap_or("sha256:unknown");
                    *last_tool_summary = Some(format!(
                        "verified + merged isolated patch · {} bytes · {digest}",
                        receipt.patch_bytes
                    ));
                }
            }
            Err(error) => {
                merging.fail(iteron_protocol::ActivityDetailCode::RecordCommit);
                let _ = self.discard_writer_worktree(worktree).await;
                *result = AgentOutcome::null(error.public_summary());
            }
        }
    }

    async fn discard_writer_worktree(
        &self,
        worktree: &mut WriterWorktree,
    ) -> Result<(), super::worktree::MergeFailure> {
        let discarding = self
            .cx
            .activity
            .span(crate::runtime::activity::ActivityStage::Discarding, None);
        let result = worktree.discard().await;
        if result.is_ok() {
            discarding.complete();
        } else {
            discarding.fail(iteron_protocol::ActivityDetailCode::WorkflowResultPersist);
        }
        result
    }
}

#[derive(Default)]
struct LiveAgentActivity {
    tokens: u64,
    tool_calls: u64,
    last_tool_summary: Option<String>,
    current_activity: Option<String>,
    output_chars: usize,
    thinking_chars: usize,
}

impl LiveAgentActivity {
    fn observe(&mut self, event: UiEvent, reporter: Option<&AgentActivityReporter>) {
        let changed = match &event {
            UiEvent::TurnEnd { usage, .. } => {
                self.tokens = self.tokens.saturating_add(usage_tokens(usage));
                self.current_activity = workflow_child_activity(&event);
                true
            }
            UiEvent::ToolStart { .. } => {
                self.tool_calls = self.tool_calls.saturating_add(1);
                self.last_tool_summary = workflow_child_activity(&event);
                self.current_activity = self.last_tool_summary.clone();
                true
            }
            UiEvent::Text(delta) => {
                self.output_chars = self.output_chars.saturating_add(delta.chars().count());
                self.current_activity =
                    Some(format!("drafting report · {} chars", self.output_chars));
                true
            }
            UiEvent::Thinking(delta) => {
                self.thinking_chars = self.thinking_chars.saturating_add(delta.chars().count());
                self.current_activity = Some(format!(
                    "reasoning over evidence · {} chars",
                    self.thinking_chars
                ));
                true
            }
            UiEvent::Phase(Phase::Model | Phase::Tools | Phase::Verify) => {
                self.current_activity = workflow_child_activity(&event);
                true
            }
            _ => false,
        };
        if changed && let Some(reporter) = reporter {
            reporter.report(self.tokens, self.tool_calls, self.current_activity.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use iteron_agents::AgentCatalog;
    use iteron_protocol::{Block, StopReason, TenantId, ToolUse, Usage};
    use iteron_provider::{
        Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport,
    };
    use iteron_workflow::{
        AgentSpawner, ProgressEvent, ProgressSink, RunId, RunSpec, WorkflowEngine,
    };

    use super::*;
    use crate::runtime::workflow_spawner::KernelSpawnerContext;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ProgressEvent>>,
    }

    impl ProgressSink for RecordingSink {
        fn emit(&self, event: ProgressEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    struct ReportingSpawner {
        reports: u64,
        between_reports: Duration,
        settle_after_reports: Duration,
    }

    impl ReportingSpawner {
        fn outcome(&self) -> AgentOutcome {
            AgentOutcome::Text {
                text: "report".into(),
                tokens: self.reports.saturating_mul(100),
                tool_calls: self.reports,
                last_tool_summary: Some(format!("read file {}", self.reports)),
            }
        }
    }

    #[async_trait]
    impl AgentSpawner for ReportingSpawner {
        async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
            self.outcome()
        }

        async fn spawn_with_activity(
            &self,
            _call: AgentCall,
            activity: AgentActivityReporter,
        ) -> AgentOutcome {
            for step in 1..=self.reports {
                activity.report(
                    step.saturating_mul(100),
                    step,
                    Some(format!("read file {step}")),
                );
                tokio::time::sleep(self.between_reports).await;
            }
            tokio::time::sleep(self.settle_after_reports).await;
            self.outcome()
        }
    }

    #[derive(Default)]
    struct ThreeTurnActivityProvider {
        turn: AtomicU64,
    }

    #[async_trait]
    impl Provider for ThreeTurnActivityProvider {
        fn provider_instance_id(&self) -> Option<&str> {
            Some("test-provider")
        }

        async fn turn(
            &self,
            _request: &TurnRequest,
            on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            let turn = self.turn.fetch_add(1, Ordering::SeqCst);
            on_item(StreamItem::ThinkingDelta("checking evidence ".into()));
            if turn >= 2 {
                on_item(StreamItem::TextDelta("production report".into()));
            }
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            let usage = UsageReport::complete(Usage {
                input: 5,
                output: 5,
                ..Usage::default()
            });
            if turn < 2 {
                let tool = ToolUse {
                    id: format!("read-{turn}"),
                    name: "read_file".into(),
                    input: serde_json::json!({"path": "evidence.txt"}),
                };
                on_item(StreamItem::ToolUseComplete(tool.clone()));
                tokio::time::sleep(Duration::from_millis(1_100)).await;
                Ok(TurnResult {
                    blocks: vec![Block::ToolUse(tool)],
                    stop_reason: StopReason::ToolUse,
                    usage,
                })
            } else {
                Ok(TurnResult {
                    blocks: vec![Block::Text {
                        text: "production report".into(),
                    }],
                    stop_reason: StopReason::EndTurn,
                    usage,
                })
            }
        }
    }

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "iteron-workflow-activity-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn activity_catalog(root: &std::path::Path) -> AgentCatalog {
        let home = root.join("home");
        let repo = root.join("repo");
        std::fs::create_dir_all(home.join(".iteron/agents")).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            home.join(".iteron/agents/reviewer.md"),
            "---\nname: reviewer\ndescription: Activity reviewer\ntools: [read_file]\n\
             maxTurns: 4\nmaxTokens: 100\nmaxWallSecs: 30\nmaxConsecutiveToolErrors: 1\n---\n\
             Read evidence and report it.\n",
        )
        .unwrap();
        AgentCatalog::discover(&home, &repo)
    }

    fn context(root: &std::path::Path, catalog: AgentCatalog) -> KernelSpawnerContext {
        let mut context = KernelSpawnerContext::new(
            Arc::new(ThreeTurnActivityProvider::default()),
            "test-model".into(),
            "test-provider".into(),
            String::new(),
            String::new(),
            root.join("repo"),
            root.join("runs"),
            TenantId("tenant".into()),
            "parent".into(),
            "workflow".into(),
        );
        context.agent_catalog = Arc::new(catalog);
        context.budget.max_turns = 12;
        context.budget.max_tokens = Some(100);
        context.budget.max_wall_secs = 60;
        super::super::tests::pin_context(root, &mut context);
        context
    }

    async fn run_reporting_spawner(label: &str, spawner: ReportingSpawner) -> Vec<ProgressEvent> {
        let root = scratch(label);
        let sink = Arc::new(RecordingSink::default());
        let spec = RunSpec::new("return await agent('inspect');")
            .with_run_id(RunId::new(label))
            .with_workflows_dir(root.join("workflows"));
        let report = WorkflowEngine::execute(spec, Arc::new(spawner), sink.clone())
            .await
            .unwrap();
        assert_eq!(report.value, serde_json::Value::String("report".into()));
        let events = std::mem::take(&mut *sink.events.lock().unwrap());
        std::fs::remove_dir_all(root).unwrap();
        events
    }

    type ActivitySample<'a> = (u64, u64, Option<&'a str>);
    type ActivityByAgent<'a> = std::collections::BTreeMap<usize, Vec<ActivitySample<'a>>>;

    fn activity_by_agent(events: &[ProgressEvent]) -> ActivityByAgent<'_> {
        let mut by_agent = std::collections::BTreeMap::new();
        for event in events {
            if let ProgressEvent::AgentActivity {
                index,
                tokens,
                tool_calls,
                last_tool_summary,
            } = event
            {
                by_agent.entry(*index).or_insert_with(Vec::new).push((
                    *tokens,
                    *tool_calls,
                    last_tool_summary.as_deref(),
                ));
            }
        }
        by_agent
    }

    fn assert_monotone_activity(by_agent: &ActivityByAgent<'_>) {
        for (index, activity) in by_agent {
            assert!(
                activity
                    .windows(2)
                    .all(|pair| pair[0].0 <= pair[1].0 && pair[0].1 <= pair[1].1),
                "agent {index} activity regressed: {activity:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn workflow_agent_activity_repeats_at_one_hertz_with_monotone_metrics() {
        let events = run_reporting_spawner(
            "activity-long",
            ReportingSpawner {
                reports: 3,
                between_reports: Duration::from_millis(1_100),
                settle_after_reports: Duration::ZERO,
            },
        )
        .await;
        let activity = activity_by_agent(&events);

        assert!(
            activity.values().map(Vec::len).sum::<usize>() > 1,
            "{events:?}"
        );
        assert_monotone_activity(&activity);
        assert!(
            activity
                .values()
                .flatten()
                .all(|(_, _, summary)| summary.is_some())
        );
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::AgentFinished {
                tokens: 300,
                tool_calls: 3,
                last_tool_summary: Some(summary),
                ..
            }) if summary == "read file 3"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn workflow_agent_activity_streams_real_child_turns_and_tool_summaries() {
        let root = scratch("production");
        let catalog = activity_catalog(&root);
        std::fs::write(root.join("repo/evidence.txt"), "evidence").unwrap();
        let sink = Arc::new(RecordingSink::default());
        let spec = RunSpec::new("return await agent('inspect', { agentType: 'reviewer' });")
            .with_run_id(RunId::new("activity-production"))
            .with_workflows_dir(root.join("workflows"));

        let report = WorkflowEngine::execute(
            spec,
            Arc::new(KernelSpawner::new(context(&root, catalog))),
            sink.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            report.value,
            serde_json::Value::String("production report".into()),
            "{:?}",
            sink.events.lock().unwrap()
        );
        let events = sink.events.lock().unwrap();
        let activity = activity_by_agent(&events);
        assert!(
            activity.values().map(Vec::len).sum::<usize>() > 1,
            "{events:?}"
        );
        assert_monotone_activity(&activity);
        assert!(activity.values().flatten().any(|(_, _, summary)| {
            summary.is_some_and(|summary| summary.contains("reasoning over evidence"))
        }));
        assert!(activity.values().flatten().any(|(_, _, summary)| {
            summary.is_some_and(|summary| summary.contains("drafting report"))
        }));
        assert!(activity.values().flatten().any(|(_, _, summary)| {
            summary.is_some_and(|summary| summary.contains("read_file"))
        }));
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::AgentFinished {
                tokens: 30,
                tool_calls: 2,
                last_tool_summary: Some(summary),
                ..
            }) if summary.contains("read_file")
        ));
        drop(events);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn workflow_agent_activity_coalesces_a_fast_agent_instead_of_storming() {
        let events = run_reporting_spawner(
            "activity-fast",
            ReportingSpawner {
                reports: 100,
                between_reports: Duration::ZERO,
                settle_after_reports: Duration::from_millis(100),
            },
        )
        .await;
        let activity_count = events
            .iter()
            .filter(|event| matches!(event, ProgressEvent::AgentActivity { .. }))
            .count();
        assert!(activity_count <= 1, "{events:?}");
        assert!(matches!(
            events.last(),
            Some(ProgressEvent::AgentFinished {
                tokens: 10_000,
                tool_calls: 100,
                ..
            })
        ));
    }
}
