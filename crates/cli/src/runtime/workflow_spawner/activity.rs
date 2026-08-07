use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use core_protocol::Phase;
use core_workflow::{AgentActivityReporter, AgentCall, AgentOutcome};

use super::{KernelSpawner, safe_agent_refusal};
use crate::runtime::{UiEvent, usage_tokens, workflow_child_activity};

impl KernelSpawner {
    pub(super) async fn spawn_reporting(
        &self,
        call: AgentCall,
        activity: Option<AgentActivityReporter>,
    ) -> AgentOutcome {
        let ultracode_planner =
            call.agent_type.as_deref() == Some(core_agents::ULTRACODE_PLANNER_NAME);
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::Relaxed);
        let mut child = match self.build_child(&call, ordinal) {
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
        let (ui_tx, mut ui_rx) = tokio::sync::mpsc::unbounded_channel();
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
        if let Some(collector) = &self.cx.child_outcomes {
            let terminal = outcome
                .as_ref()
                .map(|outcome| (*outcome).clone())
                .map_err(|error| safe_agent_refusal(&error.public_summary()));
            collector.lock().unwrap().push((ordinal, terminal));
        }
        let result = match outcome {
            // Any terminal with a non-empty final report becomes the JS string value (real model
            // output). This mirrors the kernel's own investigator distillation, which treats every
            // `Ok(_)` outcome as carrying a report and only degrades on an empty one.
            Ok(core_protocol::Outcome::Done) => {
                let text = child.last_assistant_text().trim().to_string();
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
            Ok(core_protocol::Outcome::Drained) => AgentOutcome::Null {
                reason: Some("subagent drained after a durable checkpoint".into()),
            },
            Ok(core_protocol::Outcome::Interrupted) => AgentOutcome::Null {
                reason: Some("subagent interrupted at a safe point".into()),
            },
            Ok(core_protocol::Outcome::BudgetExhausted(_)) => AgentOutcome::Null {
                reason: Some("subagent exhausted its bounded budget".into()),
            },
            Ok(core_protocol::Outcome::Stuck) => AgentOutcome::Null {
                reason: Some("subagent reached the tool-error limit".into()),
            },
            Ok(core_protocol::Outcome::HarnessError) => AgentOutcome::Null {
                reason: Some("subagent stopped on a harness error".into()),
            },
            // A harness/provider/budget error resolves to JS `null` (never a thrown rejection) so a
            // surrounding `parallel`/`pipeline` keeps its other items flowing.
            Err(error) => AgentOutcome::Null {
                reason: Some(safe_agent_refusal(&error.public_summary())),
            },
        };
        if let Some(collector) = &self.cx.child_ledgers {
            collector
                .lock()
                .unwrap()
                .push((ordinal, std::mem::take(&mut child.ledger)));
        }
        if ultracode_planner {
            self.normalize_ultracode_plan(result)
        } else {
            result
        }
    }

    /// Convert the planner's untrusted line list into a harness-authored JSON task list. This is
    /// deliberately inside the spawner boundary: QuickJS never gets raw model control-flow data,
    /// and the pinned `core/planner` seat can narrow/reorder but cannot invent a leaf.
    fn normalize_ultracode_plan(&self, outcome: AgentOutcome) -> AgentOutcome {
        let Some(config) = self.cx.ultracode_planning else {
            return AgentOutcome::null(
                "the ultracode planner is available only to the built-in dynamic workflow",
            );
        };
        let AgentOutcome::Text {
            text,
            tokens,
            tool_calls,
            last_tool_summary,
        } = outcome
        else {
            return outcome;
        };
        let leaves = text.lines().map(str::to_owned).collect::<Vec<_>>();
        let planned = match core_agents::Decomposer::plan_within_with(
            self.cx.planner.as_ref(),
            config.class,
            leaves,
            config.max_leaves,
            core_protocol::capability_set::CapabilitySet::only(core_protocol::Capability::ReadOnly)
                .intersect(self.cx.authority_ceiling),
        ) {
            Ok(planned) => planned,
            Err(error) => {
                return AgentOutcome::null(format!("planner policy refused the plan: {error}"));
            }
        };
        let (tasks, dropped, duplicates_removed, invalid_removed) = match planned {
            Some(plan) => {
                let tasks = plan
                    .fan_tasks()
                    .iter()
                    .map(|task| {
                        serde_json::json!({
                            "objective": task.objective,
                            "scope": task.scope,
                            "deliverable": task.deliverable,
                            "agentType": task.agent_type,
                        })
                    })
                    .collect::<Vec<_>>();
                (
                    tasks,
                    plan.truncated.unwrap_or(0),
                    plan.duplicates_removed,
                    plan.invalid_removed,
                )
            }
            None => (Vec::new(), 0, 0, 0),
        };
        AgentOutcome::Text {
            text: serde_json::json!({
                "tasks": tasks,
                "dropped": dropped,
                "duplicatesRemoved": duplicates_removed,
                "invalidRemoved": invalid_removed,
            })
            .to_string(),
            tokens,
            tool_calls,
            last_tool_summary,
        }
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
    use core_agents::AgentCatalog;
    use core_protocol::{Block, StopReason, TenantId, ToolUse, Usage};
    use core_provider::{
        Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport,
    };
    use core_workflow::{
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
            "core-workflow-activity-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn activity_catalog(root: &std::path::Path) -> AgentCatalog {
        let home = root.join("home");
        let repo = root.join("repo");
        std::fs::create_dir_all(home.join(".core/agents")).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            home.join(".core/agents/reviewer.md"),
            "---\nname: reviewer\ndescription: Activity reviewer\ntools: [read_file]\n\
             maxTurns: 4\nmaxTokens: 100\nmaxWallSecs: 10\nmaxConsecutiveToolErrors: 1\n---\n\
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
        let activity: Vec<(u64, u64, Option<&str>)> = events
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::AgentActivity {
                    tokens,
                    tool_calls,
                    last_tool_summary,
                    ..
                } => Some((*tokens, *tool_calls, last_tool_summary.as_deref())),
                _ => None,
            })
            .collect();

        assert!(activity.len() > 1, "{events:?}");
        assert!(
            activity
                .windows(2)
                .all(|pair| pair[0].0 <= pair[1].0 && pair[0].1 <= pair[1].1)
        );
        assert!(activity.iter().all(|(_, _, summary)| summary.is_some()));
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
            serde_json::Value::String("production report".into())
        );
        let events = sink.events.lock().unwrap();
        let activity: Vec<(u64, u64, Option<&str>)> = events
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::AgentActivity {
                    tokens,
                    tool_calls,
                    last_tool_summary,
                    ..
                } => Some((*tokens, *tool_calls, last_tool_summary.as_deref())),
                _ => None,
            })
            .collect();
        assert!(activity.len() > 1, "{events:?}");
        assert!(
            activity
                .windows(2)
                .all(|pair| pair[0].0 <= pair[1].0 && pair[0].1 <= pair[1].1)
        );
        assert!(activity.iter().any(|(_, _, summary)| {
            summary.is_some_and(|summary| summary.contains("reasoning over evidence"))
        }));
        assert!(activity.iter().any(|(_, _, summary)| {
            summary.is_some_and(|summary| summary.contains("drafting report"))
        }));
        assert!(activity.iter().any(|(_, _, summary)| {
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
