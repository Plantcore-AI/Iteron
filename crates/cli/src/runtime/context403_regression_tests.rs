//! Synthetic same-session coverage in addition to the fresh-run materialization fixture.
//! The original incident's task/profile/frame records are unavailable; this is not its replay.

use crate::runtime::{Agent, gate_integration_tests, provider_selection::SelectedRoute};
use iteron_ctx::ContextBudgetPolicy;
use iteron_protocol::{
    Block, Budget, EventKind, Outcome, PricingRoute, Role, RunId, StopReason, TenantId, Trust,
    Usage, home,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use iteron_tunables::ResolutionValue;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const MODEL_WINDOW: usize = 1_208_192;
const SUBMISSIONS: usize = 6;

struct HistoryProvider {
    tasks: Vec<String>,
    answers: Vec<String>,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Provider for HistoryProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        Some("context403-fixture")
    }

    // This script reports one input/output token regardless of text length. Runtime context
    // estimation and component admission still inspect every full request before this boundary.
    fn physical_input_token_ceiling(&self, _: &str) -> Option<u64> {
        Some(1)
    }

    fn physical_output_token_ceiling(
        &self,
        _: iteron_provider::output_ceiling::ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        Ok(Some(1))
    }

    async fn turn(
        &self,
        request: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let submission = self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(submission < SUBMISSIONS, "unexpected extra provider round");
        let user_texts: Vec<&str> = request
            .messages
            .iter()
            .filter(|message| message.role == Role::User)
            .flat_map(|message| &message.content)
            .filter_map(|block| match block {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        for task in &self.tasks[..=submission] {
            assert!(
                user_texts.contains(&task.as_str()),
                "submission {} lost or truncated an original JSON task",
                submission + 1
            );
        }
        let assistant_texts: Vec<&str> = request
            .messages
            .iter()
            .filter(|message| message.role == Role::Assistant)
            .flat_map(|message| &message.content)
            .filter_map(|block| match block {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        for answer in &self.answers[..submission] {
            assert!(assistant_texts.contains(&answer.as_str()));
        }
        assert!(request.system.contains("synthetic project instruction"));
        assert!(request.system.contains("Inspect saved analysis reports"));
        if submission >= 2 {
            for analysis in ["analysis-0", "analysis-1"] {
                assert!(request.system.contains(analysis), "missing {analysis}");
            }
        }
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: self.answers[submission].clone(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage {
                input: 1,
                output: 1,
                ..Default::default()
            }),
        })
    }
}

fn integer_fields(fields: impl IntoIterator<Item = (&'static str, usize)>) -> ResolutionValue {
    ResolutionValue::Object {
        fields: fields
            .into_iter()
            .map(|(key, value)| {
                (
                    key.into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(value).unwrap(),
                    },
                )
            })
            .collect(),
    }
}

#[tokio::test]
async fn six_same_agent_submissions_preserve_large_cjk_tasks_and_analysis_history() {
    let workspace = gate_integration_tests::temp_ws("context403-same-agent");
    let skill = home::path(&workspace, "skills").join("inspect");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: inspect\ndescription: Inspect saved analysis reports\npaths: [src/**]\n---\nRead the selected source.\n",
    )
    .unwrap();
    let memory = home::path(&workspace, "memory");
    std::fs::create_dir_all(&memory).unwrap();
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/lib.rs"), "pub fn inspect() {}\n").unwrap();
    let instructions = "synthetic project instruction\n".repeat(256);
    std::fs::write(workspace.join("AGENTS.md"), &instructions).unwrap();
    let analyses: [String; 2] = [
        "Saved analysis 0: 分析".into(),
        "Saved analysis 1: 复查".into(),
    ];
    let tasks = (0..SUBMISSIONS)
        .map(|submission| {
            let mut task = serde_json::json!({
                "a_path": "src/lib.rs",
                "analyses": if submission >= 2 { &analyses[..] } else { &[] },
                "padding": "",
                "submission": submission + 1,
                "z_request": "inspect saved analysis reports and src/lib.rs",
            });
            let padding = 28_000 - task.to_string().chars().count();
            task["padding"] = serde_json::Value::String("界".repeat(padding));
            let task = task.to_string();
            assert_eq!(task.chars().count(), 28_000);
            assert!((80_000..84_000).contains(&task.len()));
            task
        })
        .collect::<Vec<_>>();
    let provider = Arc::new(HistoryProvider {
        tasks,
        answers: (0..SUBMISSIONS)
            .map(|submission| {
                analyses
                    .get(submission)
                    .cloned()
                    .unwrap_or_else(|| format!("report for submission {}", submission + 1))
            })
            .collect(),
        calls: AtomicUsize::new(0),
    });
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("context403-same-agent".into()),
        TenantId("context403-fixture".into()),
    )
    .unwrap();
    let mut agent = Agent::new(
        provider.clone(),
        iteron_tools::Registry::read_only(&workspace).unwrap(),
        rollout,
        "context403-model".into(),
        "Synthetic context continuity test.".into(),
        Budget {
            max_turns: 12,
            max_wall_secs: 60,
            ..Budget::default()
        },
    );
    agent.workspace = workspace.clone();
    agent.memory_workspace = Some(workspace.clone());
    agent.instruction_context = Some((instructions, Trust::Untrusted));
    let mut policy = ContextBudgetPolicy::for_usable_window(MODEL_WINDOW, 8_192, 0);
    // Six CJK inputs use about two tokens per scalar. Rebalance the explicit synthetic
    // history profile without enlarging the model window or the 120k active-task partition.
    policy.transcript_tokens += 100_000;
    policy.tool_result_tokens -= 100_000;
    assert_eq!(policy.task_context_tokens, 120_000);
    policy.validate_for_window(MODEL_WINDOW).unwrap();
    agent.context_budget_policy = policy;
    agent.provider_selection.fixture_selection(
        Some(SelectedRoute {
            route: PricingRoute {
                provider_id: "context403-fixture".into(),
                model_id: "context403-model".into(),
                catalog_digest: String::new(),
                capability_digest: String::new(),
            },
        }),
        provider.clone(),
    );
    // Pin the model window and partitions together, rather than changing only in-memory caps.
    // This is a synthetic resolved checkpoint, not an attestation of the missing incident profile.
    let memory_budget = iteron_ctx::MemBudget::default();
    gate_integration_tests::record_test_genesis_with_tunable_edits(
        &mut agent,
        &workspace,
        [
            (
                "context_window_override_reserve",
                integer_fields([
                    ("model_window_tokens", MODEL_WINDOW),
                    ("output_reserve_tokens", 8_192),
                    ("verification_reserve_tokens", 0),
                    ("instruction_budget_tokens", policy.instruction_tokens),
                    ("task_context_budget_tokens", policy.task_context_tokens),
                    ("memory_budget_tokens", policy.memory_tokens),
                    ("attachment_budget_tokens", policy.attachment_tokens),
                    ("tool_schema_budget_tokens", policy.tool_schema_tokens),
                ]),
            ),
            (
                "memory_budgets",
                integer_fields([
                    ("index_bytes", memory_budget.index_bytes),
                    ("recall_bytes", memory_budget.recall_bytes),
                    ("instruction_bytes", memory_budget.instr_bytes),
                    // Required registry field; matches the production memory fact ceiling.
                    ("fact_bytes", 8_000),
                    ("total_bytes", memory_budget.total),
                ]),
            ),
            (
                "skill_listing_budget",
                ResolutionValue::Integer { value: 6_000 },
            ),
            // The structural schema sampler's zero pressure ratios force a summary after two
            // turns. Keep real ordinary compaction enabled with its production hysteresis.
            (
                "compaction_cooldown_hysteresis",
                ResolutionValue::Object {
                    fields: [
                        (
                            "cooldown_turns".into(),
                            ResolutionValue::Integer { value: 1 },
                        ),
                        (
                            "enter_ratio".into(),
                            ResolutionValue::Decimal {
                                value: iteron_tunables::DecimalValue {
                                    coefficient: 75,
                                    scale: 2,
                                },
                            },
                        ),
                        (
                            "exit_ratio".into(),
                            ResolutionValue::Decimal {
                                value: iteron_tunables::DecimalValue {
                                    coefficient: 5,
                                    scale: 1,
                                },
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
            ),
        ],
    );
    let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
        agent.tunables_checkpoint().unwrap(),
        None,
    )
    .unwrap()
    .core;
    assert_eq!(effective.model_context_window, Some(MODEL_WINDOW as u64));
    assert_eq!(effective.context_budget.task_context_tokens, 120_000);
    assert_eq!(effective.context_budget.transcript_tokens, 400_000);
    assert_eq!(effective.context_budget.tool_result_tokens, 80_000);
    assert!(effective.compaction.enabled);
    assert_eq!(
        effective.compaction.hysteresis,
        iteron_ctx::CompactionPolicy::default().hysteresis
    );
    agent.context_budget_policy = effective.context_budget;
    agent.context_materialization_policy = effective.context_materialization;
    agent.compaction = effective.compaction;
    agent
        .record_model_selection(
            "context403-fixture".into(),
            "context403-model".into(),
            String::new(),
            String::new(),
        )
        .unwrap();
    gate_integration_tests::install_test_provider_governor_from_tunables(&mut agent);
    agent.guard_unresolved_effects().unwrap();
    let journal_path = agent.rollout.path().to_path_buf();
    for submission in 0..SUBMISSIONS {
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            if submission == 0 {
                agent.run(&provider.tasks[submission]).await
            } else {
                agent.follow_up(&provider.tasks[submission]).await
            }
        })
        .await
        .expect("same-session context submission must terminate")
        .unwrap_or_else(|error| panic!("submission {} failed: {error}", submission + 1));
        assert!(matches!(outcome, Outcome::Done), "{outcome:?}");
        assert_eq!(provider.calls.load(Ordering::SeqCst), submission + 1);
        assert_eq!(agent.rollout.path(), journal_path);
        if submission < analyses.len() {
            std::fs::write(
                memory.join(format!("analysis-{submission}.md")),
                format!(
                    "# {}\ninspect saved analysis reports\n",
                    analyses[submission]
                ),
            )
            .unwrap();
        }
    }
    let events = iteron_record::replay(&journal_path).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider"))
            .count(),
        SUBMISSIONS
    );
    for task in &provider.tasks {
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            EventKind::Message { message } if message.role == Role::User
                && message.content.iter().any(|block| matches!(block, Block::Text { text } if text == task))
        )));
    }
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        EventKind::ContextInjection { text, .. }
            if text.contains("analysis-0") && text.contains("analysis-1")
    )));
    // All submissions have stopped; keep the owner alive until its native maintenance IO ends.
    agent
        .finish_advisory_maintenance_for_test()
        .await
        .expect("context continuity fixture maintenance IO settles before workspace removal");
    drop(agent);
    std::fs::remove_dir_all(workspace).unwrap();
}
