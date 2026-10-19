use super::*;
use crate::runtime::DurableAppendFault;
use crate::runtime::session_transcript::TranscriptAdmissionJournal;
use crate::runtime::turn_publication::TurnPublicationOwner;
use iteron_ctx::{ContextStrategy, MemoryRecallStrategy, PortStub};
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_protocol::{Effort, Event, RunId, Seq, TenantId};
use iteron_record::Rollout;

struct Writer {
    root: PathBuf,
    rollout: Rollout,
    ledger: Ledger,
    failed: bool,
    publications: TurnPublicationOwner,
    diagnostics: DiagnosticEmitter,
    fault: Option<DurableAppendFault>,
}
impl Writer {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "iteron-context-materialization-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut rollout =
            Rollout::open(&root, &RunId("context".into()), TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::RunStart {
                    cwd: root.to_string_lossy().into(),
                    model: "fixture".into(),
                    effort: Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    agent_definition_tag: None,
                    max_usd: None,
                },
            })
            .unwrap();
        let publications = TurnPublicationOwner::for_rollout(&rollout);
        Self {
            root,
            rollout,
            publications,
            ledger: Ledger::default(),
            failed: false,
            diagnostics: DiagnosticEmitter::default(),
            fault: None,
        }
    }
    fn journal(&mut self) -> ContextInjectionJournal<'_> {
        ContextInjectionJournal {
            transcript: TranscriptAdmissionJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.failed,
                diagnostics: &self.diagnostics,
                publications: &mut self.publications,
                fault: &mut self.fault,
            },
            policy: None,
        }
    }
    fn close(self) -> (PathBuf, PathBuf) {
        let path = self.rollout.path().to_path_buf();
        let root = self.root.clone();
        drop(self);
        (root, path)
    }
}

fn world<'a>(
    context: &'a ContextStrategy,
    memory: &'a MemoryRecallStrategy,
    port: &'a PortStub,
) -> ContextInjectionWorld<'a> {
    ContextInjectionWorld {
        memory_workspace: None,
        home: None,
        dependency_skill_dirs: &[],
        context,
        memory,
        port,
        benchmark_scope: None,
        materialization: ContextMaterializationPolicy::default(),
    }
}

#[test]
fn actual_legacy_upgrade_reopens_with_its_admitted_prefix_and_ignores_changed_proposals() {
    let mut writer = Writer::new();
    writer
        .journal()
        .injection(
            TurnId(0),
            "historical memory\n".into(),
            Trust::Workspace,
            None,
        )
        .unwrap();
    let recorded = RecordedContextHistory::read(writer.rollout.path()).unwrap();
    let instructions = ("original instructions\n".into(), Trust::Untrusted);
    let environment = ("original environment\n".into(), Trust::Workspace);
    let preparation = ContextInjectionPreparation::new(
        recorded,
        Some(&instructions),
        Some(&environment),
        false,
        Instant::now(),
    );
    assert!(!preparation.needs_live_policy(true));
    let context = ContextStrategy::default();
    let memory = MemoryRecallStrategy::default();
    let port = PortStub::new(Vec::new());
    let materialized = preparation
        .materialize(
            TurnId(1),
            "resume",
            world(&context, &memory, &port),
            &mut writer.journal(),
        )
        .unwrap();
    assert!(matches!(
        materialized.observation(TurnId(1), "resume"),
        ContextInjectionObservation::Recorded {
            trust: Trust::Untrusted,
            ..
        }
    ));
    let committed = materialized
        .commit(
            TurnId(1),
            &mut writer.journal(),
            &mut RequestContextEvidenceOwner::default(),
        )
        .unwrap();
    assert!(committed.text.contains("original instructions"));
    assert!(committed.text.contains("original environment"));
    assert!(committed.text.contains("historical memory"));
    assert_eq!(committed.trust, Some(Trust::Untrusted));
    let (root, path) = writer.close();
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::ContextInjection { .. }))
            .count(),
        2
    );
    let changed = ("changed live proposal\n".into(), Trust::Trusted);
    let preparation = ContextInjectionPreparation::new(
        RecordedContextHistory::read(&path).unwrap(),
        Some(&changed),
        Some(&changed),
        false,
        Instant::now(),
    );
    let mut reopened = Rollout::open(&root, &RunId("context".into()), TenantId::default()).unwrap();
    let mut publications = TurnPublicationOwner::for_rollout(&reopened);
    let mut ledger = Ledger::default();
    let mut failed = false;
    let mut fault = None;
    let diagnostics = DiagnosticEmitter::default();
    let mut journal = ContextInjectionJournal {
        transcript: TranscriptAdmissionJournal {
            rollout: &mut reopened,
            ledger: &mut ledger,
            record_failed: &mut failed,
            diagnostics: &diagnostics,
            publications: &mut publications,
            fault: &mut fault,
        },
        policy: None,
    };
    let replayed = preparation
        .materialize(
            TurnId(2),
            "different task",
            world(&context, &memory, &port),
            &mut journal,
        )
        .unwrap()
        .commit(
            TurnId(2),
            &mut journal,
            &mut RequestContextEvidenceOwner::default(),
        )
        .unwrap();
    assert_eq!(replayed.text, committed.text);
    assert_eq!(replayed.trust, committed.trust);
    drop(reopened);
    assert_eq!(iteron_record::replay(&path).unwrap().len(), events.len());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn real_poisoned_writer_cannot_release_an_installable_live_prefix() {
    let mut writer = Writer::new();
    // Refuse the actual owning journal, then carry that same poisoned writer into the new context
    // barrier. Reopening must contain neither the refused observation nor a ContextInjection.
    writer.fault = Some(DurableAppendFault::Notice);
    assert!(
        writer
            .journal()
            .transcript
            .notice(TurnId(0), "refused observation".into())
            .is_err()
    );
    assert!(writer.failed);
    let instruction = ("not yet admitted prefix\n".into(), Trust::Workspace);
    let preparation = ContextInjectionPreparation::new(
        RecordedContextHistory::read(writer.rollout.path()).unwrap(),
        Some(&instruction),
        None,
        false,
        Instant::now(),
    );
    let context = ContextStrategy::default();
    let memory = MemoryRecallStrategy::default();
    let port = PortStub::new(Vec::new());
    let pending = preparation
        .materialize(
            TurnId(0),
            "task",
            world(&context, &memory, &port),
            &mut writer.journal(),
        )
        .unwrap();
    assert!(
        pending
            .commit(
                TurnId(0),
                &mut writer.journal(),
                &mut RequestContextEvidenceOwner::default()
            )
            .is_err()
    );
    assert!(writer.failed);
    let (root, path) = writer.close();
    let events = iteron_record::replay(&path).unwrap();
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::ContextInjection { .. } | EventKind::Notice { .. }
    )));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn six_fresh_context_materializations_admit_large_json_and_preserve_source_budgets() {
    use crate::runtime::request_accounting::RequestAccounting;
    use iteron_ctx::{ContextBudgetPolicy, ContextSourceClass, RequestEstimator};
    use iteron_protocol::{Message, context::ContextSource, home};

    let policy = ContextBudgetPolicy::for_usable_window(1_208_192, 8_192, 0);
    assert_eq!(policy.task_context_tokens, 120_000);
    policy.validate_for_window(1_208_192).unwrap();

    for submission in 1..=6 {
        // Each submission gets a new durable run and workspace; this exercises materialization
        // without inheriting an in-process transcript or a previous run's cached injection.
        let mut writer = Writer::new();
        let workspace = writer.root.clone();
        let skill = home::path(&workspace, "skills").join("inspect");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: inspect\ndescription: Inspect saved analysis reports\npaths: [src/**]\n---\nRead the selected source.\n",
        )
        .unwrap();
        let memory = home::path(&workspace, "memory");
        std::fs::create_dir_all(&memory).unwrap();
        let analyses: Vec<String> = if submission >= 3 {
            vec!["分析".repeat(2_000), "复查".repeat(2_000)]
        } else {
            Vec::new()
        };
        for (ordinal, body) in analyses.iter().enumerate() {
            std::fs::write(
                memory.join(format!("analysis-{ordinal}.md")),
                format!("# Saved analysis {ordinal}\n{body}\n"),
            )
            .unwrap();
        }
        let mut task = serde_json::json!({
            "a_path": "src/lib.rs",
            "analyses": analyses,
            "padding": "",
            "submission": submission,
            "z_request": "inspect saved analysis reports and src/lib.rs",
        });
        let target_chars = 26_000 + submission * 250;
        let padding = target_chars - task.to_string().chars().count();
        task["padding"] = serde_json::Value::String("界".repeat(padding));
        let task = task.to_string();
        assert_eq!(task.chars().count(), target_chars);
        assert!(task.len() > 64 * 1024);

        let instructions = (
            "synthetic project instruction\n".repeat(256),
            Trust::Untrusted,
        );
        std::fs::write(workspace.join("AGENTS.md"), &instructions.0).unwrap();
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/lib.rs"), "pub fn inspect() {}\n").unwrap();
        let environment = ("workspace fixture\n".into(), Trust::Workspace);
        let preparation = ContextInjectionPreparation::new(
            RecordedContextHistory::read(writer.rollout.path()).unwrap(),
            Some(&instructions),
            Some(&environment),
            false,
            Instant::now(),
        );
        let materialized = preparation
            .materialize(
                TurnId(0),
                &task,
                ContextInjectionWorld {
                    memory_workspace: Some(&workspace),
                    home: None,
                    dependency_skill_dirs: &[],
                    context: &ContextStrategy::default(),
                    memory: &MemoryRecallStrategy::default(),
                    port: &iteron_ctx::DefaultContextPort,
                    benchmark_scope: None,
                    materialization: ContextMaterializationPolicy::default(),
                },
                &mut writer.journal(),
            )
            .unwrap();
        let live = materialized.live.as_ref().unwrap();
        assert!(live.policy_observation.task.len() <= 64 * 1024);
        // Materialization transfers the rendered text into the pending injection body;
        // the retained live observation keeps segments/audit, with its text moved out.
        assert!(materialized.body.len() <= live.policy_plan.request.max_bytes as usize);
        assert!(
            live.segments
                .iter()
                .any(|s| s.source == ContextSource::Skills)
        );
        assert!(
            !live
                .segments
                .iter()
                .any(|s| s.source == ContextSource::Instructions)
        );
        if submission >= 3 {
            assert_eq!(
                live.segments.iter().map(|s| s.source).collect::<Vec<_>>(),
                [ContextSource::Memory, ContextSource::Skills],
            );
            assert!(
                materialized.body.find("analysis-0").unwrap()
                    < materialized.body.find("analysis-1").unwrap()
            );
        }
        if submission == 6 {
            let repeated = strategy_runtime::resolve_live_context(
                &ContextStrategy::default(),
                &MemoryRecallStrategy::default(),
                &iteron_ctx::DefaultContextPort,
                LiveContextRequest {
                    workspace: &workspace,
                    home_dir: None,
                    dependency_skill_dirs: &[],
                    turn: TurnId(0),
                    task: &task,
                    memory_benchmark_scope: None,
                    materialization: ContextMaterializationPolicy::default(),
                },
            )
            .unwrap();
            assert_eq!(live.segments, repeated.segments);
            assert_eq!(materialized.body, repeated.text);
        }
        let mut sources = RequestContextEvidenceOwner::default();
        sources.replace_materialized(&live.materialization_audit, 0);
        let selected_task_tokens = sources
            .segments()
            .iter()
            .filter(|s| s.source_class == ContextSourceClass::SkillIndex)
            .map(|s| s.estimated_tokens as usize)
            .sum::<usize>();
        let committed = materialized
            .commit(TurnId(0), &mut writer.journal(), &mut sources)
            .unwrap();
        assert!(
            committed
                .text
                .starts_with(&format!("{}{}", environment.0, instructions.0))
        );
        assert_eq!(
            committed
                .text
                .matches("synthetic project instruction")
                .count(),
            256
        );
        assert_eq!(committed.trust, Some(Trust::Untrusted));

        let estimator = RequestEstimator::new();
        let messages = [Message::user_text(&task)];
        let estimate = estimator.estimate_uncached(&committed.text, &messages, &[]);
        let accounting = RequestAccounting::new(
            sources.segments(),
            policy,
            Default::default(),
            ("fixture", "fixture"),
            None,
            None,
        );
        let usage = accounting.components(&estimator, &messages, &estimate);
        assert_eq!(
            usage.task_context_tokens,
            estimator.estimate_text(&task) + selected_task_tokens
        );
        assert_eq!(
            usage.transcript_tokens, 0,
            "embedded saved analyses remain part of the active JSON task"
        );
        policy.admit_components(&usage).unwrap();
        let mut tightened = policy;
        tightened.task_context_tokens = usage.task_context_tokens - 1;
        assert_eq!(
            tightened.admit_components(&usage).unwrap_err().class,
            iteron_ctx::ContextBudgetClass::TaskContext
        );
        let (root, path) = writer.close();
        assert_eq!(
            iteron_record::replay(&path)
                .unwrap()
                .iter()
                .filter(|event| matches!(event.kind, EventKind::ContextInjection { .. }))
                .count(),
            1
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
