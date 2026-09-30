use super::*;
use iteron_protocol::{Block, StopReason, Usage};
use iteron_provider::{ProviderError, TurnResult, UsageReport};
use iteron_workflow::{RunId, RunReport};
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct RecordingProvider {
    turns: AtomicUsize,
    failure: Option<String>,
}

impl RecordingProvider {
    fn successful() -> Self {
        Self {
            turns: AtomicUsize::new(0),
            failure: None,
        }
    }

    fn failing(message: String) -> Self {
        Self {
            turns: AtomicUsize::new(0),
            failure: Some(message),
        }
    }
}

#[async_trait::async_trait]
impl Provider for RecordingProvider {
    async fn turn(
        &self,
        _request: &TurnRequest,
        _on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.turns.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = &self.failure {
            return Err(ProviderError::Http(message.clone()));
        }
        Ok(TurnResult {
            blocks: vec![Block::Text {
                text: "provider result".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Usage::default()),
        })
    }
}

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<ProgressEvent>>,
}

impl ProgressSink for RecordingSink {
    fn emit(&self, event: ProgressEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "iteron-cli-workflow-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn assert_safe_refusal_surfaces(
    workflows_dir: &Path,
    run_id: &str,
    sink: &RecordingSink,
    expected: usize,
    secret: &str,
) {
    let events = sink.events.lock().unwrap();
    let rendered = format!("{events:?}");
    assert!(!rendered.contains(secret), "{rendered}");
    let errors: Vec<&String> = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::AgentFinished {
                state: WorkflowState::Error,
                error: Some(error),
                ..
            } => Some(error),
            _ => None,
        })
        .collect();
    assert_eq!(errors.len(), expected);
    assert!(errors.iter().all(|error| {
        error.len() <= 512 && !error.chars().any(char::is_control) && !error.contains(secret)
    }));
    drop(events);

    let journal =
        std::fs::read_to_string(run_dir(workflows_dir, run_id).join("journal.jsonl")).unwrap();
    assert!(!journal.contains(secret), "{journal}");
    let reasons: Vec<String> = journal
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|line| {
            line.get("record")?
                .get("outcome")?
                .get("reason")?
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(reasons.len(), expected);
    assert!(reasons.iter().all(|reason| {
        reason.len() <= 512 && !reason.chars().any(char::is_control) && !reason.contains(secret)
    }));
}

#[tokio::test]
async fn provider_fallback_refuses_unknown_agent_and_unresolved_models_before_any_turn() {
    let workflows_dir = scratch_dir("provider-fallback-refusals");
    let provider = Arc::new(RecordingProvider::successful());
    let spawner = Arc::new(ProviderSpawner::new(
        provider.clone(),
        "parent-model".into(),
    ));
    let sink = Arc::new(RecordingSink::default());
    let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
    let script = r#"export const meta = { name: 'fallback-refusals', description: '', phases: [] };
return await parallel([
  () => agent('unknown type', {agentType: 'reviewer'}),
  () => agent('secret type', {agentType: args.secret}),
  () => agent('alternate model', {model: 'alternate-model'}),
  () => agent('secret model', {model: args.secret}),
]);
"#;
    let spec = RunSpec::new(script)
        .with_args(serde_json::json!({"secret": secret}))
        .with_run_id(RunId::new("fallback-refusals"))
        .with_workflows_dir(workflows_dir.clone());
    let report = WorkflowEngine::execute(spec, spawner, sink.clone())
        .await
        .expect("authorization refusals settle as null");
    assert_eq!(
        report.value,
        serde_json::Value::Array(vec![serde_json::Value::Null; 4])
    );
    assert_eq!(provider.turns.load(Ordering::SeqCst), 0);
    assert_safe_refusal_surfaces(&workflows_dir, "fallback-refusals", &sink, 4, secret);
    let _ = std::fs::remove_dir_all(workflows_dir);
}

#[tokio::test]
async fn provider_fallback_never_reflects_raw_provider_error_into_null_journal_or_progress() {
    let workflows_dir = scratch_dir("provider-fallback-error");
    let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
    let provider = Arc::new(RecordingProvider::failing(format!(
        "request to https://gateway.invalid/{secret} failed\n\u{1b}[2J{}",
        "x".repeat(4_096)
    )));
    let spawner = Arc::new(ProviderSpawner::new(
        provider.clone(),
        "parent-model".into(),
    ));
    let sink = Arc::new(RecordingSink::default());
    let script = r#"export const meta = { name: 'fallback-error', description: '', phases: [] };
return await agent('inspect', {agentType: 'generic', model: 'parent-model'});
"#;
    let spec = RunSpec::new(script)
        .with_run_id(RunId::new("fallback-error"))
        .with_workflows_dir(workflows_dir.clone());
    let report = WorkflowEngine::execute(spec, spawner, sink.clone())
        .await
        .expect("provider failure settles as null");
    assert_eq!(report.value, serde_json::Value::Null);
    assert_eq!(
        provider.turns.load(Ordering::SeqCst),
        2,
        "the workflow's bounded retry policy gives the failed logical agent one retry"
    );
    assert_safe_refusal_surfaces(&workflows_dir, "fallback-error", &sink, 1, secret);
    let _ = std::fs::remove_dir_all(workflows_dir);
}

#[test]
fn a_run_that_only_wrote_a_journal_lists_as_an_unnamed_running_stub() {
    // The in-turn (`Workflow` tool) path used to do exactly this: write its journal into the
    // directory `iteron workflow list` enumerates and never call either persistence helper. This
    // pins what that looked like, so the assertion below is a real difference.
    let workflows_dir = scratch_dir("orphan");
    let run = run_dir(&workflows_dir, "wf_orphan");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("journal.jsonl"), b"").unwrap();

    let listed = list_runs(&workflows_dir);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "workflow");
    assert_eq!(listed[0].model, "");
    assert_eq!(listed[0].status, "running");

    let _ = std::fs::remove_dir_all(&workflows_dir);
}

#[test]
fn a_persisted_run_lists_with_its_name_model_and_terminal_state() {
    let workflows_dir = scratch_dir("persisted");
    let manifest = RunManifest {
        run_id: "wf_persisted".into(),
        name: "triage".into(),
        args: serde_json::json!({ "topic": "flaky test" }),
        provider_id: "anthropic".into(),
        model: "core-model-1".into(),
        created_at: 42,
    };
    persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
    std::fs::write(
        run_dir(&workflows_dir, "wf_persisted").join("journal.jsonl"),
        b"",
    )
    .unwrap();
    persist_result(
        &workflows_dir,
        "wf_persisted",
        &RunReport {
            run_id: RunId::new("wf_persisted"),
            value: serde_json::json!(["a", "b"]),
            stopped: false,
            cache_hits: 0,
            cache_misses: 2,
            errors: 0,
            tokens: 1_234,
            tool_calls: 7,
            elapsed_ms: 4_200,
        },
    )
    .unwrap();

    let listed = list_runs(&workflows_dir);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "triage");
    assert_eq!(listed[0].model, "core-model-1");
    assert_eq!(
        listed[0].status, "done",
        "a completed run must reach a terminal state, not stay `running` forever"
    );
    assert_eq!(
        load_script(&workflows_dir, "wf_persisted").as_deref(),
        Some("export const meta = {};"),
        "the inputs sidecar makes the run re-launchable"
    );

    let _ = std::fs::remove_dir_all(&workflows_dir);
}

#[test]
fn a_persisted_agent_failure_lists_as_failed() {
    let workflows_dir = scratch_dir("persisted-agent-failure");
    let manifest = RunManifest {
        run_id: "wf_agent_failed".into(),
        name: "triage".into(),
        args: serde_json::Value::Null,
        provider_id: "anthropic".into(),
        model: "core-model-1".into(),
        created_at: 43,
    };
    persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
    persist_result(
        &workflows_dir,
        "wf_agent_failed",
        &RunReport {
            run_id: RunId::new("wf_agent_failed"),
            value: serde_json::json!(["ok", null]),
            stopped: false,
            cache_hits: 0,
            cache_misses: 2,
            errors: 1,
            tokens: 7,
            tool_calls: 0,
            elapsed_ms: 10,
        },
    )
    .unwrap();

    assert_eq!(list_runs(&workflows_dir)[0].status, "failed");
    assert_eq!(
        load_result(&workflows_dir, "wf_agent_failed")
            .unwrap()
            .errors,
        1
    );
    let _ = std::fs::remove_dir_all(&workflows_dir);
}

#[test]
fn workflow_failure_exit_and_status_contract_distinguishes_clean_failed_and_cancelled() {
    let report = |errors, stopped| RunReport {
        run_id: RunId::new("wf_contract"),
        value: serde_json::Value::Null,
        stopped,
        cache_hits: 0,
        cache_misses: 3,
        errors,
        tokens: 21,
        tool_calls: 0,
        elapsed_ms: 10,
    };

    let clean = report(0, false);
    assert_eq!(run_status(&clean), "done");
    assert_eq!(run_exit_code(&clean), crate::output::EXIT_SUCCESS);
    assert!(final_status_line("wf_contract", &clean).contains("done \u{b7} 0 failed"));

    for errors in [1, 3] {
        let failed = report(errors, false);
        assert_eq!(run_status(&failed), "failed");
        assert_eq!(run_exit_code(&failed), crate::output::EXIT_WORKFLOW_FAILED);
        assert!(
            final_status_line("wf_contract", &failed)
                .contains(&format!("failed \u{b7} {errors} failed"))
        );
    }

    let cancelled = report(1, true);
    assert_eq!(run_status(&cancelled), "stopped");
    assert_eq!(run_exit_code(&cancelled), crate::output::EXIT_INTERRUPTED);
}

#[test]
fn a_run_whose_join_failed_still_settles_to_a_terminal_state() {
    // The in-turn path returns early when the engine hands back an error — now a reachable
    // path, because the journal refuses a second writer for a colliding run id instead of
    // interleaving into it. `persist_inputs` has ALREADY created the directory `list`
    // enumerates, so a failure that skipped `persist_result` would sit there as a stub
    // forever: the same permanent pollution as never persisting at all.
    let workflows_dir = scratch_dir("failed");
    let manifest = RunManifest {
        run_id: "wf_failed".into(),
        name: "triage".into(),
        args: serde_json::Value::Null,
        provider_id: "anthropic".into(),
        model: "core-model-1".into(),
        created_at: 7,
    };
    persist_inputs(&workflows_dir, &manifest, "export const meta = {};").unwrap();
    assert_eq!(
        list_runs(&workflows_dir)[0].status,
        "pending",
        "inputs alone are not a terminal state"
    );

    persist_result(
        &workflows_dir,
        "wf_failed",
        &RunReport {
            run_id: RunId::new("wf_failed"),
            value: serde_json::json!({ "error": "Workflow run failed: journal locked" }),
            stopped: true,
            cache_hits: 0,
            cache_misses: 0,
            errors: 0,
            tokens: 0,
            tool_calls: 0,
            elapsed_ms: 0,
        },
    )
    .unwrap();

    let listed = list_runs(&workflows_dir);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "triage");
    assert_eq!(listed[0].model, "core-model-1");
    assert_eq!(
        listed[0].status, "stopped",
        "a run that failed to join must reach a terminal state, not linger as running"
    );

    let _ = std::fs::remove_dir_all(&workflows_dir);
}

// -----------------------------------------------------------------------------------------
// Interrupt (Ctrl-C) on the live surface.
//
// Raw mode clears ISIG, so Ctrl-C is a KEY EVENT, not a signal: a fix built on
// `tokio::signal::ctrl_c` would compile, run, and never fire. These pin the decision and the
// loop that acts on it; the terminal-restore + exit-code halves are pinned end-to-end in
// `crates/cli/tests/workflow_interrupt_pty.rs`, which drives the real binary in a PTY.
// -----------------------------------------------------------------------------------------

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

fn ctrl_c() -> KeyEvent {
    key(KeyCode::Char('c'), KeyModifiers::CONTROL)
}

fn settled_report() -> RunReport {
    RunReport {
        run_id: RunId::new("wf_interrupt"),
        value: serde_json::Value::Null,
        stopped: true,
        cache_hits: 0,
        cache_misses: 0,
        errors: 0,
        tokens: 0,
        tool_calls: 0,
        elapsed_ms: 1,
    }
}

#[test]
fn ctrl_c_is_the_key_that_cancels_and_nothing_else_is() {
    assert_eq!(live_key_action(ctrl_c(), false), LiveAction::Cancel);
    assert_eq!(
        live_key_action(key(KeyCode::Char('C'), KeyModifiers::CONTROL), false),
        LiveAction::Cancel,
        "a shifted Ctrl-C is still Ctrl-C"
    );
    for benign in [
        key(KeyCode::Char('c'), KeyModifiers::NONE),
        key(KeyCode::Char('c'), KeyModifiers::ALT),
        key(KeyCode::Char('d'), KeyModifiers::CONTROL),
        key(KeyCode::Esc, KeyModifiers::NONE),
        key(KeyCode::Enter, KeyModifiers::NONE),
    ] {
        assert_eq!(
            live_key_action(benign, false),
            LiveAction::Ignore,
            "{benign:?} must not stop a running workflow"
        );
    }
}

#[test]
fn a_key_release_never_cancels() {
    // Windows reports a Release for every press; acting on both would cancel twice from one
    // physical Ctrl-C, i.e. force-exit before the run ever got a chance to settle.
    let mut release = ctrl_c();
    release.kind = KeyEventKind::Release;
    assert_eq!(live_key_action(release, false), LiveAction::Ignore);
    assert_eq!(live_key_action(release, true), LiveAction::Ignore);
}

#[test]
fn a_second_ctrl_c_while_settling_forces_the_exit() {
    assert_eq!(live_key_action(ctrl_c(), true), LiveAction::ForceExit);
}

#[test]
fn the_cancelled_frame_says_so_instead_of_just_freezing() {
    let theme = crate::theme::Theme::dark();
    let mut card = new_run_card("wf_interrupt", "triage", &["plan".to_string()]);

    let live = plain_lines(&live_lines(&card, 80, &theme, 0, true));
    assert!(live.contains("cancelling"), "{live}");
    assert!(live.contains("Ctrl-C again"), "{live}");

    card.finished = true;
    let settled = plain_lines(&live_lines(&card, 80, &theme, 0, true));
    assert!(settled.contains("run cancelled"), "{settled}");

    let untouched = plain_lines(&live_lines(&card, 80, &theme, 0, false));
    assert!(
        !untouched.contains("cancel"),
        "a run nobody interrupted must not claim it was cancelled: {untouched}"
    );
}

#[tokio::test]
async fn ctrl_c_invokes_cancel_and_the_loop_keeps_rendering_until_the_run_settles() {
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(Mutex::new(Vec::<bool>::new()));

    // The stand-in for the engine: it only resolves once cancellation was actually requested,
    // so a loop that drew a "cancelled" banner without calling `cancel()` would hang here.
    let settles_on_cancel = {
        let cancelled = cancelled.clone();
        async move {
            loop {
                if cancelled.load(Ordering::SeqCst) {
                    return Ok(settled_report());
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    };

    let mut keys = vec![ctrl_c()].into_iter();
    let draw_log = observed.clone();
    let cancel_flag = cancelled.clone();

    let outcome = live_loop(
        settles_on_cancel,
        move |cancelled, _spin| {
            draw_log.lock().unwrap().push(cancelled);
            Ok(())
        },
        move || keys.next(),
        move || cancel_flag.store(true, Ordering::SeqCst),
        std::time::Duration::from_millis(1),
    )
    .await
    .expect("the live loop settles");

    assert!(
        cancelled.load(Ordering::SeqCst),
        "Ctrl-C must actually invoke cancel() on the run handle"
    );
    match outcome {
        LiveOutcome::Settled {
            report, cancelled, ..
        } => {
            assert!(cancelled, "the loop must report that it was interrupted");
            assert!(report.stopped, "an interrupted run settles as stopped");
        }
        LiveOutcome::Forced => panic!("one Ctrl-C must wait for the run, not force-exit"),
    }
    let frames = observed.lock().unwrap();
    assert!(
        frames.iter().any(|drawn| *drawn),
        "the operator must see at least one frame acknowledging the interrupt: {frames:?}"
    );
}

#[tokio::test]
async fn a_second_ctrl_c_stops_waiting_on_a_run_that_will_not_settle() {
    let cancels = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = cancels.clone();
    // A run that ignores cancellation entirely — exactly the case a single Ctrl-C cannot fix.
    let never_settles = async {
        std::future::pending::<()>().await;
        unreachable!()
    };
    let mut keys = vec![ctrl_c(), ctrl_c()].into_iter();

    let outcome = live_loop(
        never_settles,
        |_cancelled, _spin| Ok(()),
        move || keys.next(),
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
        },
        std::time::Duration::from_millis(1),
    )
    .await
    .expect("the live loop returns instead of hanging");

    assert!(
        matches!(outcome, LiveOutcome::Forced),
        "a second Ctrl-C must stop waiting rather than hang forever"
    );
    assert_eq!(
        cancels.load(Ordering::SeqCst),
        1,
        "the run is asked to cancel once; the second press is the operator giving up"
    );
}

// -----------------------------------------------------------------------------------------
// The interactive-TUI progress seam (ADR-0001 step 1).
//
// The mapping is a pure function, so it is tested as one: no engine, no terminal, no channel.
// The exhaustiveness obligation the brief names is enforced twice over — `ui_safe_progress`
// matches every `ProgressEvent` variant with no wildcard arm (a new variant does not compile
// until it is given a projection), and `variant_tag` below repeats that with no wildcard, so a
// new variant also cannot be forgotten out of `every_progress_variant`.
// -----------------------------------------------------------------------------------------

/// A name for the shape of an event, by an exhaustive match. This exists so a `ProgressEvent`
/// variant added tomorrow breaks THIS file too, rather than quietly making the coverage
/// assertion below weaker by one variant.
fn variant_tag(event: &ProgressEvent) -> &'static str {
    match event {
        ProgressEvent::Phase { .. } => "phase",
        ProgressEvent::Log { .. } => "log",
        ProgressEvent::AgentQueued { .. } => "agent_queued",
        ProgressEvent::AgentStarted { .. } => "agent_started",
        ProgressEvent::AgentActivity { .. } => "agent_activity",
        ProgressEvent::AgentCancelling { .. } => "agent_cancelling",
        ProgressEvent::AgentFinished { .. } => "agent_finished",
    }
}

/// One of every variant, each carrying a hostile string in every string-shaped field: a screen-
/// clearing control sequence and a credential-shaped token.
///
/// The credential is delimited from what precedes it because `crate::semantic_text::ui_safe_text` defers
/// to `iteron_record::redact::scrub`, which matches credential-shaped TOKENS. What this pins is
/// that the seam ROUTES untrusted strings through the frontend's one gate — not a second,
/// private redaction implementation, which is exactly the drift that would let the two
/// disagree about what a secret looks like.
fn every_progress_variant(secret: &str) -> Vec<ProgressEvent> {
    vec![
        ProgressEvent::Phase {
            index: 1,
            title: format!("build \u{1b}[2Jindex {secret}"),
        },
        ProgressEvent::Log {
            message: format!("scanning \u{1b}[2J {secret}"),
        },
        ProgressEvent::AgentQueued {
            index: 0,
            label: format!("queued \u{1b}[2J {secret}"),
            phase: Some(format!("build \u{1b}[2Jindex {secret}")),
            model: Some(format!("model-x \u{1b}[2J {secret}")),
        },
        ProgressEvent::AgentStarted {
            index: 1,
            label: format!("started \u{1b}[2J {secret}"),
            phase: Some(format!("build \u{1b}[2Jindex {secret}")),
            model: Some(format!("model-x \u{1b}[2J {secret}")),
            queued_ms: 17,
            available_permits: 2,
        },
        ProgressEvent::AgentActivity {
            index: 1,
            tokens: 1_200,
            tool_calls: 3,
            last_tool_summary: Some(format!("read \u{1b}[2J {secret}")),
        },
        ProgressEvent::AgentCancelling {
            index: 1,
            cleanup_deadline_ms: 2_000,
        },
        ProgressEvent::AgentFinished {
            index: 1,
            label: format!("finished \u{1b}[2J {secret}"),
            state: WorkflowState::Error,
            tokens: 2_400,
            tool_calls: 4,
            duration_ms: 3_200,
            result_preview: Some(format!("result \u{1b}[2J {secret}")),
            last_tool_summary: Some(format!("read \u{1b}[2J {secret}")),
            error: Some(format!("refused \u{1b}[2J {secret}")),
        },
    ]
}

/// Every string a projected event carries, so a leak cannot hide in a field the test forgot.
fn strings_of(event: &ProgressEvent) -> Vec<String> {
    match event {
        ProgressEvent::Phase { title, .. } => vec![title.clone()],
        ProgressEvent::Log { message } => vec![message.clone()],
        ProgressEvent::AgentQueued {
            label,
            phase,
            model,
            ..
        }
        | ProgressEvent::AgentStarted {
            label,
            phase,
            model,
            ..
        } => [Some(label.clone()), phase.clone(), model.clone()]
            .into_iter()
            .flatten()
            .collect(),
        ProgressEvent::AgentActivity {
            last_tool_summary, ..
        } => last_tool_summary.clone().into_iter().collect(),
        ProgressEvent::AgentCancelling { .. } => Vec::new(),
        ProgressEvent::AgentFinished {
            label,
            result_preview,
            last_tool_summary,
            error,
            ..
        } => [
            Some(label.clone()),
            result_preview.clone(),
            last_tool_summary.clone(),
            error.clone(),
        ]
        .into_iter()
        .flatten()
        .collect(),
    }
}

#[test]
fn no_progress_variant_is_dropped_on_its_way_to_the_frontend() {
    let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
    let variants = every_progress_variant(secret);
    let tags: BTreeSet<&'static str> = variants.iter().map(variant_tag).collect();
    assert_eq!(
        tags.len(),
        variants.len(),
        "the coverage fixture must hold each variant exactly once"
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let sink = UiProgressSink::new("wf_seam", tx);
    for event in &variants {
        sink.emit(event.clone());
    }
    drop(sink);

    let mut seen: Vec<&'static str> = Vec::new();
    while let Ok(event) = rx.try_recv() {
        match event {
            WorkflowRunUiEvent::Progress { run_id, event } => {
                assert_eq!(run_id, "wf_seam", "every row is correlated to its run");
                seen.push(variant_tag(&event));
            }
            other => panic!("the sink emits only progress: {other:?}"),
        }
    }
    assert_eq!(
        seen,
        variants.iter().map(variant_tag).collect::<Vec<_>>(),
        "every variant must arrive, once, in order — a swallowed one is a row that never \
         appears or never settles"
    );
}

#[test]
fn untrusted_strings_are_gated_before_they_enter_retained_transcript_state() {
    let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
    for event in every_progress_variant(secret) {
        let projected = ui_safe_progress(event.clone());
        assert_eq!(
            variant_tag(&projected),
            variant_tag(&event),
            "the gate must not change what KIND of thing happened"
        );
        if let (
            ProgressEvent::AgentCancelling {
                index: expected_index,
                cleanup_deadline_ms: expected_deadline,
            },
            ProgressEvent::AgentCancelling {
                index,
                cleanup_deadline_ms,
            },
        ) = (&event, &projected)
        {
            assert_eq!(
                (index, cleanup_deadline_ms),
                (expected_index, expected_deadline)
            );
            continue;
        }
        let strings = strings_of(&projected);
        assert!(
            !strings.is_empty(),
            "{}: a variant with string fields must still carry them",
            variant_tag(&projected)
        );
        for text in strings {
            assert!(
                !text.contains(secret),
                "credential survived the gate: {text}"
            );
            assert!(
                !text.chars().any(char::is_control),
                "a control sequence reached the transcript: {text:?}"
            );
        }
    }
}

#[test]
fn an_oversized_label_cannot_push_a_row_off_the_screen() {
    let projected = ui_safe_progress(ProgressEvent::AgentStarted {
        index: 0,
        label: "x".repeat(10_000),
        phase: None,
        model: None,
        queued_ms: 0,
        available_permits: 0,
    });
    let ProgressEvent::AgentStarted { label, .. } = projected else {
        panic!("the variant is preserved");
    };
    assert_eq!(label.chars().count(), UI_LABEL_MAX + 1); // bound + the ellipsis
    assert!(label.ends_with('…'));
}

#[test]
fn the_gate_preserves_every_non_string_field() {
    let projected = ui_safe_progress(ProgressEvent::AgentFinished {
        index: 7,
        label: "row".into(),
        state: WorkflowState::Skipped,
        tokens: 2_400,
        tool_calls: 4,
        duration_ms: 3_200,
        result_preview: None,
        last_tool_summary: None,
        error: None,
    });
    // `Skipped` in particular: the engine's 5-state model is reused by the card, not projected
    // onto the native `WorkflowAgentOutcomeUi`, so no state has to be invented or collapsed.
    assert!(matches!(
        projected,
        ProgressEvent::AgentFinished {
            index: 7,
            state: WorkflowState::Skipped,
            tokens: 2_400,
            tool_calls: 4,
            duration_ms: 3_200,
            ..
        }
    ));
}

#[test]
fn a_narrator_line_that_sanitizes_to_nothing_is_still_a_log_line() {
    // `Log` has no counterpart in the native `WorkflowUiEvent` vocabulary at all, which is one
    // of ADR-0001's reasons for keeping the engine's own. It is carried, never merged away.
    let projected = ui_safe_progress(ProgressEvent::Log {
        message: "   ".into(),
    });
    let ProgressEvent::Log { message } = projected else {
        panic!("a log stays a log");
    };
    assert!(message.is_empty());
}

#[test]
fn the_fanout_feeds_every_sink_and_reports_its_least_capable_member() {
    struct OldSink;
    impl ProgressSink for OldSink {
        fn port_version(&self) -> u32 {
            1
        }
        fn emit(&self, _event: ProgressEvent) {}
    }

    let degraded = Arc::new(DegradedAgentSink::new());
    let recording = Arc::new(RecordingSink::default());
    let fanout = FanoutProgressSink::new(vec![degraded.clone(), recording.clone()]);
    assert_eq!(
        fanout.port_version(),
        PROGRESS_SINK_PORT_VERSION,
        "two current sinks are still current"
    );

    fanout.emit(ProgressEvent::AgentFinished {
        index: 2,
        label: "starved".into(),
        state: WorkflowState::Error,
        tokens: 0,
        tool_calls: 0,
        duration_ms: 1,
        result_preview: None,
        last_tool_summary: None,
        error: Some("agent call ceiling 1 reached".into()),
    });

    // Both halves of the in-turn contract survive: the model is still told what degraded, and
    // the operator's tree still receives the row.
    assert_eq!(
        degraded.reasons(),
        vec!["#2 starved: agent call ceiling 1 reached".to_string()]
    );
    assert_eq!(recording.events.lock().unwrap().len(), 1);

    let with_old = FanoutProgressSink::new(vec![recording, Arc::new(OldSink)]);
    assert_eq!(
        with_old.port_version(),
        1,
        "a fan-out is only as capable as its least capable member; claiming otherwise would \
         let the engine emit events one member cannot represent"
    );
}

#[test]
fn the_in_turn_sink_gains_the_tree_without_losing_the_models_degradation_reasons() {
    let starved = || ProgressEvent::AgentFinished {
        index: 2,
        label: "starved".into(),
        state: WorkflowState::Error,
        tokens: 0,
        tool_calls: 0,
        duration_ms: 1,
        result_preview: None,
        last_tool_summary: None,
        error: Some("agent call ceiling 1 reached".into()),
    };

    // No frontend attached (`iteron -p`, `--output-format json`, an embedder): the sink is the
    // degraded sink itself, so this path is byte-for-byte what it was before the seam existed.
    let headless = Arc::new(DegradedAgentSink::new());
    in_turn_progress_sink(headless.clone(), "wf_headless", None).emit(starved());
    assert_eq!(
        headless.reasons(),
        vec!["#2 starved: agent call ceiling 1 reached".to_string()]
    );

    // Frontend attached: the operator gets the row AND the model still gets the reason. Losing
    // either one is a silent lie to somebody.
    let attached = Arc::new(DegradedAgentSink::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    in_turn_progress_sink(attached.clone(), "wf_attached", Some(tx)).emit(starved());
    assert_eq!(
        attached.reasons(),
        vec!["#2 starved: agent call ceiling 1 reached".to_string()],
        "the tree must not replace what the model is told"
    );
    match rx.try_recv().expect("the frontend saw the row") {
        WorkflowRunUiEvent::Progress { run_id, event } => {
            assert_eq!(run_id, "wf_attached");
            assert_eq!(variant_tag(&event), "agent_finished");
        }
        other => panic!("unexpected seam event: {other:?}"),
    }
}

#[test]
fn the_degraded_sink_keeps_only_the_agents_that_did_not_complete() {
    let sink = DegradedAgentSink::new();
    sink.emit(ProgressEvent::AgentFinished {
        index: 1,
        label: "ok".into(),
        state: WorkflowState::Done,
        tokens: 10,
        tool_calls: 0,
        duration_ms: 5,
        result_preview: None,
        last_tool_summary: None,
        error: None,
    });
    sink.emit(ProgressEvent::AgentFinished {
        index: 2,
        label: "starved".into(),
        state: WorkflowState::Error,
        tokens: 0,
        tool_calls: 0,
        duration_ms: 1,
        result_preview: None,
        last_tool_summary: None,
        error: Some("agent call ceiling 1 reached".into()),
    });
    sink.emit(ProgressEvent::Log {
        message: "narration".into(),
    });

    assert_eq!(
        sink.reasons(),
        vec!["#2 starved: agent call ceiling 1 reached".to_string()],
        "an exhausted budget must stay visible instead of being filtered away as a null"
    );
}

// ---- S9: the session-scoped owner of detached runs -----------------------------------------

/// Build a `PreparedWorkflow` for `script` the way `Agent::prepare_workflow` does, minus
/// everything that needs a live route. The manifest is written first for the same reason the
/// kernel writes it first: a run must be listable before anything can start it.
fn prepared_for(tag: &str, script: &str, background: bool) -> PreparedWorkflow {
    prepared_with(
        tag,
        script,
        background,
        Arc::new(ProviderSpawner::new(
            Arc::new(RecordingProvider::successful()),
            "parent-model".into(),
        )),
    )
}

/// The same, with the spawner chosen by the caller: the owner tests below need to decide when
/// an agent finishes and which one degrades, which no provider stand-in can express.
fn prepared_with(
    tag: &str,
    script: &str,
    background: bool,
    spawner: Arc<dyn AgentSpawner>,
) -> PreparedWorkflow {
    let workflows_dir = scratch_dir(tag);
    let run_id = format!("wf-{tag}");
    let name = "owned".to_string();
    persist_inputs(
        &workflows_dir,
        &RunManifest {
            run_id: run_id.clone(),
            name: name.clone(),
            args: serde_json::Value::Null,
            provider_id: "provider-a".into(),
            model: "model-a".into(),
            created_at: 0,
        },
        script,
    )
    .unwrap();
    let degraded = Arc::new(DegradedAgentSink::new());
    PreparedWorkflow {
        run_id: run_id.clone(),
        name,
        declared_phases: Vec::new(),
        workflows_dir: workflows_dir.clone(),
        spec: RunSpec::new(script)
            .with_run_id(RunId::new(run_id))
            .with_workflows_dir(workflows_dir),
        spawner,
        sink: degraded.clone(),
        degraded,
        background,
    }
}

/// Pure QuickJS, so these tests never touch a provider.
const OWNED_SCRIPT: &str =
    "export const meta = { name: 'owned', description: '', phases: [] };\nreturn 7;\n";
/// A script that will not finish on its own: the only way out is cancellation.
const ENDLESS_SCRIPT: &str =
    "export const meta = { name: 'owned', description: '', phases: [] };\nwhile (true) {}\n";

async fn settled_line(rx: &mut tokio::sync::mpsc::Receiver<RunSettled>) -> RunSettled {
    tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
        .await
        .expect("the reaper announced the run within the test timeout")
        .expect("the supervisor still holds a sender")
}

#[tokio::test]
async fn an_unrequested_run_still_belongs_to_the_turn_even_with_an_owner_installed() {
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let prepared = prepared_for("owner-default", OWNED_SCRIPT, false);
    let dir = prepared.workflows_dir.clone();

    let Launched::InTurn(handle) = owner.launch(prepared) else {
        panic!("detaching is opt-in; an unrequested run must stay in-turn");
    };
    assert_eq!(handle.join().await.unwrap().value, serde_json::json!(7));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn a_backgrounded_run_is_detached_and_its_result_is_readable_only_by_collecting_it() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let prepared = prepared_for("owner-detach", OWNED_SCRIPT, true);
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();

    let Launched::Detached(detached) = owner.launch(prepared) else {
        panic!("an owner that can hold a run must grant the request");
    };
    assert_eq!(detached.run_id, run_id);
    assert_eq!(detached.ownership, WorkflowSupervisor::OWNERSHIP);

    // Before the run settles, collect is a status and NEVER a value: this is the property that
    // stops the model reporting a completion that has not happened.
    match owner.collect(&run_id) {
        Collected::Running { .. } | Collected::Settled { .. } => {}
        other => panic!(
            "a live detached run is running or settled, never unknown: {}",
            matches!(other, Collected::Unknown(_))
        ),
    }

    let settled = settled_line(&mut rx).await;
    assert_eq!(settled.run_id, run_id);
    assert!(settled.notice.contains("finished"), "{}", settled.notice);

    let Collected::Settled { summary } = owner.collect(&run_id) else {
        panic!("a settled run collects its result");
    };
    // The SAME rendering the in-turn path would have returned for this report.
    assert!(summary.contains(&run_id), "{summary}");
    assert!(summary.contains("finished"), "{summary}");
    assert!(summary.contains('7'), "{summary}");

    // And the result is durable, so a model that never collects has still not destroyed it.
    let listed = list_runs(&dir);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "done");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn collecting_a_run_this_session_never_started_is_answered_not_guessed() {
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let Collected::Unknown(message) = owner.collect("wf-never-existed") else {
        panic!("an unknown id is unknown, not a result");
    };
    assert!(message.contains("wf-never-existed"), "{message}");
    // The in-turn launcher owns nothing past the turn and says exactly that.
    assert!(matches!(
        InTurnWorkflowLauncher.collect("wf-anything"),
        Collected::Unknown(_)
    ));
}

#[tokio::test]
async fn a_session_that_ends_with_a_live_run_stops_it_and_records_a_terminal_state() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let prepared = prepared_for("owner-shutdown", ENDLESS_SCRIPT, true);
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();
    let Launched::Detached(_) = owner.launch(prepared) else {
        panic!("the run must detach for this to be a test of session exit");
    };

    let report = owner
        .shutdown(&mut rx, std::time::Duration::from_secs(10))
        .await;
    assert!(!report.is_empty(), "a stopped run is always reported");
    let line = report.lines.join("\n");
    assert!(line.contains(&run_id), "{line}");
    assert!(
        line.contains("iteron workflow resume"),
        "the operator is told how to continue it: {line}"
    );

    // The run is no longer listed as `running`: the exact "stub that never reaches a terminal
    // state" failure an unowned detached run would have created.
    let listed = list_runs(&dir);
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].status, "running", "{:?}", listed[0].status);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn a_session_with_no_live_run_reports_nothing_at_exit() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    assert!(
        owner
            .shutdown(&mut rx, std::time::Duration::from_secs(1))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn cancelling_a_detached_run_stops_it_and_the_owner_still_records_it() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let prepared = prepared_for("owner-cancel", ENDLESS_SCRIPT, true);
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();
    let Launched::Detached(_) = owner.launch(prepared) else {
        panic!("the run must detach to be cancellable out of band");
    };

    let before = owner.inventory();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].status, SupervisedRunStatus::Running);
    let stopping = owner
        .cancel_for_operator(&run_id)
        .expect("the operator owns this run");
    assert_eq!(stopping.status, SupervisedRunStatus::Cancelling);
    assert!(!owner.may_resume(&run_id));

    let settled = settled_line(&mut rx).await;
    assert_eq!(settled.run_id, run_id);
    assert!(owner.may_resume(&run_id));
    assert_eq!(owner.inventory()[0].status, SupervisedRunStatus::Settled);
    let Collected::Settled { summary } = owner.collect(&run_id) else {
        panic!("a cancelled run still settles with a readable outcome");
    };
    assert!(summary.contains("KILLED"), "{summary}");
    assert_eq!(
        list_runs(&dir)[0].status,
        run_status(&unreported_run(&run_id, ""))
    );
    std::fs::remove_dir_all(dir).ok();
}

// ---- Killing a run returns the work it had already finished -------------------------------
//
// The engine forces a stopped run's value to `null` on purpose (a half-evaluated JS value is
// meaningless), so nothing INSIDE it can carry the finished agents' results across a kill. If
// the owner does not keep them, a deliberate cancellation and a crash produce byte-identical
// answers, and the operator silently pays for work they are never shown.

/// A spawner with no provider behind it, so these tests exercise the OWNER rather than a route.
/// `fail_on` degrades to null; `block_on` never returns on its own, so the run's cancellation is
/// the only way out. Every call announces itself, which is what lets a test act at a known point
/// in the run instead of racing it.
struct ScriptedSpawner {
    started: tokio::sync::mpsc::Sender<String>,
    calls: AtomicUsize,
    fail_on: Option<&'static str>,
    block_on: Option<&'static str>,
}

impl ScriptedSpawner {
    fn new(started: tokio::sync::mpsc::Sender<String>) -> Self {
        ScriptedSpawner {
            started,
            calls: AtomicUsize::new(0),
            fail_on: None,
            block_on: None,
        }
    }

    fn failing_on(mut self, prompt: &'static str) -> Self {
        self.fail_on = Some(prompt);
        self
    }

    fn blocking_on(mut self, prompt: &'static str) -> Self {
        self.block_on = Some(prompt);
        self
    }
}

#[async_trait::async_trait]
impl AgentSpawner for ScriptedSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.started.try_send(call.prompt.clone());
        if self.fail_on == Some(call.prompt.as_str()) {
            return AgentOutcome::null("provider exploded");
        }
        if self.block_on == Some(call.prompt.as_str()) {
            // The engine also aborts this child on cancel; awaiting the token makes the intent
            // explicit rather than leaning on that backstop.
            call.cancel.cancelled().await;
            return AgentOutcome::null("stopped");
        }
        AgentOutcome::text(format!("{}-result", call.prompt), 3)
    }
}

async fn next_started(rx: &mut tokio::sync::mpsc::Receiver<String>) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
        .await
        .expect("the spawner reported a call within the test timeout")
        .expect("the run still holds the spawner")
}

/// Two agents in sequence, the second of which blocks forever: a kill therefore lands on a run
/// with one agent's work already done and exactly one agent in flight.
const KILL_SCRIPT: &str = "export const meta = { name: 'owned', description: '', phases: [] };\n\
     const first = await agent('alpha');\n\
     const second = await agent('beta');\n\
     return [first, second];\n";

/// A fan of three, one of which degrades to null.
const FAN_SCRIPT: &str = "export const meta = { name: 'owned', description: '', phases: [] };\n\
     return await parallel([() => agent('alpha'), () => agent('boom'), () => agent('gamma')]);\n";

#[tokio::test]
async fn killing_a_detached_run_returns_the_agents_that_had_already_finished() {
    let (settled_tx, mut settled_rx) = tokio::sync::mpsc::channel(16);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(settled_tx);
    let prepared = prepared_with(
        "owner-kill-partial",
        KILL_SCRIPT,
        true,
        Arc::new(ScriptedSpawner::new(started_tx).blocking_on("beta")),
    );
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();
    let Launched::Detached(_) = owner.launch(prepared) else {
        panic!("the run must detach to be killable out of band");
    };

    // `beta` having started proves `alpha` finished: the script awaits them in sequence. So the
    // kill below lands on a run with one real result behind it and one agent still running —
    // no sleep, no polling, no race.
    assert_eq!(next_started(&mut started_rx).await, "alpha");
    assert_eq!(next_started(&mut started_rx).await, "beta");

    let Collected::Running { name, .. } = owner.cancel(&run_id) else {
        panic!("cancel stays a request honoured at the engine's next safe point");
    };
    assert!(name.contains("cancelling"), "{name}");

    settled_line(&mut settled_rx).await;
    let Collected::Settled { summary } = owner.collect(&run_id) else {
        panic!("a killed run still has a terminal answer");
    };
    assert!(
        summary.contains("alpha-result"),
        "a kill must return the work the run had already finished, or it is indistinguishable \
         from a crash: {summary}"
    );
    assert!(
        summary.contains("1 agent(s) were still running"),
        "the answer must count what the kill interrupted: {summary}"
    );
    assert!(summary.contains("KILLED"), "{summary}");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn one_agent_failing_does_not_kill_the_run_or_its_siblings() {
    let (settled_tx, mut settled_rx) = tokio::sync::mpsc::channel(16);
    let (started_tx, _started_rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(settled_tx);
    let spawner = Arc::new(ScriptedSpawner::new(started_tx).failing_on("boom"));
    let prepared = prepared_with("owner-one-failure", FAN_SCRIPT, true, spawner.clone());
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();
    let Launched::Detached(_) = owner.launch(prepared) else {
        panic!("the run must detach for this to be a test of the owner");
    };

    let settled = settled_line(&mut settled_rx).await;
    assert!(
        settled.notice.contains("finished"),
        "a failed agent is not a killed run: {}",
        settled.notice
    );
    let Collected::Settled { summary } = owner.collect(&run_id) else {
        panic!("the run settles");
    };
    assert!(!summary.contains("KILLED"), "{summary}");
    assert_eq!(
        spawner.calls.load(Ordering::SeqCst),
        4,
        "all three declared agents run and the failed agent receives its one bounded retry"
    );
    for survivor in ["alpha-result", "gamma-result"] {
        assert!(
            summary.contains(survivor),
            "a sibling's failure must not delete {survivor}: {summary}"
        );
    }
    assert!(
        summary.contains("provider exploded"),
        "the one that failed is named, because it resolved to JS null and a script's \
         `.filter(Boolean)` would otherwise delete it silently: {summary}"
    );
    assert_ne!(
        list_runs(&dir)[0].status,
        "stopped",
        "an agent failure must not record the run as cancelled"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_partial_work_sink_keeps_finished_results_and_counts_what_the_kill_interrupted() {
    let sink = PartialWorkSink::new();
    let started = |index: usize| ProgressEvent::AgentStarted {
        index,
        label: format!("agent-{index}"),
        phase: None,
        model: None,
        queued_ms: 0,
        available_permits: 0,
    };
    let finished = |index: usize, state, preview: Option<&str>| ProgressEvent::AgentFinished {
        index,
        label: format!("agent-{index}"),
        state,
        tokens: 0,
        tool_calls: 0,
        duration_ms: 1,
        result_preview: preview.map(str::to_string),
        last_tool_summary: None,
        error: None,
    };

    for index in 0..3 {
        sink.emit(started(index));
    }
    sink.emit(finished(0, WorkflowState::Done, Some("first")));
    assert_eq!(sink.snapshot().running, 2);

    sink.note_kill();
    // The engine retires the in-flight rows as `stopped` errors on its way out. The answer must
    // report what the kill INTERRUPTED, not the zero that is left once it has finished
    // interrupting — a sample taken after the cancel flatters the kill.
    sink.emit(finished(1, WorkflowState::Error, None));
    sink.emit(finished(2, WorkflowState::Error, None));
    sink.note_kill();

    let partial = sink.snapshot();
    assert_eq!(partial.running, 2, "the count is sampled at the first kill");
    assert_eq!(partial.finished.len(), 1, "only results are kept");
    assert_eq!(partial.finished[0].result, "first");
    assert_eq!(partial.dropped, 0);
}

#[test]
fn retained_partial_results_are_bounded_and_every_refusal_is_counted() {
    let sink = PartialWorkSink::new();
    let wide = 4_000usize;
    for index in 0..wide {
        sink.emit(ProgressEvent::AgentFinished {
            index,
            label: "row".into(),
            state: WorkflowState::Done,
            tokens: 0,
            tool_calls: 0,
            duration_ms: 1,
            result_preview: Some("x".repeat(PREVIEW_MAX)),
            last_tool_summary: None,
            error: None,
        });
    }

    let partial = sink.snapshot();
    assert!(
        partial.finished.len() < wide,
        "a wide fan-out cannot be retained whole"
    );
    assert_eq!(
        partial.finished.len() + partial.dropped,
        wide,
        "every result is either kept or counted as dropped; silent truncation would make a \
         short answer look complete"
    );
    assert_eq!(
        partial.finished[0].index, 0,
        "the earliest results are the ones kept, so a result a client already read in one \
         collect cannot vanish from the next"
    );
}

#[test]
fn a_killed_summary_and_a_completed_one_cannot_be_mistaken_for_each_other() {
    let killed_report = RunReport {
        run_id: RunId::new("wf_kill"),
        value: serde_json::Value::Null,
        stopped: true,
        cache_hits: 0,
        cache_misses: 2,
        errors: 1,
        tokens: 9,
        tool_calls: 0,
        elapsed_ms: 5,
    };
    let partial = PartialWork {
        finished: vec![FinishedAgent {
            index: 0,
            label: "alpha".into(),
            result: "alpha said this".into(),
        }],
        running: 2,
        dropped: 0,
    };

    let killed = killed_run_summary(
        "triage",
        "wf_kill",
        &killed_report,
        &partial,
        &["#1 beta: stopped".to_string()],
    );
    assert!(killed.contains("KILLED"), "{killed}");
    assert!(killed.contains("alpha said this"), "{killed}");
    assert!(killed.contains("2 agent(s) were still running"), "{killed}");
    assert!(killed.contains("#1 beta: stopped"), "{killed}");

    let mut done_report = killed_report.clone();
    done_report.stopped = false;
    let done = run_result_summary("triage", "wf_done", &done_report, &[]);
    assert!(done.contains("finished"), "{done}");
    assert!(
        !done.contains("KILLED"),
        "a completed run must never read as a kill: {done}"
    );

    // A kill with nothing behind it says so, rather than leaving the client to read an empty
    // list as either "no work" or "the work was dropped".
    let nothing = killed_run_summary(
        "triage",
        "wf_kill",
        &killed_report,
        &PartialWork::default(),
        &[],
    );
    assert!(nothing.contains("no partial result"), "{nothing}");
    assert!(
        nothing.contains("0 agent(s) were still running"),
        "{nothing}"
    );
}

#[tokio::test]
async fn cancelling_a_run_whose_summary_was_evicted_still_admits_the_run_existed() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let owner = WorkflowSupervisor::new(tx);
    let prepared = prepared_for("owner-evicted-cancel", OWNED_SCRIPT, true);
    let dir = prepared.workflows_dir.clone();
    let run_id = prepared.run_id.clone();
    let Launched::Detached(_) = owner.launch(prepared) else {
        panic!("the run must detach to be owned");
    };
    settled_line(&mut rx).await;

    // Force the state the byte bound eventually produces. Driving 4 MiB of real summaries
    // through the reaper would exercise the same branch a thousand times more slowly.
    owner.evict_summary_for_test(&run_id);

    let Collected::Settled { summary } = owner.cancel(&run_id) else {
        panic!("a run this session owned is never unknown to it, even once its summary is gone");
    };
    assert!(summary.contains("result.json"), "{summary}");
    let Collected::Settled { summary: collected } = owner.collect(&run_id) else {
        panic!("collect gives the same answer");
    };
    assert_eq!(
        summary, collected,
        "cancel and collect disagreeing about one run is how a result gets reported as lost"
    );
    std::fs::remove_dir_all(dir).ok();
}
