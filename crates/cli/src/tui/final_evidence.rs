//! Completion observations never change the run owner, terminal outcome or input readiness.
use super::{App, Session, block, kv};
use iteron_protocol::client_final_evidence::HostFinalEvidenceReadV1;
use iteron_protocol::client_final_evidence::description;
use iteron_protocol::final_evidence::{
    HostConfiguredCheckV1, HostFinalCorrectionV1, HostFinalEvidenceV1,
};
use iteron_protocol::{RunId, Seq};
use serde::Deserialize as _;

#[derive(Default)]
pub(super) struct FinalEvidencePresentation {
    last: Option<(RunId, Seq)>,
}
impl FinalEvidencePresentation {
    fn admit(&mut self, fact: &HostFinalEvidenceV1) -> bool {
        if self
            .last
            .as_ref()
            .is_some_and(|(run, seq)| *run == fact.run_id && *seq >= fact.source_seq)
        {
            return false;
        }
        self.last = Some((fact.run_id.clone(), fact.source_seq));
        true
    }
}
pub(super) fn apply(app: &mut App, session: &Session, fact: HostFinalEvidenceV1) {
    let Some(scope) = session.client.thread_snapshot_v1() else {
        return;
    };
    if scope.run_id != fact.run_id {
        return;
    }
    let actual = session
        .client
        .host_final_evidence_v1(HostFinalEvidenceReadV1 {
            thread_id: scope.thread_id,
            run_id: scope.run_id,
        });
    let Some(observed) = actual
        .get("evidence")
        .and_then(|value| serde_json::from_value::<HostFinalEvidenceV1>(value.clone()).ok())
    else {
        return;
    };
    if observed != fact || !app.final_evidence.admit(&fact) {
        return;
    }
    render(app, &fact);
}
fn render(app: &mut App, fact: &HostFinalEvidenceV1) {
    let mut observations = Vec::new();
    match fact.configured_check {
        HostConfiguredCheckV1::Passed => observations.push("Configured check passed.".into()),
        HostConfiguredCheckV1::Failed => {
            observations.push("Configured check failed; review its output.".into());
        }
        HostConfiguredCheckV1::Unknown if fact.configured_check_source_seq.is_some() => {
            observations.push("Configured check outcome is unconfirmed; review its output.".into());
        }
        HostConfiguredCheckV1::NotObserved | HostConfiguredCheckV1::Unknown => {}
    }
    if fact.observed_tool_failures > 0 {
        observations.push(format!(
            "{} tool {} failed; review the tool output.",
            fact.observed_tool_failures,
            if fact.observed_tool_failures == 1 {
                "call"
            } else {
                "calls"
            },
        ));
    }
    if !fact.effects_known {
        observations
            .push("Tool effects are unconfirmed; inspect affected work before retrying.".into());
    }
    if fact.correction == Some(HostFinalCorrectionV1::ConfiguredCheckFailed)
        && fact.configured_check != HostConfiguredCheckV1::Failed
    {
        observations.push("Configured check failed; review its output.".into());
    }
    if !observations.is_empty() {
        let level = if fact.configured_check == HostConfiguredCheckV1::Passed
            && fact.observed_tool_failures == 0
            && fact.effects_known
            && fact.correction != Some(HostFinalCorrectionV1::ConfiguredCheckFailed)
        {
            block::NoticeLevel::Info
        } else {
            block::NoticeLevel::Warn
        };
        app.note(level, observations.join(" "));
    }
}

pub(super) fn details(app: &mut App, session: &Session) {
    let Some(scope) = session.client.thread_snapshot_v1() else {
        return;
    };
    let actual = session
        .client
        .host_final_evidence_v1(HostFinalEvidenceReadV1 {
            thread_id: scope.thread_id,
            run_id: scope.run_id,
        });
    if let Some(fact) = actual
        .get("evidence")
        .and_then(|value| serde_json::from_value::<HostFinalEvidenceV1>(value.clone()).ok())
    {
        render_details(app, &fact);
    }
}

fn render_details(app: &mut App, fact: &HostFinalEvidenceV1) {
    app.panel(
        "◇",
        "Completion checks",
        vec![
            block::PanelRow::Note(description(fact).into()),
            kv(
                "tool completions",
                &fact.observed_tool_completions.to_string(),
            ),
            kv("tool failures", &fact.observed_tool_failures.to_string()),
            kv(
                "effects",
                if fact.effects_known {
                    "known"
                } else {
                    "unconfirmed"
                },
            ),
            kv(
                "write-capable work",
                if fact.write_capable_effect_admitted {
                    "admitted; changes not independently inspected"
                } else {
                    "not observed"
                },
            ),
            kv("observed work", fact.work_state.label()),
            kv("observed native file commits", &fact.observed_native_file_changes.to_string()),
            kv("test-suite identity", "unverified"),
            block::PanelRow::Note("Shows observed native file commits from this task. Repeat commits to a file each count; current workspace not scanned. Relevant test-suite identity remains unverified.".into()),
        ],
    );
}

pub(super) fn remote(
    app: &mut App,
    value: &serde_json::Value,
    thread: &iteron_protocol::SessionId,
    tenant: &iteron_protocol::TenantId,
    run: &RunId,
) {
    remote_read(app, value, thread, tenant, run, false);
}

pub(super) fn remote_details(
    app: &mut App,
    value: &serde_json::Value,
    thread: &iteron_protocol::SessionId,
    tenant: &iteron_protocol::TenantId,
    run: &RunId,
) {
    remote_read(app, value, thread, tenant, run, true);
}

fn remote_read(
    app: &mut App,
    value: &serde_json::Value,
    thread: &iteron_protocol::SessionId,
    tenant: &iteron_protocol::TenantId,
    run: &RunId,
    detailed: bool,
) {
    if value["type"] != "host_final_evidence_v1"
        || value["thread_id"] != thread.0
        || value["run_id"] != run.0
        || value["source"] != "actual_host_receipt"
        || value["historical_recovery"] != false
    {
        return;
    }
    let Ok(fact) = HostFinalEvidenceV1::deserialize(&value["evidence"]) else {
        return;
    };
    if fact.tenant != *tenant
        || fact.run_id != *run
        || fact.source_seq.0 == 0
        || fact.first_turn.0 > fact.final_turn.0
        || fact.observed_tool_failures > fact.observed_tool_completions
        || !fact.native_change_evidence_valid()
        || fact.workspace_diff_inspected
        || fact.test_suite_identity_verified
        || fact
            .configured_check_source_seq
            .is_some_and(|seq| seq.0 == 0 || seq >= fact.source_seq)
    {
        return;
    }
    if matches!(
        fact.configured_check,
        HostConfiguredCheckV1::Passed | HostConfiguredCheckV1::Failed
    ) && fact.configured_check_source_seq.is_none()
        || fact.configured_check == HostConfiguredCheckV1::NotObserved
            && fact.configured_check_source_seq.is_some()
    {
        return;
    }
    if detailed {
        render_details(app, &fact);
    } else if app.final_evidence.admit(&fact) {
        render(app, &fact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::final_evidence::{HostConfiguredCheckV1, HostFinalCoverageV1};
    use iteron_protocol::{TenantId, TurnId};
    #[test]
    fn configured_check_and_generic_completion_never_render_suite_success() {
        let mut fact = HostFinalEvidenceV1 {
            tenant: TenantId::default(),
            run_id: RunId("run".into()),
            first_turn: TurnId(0),
            final_turn: TurnId(0),
            source_seq: Seq(8),
            observed_tool_completions: 1,
            observed_tool_failures: 0,
            observed_native_file_changes: 0,
            native_change_source_seq: None,
            work_state: iteron_protocol::final_evidence::HostFinalWorkStateV1::Unverified,
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
            effects_known: true,
            write_capable_effect_admitted: true,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        };
        assert!(description(&fact).contains("success is unverified"));
        fact.configured_check = HostConfiguredCheckV1::Passed;
        assert_eq!(
            description(&fact),
            "Configured check passed; test-suite identity remains unverified."
        );
        let mut owner = FinalEvidencePresentation::default();
        assert!(owner.admit(&fact));
        assert!(!owner.admit(&fact));
        fact.source_seq = Seq(9);
        assert!(owner.admit(&fact));
        fact.run_id = RunId("other".into());
        fact.source_seq = Seq(1);
        assert!(owner.admit(&fact));
    }
    #[test]
    fn attached_final_fact_requires_actual_reader_scope_and_cannot_invent_suite_success() {
        let mut app = App::new();
        let initial_history = app
            .history
            .blocks()
            .iter()
            .map(|block| block.to_text())
            .collect::<Vec<_>>();
        let thread = iteron_protocol::SessionId("thread".into());
        let run = RunId("run".into());
        let tenant = TenantId::default();
        let fact = HostFinalEvidenceV1 {
            tenant: tenant.clone(),
            run_id: run.clone(),
            first_turn: TurnId(0),
            final_turn: TurnId(0),
            source_seq: Seq(17),
            observed_tool_completions: 0,
            observed_tool_failures: 0,
            observed_native_file_changes: 0,
            native_change_source_seq: None,
            work_state: iteron_protocol::final_evidence::HostFinalWorkStateV1::Unverified,
            configured_check: HostConfiguredCheckV1::Passed,
            configured_check_source_seq: Some(Seq(12)),
            effects_known: true,
            write_capable_effect_admitted: false,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        };
        let value = serde_json::json!({"type":"host_final_evidence_v1","thread_id":thread,"run_id":run,"evidence":fact,"source":"actual_host_receipt","historical_recovery":false});
        for key in ["run_id", "source", "historical_recovery", "suite"] {
            let mut forged = value.clone();
            match key {
                "run_id" => forged["run_id"] = serde_json::json!("other"),
                "source" => forged["source"] = serde_json::json!("model_claim"),
                "historical_recovery" => forged["historical_recovery"] = serde_json::json!(true),
                _ => forged["evidence"]["test_suite_identity_verified"] = serde_json::json!(true),
            };
            remote(&mut app, &forged, &thread, &tenant, &run);
            assert_eq!(
                app.history
                    .blocks()
                    .iter()
                    .map(|block| block.to_text())
                    .collect::<Vec<_>>(),
                initial_history
            );
        }
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), initial_history.len() + 1);
        let text = app.history.blocks().last().unwrap().to_text();
        assert!(text.contains("Configured check passed."));
        assert!(!text.contains("Completion checks"));
        assert!(!text.contains("suite passed"));
        assert!(!app.run.running());
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), initial_history.len() + 1);
    }
    #[test]
    fn successful_native_work_is_quiet_until_explicit_evidence_read() {
        let mut app = App::new();
        let initial_history = app
            .history
            .blocks()
            .iter()
            .map(|block| block.to_text())
            .collect::<Vec<_>>();
        let thread = iteron_protocol::SessionId("thread".into());
        let run = RunId("native-run".into());
        let tenant = TenantId::default();
        let fact = HostFinalEvidenceV1 {
            tenant: tenant.clone(),
            run_id: run.clone(),
            first_turn: TurnId(0),
            final_turn: TurnId(1),
            source_seq: Seq(17),
            observed_tool_completions: 1,
            observed_tool_failures: 0,
            observed_native_file_changes: 2,
            native_change_source_seq: Some(Seq(12)),
            work_state: iteron_protocol::final_evidence::HostFinalWorkStateV1::ChangedUnverified,
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
            effects_known: true,
            write_capable_effect_admitted: true,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        };
        let value = serde_json::json!({"type":"host_final_evidence_v1","thread_id":thread,"run_id":run,"evidence":fact,"source":"actual_host_receipt","historical_recovery":false});
        for field in [
            "work_state",
            "native_change_source_seq",
            "observed_native_file_changes",
        ] {
            let mut forged = value.clone();
            forged["evidence"][field] = match field {
                "work_state" => serde_json::json!("unverified"),
                "native_change_source_seq" => serde_json::json!(17),
                _ => serde_json::json!(0),
            };
            remote(&mut app, &forged, &thread, &tenant, &run);
            remote_details(&mut app, &forged, &thread, &tenant, &run);
            assert_eq!(
                app.history
                    .blocks()
                    .iter()
                    .map(|block| block.to_text())
                    .collect::<Vec<_>>(),
                initial_history
            );
        }
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), initial_history.len());
        remote_details(&mut app, &value, &thread, &tenant, &run);
        let semantic = app.history.blocks().last().unwrap().to_text();
        assert!(semantic.contains("Native changes committed"));
        assert!(semantic.contains("observed native file commits"));
        assert!(semantic.contains("current workspace not scanned"));
        assert!(semantic.contains("suite unverified"));
        assert!(!semantic.contains("suite passed") && !semantic.contains("no problem found"));
        assert!(!app.run.running());
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 40)).unwrap();
        terminal
            .draw(|frame| crate::tui::draw(frame, &mut app))
            .unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Native changes committed"));
        assert!(rendered.contains("unverified"));
        assert!(!rendered.contains("suite passed"));
        remote_details(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), initial_history.len() + 2);
    }

    fn greeting_fact() -> HostFinalEvidenceV1 {
        HostFinalEvidenceV1 {
            tenant: TenantId::default(),
            run_id: RunId("greeting".into()),
            first_turn: TurnId(0),
            final_turn: TurnId(0),
            source_seq: Seq(8),
            observed_tool_completions: 0,
            observed_tool_failures: 0,
            observed_native_file_changes: 0,
            native_change_source_seq: None,
            work_state: iteron_protocol::final_evidence::HostFinalWorkStateV1::Unverified,
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
            effects_known: true,
            write_capable_effect_admitted: false,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        }
    }

    fn terminal_text(app: &mut App) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| crate::tui::draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn greeting_and_successful_tools_add_no_completion_chrome() {
        let mut app = App::new();
        app.stream_text("Hi! How can I help?");
        app.flush_text();
        let before = app.history.blocks().len();
        let screen = terminal_text(&mut app);
        let mut fact = greeting_fact();
        render(&mut app, &fact);
        let thread = iteron_protocol::SessionId("thread".into());
        let value = serde_json::json!({"type":"host_final_evidence_v1","thread_id":thread,"run_id":fact.run_id,"evidence":fact,"source":"actual_host_receipt","historical_recovery":false});
        remote(&mut app, &value, &thread, &fact.tenant, &fact.run_id);
        assert_eq!(app.history.blocks().len(), before);
        assert_eq!(terminal_text(&mut app), screen);
        assert!(screen.contains("Hi! How can I help?"));
        assert!(!screen.contains("Completion checks"));
        assert!(!app.run.running());

        fact.observed_tool_completions = 1;
        render(&mut app, &fact);
        assert_eq!(app.history.blocks().len(), before);
        assert_eq!(terminal_text(&mut app), screen);

        fact.correction = Some(HostFinalCorrectionV1::TestSuccessUnverified);
        fact.source_seq = Seq(9);
        render(&mut app, &fact);
        let value = serde_json::json!({"type":"host_final_evidence_v1","thread_id":thread,"run_id":fact.run_id,"evidence":fact,"source":"actual_host_receipt","historical_recovery":false});
        remote(&mut app, &value, &thread, &fact.tenant, &fact.run_id);
        assert_eq!(app.history.blocks().len(), before);
        assert_eq!(terminal_text(&mut app), screen);
    }

    #[test]
    fn failures_and_unknown_effects_remain_concise_and_visible() {
        for (check, effects_known, expected) in [
            (
                HostConfiguredCheckV1::Failed,
                true,
                "Configured check failed",
            ),
            (
                HostConfiguredCheckV1::Unknown,
                false,
                "Tool effects are unconfirmed",
            ),
        ] {
            let mut app = App::new();
            let before = app.history.blocks().len();
            let mut fact = greeting_fact();
            fact.observed_tool_completions = 1;
            fact.observed_tool_failures = 1;
            fact.configured_check = check;
            fact.configured_check_source_seq = Some(Seq(5));
            fact.effects_known = effects_known;
            fact.write_capable_effect_admitted = true;
            render(&mut app, &fact);
            assert_eq!(app.history.blocks().len(), before + 1);
            let last = app.history.blocks().last().unwrap();
            assert!(matches!(
                last.kind,
                block::BlockKind::Notice {
                    level: block::NoticeLevel::Warn,
                    ..
                }
            ));
            let semantic = last.to_text();
            assert!(semantic.contains(expected));
            assert!(semantic.contains("1 tool call failed"));
            let screen = terminal_text(&mut app);
            // A warning may wrap between words; the terminal buffer includes the next row's
            // gutter and padding. Still require the complete visible phrase after whitespace.
            let visible = screen.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                visible.contains(expected),
                "expected {expected:?}: {visible}"
            );
            assert!(!screen.contains("Completion checks"));
            assert!(!screen.contains("test-suite identity"));
            assert!(!app.run.running());
        }
    }
}
