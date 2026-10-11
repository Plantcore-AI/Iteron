//! Completion observations never change the run owner, terminal outcome or input readiness.
use super::{App, Session, block, kv};
use iteron_protocol::client_final_evidence::HostFinalEvidenceReadV1;
use iteron_protocol::client_final_evidence::description;
use iteron_protocol::final_evidence::HostFinalEvidenceV1;
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
        || fact.first_turn > fact.final_turn
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
    use iteron_protocol::final_evidence::HostConfiguredCheckV1;
    if matches!(
        fact.configured_check,
        HostConfiguredCheckV1::Passed | HostConfiguredCheckV1::Failed
    ) && fact.configured_check_source_seq.is_none()
        || fact.configured_check == HostConfiguredCheckV1::NotObserved
            && fact.configured_check_source_seq.is_some()
    {
        return;
    }
    if app.final_evidence.admit(&fact) {
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
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
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
            assert!(app.history.blocks().is_empty());
        }
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), 1);
        let text = app.history.blocks()[0].to_text();
        assert!(text.contains("unverified"));
        assert!(!text.contains("suite passed"));
        assert!(!app.run.running());
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), 1);
    }
    #[test]
    fn changed_native_receipts_render_positive_work_without_suite_or_current_workspace_claims() {
        let mut app = App::new();
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
            assert!(app.history.blocks().is_empty());
        }
        remote(&mut app, &value, &thread, &tenant, &run);
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
    }
}
