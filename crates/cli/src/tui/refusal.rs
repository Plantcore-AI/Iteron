//! Authority labels come from the closed host reason, never from error prose.
use super::{App, block, kv};
use iteron_protocol::refusal::{
    HostRefusalV1, RefusalEffectStateV1, RefusalOriginV1, RefusalReasonV1,
};
use serde::Deserialize as _;
pub(super) fn origin_label(origin: RefusalOriginV1) -> &'static str {
    match origin {
        RefusalOriginV1::Unknown => "unavailable",
        RefusalOriginV1::OsSandbox => "operating-system sandbox",
        RefusalOriginV1::UserApproval => "operator approval",
        RefusalOriginV1::HostPolicy => "host permission policy",
        RefusalOriginV1::AdministratorPolicy => "administrator policy",
        RefusalOriginV1::ExtensionPolicy => "extension policy",
        RefusalOriginV1::ResourceLimit => "resource ceiling",
        RefusalOriginV1::ModelCapability => "model capability",
        RefusalOriginV1::Provider => "provider",
        RefusalOriginV1::DurableRecord => "durable record",
        RefusalOriginV1::OperatorControl => "operator control",
    }
}
pub(super) fn show(app: &mut App, refusal: &HostRefusalV1) {
    show_with_detail(app, refusal, "");
}

pub(super) fn show_with_detail(app: &mut App, refusal: &HostRefusalV1, detail: &str) {
    // Only the closed record classifier can supply a more precise host cause. Arbitrary remote
    // prose cannot replace the reason or name a different authority.
    let record_detail = refusal.reason == RefusalReasonV1::DurableRecordUnavailable
        && crate::runtime::KernelError::is_public_record_failure(detail);
    let mut text = format!(
        "Operation refused ({}): {}",
        origin_label(refusal.origin()),
        if record_detail {
            detail
        } else {
            refusal.summary()
        },
    );
    if !text.ends_with('.') {
        text.push('.');
    }
    match refusal.effects {
        RefusalEffectStateV1::NotDispatched => {}
        RefusalEffectStateV1::Settled => text.push_str(" Inspect the result before repeating."),
        RefusalEffectStateV1::Unknown => {
            text.push_str(" Effects are unconfirmed; do not repeat.");
        }
        RefusalEffectStateV1::Unavailable => text.push_str(" Retry safety is unavailable."),
    }
    if !record_detail {
        text.push(' ');
        text.push_str(next_step(refusal));
    }
    app.note(block::NoticeLevel::Warn, text);
}
fn retry_guidance(effects: RefusalEffectStateV1) -> &'static str {
    match effects {
        RefusalEffectStateV1::NotDispatched => "new request after fixing the cause",
        RefusalEffectStateV1::Settled => "inspect the result before repeating",
        RefusalEffectStateV1::Unknown => "do not repeat while effects remain unconfirmed",
        RefusalEffectStateV1::Unavailable => "retry safety unavailable; inspect the actual owner",
    }
}
fn next_step(refusal: &HostRefusalV1) -> &'static str {
    if matches!(
        refusal.effects,
        RefusalEffectStateV1::Unknown | RefusalEffectStateV1::Unavailable
    ) {
        return "Use /status and /activity to inspect actual work before another attempt.";
    }
    match refusal.reason {
        RefusalReasonV1::PermissionDenied
        | RefusalReasonV1::CapabilityCeiling
        | RefusalReasonV1::UntrustedExternalEffect
        | RefusalReasonV1::InvalidPermissionPolicy
        | RefusalReasonV1::AdministratorDenied => {
            "Use /status to inspect the effective policy; choose a permitted operation."
        }
        RefusalReasonV1::OperatorDenied
        | RefusalReasonV1::ApprovalUnavailable
        | RefusalReasonV1::ApprovalCancelled => {
            "Continue with a permitted alternative or send a revised request."
        }
        RefusalReasonV1::ApprovalProjectionIncomplete => {
            "Reduce the operation so its command, target and scope can be shown completely."
        }
        RefusalReasonV1::SandboxUnavailable | RefusalReasonV1::SandboxProfileRefused => {
            "Check the configured sandbox and backend before sending a new request."
        }
        RefusalReasonV1::ExtensionDenied | RefusalReasonV1::ExtensionUnavailable => {
            "Inspect extension configuration or choose another available tool."
        }
        RefusalReasonV1::BudgetLimit | RefusalReasonV1::DeadlineLimit => {
            "Use /status to inspect the limit; reduce the task or set a new budget."
        }
        RefusalReasonV1::ObservationLimit | RefusalReasonV1::ResourceUnavailable => {
            "Use /activity to inspect retained tasks and available owner capacity."
        }
        RefusalReasonV1::PricingUnavailable => {
            "Use /models to inspect an available route with valid pricing evidence."
        }
        RefusalReasonV1::ModelUnavailable | RefusalReasonV1::ModelContextLimit => {
            "Use /models to select an available route or reduce the request."
        }
        RefusalReasonV1::ProviderRefusal => "Revise the request before asking the provider again.",
        RefusalReasonV1::DurableRecordUnavailable => {
            "Preserve the session and inspect its record health before new work."
        }
        RefusalReasonV1::OperatorInterrupted => "Continue with a new request when ready.",
        RefusalReasonV1::DuplicateFailedAction => {
            "Change the failed operation or inspect its prior result before another attempt."
        }
        RefusalReasonV1::InvalidRequest => "Correct the request shape or use /help.",
        RefusalReasonV1::Unknown => "Use /status and /activity to inspect the actual owner.",
    }
}
pub(super) fn remote(
    app: &mut App,
    value: &serde_json::Value,
    thread: &iteron_protocol::SessionId,
    tenant: &iteron_protocol::TenantId,
    run: &iteron_protocol::RunId,
) {
    if value["type"] != "refusals_snapshot_v1"
        || value["thread_id"] != thread.0
        || value["run_id"] != run.0
        || value["source"] != "live_host_provenance"
    {
        return;
    }
    let Some(rows) = value["observations"]
        .as_array()
        .filter(|rows| rows.len() <= 64)
    else {
        return;
    };
    let mut previous = None;
    let mut display = Vec::new();
    for row in rows {
        let Some(sequence) = row["observation_sequence"].as_u64() else {
            return;
        };
        if previous.is_some_and(|old| sequence <= old) {
            return;
        }
        previous = Some(sequence);
        let raw = &row["refusal"];
        if ["tool", "tool_use_id"].into_iter().any(|key| {
            !raw[key].is_null() && raw[key].as_str().is_none_or(|text| text.len() > 2048)
        }) {
            return;
        }
        if !raw["source"].is_null()
            && (raw["source"]["tenant"] != tenant.0 || raw["source"]["run_id"] != run.0)
        {
            return;
        }
        let Ok(fact) = HostRefusalV1::deserialize(raw) else {
            return;
        };
        if fact.tool.as_ref().is_some_and(|tool| tool.len() > 2048)
            || fact.tool_use_id.as_ref().is_some_and(|id| id.len() > 2048)
            || fact.source.as_ref().is_some_and(|source| {
                source.tenant != *tenant || source.run_id != *run || source.sequence.0 == 0
            })
        {
            return;
        }
        display.push(block::PanelRow::Note(format!(
            "{} · {} · effects {}",
            origin_label(fact.origin()),
            fact.summary(),
            match fact.effects {
                iteron_protocol::refusal::RefusalEffectStateV1::NotDispatched => "not dispatched",
                iteron_protocol::refusal::RefusalEffectStateV1::Settled => "settled",
                iteron_protocol::refusal::RefusalEffectStateV1::Unknown => "unconfirmed",
                iteron_protocol::refusal::RefusalEffectStateV1::Unavailable => "unavailable",
            }
        )));
        display.push(kv("retry", retry_guidance(fact.effects)));
        display.push(kv("next step", next_step(&fact)));
    }
    display.push(block::PanelRow::Note(
        "Live host causes only; historical prose is not reclassified.".into(),
    ));
    app.panel("!", "Refusal causes", display);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_effects_keep_retry_guidance_uncertain_even_with_a_known_policy_cause() {
        let mut app = App::new();
        let mut refusal = HostRefusalV1::unscoped(RefusalReasonV1::PermissionDenied);
        refusal.effects = RefusalEffectStateV1::Unknown;
        show(&mut app, &refusal);
        let unknown = app.history.blocks().last().unwrap().to_text();
        assert!(unknown.contains("host permission policy"));
        assert!(unknown.contains("unconfirmed"));
        assert!(unknown.contains("do not repeat"));
        assert!(unknown.contains("/activity"));
        assert!(!unknown.contains("new request after fixing"));
        assert!(!app.run.running());
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 20)).unwrap();
        terminal
            .draw(|frame| crate::tui::draw(frame, &mut app))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(screen.contains("unconfirmed"));
        assert!(screen.contains("/activity"));
        refusal.effects = RefusalEffectStateV1::NotDispatched;
        show(&mut app, &refusal);
        let known = app.history.blocks().last().unwrap().to_text();
        assert!(known.contains("choose a permitted operation"));
        assert!(!known.contains("supporting record"));
        assert!(!known.contains("do not repeat"));
        assert!(matches!(
            app.history.blocks().last().unwrap().kind,
            block::BlockKind::Notice {
                level: block::NoticeLevel::Warn,
                ..
            }
        ));
    }

    #[test]
    fn ordinary_refusal_is_compact_and_closed_record_detail_keeps_the_recovery_step() {
        let mut app = App::new();
        let before = app.history.blocks().len();
        let mut refusal = HostRefusalV1::unscoped(RefusalReasonV1::DurableRecordUnavailable);
        refusal.effects = RefusalEffectStateV1::NotDispatched;
        let detail =
            crate::runtime::KernelError::Record(iteron_record::RecordError::WriterPoisoned)
                .public_summary();
        show_with_detail(&mut app, &refusal, &detail);
        assert_eq!(app.history.blocks().len(), before + 1);
        let text = app.history.blocks().last().unwrap().to_text();
        assert!(text.contains("durable record"));
        assert!(text.contains("[writer_poisoned]"));
        assert!(text.contains("close and recover this run"));
        assert!(!text.contains("supporting record"));
        assert!(!text.contains("next step"));
        assert!(!text.contains("record health"));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 20)).unwrap();
        terminal
            .draw(|frame| crate::tui::draw(frame, &mut app))
            .unwrap();
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(screen.contains("[writer_poisoned]"));
        assert!(screen.contains("recover"));
        assert!(screen.contains("reopening"));
        assert!(!screen.contains("supporting record"));
        assert!(!app.run.running());

        show_with_detail(
            &mut app,
            &refusal,
            "administrator denied private/record.json",
        );
        let opaque = app.history.blocks().last().unwrap().to_text();
        assert!(opaque.contains(refusal.summary()));
        assert!(!opaque.contains("administrator"));
        assert!(!opaque.contains("private/record.json"));
        refusal.reason = RefusalReasonV1::PermissionDenied;
        show_with_detail(&mut app, &refusal, &detail);
        let mismatched = app.history.blocks().last().unwrap().to_text();
        assert!(mismatched.contains("host permission policy"));
        assert!(!mismatched.contains("writer_poisoned"));
    }
    #[test]
    fn labels_keep_user_admin_and_sandbox_distinct() {
        assert_ne!(
            origin_label(RefusalOriginV1::UserApproval),
            origin_label(RefusalOriginV1::AdministratorPolicy)
        );
        assert_ne!(
            origin_label(RefusalOriginV1::HostPolicy),
            origin_label(RefusalOriginV1::OsSandbox)
        );
        assert_eq!(origin_label(RefusalOriginV1::Unknown), "unavailable");
    }
    #[test]
    fn attached_read_never_labels_foreign_record_or_opaque_prose_as_a_host_refusal() {
        let mut app = App::new();
        let initial_history = app
            .history
            .blocks()
            .iter()
            .map(|block| block.to_text())
            .collect::<Vec<_>>();
        let thread = iteron_protocol::SessionId("thread".into());
        let run = iteron_protocol::RunId("run".into());
        let tenant = iteron_protocol::TenantId::default();
        let mut value = serde_json::json!({"type":"refusals_snapshot_v1","thread_id":thread,"run_id":run,"source":"live_host_provenance","observations":[{"observation_sequence":0,"refusal":{"reason":"permission_denied","source":null,"tool":null,"tool_use_id":null,"effects":"not_dispatched"}}]});
        // Derive the actual closed serialized reason rather than guessing its spelling.
        value["observations"][0]["refusal"] = serde_json::to_value(HostRefusalV1::unscoped(
            iteron_protocol::refusal::RefusalReasonV1::PermissionDenied,
        ))
        .unwrap();
        let mut foreign = value.clone();
        foreign["observations"][0]["refusal"]["source"] =
            serde_json::json!({"tenant":tenant,"run_id":"other","turn":0,"sequence":9});
        remote(&mut app, &foreign, &thread, &tenant, &run);
        assert_eq!(
            app.history
                .blocks()
                .iter()
                .map(|block| block.to_text())
                .collect::<Vec<_>>(),
            initial_history
        );
        let mut oversized = value.clone();
        oversized["observations"][0]["refusal"]["tool"] = serde_json::json!("x".repeat(2049));
        remote(&mut app, &oversized, &thread, &tenant, &run);
        assert_eq!(
            app.history
                .blocks()
                .iter()
                .map(|block| block.to_text())
                .collect::<Vec<_>>(),
            initial_history
        );
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), initial_history.len() + 1);
        assert!(
            app.history
                .blocks()
                .last()
                .unwrap()
                .to_text()
                .contains("host permission policy")
        );
        assert!(!app.run.running());
    }
}
