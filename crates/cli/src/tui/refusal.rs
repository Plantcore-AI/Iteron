//! Authority labels come from the closed host reason, never from error prose.
use super::{App, block, kv};
use iteron_protocol::refusal::{HostRefusalV1, RefusalOriginV1};
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
    let mut rows = vec![
        kv("source", origin_label(refusal.origin())),
        block::PanelRow::Note(refusal.summary().into()),
        kv(
            "effects",
            match refusal.effects {
                iteron_protocol::refusal::RefusalEffectStateV1::NotDispatched => "not dispatched",
                iteron_protocol::refusal::RefusalEffectStateV1::Settled => "settled",
                iteron_protocol::refusal::RefusalEffectStateV1::Unknown => "unconfirmed",
                iteron_protocol::refusal::RefusalEffectStateV1::Unavailable => "unavailable",
            },
        ),
    ];
    if let Some(source) = &refusal.source {
        rows.push(kv(
            "supporting record",
            &format!(
                "{} seq {}",
                super::ui_safe_text(&source.run_id.0),
                source.sequence.0
            ),
        ));
    }
    app.panel("!", "Operation refused", rows);
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
            !raw[key].is_null() && !raw[key].as_str().is_some_and(|text| text.len() <= 2048)
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
        assert!(app.history.blocks().is_empty());
        let mut oversized = value.clone();
        oversized["observations"][0]["refusal"]["tool"] = serde_json::json!("x".repeat(2049));
        remote(&mut app, &oversized, &thread, &tenant, &run);
        assert!(app.history.blocks().is_empty());
        remote(&mut app, &value, &thread, &tenant, &run);
        assert_eq!(app.history.blocks().len(), 1);
        assert!(
            app.history.blocks()[0]
                .to_text()
                .contains("host permission policy")
        );
        assert!(!app.run.running());
    }
}
