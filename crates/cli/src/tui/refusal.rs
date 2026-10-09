//! Authority labels come from the closed host reason, never from error prose.
use super::{App, block, kv};
use iteron_protocol::refusal::{HostRefusalV1, RefusalOriginV1};
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
}
