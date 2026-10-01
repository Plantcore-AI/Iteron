//! Strict ordinary-client controls for the same host discovery and retry owner used by TUI.
use crate::app_server::ProviderCatalogControl;
use iteron_protocol::client_inventory::ClientModelSelectionV1;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ProviderCatalogCommandV1 {
    FirstFrame,
    Refresh,
    Retry { selection: ClientModelSelectionV1 },
}
impl ProviderCatalogCommandV1 {
    pub(super) fn into_control(self) -> ProviderCatalogControl {
        match self {
            Self::FirstFrame => ProviderCatalogControl::FirstFrame,
            Self::Refresh => ProviderCatalogControl::Refresh,
            Self::Retry { selection } => ProviderCatalogControl::Retry(selection),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::headless::control::WireControl;
    use serde_json::json;
    #[test]
    fn host_discovery_retry_are_operator_only_and_accept_no_bootstrap_authority() {
        for action in ["first_frame", "refresh"] {
            let command: WireControl = serde_json::from_value(
                json!({"type":"provider_catalog_v1","command":{"action":action}}),
            )
            .unwrap();
            assert!(!command.is_read_only());
            for key in ["path", "credential", "config", "endpoint", "actor"] {
                assert!(serde_json::from_value::<WireControl>(json!({"type":"provider_catalog_v1","command":{"action":action,(key):"untrusted"}})).is_err());
            }
        }
        let command:ProviderCatalogCommandV1=serde_json::from_value(json!({"action":"retry","selection":{"inventory_digest_sha256":"1".repeat(64),"provider_id":"host","model_id":"model","catalog_digest_sha256":"2".repeat(64),"capability_digest_sha256":"3".repeat(64)}})).unwrap();
        assert!(matches!(
            command.into_control(),
            ProviderCatalogControl::Retry(_)
        ));
    }
}
