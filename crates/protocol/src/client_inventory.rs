//! Bounded public inventory queries and immutable route selection identities.

use serde::{Deserialize, Serialize};

pub const CLIENT_INVENTORY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientInventoryKindV1 {
    Overview,
    Providers,
    Models,
    Plugins,
    Tools,
    Hooks,
    Agents,
    Skills,
    EffectiveConfig,
    Permissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInventoryQueryV1 {
    pub kind: ClientInventoryKindV1,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u16,
}

fn default_limit() -> u16 {
    32
}

impl ClientInventoryQueryV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.limit == 0 || self.limit > 100 || self.offset > 50_000 {
            return Err("inventory page is outside its bound");
        }
        if self
            .provider_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            return Err("invalid bounded provider identity");
        }
        if self.provider_id.is_some() && !matches!(self.kind, ClientInventoryKindV1::Models) {
            return Err("provider filter is only valid for models");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientModelSelectionV1 {
    pub inventory_digest_sha256: String,
    pub provider_id: String,
    pub model_id: String,
    pub catalog_digest_sha256: String,
    pub capability_digest_sha256: String,
}

impl ClientModelSelectionV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        for value in [
            &self.inventory_digest_sha256,
            &self.catalog_digest_sha256,
            &self.capability_digest_sha256,
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("model selection requires exact captured SHA-256 identities");
            }
        }
        for value in [&self.provider_id, &self.model_id] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err("invalid bounded route identity");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_and_route_schema_reject_authority_and_unknown_evidence() {
        let query: ClientInventoryQueryV1 = serde_json::from_str(r#"{"kind":"tools"}"#).unwrap();
        assert_eq!(query.limit, 32);
        assert!(query.validate().is_ok());
        for value in [
            r#"{"kind":"tools","actor":"operator"}"#,
            r#"{"kind":"models","path":"/tmp"}"#,
        ] {
            assert!(serde_json::from_str::<ClientInventoryQueryV1>(value).is_err());
        }
        let mut query = query;
        query.limit = 101;
        assert!(query.validate().is_err());
        query.limit = 1;
        query.provider_id = Some("p".into());
        assert!(query.validate().is_err());
        let mut route = ClientModelSelectionV1 {
            inventory_digest_sha256: "a".repeat(64),
            provider_id: "p".into(),
            model_id: "m".into(),
            catalog_digest_sha256: "b".repeat(64),
            capability_digest_sha256: "c".repeat(64),
        };
        assert!(route.validate().is_ok());
        route.capability_digest_sha256 = "unknown".into();
        assert!(route.validate().is_err());
    }
}
