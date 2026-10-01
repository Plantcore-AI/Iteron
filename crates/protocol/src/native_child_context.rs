//! Host-native child context publications and exact content-free references.
//! These are journal vocabulary, never model/client configuration admission.
use crate::{Effort, PermissionMode, PermissionRules, PricingRoute, capability_set::CapabilitySet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeChildContextV1 {
    pub version: u32,
    pub generation_sha256: String,
    pub base_sha256: String,
    pub publication_sequence: u64,
    pub tenant: String,
    pub run: String,
    pub scope_sha256: String,
    pub route: PricingRoute,
    pub context_window: Option<u64>,
    pub output_cap: Option<u32>,
    pub permission_mode: PermissionMode,
    pub permission_rules: PermissionRules,
    pub authority_ceiling: CapabilitySet,
    pub policy_capabilities: CapabilitySet,
    pub bypass_permissions: bool,
    pub default_effort: Effort,
}
impl NativeChildContextV1 {
    pub fn digest(&self) -> Result<String, &'static str> {
        if self.permission_rules.tool_rules().len() > 256
            || self
                .permission_rules
                .tool_rules()
                .any(|(name, _)| name.len() > 128)
            || [
                &self.tenant,
                &self.run,
                &self.route.provider_id,
                &self.route.model_id,
            ]
            .iter()
            .any(|value| value.len() > 512)
            || [
                &self.generation_sha256,
                &self.base_sha256,
                &self.scope_sha256,
                &self.route.catalog_digest,
                &self.route.capability_digest,
            ]
            .iter()
            .any(|value| value.len() > 71)
        {
            return Err("native child context exceeds its pre-encoding bound");
        }
        let mut value = self.clone();
        value.generation_sha256.clear();
        let bytes =
            serde_json::to_vec(&value).map_err(|_| "native child context encoding failed")?;
        if bytes.len() > 48 * 1024 {
            return Err("native child context exceeds its encoded bound");
        }
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 || !digest(&self.base_sha256) || !digest(&self.scope_sha256) {
            return Err("invalid native child context identity");
        }
        for text in [
            &self.tenant,
            &self.run,
            &self.route.provider_id,
            &self.route.model_id,
        ] {
            if text.is_empty() || text.len() > 512 || text.chars().any(char::is_control) {
                return Err("invalid native child context scope or route");
            }
        }
        for text in [&self.route.catalog_digest, &self.route.capability_digest] {
            if !text.is_empty() && !digest(text) {
                return Err("invalid native child route evidence");
            }
        }
        if self.scope_sha256
            != crate::agent_cohort::provider_scope(
                &crate::TenantId(self.tenant.clone()),
                &crate::RunId(self.run.clone()),
            )
        {
            return Err("native context source scope differs");
        }
        if self.context_window == Some(0) || self.output_cap == Some(0) {
            return Err("native child planning bound cannot be zero");
        }
        let mut count = 0usize;
        let mut bytes = 0usize;
        for (name, _) in self.permission_rules.tool_rules() {
            count += 1;
            bytes = bytes
                .checked_add(name.len())
                .ok_or("native tool-rule bound")?;
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err("invalid native tool-rule name");
            }
        }
        if count > 256 || bytes > 32 * 1024 || self.permission_rules.capability_rules().len() > 5 {
            return Err("native permission rules exceed their bound");
        }
        if self.generation_sha256 != self.digest()? {
            return Err("native child generation digest differs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeChildContextRefV1 {
    pub generation_sha256: String,
    pub tenant: String,
    pub run: String,
    pub sequence: u64,
}
impl NativeChildContextRefV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !digest(&self.generation_sha256) {
            return Err("invalid native child context reference digest");
        }
        for text in [&self.tenant, &self.run] {
            if text.is_empty() || text.len() > 512 || text.chars().any(char::is_control) {
                return Err("invalid native child context reference scope");
            }
        }
        Ok(())
    }
}
fn digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
