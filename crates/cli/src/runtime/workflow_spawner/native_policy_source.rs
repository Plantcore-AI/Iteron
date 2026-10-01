//! Immutable child-policy source from the actual validated run checkpoint.
//! Current executable provider selection is independent of the original family commitment.
use super::KernelSpawnerContext;
use crate::runtime::tunables_pin::TunablesPin;
use crate::runtime_tunables::execution_policy::{
    PerAgentToolProfileIdentity, RoleSpecificModelMapIdentity,
};
use iteron_record::TunablesCheckpoint;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) struct NativePolicySource {
    provider: String,
    model: String,
    roles: BTreeMap<String, String>,
    tools: BTreeMap<String, String>,
    checkpoint: String,
}
impl NativePolicySource {
    pub(crate) fn capture(pin: Option<&TunablesPin>) -> Result<Option<Arc<Self>>, &'static str> {
        let Some(pin) = pin else {
            return Ok(None);
        };
        let TunablesCheckpoint::V2(snapshot) = pin.checkpoint() else {
            return Ok(None);
        };
        let row = |key: &str| {
            snapshot
                .entries
                .iter()
                .find(|row| row.semantic_key == key)
                .and_then(|row| row.effective_value.as_ref())
                .ok_or("native policy source is unavailable")
        };
        let enumeration = |value: &serde_json::Value| -> Result<String, &'static str> {
            if value.get("type").and_then(serde_json::Value::as_str) != Some("enum") {
                return Err("native policy source has wrong type");
            }
            let text = value
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or("native policy source has no route")?;
            if text.is_empty() || text.len() > 512 || text.chars().any(char::is_control) {
                return Err("native policy route exceeds its bound");
            }
            Ok(text.to_owned())
        };
        let primary = enumeration(row("per_agent_model")?)?;
        let (provider, model) = primary
            .split_once(':')
            .ok_or("native policy route has no provider")?;
        if provider.is_empty() || provider.len() > 64 || model.is_empty() || model.len() > 512 {
            return Err("native policy route is invalid");
        }
        let value = row("role_specific_model_map")?;
        if value.get("type").and_then(serde_json::Value::as_str) != Some("map") {
            return Err("native role source has wrong type");
        }
        let entries = value
            .get("entries")
            .and_then(serde_json::Value::as_object)
            .ok_or("native role source has no entries")?;
        if entries.len() > 256 {
            return Err("native role source exceeds its bound");
        }
        let mut roles = BTreeMap::new();
        for (name, route) in entries {
            if name.is_empty() || name.len() > 96 || name.chars().any(char::is_control) {
                return Err("native role name exceeds its bound");
            }
            roles.insert(name.clone(), enumeration(route)?);
        }
        let tool_value = row("per_agent_tool_profile")?;
        if tool_value.get("type").and_then(serde_json::Value::as_str) != Some("map") {
            return Err("native tool source has wrong type");
        }
        let tool_entries = tool_value
            .get("entries")
            .and_then(serde_json::Value::as_object)
            .ok_or("native tool source is unavailable")?;
        if tool_entries.len() > 256 {
            return Err("native tool source exceeds its bound");
        }
        let mut tools = BTreeMap::new();
        for (name, value) in tool_entries {
            if name.is_empty() || name.len() > 96 || name.chars().any(char::is_control) {
                return Err("native tool source is invalid");
            }
            tools.insert(name.clone(), enumeration(value)?);
        }
        Ok(Some(Arc::new(Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
            roles,
            tools,
            checkpoint: pin.resolution_digest_sha256().to_owned(),
        })))
    }
    pub(crate) fn validate(&self, context: &KernelSpawnerContext) -> Result<(), &'static str> {
        if context
            .tunables_pin
            .as_ref()
            .map(TunablesPin::resolution_digest_sha256)
            != Some(self.checkpoint.as_str())
        {
            return Err("native policy checkpoint differs");
        }
        context
            .execution_policy
            .per_agent_model
            .validate_owner(&self.provider, &self.model)?;
        if context.execution_policy.role_specific_models
            != RoleSpecificModelMapIdentity::from_routes(&self.roles)?
        {
            return Err("native role map differs from its checkpoint");
        }
        if context.execution_policy.per_agent_tool_profile
            != PerAgentToolProfileIdentity::from_labels(&self.tools)?
        {
            return Err("native tool profile differs from its checkpoint");
        }
        // Every recorded role still names its exact admitted definition. Current route choice is
        // checked separately against actually retained Provider objects by the native route owner.
        for (role, route) in &self.roles {
            let definition = context
                .agent_catalog
                .get(role)
                .ok_or("native role is absent from the admitted catalog")?;
            let (_, model) = route
                .split_once(':')
                .ok_or("native role route is invalid")?;
            if definition.model.as_deref() != Some(model) {
                return Err("native role definition differs from its source");
            }
        }
        Ok(())
    }
    pub(crate) fn validate_selected(
        &self,
        name: &str,
        model: Option<&str>,
        route: &iteron_protocol::PricingRoute,
    ) -> Result<(), &'static str> {
        if model.is_some()
            && self.roles.get(name).map(String::as_str)
                != Some(format!("{}:{}", route.provider_id, route.model_id).as_str())
        {
            return Err("native role route differs from its admitted qualified identity");
        }
        Ok(())
    }
    pub(crate) fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }
}
