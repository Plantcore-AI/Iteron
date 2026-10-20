//! Explicit operator consent for particular MCP tools to consume untrusted context.
//!
//! This does NOT certify an MCP server as read-only. Operators must independently constrain the
//! server (for example, an audited read-only data connector with fixed destinations and scope).
//! Tool names remain IrreversibleExternal; plan mode, capability ceilings, explicit denies and
//! normal approval rules still apply. Descriptions, schemas and results stay Untrusted.
//! A project, plugin, model, README or MCP annotation cannot provide this authority.

use super::McpServerConfig;

impl McpServerConfig {
    pub(crate) fn validate_context_egress(&self) -> Result<(), String> {
        if self.context_egress_tools.is_empty() {
            return Ok(());
        }
        if self.origin.label() != "operator"
            || self.name == "plantcore-run-gateway"
            || self.context_egress_tools.len() > 16
        {
            return Err("context_egress_tools requires an ordinary operator-owned MCP server and at most 16 exact names".into());
        }
        let names = iteron_mcp::McpToolFilter {
            allow: self.context_egress_tools.clone(),
            deny: Vec::new(),
        };
        names
            .validate()
            .map_err(|_| "context_egress_tools requires unique exact bare tool names".to_owned())?;
        let unique: std::collections::BTreeSet<_> = self.context_egress_tools.iter().collect();
        if unique.len() != self.context_egress_tools.len()
            || self
                .context_egress_tools
                .iter()
                .any(|name| !self.tools.allow.contains(name) || self.tools.deny.contains(name))
        {
            return Err(
                "context_egress_tools must be a unique subset of tools.allow, with no denied names"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> McpServerConfig {
        serde_json::from_value(json!({
            "name": "sample", "command": "/bin/false",
            "tools": {"allow": ["read"]}, "context_egress_tools": ["read"]
        }))
        .unwrap()
    }

    #[test]
    fn scoped_context_egress_is_explicit_finite_and_checkpoint_bound() {
        let granted = config();
        granted.validate_context_egress().unwrap();
        let mut plain = granted.clone();
        plain.context_egress_tools.clear();
        assert_ne!(
            plain.runtime_binding_id().unwrap(),
            granted.runtime_binding_id().unwrap()
        );
        for names in [vec!["*"], vec!["other"], vec!["read", "read"]] {
            let mut invalid = config();
            invalid.context_egress_tools = names.into_iter().map(str::to_owned).collect();
            assert!(invalid.validate_context_egress().is_err());
        }
        let mut denied = config();
        denied.tools.deny.push("read".into());
        assert!(denied.validate_context_egress().is_err());
        let mut unlimited = config();
        unlimited.tools.allow.clear();
        assert!(unlimited.validate_context_egress().is_err());
        let mut managed = config();
        managed.name = "plantcore-run-gateway".into();
        assert!(managed.validate_context_egress().is_err());
    }
}
