//! Version-neutral decoder for the MCP lifecycle families owned by the session runtime.
//!
//! Fresh and resumed sessions both arrive here through [`EffectiveTunablesView`]. No MCP
//! connection is allowed to start until this projection succeeds, which prevents reconnect,
//! deadline, and result-spill behavior from falling back to process-local defaults on resume.

use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use iteron_mcp::{
    McpDeadlinePolicy, McpResultPolicy, McpSpillCleanup, McpTransportDeadlines,
    reconnect::ReconnectPolicy,
};
use iteron_tunables::{ResolutionValue, RuntimeGetterId};
use std::collections::{BTreeMap, BTreeSet};

use crate::config::{
    McpServerBindingId, McpServerConfig, McpServerOrigin, McpTransportConfig, PluginMcpBindingId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpDiscoveryMode {
    Disabled,
    Lazy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpCapabilityExposure {
    pub resource_discovery: McpDiscoveryMode,
    pub prompt_discovery: McpDiscoveryMode,
    pub resource_tool_ids: BTreeSet<String>,
    pub prompt_tool_ids: BTreeSet<String>,
    /// Exact verified plugin/version/server bindings. Operator-owned servers are intentionally
    /// absent; a resumed checkpoint therefore detects both plugin disappearance and an operator
    /// server being silently substituted under the same server name.
    pub plugin_binding_ids: BTreeSet<PluginMcpBindingId>,
    /// Exact content-free binding for every configured server slot. A legacy checkpoint has an
    /// empty set and is handled conservatively by `McpRuntimeControl::configure`.
    pub server_binding_ids: BTreeSet<McpServerBindingId>,
    pub max_visible_bytes: usize,
}

impl McpCapabilityExposure {
    pub(crate) fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        view.with_getter(RuntimeGetterId::EffectiveMcp, || Self::decode_inner(view))
    }

    fn decode_inner(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        let family = "resource_prompt_plugin_capability_exposure";
        let values = view.object(family)?;
        Self::decode_fields(values)
    }

    fn decode_fields(
        values: &BTreeMap<String, ResolutionValue>,
    ) -> Result<Self, EffectiveMcpError> {
        let family = "resource_prompt_plugin_capability_exposure";
        let resource_discovery = discovery_mode(values, family, "resource_discovery")?;
        let prompt_discovery = discovery_mode(values, family, "prompt_discovery")?;
        let resource_tool_ids = identifier_set(values, family, "resource_tool_ids")?;
        let prompt_tool_ids = identifier_set(values, family, "prompt_tool_ids")?;
        // V2 run checkpoints sealed before the value-v2 family existed carry the valid five-field
        // value-v1 object. Absence maps only to the legacy empty plugin set. New resolution still
        // requires the sixth field in the canonical schema; the immutable checkpoint digest
        // prevents an existing value from being stripped in place. The live configure preflight
        // then rejects this empty legacy set if any registered server is plugin-owned.
        let plugin_binding_ids = if values.contains_key("plugin_binding_ids") {
            identifier_set(values, family, "plugin_binding_ids")?
                .into_iter()
                .map(|value| {
                    PluginMcpBindingId::parse(&value).map_err(|reason| {
                        EffectiveMcpError::InvalidOwner {
                            family,
                            reason: reason.into(),
                        }
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?
        } else {
            BTreeSet::new()
        };
        let server_binding_ids = if values.contains_key("server_binding_ids") {
            identifier_set(values, family, "server_binding_ids")?
                .into_iter()
                .map(|value| {
                    McpServerBindingId::parse(&value).map_err(|reason| {
                        EffectiveMcpError::InvalidOwner {
                            family,
                            reason: reason.into(),
                        }
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?
        } else {
            BTreeSet::new()
        };
        let max_visible_bytes = usizev(field(values, family, "max_visible_bytes")?, family)?;
        if (resource_discovery == McpDiscoveryMode::Disabled && !resource_tool_ids.is_empty())
            || (resource_discovery == McpDiscoveryMode::Lazy && resource_tool_ids.is_empty())
            || (prompt_discovery == McpDiscoveryMode::Disabled && !prompt_tool_ids.is_empty())
            || (prompt_discovery == McpDiscoveryMode::Lazy && prompt_tool_ids.is_empty())
            || (resource_discovery == McpDiscoveryMode::Disabled
                && prompt_discovery == McpDiscoveryMode::Disabled
                && max_visible_bytes != 0)
            || ((resource_discovery == McpDiscoveryMode::Lazy
                || prompt_discovery == McpDiscoveryMode::Lazy)
                && max_visible_bytes == 0)
        {
            return Err(EffectiveMcpError::InvalidOwner {
                family,
                reason: "discovery mode, exposed IDs, and visible-byte bound disagree".into(),
            });
        }
        Ok(Self {
            resource_discovery,
            prompt_discovery,
            resource_tool_ids,
            prompt_tool_ids,
            plugin_binding_ids,
            server_binding_ids,
            max_visible_bytes,
        })
    }

    pub(crate) fn allows(&self, tool_id: &str, method: &str) -> bool {
        match method {
            "resources/list" | "resources/read" => {
                self.resource_discovery == McpDiscoveryMode::Lazy
                    && self.resource_tool_ids.contains(tool_id)
            }
            "prompts/list" | "prompts/get" => {
                self.prompt_discovery == McpDiscoveryMode::Lazy
                    && self.prompt_tool_ids.contains(tool_id)
            }
            _ => false,
        }
    }

    /// Fail-closed identity preflight shared by every MCP serving seam. A plugin route must match
    /// the exact plugin id, version, and server slot captured in the checkpoint; an operator route
    /// is admitted only when the checkpoint does not attribute that slot to any plugin.
    pub(crate) fn allows_server(
        &self,
        server_name: &str,
        origin: &McpServerOrigin,
        binding: &McpServerBindingId,
    ) -> bool {
        let exact_server = if self.server_binding_ids.is_empty() {
            // Legacy value-v1/v2 compatibility is admitted only by the configure-time single
            // operator/no-OAuth proof. A new checkpoint always carries this exact identity.
            true
        } else {
            self.server_binding_ids.contains(binding)
                && self
                    .server_binding_ids
                    .iter()
                    .filter(|candidate| candidate.owns_server(server_name))
                    .count()
                    == 1
        };
        exact_server
            && match origin.plugin_binding_id(server_name) {
                Ok(Some(binding)) => self.plugin_binding_ids.contains(&binding),
                Ok(None) => !self
                    .plugin_binding_ids
                    .iter()
                    .any(|binding| binding.owns_server(server_name)),
                Err(_) => false,
            }
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.resource_discovery == McpDiscoveryMode::Disabled
            && self.prompt_discovery == McpDiscoveryMode::Disabled
            && self.resource_tool_ids.is_empty()
            && self.prompt_tool_ids.is_empty()
            && self.plugin_binding_ids.is_empty()
            && self.server_binding_ids.is_empty()
            && self.max_visible_bytes == 0
    }
}

#[cfg(test)]
mod capability_exposure_tests {
    use super::*;

    #[test]
    fn legacy_value_v1_operator_only_exposure_decodes_to_an_empty_plugin_set() {
        let fields = BTreeMap::from([
            (
                "resource_discovery".into(),
                ResolutionValue::Enum {
                    value: "lazy".into(),
                },
            ),
            (
                "prompt_discovery".into(),
                ResolutionValue::Enum {
                    value: "lazy".into(),
                },
            ),
            (
                "resource_tool_ids".into(),
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "alpha__resources_list".into(),
                    }],
                },
            ),
            (
                "prompt_tool_ids".into(),
                ResolutionValue::List {
                    items: vec![ResolutionValue::Text {
                        value: "alpha__prompts_list".into(),
                    }],
                },
            ),
            (
                "max_visible_bytes".into(),
                ResolutionValue::Integer { value: 128 },
            ),
        ]);
        let decoded = McpCapabilityExposure::decode_fields(&fields).unwrap();
        assert!(decoded.plugin_binding_ids.is_empty());
        assert!(decoded.server_binding_ids.is_empty());
        assert_eq!(decoded.max_visible_bytes, 128);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct McpTransportSelection {
    stdio: bool,
    http: bool,
}

impl McpTransportSelection {
    #[cfg(test)]
    pub(crate) const fn stdio_fixture() -> Self {
        Self {
            stdio: true,
            http: false,
        }
    }

    fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        let family = "mcp_transport_selection";
        let Some(value) = view.optional_value(family) else {
            return Ok(Self {
                stdio: false,
                http: false,
            });
        };
        let ResolutionValue::List { items } = value else {
            return Err(EffectiveMcpError::View(EffectiveViewError::WrongType {
                family: family.into(),
                expected: "list",
            }));
        };
        let mut selection = Self {
            stdio: false,
            http: false,
        };
        for item in items {
            let ResolutionValue::Enum { value } = item else {
                return Err(EffectiveMcpError::InvalidOwner {
                    family,
                    reason: "transport entries must be enums".into(),
                });
            };
            let slot = match value.as_str() {
                "stdio" => &mut selection.stdio,
                "http" => &mut selection.http,
                _ => {
                    return Err(EffectiveMcpError::InvalidOwner {
                        family,
                        reason: format!("unknown MCP transport `{value}`"),
                    });
                }
            };
            if *slot {
                return Err(EffectiveMcpError::InvalidOwner {
                    family,
                    reason: format!("duplicate MCP transport `{value}`"),
                });
            }
            *slot = true;
        }
        if items.is_empty() {
            return Err(EffectiveMcpError::InvalidOwner {
                family,
                reason: "an effective transport selection cannot be empty".into(),
            });
        }
        Ok(selection)
    }

    pub(crate) const fn is_disabled(self) -> bool {
        !self.stdio && !self.http
    }

    pub(crate) fn from_servers(servers: &[McpServerConfig]) -> Self {
        Self {
            stdio: servers
                .iter()
                .any(|server| server.transport == McpTransportConfig::Stdio),
            http: servers
                .iter()
                .any(|server| server.transport == McpTransportConfig::Http),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpOAuthCredentialMode {
    Disabled,
    Bearer,
    RefreshToken,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct McpOAuthLifecyclePolicy {
    mode: McpOAuthCredentialMode,
    binding_count: u16,
    refresh_binding_count: u16,
    revocation_binding_count: u16,
    refresh_before_expiry_when_capable: bool,
    retry_once_after_unauthorized_when_capable: bool,
    revoke_access_after_forbidden: bool,
    expiry_skew_seconds: u16,
    revocation_endpoint_configured: bool,
}

impl McpOAuthLifecyclePolicy {
    fn disabled() -> Self {
        Self {
            mode: McpOAuthCredentialMode::Disabled,
            binding_count: 0,
            refresh_binding_count: 0,
            revocation_binding_count: 0,
            refresh_before_expiry_when_capable: false,
            retry_once_after_unauthorized_when_capable: false,
            revoke_access_after_forbidden: true,
            expiry_skew_seconds: iteron_mcp::token::EXPIRY_SKEW_SECS as u16,
            revocation_endpoint_configured: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn disabled_fixture() -> Self {
        Self::disabled()
    }

    fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        let family = "oauth_auth_lifecycle_policy";
        let Some(value) = view.optional_value(family) else {
            return Ok(Self::disabled());
        };
        let ResolutionValue::Object { fields } = value else {
            return Err(EffectiveMcpError::View(EffectiveViewError::WrongType {
                family: family.into(),
                expected: "object",
            }));
        };
        let mode = match text_field(fields, family, "credential_mode")? {
            "disabled" => McpOAuthCredentialMode::Disabled,
            "bearer" => McpOAuthCredentialMode::Bearer,
            "refresh_token" => McpOAuthCredentialMode::RefreshToken,
            "mixed" => McpOAuthCredentialMode::Mixed,
            other => {
                return Err(EffectiveMcpError::InvalidOwner {
                    family,
                    reason: format!("unknown OAuth credential mode `{other}`"),
                });
            }
        };
        let policy = Self {
            mode,
            binding_count: u16v(field(fields, family, "binding_count")?, family)?,
            refresh_binding_count: u16v(field(fields, family, "refresh_binding_count")?, family)?,
            revocation_binding_count: u16v(
                field(fields, family, "revocation_binding_count")?,
                family,
            )?,
            refresh_before_expiry_when_capable: bool_field(
                fields,
                family,
                "refresh_before_expiry_when_capable",
            )?,
            retry_once_after_unauthorized_when_capable: bool_field(
                fields,
                family,
                "retry_once_after_unauthorized_when_capable",
            )?,
            revoke_access_after_forbidden: bool_field(
                fields,
                family,
                "revoke_access_after_forbidden",
            )?,
            expiry_skew_seconds: u16v(field(fields, family, "expiry_skew_seconds")?, family)?,
            revocation_endpoint_configured: bool_field(
                fields,
                family,
                "revocation_endpoint_configured",
            )?,
        };
        if policy.binding_count == 0
            || policy.refresh_binding_count > policy.binding_count
            || policy.revocation_binding_count > policy.refresh_binding_count
            || policy
                != Self::from_counts(
                    policy.binding_count,
                    policy.refresh_binding_count,
                    policy.revocation_binding_count,
                )
        {
            return Err(EffectiveMcpError::InvalidOwner {
                family,
                reason: "OAuth mode/count/lifecycle controls disagree with the production owner"
                    .into(),
            });
        }
        Ok(policy)
    }

    fn from_counts(binding_count: u16, refresh_count: u16, revocation_count: u16) -> Self {
        let mode = match (binding_count, refresh_count) {
            (0, 0) => McpOAuthCredentialMode::Disabled,
            (_, 0) => McpOAuthCredentialMode::Bearer,
            (total, refresh) if total == refresh => McpOAuthCredentialMode::RefreshToken,
            _ => McpOAuthCredentialMode::Mixed,
        };
        Self {
            mode,
            binding_count,
            refresh_binding_count: refresh_count,
            revocation_binding_count: revocation_count,
            refresh_before_expiry_when_capable: refresh_count > 0,
            retry_once_after_unauthorized_when_capable: refresh_count > 0,
            revoke_access_after_forbidden: true,
            expiry_skew_seconds: iteron_mcp::token::EXPIRY_SKEW_SECS as u16,
            revocation_endpoint_configured: revocation_count > 0,
        }
    }

    pub(crate) fn from_servers(servers: &[McpServerConfig]) -> Result<Self, EffectiveMcpError> {
        let oauth = servers
            .iter()
            .filter_map(|server| server.oauth.as_ref())
            .collect::<Vec<_>>();
        let refresh = oauth
            .iter()
            .filter(|config| config.refresh_url.is_some() && config.refresh_token_env.is_some())
            .count();
        let revocation = oauth
            .iter()
            .filter(|config| {
                config.refresh_url.is_some()
                    && config.refresh_token_env.is_some()
                    && config.revoke_url.is_some()
            })
            .count();
        Ok(Self::from_counts(
            u16::try_from(oauth.len()).map_err(|_| EffectiveMcpError::Range {
                family: "oauth_auth_lifecycle_policy",
            })?,
            u16::try_from(refresh).map_err(|_| EffectiveMcpError::Range {
                family: "oauth_auth_lifecycle_policy",
            })?,
            u16::try_from(revocation).map_err(|_| EffectiveMcpError::Range {
                family: "oauth_auth_lifecycle_policy",
            })?,
        ))
    }

    pub(crate) const fn is_disabled(self) -> bool {
        matches!(self.mode, McpOAuthCredentialMode::Disabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveMcpSettings {
    pub transport: McpTransportSelection,
    pub oauth: McpOAuthLifecyclePolicy,
    pub reconnect: ReconnectPolicy,
    pub deadlines: McpDeadlinePolicy,
    pub result: McpResultPolicy,
}

impl EffectiveMcpSettings {
    #[cfg(test)]
    pub(crate) fn with_live_bindings_for_test(
        mut self,
        servers: &[McpServerConfig],
    ) -> Result<Self, EffectiveMcpError> {
        self.transport = McpTransportSelection::from_servers(servers);
        self.oauth = McpOAuthLifecyclePolicy::from_servers(servers)?;
        Ok(self)
    }

    pub(crate) fn decode(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        view.with_getter(RuntimeGetterId::EffectiveMcp, || Self::decode_inner(view))
    }

    pub(crate) const fn is_disabled(self) -> bool {
        self.transport.is_disabled() && self.oauth.is_disabled()
    }

    fn decode_inner(view: &EffectiveTunablesView) -> Result<Self, EffectiveMcpError> {
        let transport = McpTransportSelection::decode(view)?;
        let oauth = McpOAuthLifecyclePolicy::decode(view)?;
        let reconnect = view.object("mcp_reconnect_backoff")?;
        let reconnect = ReconnectPolicy::new(
            u32v(
                field(reconnect, "mcp_reconnect_backoff", "max_attempts")?,
                "mcp_reconnect_backoff",
            )?,
            u64v(
                field(reconnect, "mcp_reconnect_backoff", "base_milliseconds")?,
                "mcp_reconnect_backoff",
            )?,
            u64v(
                field(reconnect, "mcp_reconnect_backoff", "cap_milliseconds")?,
                "mcp_reconnect_backoff",
            )?,
        )
        .map_err(|error| invalid("mcp_reconnect_backoff", error))?;

        let startup = view.object("per_server_startup_deadline")?;
        let tool = view.object("per_tool_mcp_deadline")?;
        let stdio = McpTransportDeadlines::new(
            u64v(
                field(startup, "per_server_startup_deadline", "stdio_milliseconds")?,
                "per_server_startup_deadline",
            )?,
            u64v(
                field(tool, "per_tool_mcp_deadline", "stdio_milliseconds")?,
                "per_tool_mcp_deadline",
            )?,
        )
        .map_err(|reason| EffectiveMcpError::InvalidOwner {
            family: "per_server_startup_deadline/per_tool_mcp_deadline",
            reason: reason.into(),
        })?;
        let http = McpTransportDeadlines::new(
            u64v(
                field(startup, "per_server_startup_deadline", "http_milliseconds")?,
                "per_server_startup_deadline",
            )?,
            u64v(
                field(tool, "per_tool_mcp_deadline", "http_milliseconds")?,
                "per_tool_mcp_deadline",
            )?,
        )
        .map_err(|reason| EffectiveMcpError::InvalidOwner {
            family: "per_server_startup_deadline/per_tool_mcp_deadline",
            reason: reason.into(),
        })?;

        let result = view.object("mcp_result_cap_spill_policy")?;
        if !bool_field(result, "mcp_result_cap_spill_policy", "private_storage")? {
            return Err(EffectiveMcpError::InvalidOwner {
                family: "mcp_result_cap_spill_policy",
                reason: "MCP overflow storage cannot be made public".into(),
            });
        }
        let cleanup = match text_field(result, "mcp_result_cap_spill_policy", "cleanup")? {
            "tool_end" => McpSpillCleanup::ToolEnd,
            "turn_end" => McpSpillCleanup::TurnEnd,
            "run_end" => McpSpillCleanup::RunEnd,
            "session_end" => McpSpillCleanup::SessionEnd,
            other => {
                return Err(EffectiveMcpError::UnsupportedCleanup(other.to_owned()));
            }
        };
        let result = McpResultPolicy::new(
            usizev(
                field(result, "mcp_result_cap_spill_policy", "visible_max_bytes")?,
                "mcp_result_cap_spill_policy",
            )?,
            usizev(
                field(result, "mcp_result_cap_spill_policy", "spill_max_bytes")?,
                "mcp_result_cap_spill_policy",
            )?,
            cleanup,
        )
        .map_err(|error| invalid("mcp_result_cap_spill_policy", error))?;

        Ok(Self {
            transport,
            oauth,
            reconnect,
            deadlines: McpDeadlinePolicy::new(stdio, http),
            result,
        })
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    fn object(
        fields: impl IntoIterator<Item = (&'static str, ResolutionValue)>,
    ) -> ResolutionValue {
        ResolutionValue::Object {
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        }
    }

    fn int(value: i64) -> ResolutionValue {
        ResolutionValue::Integer { value }
    }

    fn boolv(value: bool) -> ResolutionValue {
        ResolutionValue::Boolean { value }
    }

    fn en(value: &str) -> ResolutionValue {
        ResolutionValue::Enum {
            value: value.to_owned(),
        }
    }

    fn effective_values() -> BTreeMap<String, ResolutionValue> {
        BTreeMap::from([
            (
                "mcp_transport_selection".into(),
                ResolutionValue::List {
                    items: vec![en("http")],
                },
            ),
            (
                "oauth_auth_lifecycle_policy".into(),
                object([
                    ("credential_mode", en("refresh_token")),
                    ("binding_count", int(1)),
                    ("refresh_binding_count", int(1)),
                    ("revocation_binding_count", int(1)),
                    ("refresh_before_expiry_when_capable", boolv(true)),
                    ("retry_once_after_unauthorized_when_capable", boolv(true)),
                    ("revoke_access_after_forbidden", boolv(true)),
                    (
                        "expiry_skew_seconds",
                        int(iteron_mcp::token::EXPIRY_SKEW_SECS as i64),
                    ),
                    ("revocation_endpoint_configured", boolv(true)),
                ]),
            ),
            (
                "mcp_reconnect_backoff".into(),
                object([
                    ("max_attempts", int(1)),
                    ("base_milliseconds", int(1)),
                    ("cap_milliseconds", int(1)),
                ]),
            ),
            (
                "per_server_startup_deadline".into(),
                object([
                    ("stdio_milliseconds", int(1)),
                    ("http_milliseconds", int(1)),
                ]),
            ),
            (
                "per_tool_mcp_deadline".into(),
                object([
                    ("stdio_milliseconds", int(1)),
                    ("http_milliseconds", int(1)),
                ]),
            ),
            (
                "mcp_result_cap_spill_policy".into(),
                object([
                    ("visible_max_bytes", int(128)),
                    ("spill_max_bytes", int(4096)),
                    ("cleanup", en("session_end")),
                    ("private_storage", boolv(true)),
                ]),
            ),
        ])
    }

    #[test]
    fn transport_and_oauth_are_decoded_from_effective_checkpoint_values() {
        let view = EffectiveTunablesView::from_test_values(effective_values());
        let decoded = EffectiveMcpSettings::decode(&view).unwrap();
        assert_eq!(
            decoded.transport,
            McpTransportSelection {
                stdio: false,
                http: true
            }
        );
        assert_eq!(decoded.oauth.mode, McpOAuthCredentialMode::RefreshToken);
        assert_eq!(decoded.oauth.binding_count, 1);
        assert_eq!(decoded.oauth.revocation_binding_count, 1);
    }

    #[test]
    fn contradictory_oauth_lifecycle_never_reaches_runtime_installation() {
        let mut values = effective_values();
        let ResolutionValue::Object { fields } = values
            .get_mut("oauth_auth_lifecycle_policy")
            .expect("fixture")
        else {
            unreachable!()
        };
        fields.insert(
            "retry_once_after_unauthorized_when_capable".into(),
            boolv(false),
        );
        let view = EffectiveTunablesView::from_test_values(values);
        assert!(EffectiveMcpSettings::decode(&view).is_err());
    }
}

fn field(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<i64, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Integer { value }) => Ok(*value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn bool_field(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<bool, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Boolean { value }) => Ok(*value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn text_field<'a>(
    values: &'a BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<&'a str, EffectiveMcpError> {
    match values.get(field) {
        Some(ResolutionValue::Enum { value } | ResolutionValue::Text { value }) => Ok(value),
        Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
        None => Err(EffectiveMcpError::MissingField { family, field }),
    }
}

fn discovery_mode(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<McpDiscoveryMode, EffectiveMcpError> {
    match text_field(values, family, field)? {
        "disabled" => Ok(McpDiscoveryMode::Disabled),
        "lazy" => Ok(McpDiscoveryMode::Lazy),
        value => Err(EffectiveMcpError::InvalidOwner {
            family,
            reason: format!("unknown {field} mode `{value}`"),
        }),
    }
}

fn identifier_set(
    values: &BTreeMap<String, ResolutionValue>,
    family: &'static str,
    field: &'static str,
) -> Result<BTreeSet<String>, EffectiveMcpError> {
    let Some(ResolutionValue::List { items }) = values.get(field) else {
        return match values.get(field) {
            Some(_) => Err(EffectiveMcpError::WrongFieldType { family, field }),
            None => Err(EffectiveMcpError::MissingField { family, field }),
        };
    };
    let mut result = BTreeSet::new();
    for item in items {
        let ResolutionValue::Text { value } = item else {
            return Err(EffectiveMcpError::WrongFieldType { family, field });
        };
        if !result.insert(value.clone()) {
            return Err(EffectiveMcpError::InvalidOwner {
                family,
                reason: format!("duplicate tool id `{value}`"),
            });
        }
    }
    Ok(result)
}

fn u64v(value: i64, family: &'static str) -> Result<u64, EffectiveMcpError> {
    u64::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn u32v(value: i64, family: &'static str) -> Result<u32, EffectiveMcpError> {
    u32::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn u16v(value: i64, family: &'static str) -> Result<u16, EffectiveMcpError> {
    u16::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn usizev(value: i64, family: &'static str) -> Result<usize, EffectiveMcpError> {
    usize::try_from(value).map_err(|_| EffectiveMcpError::Range { family })
}

fn invalid(family: &'static str, error: iteron_mcp::McpError) -> EffectiveMcpError {
    EffectiveMcpError::InvalidOwner {
        family,
        reason: error.public_summary(),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveMcpError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error("effective MCP tunable `{family}` is outside the runtime type range")]
    Range { family: &'static str },
    #[error("effective MCP tunable `{family}` is missing object field `{field}`")]
    MissingField {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective MCP tunable `{family}` object field `{field}` has the wrong type")]
    WrongFieldType {
        family: &'static str,
        field: &'static str,
    },
    #[error("effective MCP tunable `{family}` violates its production owner: {reason}")]
    InvalidOwner {
        family: &'static str,
        reason: String,
    },
    #[error("MCP spill cleanup `{0}` is not implementable by the current session-owned store")]
    UnsupportedCleanup(String),
}
