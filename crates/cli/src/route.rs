//! The single resolved route, built once at the composition root.
//!
//! `/status`, `/config`, `/model`, the statusline and the startup banner each used to derive the
//! current route independently — from the provider directory, from ad-hoc `App` fields, and (for
//! `/config`) by re-reading the REPOSITORY config file, which is why `core --max-turns 5` reported
//! `max_turns: default` while the kernel enforced 5. Four derivations of one fact are four chances
//! to disagree with the request that actually goes out (I-26).
//!
//! `RouteView` is that fact, captured from the already-resolved values the run dispatches with. It
//! is value-free by construction: the credential is named, never carried, so this type can be
//! rendered into a panel, a statusline, or stderr without a redaction step.

use crate::providers::{ModelSelection, ProviderDirectory};

/// The bounded, effective limits the kernel was actually given.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RouteLimits {
    pub max_turns: u32,
    pub max_usd: Option<f64>,
    pub max_tokens: Option<u64>,
    pub max_wall_secs: u64,
}

impl RouteLimits {
    /// Human rendering that never prints a raw `Option` debug: `None` is a policy statement
    /// ("no ceiling"), not a Rust value an operator should have to read.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        vec![
            ("max_turns", self.max_turns.to_string()),
            (
                "max_usd",
                self.max_usd
                    .map(|value| format!("${value:.2}"))
                    .unwrap_or_else(|| "no ceiling".into()),
            ),
            (
                "max_tokens",
                self.max_tokens
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "no ceiling".into()),
            ),
            ("max_wall_secs", self.max_wall_secs.to_string()),
        ]
    }
}

/// Everything a display may say about the current route, and nothing a display may invent.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RouteView {
    pub provider_id: String,
    pub provider_display_name: String,
    pub model_id: String,
    /// The exact API root the next request is dispatched to, including its version prefix. A BYOK
    /// operator debugging a 401 needs this and the credential name before anything else.
    pub api_root: String,
    pub adapter: String,
    pub error_profile: String,
    /// `env NAME` or `file /path` plus presence/expiry. Never a credential value.
    pub credential: String,
    pub catalog_provenance: String,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
    pub capability_source: Option<String>,
    /// Why this route cannot currently be selected, if the directory says so.
    pub blocked_reason: Option<String>,
    pub limits: RouteLimits,
}

impl RouteView {
    /// The view before a route exists. Used only as the pre-attach value of a frontend's field;
    /// the composition root replaces it with the resolved route before the first frame.
    pub fn unresolved() -> Self {
        Self {
            provider_id: String::new(),
            provider_display_name: String::new(),
            model_id: String::new(),
            api_root: "(unresolved)".into(),
            adapter: "(unresolved)".into(),
            error_profile: "(unresolved)".into(),
            credential: "(unresolved)".into(),
            catalog_provenance: "unavailable".into(),
            context_window_tokens: None,
            max_output_tokens: None,
            capability_source: None,
            blocked_reason: None,
            limits: RouteLimits {
                max_turns: 0,
                max_usd: None,
                max_tokens: None,
                max_wall_secs: 0,
            },
        }
    }

    /// Build the view from the resolved selection the run dispatches with.
    ///
    /// A provider that is not in the directory still produces a view: `--base-url` overrides and
    /// unavailable providers must be *shown*, and a display that silently omits the route is how a
    /// wrong route survives to the first paid request.
    pub fn resolve(
        directory: &ProviderDirectory,
        selection: &ModelSelection,
        limits: RouteLimits,
    ) -> Self {
        let capabilities = directory.selection_capabilities(selection);
        let Some(entry) = directory.entry(&selection.provider_id) else {
            return Self {
                provider_id: selection.provider_id.clone(),
                provider_display_name: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                api_root: "(unresolved)".into(),
                adapter: "(unresolved)".into(),
                error_profile: "(unresolved)".into(),
                credential: "(unresolved)".into(),
                catalog_provenance: "unavailable".into(),
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
                capability_source: capabilities.source.clone(),
                blocked_reason: Some(format!(
                    "provider `{}` is not in this configuration",
                    selection.provider_id
                )),
                limits,
            };
        };
        Self {
            provider_id: selection.provider_id.clone(),
            provider_display_name: entry.display_name().to_owned(),
            model_id: selection.model_id.clone(),
            api_root: entry.instance.api_root().as_str().to_owned(),
            adapter: adapter_label(entry.instance.adapter()).into(),
            error_profile: error_profile_label(entry.instance.error_profile()).into(),
            credential: entry.credential_display(),
            catalog_provenance: entry.catalog_provenance_label(),
            context_window_tokens: capabilities.context_window_tokens,
            max_output_tokens: capabilities.max_output_tokens,
            capability_source: capabilities.source.clone(),
            blocked_reason: directory
                .blocked_reason(entry)
                .or_else(|| directory.model_blocked_reason(&selection.provider_id, &selection.model_id)),
            limits,
        }
    }

    /// Re-resolve for a new `(provider, model)` while keeping the run's effective limits. `/model`
    /// uses this so a picker choice updates every display through the same one construction.
    pub fn reselect(&self, directory: &ProviderDirectory, selection: &ModelSelection) -> Self {
        Self::resolve(directory, selection, self.limits.clone())
    }

    /// `provider/model` for the statusline, with the vendor path prefix trimmed off the model.
    pub fn short_label(&self) -> String {
        if self.model_id.is_empty() {
            return String::new();
        }
        let model = self
            .model_id
            .split(['/', ':'])
            .next_back()
            .unwrap_or(&self.model_id);
        if self.provider_id.is_empty() {
            model.to_string()
        } else {
            format!("{}/{model}", self.provider_id)
        }
    }

    /// The route rows shared by `/status`, `/config` and `core auth status`, in one order.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        let mut rows = vec![
            (
                "provider",
                if self.provider_id.is_empty() {
                    "(unresolved)".to_string()
                } else {
                    format!("{} ({})", self.provider_id, self.provider_display_name)
                },
            ),
            ("model", self.model_id.clone()),
            ("api_root", self.api_root.clone()),
            ("adapter", self.adapter.clone()),
            ("error profile", self.error_profile.clone()),
            ("credential", self.credential.clone()),
            ("catalog", self.catalog_provenance.clone()),
        ];
        if let Some(window) = self.context_window_tokens {
            rows.push(("context window", format!("{window} tokens")));
        }
        if let Some(output) = self.max_output_tokens {
            rows.push(("max output", format!("{output} tokens")));
        }
        if let Some(source) = &self.capability_source {
            rows.push(("capability source", source.clone()));
        }
        if let Some(reason) = &self.blocked_reason {
            rows.push(("blocked", reason.clone()));
        }
        rows
    }
}

fn adapter_label(adapter: core_provider::AdapterKind) -> &'static str {
    match adapter {
        core_provider::AdapterKind::AnthropicMessages => "anthropic_messages",
        core_provider::AdapterKind::OpenAiResponses => "openai_responses",
        core_provider::AdapterKind::OpenAiCompatibleChat => "openai_chat",
    }
}

fn error_profile_label(profile: core_provider::ErrorProfile) -> &'static str {
    match profile {
        core_provider::ErrorProfile::Anthropic => "anthropic",
        core_provider::ErrorProfile::OpenAi => "openai",
        core_provider::ErrorProfile::DeepSeek => "deepseek",
        core_provider::ErrorProfile::Glm => "glm",
        core_provider::ErrorProfile::MiniMax => "minimax",
        core_provider::ErrorProfile::Fireworks => "fireworks",
        core_provider::ErrorProfile::CustomConservative => "custom",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> RouteLimits {
        RouteLimits {
            max_turns: 5,
            max_usd: Some(2.5),
            max_tokens: None,
            max_wall_secs: 1800,
        }
    }

    /// I-26 — `/config` re-read the repository config file instead of the effective layered value,
    /// so `core --max-turns 5` displayed `max_turns: default`. The view carries the limits the
    /// kernel was given, so the displayed ceiling is the enforced ceiling.
    #[test]
    fn i26_the_view_reports_the_effective_limits_not_the_config_file() {
        let rows = limits().rows();
        assert_eq!(rows[0], ("max_turns", "5".to_string()));
        assert_eq!(rows[1], ("max_usd", "$2.50".to_string()));
        assert_eq!(rows[2], ("max_tokens", "no ceiling".to_string()));
        assert!(
            !rows.iter().any(|(_, value)| value.contains("default")
                || value.contains("Some(")
                || value.contains("None")),
            "limits must render as policy, never as a raw Option: {rows:?}"
        );
    }

    /// A failing BYOK operator needs the endpoint and the credential NAME; neither was ever shown
    /// by `/config` or `/status`, and neither may be a credential VALUE.
    #[test]
    fn i26_route_rows_name_the_endpoint_and_the_credential_source_but_no_value() {
        let view = RouteView {
            provider_id: "gateway".into(),
            provider_display_name: "Gateway".into(),
            model_id: "vendor/model-1".into(),
            api_root: "https://gateway.example/v1".into(),
            adapter: "openai_chat".into(),
            error_profile: "custom".into(),
            credential: "env GATEWAY_KEY".into(),
            catalog_provenance: "provider catalog (fresh)".into(),
            context_window_tokens: Some(128_000),
            max_output_tokens: Some(8192),
            capability_source: Some("vendor snapshot".into()),
            blocked_reason: None,
            limits: limits(),
        };
        let rows = view.rows();
        let keys: Vec<&str> = rows.iter().map(|(key, _)| *key).collect();
        assert!(keys.contains(&"api_root"), "{keys:?}");
        assert!(keys.contains(&"credential"), "{keys:?}");
        assert_eq!(
            rows.iter()
                .find(|(key, _)| *key == "api_root")
                .map(|(_, value)| value.as_str()),
            Some("https://gateway.example/v1")
        );
        assert_eq!(view.short_label(), "gateway/model-1");
    }

    /// An unresolvable provider still renders, and says so, instead of vanishing from the panel.
    #[test]
    fn i26_an_unknown_provider_still_produces_a_visible_blocked_route() {
        let view = RouteView {
            provider_id: "cli-override".into(),
            provider_display_name: "cli-override".into(),
            model_id: String::new(),
            api_root: "(unresolved)".into(),
            adapter: "(unresolved)".into(),
            error_profile: "(unresolved)".into(),
            credential: "(unresolved)".into(),
            catalog_provenance: "unavailable".into(),
            context_window_tokens: None,
            max_output_tokens: None,
            capability_source: None,
            blocked_reason: Some("provider `cli-override` is not in this configuration".into()),
            limits: limits(),
        };
        assert!(view.rows().iter().any(|(key, _)| *key == "blocked"));
        assert_eq!(view.short_label(), "");
    }
}
