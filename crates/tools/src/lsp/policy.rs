use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_LSP_POOL_SERVERS: usize = 8;
pub const MAX_LSP_ROUTES: usize = 64;
pub const MAX_LSP_ARGUMENTS: usize = 128;
pub const MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS: u64 = 120_000;
pub const MAX_LSP_RESTARTS: u32 = 8;
pub const MAX_LSP_BACKOFF_MILLISECONDS: u64 = 60_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LspLanguageRoute {
    pub language_id: String,
    pub server_id: String,
    pub executable: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub workspace_markers: Vec<String>,
}

impl LspLanguageRoute {
    pub(crate) fn command(&self) -> String {
        std::iter::once(&self.executable)
            .chain(self.arguments.iter())
            .map(|part| format!("'{}'", part.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LspRecoveryPolicy {
    pub request_timeout_milliseconds: u64,
    pub max_restarts: u32,
    pub backoff_base_milliseconds: u64,
    pub backoff_cap_milliseconds: u64,
}

impl LspRecoveryPolicy {
    pub fn validate(self) -> Result<Self, LspPolicyError> {
        if !(1..=MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS).contains(&self.request_timeout_milliseconds)
        {
            return Err(LspPolicyError::RequestTimeout);
        }
        if self.max_restarts > MAX_LSP_RESTARTS {
            return Err(LspPolicyError::RestartCount);
        }
        if self.backoff_base_milliseconds > MAX_LSP_BACKOFF_MILLISECONDS
            || self.backoff_cap_milliseconds > MAX_LSP_BACKOFF_MILLISECONDS
        {
            return Err(LspPolicyError::RestartBackoff);
        }
        if self.backoff_base_milliseconds > self.backoff_cap_milliseconds {
            return Err(LspPolicyError::RestartBackoffOrder);
        }
        Ok(self)
    }

    pub(crate) fn delay_for(self, attempt: u32) -> u64 {
        let steps = attempt.saturating_sub(1).min(32);
        self.backoff_base_milliseconds
            .saturating_mul(1_u64 << steps)
            .min(self.backoff_cap_milliseconds)
    }
}

impl Default for LspRecoveryPolicy {
    fn default() -> Self {
        Self {
            request_timeout_milliseconds: 30_000,
            max_restarts: 3,
            backoff_base_milliseconds: 250,
            backoff_cap_milliseconds: 10_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LspRuntimePolicy {
    pub routes: Vec<LspLanguageRoute>,
    pub recovery: LspRecoveryPolicy,
}

impl LspRuntimePolicy {
    pub fn new(
        routes: Vec<LspLanguageRoute>,
        recovery: LspRecoveryPolicy,
    ) -> Result<Self, LspPolicyError> {
        if routes.is_empty() || routes.len() > MAX_LSP_ROUTES {
            return Err(LspPolicyError::RouteCount);
        }
        let mut languages = BTreeSet::new();
        for route in &routes {
            validate_route(route)?;
            if !languages.insert(route.language_id.as_str()) {
                return Err(LspPolicyError::DuplicateLanguage);
            }
        }
        Ok(Self {
            routes,
            recovery: recovery.validate()?,
        })
    }

    pub(crate) fn by_language(&self) -> BTreeMap<String, LspLanguageRoute> {
        self.routes
            .iter()
            .cloned()
            .map(|route| (route.language_id.clone(), route))
            .collect()
    }

    pub(crate) fn with_command_overrides(
        configured: Vec<super::LanguageServerRoute>,
    ) -> Result<Self, LspPolicyError> {
        let mut routes = Self::default().by_language();
        for configured in configured {
            if configured.command.is_empty() || configured.command.len() > MAX_LSP_ARGUMENTS {
                return Err(LspPolicyError::Arguments);
            }
            let mut command = configured.command.into_iter();
            let executable = command.next().ok_or(LspPolicyError::Arguments)?;
            let language_id = configured.language;
            let route = LspLanguageRoute {
                server_id: format!("plugin:{language_id}"),
                language_id: language_id.clone(),
                executable,
                arguments: command.collect(),
                workspace_markers: Vec::new(),
            };
            validate_route(&route)?;
            let Some(previous) = routes.insert(language_id, route) else {
                return Err(LspPolicyError::UnsupportedLanguage);
            };
            if previous.server_id.starts_with("plugin:") {
                return Err(LspPolicyError::DuplicateLanguage);
            }
        }
        Self::new(routes.into_values().collect(), LspRecoveryPolicy::default())
    }
}

impl Default for LspRuntimePolicy {
    fn default() -> Self {
        let route = |language_id: &str, server_id: &str, executable: &str, arguments: &[&str]| {
            LspLanguageRoute {
                language_id: language_id.into(),
                server_id: server_id.into(),
                executable: executable.into(),
                arguments: arguments.iter().map(|value| (*value).into()).collect(),
                workspace_markers: Vec::new(),
            }
        };
        Self::new(
            vec![
                route("rust", "core:rust-analyzer", "rust-analyzer", &[]),
                route(
                    "typescript",
                    "core:typescript-language-server",
                    "typescript-language-server",
                    &["--stdio"],
                ),
                route(
                    "typescriptreact",
                    "core:typescript-language-server",
                    "typescript-language-server",
                    &["--stdio"],
                ),
                route(
                    "javascript",
                    "core:typescript-language-server",
                    "typescript-language-server",
                    &["--stdio"],
                ),
                route(
                    "javascriptreact",
                    "core:typescript-language-server",
                    "typescript-language-server",
                    &["--stdio"],
                ),
                route("python", "core:pyright", "pyright-langserver", &["--stdio"]),
            ],
            LspRecoveryPolicy::default(),
        )
        .expect("the built-in LSP policy must satisfy its hard ceilings")
    }
}

fn validate_route(route: &LspLanguageRoute) -> Result<(), LspPolicyError> {
    const LANGUAGES: [&str; 6] = [
        "rust",
        "typescript",
        "typescriptreact",
        "javascript",
        "javascriptreact",
        "python",
    ];
    if !LANGUAGES.contains(&route.language_id.as_str()) {
        return Err(LspPolicyError::UnsupportedLanguage);
    }
    if !valid_identifier(&route.server_id, true) {
        return Err(LspPolicyError::ServerId);
    }
    if !valid_part(&route.executable)
        || route.arguments.len() > MAX_LSP_ARGUMENTS
        || route.arguments.iter().any(|part| !valid_part(part))
    {
        return Err(LspPolicyError::Arguments);
    }
    if route.workspace_markers.len() > 128
        || route.workspace_markers.iter().any(|marker| {
            !valid_part(marker)
                || marker.starts_with('/')
                || marker.split('/').any(|component| component == "..")
        })
    {
        return Err(LspPolicyError::WorkspaceMarkers);
    }
    Ok(())
}

fn valid_part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, namespaced: bool) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && (!namespaced || value.contains(':'))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LspPolicyError {
    #[error("LSP policy must contain 1..={MAX_LSP_ROUTES} typed routes")]
    RouteCount,
    #[error("LSP language route is not supported by the source adapter")]
    UnsupportedLanguage,
    #[error("LSP policy contains a duplicate language route")]
    DuplicateLanguage,
    #[error("LSP server_id must be a bounded namespaced identifier")]
    ServerId,
    #[error("LSP executable/arguments are empty, unsafe, or exceed their fixed bounds")]
    Arguments,
    #[error("LSP workspace markers are unsafe or exceed their fixed bounds")]
    WorkspaceMarkers,
    #[error("LSP request timeout must be within 1..={MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS}ms")]
    RequestTimeout,
    #[error("LSP restart count exceeds the fixed {MAX_LSP_RESTARTS}-restart ceiling")]
    RestartCount,
    #[error("LSP restart backoff exceeds the fixed {MAX_LSP_BACKOFF_MILLISECONDS}ms ceiling")]
    RestartBackoff,
    #[error("LSP restart backoff base exceeds its cap")]
    RestartBackoffOrder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_typed_unique_and_bounded() {
        let policy = LspRuntimePolicy::default();
        assert_eq!(policy.routes.len(), 6);
        assert!(policy.routes.len() <= MAX_LSP_ROUTES);
        assert!(LspRuntimePolicy::new(policy.routes, policy.recovery).is_ok());
    }

    #[test]
    fn recovery_rejects_unbounded_restart_or_timeout() {
        assert!(matches!(
            LspRecoveryPolicy {
                request_timeout_milliseconds: MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS + 1,
                ..LspRecoveryPolicy::default()
            }
            .validate(),
            Err(LspPolicyError::RequestTimeout)
        ));
    }
}
