//! Config layering (production necessity).
//!
//! A cloned repository is input, not an authorization principal. Repository `.core/config.json`
//! may select a bare model within an independently trusted provider and may *tighten* resource
//! ceilings. It cannot grant code execution, raise effort/spend/time ceilings, configure egress,
//! providers, hooks, or MCP processes. Those authorities come only from operator-owned sources.
//!
//! JSON, not TOML, to avoid a dependency (serde_json is already in the tree — zero-dependency
//! first). Every field is optional; a missing file is not an error (defaults apply).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
// `deny_unknown_fields` fails loud on a typo'd key (e.g. `max_turn`) instead of silently ignoring it —
// a silently-dropped budget/security knob is a production footgun.
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// Model default. From a project config, the CLI accepts only a bare id and constrains it to
    /// the independently trusted provider; trusted user config may use provider qualification.
    pub model: Option<String>,
    pub max_turns: Option<u32>,
    pub max_usd: Option<f64>,
    pub max_wall_secs: Option<u64>,
    pub allow_code: Option<bool>,
    /// Egress allowlist for code execution (hosts). Empty/absent = egress off (ADR-007).
    pub egress_allow: Option<Vec<String>>,
    /// Compaction policy. Accepted from trusted user config only; a project value is ignored
    /// because either direction changes paid provider-call timing rather than a monotone ceiling.
    pub compaction_trigger_tokens: Option<usize>,
    /// Session effort. The shared schema accepts it for trusted user config; a repository value is
    /// deliberately ignored because effort changes cost and orchestration authority.
    pub effort: Option<String>,
    /// Default provider instance id. Consumed only from trusted user config; ignored when this
    /// schema was loaded from a repository.
    pub provider: Option<String>,
    /// OpenAI-compatible API root. Consumed only from trusted user config; ignored when this
    /// schema was loaded from a repository.
    pub base_url: Option<String>,
    /// Additional provider instances. Security-sensitive: the CLI consumes these only from the
    /// operator-owned user config, never from a repository config.
    pub providers: Option<Vec<ProviderConfig>>,
    /// MCP servers to connect and expose as tools (each an operator-configured stdio server).
    pub mcp_servers: Option<Vec<McpServerConfig>>,
    /// Lifecycle hooks are consumed by `core_kernel::hooks::Hooks`, but they must also be part
    /// of this strict top-level schema. Without this field, `deny_unknown_fields` rejects the user
    /// config before the dedicated hook loader can read it, making every configured hook brick
    /// startup. Keep the raw command lists here; only the trusted user-config loader executes them.
    pub hooks: Option<BTreeMap<String, Vec<String>>>,
}

/// One MCP server the operator configured. Configuring it is the consent to run its tools;
/// its tool descriptions are still treated as untrusted (scanned) per ADR-007.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One operator-defined provider instance. Credentials remain indirect: Core reads the named
/// environment variable at call time and never persists a plaintext key in configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub display_name: Option<String>,
    /// `anthropic_messages`, `openai_responses`, or `openai_chat`.
    pub adapter: String,
    /// Provider-specific error-code semantics. OpenAI-compatible wire shape does not imply that
    /// numeric business codes mean the same thing across vendors.
    pub error_profile: Option<String>,
    /// Full API root, including the provider's version/path prefix.
    pub api_root: String,
    pub key_env: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Some compatible gateways do not expose `GET models`; keep this explicit.
    #[serde(default = "default_true")]
    pub catalog: bool,
    /// Operator-declared model ids for gateways whose catalog is absent or incomplete. This is a
    /// manifest, not discovery output; the provider composition layer decides how to merge it.
    #[serde(default)]
    pub models: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl FileConfig {
    /// Load `.core/config.json` under `repo`, if present. A malformed file IS an error
    /// (fail loud on a config the operator wrote), but an absent file is fine.
    pub fn load(repo: &Path) -> anyhow::Result<FileConfig> {
        let path = core_protocol::home::path(repo, "config.json");
        let Some(text) = read_bounded_config(&path, false)? else {
            return Ok(FileConfig::default());
        };
        let cfg: FileConfig =
            serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        cfg.validate()
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        Ok(cfg)
    }

    /// Reject nonsensical numeric knobs BEFORE they weaken a budget/bound invariant (a `max_turns:0`
    /// or negative `max_usd` would silently disable the ceiling). Called on every load.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_turns == Some(0) {
            return Err("max_turns must be >= 1 (0 would disable the turn budget)".into());
        }
        if let Some(u) = self.max_usd
            && (!u.is_finite() || u < 0.0)
        {
            return Err(format!(
                "max_usd must be a finite non-negative number, got {u}"
            ));
        }
        if self.max_wall_secs == Some(0) {
            return Err("max_wall_secs must be >= 1".into());
        }
        if self.compaction_trigger_tokens == Some(0) {
            return Err("compaction_trigger_tokens must be >= 1".into());
        }
        if let Some(effort) = self.effort.as_deref()
            && core_protocol::Effort::parse(effort).is_none()
        {
            return Err(format!(
                "effort must be one of low|medium|high|xhigh|max|ultracode, got `{effort}`"
            ));
        }
        if let Some(providers) = &self.providers {
            if providers.len() > 64 {
                return Err("providers exceeds the 64-instance configuration bound".into());
            }
            let mut ids = std::collections::BTreeSet::new();
            for provider in providers {
                let valid_id = !provider.id.is_empty()
                    && provider.id.len() <= 64
                    && provider.id.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_')
                    });
                if !valid_id {
                    return Err(format!(
                        "provider id `{}` must be a lowercase ASCII slug up to 64 bytes",
                        provider.id
                    ));
                }
                if !ids.insert(provider.id.as_str()) {
                    return Err(format!("duplicate provider id `{}`", provider.id));
                }
                if !matches!(
                    provider.adapter.as_str(),
                    "anthropic_messages" | "openai_responses" | "openai_chat"
                ) {
                    return Err(format!(
                        "provider `{}` has unsupported adapter `{}`",
                        provider.id, provider.adapter
                    ));
                }
                if provider.error_profile.as_deref().is_some_and(|profile| {
                    !matches!(
                        profile,
                        "anthropic"
                            | "openai"
                            | "deepseek"
                            | "glm"
                            | "minimax"
                            | "fireworks"
                            | "custom"
                    )
                }) {
                    return Err(format!(
                        "provider `{}` has unsupported error_profile `{}`",
                        provider.id,
                        provider.error_profile.as_deref().unwrap_or_default()
                    ));
                }
                validate_api_root(&provider.id, &provider.api_root)?;
                if provider.key_env.is_empty()
                    || provider.key_env.len() > 128
                    || !provider.key_env.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(format!(
                        "provider `{}` key_env must be an uppercase ASCII environment name",
                        provider.id
                    ));
                }
                if provider
                    .display_name
                    .as_ref()
                    .is_some_and(|name| name.trim().is_empty() || name.len() > 128)
                {
                    return Err(format!(
                        "provider `{}` display_name must be 1..=128 bytes",
                        provider.id
                    ));
                }
                if provider.models.len() > 256 {
                    return Err(format!(
                        "provider `{}` models exceeds the 256-entry manifest bound",
                        provider.id
                    ));
                }
                let mut model_ids = std::collections::BTreeSet::new();
                for model_id in &provider.models {
                    if model_id.trim().is_empty()
                        || model_id.len() > 512
                        || model_id.chars().any(char::is_control)
                    {
                        return Err(format!(
                            "provider `{}` model ids must be non-empty, control-free, and at most 512 bytes",
                            provider.id
                        ));
                    }
                    if !model_ids.insert(model_id.as_str()) {
                        return Err(format!(
                            "provider `{}` has duplicate model id `{model_id}`",
                            provider.id
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Load the USER config `~/.core/config.json` (trust-by-origin). ONLY the user's own config may
    /// declare command-spawning entries — `mcp_servers` spawns a subprocess at startup, so a project/
    /// cloned-repo config must never supply them (else cloning a hostile repo = RCE). Mirrors
    /// `Hooks::load_user`. Absent HOME/file → default; malformed → error (fail loud on your own config).
    pub fn load_user() -> anyhow::Result<FileConfig> {
        let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
            return Ok(FileConfig::default());
        };
        let path = core_protocol::home::path(&home, "config.json");
        let Some(text) = read_bounded_config(&path, true)? else {
            return Ok(FileConfig::default());
        };
        let cfg: FileConfig =
            serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        cfg.validate()
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        Ok(cfg)
    }
}

/// Read configuration through a bounded descriptor. Project configuration is opened with
/// `O_NOFOLLOW` on Unix and is always rejected when the named file is a symlink; otherwise a
/// repository could make config parsing observe an arbitrary machine file. User configuration is
/// operator-owned and may intentionally be a dotfiles symlink, but remains size bounded.
fn read_bounded_config(path: &Path, allow_symlink: bool) -> anyhow::Result<Option<String>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() && !allow_symlink {
        anyhow::bail!("{}: project config must not be a symlink", path.display());
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    if !allow_symlink {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let opened = file.metadata()?;
    if !opened.is_file() {
        anyhow::bail!("{}: config must be a regular file", path.display());
    }
    if opened.len() > MAX_CONFIG_BYTES as u64 {
        anyhow::bail!(
            "{}: config exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_BYTES
        );
    }
    let mut bytes = Vec::with_capacity((opened.len() as usize).min(MAX_CONFIG_BYTES));
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        anyhow::bail!(
            "{}: config exceeds the {} byte limit",
            path.display(),
            MAX_CONFIG_BYTES
        );
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| anyhow::anyhow!("{}: config is not valid UTF-8", path.display()))
}

fn validate_api_root(provider_id: &str, value: &str) -> Result<(), String> {
    if value.len() > 2_048 {
        return Err(format!(
            "provider `{provider_id}` api_root exceeds the 2048-byte bound"
        ));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| format!("provider `{provider_id}` api_root is not a valid absolute URL"))?;
    let is_loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let allowed_transport =
        parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback);
    if !allowed_transport {
        return Err(format!(
            "provider `{provider_id}` api_root must be HTTPS (exact loopback hosts may use HTTP)"
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!(
            "provider `{provider_id}` api_root must not contain credentials, a query, or a fragment"
        ));
    }
    Ok(())
}

/// Read an env override for a field. Env sits above the file, below the flags.
pub fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}
pub fn env_f64(key: &str) -> Option<f64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}
pub fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Resolve one value across the precedence chain: flag > env > file > default.
pub fn pick<T>(flag: Option<T>, env: Option<T>, file: Option<T>, default: T) -> T {
    flag.or(env).or(file).unwrap_or(default)
}

/// Apply an untrusted repository ceiling to a value already resolved from trusted operator
/// sources. A project may request *less* authority/spend/time, never more.
pub fn tighten<T: PartialOrd>(project: Option<T>, trusted: T) -> T {
    match project {
        Some(project) if project < trusted => project,
        _ => trusted,
    }
}

/// Optional ceiling variant: absence means the operator made no monetary guarantee. A project may
/// introduce or lower a ceiling, but can never remove or raise a trusted one.
pub fn tighten_optional<T: PartialOrd>(project: Option<T>, trusted: Option<T>) -> Option<T> {
    match (project, trusted) {
        (Some(project), Some(trusted)) => {
            if project < trusted {
                Some(project)
            } else {
                Some(trusted)
            }
        }
        (Some(project), None) => Some(project),
        (None, trusted) => trusted,
    }
}

/// Apply an untrusted repository restriction to an operator-owned boolean grant. `true` can never
/// mint authority; an explicit project `false` may only remove an existing grant.
pub fn tighten_grant(project: Option<bool>, trusted: bool) -> bool {
    trusted && project.unwrap_or(true)
}

/// Resolve a repository-safe scalar across every implemented configuration layer. Project config
/// intentionally outranks the user's default for this repository, while environment and CLI remain
/// explicit runtime overrides.
pub fn pick_run_setting<T>(
    flag: Option<T>,
    env: Option<T>,
    project: Option<T>,
    user: Option<T>,
    default: T,
) -> T {
    flag.or(env).or(project).or(user).unwrap_or(default)
}

/// Origin of a provider/model/egress default. Only `ProjectConfig` is untrusted for routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigOrigin {
    Cli,
    Environment,
    UserConfig,
    ProjectConfig,
    Builtin,
}

impl ConfigOrigin {
    /// Precedence for routing-sensitive values. Project config is intentionally below even the
    /// built-in route and therefore can never redirect it.
    pub(crate) const fn routing_priority(self) -> u8 {
        match self {
            Self::Cli => 4,
            Self::Environment => 3,
            Self::UserConfig => 2,
            Self::Builtin => 1,
            Self::ProjectConfig => 0,
        }
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

/// Select a routing-sensitive string exclusively from trusted origins.
pub(crate) fn pick_trusted_string(
    cli: Option<String>,
    env: Option<String>,
    user: Option<String>,
    builtin: &str,
) -> (String, ConfigOrigin) {
    if let Some(value) = non_empty(cli) {
        (value, ConfigOrigin::Cli)
    } else if let Some(value) = non_empty(env) {
        (value, ConfigOrigin::Environment)
    } else if let Some(value) = non_empty(user) {
        (value, ConfigOrigin::UserConfig)
    } else {
        (builtin.to_owned(), ConfigOrigin::Builtin)
    }
}

/// Select an optional routing-sensitive string exclusively from trusted origins.
pub(crate) fn pick_optional_trusted_string(
    cli: Option<String>,
    env: Option<String>,
    user: Option<String>,
) -> Option<(String, ConfigOrigin)> {
    if let Some(value) = non_empty(cli) {
        Some((value, ConfigOrigin::Cli))
    } else if let Some(value) = non_empty(env) {
        Some((value, ConfigOrigin::Environment))
    } else {
        non_empty(user).map(|value| (value, ConfigOrigin::UserConfig))
    }
}

/// Model defaults are allowed one repository-scoped exception: a project may name a bare model,
/// but the caller must constrain it to the already trusted provider. A recognized
/// `provider:model` value from this origin is rejected by the caller rather than followed.
pub(crate) fn pick_model_string(
    cli: Option<String>,
    env: Option<String>,
    user: Option<String>,
    project: Option<String>,
) -> Option<(String, ConfigOrigin)> {
    pick_optional_trusted_string(cli, env, user)
        .or_else(|| non_empty(project).map(|value| (value, ConfigOrigin::ProjectConfig)))
}

/// Treat `left:right` as provider-qualified only when `left` names a configured provider. This
/// avoids confusing model-native colons with a routing instruction.
pub(crate) fn has_known_provider_qualifier(
    value: &str,
    mut is_known_provider: impl FnMut(&str) -> bool,
) -> bool {
    value
        .trim()
        .split_once(':')
        .is_some_and(|(provider_id, _)| is_known_provider(provider_id))
}

/// A model qualifier may keep the selected provider, or replace it only when the model setting
/// came from a strictly higher-precedence trusted layer. Equal-precedence contradictions fail
/// closed so two fields from the same layer cannot silently disagree about egress.
pub(crate) fn qualifier_may_route(
    qualified_provider: &str,
    selected_provider: &str,
    model_origin: ConfigOrigin,
    provider_origin: ConfigOrigin,
) -> bool {
    qualified_provider == selected_provider
        || model_origin.routing_priority() > provider_origin.routing_priority()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_prefers_flag_then_env_then_file_then_default() {
        assert_eq!(pick(Some(9u32), Some(2), Some(3), 1), 9); // flag wins
        assert_eq!(pick(None, Some(2), Some(3), 1), 2); // env wins
        assert_eq!(pick(None, None, Some(3), 1), 3); // file wins
        assert_eq!(pick(None, None, None, 7), 7); // default
    }

    #[test]
    fn an_untrusted_project_ceiling_can_only_tighten() {
        assert_eq!(tighten(Some(20_u32), 40), 20);
        assert_eq!(tighten(Some(400_u32), 40), 40);
        assert_eq!(tighten(None, 40_u32), 40);
        assert_eq!(tighten(Some(0.25_f64), 2.0), 0.25);
        assert_eq!(tighten(Some(200.0_f64), 2.0), 2.0);
        assert_eq!(tighten_optional(Some(0.25_f64), None), Some(0.25));
        assert_eq!(tighten_optional(None, None::<f64>), None);
        assert_eq!(tighten_optional(Some(4.0_f64), Some(2.0)), Some(2.0));
        assert_eq!(tighten_optional(Some(1.0_f64), Some(2.0)), Some(1.0));
        assert!(!tighten_grant(Some(true), false));
        assert!(!tighten_grant(Some(false), true));
        assert!(tighten_grant(Some(true), true));
        assert!(tighten_grant(None, true));
    }

    #[test]
    fn run_setting_layers_cli_env_project_user_and_default() {
        assert_eq!(pick_run_setting(Some(5), Some(4), Some(3), Some(2), 1), 5);
        assert_eq!(pick_run_setting(None, Some(4), Some(3), Some(2), 1), 4);
        assert_eq!(pick_run_setting(None, None, Some(3), Some(2), 1), 3);
        assert_eq!(pick_run_setting(None, None, None, Some(2), 1), 2);
        assert_eq!(pick_run_setting(None, None, None, None, 1), 1);
    }

    #[test]
    fn routing_defaults_use_only_trusted_precedence() {
        assert_eq!(
            pick_trusted_string(
                Some("cli".into()),
                Some("env".into()),
                Some("user".into()),
                "builtin"
            ),
            ("cli".into(), ConfigOrigin::Cli)
        );
        assert_eq!(
            pick_trusted_string(None, Some("env".into()), Some("user".into()), "builtin"),
            ("env".into(), ConfigOrigin::Environment)
        );
        assert_eq!(
            pick_trusted_string(None, None, Some("user".into()), "builtin"),
            ("user".into(), ConfigOrigin::UserConfig)
        );
        assert_eq!(
            pick_trusted_string(None, None, None, "builtin"),
            ("builtin".into(), ConfigOrigin::Builtin)
        );
        assert_eq!(
            pick_optional_trusted_string(None, None, Some("https://user.example/v1".into())),
            Some(("https://user.example/v1".into(), ConfigOrigin::UserConfig))
        );
        assert!(
            ConfigOrigin::Cli.routing_priority() > ConfigOrigin::Environment.routing_priority()
        );
        assert!(
            ConfigOrigin::Environment.routing_priority()
                > ConfigOrigin::UserConfig.routing_priority()
        );
        assert!(
            ConfigOrigin::UserConfig.routing_priority() > ConfigOrigin::Builtin.routing_priority()
        );
        assert!(
            ConfigOrigin::Builtin.routing_priority()
                > ConfigOrigin::ProjectConfig.routing_priority()
        );
    }

    #[test]
    fn project_model_is_last_and_carries_untrusted_origin() {
        assert_eq!(
            pick_model_string(
                None,
                None,
                Some("user-model".into()),
                Some("project-model".into())
            ),
            Some(("user-model".into(), ConfigOrigin::UserConfig))
        );
        assert_eq!(
            pick_model_string(None, None, None, Some("project-model".into())),
            Some(("project-model".into(), ConfigOrigin::ProjectConfig))
        );
    }

    #[test]
    fn only_a_known_provider_prefix_is_a_routing_qualifier() {
        let known = |value: &str| matches!(value, "anthropic" | "openai");
        assert!(has_known_provider_qualifier("openai:gpt-5", known));
        assert!(!has_known_provider_qualifier("ft:gpt-4o", known));
        assert!(!has_known_provider_qualifier("qwen2.5-coder:7b", known));
    }

    #[test]
    fn model_qualifier_cannot_override_an_equal_or_more_trusted_provider() {
        assert!(qualifier_may_route(
            "openai",
            "anthropic",
            ConfigOrigin::Cli,
            ConfigOrigin::Environment
        ));
        assert!(!qualifier_may_route(
            "openai",
            "anthropic",
            ConfigOrigin::UserConfig,
            ConfigOrigin::Cli
        ));
        assert!(!qualifier_may_route(
            "openai",
            "anthropic",
            ConfigOrigin::Cli,
            ConfigOrigin::Cli
        ));
        assert!(qualifier_may_route(
            "anthropic",
            "anthropic",
            ConfigOrigin::UserConfig,
            ConfigOrigin::Cli
        ));
    }

    #[test]
    fn rejects_typos_and_bad_numeric_knobs() {
        // deny_unknown_fields: a typo'd key is an error, not silently dropped
        assert!(serde_json::from_str::<FileConfig>(r#"{"max_turn": 5}"#).is_err());
        // range validation catches disabled/negative budgets
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"max_turns":0}"#)
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"max_usd":-1.0}"#)
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"max_wall_secs":0}"#)
                .unwrap()
                .validate()
                .is_err()
        );
        // a sane config passes
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"max_turns":40,"max_usd":2.0}"#)
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"effort":"xhigh"}"#)
                .unwrap()
                .validate()
                .is_ok()
        );
        assert!(
            serde_json::from_str::<FileConfig>(r#"{"effort":"maximum-ish"}"#)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn strict_schema_accepts_the_hooks_block_consumed_by_the_kernel() {
        let cfg = serde_json::from_str::<FileConfig>(
            r#"{"hooks":{"PreToolUse":["./check.sh"],"Stop":["./cleanup.sh"]}}"#,
        )
        .expect("hooks is a supported top-level user-config key");
        let hooks = cfg.hooks.expect("hooks parsed");
        assert_eq!(hooks.get("PreToolUse").unwrap(), &["./check.sh"]);
        assert_eq!(hooks.get("Stop").unwrap(), &["./cleanup.sh"]);
    }

    #[test]
    fn provider_instances_are_bounded_indirect_and_strict() {
        let config = serde_json::from_str::<FileConfig>(
            r#"{
                "providers": [{
                    "id": "local-vllm",
                    "display_name": "Local vLLM",
                    "adapter": "openai_chat",
                    "api_root": "http://localhost:8000/v1",
                    "key_env": "LOCAL_VLLM_API_KEY"
                }]
            }"#,
        )
        .unwrap();
        config.validate().unwrap();

        let inline_secret = r#"{
            "providers": [{
                "id": "bad",
                "adapter": "openai_chat",
                "api_root": "https://example.com/v1",
                "key_env": "BAD_KEY",
                "api_key": "plaintext"
            }]
        }"#;
        assert!(
            serde_json::from_str::<FileConfig>(inline_secret).is_err(),
            "plaintext credential fields are outside the strict schema"
        );

        let duplicate = serde_json::from_str::<FileConfig>(
            r#"{"providers":[
                {"id":"same","adapter":"openai_chat","api_root":"https://a.example/v1","key_env":"A_KEY"},
                {"id":"same","adapter":"openai_chat","api_root":"https://b.example/v1","key_env":"B_KEY"}
            ]}"#,
        )
        .unwrap();
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn provider_http_requires_an_exact_loopback_host() {
        let config_with_root = |api_root: &str| FileConfig {
            providers: Some(vec![ProviderConfig {
                id: "local".into(),
                display_name: None,
                adapter: "openai_chat".into(),
                error_profile: None,
                api_root: api_root.into(),
                key_env: "LOCAL_KEY".into(),
                enabled: true,
                catalog: true,
                models: Vec::new(),
            }]),
            ..FileConfig::default()
        };

        for allowed in [
            "https://gateway.example/v1",
            "http://localhost:8000/v1",
            "http://127.0.0.1:8000/v1",
            "http://127.42.0.9:8000/v1",
            "http://[::1]:8000/v1",
        ] {
            assert!(
                config_with_root(allowed).validate().is_ok(),
                "expected {allowed} to be accepted"
            );
        }

        for rejected in [
            "http://localhost.evil.example/v1",
            "http://127.0.0.1.evil.example/v1",
            "http://192.168.1.2/v1",
            "http://example.com/v1",
            "ftp://localhost/v1",
            "https://user:secret\
@gateway.example/v1",
            "https://gateway.example/v1?tenant=other",
            "https://gateway.example/v1#fragment",
        ] {
            assert!(
                config_with_root(rejected).validate().is_err(),
                "expected {rejected} to be rejected"
            );
        }
    }

    #[test]
    fn provider_model_manifests_are_strict_and_bounded() {
        let parse = |models: &str| {
            serde_json::from_str::<FileConfig>(&format!(
                r#"{{"providers":[{{"id":"gateway","adapter":"openai_chat","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY","models":{models}}}]}}"#
            ))
            .unwrap()
        };

        assert!(
            parse(r#"["vendor/model-a","vendor/model-b"]"#)
                .validate()
                .is_ok()
        );
        assert!(
            parse(r#"["vendor/model-a","vendor/model-a"]"#)
                .validate()
                .is_err()
        );
        assert!(parse(r#"[""]"#).validate().is_err());
        assert!(parse(r#"["bad\nmodel"]"#).validate().is_err());
        let too_many_models = (0..257)
            .map(|index| format!("model-{index}"))
            .collect::<Vec<_>>();
        let too_many = serde_json::to_string(&too_many_models).unwrap();
        assert!(parse(&too_many).validate().is_err());
        let too_long = serde_json::to_string(&vec!["x".repeat(513)]).unwrap();
        assert!(parse(&too_long).validate().is_err());
    }

    #[test]
    fn provider_error_profiles_are_explicit_and_strict() {
        for profile in [
            "anthropic",
            "openai",
            "deepseek",
            "glm",
            "minimax",
            "fireworks",
            "custom",
        ] {
            let config = serde_json::from_str::<FileConfig>(&format!(
                r#"{{"providers":[{{"id":"gateway","adapter":"openai_chat","error_profile":"{profile}","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY"}}]}}"#
            ))
            .unwrap();
            assert!(config.validate().is_ok(), "profile {profile} should pass");
        }
        let invalid = serde_json::from_str::<FileConfig>(
            r#"{"providers":[{"id":"gateway","adapter":"openai_chat","error_profile":"guess","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY"}]}"#,
        )
        .unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn absent_config_file_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("core-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(FileConfig::load(&dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn project_config_is_bounded_before_allocation() {
        let dir = std::env::temp_dir().join(format!(
            "core-cfg-oversize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_dir = dir.join(core_protocol::home::HOME_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.json"),
            vec![b' '; MAX_CONFIG_BYTES + 1],
        )
        .unwrap();
        let error = FileConfig::load(&dir).unwrap_err().to_string();
        assert!(error.contains("exceeds"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn project_config_cannot_follow_a_symlink() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("core-cfg-symlink-{}-{nonce}", std::process::id()));
        let outside = std::env::temp_dir().join(format!(
            "core-cfg-outside-{}-{nonce}.json",
            std::process::id()
        ));
        let config_dir = dir.join(core_protocol::home::HOME_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(&outside, r#"{"allow_code":true}"#).unwrap();
        std::os::unix::fs::symlink(&outside, config_dir.join("config.json")).unwrap();
        let error = FileConfig::load(&dir).unwrap_err().to_string();
        assert!(error.contains("must not be a symlink"));
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_file(outside).ok();
    }
}
