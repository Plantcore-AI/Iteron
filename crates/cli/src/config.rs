//! Config layering (production necessity).
//!
//! A cloned repository is input, not an authorization principal. Repository `.iteron/config.json`
//! may select a bare model within an independently trusted provider and may *tighten* resource
//! ceilings. It cannot grant code execution, raise effort/spend/time ceilings, configure egress,
//! providers, hooks, or MCP processes. Those authorities come only from operator-owned sources.
//!
//! JSON, not TOML, to avoid a dependency (serde_json is already in the tree — zero-dependency
//! first). Every field is optional; a missing file is not an error (defaults apply).

mod provider_governor;
mod retry;
mod schema;
mod verification;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_MCP_SERVERS: usize = 32;
const MAX_MCP_SERVER_ARGS: usize = 128;
/// Upper bound for an operator-declared context window. Two orders of magnitude above any
/// window a provider currently documents, and far enough below `u64::MAX / 4` that the
/// window-relative compaction arithmetic never saturates. It bounds absurd input; it is not a
/// claim that any model this large exists.
pub(crate) const MAX_DECLARED_CONTEXT_WINDOW: u64 = 1_000_000_000;
pub(crate) use provider_governor::{
    ProviderGovernorConfig, ResolvedProviderGovernorConfig, builtin_failover_rules,
};
pub(crate) use retry::{RetryConfig, load_retry_environment, resolve_retry_policy};
pub(crate) use schema::{FILE_CONFIG_SCHEMA_VERSION, FileConfigSchemaError};
pub(crate) use verification::VerificationConfig;

#[derive(Debug, Serialize, Deserialize)]
// The TOP level is deliberately NOT `deny_unknown_fields`. One config is explicitly shared across
// machines through dotfiles, so a decorative key written by a newer binary would otherwise brick
// every older binary on the same machine rather than degrading. Unknown top-level keys are
// collected, warned about once, and ignored. Strict rejection is retained exactly where a silently
// dropped key would be a security or spend decision: `providers`, `mcp_servers`, and `hooks`.
#[serde(default)]
pub struct FileConfig {
    /// On-disk schema. Legacy files without this field are migrated from v0 before decoding.
    #[serde(default = "schema::current_version")]
    pub schema_version: u32,
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
    /// Bounded provider retry policy. It is parsed for both origins so typos fail loudly, but the
    /// composition root accepts values only from trusted operator layers.
    pub retry: Option<RetryConfig>,
    /// Bounded provider routing/admission controls. Consumed only from operator-owned config.
    pub provider_governor: Option<ProviderGovernorConfig>,
    /// Bounded policy around the operator-owned `--verify` command. Trusted user config may add
    /// narrower feedback commands, but `--verify` remains the mandatory full completion gate.
    /// Repository config is never consumed for command, rollback, or verifier-spawn authority.
    pub verification: Option<VerificationConfig>,
    /// Bounded out-of-band attention notifications for completed runs, approval requests, and
    /// long-idle periods. This preference is consumed only from operator-owned user configuration.
    pub completion_notifications: Option<bool>,
    /// Durable prompt history policy. The default is repository-scoped so prompts from unrelated
    /// workspaces never share one search corpus; `disabled` is the explicit private-session mode.
    /// Project configuration is parsed but ignored by the composition root because a cloned
    /// repository cannot decide whether operator text is retained outside that repository.
    pub prompt_history: Option<PromptHistoryMode>,
    /// Interactive input mode and the closed set of remappable composer actions. Operator-owned:
    /// repository content cannot take over terminal lifecycle keys.
    pub tui_keymap: Option<crate::keymap::Config>,
    /// External editor argv. It is executed directly (never through a shell) and consumed only
    /// from trusted user configuration.
    pub external_editor: Option<Vec<String>>,
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
    /// Immutable signed pricing artifacts. Consumed only from trusted user configuration; a
    /// repository value is parsed for strictness but ignored by the composition root.
    pub rate_cards: Option<Vec<crate::pricing::RateCardConfig>>,
    /// Exact active policy-bundle identity selected by the operator's offline promotion process.
    /// Consumed only from trusted user configuration; it carries identities/digests, never policy
    /// bodies or credentials.
    pub active_policy_bundle: Option<iteron_evolve::PolicyBundle>,
    /// MCP servers to connect and expose as tools (each an operator-configured stdio server).
    pub mcp_servers: Option<Vec<McpServerConfig>>,
    /// Lifecycle hooks are consumed by `crate::runtime::hooks::Hooks`, but they must also be part
    /// of this strict top-level schema. Without this field, `deny_unknown_fields` rejects the user
    /// config before the dedicated hook loader can read it, making every configured hook brick
    /// startup. Keep the raw command lists here; only the trusted user-config loader executes them.
    pub hooks: Option<BTreeMap<String, Vec<String>>>,
    /// Top-level keys this binary does not know. Retained so the parser can WARN about each one
    /// (a typo must still be visible) and so `iteron config set` round-trips a newer binary's field
    /// instead of deleting it. Never consumed as configuration.
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

fn validate_upper_env_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("environment names must be uppercase ASCII and at most 128 bytes");
    }
    Ok(())
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            schema_version: FILE_CONFIG_SCHEMA_VERSION,
            model: None,
            max_turns: None,
            max_usd: None,
            max_wall_secs: None,
            allow_code: None,
            egress_allow: None,
            compaction_trigger_tokens: None,
            retry: None,
            provider_governor: None,
            verification: None,
            completion_notifications: None,
            prompt_history: None,
            tui_keymap: None,
            external_editor: None,
            effort: None,
            provider: None,
            base_url: None,
            providers: None,
            rate_cards: None,
            active_policy_bundle: None,
            mcp_servers: None,
            hooks: None,
            unknown: BTreeMap::new(),
        }
    }
}

/// Select the only verification-policy configuration that may grant verifier concurrency or ask
/// for a rollback. Repository configuration is accepted by the shared parser for portability but
/// is never an authority source for these fields.
pub(crate) fn trusted_verification_config<'a>(
    user: &'a FileConfig,
    _project: &FileConfig,
) -> Option<&'a VerificationConfig> {
    user.verification.as_ref()
}

/// Where the interactive frontend persists scrubbed prompt history and its last text-only draft.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptHistoryMode {
    /// One file per canonical workspace identity. This is the safe default.
    #[default]
    Project,
    /// One operator-wide history file, useful when prompts intentionally span repositories.
    Global,
    /// Keep history only in memory and write no draft or prompt bytes to disk.
    Disabled,
}

/// Current-schema repository starter used by `/init`. Keeping the discriminator beside the
/// parser prevents a newer binary from scaffolding a legacy document by accident.
///
/// It deliberately does NOT emit `allow_code`. A project-level `false` is honoured as a tightening
/// (`tighten_grant`), so scaffolding one silently revoked code execution for the whole repository:
/// the documented onboarding step turned off builds and tests, and nothing connected the two
/// events. Absence keeps the effective grant exactly where the operator left it; a repository that
/// genuinely wants code execution off can still add the key by hand.
pub(crate) fn starter_project_config() -> String {
    format!(
        "{{\n  \"schema_version\": {FILE_CONFIG_SCHEMA_VERSION},\n  \"model\": null,\n  \"max_turns\": 40\n}}\n"
    )
}

/// Runtime provenance for one MCP server declaration.
///
/// The field is never deserialized from operator configuration. Only the verified plugin
/// composition root can mint plugin provenance, so a config document cannot impersonate a signed
/// plugin or satisfy a resumed checkpoint's plugin identity by adding another JSON field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpServerOrigin(McpServerOriginKind);

/// Canonical checkpoint identity for one verified plugin-owned MCP server slot.
///
/// The server namespace remains reversibly encoded so an operator-owned server cannot replace a
/// plugin slot on resume. Plugin id and full SemVer (including prerelease/build metadata) are
/// length-framed into the digest, avoiding delimiter ambiguity while staying inside the tunables
/// `NamespacedId` alphabet and byte ceiling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PluginMcpBindingId(String);

impl PluginMcpBindingId {
    const PREFIX: &'static str = "plugin-mcp-v1:";
    const MAX_SERVER_BYTES: usize = 64;

    fn new(plugin_id: &str, version: &str, server_name: &str) -> Result<Self, &'static str> {
        if plugin_id.is_empty()
            || plugin_id.len() > 128
            || version.is_empty()
            || version.len() > 128
            || server_name.is_empty()
            || server_name.len() > Self::MAX_SERVER_BYTES
            || [plugin_id, version, server_name]
                .into_iter()
                .any(|value| value.chars().any(char::is_control))
        {
            return Err("plugin MCP identity is outside the checkpoint identity domain");
        }
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"core-plugin-mcp-binding-v1\0");
        for part in [
            plugin_id.as_bytes(),
            version.as_bytes(),
            server_name.as_bytes(),
        ] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let encoded = format!(
            "{}{}:{}",
            Self::PREFIX,
            hex::encode(server_name.as_bytes()),
            hex::encode(digest.finalize())
        );
        if encoded.len() > 256 {
            return Err("plugin MCP identity is outside the checkpoint identity domain");
        }
        Ok(Self(encoded))
    }

    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        let body = value
            .strip_prefix(Self::PREFIX)
            .ok_or("plugin MCP identity has an unknown version")?;
        let (server_hex, digest) = body
            .split_once(':')
            .ok_or("plugin MCP identity is malformed")?;
        if server_hex.is_empty()
            || server_hex.len() > Self::MAX_SERVER_BYTES * 2
            || server_hex.len() % 2 != 0
            || !server_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.len() > 256
        {
            return Err("plugin MCP identity is malformed");
        }
        let server = hex::decode(server_hex).map_err(|_| "plugin MCP identity is malformed")?;
        let server = std::str::from_utf8(&server)
            .map_err(|_| "plugin MCP identity server namespace is not UTF-8")?;
        if server.is_empty() || server.chars().any(char::is_control) {
            return Err("plugin MCP identity server namespace is invalid");
        }
        // Canonical lower-case hex prevents two strings from naming one identity.
        if hex::encode(server.as_bytes()) != server_hex || digest.to_ascii_lowercase() != digest {
            return Err("plugin MCP identity is not canonically encoded");
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn owns_server(&self, server_name: &str) -> bool {
        self.0
            .strip_prefix(Self::PREFIX)
            .and_then(|body| body.split_once(':'))
            .is_some_and(|(server_hex, _)| hex::encode(server_name.as_bytes()) == server_hex)
    }
}

/// Content-free checkpoint identity for one complete validated MCP server binding.
///
/// The reversible server namespace prevents one slot from replacing another. The digest covers
/// the complete serialized operator/plugin server declaration (transport, executable/endpoint,
/// environment-variable names, OAuth lifecycle, filters, and authority policy) plus trusted
/// runtime origin. Credential values never enter `McpServerConfig`, so they cannot enter this ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct McpServerBindingId(String);

impl McpServerBindingId {
    const PREFIX: &'static str = "mcp-server-v1:";
    const MAX_SERVER_BYTES: usize = 64;

    fn new(config: &McpServerConfig) -> Result<Self, &'static str> {
        if config.name.is_empty()
            || config.name.len() > Self::MAX_SERVER_BYTES
            || config.name.chars().any(char::is_control)
        {
            return Err("MCP server binding namespace is outside its checkpoint domain");
        }
        let encoded_config = serde_json::to_vec(config)
            .map_err(|_| "MCP server binding could not encode validated configuration")?;
        let origin = config
            .origin
            .plugin_binding_id(&config.name)?
            .map_or_else(|| "operator".to_owned(), |binding| binding.0);
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"core-mcp-server-binding-v1\0");
        for part in [encoded_config.as_slice(), origin.as_bytes()] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let encoded = format!(
            "{}{}:{}",
            Self::PREFIX,
            hex::encode(config.name.as_bytes()),
            hex::encode(digest.finalize())
        );
        if encoded.len() > 256 {
            return Err("MCP server binding is outside the checkpoint identity domain");
        }
        Ok(Self(encoded))
    }

    pub(crate) fn parse(value: &str) -> Result<Self, &'static str> {
        let body = value
            .strip_prefix(Self::PREFIX)
            .ok_or("MCP server binding has an unknown version")?;
        let (server_hex, digest) = body
            .split_once(':')
            .ok_or("MCP server binding is malformed")?;
        if server_hex.is_empty()
            || server_hex.len() > Self::MAX_SERVER_BYTES * 2
            || server_hex.len() % 2 != 0
            || !server_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.len() > 256
        {
            return Err("MCP server binding is malformed");
        }
        let server = hex::decode(server_hex).map_err(|_| "MCP server binding is malformed")?;
        let server = std::str::from_utf8(&server)
            .map_err(|_| "MCP server binding namespace is not UTF-8")?;
        if server.is_empty() || server.chars().any(char::is_control) {
            return Err("MCP server binding namespace is invalid");
        }
        if hex::encode(server.as_bytes()) != server_hex || digest.to_ascii_lowercase() != digest {
            return Err("MCP server binding is not canonically encoded");
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn owns_server(&self, server_name: &str) -> bool {
        self.0
            .strip_prefix(Self::PREFIX)
            .and_then(|body| body.split_once(':'))
            .is_some_and(|(server_hex, _)| hex::encode(server_name.as_bytes()) == server_hex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum McpServerOriginKind {
    Operator,
    Plugin { plugin_id: String, version: String },
}

impl Default for McpServerOrigin {
    fn default() -> Self {
        Self(McpServerOriginKind::Operator)
    }
}

impl McpServerOrigin {
    /// The argument is an unforgeable production token: its constructor is private to the
    /// verified plugin materializer. Other runtime/config code can carry an origin but cannot mint
    /// plugin provenance from user strings.
    pub(crate) fn from_verified_plugin(
        verified: crate::plugin_runtime::VerifiedMcpPluginOrigin<'_>,
    ) -> Self {
        Self(McpServerOriginKind::Plugin {
            plugin_id: verified.plugin_id().to_owned(),
            version: verified.version(),
        })
    }

    #[cfg(test)]
    pub(crate) fn plugin_fixture(plugin_id: &str, version: &str) -> Self {
        Self(McpServerOriginKind::Plugin {
            plugin_id: plugin_id.to_owned(),
            version: version.to_owned(),
        })
    }

    /// Exact, content-free identity persisted in the tunables checkpoint for a plugin-owned
    /// server slot. The server name is part of the identity because one plugin may own several
    /// independently dispatched MCP servers.
    pub(crate) fn plugin_binding_id(
        &self,
        server_name: &str,
    ) -> Result<Option<PluginMcpBindingId>, &'static str> {
        match &self.0 {
            McpServerOriginKind::Operator => Ok(None),
            McpServerOriginKind::Plugin { plugin_id, version } => {
                PluginMcpBindingId::new(plugin_id, version, server_name).map(Some)
            }
        }
    }

    pub(crate) const fn label(&self) -> &'static str {
        match &self.0 {
            McpServerOriginKind::Operator => "operator",
            McpServerOriginKind::Plugin { .. } => "plugin",
        }
    }

    pub(crate) fn validate_for_server(&self, server_name: &str) -> Result<(), &'static str> {
        self.plugin_binding_id(server_name).map(|_| ())
    }
}

/// One MCP server the operator configured or the verified plugin composition root admitted.
/// Configuring it is the consent to run its tools; its tool descriptions are still treated as
/// untrusted (scanned) per ADR-007.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    pub name: String,
    /// Runtime-only origin. `serde(skip)` is load-bearing: untrusted JSON can never claim plugin
    /// provenance, while plugin materialization installs the verified identity after parsing.
    #[serde(skip)]
    pub(crate) origin: McpServerOrigin,
    /// Omitted for legacy documents and therefore defaults to stdio.
    #[serde(default, skip_serializing_if = "McpTransportConfig::is_stdio")]
    pub transport: McpTransportConfig,
    /// Direct executable for stdio transport. Mutually exclusive with `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Streamable-HTTP endpoint. HTTPS is required except for loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Header name -> environment-variable name. Values never enter configuration.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub header_env: BTreeMap<String, String>,
    /// Optional bearer/OAuth lifecycle. Every secret is named by environment source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<McpOAuthConfig>,
    /// Exact bare-name filter. Empty `allow` means all safe names; `deny` is applied last.
    #[serde(default, skip_serializing_if = "iteron_mcp::McpToolFilter::is_empty")]
    pub tools: iteron_mcp::McpToolFilter,
    /// Authority ceiling for this server's tools, narrowing only.
    ///
    /// Distinct from `tools`, and not a second spelling of it. `tools` names the tools that exist
    /// today; a server that adds a tool after installation is admitted by an empty allow-list
    /// because the operator could not have named a tool that did not exist. `policy` bounds the
    /// authority of every tool of the server, including the ones it has not published yet, so
    /// `{"capabilities": []}` is a statement about the server rather than about a list of names.
    /// Absent means inherit: it never widens what the host already allows.
    #[serde(default, skip_serializing_if = "iteron_mcp::McpServerPolicy::is_empty")]
    pub policy: iteron_mcp::McpServerPolicy,
}

impl McpServerConfig {
    pub(crate) fn runtime_binding_id(&self) -> Result<McpServerBindingId, &'static str> {
        McpServerBindingId::new(self)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportConfig {
    #[default]
    Stdio,
    Http,
}

impl McpTransportConfig {
    fn is_stdio(&self) -> bool {
        matches!(self, Self::Stdio)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpOAuthConfig {
    pub access_token_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_url: Option<String>,
}

/// Where one provider instance's credential comes from.
///
/// `key_env` alone could only ever name an environment variable, which cannot describe a hosted
/// subscription token: such a token is issued to a file, carries an expiry, and rotates while
/// Core is running. The tagged form says which of the two it is; the value itself is still never
/// written into configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderCredential {
    /// A process-environment variable name, read by the composition root.
    Env { name: String },
    /// An operator-owned credential file: either one bare token line, or
    /// `{"token": "...", "expires_at_unix": <seconds>}`. Must be mode 0600.
    File { path: String },
}

impl ProviderCredential {
    /// Value-free display used by `/config`, `/status`, and `iteron auth status`.
    pub fn display(&self) -> String {
        match self {
            Self::Env { name } => format!("env {name}"),
            Self::File { path } => format!("file {path}"),
        }
    }

    /// The environment variable name, when this credential is env-backed. Only names — never
    /// values — leave configuration, and this is what the redaction set is built from.
    pub fn env_name(&self) -> Option<&str> {
        match self {
            Self::Env { name } => Some(name),
            Self::File { .. } => None,
        }
    }

    fn validate(&self, provider_id: &str) -> Result<(), String> {
        match self {
            Self::Env { name } => {
                if name.is_empty()
                    || name.len() > 128
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(format!(
                        "provider `{provider_id}` credential env name must be an uppercase ASCII environment name"
                    ));
                }
                Ok(())
            }
            Self::File { path } => {
                if path.trim().is_empty() || path.len() > 4096 || path.contains('\0') {
                    return Err(format!(
                        "provider `{provider_id}` credential file path must be 1..=4096 bytes and contain no NUL"
                    ));
                }
                Ok(())
            }
        }
    }
}

/// One operator-defined provider instance. Credentials remain indirect: configuration names an
/// environment variable or a credential file, never a plaintext key, and the named source is
/// resolved on every turn (see `iteron_provider::CredentialSource`) so a token can rotate under a
/// running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// DEPRECATED alias for `credential: {"type":"env","name":"..."}`. Every released v2 document
    /// spells it this way, so it keeps loading verbatim. Adding an alias-preserving field is
    /// additive and deliberately does NOT bump the schema version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<ProviderCredential>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Some compatible gateways do not expose `GET models`; keep this explicit.
    #[serde(default = "default_true")]
    pub catalog: bool,
    /// Operator-declared model ids for gateways whose catalog is absent or incomplete. This is a
    /// manifest, not discovery output; the provider composition layer decides how to merge it.
    #[serde(default)]
    pub models: Vec<String>,
    /// Operator-declared per-model facts that no account-scoped API reports, keyed by model id.
    /// Same standing as `models`: a manifest the operator authored, not discovery output.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_capabilities: BTreeMap<String, ProviderModelCapabilities>,
}

/// Operator-declared capabilities for one model of one provider instance.
///
/// Core cannot discover a context window: `GET models` responses are not capability evidence
/// (ADR: listing a model never implicitly grants limits), and the static provider metadata
/// document is a bounded set of official vendor snapshots, so it can only speak for the vendors
/// it ships. That left every provider except GLM with an unknown window, which silently costs
/// the operator real context: with no window, compaction falls back to its absolute trigger
/// instead of a share of the window, and the pre-flight admission check cannot run at all.
///
/// This is the operator saying "I read my provider's documentation, and this is the number".
/// It is deliberately narrow. Image input is declarable because it is a binary wire capability
/// that custom gateways do not expose through a portable discovery API. `max_output_tokens` is not declarable because it is the reservation
/// the request actually asks the provider for, and an over-declared ceiling is rejected at the
/// wire rather than merely mis-sizing an estimate; `tool_calling` and `semantic_effort` are not
/// declarable because they gate a request feature rather than an arithmetic bound, and a
/// declaration is not an entitlement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModelCapabilities {
    /// Total input+output window the provider documents for this model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window_tokens: Option<u64>,
    /// Whether this exact route/model accepts image content on its configured adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_input: Option<bool>,
    /// Complete normalized route-ranking evidence. Larger is better for every component;
    /// `cost_efficiency` is deliberately inverted so the ranker never mixes score directions.
    /// Partial triples are unrepresentable and absence means objective routing is unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_objectives: Option<iteron_provider::RouteObjectiveScores>,
}

fn default_true() -> bool {
    true
}

impl ProviderConfig {
    /// Collapse the deprecated alias and the tagged field into one answer. Two spellings that
    /// disagree are a contradiction about which credential a paid request uses, so they fail
    /// closed rather than silently picking one.
    pub fn resolved_credential(&self) -> Result<ProviderCredential, String> {
        match (&self.credential, &self.key_env) {
            (Some(credential), None) => Ok(credential.clone()),
            (None, Some(name)) => Ok(ProviderCredential::Env { name: name.clone() }),
            (Some(credential), Some(name)) => {
                if credential.env_name() == Some(name.as_str()) {
                    Ok(credential.clone())
                } else {
                    Err(format!(
                        "provider `{}` declares both `credential` and the deprecated `key_env` with different sources; keep one",
                        self.id
                    ))
                }
            }
            (None, None) => Err(format!(
                "provider `{}` must declare a `credential` ({{\"type\":\"env\",\"name\":\"…\"}} or {{\"type\":\"file\",\"path\":\"…\"}})",
                self.id
            )),
        }
    }
}

impl FileConfig {
    /// Parse and migrate a bounded config document into the current strict schema.
    pub(crate) fn parse(text: &str) -> Result<Self, FileConfigSchemaError> {
        schema::parse(text)
    }

    /// Load `.iteron/config.json` under `repo`, if present. A malformed file IS an error
    /// (fail loud on a config the operator wrote), but an absent file is fine.
    pub fn load(repo: &Path) -> anyhow::Result<FileConfig> {
        let path = iteron_protocol::home::path(repo, "config.json");
        // Running `iteron` from the operator's home makes the PROJECT config path resolve to the very
        // file the USER config lives in. Reading it a second time under untrusted-origin rules made
        // the operator's own `providers`/`provider` look like a cloned repository's suggestion, and
        // the session warned that it was ignoring them — from the one file that is allowed to
        // declare them. Trust is a property of WHERE a file is, and this is the same `where`.
        if user_config_path().is_some_and(|user| same_file(&user, &path)) {
            return Ok(FileConfig::default());
        }
        let Some(text) = read_bounded_config(&path, false)? else {
            return Ok(FileConfig::default());
        };
        Self::parse(&text).map_err(|error| {
            anyhow::Error::new(error).context(format!("failed to load {}", path.display()))
        })
    }

    /// Reject nonsensical numeric knobs BEFORE they weaken a budget/bound invariant (a `max_turns:0`
    /// or negative `max_usd` would silently disable the ceiling). Called on every load.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != FILE_CONFIG_SCHEMA_VERSION {
            return Err(format!(
                "schema_version must be {FILE_CONFIG_SCHEMA_VERSION}, got {}",
                self.schema_version
            ));
        }
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
        if let Some(retry) = &self.retry {
            retry.validate()?;
        }
        if let Some(governor) = &self.provider_governor {
            governor.validate()?;
        }
        crate::keymap::Keymap::from_config(self.tui_keymap.as_ref())?;
        if let Some(command) = &self.external_editor {
            crate::external_editor::validate_command(command)?;
        }
        if let Some(effort) = self.effort.as_deref()
            && iteron_protocol::Effort::parse(effort).is_none()
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
                validate_provider_id_slug(&provider.id)?;
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
                provider.resolved_credential()?.validate(&provider.id)?;
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
                if provider.model_capabilities.len() > 256 {
                    return Err(format!(
                        "provider `{}` model_capabilities exceeds the 256-entry manifest bound",
                        provider.id
                    ));
                }
                for (model_id, capabilities) in &provider.model_capabilities {
                    if model_id.trim().is_empty()
                        || model_id.len() > 512
                        || model_id.chars().any(char::is_control)
                    {
                        return Err(format!(
                            "provider `{}` model_capabilities ids must be non-empty, control-free, and at most 512 bytes",
                            provider.id
                        ));
                    }
                    // A zero window is not "unknown": the admission and compaction paths both
                    // filter it out, so it would read as a working declaration while doing
                    // nothing. Refuse it here instead of accepting a no-op.
                    if capabilities
                        .context_window_tokens
                        .is_some_and(|window| window == 0 || window > MAX_DECLARED_CONTEXT_WINDOW)
                    {
                        return Err(format!(
                            "provider `{}` model `{model_id}` context_window_tokens must be 1..={MAX_DECLARED_CONTEXT_WINDOW}",
                            provider.id
                        ));
                    }
                    if capabilities
                        .routing_objectives
                        .is_some_and(|scores| scores.validate().is_err())
                    {
                        return Err(format!(
                            "provider `{}` model `{model_id}` routing objective scores must each be in 0..=1000000",
                            provider.id
                        ));
                    }
                }
            }
        }
        if let Some(rate_cards) = &self.rate_cards {
            crate::pricing::validate_rate_card_configs(rate_cards)?;
        }
        if let Some(bundle) = &self.active_policy_bundle {
            bundle
                .validate()
                .map_err(|error| format!("active_policy_bundle: {error}"))?;
        }
        if let Some(servers) = &self.mcp_servers {
            if servers.len() > MAX_MCP_SERVERS {
                return Err(format!(
                    "mcp_servers exceeds the {MAX_MCP_SERVERS}-server configuration bound"
                ));
            }
            let mut names = std::collections::BTreeSet::new();
            for (index, server) in servers.iter().enumerate() {
                iteron_mcp::validate_server_name(&server.name)
                    .map_err(|error| format!("mcp_servers[{index}]: {error}"))?;
                if !names.insert(server.name.as_str()) {
                    return Err(format!(
                        "mcp_servers contains a duplicate server namespace at index {index}"
                    ));
                }
                if server.args.len() > MAX_MCP_SERVER_ARGS
                    || server
                        .args
                        .iter()
                        .any(|arg| arg.len() > 16 * 1024 || arg.contains('\0'))
                {
                    return Err(format!(
                        "mcp_servers[{index}].args exceeds its 128-entry/16-KiB-per-entry bound or contains NUL"
                    ));
                }
                match server.transport {
                    McpTransportConfig::Stdio => {
                        let command = server.command.as_deref().ok_or_else(|| {
                            format!("mcp_servers[{index}].command is required for stdio")
                        })?;
                        if command.is_empty() || command.len() > 4096 || command.contains('\0') {
                            return Err(format!(
                                "mcp_servers[{index}].command must be 1..=4096 bytes and contain no NUL"
                            ));
                        }
                        if server.url.is_some()
                            || !server.header_env.is_empty()
                            || server.oauth.is_some()
                        {
                            return Err(format!(
                                "mcp_servers[{index}] stdio transport cannot declare url, header_env, or oauth"
                            ));
                        }
                    }
                    McpTransportConfig::Http => {
                        if server.command.is_some() || !server.args.is_empty() {
                            return Err(format!(
                                "mcp_servers[{index}] http transport cannot declare command or args"
                            ));
                        }
                        let url = server.url.as_deref().ok_or_else(|| {
                            format!("mcp_servers[{index}].url is required for http")
                        })?;
                        iteron_mcp::http::McpHttpEndpoint::parse(url)
                            .map_err(|error| format!("mcp_servers[{index}].url: {error}"))?;
                        iteron_mcp::http::McpHttpHeaderPolicy::new(
                            server.header_env.keys().cloned().collect(),
                        )
                        .map_err(|error| format!("mcp_servers[{index}].header_env: {error}"))?;
                        for env_name in server.header_env.values() {
                            validate_upper_env_name(env_name).map_err(|reason| {
                                format!("mcp_servers[{index}].header_env: {reason}")
                            })?;
                        }
                        if let Some(oauth) = &server.oauth {
                            validate_upper_env_name(&oauth.access_token_env).map_err(|reason| {
                                format!("mcp_servers[{index}].oauth.access_token_env: {reason}")
                            })?;
                            for name in [
                                oauth.expires_at_env.as_deref(),
                                oauth.refresh_token_env.as_deref(),
                                oauth.client_secret_env.as_deref(),
                            ]
                            .into_iter()
                            .flatten()
                            {
                                validate_upper_env_name(name).map_err(|reason| {
                                    format!("mcp_servers[{index}].oauth: {reason}")
                                })?;
                            }
                            if oauth.refresh_url.is_some() != oauth.refresh_token_env.is_some() {
                                return Err(format!(
                                    "mcp_servers[{index}].oauth refresh_url and refresh_token_env must be declared together"
                                ));
                            }
                            for endpoint in
                                [oauth.refresh_url.as_deref(), oauth.revoke_url.as_deref()]
                                    .into_iter()
                                    .flatten()
                            {
                                iteron_mcp::http::McpHttpEndpoint::parse(endpoint).map_err(
                                    |error| format!("mcp_servers[{index}].oauth endpoint: {error}"),
                                )?;
                            }
                        }
                    }
                }
                server
                    .tools
                    .validate()
                    .map_err(|error| format!("mcp_servers[{index}].tools: {error}"))?;
                server
                    .policy
                    .validate()
                    .map_err(|error| format!("mcp_servers[{index}].policy: {error}"))?;
            }
        }
        Ok(())
    }

    /// Load the USER config `~/.iteron/config.json` (trust-by-origin). ONLY the user's own config may
    /// declare command-spawning entries — `mcp_servers` spawns a subprocess at startup, so a project/
    /// cloned-repo config must never supply them (else cloning a hostile repo = RCE). Mirrors
    /// `Hooks::load_user`. Absent operator home/file → default; malformed → error (fail loud on
    /// your own config).
    pub fn load_user() -> anyhow::Result<FileConfig> {
        let Some(path) = user_config_path() else {
            return Ok(FileConfig::default());
        };
        let Some(text) = read_bounded_config(&path, true)? else {
            return Ok(FileConfig::default());
        };
        Self::parse(&text).map_err(|error| {
            anyhow::Error::new(error).context(format!("failed to load {}", path.display()))
        })
    }
}

/// Whether two paths name the same file on disk.
///
/// Canonicalized, so `~/.iteron/config.json` and `<repo>/.iteron/config.json` are recognised as one file
/// when the repo IS the home directory — including through a symlinked home, which is why this is
/// not a string comparison.
fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// The root that holds the operator's `.core` directory.
///
/// `ITERON_CONFIG_HOME` takes precedence so a container image, a CI runner, or a `sudo -E`
/// invocation with no `HOME` is still configurable; without it there is no supported way to point
/// Core at a config at all in those environments. Otherwise the one operator-home resolution in
/// `iteron_protocol::home::operator` decides, so a native Windows process with only `USERPROFILE`
/// (or `HOMEDRIVE` + `HOMEPATH`) resolves the same `.core` root the rest of the binary uses.
pub(crate) fn config_home() -> Option<std::path::PathBuf> {
    std::env::var_os("ITERON_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(iteron_protocol::home::operator)
}

/// Absolute path of the operator-owned user config, if a config root is resolvable.
pub(crate) fn user_config_path() -> Option<std::path::PathBuf> {
    config_home().map(|home| iteron_protocol::home::path(&home, "config.json"))
}

/// The directory credential files written by `iteron setup` live in: `<config root>/.iteron/credentials`.
pub(crate) fn credentials_dir() -> Option<std::path::PathBuf> {
    config_home().map(|home| iteron_protocol::home::path(&home, "credentials"))
}

/// The credential file `iteron setup` writes for one provider id.
///
/// The id is already constrained to the provider-instance alphabet, but this is the function that
/// turns operator text into a filesystem path, so it refuses anything that is not that alphabet
/// rather than trusting a caller to have validated first.
pub(crate) fn credential_file_path(provider_id: &str) -> Option<std::path::PathBuf> {
    if validate_provider_id_slug(provider_id).is_err() {
        return None;
    }
    credentials_dir().map(|directory| directory.join(provider_id))
}

/// Validate the provider-instance identity used by config, credential storage, and durable setup
/// evidence. Keeping one closed alphabet prevents a setup record from becoming an arbitrary
/// content or path persistence surface.
pub(crate) fn validate_provider_id_slug(provider_id: &str) -> Result<(), String> {
    if provider_id.is_empty()
        || provider_id.len() > 64
        || !provider_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(format!(
            "provider id `{provider_id}` must be a lowercase ASCII slug up to 64 bytes"
        ));
    }
    Ok(())
}

/// Every key `iteron config set` accepts, with the parser that turns operator text into the typed
/// field. A closed list is the point: a settable key is a supported key, and a typo is refused
/// rather than persisted into a document the next launch silently ignores.
const SETTABLE_KEYS: &[&str] = &[
    "provider",
    "model",
    "base_url",
    "effort",
    "max_turns",
    "max_usd",
    "max_wall_secs",
    "allow_code",
    "completion_notifications",
    "prompt_history",
    "tui_keymap",
    "external_editor",
    "compaction_trigger_tokens",
];

/// Apply one settable key to an in-memory document. Callers that need several keys to land
/// together (a `/model` choice is a provider AND a model) compose them inside one
/// [`update_user_config`] transaction rather than issuing two writes.
pub(crate) fn apply_setting(config: &mut FileConfig, key: &str, value: &str) -> Result<(), String> {
    let parse_u32 = |value: &str| {
        value
            .parse::<u32>()
            .map_err(|_| format!("`{key}` must be a non-negative integer, got `{value}`"))
    };
    let parse_u64 = |value: &str| {
        value
            .parse::<u64>()
            .map_err(|_| format!("`{key}` must be a non-negative integer, got `{value}`"))
    };
    let parse_bool = |value: &str| match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("`{key}` must be true or false, got `{other}`")),
    };
    match key {
        "provider" => config.provider = Some(value.to_owned()),
        "model" => config.model = Some(value.to_owned()),
        "base_url" => config.base_url = Some(value.to_owned()),
        "effort" => config.effort = Some(value.to_owned()),
        "max_turns" => config.max_turns = Some(parse_u32(value)?),
        "max_usd" => {
            config.max_usd = Some(
                value
                    .trim_start_matches('$')
                    .parse::<f64>()
                    .map_err(|_| format!("`{key}` must be a number, got `{value}`"))?,
            )
        }
        "max_wall_secs" => config.max_wall_secs = Some(parse_u64(value)?),
        "allow_code" => config.allow_code = Some(parse_bool(value)?),
        "completion_notifications" => config.completion_notifications = Some(parse_bool(value)?),
        "prompt_history" => {
            config.prompt_history = Some(match value {
                "project" => PromptHistoryMode::Project,
                "global" => PromptHistoryMode::Global,
                "disabled" => PromptHistoryMode::Disabled,
                other => {
                    return Err(format!(
                        "`{key}` must be project, global, or disabled, got `{other}`"
                    ));
                }
            })
        }
        "tui_keymap" => {
            config.tui_keymap = Some(
                serde_json::from_str(value)
                    .map_err(|error| format!("`{key}` must be a JSON keymap object: {error}"))?,
            );
            crate::keymap::Keymap::from_config(config.tui_keymap.as_ref())?;
        }
        "external_editor" => {
            let command = if value.trim_start().starts_with('[') {
                serde_json::from_str::<Vec<String>>(value)
                    .map_err(|error| format!("`{key}` must be a JSON argv array: {error}"))?
            } else {
                vec![value.to_owned()]
            };
            crate::external_editor::validate_command(&command)?;
            config.external_editor = Some(command);
        }
        "compaction_trigger_tokens" => {
            config.compaction_trigger_tokens =
                Some(value.parse::<usize>().map_err(|_| {
                    format!("`{key}` must be a non-negative integer, got `{value}`")
                })?)
        }
        other => {
            return Err(format!(
                "unknown config key `{other}`; settable keys: {}",
                SETTABLE_KEYS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Render one key's effective value from a decoded document, for `iteron config get`.
pub(crate) fn setting_value(config: &FileConfig, key: &str) -> Option<String> {
    match key {
        "provider" => config.provider.clone(),
        "model" => config.model.clone(),
        "base_url" => config.base_url.clone(),
        "effort" => config.effort.clone(),
        "max_turns" => config.max_turns.map(|value| value.to_string()),
        "max_usd" => config.max_usd.map(|value| format!("{value}")),
        "max_wall_secs" => config.max_wall_secs.map(|value| value.to_string()),
        "allow_code" => config.allow_code.map(|value| value.to_string()),
        "completion_notifications" => config
            .completion_notifications
            .map(|value| value.to_string()),
        "prompt_history" => config.prompt_history.map(|value| match value {
            PromptHistoryMode::Project => "project".to_owned(),
            PromptHistoryMode::Global => "global".to_owned(),
            PromptHistoryMode::Disabled => "disabled".to_owned(),
        }),
        "tui_keymap" => config
            .tui_keymap
            .as_ref()
            .and_then(|value| serde_json::to_string(value).ok()),
        "external_editor" => config
            .external_editor
            .as_ref()
            .and_then(|value| serde_json::to_string(value).ok()),
        "compaction_trigger_tokens" => config
            .compaction_trigger_tokens
            .map(|value| value.to_string()),
        _ => None,
    }
}

/// Every settable key and its currently persisted value.
pub(crate) fn settable_keys() -> &'static [&'static str] {
    SETTABLE_KEYS
}

/// An advisory exclusive lock on the user config, held for one read-modify-write.
///
/// `rename` alone makes each individual write atomic but does NOT make a read-modify-write
/// serializable: two concurrent `iteron config set` calls would both read the old document and the
/// loser's field would vanish. The lock closes that window; a stale lock older than its timeout is
/// broken so a killed process cannot wedge configuration forever.
struct ConfigLock {
    path: std::path::PathBuf,
}

const CONFIG_LOCK_STALE_SECS: u64 = 30;

impl ConfigLock {
    fn acquire(config_path: &Path) -> anyhow::Result<Self> {
        let path = config_path.with_extension("json.lock");
        for _ in 0..300 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .map(|modified| {
                            modified.elapsed().map(|age| age.as_secs()).unwrap_or(0)
                                > CONFIG_LOCK_STALE_SECS
                        })
                        .unwrap_or(false);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!(
            "{}: another process is writing the config; try again",
            path.display()
        )
    }
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Read the user config for a read-modify-write. A document that does not parse is returned as an
/// error: rewriting it would destroy an operator's file to "fix" a typo they can see and correct.
fn read_user_config_for_write(path: &Path) -> anyhow::Result<FileConfig> {
    match read_bounded_config(path, true)? {
        Some(text) => FileConfig::parse(&text).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "refusing to rewrite {}: the existing document does not parse",
                path.display()
            ))
        }),
        None => Ok(FileConfig::default()),
    }
}

/// Serialize and install a config document atomically at mode 0600.
///
/// Unset keys are dropped rather than written as `null`. This file is hand-edited by operators, so
/// persisting one setting must not turn a three-line document into a wall of nulls — and a written
/// `null` is indistinguishable from a deliberate value to a reader that is not this binary.
fn write_user_config(path: &Path, config: &FileConfig) -> anyhow::Result<()> {
    config.validate().map_err(anyhow::Error::msg)?;
    let mut document = serde_json::to_value(config)?;
    if let Some(object) = document.as_object_mut() {
        object.retain(|_, value| !value.is_null());
    }
    let mut text = serde_json::to_string_pretty(&document)?;
    text.push('\n');
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_atomic(path, text.as_bytes())
}

/// Write bytes to `path` through a same-directory temp file plus `rename`, at mode 0600.
///
/// A reader therefore observes either the whole previous document or the whole new one, never a
/// half-written credential or a truncated config.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{}: has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp = parent.join(format!(
        ".{}.{}.{nonce}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
}

/// THE single writer for operator configuration. Every product path that persists an operator
/// choice — `iteron config set`, `iteron setup`, `/model`, `iteron auth logout` — mutates the document
/// through this function, so there is exactly one place that locks, validates, and installs.
pub(crate) fn update_user_config(
    mutate: impl FnOnce(&mut FileConfig) -> Result<(), String>,
) -> anyhow::Result<std::path::PathBuf> {
    let path = user_config_path().ok_or_else(|| {
        anyhow::anyhow!(
            "no config root: set HOME or ITERON_CONFIG_HOME before writing configuration"
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _lock = ConfigLock::acquire(&path)?;
    let mut config = read_user_config_for_write(&path)?;
    mutate(&mut config).map_err(anyhow::Error::msg)?;
    config.schema_version = FILE_CONFIG_SCHEMA_VERSION;
    write_user_config(&path, &config)?;
    Ok(path)
}

/// `iteron config set <key> <value>`.
pub(crate) fn set_user_setting(key: &str, value: &str) -> anyhow::Result<std::path::PathBuf> {
    update_user_config(|config| apply_setting(config, key, value))
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
#[cfg(test)]
pub fn pick<T>(flag: Option<T>, env: Option<T>, file: Option<T>, default: T) -> T {
    flag.or(env).or(file).unwrap_or(default)
}

/// Resolve one trusted scalar while retaining the exact winning authority. Runtime tunables
/// evidence must never reconstruct provenance after the value has been flattened.
pub(crate) fn pick_with_origin<T>(
    flag: Option<T>,
    env: Option<T>,
    user: Option<T>,
    default: T,
) -> (T, ConfigOrigin) {
    if let Some(value) = flag {
        (value, ConfigOrigin::Cli)
    } else if let Some(value) = env {
        (value, ConfigOrigin::Environment)
    } else if let Some(value) = user {
        (value, ConfigOrigin::UserConfig)
    } else {
        (default, ConfigOrigin::Builtin)
    }
}

/// Optional trusted scalar resolution retaining absence as absence. This is used for ceilings
/// whose unset state is semantically different from a fabricated built-in value.
pub(crate) fn pick_optional_with_origin<T>(
    flag: Option<T>,
    env: Option<T>,
    user: Option<T>,
) -> Option<(T, ConfigOrigin)> {
    if let Some(value) = flag {
        Some((value, ConfigOrigin::Cli))
    } else if let Some(value) = env {
        Some((value, ConfigOrigin::Environment))
    } else {
        user.map(|value| (value, ConfigOrigin::UserConfig))
    }
}

/// Apply an untrusted repository ceiling to a value already resolved from trusted operator
/// sources. A project may request *less* authority/spend/time, never more.
#[cfg(test)]
pub fn tighten<T: PartialOrd>(project: Option<T>, trusted: T) -> T {
    match project {
        Some(project) if project < trusted => project,
        _ => trusted,
    }
}

/// Apply a project ceiling and preserve which layer supplied the effective value.
pub(crate) fn tighten_with_origin<T: PartialOrd>(
    project: Option<T>,
    trusted: (T, ConfigOrigin),
) -> (T, ConfigOrigin) {
    match project {
        Some(project) if project < trusted.0 => (project, ConfigOrigin::ProjectConfig),
        _ => trusted,
    }
}

/// Optional ceiling variant: absence means the operator made no monetary guarantee. A project may
/// introduce or lower a ceiling, but can never remove or raise a trusted one.
#[cfg(test)]
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

/// Optional ceiling variant retaining the winning layer. `None` remains an explicit absence, not
/// a fabricated built-in ceiling.
pub(crate) fn tighten_optional_with_origin<T: PartialOrd>(
    project: Option<T>,
    trusted: Option<(T, ConfigOrigin)>,
) -> Option<(T, ConfigOrigin)> {
    match (project, trusted) {
        (Some(project), Some(trusted)) if project < trusted.0 => {
            Some((project, ConfigOrigin::ProjectConfig))
        }
        (_, Some(trusted)) => Some(trusted),
        (Some(project), None) => Some((project, ConfigOrigin::ProjectConfig)),
        (None, None) => None,
    }
}

/// Apply an untrusted repository restriction to an operator-owned boolean grant. `true` can never
/// mint authority; an explicit project `false` may only remove an existing grant.
#[cfg(test)]
pub fn tighten_grant(project: Option<bool>, trusted: bool) -> bool {
    trusted && project.unwrap_or(true)
}

/// Boolean grant tightening with retained provenance. Project `true` is inert; project `false`
/// owns the resulting restriction only when it changes a trusted grant.
pub(crate) fn tighten_grant_with_origin(
    project: Option<bool>,
    trusted: (bool, ConfigOrigin),
) -> (bool, ConfigOrigin) {
    if trusted.0 && project == Some(false) {
        (false, ConfigOrigin::ProjectConfig)
    } else {
        trusted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompletionNotificationResolution {
    pub enabled: bool,
    pub project_ignored: bool,
}

/// Resolve a presentation preference exclusively from operator-owned configuration. A cloned
/// repository cannot turn terminal control output on or off, and absence conservatively means off.
pub(crate) fn resolve_completion_notifications(
    trusted_user: Option<bool>,
    untrusted_project: Option<bool>,
) -> CompletionNotificationResolution {
    CompletionNotificationResolution {
        enabled: trusted_user.unwrap_or(false),
        project_ignored: untrusted_project.is_some(),
    }
}

/// Resolve a repository-safe scalar across every implemented configuration layer. Project config
/// intentionally outranks the user's default for this repository, while environment and CLI remain
/// explicit runtime overrides.
#[cfg(test)]
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

/// Select a model only from operator-trusted origins.
///
/// A model id changes cost, capability, retention behavior, and request serialization even when
/// the provider/egress destination stays fixed. A cloned repository therefore cannot select one;
/// project configuration may tighten resource/permission ceilings but cannot choose execution.
pub(crate) fn pick_model_string(
    cli: Option<String>,
    env: Option<String>,
    user: Option<String>,
    _project: Option<String>,
) -> Option<(String, ConfigOrigin)> {
    pick_optional_trusted_string(cli, env, user)
}

/// Treat `left:right` as provider-qualified only when `left` names a configured provider. This
/// avoids confusing model-native colons with a routing instruction.
#[cfg(test)]
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
    fn completion_notifications_are_user_scoped_and_default_off() {
        assert_eq!(
            resolve_completion_notifications(None, None),
            CompletionNotificationResolution {
                enabled: false,
                project_ignored: false,
            }
        );
        assert_eq!(
            resolve_completion_notifications(Some(true), None),
            CompletionNotificationResolution {
                enabled: true,
                project_ignored: false,
            }
        );
        assert_eq!(
            resolve_completion_notifications(None, Some(true)),
            CompletionNotificationResolution {
                enabled: false,
                project_ignored: true,
            }
        );
        assert_eq!(
            resolve_completion_notifications(Some(false), Some(true)),
            CompletionNotificationResolution {
                enabled: false,
                project_ignored: true,
            }
        );

        let parsed = FileConfig::parse(r#"{"schema_version":2,"completion_notifications":true}"#)
            .expect("the current strict schema accepts the user preference");
        assert_eq!(parsed.completion_notifications, Some(true));
    }

    #[test]
    fn prompt_history_modes_are_strict_and_round_trip_through_config_commands() {
        let parsed = FileConfig::parse(r#"{"schema_version":2,"prompt_history":"disabled"}"#)
            .expect("the current strict schema accepts the retention preference");
        assert_eq!(parsed.prompt_history, Some(PromptHistoryMode::Disabled));

        let mut config = FileConfig::default();
        for (text, expected) in [
            ("project", PromptHistoryMode::Project),
            ("global", PromptHistoryMode::Global),
            ("disabled", PromptHistoryMode::Disabled),
        ] {
            apply_setting(&mut config, "prompt_history", text).unwrap();
            assert_eq!(config.prompt_history, Some(expected));
            assert_eq!(
                setting_value(&config, "prompt_history").as_deref(),
                Some(text)
            );
        }
        assert!(apply_setting(&mut config, "prompt_history", "forever").is_err());
        assert!(settable_keys().contains(&"prompt_history"));
    }

    #[test]
    fn operator_keymap_and_external_editor_are_typed_bounded_and_round_trip() {
        let parsed = FileConfig::parse(
            r#"{"schema_version":2,"tui_keymap":{"mode":"vim","bindings":{"external_editor":"alt+e"}},"external_editor":["/usr/bin/vi","-f"]}"#,
        )
        .expect("the current schema accepts typed operator input configuration");
        parsed.validate().unwrap();
        assert_eq!(
            parsed.tui_keymap.as_ref().map(|config| config.mode),
            Some(crate::keymap::Mode::Vim)
        );
        assert_eq!(
            parsed.external_editor,
            Some(vec!["/usr/bin/vi".into(), "-f".into()])
        );

        let mut config = FileConfig::default();
        apply_setting(
            &mut config,
            "tui_keymap",
            r#"{"mode":"standard","bindings":{"reverse_search":"alt+r"}}"#,
        )
        .unwrap();
        apply_setting(&mut config, "external_editor", r#"["/usr/bin/vi","-f"]"#).unwrap();
        assert!(
            setting_value(&config, "tui_keymap")
                .as_deref()
                .is_some_and(|value| value.contains("alt+r"))
        );
        assert_eq!(
            setting_value(&config, "external_editor").as_deref(),
            Some(r#"["/usr/bin/vi","-f"]"#)
        );
        assert!(settable_keys().contains(&"tui_keymap"));
        assert!(settable_keys().contains(&"external_editor"));

        assert!(
            apply_setting(
                &mut config,
                "tui_keymap",
                r#"{"bindings":{"external_editor":"ctrl+c"}}"#,
            )
            .unwrap_err()
            .contains("reserved")
        );
        assert!(apply_setting(&mut config, "external_editor", "[]").is_err());
        assert!(
            FileConfig::parse(r#"{"schema_version":2,"tui_keymap":{"mode":"emacs"}}"#).is_err()
        );
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
    fn scalar_resolution_retains_the_effective_authority() {
        assert_eq!(
            pick_with_origin(Some(5), Some(4), Some(3), 2),
            (5, ConfigOrigin::Cli)
        );
        assert_eq!(
            pick_with_origin(None, Some(4), Some(3), 2),
            (4, ConfigOrigin::Environment)
        );
        assert_eq!(
            pick_optional_with_origin(Some(5), Some(4), Some(3)),
            Some((5, ConfigOrigin::Cli))
        );
        assert_eq!(pick_optional_with_origin::<u32>(None, None, None), None);
        assert_eq!(
            tighten_with_origin(Some(2), (4, ConfigOrigin::UserConfig)),
            (2, ConfigOrigin::ProjectConfig)
        );
        assert_eq!(
            tighten_with_origin(Some(6), (4, ConfigOrigin::UserConfig)),
            (4, ConfigOrigin::UserConfig)
        );
        assert_eq!(
            tighten_optional_with_origin(Some(2), None),
            Some((2, ConfigOrigin::ProjectConfig))
        );
        assert_eq!(
            tighten_optional_with_origin(Some(6), Some((4, ConfigOrigin::Cli))),
            Some((4, ConfigOrigin::Cli))
        );
        assert_eq!(
            tighten_grant_with_origin(Some(false), (true, ConfigOrigin::Cli)),
            (false, ConfigOrigin::ProjectConfig)
        );
        assert_eq!(
            tighten_grant_with_origin(Some(true), (false, ConfigOrigin::UserConfig)),
            (false, ConfigOrigin::UserConfig)
        );
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
    fn project_model_is_ignored_as_untrusted_execution_selection() {
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
            None
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
        // A typo'd top-level key is no longer a hard startup failure — one config is shared
        // across binaries through dotfiles, so an unknown key degrades (I-24) — but it is still
        // retained and warned about rather than silently dropped.
        let typo = serde_json::from_str::<FileConfig>(r#"{"max_turn": 5}"#).unwrap();
        assert!(typo.unknown.contains_key("max_turn"));
        assert_eq!(typo.max_turns, None);
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
    fn init_starter_is_current_schema_and_round_trips() {
        let starter = starter_project_config();
        let config = FileConfig::parse(&starter).expect("starter must use the current schema");
        assert_eq!(config.schema_version, FILE_CONFIG_SCHEMA_VERSION);
        assert_eq!(config.max_turns, Some(40));
        assert_eq!(config.allow_code, None);
        assert_eq!(
            serde_json::to_value(config).unwrap()["schema_version"],
            FILE_CONFIG_SCHEMA_VERSION
        );
    }

    #[test]
    fn init_starter_does_not_change_the_effective_code_execution_grant() {
        // `/init` used to scaffold `"allow_code": false`, which `tighten_grant` honours, so
        // following the documented onboarding step silently stopped the agent running builds and
        // tests. Running it must leave the grant exactly as the operator's own layers left it.
        let starter = starter_project_config();
        assert!(
            !starter.contains("allow_code"),
            "the starter must not carry a grant it never explained: {starter}"
        );
        let config = FileConfig::parse(&starter).expect("starter must use the current schema");
        for trusted in [true, false] {
            assert_eq!(
                tighten_grant(config.allow_code, trusted),
                trusted,
                "the starter must be grant-neutral"
            );
        }
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
    fn mcp_filters_are_strict_bounded_and_use_safe_unambiguous_namespaces() {
        let config = FileConfig::parse(
            r#"{
                "schema_version": 2,
                "mcp_servers": [{
                    "name": "operator-tools",
                    "command": "/opt/operator/bin/mcp",
                    "args": ["--stdio"],
                    "tools": {
                        "allow": ["shared", "read.file"],
                        "deny": ["delete_all"]
                    }
                }]
            }"#,
        )
        .unwrap();
        let server = &config.mcp_servers.unwrap()[0];
        assert_eq!(server.tools.allow, ["shared", "read.file"]);
        assert_eq!(server.tools.deny, ["delete_all"]);

        for invalid in [
            r#"{"schema_version":2,"mcp_servers":[{"name":"a__b","command":"mcp"}]}"#,
            r#"{"schema_version":2,"mcp_servers":[{"name":"alpha","command":"mcp","tools":{"allow":["unsafe/path"]}}]}"#,
            r#"{"schema_version":2,"mcp_servers":[{"name":"alpha","command":"mcp","tools":{"alllow":["read"]}}]}"#,
            r#"{"schema_version":2,"mcp_servers":[{"name":"alpha","command":"mcp"},{"name":"alpha","command":"other"}]}"#,
        ] {
            assert!(FileConfig::parse(invalid).is_err(), "accepted {invalid}");
        }

        let entries: Vec<_> = (0..=iteron_mcp::MAX_MCP_TOOL_FILTER_ENTRIES)
            .map(|index| format!("tool-{index}"))
            .collect();
        let oversized = serde_json::json!({
            "schema_version": FILE_CONFIG_SCHEMA_VERSION,
            "mcp_servers": [{
                "name": "alpha",
                "command": "mcp",
                "tools": {"allow": entries}
            }]
        });
        assert!(FileConfig::parse(&oversized.to_string()).is_err());
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

    /// I-23 — the credential field could only ever be `key_env`, an uppercase ASCII environment
    /// name, which cannot describe a hosted subscription token. This fixture pins BOTH spellings:
    /// every released v2 document keeps loading verbatim, and the tagged form describes a file.
    #[test]
    fn i23_a_fixture_pins_both_credential_spellings() {
        const FIXTURE: &str = r#"{
            "schema_version": 2,
            "providers": [
                {
                    "id": "legacy",
                    "adapter": "openai_chat",
                    "api_root": "https://legacy.example/v1",
                    "key_env": "LEGACY_KEY"
                },
                {
                    "id": "plan",
                    "adapter": "openai_chat",
                    "api_root": "https://plan.example/v1",
                    "credential": { "type": "file", "path": "/home/op/.iteron/credentials/plan" }
                },
                {
                    "id": "tagged-env",
                    "adapter": "openai_chat",
                    "api_root": "https://tagged.example/v1",
                    "credential": { "type": "env", "name": "TAGGED_KEY" }
                }
            ]
        }"#;
        let config = FileConfig::parse(FIXTURE).expect("both spellings load");
        config.validate().expect("both spellings validate");
        // An alias-preserving additive field is NOT a schema break, so the version is unchanged.
        assert_eq!(config.schema_version, FILE_CONFIG_SCHEMA_VERSION);
        let providers = config.providers.as_deref().unwrap();
        assert_eq!(
            providers[0].resolved_credential().unwrap(),
            ProviderCredential::Env {
                name: "LEGACY_KEY".into()
            }
        );
        assert_eq!(
            providers[1].resolved_credential().unwrap(),
            ProviderCredential::File {
                path: "/home/op/.iteron/credentials/plan".into()
            }
        );
        assert_eq!(
            providers[2].resolved_credential().unwrap(),
            ProviderCredential::Env {
                name: "TAGGED_KEY".into()
            }
        );
        assert_eq!(
            providers[1].resolved_credential().unwrap().display(),
            "file /home/op/.iteron/credentials/plan"
        );

        // Round-tripping keeps each entry's own spelling: rewriting the document to persist an
        // unrelated key must not silently migrate an operator's file under them.
        let rendered = serde_json::to_string(&config).unwrap();
        assert!(rendered.contains(r#""key_env":"LEGACY_KEY""#), "{rendered}");
        assert!(rendered.contains(r#""type":"file""#), "{rendered}");
    }

    /// Two spellings that disagree are a contradiction about which credential a PAID request
    /// uses. There is no safe way to pick one, so the config fails closed.
    #[test]
    fn i23_contradictory_credential_spellings_fail_closed() {
        let error = FileConfig::parse(
            r#"{"schema_version":2,"providers":[{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","key_env":"A_KEY","credential":{"type":"env","name":"B_KEY"}}]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("keep one"), "{error}");

        // Agreeing spellings are redundant, not contradictory, and are accepted.
        FileConfig::parse(
            r#"{"schema_version":2,"providers":[{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","key_env":"A_KEY","credential":{"type":"env","name":"A_KEY"}}]}"#,
        )
        .expect("agreeing spellings are not a contradiction");

        // Declaring neither is still a hard error: a provider with no credential source cannot
        // dispatch, and discovering that at the first paid turn is the failure mode being fixed.
        let error = FileConfig::parse(
            r#"{"schema_version":2,"providers":[{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1"}]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must declare a `credential`"), "{error}");
    }

    /// The env spelling keeps its exact historical validation: only an uppercase ASCII
    /// environment name, so a path or a shell expression can never be smuggled in as one.
    #[test]
    fn i23_an_env_credential_keeps_its_exact_name_validation() {
        for rejected in ["lowercase", "HAS SPACE", "WITH-DASH", ""] {
            let error = FileConfig::parse(&format!(
                r#"{{"schema_version":2,"providers":[{{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","key_env":"{rejected}"}}]}}"#
            ))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("uppercase ASCII environment name"),
                "`{rejected}`: {error}"
            );
        }
        for rejected in ["", "   "] {
            let error = FileConfig::parse(&format!(
                r#"{{"schema_version":2,"providers":[{{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","credential":{{"type":"file","path":"{rejected}"}}}}]}}"#
            ))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("credential file path"),
                "`{rejected}`: {error}"
            );
        }
    }

    /// I-24 — strict rejection is retained exactly where a silently dropped key would be a
    /// security or spend decision, and relaxed only at the decorative top level.
    #[test]
    fn i24_security_sensitive_objects_stay_strict_while_the_top_level_degrades() {
        for strict in [
            r#"{"providers":[{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","key_env":"GW_KEY","unexpected":1}]}"#,
            r#"{"mcp_servers":{"srv":{"command":"x","args":[],"unexpected":1}}}"#,
        ] {
            assert!(
                FileConfig::parse(strict).is_err(),
                "a security-sensitive sub-object must stay strict: {strict}"
            );
        }
        // The top level degrades: an unknown key is retained (so a rewrite cannot delete a newer
        // binary's field) and never consumed as configuration.
        let config = FileConfig::parse(r#"{"schema_version":2,"written_by_a_newer_core":{"a":1}}"#)
            .expect("an unknown top-level key loads");
        assert!(config.unknown.contains_key("written_by_a_newer_core"));
        let rendered = serde_json::to_string(&config).unwrap();
        assert!(
            rendered.contains("written_by_a_newer_core"),
            "a rewrite must round-trip the field it does not understand: {rendered}"
        );
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
                key_env: Some("LOCAL_KEY".into()),
                credential: None,
                enabled: true,
                catalog: true,
                models: Vec::new(),
                model_capabilities: BTreeMap::new(),
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

    fn provider_with_capabilities(capabilities: &str) -> FileConfig {
        serde_json::from_str::<FileConfig>(&format!(
            r#"{{"providers":[{{"id":"gateway","adapter":"openai_chat","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY","model_capabilities":{capabilities}}}]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn declared_context_window_is_bounded_and_never_a_no_op() {
        let valid = provider_with_capabilities(r#"{"k3":{"context_window_tokens":1048576}}"#);
        assert!(valid.validate().is_ok());
        let providers = valid.providers.as_ref().unwrap();
        assert_eq!(
            providers[0].model_capabilities["k3"].context_window_tokens,
            Some(1_048_576)
        );

        // Absent is the honest way to say "unknown". Zero is not: the admission and compaction
        // paths both filter it out, so accepting it would store a declaration that does nothing.
        assert!(
            provider_with_capabilities(r#"{"k3":{"context_window_tokens":0}}"#)
                .validate()
                .is_err()
        );
        assert!(
            provider_with_capabilities(&format!(
                r#"{{"k3":{{"context_window_tokens":{}}}}}"#,
                MAX_DECLARED_CONTEXT_WINDOW + 1
            ))
            .validate()
            .is_err()
        );
        assert!(
            provider_with_capabilities(&format!(
                r#"{{"k3":{{"context_window_tokens":{MAX_DECLARED_CONTEXT_WINDOW}}}}}"#
            ))
            .validate()
            .is_ok()
        );

        // An empty map and an entry that declares nothing are both legal: the second is how an
        // operator records "I looked and my provider does not document it".
        assert!(provider_with_capabilities("{}").validate().is_ok());
        assert!(
            provider_with_capabilities(r#"{"k3":{}}"#)
                .validate()
                .is_ok()
        );

        assert!(
            provider_with_capabilities(r#"{"  ":{"context_window_tokens":1}}"#)
                .validate()
                .is_err()
        );
        let over_bound = (0..257)
            .map(|index| format!(r#""m{index}":{{"context_window_tokens":1}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            provider_with_capabilities(&format!("{{{over_bound}}}"))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn declared_capability_keys_are_strict() {
        // The point of the narrow schema is that a knob Core does not honour cannot be quietly
        // written into a config and believed. A typo'd or aspirational field is an error.
        for rejected in [
            r#"{"k3":{"context_window":1048576}}"#,
            r#"{"k3":{"max_output_tokens":65536}}"#,
            r#"{"k3":{"tool_calling":true}}"#,
            r#"{"k3":{"semantic_effort":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<FileConfig>(&format!(
                    r#"{{"providers":[{{"id":"gateway","adapter":"openai_chat","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY","model_capabilities":{rejected}}}]}}"#
                ))
                .is_err(),
                "{rejected} should be rejected by the strict schema"
            );
        }
    }

    #[test]
    fn declared_routing_objectives_are_complete_normalized_route_facts() {
        let valid = provider_with_capabilities(
            r#"{"k3":{"routing_objectives":{"quality_millionths":800000,"cost_efficiency_millionths":700000,"latency_millionths":600000}}}"#,
        );
        assert!(valid.validate().is_ok());
        let invalid = provider_with_capabilities(
            r#"{"k3":{"routing_objectives":{"quality_millionths":1000001,"cost_efficiency_millionths":700000,"latency_millionths":600000}}}"#,
        );
        assert!(invalid.validate().is_err());
        assert!(
            serde_json::from_str::<FileConfig>(
                r#"{"providers":[{"id":"gateway","adapter":"openai_chat","api_root":"https://gateway.example/v1","key_env":"GATEWAY_KEY","model_capabilities":{"k3":{"routing_objectives":{"quality_millionths":800000,"latency_millionths":600000}}}}]}"#,
            )
            .is_err(),
            "a partial objective triple must be unrepresentable"
        );
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
        let config_dir = dir.join(iteron_protocol::home::HOME_DIR);
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
        let config_dir = dir.join(iteron_protocol::home::HOME_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(&outside, r#"{"allow_code":true}"#).unwrap();
        std::os::unix::fs::symlink(&outside, config_dir.join("config.json")).unwrap();
        let error = FileConfig::load(&dir).unwrap_err().to_string();
        assert!(error.contains("must not be a symlink"));
        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_file(outside).ok();
    }
}
