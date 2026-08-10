//! Dynamic provider/model discovery and account health.
//!
//! A catalog is evidence about what an account can see now, not a permanent hard-coded model
//! list. Discovery is deliberately bounded and model compatibility is represented separately
//! from visibility: unknown model IDs remain visible without being silently treated as valid
//! coding-turn models.

pub use crate::static_metadata::{
    GLM_STANDARD_CHAT_MANIFEST, GLM_STANDARD_CHAT_MODELS, StaticCatalogManifest,
};
use crate::{AvailabilityTransition, ProviderError, api_error_from_response};
use core_protocol::{TokenRateCard, Usage};
use futures_util::StreamExt;
use reqwest::Url;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bounded connect timeout shared by every adapter's HTTP client.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an idle pooled connection is kept for the next turn. A coding turn is mostly the
/// operator (or the model) thinking, and reqwest's 90s default evicts the connection during that
/// pause: the next turn then pays a full TCP+TLS handshake again, measured at 0.78-1.02s on this
/// network. 300s covers a long think without holding a connection open indefinitely.
const HTTP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// TCP keepalive on the pooled connection, so a NAT or middlebox on the path does not silently
/// drop a connection that is being kept for exactly that long think.
const HTTP_TCP_KEEPALIVE: Duration = Duration::from_secs(30);

/// The concrete HTTP client an adapter dispatches through. Re-exported so a host
/// implementing [`HttpTransport`] can name the port's return type without
/// depending on `reqwest` directly.
pub type HttpClient = reqwest::Client;

/// The provider's network-I/O capability port.
///
/// Every live adapter used to build its own `reqwest::Client` inline with an
/// identical, security-critical policy (redirects disabled — the configured API
/// root is an authority boundary — plus a bounded connect timeout). That direct
/// construction left the network seam unmediated: a host could neither broker,
/// observe, nor substitute transport for the provider adapters. This port turns
/// that seam into an injected capability with one default implementation
/// ([`DefaultHttpTransport`]); adapters now obtain their client from the port
/// instead of constructing it inline (D2-21).
///
/// This is the network half of the injected provider port the architecture
/// roadmap targets: the adapter receives its transport instead of reaching for
/// the runtime's HTTP stack directly.
pub trait HttpTransport: Send + Sync {
    /// Produce the HTTP client an adapter will send requests through.
    ///
    /// Implementations MUST disable transparent redirects: the configured API
    /// root is an authority boundary, and an API key, prompt, or POST body must
    /// never be replayed to a redirect target chosen by the remote endpoint.
    fn client(&self) -> Result<HttpClient, ProviderError>;
}

/// Default transport: the mandated secure client construction the adapters used
/// to copy-paste. It disables redirects and applies the shared connect timeout.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultHttpTransport;

impl HttpTransport for DefaultHttpTransport {
    fn client(&self) -> Result<HttpClient, ProviderError> {
        reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            // Connection reuse is a latency policy, not a tuning detail: without these two the
            // pool drops the connection across a long think and the next turn re-handshakes.
            .pool_idle_timeout(HTTP_POOL_IDLE_TIMEOUT)
            .tcp_keepalive(HTTP_TCP_KEEPALIVE)
            // The configured API root is an authority boundary. Never replay an
            // API key, prompt, or POST body through an endpoint-chosen redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderError::Configuration("HTTP client could not be built".into()))
    }
}

const CATALOG_PAGE_SIZE: usize = 100;
const MAX_CATALOG_PAGES: usize = 32;
const MAX_CATALOG_MODELS: usize = 10_000;
const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_MODEL_ID_BYTES: usize = 512;
const MAX_DISPLAY_NAME_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_HEALTH_ENTRIES: usize = 256;
const MAX_MODEL_HEALTH_ENTRIES: usize = 4096;
const MAX_ACCOUNT_PROBE_PAGE_BYTES: usize = 64 * 1024;
const MAX_ACCOUNT_PROBE_TOTAL_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACCOUNT_PAGES: usize = 32;
const MAX_ACCOUNTS: usize = 10_000;
const MAX_PAGE_TOKEN_BYTES: usize = 4096;
const FIREWORKS_PAGE_SIZE: usize = 200;
const MAX_FIREWORKS_CATALOG_ACCOUNTS: usize = 64;
const MAX_FIREWORKS_CATALOG_PAGES: usize = 128;
const MAX_FIREWORKS_DEPLOYED_MODELS: usize = 10_000;
const FIREWORKS_INFERENCE_ROOT: &str = "https://api.fireworks.ai/inference/v1";
const FIREWORKS_CONTROL_PLANE_ROOT: &str = "https://api.fireworks.ai/v1";
const FIREWORKS_SERVERLESS_MODELS_PATH: &str = "accounts/fireworks/models";
const FIREWORKS_SERVERLESS_FILTER: &str = "supports_serverless=true";
const GLM_STANDARD_ROOT: &str = "https://open.bigmodel.cn/api/paas/v4";
const GLM_CODING_ROOT: &str = "https://open.bigmodel.cn/api/coding/paas/v4";
const GLM_ANTHROPIC_ROOT: &str = "https://open.bigmodel.cn/api/anthropic";
const GLM_UNSUPPORTED_CATALOG_REASON: &str = "GLM documents no model-list endpoint for this API root; use Core's standard-root official schema manifest, an operator manifest, or an explicit manual model id; account entitlement remains unknown";
const ANTHROPIC_ROOT: &str = "https://api.anthropic.com/v1";
const OPENAI_ROOT: &str = "https://api.openai.com/v1";
const DEEPSEEK_ROOT: &str = "https://api.deepseek.com";
const DEEPSEEK_V1_ROOT: &str = "https://api.deepseek.com/v1";
const MINIMAX_ROOT: &str = "https://api.minimax.io/v1";
const MINIMAX_LEGACY_ROOT: &str = "https://api.minimaxi.com/v1";

/// Transport/protocol adapter selected for one provider instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterKind {
    AnthropicMessages,
    OpenAiCompatibleChat,
    OpenAiResponses,
}

/// Provider-specific error vocabulary. Wire compatibility is not error-semantic compatibility:
/// for example, business code `1002` means rate limiting at MiniMax but authentication failure at
/// GLM. Unknown gateways therefore use `CustomConservative` and never inherit numeric meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorProfile {
    Anthropic,
    OpenAi,
    DeepSeek,
    Glm,
    MiniMax,
    Fireworks,
    CustomConservative,
}

impl ErrorProfile {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::DeepSeek => "deepseek",
            Self::Glm => "glm",
            Self::MiniMax => "minimax",
            Self::Fireworks => "fireworks",
            Self::CustomConservative => "custom-provider",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinProvider {
    Anthropic,
    OpenAi,
}

/// The source of truth for one provider instance's catalog.
///
/// This is deliberately separate from the turn adapter: sharing Chat Completions wire syntax does
/// not imply sharing a `/models` control-plane endpoint. In particular, Fireworks publishes its
/// serverless inventory under a separate control-plane root, while GLM documents no list-models
/// operation at its inference roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogStrategy {
    AnthropicModels,
    OpenAiModels,
    FireworksControlPlane { api_root: ApiRoot },
    Unsupported { reason: String },
}

/// A parsed API root whose path is authoritative. `https://host/v1` and
/// `https://host/inference/v1` remain exactly those roots; endpoint construction never guesses,
/// inserts, or strips a version segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiRoot(String);

impl ApiRoot {
    pub fn parse(value: &str) -> Result<Self, ProviderError> {
        let mut url = Url::parse(value).map_err(|_| {
            ProviderError::Configuration("API root must be an absolute HTTP(S) URL".into())
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ProviderError::Configuration(
                "API root scheme must be http or https".into(),
            ));
        }
        if url.host_str().is_none() {
            return Err(ProviderError::Configuration(
                "API root must include a host".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ProviderError::Configuration(
                "API root must not contain user information".into(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ProviderError::Configuration(
                "API root must not contain a query or fragment".into(),
            ));
        }

        // Url canonicalizes origin/path syntax. Store one representation with no trailing slash
        // so endpoint appends are mechanical and do not invoke URL-join replacement semantics.
        let normalized_path = url.path().trim_end_matches('/').to_string();
        url.set_path(if normalized_path.is_empty() {
            "/"
        } else {
            &normalized_path
        });
        let normalized = url.as_str().trim_end_matches('/').to_string();
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Append a relative endpoint path to the complete configured root.
    pub fn endpoint(&self, path: &str) -> Result<Url, ProviderError> {
        let path = path.trim_matches('/');
        if path.is_empty()
            || path.split('/').any(|segment| {
                segment.is_empty()
                    || matches!(segment, "." | "..")
                    || segment.contains(['?', '#', '\\'])
            })
        {
            return Err(ProviderError::Configuration(
                "provider endpoint path is invalid".into(),
            ));
        }
        Url::parse(&format!("{}/{path}", self.0)).map_err(|_| {
            ProviderError::Configuration("provider endpoint could not be constructed".into())
        })
    }

    /// Build an endpoint at the provider origin, intentionally ignoring the configured API path.
    /// This exists only for documented out-of-tree account endpoints such as DeepSeek's
    /// `/user/balance`; model/turn endpoints must always use `endpoint`.
    fn origin_endpoint(&self, path: &str) -> Result<Url, ProviderError> {
        let mut origin = Url::parse(&self.0).map_err(|_| {
            ProviderError::Configuration("provider origin could not be parsed".into())
        })?;
        origin.set_path("/");
        let origin = ApiRoot::parse(origin.as_str())?;
        origin.endpoint(path)
    }
}

impl std::str::FromStr for ApiRoot {
    type Err = ProviderError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Bytes admitted from a credential file. A credential document is a token plus an expiry; a
/// larger file is a mistake or an attack, never something to allocate.
const MAX_CREDENTIAL_FILE_BYTES: u64 = 8 * 1024;
/// Re-read a file credential once it is within this window of its recorded expiry. A subscription
/// token therefore rotates a full minute before the provider would start rejecting it.
const CREDENTIAL_REFRESH_SKEW_SECS: u64 = 60;

/// Which kind of source produced (or failed to produce) a credential. Kept separate from the
/// value so status output can name the source without ever holding the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Env,
    File,
}

impl CredentialKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::File => "file",
        }
    }
}

/// Everything an operator needs to debug "why is my key not working" — and nothing else. This
/// type is deliberately value-free: it names the source, says whether a credential resolved, and
/// reports the expiry, so it can be printed, logged, and handed to the TUI safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialStatus {
    pub kind: CredentialKind,
    /// The environment variable name, or the credential file path. Never the value.
    pub name: String,
    pub present: bool,
    pub expires_at_unix: Option<u64>,
    pub error: Option<String>,
}

impl CredentialStatus {
    /// One-line operator display. A missing credential names what to set, not what was set.
    pub fn display(&self) -> String {
        let mut text = format!("{} {}", self.kind.label(), self.name);
        if !self.present {
            text.push_str(" (absent)");
        }
        if let Some(expires_at) = self.expires_at_unix {
            text.push_str(&format!(" (expires at {expires_at})"));
        }
        if let Some(error) = &self.error {
            text.push_str(&format!(" ({error})"));
        }
        text
    }
}

/// Where a provider credential comes from.
///
/// This used to be an `Option<String>` snapshotted once at process construction, which made two
/// documented "read at call time" claims false and made a hosted subscription token unusable:
/// rotation required restarting Core. The source is now resolved per turn. `Env` keeps the exact
/// previous behaviour — a running process's own environment is not a rotation channel — while
/// `File` re-reads an operator-owned credential document ahead of its recorded expiry.
#[derive(Clone)]
pub enum CredentialSource {
    /// A value the composition root read out of the process environment (or that a test supplied
    /// directly). `name` is the environment variable it came from, when one is known.
    Env {
        name: Option<String>,
        value: Option<String>,
    },
    /// An operator-owned credential file holding a token and an optional expiry.
    File(Arc<FileCredential>),
}

impl CredentialSource {
    /// The historical constructor shape: an already-resolved optional value with no source name.
    pub fn env_value(value: Option<String>) -> Self {
        Self::Env {
            name: None,
            value: value.filter(|value| !value.trim().is_empty()),
        }
    }

    /// A named environment variable, read once by the composition root.
    pub fn env(name: impl Into<String>, value: Option<String>) -> Self {
        Self::Env {
            name: Some(name.into()),
            value: value.filter(|value| !value.trim().is_empty()),
        }
    }

    /// A credential file, re-read on resolution once it is close to expiring.
    pub fn file(path: impl Into<std::path::PathBuf>) -> Self {
        Self::File(Arc::new(FileCredential::new(path.into())))
    }

    /// Resolve the credential value NOW. Every call site that dispatches a request must use this
    /// rather than a value captured at construction.
    pub fn resolve(&self) -> Option<String> {
        match self {
            Self::Env { value, .. } => value.clone(),
            Self::File(file) => file.resolve(),
        }
    }

    /// Value-free provenance for display. Resolving is part of the status: an operator asking
    /// "which credential am I using" is asking about the one the next turn would use.
    pub fn status(&self) -> CredentialStatus {
        match self {
            Self::Env { name, value } => CredentialStatus {
                kind: CredentialKind::Env,
                name: name.clone().unwrap_or_else(|| "(direct)".into()),
                present: value.is_some(),
                expires_at_unix: None,
                error: None,
            },
            Self::File(file) => file.status(),
        }
    }

    /// The credential file backing this source, if any. The composition root adds it to the
    /// redaction set; nothing else may read it.
    pub fn file_path(&self) -> Option<&std::path::Path> {
        match self {
            Self::Env { .. } => None,
            Self::File(file) => Some(file.path()),
        }
    }
}

impl fmt::Debug for CredentialSource {
    /// Never print a credential value, not even behind a formatter an operator asked for.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = self.status();
        formatter
            .debug_struct("CredentialSource")
            .field("kind", &status.kind)
            .field("name", &status.name)
            .field("present", &status.present)
            .finish()
    }
}

/// One operator-owned credential file plus the last value read from it.
///
/// The cache exists so an unexpiring token is not re-read on a hot path forever; it is bypassed
/// as soon as the token is inside [`CREDENTIAL_REFRESH_SKEW_SECS`] of expiry, which is what makes
/// mid-session rotation work without a restart.
pub struct FileCredential {
    path: std::path::PathBuf,
    state: Mutex<Option<LoadedCredential>>,
}

#[derive(Clone)]
struct LoadedCredential {
    token: Option<String>,
    expires_at_unix: Option<u64>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialDocument {
    token: String,
    #[serde(default)]
    expires_at_unix: Option<u64>,
}

impl FileCredential {
    fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn resolve(&self) -> Option<String> {
        self.load().token
    }

    fn status(&self) -> CredentialStatus {
        let loaded = self.load();
        CredentialStatus {
            kind: CredentialKind::File,
            name: self.path.display().to_string(),
            present: loaded.token.is_some(),
            expires_at_unix: loaded.expires_at_unix,
            error: loaded.error,
        }
    }

    /// Return the cached credential when it is comfortably inside its validity window, otherwise
    /// re-read the file. A credential with no declared expiry is always re-read: that is exactly
    /// the "read at call time" behaviour the provider documentation already claimed.
    fn load(&self) -> LoadedCredential {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = unix_now();
        let usable = state.as_ref().is_some_and(|loaded| {
            loaded
                .expires_at_unix
                .is_some_and(|expiry| now.saturating_add(CREDENTIAL_REFRESH_SKEW_SECS) < expiry)
        });
        if !usable {
            *state = Some(read_credential_file(&self.path));
        }
        state.clone().unwrap_or(LoadedCredential {
            token: None,
            expires_at_unix: None,
            error: Some("credential file could not be read".into()),
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Read a credential document through a bounded, permission-checked descriptor.
///
/// A credential file is the highest-value file Core reads, so it is held to the same standard as
/// the catalog scope key: a regular file, never a symlink, never group/world readable, and small.
fn read_credential_file(path: &std::path::Path) -> LoadedCredential {
    let absent = |error: String| LoadedCredential {
        token: None,
        expires_at_unix: None,
        error: Some(error),
    };
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return absent("credential file is absent".into());
        }
        Err(_) => return absent("credential file could not be inspected".into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return absent("credential file must be a regular file, not a symlink".into());
    }
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return absent("credential file exceeds its 8 KiB bound".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return absent(
                "credential file must not be group- or world-accessible (chmod 600)".into(),
            );
        }
    }
    let Ok(bytes) = std::fs::read(path) else {
        return absent("credential file could not be read".into());
    };
    if bytes.len() as u64 > MAX_CREDENTIAL_FILE_BYTES {
        return absent("credential file exceeds its 8 KiB bound".into());
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return absent("credential file is not valid UTF-8".into());
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return absent("credential file is empty".into());
    }
    // A JSON document carries the expiry a subscription token needs; a bare line is the simple
    // BYOK case. Both are accepted, neither is guessed at: a `{` starts a document.
    if trimmed.starts_with('{') {
        return match serde_json::from_str::<CredentialDocument>(trimmed) {
            Ok(document) if !document.token.trim().is_empty() => LoadedCredential {
                token: Some(document.token.trim().to_owned()),
                expires_at_unix: document.expires_at_unix,
                error: None,
            },
            Ok(_) => absent("credential document has an empty `token`".into()),
            Err(_) => {
                absent("credential document must be {\"token\":\"…\",\"expires_at_unix\":…}".into())
            }
        };
    }
    if trimmed.lines().count() != 1 || trimmed.chars().any(char::is_whitespace) {
        return absent("credential file must hold one token line or a JSON document".into());
    }
    LoadedCredential {
        token: Some(trimmed.to_owned()),
        expires_at_unix: None,
        error: None,
    }
}

/// One configured account/gateway. A credential is intentionally omitted from Debug output.
#[derive(Clone)]
pub struct ProviderInstance {
    id: String,
    display_name: String,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    api_root: ApiRoot,
    catalog_strategy: CatalogStrategy,
    credential: CredentialSource,
    static_metadata: Arc<crate::StaticProviderMetadata>,
    prompt_cache: bool,
}

impl fmt::Debug for ProviderInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderInstance")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("adapter", &self.adapter)
            .field("error_profile", &self.error_profile)
            .field("api_root", &self.api_root)
            .field("catalog_strategy", &self.catalog_strategy)
            .field(
                "static_metadata_revision",
                &self.static_metadata.bundle_revision(),
            )
            // `CredentialSource` has a hand-written Debug that never prints a value, so this is
            // strictly better than the blanket "[REDACTED]" it replaces: kind, name and presence
            // stay visible, which is what an operator debugging a route actually needs.
            .field("credential", &self.credential)
            .field("prompt_cache", &self.prompt_cache)
            .finish()
    }
}

impl ProviderInstance {
    pub fn builtin(
        builtin: BuiltinProvider,
        credential: Option<String>,
    ) -> Result<Self, ProviderError> {
        match builtin {
            BuiltinProvider::Anthropic => Self::new(
                "anthropic",
                "Anthropic",
                AdapterKind::AnthropicMessages,
                ApiRoot::parse(ANTHROPIC_ROOT)?,
                credential,
            ),
            BuiltinProvider::OpenAi => Self::new(
                "openai",
                "OpenAI",
                AdapterKind::OpenAiResponses,
                ApiRoot::parse(OPENAI_ROOT)?,
                credential,
            ),
        }
    }

    pub fn custom(
        id: impl Into<String>,
        display_name: impl Into<String>,
        adapter: AdapterKind,
        api_root: ApiRoot,
        credential: Option<String>,
    ) -> Result<Self, ProviderError> {
        Self::new(id, display_name, adapter, api_root, credential)
    }

    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        adapter: AdapterKind,
        api_root: ApiRoot,
        credential: Option<String>,
    ) -> Result<Self, ProviderError> {
        let id = id.into();
        let display_name = display_name.into();
        if id.is_empty()
            || id.len() > MAX_INSTANCE_ID_BYTES
            || !id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(ProviderError::Configuration(
                "provider instance id is invalid".into(),
            ));
        }
        if display_name.is_empty() || display_name.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(ProviderError::Configuration(
                "provider display name is invalid".into(),
            ));
        }
        let catalog_strategy = default_catalog_strategy(adapter, &api_root)?;
        let error_profile = default_error_profile(adapter, &api_root);
        let credential = CredentialSource::env_value(credential);
        Ok(Self {
            id,
            display_name,
            adapter,
            error_profile,
            api_root,
            catalog_strategy,
            credential,
            static_metadata: crate::StaticProviderMetadata::embedded(),
            prompt_cache: true,
        })
    }

    /// Override catalog routing with an explicit, already-parsed strategy. This is the controlled
    /// seam used by local conformance tests and by future operator catalog plugins; it never
    /// derives an endpoint from a turn URL.
    pub fn with_catalog_strategy(
        mut self,
        catalog_strategy: CatalogStrategy,
    ) -> Result<Self, ProviderError> {
        validate_catalog_strategy(self.adapter, &catalog_strategy)?;
        self.catalog_strategy = catalog_strategy;
        Ok(self)
    }

    pub fn anthropic(credential: Option<String>) -> Result<Self, ProviderError> {
        Self::builtin(BuiltinProvider::Anthropic, credential)
    }

    pub fn openai(credential: Option<String>) -> Result<Self, ProviderError> {
        Self::builtin(BuiltinProvider::OpenAi, credential)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn adapter(&self) -> AdapterKind {
        self.adapter
    }

    pub fn error_profile(&self) -> ErrorProfile {
        self.error_profile
    }

    /// Explicitly select an error vocabulary for a trusted gateway. The default for an unknown
    /// root is conservative and intentionally ignores provider-specific numeric business codes.
    pub fn with_error_profile(mut self, error_profile: ErrorProfile) -> Self {
        self.error_profile = error_profile;
        self
    }

    /// Whether this route may mark prompt-cache breakpoints. Default on.
    pub fn prompt_cache(&self) -> bool {
        self.prompt_cache
    }

    /// Opt one configured route out of prompt caching.
    ///
    /// `cache_control` is part of the Anthropic Messages wire, not a per-account entitlement, so
    /// every adapter speaking that wire marks breakpoints by default. This is the escape hatch
    /// for the rare gateway that rejects the field outright rather than ignoring it; it is the
    /// operator declaring an endpoint fact, never a guess Core makes from a model name.
    pub fn with_prompt_cache(mut self, prompt_cache: bool) -> Self {
        self.prompt_cache = prompt_cache;
        self
    }

    /// Replace dated world-data snapshots while retaining the exact configured route and adapter.
    pub fn with_static_metadata(
        mut self,
        static_metadata: Arc<crate::StaticProviderMetadata>,
    ) -> Self {
        self.static_metadata = static_metadata;
        self
    }

    pub fn api_root(&self) -> &ApiRoot {
        &self.api_root
    }

    pub fn catalog_strategy(&self) -> &CatalogStrategy {
        &self.catalog_strategy
    }

    pub fn static_metadata(&self) -> &crate::StaticProviderMetadata {
        &self.static_metadata
    }

    pub fn static_metadata_handle(&self) -> Arc<crate::StaticProviderMetadata> {
        self.static_metadata.clone()
    }

    /// Replace the credential provenance while keeping the exact configured route. This is the
    /// seam a hosted subscription token uses: the composition root hands over a file source and
    /// every later resolution re-reads it.
    pub fn with_credential_source(mut self, credential: CredentialSource) -> Self {
        self.credential = credential;
        self
    }

    pub fn credential_source(&self) -> &CredentialSource {
        &self.credential
    }

    /// Value-free credential provenance for `core auth status`, `/status`, and `/config`.
    pub fn credential_status(&self) -> CredentialStatus {
        self.credential.status()
    }

    pub fn has_credential(&self) -> bool {
        self.credential.resolve().is_some()
    }

    /// Derive an opaque, installation-local scope for credential-visible catalog evidence.
    ///
    /// The credential never crosses the provider boundary. The caller supplies a random local
    /// key and persists only this HMAC alongside the catalog, so neither a raw API key nor an
    /// offline-testable naked credential hash is written to disk. Route metadata is included in
    /// the MAC input to avoid revealing that two provider instances reuse the same credential.
    pub fn catalog_cache_credential_scope(&self, local_key: &[u8; 32]) -> Option<[u8; 32]> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let credential = self.credential.resolve()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(local_key)
            .expect("HMAC-SHA256 accepts every key length");
        update_mac_part(&mut mac, b"core/catalog-cache-credential-scope/v1");
        update_mac_part(&mut mac, self.id.as_bytes());
        update_mac_part(&mut mac, self.api_root.as_str().as_bytes());
        update_mac_part(&mut mac, adapter_scope_name(self.adapter).as_bytes());
        update_mac_part(&mut mac, credential.as_bytes());
        Some(mac.finalize().into_bytes().into())
    }

    /// Construct the turn transport without exposing the credential to frontend crates.
    ///
    /// The credential is resolved HERE, per turn, not captured at construction: a file-backed
    /// subscription token that rotated since the last turn is picked up without a restart.
    pub fn build_turn_provider(&self) -> Result<Box<dyn crate::Provider>, ProviderError> {
        let credential =
            self.credential
                .resolve()
                .ok_or_else(|| ProviderError::MissingCredential {
                    provider: self.id.clone(),
                })?;
        match self.adapter {
            AdapterKind::AnthropicMessages => Ok(Box::new(
                crate::Anthropic::with_root(credential, self.api_root.clone())?
                    .with_error_profile(self.error_profile)
                    .with_static_metadata(self.static_metadata.clone())
                    .with_prompt_cache(self.prompt_cache)
                    .with_route_scope(self.id.clone())?,
            )),
            AdapterKind::OpenAiCompatibleChat => Ok(Box::new(
                crate::OpenAiCompat::with_root(credential, self.api_root.clone())?
                    .with_error_profile(self.error_profile)
                    .with_static_metadata(self.static_metadata.clone())
                    .with_route_scope(self.id.clone())?,
            )),
            AdapterKind::OpenAiResponses => Ok(Box::new(
                crate::OpenAiResponses::with_root(credential, self.api_root.clone())?
                    .with_error_profile(self.error_profile)
                    .with_route_scope(self.id.clone())?,
            )),
        }
    }

    pub(crate) fn credential(&self) -> Option<String> {
        self.credential.resolve()
    }
}

fn update_mac_part(mac: &mut hmac::Hmac<sha2::Sha256>, value: &[u8]) {
    use hmac::Mac;

    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn adapter_scope_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::AnthropicMessages => "anthropic_messages",
        AdapterKind::OpenAiCompatibleChat => "openai_chat",
        AdapterKind::OpenAiResponses => "openai_responses",
    }
}

fn default_error_profile(adapter: AdapterKind, api_root: &ApiRoot) -> ErrorProfile {
    match api_root.as_str() {
        ANTHROPIC_ROOT if adapter == AdapterKind::AnthropicMessages => ErrorProfile::Anthropic,
        OPENAI_ROOT if adapter == AdapterKind::OpenAiResponses => ErrorProfile::OpenAi,
        DEEPSEEK_ROOT | DEEPSEEK_V1_ROOT => ErrorProfile::DeepSeek,
        GLM_STANDARD_ROOT | GLM_CODING_ROOT | GLM_ANTHROPIC_ROOT => ErrorProfile::Glm,
        MINIMAX_ROOT | MINIMAX_LEGACY_ROOT => ErrorProfile::MiniMax,
        FIREWORKS_INFERENCE_ROOT => ErrorProfile::Fireworks,
        _ => ErrorProfile::CustomConservative,
    }
}

fn default_catalog_strategy(
    adapter: AdapterKind,
    api_root: &ApiRoot,
) -> Result<CatalogStrategy, ProviderError> {
    let strategy = match api_root.as_str() {
        FIREWORKS_INFERENCE_ROOT => CatalogStrategy::FireworksControlPlane {
            api_root: ApiRoot::parse(FIREWORKS_CONTROL_PLANE_ROOT)?,
        },
        GLM_STANDARD_ROOT | GLM_CODING_ROOT | GLM_ANTHROPIC_ROOT => CatalogStrategy::Unsupported {
            reason: GLM_UNSUPPORTED_CATALOG_REASON.into(),
        },
        _ => match adapter {
            AdapterKind::AnthropicMessages => CatalogStrategy::AnthropicModels,
            AdapterKind::OpenAiCompatibleChat | AdapterKind::OpenAiResponses => {
                CatalogStrategy::OpenAiModels
            }
        },
    };
    validate_catalog_strategy(adapter, &strategy)?;
    Ok(strategy)
}

fn validate_catalog_strategy(
    adapter: AdapterKind,
    strategy: &CatalogStrategy,
) -> Result<(), ProviderError> {
    let valid = match strategy {
        CatalogStrategy::AnthropicModels => adapter == AdapterKind::AnthropicMessages,
        CatalogStrategy::OpenAiModels => adapter != AdapterKind::AnthropicMessages,
        CatalogStrategy::FireworksControlPlane { .. } => {
            adapter == AdapterKind::OpenAiCompatibleChat
        }
        CatalogStrategy::Unsupported { .. } => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Configuration(
            "catalog strategy is incompatible with the turn adapter".into(),
        ))
    }
}

/// Known account usability. `Unknown` is not equivalent to funded: most providers expose no
/// safe balance API for normal API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAvailability {
    Unknown,
    Discovering,
    Ready,
    MissingCredential,
    AuthenticationBlocked,
    BillingBlocked,
    PermissionBlocked,
    RateLimited,
    Degraded,
    ConfigurationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceAvailability {
    Unknown,
    Sufficient,
    Depleted,
}

/// Optional account probes admitted only where a provider documents a normal-key balance API.
/// Most providers intentionally have no variant and remain `BalanceAvailability::Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountProbe {
    DeepSeekBalance,
    /// Read Fireworks' documented account control-plane `suspendState`; this does not make an
    /// inference request and does not guess remaining credit from ordinary usage metadata.
    FireworksSuspendState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountProbeResult {
    pub availability: AccountAvailability,
    pub balance: BalanceAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RawModel {
    pub id: String,
    pub display_name: Option<String>,
    pub created_at: Option<String>,
    pub owned_by: Option<String>,
    /// Model-level evidence from the provider catalog. `None` is unknown, never false.
    pub supports_image_input: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Compatibility {
    Compatible,
    Unknown,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selectability {
    Selectable,
    Disabled { reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModelDescriptor {
    pub raw: RawModel,
    pub family_id: String,
    pub compatibility: Compatibility,
    pub selectability: Selectability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelFamily {
    pub id: String,
    pub display_name: String,
    pub models: Vec<ModelDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSnapshot {
    pub provider_instance_id: String,
    pub adapter: AdapterKind,
    pub models: Vec<ModelDescriptor>,
    pub families: Vec<ModelFamily>,
}

impl CatalogSnapshot {
    fn from_raw(instance: &ProviderInstance, raw_models: Vec<RawModel>) -> Self {
        let models = raw_models
            .into_iter()
            .map(|raw| describe_model(instance.adapter, raw))
            .collect();
        Self::from_descriptors(instance, models)
    }

    fn from_descriptors(instance: &ProviderInstance, models: Vec<ModelDescriptor>) -> Self {
        let mut deduped = BTreeMap::<String, ModelDescriptor>::new();
        for model in models {
            // Choose a canonical lexicographic record for duplicate ids so output is independent
            // of provider page/response order, even if duplicate metadata is inconsistent.
            deduped
                .entry(model.raw.id.clone())
                .and_modify(|current| {
                    if model < *current {
                        *current = model.clone();
                    }
                })
                .or_insert(model);
        }
        let models: Vec<ModelDescriptor> = deduped.into_values().collect();
        let mut grouped = BTreeMap::<String, Vec<ModelDescriptor>>::new();
        for model in &models {
            grouped
                .entry(model.family_id.clone())
                .or_default()
                .push(model.clone());
        }
        let families = grouped
            .into_iter()
            .map(|(id, mut models)| {
                models.sort_by(|left, right| left.raw.id.cmp(&right.raw.id));
                ModelFamily {
                    display_name: family_display_name(&id),
                    id,
                    models,
                }
            })
            .collect();
        Self {
            provider_instance_id: instance.id.clone(),
            adapter: instance.adapter,
            models,
            families,
        }
    }
}

/// Construct the documented GLM standard Chat Completions catalog without network access.
///
/// The returned leaves are endpoint-compatible schema entries, not credential-visible inventory.
/// This function therefore does not inspect credentials or mutate `ProviderHealthStore`; callers
/// must retain `AccountAvailability::Unknown` unless a separate request supplies stronger evidence.
pub fn glm_standard_schema_catalog(
    instance: &ProviderInstance,
) -> Result<CatalogSnapshot, ProviderError> {
    let manifest = instance.static_metadata();
    if instance.api_root.as_str() != manifest.glm_api_root()
        || instance.adapter != AdapterKind::OpenAiCompatibleChat
    {
        return Err(ProviderError::Configuration(
            "GLM standard schema manifest requires the exact standard Chat Completions root and adapter"
                .into(),
        ));
    }
    let models = manifest
        .glm_models()
        .iter()
        .map(|model_id| RawModel {
            id: model_id.clone(),
            display_name: Some(model_id.clone()),
            created_at: None,
            owned_by: None,
            supports_image_input: None,
        })
        .map(|raw| describe_model(instance.adapter, raw))
        .collect();
    Ok(CatalogSnapshot::from_descriptors(instance, models))
}

/// Discover all models visible to the configured credential within strict request, page, byte,
/// model, and wall-clock bounds. Missing credentials return before a client/request is created.
pub async fn discover_catalog(
    instance: &ProviderInstance,
) -> Result<CatalogSnapshot, ProviderError> {
    if let CatalogStrategy::Unsupported { reason } = &instance.catalog_strategy {
        return Err(ProviderError::UnsupportedCatalog {
            provider: instance.id.clone(),
            reason: reason.clone(),
        });
    }
    let credential = instance
        .credential()
        .ok_or_else(|| ProviderError::MissingCredential {
            provider: instance.id.clone(),
        })?;
    let client = reqwest::Client::builder()
        .connect_timeout(PER_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ProviderError::Configuration("HTTP client could not be built".into()))?;
    let deadline = Instant::now() + TOTAL_DISCOVERY_TIMEOUT;
    match &instance.catalog_strategy {
        CatalogStrategy::AnthropicModels => {
            let raw = discover_anthropic(&client, instance, &credential, deadline).await?;
            Ok(CatalogSnapshot::from_raw(instance, raw))
        }
        CatalogStrategy::OpenAiModels => {
            let raw = discover_openai(&client, instance, &credential, deadline).await?;
            Ok(CatalogSnapshot::from_raw(instance, raw))
        }
        CatalogStrategy::FireworksControlPlane { api_root } => {
            let models =
                discover_fireworks(&client, instance, &credential, api_root, deadline).await?;
            Ok(CatalogSnapshot::from_descriptors(instance, models))
        }
        CatalogStrategy::Unsupported { .. } => unreachable!("handled before credential lookup"),
    }
}

/// Run a documented, bounded account probe. DeepSeek's balance endpoint is rooted at the
/// provider origin (`/user/balance`), not below the model API root (`/v1`). Fireworks account
/// state comes from the separately documented control plane selected by `CatalogStrategy`.
pub async fn probe_account(
    instance: &ProviderInstance,
    probe: AccountProbe,
) -> Result<AccountProbeResult, ProviderError> {
    let credential = instance
        .credential()
        .ok_or_else(|| ProviderError::MissingCredential {
            provider: instance.id.clone(),
        })?;
    let client = reqwest::Client::builder()
        .connect_timeout(PER_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ProviderError::Configuration("HTTP client could not be built".into()))?;
    match probe {
        AccountProbe::DeepSeekBalance => {
            let endpoint = instance.api_root.origin_endpoint("user/balance")?;
            tokio::time::timeout(PER_REQUEST_TIMEOUT, async {
                let response = client
                    .get(endpoint)
                    .bearer_auth(credential)
                    .send()
                    .await
                    .map_err(|error| ProviderError::Http(error.to_string()))?;
                if !response.status().is_success() {
                    return Err(api_error_from_response(
                        response,
                        instance.adapter,
                        instance.error_profile,
                    )
                    .await);
                }
                let bytes =
                    read_bounded_response(response, MAX_ACCOUNT_PROBE_PAGE_BYTES, "account probe")
                        .await?;
                let payload: DeepSeekBalance = serde_json::from_slice(&bytes).map_err(|error| {
                    ProviderError::Decode(format!("malformed DeepSeek balance response: {error}"))
                })?;
                Ok(deepseek_probe_result(payload.is_available))
            })
            .await
            .map_err(|_| ProviderError::Http("account probe timed out".into()))?
        }
        AccountProbe::FireworksSuspendState => {
            let CatalogStrategy::FireworksControlPlane { api_root } = &instance.catalog_strategy
            else {
                return Err(ProviderError::Configuration(
                    "Fireworks account probe requires an explicit Fireworks control-plane strategy"
                        .into(),
                ));
            };
            probe_fireworks_accounts(&client, instance, &credential, api_root).await
        }
    }
}

#[derive(Deserialize)]
struct DeepSeekBalance {
    is_available: bool,
}

fn deepseek_probe_result(is_available: bool) -> AccountProbeResult {
    if is_available {
        AccountProbeResult {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Sufficient,
        }
    } else {
        AccountProbeResult {
            availability: AccountAvailability::BillingBlocked,
            balance: BalanceAvailability::Depleted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksRpcStatus {
    code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksAccount {
    name: String,
    state: Option<String>,
    status: Option<FireworksRpcStatus>,
    suspend_state: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksAccountsPage {
    accounts: Vec<FireworksAccount>,
    next_page_token: Option<String>,
}

async fn probe_fireworks_accounts(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
) -> Result<AccountProbeResult, ProviderError> {
    let endpoint = control_plane_root.endpoint("accounts")?;
    let deadline = Instant::now() + TOTAL_DISCOVERY_TIMEOUT;
    let mut accounts = Vec::new();
    let mut total_bytes = 0usize;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    for page_number in 0..MAX_ACCOUNT_PAGES {
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[("pageSize", FIREWORKS_PAGE_SIZE.to_string())])
            .query(&[("readMask", "name,state,status,suspendState")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_account_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            total_bytes,
        )
        .await?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ProviderError::Decode("account probe byte counter overflow".into()))?;
        let page: FireworksAccountsPage = serde_json::from_slice(&bytes).map_err(|error| {
            ProviderError::Decode(format!("malformed Fireworks accounts response: {error}"))
        })?;
        for account in page.accounts {
            validate_model_text(&account.name, MAX_MODEL_ID_BYTES, "account name")?;
            accounts.push(account);
            if accounts.len() > MAX_ACCOUNTS {
                return Err(ProviderError::Decode(
                    "Fireworks account probe exceeded account bound".into(),
                ));
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks accounts",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(aggregate_fireworks_accounts(accounts));
        };
        cursor = Some(next);
        if page_number + 1 == MAX_ACCOUNT_PAGES {
            return Err(ProviderError::Decode(
                "Fireworks account probe exceeded page bound".into(),
            ));
        }
    }
    Err(ProviderError::Decode(
        "Fireworks account probe exceeded page bound".into(),
    ))
}

async fn execute_account_request(
    request: reqwest::RequestBuilder,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    deadline: Instant,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::Http("account probe timed out".into()));
    }
    let timeout = remaining.min(PER_REQUEST_TIMEOUT);
    let bytes = tokio::time::timeout(timeout, async move {
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        if !response.status().is_success() {
            return Err(api_error_from_response(response, adapter, error_profile).await);
        }
        read_bounded_response(response, MAX_ACCOUNT_PROBE_PAGE_BYTES, "account probe page").await
    })
    .await
    .map_err(|_| ProviderError::Http("account probe request timed out".into()))??;
    let total = total_bytes_before
        .checked_add(bytes.len())
        .ok_or_else(|| ProviderError::Decode("account probe total size overflow".into()))?;
    if total > MAX_ACCOUNT_PROBE_TOTAL_BYTES {
        return Err(ProviderError::Decode(
            "account probe exceeded total byte bound".into(),
        ));
    }
    Ok(bytes)
}

fn aggregate_fireworks_accounts(accounts: Vec<FireworksAccount>) -> AccountProbeResult {
    let mut by_account = BTreeMap::<String, AccountProbeResult>::new();
    for account in accounts {
        let result = fireworks_account_result(
            account.state.as_deref(),
            account
                .status
                .as_ref()
                .and_then(|status| status.code.as_deref()),
            account.suspend_state.as_deref(),
        );
        by_account
            .entry(account.name)
            .and_modify(|current| {
                if *current != result {
                    // Repeated resource names with inconsistent snapshots are not authoritative.
                    *current = unknown_account_probe_result();
                }
            })
            .or_insert(result);
    }
    let mut results = by_account.into_values();
    let Some(first) = results.next() else {
        return unknown_account_probe_result();
    };
    if results.all(|result| result == first) {
        first
    } else {
        // A key may expose more than one account. Conflicting account states do not identify which
        // one funds inference, so collapsing them to either funded or depleted would be a guess.
        unknown_account_probe_result()
    }
}

fn fireworks_account_result(
    state: Option<&str>,
    status_code: Option<&str>,
    suspend_state: Option<&str>,
) -> AccountProbeResult {
    match suspend_state {
        Some("FAILED_PAYMENTS" | "CREDIT_DEPLETED" | "MONTHLY_SPEND_LIMIT_EXCEEDED") => {
            AccountProbeResult {
                availability: AccountAvailability::BillingBlocked,
                balance: BalanceAvailability::Depleted,
            }
        }
        Some("BLOCKED_BY_ABUSE_RULE") => AccountProbeResult {
            availability: AccountAvailability::PermissionBlocked,
            balance: BalanceAvailability::Unknown,
        },
        Some("UNSUSPENDED") if state == Some("READY") && status_code == Some("OK") => {
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                // Not suspended is not proof of an exact positive remaining balance.
                balance: BalanceAvailability::Unknown,
            }
        }
        _ => unknown_account_probe_result(),
    }
}

fn unknown_account_probe_result() -> AccountProbeResult {
    AccountProbeResult {
        availability: AccountAvailability::Unknown,
        balance: BalanceAvailability::Unknown,
    }
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::with_capacity(4096.min(max_bytes));
    let mut stream = response.bytes_stream();
    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| ProviderError::Http(error.to_string()))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ProviderError::Decode(format!(
                "{label} response exceeded byte bound"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn discover_anthropic(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    deadline: Instant,
) -> Result<Vec<RawModel>, ProviderError> {
    let endpoint = instance.api_root.endpoint("models")?;
    let mut models = Vec::new();
    let mut total_bytes = 0usize;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    for page_number in 0..MAX_CATALOG_PAGES {
        let mut request = client
            .get(endpoint.clone())
            .header("x-api-key", credential)
            .header("anthropic-version", "2023-06-01")
            .query(&[("limit", CATALOG_PAGE_SIZE.to_string())]);
        if let Some(after_id) = &cursor {
            request = request.query(&[("after_id", after_id)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            total_bytes,
        )
        .await?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ProviderError::Decode("catalog byte counter overflow".into()))?;
        let page: AnthropicModelsPage = decode_page(&bytes, total_bytes)?;
        for model in page.data {
            models.push(raw_anthropic_model(model)?);
            enforce_model_bound(models.len())?;
        }
        let Some(next) = advance_anthropic_cursor(
            cursor.as_deref(),
            &mut seen_cursors,
            page.has_more,
            page.last_id,
        )?
        else {
            return Ok(models);
        };
        cursor = Some(next);
        if page_number + 1 == MAX_CATALOG_PAGES {
            return Err(ProviderError::Decode(
                "Anthropic catalog exceeded page bound".into(),
            ));
        }
    }
    Err(ProviderError::Decode(
        "Anthropic catalog exceeded page bound".into(),
    ))
}

fn advance_anthropic_cursor(
    current: Option<&str>,
    seen: &mut BTreeSet<String>,
    has_more: bool,
    last_id: Option<String>,
) -> Result<Option<String>, ProviderError> {
    if !has_more {
        return Ok(None);
    }
    let next = last_id.filter(|value| !value.is_empty()).ok_or_else(|| {
        ProviderError::Decode("Anthropic catalog has_more without last_id".into())
    })?;
    if current == Some(next.as_str()) || !seen.insert(next.clone()) {
        return Err(ProviderError::Decode(
            "Anthropic catalog cursor did not advance".into(),
        ));
    }
    Ok(Some(next))
}

async fn discover_openai(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    deadline: Instant,
) -> Result<Vec<RawModel>, ProviderError> {
    let request = client
        .get(instance.api_root.endpoint("models")?)
        .bearer_auth(credential);
    let bytes = execute_catalog_request(
        request,
        instance.adapter,
        instance.error_profile,
        deadline,
        0,
    )
    .await?;
    let page: OpenAiModelsPage = decode_page(&bytes, bytes.len())?;
    enforce_model_bound(page.data.len())?;
    page.data.into_iter().map(raw_openai_model).collect()
}

async fn discover_fireworks(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    deadline: Instant,
) -> Result<Vec<ModelDescriptor>, ProviderError> {
    // Fireworks documents public serverless inventory under `accounts/fireworks/models`. It also
    // documents List Accounts and account-scoped List Models. Enumerating those private model
    // resources is safe. Dedicated deployment selectability is admitted only when List Deployed
    // Models returns a healthy default deployment, because only that documented state permits the
    // full model resource to be queried without inventing a `#deployment` routing suffix.
    let mut budget = FireworksCatalogBudget::default();
    let mut models = BTreeMap::new();
    discover_fireworks_models_at(
        client,
        instance,
        credential,
        control_plane_root,
        FIREWORKS_SERVERLESS_MODELS_PATH,
        Some(FIREWORKS_SERVERLESS_FILTER),
        FireworksModelScope::PublicServerless,
        "accounts/fireworks",
        None,
        None,
        deadline,
        &mut budget,
        &mut models,
    )
    .await?;

    let accounts = discover_fireworks_catalog_accounts(
        client,
        instance,
        credential,
        control_plane_root,
        deadline,
        &mut budget,
    )
    .await?;
    for (account, account_state) in accounts {
        if account == "accounts/fireworks" {
            continue;
        }
        let default_deployed_models = discover_fireworks_default_deployments(
            client,
            instance,
            credential,
            control_plane_root,
            &account,
            deadline,
            &mut budget,
        )
        .await?;
        discover_fireworks_models_at(
            client,
            instance,
            credential,
            control_plane_root,
            &format!("{account}/models"),
            None,
            FireworksModelScope::AccountPrivate,
            &account,
            Some(account_state),
            Some(&default_deployed_models),
            deadline,
            &mut budget,
            &mut models,
        )
        .await?;
    }
    Ok(models.into_values().collect())
}

#[derive(Default)]
struct FireworksCatalogBudget {
    pages: usize,
    total_bytes: usize,
    models: usize,
    deployed_models: usize,
}

impl FireworksCatalogBudget {
    fn record_page(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| ProviderError::Decode("catalog page counter overflow".into()))?;
        if self.pages > MAX_FIREWORKS_CATALOG_PAGES {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| ProviderError::Decode("catalog byte counter overflow".into()))?;
        if self.total_bytes > MAX_TOTAL_BYTES {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate byte bound".into(),
            ));
        }
        Ok(())
    }

    fn record_model(&mut self) -> Result<(), ProviderError> {
        self.models = self
            .models
            .checked_add(1)
            .ok_or_else(|| ProviderError::Decode("catalog model counter overflow".into()))?;
        enforce_model_bound(self.models)
    }

    fn record_deployed_model(&mut self) -> Result<(), ProviderError> {
        self.deployed_models = self.deployed_models.checked_add(1).ok_or_else(|| {
            ProviderError::Decode("Fireworks deployed-model counter overflow".into())
        })?;
        if self.deployed_models > MAX_FIREWORKS_DEPLOYED_MODELS {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded deployed-model bound".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FireworksModelScope {
    PublicServerless,
    AccountPrivate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FireworksCatalogAccountState {
    result: AccountProbeResult,
    conflicting: bool,
}

#[allow(clippy::too_many_arguments)]
async fn discover_fireworks_models_at(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    resource_path: &str,
    filter: Option<&str>,
    scope: FireworksModelScope,
    expected_account: &str,
    account_state: Option<FireworksCatalogAccountState>,
    default_deployed_models: Option<&BTreeSet<String>>,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
    models: &mut BTreeMap<String, ModelDescriptor>,
) -> Result<(), ProviderError> {
    let expected_owner = fireworks_account_id(expected_account)?;
    let endpoint = control_plane_root.endpoint(resource_path)?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    loop {
        if budget.pages >= MAX_FIREWORKS_CATALOG_PAGES {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[("pageSize", FIREWORKS_PAGE_SIZE.to_string())]);
        if let Some(filter) = filter {
            request = request.query(&[("filter", filter)]);
        }
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksModelsPage = decode_page(&bytes, budget.total_bytes)?;
        for model in page.models {
            budget.record_model()?;
            validate_fireworks_model_parent(&model.name, expected_owner, "model")?;
            let has_default_deployment =
                default_deployed_models.is_some_and(|deployed| deployed.contains(&model.name));
            merge_fireworks_descriptor(
                models,
                describe_fireworks_model(model, scope, account_state, has_default_deployment)?,
            );
        }
        let Some(next) = advance_page_token(
            "Fireworks models",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(());
        };
        cursor = Some(next);
    }
}

async fn discover_fireworks_default_deployments(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    account: &str,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
) -> Result<BTreeSet<String>, ProviderError> {
    validate_fireworks_account_name(account)?;
    let endpoint = control_plane_root.endpoint(&format!("{account}/deployedModels"))?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    // A model may have many named deployments, but Fireworks documents at most one effective
    // default route. Multiple default records are inconsistent control-plane evidence and fail
    // closed for that model leaf.
    let mut default_evidence = BTreeMap::<String, bool>::new();

    loop {
        if budget.pages >= MAX_FIREWORKS_CATALOG_PAGES {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[("pageSize", FIREWORKS_PAGE_SIZE.to_string())])
            .query(&[("readMask", "name,model,deployment,default,state,status")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksDeployedModelsPage = decode_page(&bytes, budget.total_bytes)?;
        for deployed in page.deployed_models {
            budget.record_deployed_model()?;
            validate_fireworks_scoped_resource_name(
                &deployed.name,
                account,
                "deployedModels",
                "deployed model",
            )?;
            validate_fireworks_scoped_resource_name(
                &deployed.deployment,
                account,
                "deployments",
                "deployment",
            )?;
            validate_fireworks_model_parent(
                &deployed.model,
                fireworks_account_id(account)?,
                "deployed model",
            )?;
            if deployed.is_default {
                let healthy = deployed.state.as_deref() == Some("DEPLOYED")
                    && deployed
                        .status
                        .as_ref()
                        .and_then(|status| status.code.as_deref())
                        == Some("OK");
                use std::collections::btree_map::Entry;
                match default_evidence.entry(deployed.model) {
                    Entry::Vacant(entry) => {
                        entry.insert(healthy);
                    }
                    Entry::Occupied(mut entry) => {
                        // Duplicate defaults are ambiguous even if both currently look healthy.
                        entry.insert(false);
                    }
                }
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks deployed models",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(default_evidence
                .into_iter()
                .filter_map(|(model, healthy)| healthy.then_some(model))
                .collect());
        };
        cursor = Some(next);
    }
}

async fn discover_fireworks_catalog_accounts(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
) -> Result<BTreeMap<String, FireworksCatalogAccountState>, ProviderError> {
    let endpoint = control_plane_root.endpoint("accounts")?;
    let mut accounts = BTreeMap::<String, FireworksCatalogAccountState>::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    loop {
        if budget.pages >= MAX_FIREWORKS_CATALOG_PAGES {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[("pageSize", FIREWORKS_PAGE_SIZE.to_string())])
            .query(&[("readMask", "name,state,status,suspendState")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksAccountsPage = decode_page(&bytes, budget.total_bytes)?;
        for account in page.accounts {
            validate_fireworks_account_name(&account.name)?;
            let result = fireworks_account_result(
                account.state.as_deref(),
                account
                    .status
                    .as_ref()
                    .and_then(|status| status.code.as_deref()),
                account.suspend_state.as_deref(),
            );
            accounts
                .entry(account.name)
                .and_modify(|current| {
                    if current.result != result {
                        current.result = unknown_account_probe_result();
                        current.conflicting = true;
                    }
                })
                .or_insert(FireworksCatalogAccountState {
                    result,
                    conflicting: false,
                });
            if accounts.len() > MAX_FIREWORKS_CATALOG_ACCOUNTS {
                return Err(ProviderError::Decode(
                    "Fireworks catalog exceeded account bound".into(),
                ));
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks catalog accounts",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(accounts);
        };
        cursor = Some(next);
    }
}

fn merge_fireworks_descriptor(
    models: &mut BTreeMap<String, ModelDescriptor>,
    descriptor: ModelDescriptor,
) {
    use std::collections::btree_map::Entry;
    match models.entry(descriptor.raw.id.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(descriptor);
        }
        Entry::Occupied(mut entry) if entry.get() != &descriptor => {
            let raw = std::cmp::min(entry.get().raw.clone(), descriptor.raw);
            entry.insert(ModelDescriptor {
                family_id: model_family(&raw.id),
                raw,
                compatibility: Compatibility::Unknown,
                selectability: Selectability::Disabled {
                    reason: "Fireworks returned conflicting metadata for this model",
                },
            });
        }
        Entry::Occupied(_) => {}
    }
}

fn advance_page_token(
    label: &'static str,
    current: Option<&str>,
    seen: &mut BTreeSet<String>,
    next: Option<String>,
) -> Result<Option<String>, ProviderError> {
    let Some(next) = next.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if next.len() > MAX_PAGE_TOKEN_BYTES || next.chars().any(char::is_control) {
        return Err(ProviderError::Decode(format!(
            "{label} page token is invalid"
        )));
    }
    if current == Some(next.as_str()) || !seen.insert(next.clone()) {
        return Err(ProviderError::Decode(format!(
            "{label} page token did not advance"
        )));
    }
    Ok(Some(next))
}

async fn execute_catalog_request(
    request: reqwest::RequestBuilder,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    deadline: Instant,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::Http("catalog discovery timed out".into()));
    }
    let timeout = remaining.min(PER_REQUEST_TIMEOUT);
    tokio::time::timeout(timeout, async move {
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        if !response.status().is_success() {
            return Err(api_error_from_response(response, adapter, error_profile).await);
        }
        read_catalog_body(response, total_bytes_before).await
    })
    .await
    .map_err(|_| ProviderError::Http("catalog request timed out".into()))?
}

async fn read_catalog_body(
    response: reqwest::Response,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::with_capacity(16 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| ProviderError::Http(error.to_string()))?;
        let page_size = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| ProviderError::Decode("catalog page size overflow".into()))?;
        let total_size = total_bytes_before
            .checked_add(page_size)
            .ok_or_else(|| ProviderError::Decode("catalog total size overflow".into()))?;
        if page_size > MAX_PAGE_BYTES {
            return Err(ProviderError::Decode(
                "provider catalog page exceeded 2 MiB".into(),
            ));
        }
        if total_size > MAX_TOTAL_BYTES {
            return Err(ProviderError::Decode(
                "provider catalog exceeded 8 MiB".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn decode_page<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    total_bytes: usize,
) -> Result<T, ProviderError> {
    if bytes.len() > MAX_PAGE_BYTES || total_bytes > MAX_TOTAL_BYTES {
        return Err(ProviderError::Decode(
            "provider catalog response exceeded byte bounds".into(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| ProviderError::Decode(format!("malformed provider catalog: {error}")))
}

fn enforce_model_bound(count: usize) -> Result<(), ProviderError> {
    if count > MAX_CATALOG_MODELS {
        Err(ProviderError::Decode(
            "provider catalog exceeded model bound".into(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
struct AnthropicModelsPage {
    data: Vec<AnthropicModel>,
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicModel {
    id: String,
    display_name: Option<String>,
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct OpenAiModelsPage {
    data: Vec<OpenAiModel>,
}

#[derive(Deserialize)]
struct OpenAiModel {
    id: String,
    created: Option<u64>,
    owned_by: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksModelsPage {
    models: Vec<FireworksModel>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksDeployedModelsPage {
    deployed_models: Vec<FireworksDeployedModel>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksDeployedModel {
    name: String,
    model: String,
    deployment: String,
    #[serde(rename = "default", default)]
    is_default: bool,
    state: Option<String>,
    status: Option<FireworksRpcStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksBaseModelDetails {
    model_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksModel {
    name: String,
    display_name: Option<String>,
    create_time: Option<String>,
    state: Option<String>,
    status: Option<FireworksRpcStatus>,
    kind: Option<String>,
    base_model_details: Option<FireworksBaseModelDetails>,
    public: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_conversation_config")]
    conversation_config: bool,
    supports_tools: Option<bool>,
    supports_serverless: Option<bool>,
    supports_image_input: Option<bool>,
}

fn deserialize_conversation_config<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(false),
        Some(serde_json::Value::Object(_)) => Ok(true),
        Some(_) => Err(serde::de::Error::custom(
            "Fireworks conversationConfig must be an object or null",
        )),
    }
}

fn raw_anthropic_model(model: AnthropicModel) -> Result<RawModel, ProviderError> {
    validate_model_text(&model.id, MAX_MODEL_ID_BYTES, "model id")?;
    if let Some(display_name) = &model.display_name {
        validate_model_text(display_name, MAX_DISPLAY_NAME_BYTES, "model display name")?;
    }
    Ok(RawModel {
        id: model.id,
        display_name: model.display_name,
        created_at: model.created_at,
        owned_by: Some("anthropic".into()),
        supports_image_input: None,
    })
}

fn raw_openai_model(model: OpenAiModel) -> Result<RawModel, ProviderError> {
    validate_model_text(&model.id, MAX_MODEL_ID_BYTES, "model id")?;
    if let Some(owner) = &model.owned_by {
        validate_model_text(owner, MAX_DISPLAY_NAME_BYTES, "model owner")?;
    }
    Ok(RawModel {
        display_name: Some(model.id.clone()),
        id: model.id,
        created_at: model.created.map(|value| value.to_string()),
        owned_by: model.owned_by,
        supports_image_input: None,
    })
}

fn describe_fireworks_model(
    model: FireworksModel,
    scope: FireworksModelScope,
    account_state: Option<FireworksCatalogAccountState>,
    has_default_deployment: bool,
) -> Result<ModelDescriptor, ProviderError> {
    validate_model_text(&model.name, MAX_MODEL_ID_BYTES, "model id")?;
    if let Some(display_name) = &model.display_name {
        validate_model_text(display_name, MAX_DISPLAY_NAME_BYTES, "model display name")?;
    }
    let (owner, _) = parse_fireworks_model_name(&model.name)?;
    let owned_by = Some(owner.to_string());

    let incompatible_kind = model.kind.as_deref() == Some("EMBEDDING_MODEL");
    let incompatible_type = model
        .base_model_details
        .as_ref()
        .and_then(|details| details.model_type.as_deref())
        .is_some_and(non_agent_model_type);
    let compatibility = if incompatible_kind
        || incompatible_type
        || !model.conversation_config
        || model.supports_tools != Some(true)
    {
        Compatibility::Incompatible
    } else {
        Compatibility::Compatible
    };

    let selectability = if account_state.is_some_and(|state| state.conflicting) {
        Selectability::Disabled {
            reason: "Fireworks account metadata is conflicting",
        }
    } else if account_state.is_some_and(|state| {
        state.result.balance == BalanceAvailability::Depleted
            || state.result.availability == AccountAvailability::BillingBlocked
    }) {
        Selectability::Disabled {
            reason: "Fireworks account billing is blocked",
        }
    } else if account_state
        .is_some_and(|state| state.result.availability == AccountAvailability::PermissionBlocked)
    {
        Selectability::Disabled {
            reason: "Fireworks account permission is blocked",
        }
    } else if model.state.as_deref() != Some("READY") {
        Selectability::Disabled {
            reason: "Fireworks model is not ready",
        }
    } else if model
        .status
        .as_ref()
        .and_then(|status| status.code.as_deref())
        != Some("OK")
    {
        Selectability::Disabled {
            reason: "Fireworks model status is not OK",
        }
    } else if model.supports_serverless != Some(true)
        && !(scope == FireworksModelScope::AccountPrivate && has_default_deployment)
    {
        Selectability::Disabled {
            reason: match scope {
                FireworksModelScope::PublicServerless => {
                    "Fireworks model has no serverless deployment"
                }
                FireworksModelScope::AccountPrivate => {
                    "private model has no healthy default deployment; Core does not infer #deployment routing"
                }
            },
        }
    } else if scope == FireworksModelScope::PublicServerless && model.public != Some(true) {
        Selectability::Disabled {
            reason: "Fireworks public catalog model is not marked public",
        }
    } else if !model.conversation_config {
        Selectability::Disabled {
            reason: "Fireworks Chat Completions is not enabled for this model",
        }
    } else if incompatible_kind || incompatible_type {
        Selectability::Disabled {
            reason: "model is not a coding-turn model",
        }
    } else if model.supports_tools != Some(true) {
        Selectability::Disabled {
            reason: "Fireworks model does not advertise tool calling",
        }
    } else {
        Selectability::Selectable
    };

    let raw = RawModel {
        id: model.name,
        display_name: model.display_name,
        created_at: model.create_time,
        owned_by,
        supports_image_input: model.supports_image_input,
    };
    Ok(ModelDescriptor {
        family_id: model_family(&raw.id),
        raw,
        compatibility,
        selectability,
    })
}

fn validate_fireworks_account_name(account_name: &str) -> Result<(), ProviderError> {
    fireworks_account_id(account_name).map(|_| ())
}

fn fireworks_account_id(account_name: &str) -> Result<&str, ProviderError> {
    let mut segments = account_name.split('/');
    let (Some("accounts"), Some(account), None) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    };
    if !valid_fireworks_resource_id(account) {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    }
    Ok(account)
}

fn validate_fireworks_scoped_resource_name(
    resource_name: &str,
    account_name: &str,
    collection: &str,
    label: &str,
) -> Result<(), ProviderError> {
    let mut account_segments = account_name.split('/');
    let (Some("accounts"), Some(expected_account), None) = (
        account_segments.next(),
        account_segments.next(),
        account_segments.next(),
    ) else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    };
    let mut segments = resource_name.split('/');
    let valid = matches!(segments.next(), Some("accounts"))
        && segments.next() == Some(expected_account)
        && segments.next() == Some(collection)
        && segments.next().is_some_and(valid_fireworks_resource_id)
        && segments.next().is_none();
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Decode(format!(
            "Fireworks returned an invalid {label} resource name"
        )))
    }
}

fn parse_fireworks_model_name(model_name: &str) -> Result<(&str, &str), ProviderError> {
    let mut segments = model_name.split('/');
    let (Some("accounts"), Some(account), Some("models"), Some(model_id), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid full model resource name".into(),
        ));
    };
    if !valid_fireworks_resource_id(account) || !valid_fireworks_resource_id(model_id) {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid full model resource name".into(),
        ));
    }
    Ok((account, model_id))
}

fn validate_fireworks_model_parent(
    model_name: &str,
    expected_account: &str,
    label: &str,
) -> Result<(), ProviderError> {
    let (actual_account, _) = parse_fireworks_model_name(model_name)?;
    if actual_account != expected_account {
        return Err(ProviderError::Decode(format!(
            "Fireworks {label} resource escaped its requested account parent"
        )));
    }
    Ok(())
}

fn valid_fireworks_resource_id(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn non_agent_model_type(model_type: &str) -> bool {
    let model_type = model_type.to_ascii_lowercase();
    [
        "embedding",
        "rerank",
        "image",
        "audio",
        "video",
        "speech",
        "moderation",
    ]
    .iter()
    .any(|marker| model_type.contains(marker))
}

fn validate_model_text(value: &str, max_bytes: usize, field: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ProviderError::Decode(format!(
            "provider catalog {field} is invalid"
        )));
    }
    Ok(())
}

fn describe_model(adapter: AdapterKind, raw: RawModel) -> ModelDescriptor {
    let family_id = model_family(&raw.id);
    let compatibility = compatibility(adapter, &raw.id);
    let selectability = match compatibility {
        Compatibility::Compatible => Selectability::Selectable,
        Compatibility::Unknown => Selectability::Disabled {
            reason: "coding-turn compatibility is unknown",
        },
        Compatibility::Incompatible => Selectability::Disabled {
            reason: "model is not a coding-turn model",
        },
    };
    ModelDescriptor {
        raw,
        family_id,
        compatibility,
        selectability,
    }
}

fn compatibility(adapter: AdapterKind, model_id: &str) -> Compatibility {
    if adapter == AdapterKind::AnthropicMessages {
        // Anthropic documents this endpoint as the models available to the Messages API.
        return Compatibility::Compatible;
    }
    let id = model_leaf_id(model_id).to_ascii_lowercase();
    let incompatible_markers = [
        "embedding",
        "whisper",
        "tts",
        "dall-e",
        "image",
        "moderation",
        "audio",
        "transcribe",
        "realtime",
    ];
    if incompatible_markers
        .iter()
        .any(|marker| id.contains(marker))
    {
        return Compatibility::Incompatible;
    }
    let known_text_prefixes = [
        "gpt-",
        "chatgpt-",
        "o1",
        "o3",
        "o4",
        "codex",
        "deepseek-",
        "glm-",
        "qwen",
        "llama",
        "mistral",
        "mixtral",
        "gemini-",
    ];
    if known_text_prefixes
        .iter()
        .any(|prefix| id.starts_with(prefix))
    {
        Compatibility::Compatible
    } else {
        Compatibility::Unknown
    }
}

fn model_family(model_id: &str) -> String {
    let id = model_leaf_id(model_id).to_ascii_lowercase();
    if id.starts_with("claude-") {
        for family in ["opus", "sonnet", "haiku"] {
            if id.contains(family) {
                return format!("claude-{family}");
            }
        }
    }
    let known = [
        ("gpt-5", "gpt-5"),
        ("gpt-4.1", "gpt-4.1"),
        ("gpt-4o", "gpt-4o"),
        ("gpt-4", "gpt-4"),
        ("deepseek", "deepseek"),
        ("glm", "glm"),
        ("qwen", "qwen"),
        ("llama", "llama"),
        ("mistral", "mistral"),
        ("gemini", "gemini"),
    ];
    for (prefix, family) in known {
        if id.starts_with(prefix) {
            return family.into();
        }
    }
    if id.starts_with("o1") {
        return "o1".into();
    }
    if id.starts_with("o3") {
        return "o3".into();
    }
    if id.starts_with("o4") {
        return "o4".into();
    }
    "other".into()
}

fn model_leaf_id(model_id: &str) -> &str {
    model_id.rsplit('/').next().unwrap_or(model_id)
}

fn family_display_name(id: &str) -> String {
    match id {
        "claude-opus" => "Claude Opus".into(),
        "claude-sonnet" => "Claude Sonnet".into(),
        "claude-haiku" => "Claude Haiku".into(),
        "other" => "Other / unclassified".into(),
        value => value.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub availability: AccountAvailability,
    pub balance: BalanceAvailability,
    pub last_error_code: Option<String>,
    pub last_request_id: Option<String>,
}

/// Evidence that one model leaf, rather than the provider account, is unavailable. Entries exist
/// only for known-unavailable models and are removed after a successful turn for the same pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelHealth {
    pub last_error_code: Option<String>,
    pub last_request_id: Option<String>,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            availability: AccountAvailability::Unknown,
            balance: BalanceAvailability::Unknown,
            last_error_code: None,
            last_request_id: None,
        }
    }
}

/// Shared, bounded in-memory health state. It contains no credentials and deliberately starts
/// with an unknown balance. Oldest entries are evicted deterministically at the configured cap.
#[derive(Clone)]
pub struct ProviderHealthStore {
    inner: Arc<Mutex<HealthState>>,
    max_entries: usize,
    max_model_entries: usize,
}

#[derive(Default)]
struct HealthState {
    entries: BTreeMap<String, ProviderHealth>,
    order: VecDeque<String>,
    model_entries: BTreeMap<(String, String), ModelHealth>,
    model_order: VecDeque<(String, String)>,
}

impl ProviderHealthStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HealthState::default())),
            max_entries: max_entries.clamp(1, MAX_HEALTH_ENTRIES),
            max_model_entries: max_entries
                .saturating_mul(16)
                .clamp(1, MAX_MODEL_HEALTH_ENTRIES),
        }
    }

    pub fn get(&self, provider_instance_id: &str) -> ProviderHealth {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(provider_instance_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn model_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .model_entries
            .len()
    }

    pub fn model_health(&self, provider_instance_id: &str, model_id: &str) -> Option<ModelHealth> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .model_entries
            .get(&(provider_instance_id.to_string(), model_id.to_string()))
            .cloned()
    }

    pub fn is_model_unavailable(&self, provider_instance_id: &str, model_id: &str) -> bool {
        self.model_health(provider_instance_id, model_id).is_some()
    }

    /// Clear one learned model-leaf block after an explicit operator retry request.
    ///
    /// Account-wide authentication, billing, permission, credential, and configuration gates are
    /// deliberately untouched. A subsequent typed failure recreates the leaf immediately. This
    /// is the only recovery path that does not require a successful turn, avoiding the dead state
    /// where preflight rejection prevented the very request that could prove recovery.
    pub fn clear_model_unavailable_for_retry(
        &self,
        provider_instance_id: &str,
        model_id: &str,
    ) -> bool {
        if !valid_health_key(provider_instance_id, MAX_INSTANCE_ID_BYTES)
            || !valid_health_key(model_id, MAX_MODEL_ID_BYTES)
        {
            return false;
        }
        let key = (provider_instance_id.to_string(), model_id.to_string());
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = state.model_entries.remove(&key).is_some();
        if removed {
            state.model_order.retain(|candidate| candidate != &key);
        }
        removed
    }

    /// Return only durable account blocks. Unknown, temporary rate limits, and degradation must
    /// reach the transport so they can recover naturally.
    pub fn blocked_account(&self, provider_instance_id: &str) -> Option<AccountAvailability> {
        let health = self.get(provider_instance_id);
        if health.balance == BalanceAvailability::Depleted {
            return Some(AccountAvailability::BillingBlocked);
        }
        matches!(
            health.availability,
            AccountAvailability::MissingCredential
                | AccountAvailability::AuthenticationBlocked
                | AccountAvailability::BillingBlocked
                | AccountAvailability::PermissionBlocked
                | AccountAvailability::ConfigurationError
        )
        .then_some(health.availability)
    }

    pub fn mark_ready(&self, provider_instance_id: &str) {
        self.update(provider_instance_id, |health| {
            // Catalog visibility is not proof that any durable inference/account failure has
            // recovered. It may clear only temporary/unknown states.
            if !provider_health_has_durable_block(health) {
                health.availability = AccountAvailability::Ready;
                // Catalog visibility proves credentials work, but not remaining balance.
                health.balance = BalanceAvailability::Unknown;
                health.last_error_code = None;
                health.last_request_id = None;
            }
        });
    }

    /// A paid turn is stronger evidence than catalog discovery: it proves this account/model pair
    /// works now and clears only that model leaf's prior unavailable marker.
    pub fn mark_turn_ready(&self, provider_instance_id: &str, model_id: &str) {
        self.update(provider_instance_id, |health| {
            // Concurrent requests can complete out of order. A generic success must not erase a
            // durable block observed by another request; authoritative control-plane recovery is
            // handled by `update_from_probe` with a typed probe kind.
            if !provider_health_has_durable_block(health) {
                health.availability = AccountAvailability::Ready;
                health.balance = BalanceAvailability::Unknown;
                health.last_error_code = None;
                health.last_request_id = None;
            }
        });
        self.remove_model(provider_instance_id, model_id);
    }

    pub fn mark_missing_credential(&self, provider_instance_id: &str) {
        self.update(provider_instance_id, |health| {
            health.availability = AccountAvailability::MissingCredential;
        });
    }

    pub fn update_from_error(&self, provider_instance_id: &str, error: &ProviderError) {
        self.update_error(provider_instance_id, None, error);
    }

    pub fn update_from_turn_error(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        error: &ProviderError,
    ) {
        self.update_from_turn_error_with_scope(provider_instance_id, model_id, error, false);
    }

    pub fn update_from_turn_error_with_scope(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        error: &ProviderError,
        account_failure_is_model_scoped: bool,
    ) {
        if account_failure_is_model_scoped
            && let Some(normalized) = error.normalized()
            && matches!(
                normalized.availability,
                AvailabilityTransition::Account(
                    AccountAvailability::BillingBlocked | AccountAvailability::PermissionBlocked
                )
            )
        {
            self.mark_model_unavailable(provider_instance_id, model_id, normalized);
            return;
        }
        self.update_error(provider_instance_id, Some(model_id), error);
    }

    fn update_error(
        &self,
        provider_instance_id: &str,
        model_id: Option<&str>,
        error: &ProviderError,
    ) {
        if let Some(normalized) = error.normalized()
            && normalized.availability == AvailabilityTransition::ModelUnavailable
        {
            if let Some(model_id) = model_id {
                self.mark_model_unavailable(provider_instance_id, model_id, normalized);
            }
            return;
        }
        self.update(provider_instance_id, |health| match error {
            ProviderError::MissingCredential { .. } | ProviderError::NoKey => {
                health.availability = merge_account_availability(
                    health.availability,
                    AccountAvailability::MissingCredential,
                );
            }
            ProviderError::Configuration(_) => {
                health.availability = merge_account_availability(
                    health.availability,
                    AccountAvailability::ConfigurationError,
                );
            }
            _ => {
                if let Some(normalized) = error.normalized() {
                    if let AvailabilityTransition::Account(availability) = normalized.availability {
                        health.availability =
                            merge_account_availability(health.availability, availability);
                        if availability == AccountAvailability::BillingBlocked {
                            health.balance = BalanceAvailability::Depleted;
                        }
                    }
                    health.last_error_code = normalized.code.clone();
                    health.last_request_id = normalized.request_id.clone();
                }
            }
        });
    }

    pub fn update_from_probe(
        &self,
        provider_instance_id: &str,
        probe: AccountProbe,
        result: AccountProbeResult,
    ) {
        self.update(provider_instance_id, |health| {
            // Catalog discovery and account probes run concurrently in the CLI. A successful or
            // inconclusive probe is not evidence that a catalog-auth/billing/permission failure
            // recovered, so completion order must not change the durable gate. A blocking probe,
            // however, is authoritative for its documented scope and may replace Ready.
            if provider_health_has_durable_block(health)
                && !account_result_has_durable_block(result)
            {
                let authoritative_recovery = match probe {
                    // DeepSeek documents `is_available:true` as positive balance evidence. It
                    // may clear only a prior billing/depleted state, never auth/config/permission.
                    AccountProbe::DeepSeekBalance => {
                        result.availability == AccountAvailability::Ready
                            && result.balance == BalanceAvailability::Sufficient
                            && matches!(
                                health.availability,
                                AccountAvailability::BillingBlocked
                                    | AccountAvailability::Unknown
                                    | AccountAvailability::Ready
                            )
                    }
                    // UNSUSPENDED proves only suspension state, not remaining credit. Do not let
                    // it erase a billing/auth/configuration failure from another operation.
                    AccountProbe::FireworksSuspendState => {
                        result.availability == AccountAvailability::Ready
                            && health.availability == AccountAvailability::PermissionBlocked
                            && health.balance != BalanceAvailability::Depleted
                    }
                };
                if !authoritative_recovery {
                    return;
                }
            }
            if provider_health_has_durable_block(health) && account_result_has_durable_block(result)
            {
                health.availability =
                    merge_account_availability(health.availability, result.availability);
                if result.balance == BalanceAvailability::Depleted {
                    health.balance = BalanceAvailability::Depleted;
                }
                return;
            }
            health.availability = result.availability;
            health.balance = result.balance;
            health.last_error_code = None;
            health.last_request_id = None;
        });
    }

    fn update(&self, provider_instance_id: &str, apply: impl FnOnce(&mut ProviderHealth)) {
        if provider_instance_id.is_empty() || provider_instance_id.len() > MAX_INSTANCE_ID_BYTES {
            return;
        }
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.entries.contains_key(provider_instance_id) {
            while state.entries.len() >= self.max_entries {
                if let Some(oldest) = state.order.pop_front() {
                    state.entries.remove(&oldest);
                } else {
                    break;
                }
            }
            state.order.push_back(provider_instance_id.to_string());
        }
        let health = state
            .entries
            .entry(provider_instance_id.to_string())
            .or_default();
        apply(health);
    }

    fn mark_model_unavailable(
        &self,
        provider_instance_id: &str,
        model_id: &str,
        normalized: &crate::NormalizedFailure,
    ) {
        if !valid_health_key(provider_instance_id, MAX_INSTANCE_ID_BYTES)
            || !valid_health_key(model_id, MAX_MODEL_ID_BYTES)
        {
            return;
        }
        let key = (provider_instance_id.to_string(), model_id.to_string());
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.model_entries.contains_key(&key) {
            while state.model_entries.len() >= self.max_model_entries {
                if let Some(oldest) = state.model_order.pop_front() {
                    state.model_entries.remove(&oldest);
                } else {
                    break;
                }
            }
            state.model_order.push_back(key.clone());
        }
        state.model_entries.insert(
            key,
            ModelHealth {
                last_error_code: normalized.code.clone(),
                last_request_id: normalized.request_id.clone(),
            },
        );
    }

    fn remove_model(&self, provider_instance_id: &str, model_id: &str) {
        self.clear_model_unavailable_for_retry(provider_instance_id, model_id);
    }
}

fn account_availability_is_durable_block(availability: AccountAvailability) -> bool {
    matches!(
        availability,
        AccountAvailability::MissingCredential
            | AccountAvailability::AuthenticationBlocked
            | AccountAvailability::BillingBlocked
            | AccountAvailability::PermissionBlocked
            | AccountAvailability::ConfigurationError
    )
}

fn durable_availability_priority(availability: AccountAvailability) -> u8 {
    match availability {
        AccountAvailability::ConfigurationError => 5,
        AccountAvailability::MissingCredential => 4,
        AccountAvailability::AuthenticationBlocked => 3,
        AccountAvailability::BillingBlocked => 2,
        AccountAvailability::PermissionBlocked => 1,
        AccountAvailability::Unknown
        | AccountAvailability::Discovering
        | AccountAvailability::Ready
        | AccountAvailability::RateLimited
        | AccountAvailability::Degraded => 0,
    }
}

fn merge_account_availability(
    current: AccountAvailability,
    observed: AccountAvailability,
) -> AccountAvailability {
    if account_availability_is_durable_block(current)
        && account_availability_is_durable_block(observed)
    {
        if durable_availability_priority(observed) > durable_availability_priority(current) {
            observed
        } else {
            current
        }
    } else {
        observed
    }
}

fn provider_health_has_durable_block(health: &ProviderHealth) -> bool {
    health.balance == BalanceAvailability::Depleted
        || account_availability_is_durable_block(health.availability)
}

fn account_result_has_durable_block(result: AccountProbeResult) -> bool {
    result.balance == BalanceAvailability::Depleted
        || account_availability_is_durable_block(result.availability)
}

fn valid_health_key(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

// ===========================================================================
// Route-bound published model pricing (world data).
//
// A configured route (`ProviderInstance`) already fixes an adapter, an error profile, and an API
// root; before this it carried capability world-data but no price, so a dollar cost could never be
// realized for a bound route/model. A published rate card supplies that missing world-data:
// provenance-bearing, route-scoped, and fail-closed. Absence remains unknown — an unrecognized
// gateway never inherits an official provider's list price merely by sharing its wire syntax.
//
// Token-to-money projection stays the observability/pricing strategy layer's signed authority
// (`core_protocol::pricing`); this only *publishes* the per-route rate and offers a matching
// list-price realization so the amount can finally be attached to a route/model.
// ===========================================================================

/// Micro-token normalizer: prices are quoted per one million tokens.
const MICROTOKENS_PER_TOKEN_CLASS: u128 = 1_000_000;

/// One published, route-scoped list-price snapshot for a model family.
///
/// The rates are fixed-point micro-USD per one million tokens, exactly as
/// [`core_protocol::TokenRateCard`] documents, so a realized amount here reconciles against a
/// signed `CostProjection` on identical inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedRateCard {
    /// The model family this list price was published for (matched against the requested id).
    pub family: &'static str,
    /// Non-secret provenance for the list price (a documentation URL or operator manifest id).
    pub source: &'static str,
    /// UTC capture time of the published list price.
    pub captured_at_unix_secs: u64,
    /// Fixed-point token prices in micro-USD per one million tokens.
    pub rates: TokenRateCard,
}

impl PublishedRateCard {
    /// Realize the list-price dollar cost, in micro-USD, of one provider usage sample on this
    /// route. Each token class is priced independently and ceil-rounded so a sub-unit turn is
    /// never silently rounded down to free. Thinking tokens exceeding total output, or any
    /// fixed-point overflow, fail closed with `None` rather than fabricating a cheaper amount.
    pub fn realize_cost_microusd(&self, usage: &Usage) -> Option<u64> {
        realize_cost_microusd(&self.rates, usage)
    }
}

struct FamilyRate {
    family: &'static str,
    source: &'static str,
    captured_at_unix_secs: u64,
    rates: TokenRateCard,
}

const fn token_rates(
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
    thinking: u64,
) -> TokenRateCard {
    TokenRateCard {
        input_microusd_per_million: input,
        output_microusd_per_million: output,
        cache_creation_microusd_per_million: cache_creation,
        cache_read_microusd_per_million: cache_read,
        thinking_microusd_per_million: thinking,
    }
}

// 2026-07-14 published list prices, in micro-USD per one million tokens. Thinking is priced as
// output because these providers bill reasoning tokens at the output rate.
const ANTHROPIC_PRICING_SOURCE: &str = "https://docs.anthropic.com/en/docs/about-claude/pricing";
const ANTHROPIC_RATES: &[FamilyRate] = &[
    FamilyRate {
        family: "claude-opus",
        source: ANTHROPIC_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(15_000_000, 75_000_000, 18_750_000, 1_500_000, 75_000_000),
    },
    FamilyRate {
        family: "claude-sonnet",
        source: ANTHROPIC_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(3_000_000, 15_000_000, 3_750_000, 300_000, 15_000_000),
    },
    FamilyRate {
        family: "claude-haiku",
        source: ANTHROPIC_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(800_000, 4_000_000, 1_000_000, 80_000, 4_000_000),
    },
];

// `gpt-5-mini` precedes `gpt-5` because the family matcher accepts `gpt-5` as a prefix of
// `gpt-5-mini`; first-match therefore requires the more specific family first.
const OPENAI_PRICING_SOURCE: &str = "https://openai.com/api/pricing/";
const OPENAI_RATES: &[FamilyRate] = &[
    FamilyRate {
        family: "gpt-5-mini",
        source: OPENAI_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(250_000, 2_000_000, 250_000, 25_000, 2_000_000),
    },
    FamilyRate {
        family: "gpt-5",
        source: OPENAI_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(1_250_000, 10_000_000, 1_250_000, 125_000, 10_000_000),
    },
];

// GLM families order specific-before-general for the same first-match reason (`glm-5` prefixes
// `glm-5.2`).
const GLM_PRICING_SOURCE: &str = "https://docs.bigmodel.cn/pricing";
const GLM_RATES: &[FamilyRate] = &[
    FamilyRate {
        family: "glm-5.2",
        source: GLM_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(600_000, 2_200_000, 600_000, 110_000, 2_200_000),
    },
    FamilyRate {
        family: "glm-4.6",
        source: GLM_PRICING_SOURCE,
        captured_at_unix_secs: 1_752_451_200,
        rates: token_rates(600_000, 2_200_000, 600_000, 110_000, 2_200_000),
    },
];

/// Select the published list-price table for exactly one official route, or `None`.
///
/// The route is identified by adapter *and* error profile *and* the official API root together: a
/// custom gateway that merely reuses OpenAI-compatible wire syntax resolves to
/// [`ErrorProfile::CustomConservative`] and receives no official list price.
fn pricing_route_table(
    adapter: AdapterKind,
    profile: ErrorProfile,
    api_root: &str,
) -> Option<&'static [FamilyRate]> {
    match (adapter, profile) {
        (AdapterKind::AnthropicMessages, ErrorProfile::Anthropic) if api_root == ANTHROPIC_ROOT => {
            Some(ANTHROPIC_RATES)
        }
        (AdapterKind::OpenAiResponses, ErrorProfile::OpenAi) if api_root == OPENAI_ROOT => {
            Some(OPENAI_RATES)
        }
        (AdapterKind::OpenAiCompatibleChat, ErrorProfile::Glm) if api_root == GLM_STANDARD_ROOT => {
            Some(GLM_RATES)
        }
        _ => None,
    }
}

/// Resolve the published rate card bound to one exact route and model, or `None` when the route is
/// unrecognized or the model has no published list price. The lookup fails closed: an unknown
/// gateway never inherits an official provider's price.
pub fn published_rate_card(
    adapter: AdapterKind,
    profile: ErrorProfile,
    api_root: &str,
    model: &str,
) -> Option<PublishedRateCard> {
    pricing_route_table(adapter, profile, api_root)?
        .iter()
        .find(|entry| crate::model_matches_family(model, entry.family))
        .map(|entry| PublishedRateCard {
            family: entry.family,
            source: entry.source,
            captured_at_unix_secs: entry.captured_at_unix_secs,
            rates: entry.rates,
        })
}

/// Realize the list-price dollar cost, in micro-USD, of one usage sample under a rate card. Each
/// token class is priced and ceil-rounded independently; thinking above total output, or any
/// fixed-point overflow, returns `None`. This mirrors the observability strategy's signed
/// projection so a published estimate and an authoritative projection agree on the same inputs.
pub fn realize_cost_microusd(rates: &TokenRateCard, usage: &Usage) -> Option<u64> {
    let non_thinking_output = usage.output.checked_sub(usage.thinking)?;
    let classes = [
        (usage.input, rates.input_microusd_per_million),
        (non_thinking_output, rates.output_microusd_per_million),
        (
            usage.cache_creation,
            rates.cache_creation_microusd_per_million,
        ),
        (usage.cache_read, rates.cache_read_microusd_per_million),
        (usage.thinking, rates.thinking_microusd_per_million),
    ];
    let mut total: u128 = 0;
    for (tokens, rate) in classes {
        let numerator = u128::from(tokens).checked_mul(u128::from(rate))?;
        let class_cost =
            numerator.checked_add(MICROTOKENS_PER_TOKEN_CLASS - 1)? / MICROTOKENS_PER_TOKEN_CLASS;
        total = total.checked_add(class_cost)?;
    }
    u64::try_from(total).ok()
}

impl ProviderInstance {
    /// Resolve the published rate card bound to this instance's exact route for one model.
    ///
    /// This is the route-bound entry point: the instance already fixes the adapter, error profile,
    /// and API root, so the returned card (and any [`PublishedRateCard::realize_cost_microusd`]
    /// amount) is attributable to precisely this configured provider instance.
    pub fn published_rate_card(&self, model: &str) -> Option<PublishedRateCard> {
        published_rate_card(
            self.adapter,
            self.error_profile,
            self.api_root.as_str(),
            model,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiResponseError, ErrorScope, NormalizedFailure, RetryDisposition};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn instance(adapter: AdapterKind) -> ProviderInstance {
        ProviderInstance::new(
            "test",
            "Test",
            adapter,
            ApiRoot::parse("https://example.test/v1").unwrap(),
            Some("secret".into()),
        )
        .unwrap()
    }

    fn spawn_json_server(
        bodies: Vec<String>,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 2048];
                loop {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    assert!(
                        request.len() < 16 * 1024,
                        "test request headers are unbounded"
                    );
                }
                sender.send(String::from_utf8(request).unwrap()).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (format!("http://{address}"), receiver, handle)
    }

    #[test]
    fn default_transport_pins_the_connection_reuse_policy() {
        // reqwest exposes no getter for either option, so the audited policy is pinned as named
        // constants applied in the single client constructor; the behavioural half of this pin is
        // `a_second_turn_reuses_the_pooled_connection`.
        assert_eq!(HTTP_POOL_IDLE_TIMEOUT, Duration::from_secs(300));
        assert_eq!(HTTP_TCP_KEEPALIVE, Duration::from_secs(30));
        assert!(
            HTTP_POOL_IDLE_TIMEOUT > Duration::from_secs(90),
            "the pool must outlive a think longer than reqwest's 90s default, or the next turn \
             pays a fresh TLS handshake"
        );
        assert!(DefaultHttpTransport.client().is_ok());
    }

    #[tokio::test]
    async fn a_second_turn_reuses_the_pooled_connection() {
        // Audited on origin/main: with no pool idle timeout and no TCP keepalive, the connection
        // was gone after a long think and the next turn re-handshaked (0.78-1.02s measured).
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            // Exactly one accept: both turns must arrive on the same connection.
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            for _ in 0..2 {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).unwrap();
                    assert!(read > 0, "client closed the pooled connection");
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                // Keep-alive: no `Connection: close`, so the connection returns to the pool.
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
                )
                .unwrap();
                stream.flush().unwrap();
            }
            // A connection the client opened instead of reusing is still queued in the backlog.
            listener.set_nonblocking(true).unwrap();
            sender.send(listener.accept().is_ok()).unwrap();
        });

        let client = DefaultHttpTransport.client().unwrap();
        let url = format!("http://{address}/v1/messages");
        for _ in 0..2 {
            let response = client.get(&url).send().await.unwrap();
            assert!(response.status().is_success());
            // The body must be drained before the connection can return to the pool.
            response.bytes().await.unwrap();
            // Stands in for the think between two turns.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !receiver.recv().unwrap(),
            "the second turn opened a new connection instead of reusing the pooled one"
        );
        handle.join().unwrap();
    }

    #[test]
    fn prompt_cache_is_on_by_default_and_opt_out_survives_construction() {
        let instance = instance(AdapterKind::AnthropicMessages);
        assert!(instance.prompt_cache(), "caching is the default");
        let opted_out = instance.clone().with_prompt_cache(false);
        assert!(!opted_out.prompt_cache());
        // The opt-out is a route fact, so it must survive the clone the directory keeps and
        // still build a turn provider.
        assert!(!opted_out.clone().prompt_cache());
        assert!(opted_out.build_turn_provider().is_ok());
    }

    #[test]
    fn api_root_preserves_exact_prefixes() {
        let cases = [
            (
                "https://api.openai.com/v1",
                "https://api.openai.com/v1/models",
            ),
            (
                "https://gateway.test/team/a",
                "https://gateway.test/team/a/models",
            ),
            (
                "https://open.bigmodel.cn/api/paas/v4/",
                "https://open.bigmodel.cn/api/paas/v4/models",
            ),
            (
                "https://api.fireworks.ai/inference/v1",
                "https://api.fireworks.ai/inference/v1/models",
            ),
        ];
        for (root, expected) in cases {
            let root = ApiRoot::parse(root).unwrap();
            assert_eq!(root.endpoint("models").unwrap().as_str(), expected);
        }
        assert_eq!(
            ApiRoot::parse("https://api.deepseek.com")
                .unwrap()
                .endpoint("chat/completions")
                .unwrap()
                .as_str(),
            "https://api.deepseek.com/chat/completions"
        );
        assert_eq!(
            ApiRoot::parse("https://api.deepseek.com/v1")
                .unwrap()
                .origin_endpoint("user/balance")
                .unwrap()
                .as_str(),
            "https://api.deepseek.com/user/balance"
        );
    }

    #[test]
    fn catalog_cache_scope_is_keyed_and_credential_bound() {
        let local_key = [7_u8; 32];
        let same = instance(AdapterKind::OpenAiCompatibleChat);
        let same_scope = same.catalog_cache_credential_scope(&local_key).unwrap();
        assert_eq!(
            same_scope,
            same.catalog_cache_credential_scope(&local_key).unwrap()
        );

        let different_credential = ProviderInstance::new(
            "test",
            "Test",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("https://example.test/v1").unwrap(),
            Some("different-secret".into()),
        )
        .unwrap();
        assert_ne!(
            same_scope,
            different_credential
                .catalog_cache_credential_scope(&local_key)
                .unwrap()
        );
        assert_ne!(
            same_scope,
            same.catalog_cache_credential_scope(&[8_u8; 32]).unwrap()
        );

        let missing = ProviderInstance::new(
            "test",
            "Test",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("https://example.test/v1").unwrap(),
            None,
        )
        .unwrap();
        assert!(missing.catalog_cache_credential_scope(&local_key).is_none());
    }

    #[test]
    fn api_root_rejects_ambiguous_or_secret_bearing_components() {
        for invalid in [
            "ftp://example.test/v1",
            "https://user:secret\
@example.test/v1",
            "https://example.test/v1?token=secret",
            "https://example.test/v1#models",
            "not a URL",
        ] {
            assert!(ApiRoot::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn anthropic_pages_require_advancing_cursor_and_valid_shape() {
        let bytes = br#"{"data":[{"id":"claude-sonnet-4","display_name":"Sonnet","created_at":"2025-01-01T00:00:00Z"}],"has_more":true,"last_id":"claude-sonnet-4"}"#;
        let page: AnthropicModelsPage = decode_page(bytes, bytes.len()).unwrap();
        assert!(page.has_more);
        assert_eq!(page.last_id.as_deref(), Some("claude-sonnet-4"));

        let missing = br#"{"data":[],"has_more":true}"#;
        let page: AnthropicModelsPage = decode_page(missing, missing.len()).unwrap();
        assert!(page.last_id.is_none());

        let mut seen = BTreeSet::new();
        let first = advance_anthropic_cursor(None, &mut seen, true, Some("a".into())).unwrap();
        assert_eq!(first.as_deref(), Some("a"));
        assert!(
            advance_anthropic_cursor(Some("a"), &mut seen, true, Some("a".into())).is_err(),
            "a non-advancing cursor must fail closed"
        );

        let mut seen = BTreeSet::new();
        assert_eq!(
            advance_anthropic_cursor(None, &mut seen, true, Some("a".into())).unwrap(),
            Some("a".into())
        );
        assert_eq!(
            advance_anthropic_cursor(Some("a"), &mut seen, true, Some("b".into())).unwrap(),
            Some("b".into())
        );
        assert!(
            advance_anthropic_cursor(Some("b"), &mut seen, true, Some("a".into())).is_err(),
            "a cursor cycle must fail closed"
        );
        assert!(advance_anthropic_cursor(None, &mut BTreeSet::new(), true, None).is_err());
    }

    #[test]
    fn openai_list_is_deduped_sorted_grouped_and_keeps_unknown_models() {
        let page: OpenAiModelsPage = decode_page(
            br#"{"data":[{"id":"vendor-mystery","owned_by":"v"},{"id":"gpt-5-mini","owned_by":"openai"},{"id":"gpt-5-mini","owned_by":"openai"},{"id":"text-embedding-3-small","owned_by":"openai"}]}"#,
            200,
        )
        .unwrap();
        let raw: Vec<_> = page
            .data
            .into_iter()
            .map(raw_openai_model)
            .collect::<Result<_, _>>()
            .unwrap();
        let provider = instance(AdapterKind::OpenAiCompatibleChat);
        let snapshot = CatalogSnapshot::from_raw(&provider, raw.clone());
        let mut reversed = raw;
        reversed.reverse();
        assert_eq!(snapshot, CatalogSnapshot::from_raw(&provider, reversed));
        let ids: Vec<_> = snapshot
            .models
            .iter()
            .map(|model| model.raw.id.as_str())
            .collect();
        assert_eq!(
            ids,
            ["gpt-5-mini", "text-embedding-3-small", "vendor-mystery"]
        );
        let unknown = snapshot
            .models
            .iter()
            .find(|model| model.raw.id == "vendor-mystery")
            .unwrap();
        assert_eq!(unknown.compatibility, Compatibility::Unknown);
        assert!(matches!(
            unknown.selectability,
            Selectability::Disabled { .. }
        ));
        assert_eq!(
            snapshot
                .families
                .iter()
                .map(|family| family.id.as_str())
                .collect::<Vec<_>>(),
            ["gpt-5", "other"]
        );
    }

    #[test]
    fn fireworks_parser_keeps_every_model_and_disables_unusable_entries() {
        let page: FireworksModelsPage = decode_page(
            br#"{
              "models": [
                {"name":"accounts/fireworks/models/qwen-good","displayName":"Qwen good","createTime":"2026-01-01T00:00:00Z","state":"READY","status":{"code":"OK"},"kind":"HF_BASE_MODEL","baseModelDetails":{"modelType":"qwen"},"public":true,"conversationConfig":{},"supportsTools":true,"supportsServerless":true,"supportsImageInput":true},
                {"name":"accounts/fireworks/models/no-tools","state":"READY","status":{"code":"OK"},"kind":"HF_BASE_MODEL","public":true,"conversationConfig":{},"supportsTools":false,"supportsServerless":true},
                {"name":"accounts/fireworks/models/uploading","state":"UPLOADING","status":{"code":"OK"},"kind":"HF_BASE_MODEL","public":true,"conversationConfig":{},"supportsTools":true,"supportsServerless":true},
                {"name":"accounts/fireworks/models/bad-status","state":"READY","status":{"code":"INTERNAL"},"kind":"HF_BASE_MODEL","public":true,"conversationConfig":{},"supportsTools":true,"supportsServerless":true},
                {"name":"accounts/fireworks/models/not-serverless","state":"READY","status":{"code":"OK"},"kind":"HF_BASE_MODEL","public":true,"conversationConfig":{},"supportsTools":true,"supportsServerless":false},
                {"name":"accounts/fireworks/models/no-chat","state":"READY","status":{"code":"OK"},"kind":"HF_BASE_MODEL","public":true,"supportsTools":true,"supportsServerless":true},
                {"name":"accounts/fireworks/models/embed","state":"READY","status":{"code":"OK"},"kind":"EMBEDDING_MODEL","public":true,"conversationConfig":{},"supportsTools":true,"supportsServerless":true}
              ],
              "nextPageToken":"next"
            }"#,
            2_000,
        )
        .unwrap();
        assert_eq!(page.next_page_token.as_deref(), Some("next"));
        let models = page
            .models
            .into_iter()
            .map(|model| {
                describe_fireworks_model(model, FireworksModelScope::PublicServerless, None, false)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let provider = ProviderInstance::new(
            "fireworks",
            "Fireworks",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(FIREWORKS_INFERENCE_ROOT).unwrap(),
            Some("secret".into()),
        )
        .unwrap();
        let snapshot = CatalogSnapshot::from_descriptors(&provider, models);
        assert_eq!(
            snapshot.models.len(),
            7,
            "disabled models must remain visible"
        );
        let selectable: Vec<_> = snapshot
            .models
            .iter()
            .filter(|model| model.selectability == Selectability::Selectable)
            .map(|model| model.raw.id.as_str())
            .collect();
        assert_eq!(selectable, ["accounts/fireworks/models/qwen-good"]);
        let good = snapshot
            .models
            .iter()
            .find(|model| model.raw.id.ends_with("qwen-good"))
            .unwrap();
        assert_eq!(good.raw.owned_by.as_deref(), Some("fireworks"));
        assert_eq!(good.raw.supports_image_input, Some(true));
        assert_eq!(good.family_id, "qwen");
        for id in ["no-tools", "no-chat", "embed"] {
            assert_eq!(
                snapshot
                    .models
                    .iter()
                    .find(|model| model.raw.id.ends_with(id))
                    .unwrap()
                    .compatibility,
                Compatibility::Incompatible
            );
        }
    }

    #[test]
    fn fireworks_page_tokens_must_advance_and_are_bounded() {
        let mut seen = BTreeSet::new();
        assert_eq!(
            advance_page_token("models", None, &mut seen, Some("a".into())).unwrap(),
            Some("a".into())
        );
        assert!(advance_page_token("models", Some("a"), &mut seen, Some("a".into())).is_err());
        assert!(
            advance_page_token(
                "models",
                None,
                &mut BTreeSet::new(),
                Some("x".repeat(MAX_PAGE_TOKEN_BYTES + 1)),
            )
            .is_err()
        );
        assert_eq!(
            advance_page_token("models", None, &mut BTreeSet::new(), Some(String::new())).unwrap(),
            None
        );
    }

    #[test]
    fn fireworks_model_resources_cannot_escape_the_requested_account() {
        assert!(validate_fireworks_model_parent("accounts/a/models/good", "a", "model").is_ok());
        assert!(
            validate_fireworks_model_parent("accounts/b/models/cross-scope", "a", "model").is_err()
        );
    }

    #[test]
    fn fireworks_conflicting_private_account_evidence_disables_the_leaf() {
        let mut page: FireworksModelsPage = decode_page(
            br#"{"models":[{"name":"accounts/a/models/private","state":"READY","status":{"code":"OK"},"kind":"HF_BASE_MODEL","public":false,"conversationConfig":{},"supportsTools":true,"supportsServerless":true}]}"#,
            256,
        )
        .unwrap();
        let model = describe_fireworks_model(
            page.models.remove(0),
            FireworksModelScope::AccountPrivate,
            Some(FireworksCatalogAccountState {
                result: unknown_account_probe_result(),
                conflicting: true,
            }),
            false,
        )
        .unwrap();
        assert!(matches!(
            model.selectability,
            Selectability::Disabled { reason }
                if reason == "Fireworks account metadata is conflicting"
        ));
    }

    #[test]
    fn fireworks_suspend_states_are_typed_without_guessing_unknowns() {
        for state in [
            "FAILED_PAYMENTS",
            "CREDIT_DEPLETED",
            "MONTHLY_SPEND_LIMIT_EXCEEDED",
        ] {
            assert_eq!(
                fireworks_account_result(Some("READY"), Some("OK"), Some(state)),
                AccountProbeResult {
                    availability: AccountAvailability::BillingBlocked,
                    balance: BalanceAvailability::Depleted,
                }
            );
        }
        assert_eq!(
            fireworks_account_result(Some("READY"), Some("OK"), Some("UNSUSPENDED")),
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Unknown,
            }
        );
        assert_eq!(
            fireworks_account_result(Some("READY"), Some("OK"), Some("BLOCKED_BY_ABUSE_RULE"),),
            AccountProbeResult {
                availability: AccountAvailability::PermissionBlocked,
                balance: BalanceAvailability::Unknown,
            }
        );
        for (state, status, suspended) in [
            (Some("CREATING"), Some("OK"), Some("UNSUSPENDED")),
            (Some("READY"), Some("INTERNAL"), Some("UNSUSPENDED")),
            (Some("READY"), Some("OK"), Some("FUTURE_STATE")),
            (None, None, None),
        ] {
            assert_eq!(
                fireworks_account_result(state, status, suspended),
                unknown_account_probe_result(),
            );
        }
    }

    #[test]
    fn fireworks_multi_account_conflicts_remain_unknown() {
        let page: FireworksAccountsPage = serde_json::from_slice(
            br#"{"accounts":[{"name":"accounts/ready","state":"READY","status":{"code":"OK"},"suspendState":"UNSUSPENDED"},{"name":"accounts/empty","state":"READY","status":{"code":"OK"},"suspendState":"CREDIT_DEPLETED"}]}"#,
        )
        .unwrap();
        assert_eq!(
            aggregate_fireworks_accounts(page.accounts),
            unknown_account_probe_result(),
            "a key exposing conflicting accounts must not be guessed funded or depleted",
        );

        let duplicate: FireworksAccountsPage = serde_json::from_slice(
            br#"{"accounts":[{"name":"accounts/same","state":"READY","status":{"code":"OK"},"suspendState":"UNSUSPENDED"},{"name":"accounts/same","state":"READY","status":{"code":"OK"},"suspendState":"FAILED_PAYMENTS"}]}"#,
        )
        .unwrap();
        assert_eq!(
            aggregate_fireworks_accounts(duplicate.accounts),
            unknown_account_probe_result(),
            "inconsistent duplicate resources must fail closed",
        );
    }

    #[tokio::test]
    async fn fireworks_fake_control_plane_uses_exact_resources_and_paginates() {
        let model = |account: &str,
                     name: &str,
                     supports_tools: bool,
                     supports_serverless: bool,
                     public: bool| {
            serde_json::json!({
                "name": format!("accounts/{account}/models/{name}"),
                "displayName": name,
                "state": "READY",
                "status": {"code": "OK"},
                "kind": "HF_BASE_MODEL",
                "public": public,
                "conversationConfig": {},
                "supportsTools": supports_tools,
                "supportsServerless": supports_serverless,
            })
        };
        let bodies = vec![
            serde_json::json!({
                "models": [model("fireworks", "qwen-live", true, true, true)],
                "nextPageToken": "models-2",
            })
            .to_string(),
            serde_json::json!({
                "models": [model("fireworks", "no-tools", false, true, true)]
            })
            .to_string(),
            // Account discovery is intentionally returned out of order; Core must enumerate
            // deterministic full resource paths rather than deriving a router/deployment id.
            serde_json::json!({
                "accounts": [
                    {
                        "name":"accounts/b",
                        "state":"READY",
                        "status":{"code":"OK"},
                        "suspendState":"CREDIT_DEPLETED"
                    },
                    {
                        "name":"accounts/a",
                        "state":"READY",
                        "status":{"code":"OK"},
                        "suspendState":"UNSUSPENDED"
                    }
                ]
            })
            .to_string(),
            serde_json::json!({
                "deployedModels": [
                    {
                        "name": "accounts/a/deployedModels/default-private-live",
                        "model": "accounts/a/models/private-live",
                        "deployment": "accounts/a/deployments/dedicated-a",
                        "default": true,
                        "state": "DEPLOYED",
                        "status": {"code": "OK"}
                    }
                ],
                "nextPageToken": "deployed-a-2"
            })
            .to_string(),
            serde_json::json!({
                "deployedModels": [
                    {
                        "name": "accounts/a/deployedModels/ambiguous-private-a",
                        "model": "accounts/a/models/private-needs-deployment",
                        "deployment": "accounts/a/deployments/dedicated-b",
                        "default": true,
                        "state": "DEPLOYED",
                        "status": {"code": "OK"}
                    },
                    {
                        "name": "accounts/a/deployedModels/ambiguous-private-b",
                        "model": "accounts/a/models/private-needs-deployment",
                        "deployment": "accounts/a/deployments/dedicated-c",
                        "default": true,
                        "state": "DEPLOYED",
                        "status": {"code": "OK"}
                    }
                ]
            })
            .to_string(),
            serde_json::json!({
                "models": [model("a", "private-live", true, false, false)],
                "nextPageToken": "private-a-2",
            })
            .to_string(),
            serde_json::json!({
                "models": [model("a", "private-needs-deployment", true, false, false)]
            })
            .to_string(),
            serde_json::json!({
                "deployedModels": []
            })
            .to_string(),
            serde_json::json!({
                "models": [model("b", "private-b-live", true, true, false)]
            })
            .to_string(),
            serde_json::json!({
                "accounts": [{
                    "name": "accounts/a",
                    "state": "READY",
                    "status": {"code": "OK"},
                    "suspendState": "CREDIT_DEPLETED",
                }],
                "nextPageToken": "accounts-2",
            })
            .to_string(),
            serde_json::json!({
                "accounts": [{
                    "name": "accounts/b",
                    "state": "READY",
                    "status": {"code": "OK"},
                    "suspendState": "FAILED_PAYMENTS",
                }],
            })
            .to_string(),
        ];
        let (origin, requests, server) = spawn_json_server(bodies);
        let instance = ProviderInstance::new(
            "fireworks-test",
            "Fireworks test",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(&format!("{origin}/inference/v1")).unwrap(),
            Some("secret".into()),
        )
        .unwrap()
        .with_catalog_strategy(CatalogStrategy::FireworksControlPlane {
            api_root: ApiRoot::parse(&format!("{origin}/v1")).unwrap(),
        })
        .unwrap();

        let catalog = discover_catalog(&instance).await.unwrap();
        assert_eq!(catalog.models.len(), 5);
        assert_eq!(
            catalog
                .models
                .iter()
                .filter(|model| model.selectability == Selectability::Selectable)
                .count(),
            2,
        );
        assert!(catalog.models.iter().any(|model| {
            model.raw.id == "accounts/a/models/private-live"
                && model.raw.owned_by.as_deref() == Some("a")
                && model.selectability == Selectability::Selectable
        }));
        assert!(catalog.models.iter().any(|model| {
            model.raw.id == "accounts/b/models/private-b-live"
                && matches!(
                    model.selectability,
                    Selectability::Disabled { reason }
                        if reason == "Fireworks account billing is blocked"
                )
        }));
        let needs_deployment = catalog
            .models
            .iter()
            .find(|model| model.raw.id == "accounts/a/models/private-needs-deployment")
            .unwrap();
        assert!(matches!(
            needs_deployment.selectability,
            Selectability::Disabled { reason } if reason.contains("does not infer")
        ));
        assert_eq!(
            probe_account(&instance, AccountProbe::FireworksSuspendState)
                .await
                .unwrap(),
            AccountProbeResult {
                availability: AccountAvailability::BillingBlocked,
                balance: BalanceAvailability::Depleted,
            },
        );
        server.join().unwrap();

        let requests: Vec<_> = requests.try_iter().collect();
        assert_eq!(requests.len(), 11);
        let targets: Vec<_> = requests
            .iter()
            .map(|request| {
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer secret"),
                    "control-plane request omitted bearer authentication",
                );
                request
                    .lines()
                    .next()
                    .unwrap()
                    .split_ascii_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_string()
            })
            .collect();
        for (index, target) in targets.iter().enumerate() {
            let url = Url::parse(&format!("http://test{target}")).unwrap();
            let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            if index < 2 {
                assert_eq!(url.path(), "/v1/accounts/fireworks/models");
                assert_eq!(
                    query.get("filter").map(String::as_str),
                    Some(FIREWORKS_SERVERLESS_FILTER),
                );
                assert_eq!(query.get("pageSize").map(String::as_str), Some("200"));
            } else if index == 2 {
                assert_eq!(url.path(), "/v1/accounts");
                assert_eq!(query.get("pageSize").map(String::as_str), Some("200"));
                assert_eq!(
                    query.get("readMask").map(String::as_str),
                    Some("name,state,status,suspendState")
                );
            } else if matches!(index, 3 | 4 | 7) {
                let expected = if index < 5 {
                    "/v1/accounts/a/deployedModels"
                } else {
                    "/v1/accounts/b/deployedModels"
                };
                assert_eq!(url.path(), expected);
                assert_eq!(query.get("pageSize").map(String::as_str), Some("200"));
                assert_eq!(
                    query.get("readMask").map(String::as_str),
                    Some("name,model,deployment,default,state,status"),
                );
            } else if index < 9 {
                let expected = if index < 7 {
                    "/v1/accounts/a/models"
                } else {
                    "/v1/accounts/b/models"
                };
                assert_eq!(url.path(), expected);
                assert_eq!(query.get("pageSize").map(String::as_str), Some("200"));
                assert!(!query.contains_key("filter"));
            } else {
                assert_eq!(url.path(), "/v1/accounts");
                assert_eq!(query.get("pageSize").map(String::as_str), Some("200"));
                assert_eq!(
                    query.get("readMask").map(String::as_str),
                    Some("name,state,status,suspendState"),
                );
            }
        }
        let second_models = Url::parse(&format!("http://test{}", targets[1])).unwrap();
        assert_eq!(
            second_models
                .query_pairs()
                .find(|(key, _)| key == "pageToken")
                .map(|(_, value)| value.into_owned()),
            Some("models-2".into()),
        );
        let second_deployments = Url::parse(&format!("http://test{}", targets[4])).unwrap();
        assert_eq!(
            second_deployments
                .query_pairs()
                .find(|(key, _)| key == "pageToken")
                .map(|(_, value)| value.into_owned()),
            Some("deployed-a-2".into()),
        );
        let second_accounts = Url::parse(&format!("http://test{}", targets[6])).unwrap();
        assert_eq!(
            second_accounts
                .query_pairs()
                .find(|(key, _)| key == "pageToken")
                .map(|(_, value)| value.into_owned()),
            Some("private-a-2".into()),
        );
        let second_probe_accounts = Url::parse(&format!("http://test{}", targets[10])).unwrap();
        assert_eq!(
            second_probe_accounts
                .query_pairs()
                .find(|(key, _)| key == "pageToken")
                .map(|(_, value)| value.into_owned()),
            Some("accounts-2".into()),
        );
    }

    #[test]
    fn malformed_and_oversized_pages_fail_closed() {
        assert!(decode_page::<OpenAiModelsPage>(b"not-json", 8).is_err());
        let oversized = vec![b' '; MAX_PAGE_BYTES + 1];
        assert!(decode_page::<OpenAiModelsPage>(&oversized, oversized.len()).is_err());
    }

    #[tokio::test]
    async fn missing_credential_returns_before_network() {
        let unavailable = ProviderInstance::new(
            "offline",
            "Offline",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("http://127.0.0.1:9/v1").unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            discover_catalog(&unavailable).await,
            Err(ProviderError::MissingCredential { .. })
        ));
        assert!(matches!(
            probe_account(&unavailable, AccountProbe::DeepSeekBalance).await,
            Err(ProviderError::MissingCredential { .. })
        ));
        assert!(matches!(
            unavailable.build_turn_provider(),
            Err(ProviderError::MissingCredential { .. })
        ));
    }

    #[test]
    fn glm_standard_schema_manifest_is_exact_static_and_entitlement_neutral() {
        let metadata = crate::StaticProviderMetadata::embedded();
        assert!(
            metadata
                .glm_catalog_version()
                .starts_with("glm-chat-completions-schema@2026-07-14+sha256:")
        );
        assert_eq!(metadata.glm_default_model(), "glm-5.2");
        assert_eq!(
            metadata
                .glm_models()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &[
                "glm-5.2",
                "glm-5.1",
                "glm-5-turbo",
                "glm-5",
                "glm-4.7",
                "glm-4.7-flash",
                "glm-4.7-flashx",
                "glm-4.6",
                "glm-4.5-air",
                "glm-4.5-airx",
                "glm-4.5-flash",
                "glm-4-flash-250414",
                "glm-4-flashx-250414",
            ]
        );

        // Schema construction is deliberately credential-free and cannot color account health.
        let glm = ProviderInstance::new(
            "glm",
            "GLM",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(GLM_STANDARD_ROOT).unwrap(),
            None,
        )
        .unwrap();
        let health = ProviderHealthStore::new(4);
        let catalog = glm_standard_schema_catalog(&glm).unwrap();
        assert_eq!(health.get("glm").availability, AccountAvailability::Unknown);
        assert_eq!(catalog.models.len(), metadata.glm_models().len());
        assert!(catalog.models.iter().all(|model| {
            model.compatibility == Compatibility::Compatible
                && model.selectability == Selectability::Selectable
        }));
        let mut expected = metadata
            .glm_models()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(
            catalog
                .models
                .iter()
                .map(|model| model.raw.id.as_str())
                .collect::<Vec<_>>(),
            expected,
        );

        let coding = ProviderInstance::new(
            "glm-coding",
            "GLM Coding",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(GLM_CODING_ROOT).unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            glm_standard_schema_catalog(&coding),
            Err(ProviderError::Configuration(_))
        ));
    }

    #[tokio::test]
    async fn glm_official_roots_fail_closed_without_guessing_models_endpoint() {
        for api_root in [GLM_STANDARD_ROOT, GLM_CODING_ROOT, GLM_ANTHROPIC_ROOT] {
            let adapter = if api_root == GLM_ANTHROPIC_ROOT {
                AdapterKind::AnthropicMessages
            } else {
                AdapterKind::OpenAiCompatibleChat
            };
            let glm = ProviderInstance::new(
                "glm",
                "GLM",
                adapter,
                ApiRoot::parse(api_root).unwrap(),
                Some("secret".into()),
            )
            .unwrap();
            assert!(matches!(
                glm.catalog_strategy(),
                CatalogStrategy::Unsupported { .. }
            ));
            let error = discover_catalog(&glm).await.unwrap_err();
            let ProviderError::UnsupportedCatalog { provider, reason } = error else {
                panic!("expected typed unsupported-catalog failure");
            };
            assert_eq!(provider, "glm");
            assert!(reason.contains("operator manifest"));
            assert!(reason.contains("manual model id"));
        }
    }

    #[test]
    fn builtin_openai_uses_responses_and_custom_keeps_exact_adapter_root() {
        let openai =
            ProviderInstance::builtin(BuiltinProvider::OpenAi, Some("key".into())).unwrap();
        assert_eq!(openai.adapter(), AdapterKind::OpenAiResponses);
        assert_eq!(openai.api_root().as_str(), "https://api.openai.com/v1");
        assert!(openai.build_turn_provider().is_ok());

        let custom = ProviderInstance::custom(
            "fireworks",
            "Fireworks",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("https://api.fireworks.ai/inference/v1").unwrap(),
            Some("key".into()),
        )
        .unwrap();
        assert_eq!(
            custom
                .api_root()
                .endpoint("chat/completions")
                .unwrap()
                .as_str(),
            "https://api.fireworks.ai/inference/v1/chat/completions"
        );
        assert_eq!(
            custom.catalog_strategy(),
            &CatalogStrategy::FireworksControlPlane {
                api_root: ApiRoot::parse(FIREWORKS_CONTROL_PLANE_ROOT).unwrap(),
            }
        );

        for root in [MINIMAX_ROOT, MINIMAX_LEGACY_ROOT] {
            let minimax = ProviderInstance::new(
                "minimax",
                "MiniMax",
                AdapterKind::OpenAiCompatibleChat,
                ApiRoot::parse(root).unwrap(),
                Some("key".into()),
            )
            .unwrap();
            assert_eq!(minimax.error_profile(), ErrorProfile::MiniMax, "{root}");
        }
    }

    #[test]
    fn health_store_is_bounded_and_balance_defaults_unknown() {
        let store = ProviderHealthStore::new(2);
        store.mark_ready("a");
        store.mark_ready("b");
        store.mark_ready("c");
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("a").availability, AccountAvailability::Unknown);
        assert_eq!(store.get("c").balance, BalanceAvailability::Unknown);
    }

    #[test]
    fn account_probe_merge_is_order_independent_for_durable_blocks() {
        let failure = |status: u16, code: &str, availability: AccountAvailability| {
            ProviderError::ApiResponse(ApiResponseError {
                status,
                body: String::new(),
                body_truncated: false,
                retry_after: None,
                normalized: Box::new(NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: ErrorProfile::Fireworks,
                    code: Some(code.into()),
                    public_message: "provider account is blocked",
                    scope: ErrorScope::Account,
                    availability: AvailabilityTransition::Account(availability),
                    retry: RetryDisposition::Never,
                    request_id: Some("request-1".into()),
                }),
            })
        };
        let billing = failure(
            429,
            "insufficient_quota",
            AccountAvailability::BillingBlocked,
        );
        let authentication = failure(
            401,
            "unauthenticated",
            AccountAvailability::AuthenticationBlocked,
        );
        let ready = AccountProbeResult {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Unknown,
        };
        let unknown = AccountProbeResult {
            availability: AccountAvailability::Unknown,
            balance: BalanceAvailability::Unknown,
        };

        let store = ProviderHealthStore::new(8);
        store.update_from_error("catalog-first", &billing);
        let durable = store.get("catalog-first");
        store.update_from_probe("catalog-first", AccountProbe::FireworksSuspendState, ready);
        assert_eq!(store.get("catalog-first"), durable);

        store.update_from_probe("probe-first", AccountProbe::FireworksSuspendState, ready);
        store.update_from_error("probe-first", &billing);
        assert_eq!(
            store.get("probe-first").availability,
            AccountAvailability::BillingBlocked
        );
        assert_eq!(
            store.get("probe-first").balance,
            BalanceAvailability::Depleted
        );

        store.update_from_error("auth-first", &authentication);
        let durable = store.get("auth-first");
        store.update_from_probe("auth-first", AccountProbe::FireworksSuspendState, unknown);
        assert_eq!(store.get("auth-first"), durable);

        store.mark_ready("blocking-probe");
        store.update_from_probe(
            "blocking-probe",
            AccountProbe::FireworksSuspendState,
            AccountProbeResult {
                availability: AccountAvailability::PermissionBlocked,
                balance: BalanceAvailability::Unknown,
            },
        );
        assert_eq!(
            store.get("blocking-probe").availability,
            AccountAvailability::PermissionBlocked
        );

        // A later, provider-documented positive balance observation is authoritative recovery
        // for billing only. If the failure is observed later, it still wins.
        store.update_from_error("deepseek-recovered", &billing);
        store.update_from_probe(
            "deepseek-recovered",
            AccountProbe::DeepSeekBalance,
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Sufficient,
            },
        );
        assert_eq!(
            store.get("deepseek-recovered"),
            ProviderHealth {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Sufficient,
                last_error_code: None,
                last_request_id: None,
            }
        );

        store.update_from_probe(
            "deepseek-failure-later",
            AccountProbe::DeepSeekBalance,
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Sufficient,
            },
        );
        store.update_from_error("deepseek-failure-later", &billing);
        assert_eq!(
            store.get("deepseek-failure-later").availability,
            AccountAvailability::BillingBlocked
        );

        let permission = AccountProbeResult {
            availability: AccountAvailability::PermissionBlocked,
            balance: BalanceAvailability::Unknown,
        };
        let depleted = AccountProbeResult {
            availability: AccountAvailability::BillingBlocked,
            balance: BalanceAvailability::Depleted,
        };
        store.update_from_probe("durable-a", AccountProbe::FireworksSuspendState, depleted);
        store.update_from_probe("durable-a", AccountProbe::FireworksSuspendState, permission);
        store.update_from_probe("durable-b", AccountProbe::FireworksSuspendState, permission);
        store.update_from_probe("durable-b", AccountProbe::FireworksSuspendState, depleted);
        assert_eq!(store.get("durable-a"), store.get("durable-b"));
        assert_eq!(
            store.get("durable-a").balance,
            BalanceAvailability::Depleted
        );
    }

    #[test]
    fn generic_turn_success_does_not_erase_a_concurrent_durable_block() {
        let store = ProviderHealthStore::new(4);
        let billing = ProviderError::ApiResponse(ApiResponseError {
            status: 429,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::OpenAi,
                code: Some("insufficient_quota".into()),
                public_message: "provider billing or quota is unavailable",
                scope: ErrorScope::Account,
                availability: AvailabilityTransition::Account(AccountAvailability::BillingBlocked),
                retry: RetryDisposition::Never,
                request_id: Some("billing-later".into()),
            }),
        });
        store.update_from_error("same-account", &billing);
        let blocked = store.get("same-account");
        store.mark_turn_ready("same-account", "working-model");
        assert_eq!(store.get("same-account"), blocked);
    }

    #[test]
    fn deepseek_balance_probe_maps_documented_availability() {
        let payload: DeepSeekBalance = serde_json::from_slice(
            br#"{"is_available":false,"balance_infos":[{"currency":"CNY","total_balance":"0.00"}]}"#,
        )
        .unwrap();
        assert_eq!(
            deepseek_probe_result(payload.is_available),
            AccountProbeResult {
                availability: AccountAvailability::BillingBlocked,
                balance: BalanceAvailability::Depleted,
            }
        );
        assert_eq!(
            deepseek_probe_result(true),
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Sufficient,
            }
        );
    }

    #[test]
    fn health_store_applies_account_billing_but_not_model_failure() {
        let store = ProviderHealthStore::new(8);
        let billing = ProviderError::ApiResponse(ApiResponseError {
            status: 429,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::OpenAi,
                code: Some("insufficient_quota".into()),
                public_message: "provider billing or quota is unavailable",
                scope: ErrorScope::Account,
                availability: AvailabilityTransition::Account(AccountAvailability::BillingBlocked),
                retry: RetryDisposition::Never,
                request_id: None,
            }),
        });
        store.update_from_error("p", &billing);
        assert_eq!(
            store.get("p").availability,
            AccountAvailability::BillingBlocked
        );
        assert_eq!(store.get("p").balance, BalanceAvailability::Depleted);

        let model = ProviderError::ApiResponse(ApiResponseError {
            status: 404,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::OpenAi,
                code: Some("model_not_found".into()),
                public_message: "the selected model is unavailable",
                scope: ErrorScope::Model,
                availability: AvailabilityTransition::ModelUnavailable,
                retry: RetryDisposition::Never,
                request_id: None,
            }),
        });
        store.mark_ready("q");
        store.update_from_error("q", &model);
        assert_eq!(store.get("q").availability, AccountAvailability::Ready);
    }

    fn credential_file(name: &str, contents: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "core-credential-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn instance_with_source(source: CredentialSource) -> ProviderInstance {
        ProviderInstance::new(
            "sub",
            "Subscription",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("https://gateway.example/v1").unwrap(),
            None,
        )
        .unwrap()
        .with_credential_source(source)
    }

    /// I-22 — a credential was a frozen `String`, so a subscription token could never refresh:
    /// the value was snapshotted at construction and rotation required restarting Core. The file
    /// source must be re-read whenever the cached token is inside its refresh window, so a token
    /// rewritten mid-session is the one the next turn dispatches with.
    #[test]
    fn i22_an_expiring_file_credential_refreshes_without_a_restart() {
        let now = unix_now();
        let path = credential_file(
            "rotates",
            &format!(r#"{{"token":"first","expires_at_unix":{}}}"#, now + 30),
        );
        let instance = instance_with_source(CredentialSource::file(path.clone()));

        assert_eq!(instance.credential(), Some("first".into()));
        assert!(instance.build_turn_provider().is_ok());

        std::fs::write(
            &path,
            format!(r#"{{"token":"second","expires_at_unix":{}}}"#, now + 30),
        )
        .unwrap();
        assert_eq!(
            instance.credential(),
            Some("second".into()),
            "a rotated token inside the refresh window must be re-read, not served from a snapshot"
        );

        let status = instance.credential_status();
        assert_eq!(status.kind, CredentialKind::File);
        assert!(status.present);
        assert_eq!(status.expires_at_unix, Some(now + 30));
        assert!(
            !status.display().contains("second"),
            "credential status must never carry the value: {}",
            status.display()
        );
        std::fs::remove_file(path).ok();
    }

    /// A credential that is comfortably inside its validity window is served from the cache, and
    /// an environment credential keeps exactly its previous snapshot behaviour.
    #[test]
    fn i22_a_valid_token_is_cached_and_an_env_credential_is_unchanged() {
        let far_future = unix_now() + 10 * 365 * 24 * 60 * 60;
        let path = credential_file(
            "cached",
            &format!(r#"{{"token":"stable","expires_at_unix":{far_future}}}"#),
        );
        let instance = instance_with_source(CredentialSource::file(path.clone()));
        assert_eq!(instance.credential(), Some("stable".into()));
        std::fs::write(&path, r#"{"token":"ignored-while-valid"}"#).unwrap();
        assert_eq!(instance.credential(), Some("stable".into()));
        std::fs::remove_file(path).ok();

        let env = instance_with_source(CredentialSource::env("GATEWAY_KEY", Some("k".into())));
        assert_eq!(env.credential(), Some("k".into()));
        assert!(env.has_credential());
        let status = env.credential_status();
        assert_eq!(status.kind, CredentialKind::Env);
        assert_eq!(status.name, "GATEWAY_KEY");
        assert!(status.present);
        assert_eq!(status.expires_at_unix, None);

        let empty = instance_with_source(CredentialSource::env("GATEWAY_KEY", None));
        assert!(!empty.has_credential());
        assert!(!empty.credential_status().present);
        assert!(matches!(
            empty.build_turn_provider(),
            Err(ProviderError::MissingCredential { .. })
        ));
    }

    /// No credential value may reach a formatter, a log line, or a status row — the only thing
    /// that ever leaves this type is the source name.
    #[test]
    fn i22_a_credential_value_never_escapes_through_debug_or_status() {
        let path = credential_file("redacted", "top-secret-token\n");
        let instance = instance_with_source(CredentialSource::file(path.clone()));
        assert_eq!(instance.credential(), Some("top-secret-token".into()));

        let rendered = format!("{instance:?}");
        assert!(
            !rendered.contains("top-secret-token"),
            "provider Debug leaked a credential: {rendered}"
        );
        assert!(rendered.contains(&path.display().to_string()));
        assert_eq!(
            instance.credential_source().file_path(),
            Some(path.as_path()),
            "the composition root needs the path to add it to the redaction set"
        );

        let env =
            instance_with_source(CredentialSource::env("GATEWAY_KEY", Some("sk-live".into())));
        let rendered = format!("{env:?}");
        assert!(
            !rendered.contains("sk-live"),
            "provider Debug leaked an env credential: {rendered}"
        );
        std::fs::remove_file(path).ok();
    }

    /// A credential file is the highest-value file Core reads. Anything that is not a small,
    /// private, regular file with one token resolves to absent WITH a reason, never to a guess.
    #[test]
    fn i22_a_credential_file_is_bounded_private_and_explicit() {
        let missing = instance_with_source(CredentialSource::file(
            std::env::temp_dir().join("core-credential-does-not-exist"),
        ));
        assert!(!missing.has_credential());
        assert_eq!(
            missing.credential_status().error.as_deref(),
            Some("credential file is absent")
        );

        let oversized = credential_file("oversized", &"x".repeat(9 * 1024));
        let instance = instance_with_source(CredentialSource::file(oversized.clone()));
        assert!(!instance.has_credential());
        assert!(
            instance
                .credential_status()
                .error
                .is_some_and(|error| error.contains("8 KiB"))
        );
        std::fs::remove_file(oversized).ok();

        let malformed = credential_file("malformed", r#"{"token":""}"#);
        let instance = instance_with_source(CredentialSource::file(malformed.clone()));
        assert!(!instance.has_credential());
        std::fs::remove_file(malformed).ok();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let world = credential_file("world-readable", "token\n");
            std::fs::set_permissions(&world, std::fs::Permissions::from_mode(0o644)).unwrap();
            let instance = instance_with_source(CredentialSource::file(world.clone()));
            assert!(!instance.has_credential());
            assert!(
                instance
                    .credential_status()
                    .error
                    .is_some_and(|error| error.contains("chmod 600"))
            );
            std::fs::remove_file(world).ok();
        }
    }
}

#[cfg(test)]
mod d2_23_pricing {
    use super::*;
    use core_protocol::Usage;

    /// D2-23 — a route-bound model rate card must exist so a dollar cost is finally realized.
    ///
    /// Before this gap a configured route carried capability world-data but no price, so the
    /// observability layer had nothing to project and a turn's dollar cost was never realized.
    /// This exercises the new route-bound published rate card and its list-price realization end
    /// to end through the crate's public surface.
    #[test]
    fn d2_23_route_bound_rate_card_realizes_dollar_cost() {
        // (1) Headline: a bound Anthropic route now yields a card and a concrete, non-zero dollar
        // amount. 1M input + 1M output on the Opus list price ($15/MTok in, $75/MTok out) realizes
        // exactly $90.00 = 90_000_000 micro-USD.
        let route = ProviderInstance::builtin(BuiltinProvider::Anthropic, None).unwrap();
        let card = route
            .published_rate_card("claude-opus-4-7-20260720")
            .expect("a bound Anthropic route must publish a rate card for a known family");
        assert_eq!(card.family, "claude-opus");
        let usage = Usage {
            input: 1_000_000,
            output: 1_000_000,
            ..Usage::default()
        };
        let realized = card
            .realize_cost_microusd(&usage)
            .expect("a bounded usage sample must realize a finite dollar cost");
        assert_eq!(realized, 90_000_000, "1M in + 1M out on Opus is $90.00");
        assert!(realized > 0, "the dollar cost must actually be realized");

        // (2) Ceil rounding: a sub-unit turn is never rounded down to free. One cache-read token on
        // the Opus card ($1.50/MTok) costs 1.5 micro-USD, which ceils to 2.
        let sub_unit = Usage {
            cache_read: 1,
            ..Usage::default()
        };
        assert_eq!(card.realize_cost_microusd(&sub_unit), Some(2));

        // (3) Thinking above total output fails closed instead of underpricing.
        let bad = Usage {
            output: 1,
            thinking: 2,
            ..Usage::default()
        };
        assert_eq!(card.realize_cost_microusd(&bad), None);

        // (4) Fail closed: a foreign gateway reusing OpenAI-compatible wire inherits no official
        // price, via both the free function and a route-bound instance.
        assert!(
            published_rate_card(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::CustomConservative,
                "https://gateway.invalid/v1",
                "gpt-5",
            )
            .is_none()
        );
        let unknown = ProviderInstance::custom(
            "house-gateway",
            "House Gateway",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse("https://gateway.invalid/v1").unwrap(),
            None,
        )
        .unwrap();
        assert!(unknown.published_rate_card("gpt-5").is_none());

        // (5) Distinct routes price their own families — the card is bound to the exact route, not
        // a global default. The instance lookup and free function agree, and GLM does not alias the
        // Anthropic Opus price.
        let glm = ProviderInstance::custom(
            "glm-standard",
            "GLM",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(GLM_STANDARD_ROOT).unwrap(),
            None,
        )
        .unwrap();
        let via_instance = glm.published_rate_card("glm-5.2").unwrap();
        let via_function = published_rate_card(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::Glm,
            GLM_STANDARD_ROOT,
            "glm-5.2",
        )
        .unwrap();
        assert_eq!(via_instance, via_function);
        assert_eq!(via_instance.family, "glm-5.2");
        assert_ne!(
            via_instance.rates.output_microusd_per_million, 75_000_000,
            "GLM must not carry the Anthropic Opus price"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// `core/model_router`: which model a delegated turn is allowed to run on.
// ---------------------------------------------------------------------------------------------

// The pure `core/model_router` strategy behind the frozen [`StrategySlot`] seam.
//
// Delegation is where this repository actually chooses a model. A pinned `AgentDef` may name one,
// a spawn call may name one, and the parent already holds exactly one route it has durable
// evidence for. Until now that choice was two copies of the same hard-coded rule — one in
// `prepare_investigator`, one in the workflow spawner's `build_child` — each of which refused any
// model that was not the parent's, with the reason spelled out in a string literal beside it. A
// vertical pack that resolves a second route could not express that fact without editing the
// runtime.
//
// This makes the choice a slot decision. It chooses; it never resolves anything. No catalog is
// fetched here, no credential is read, no rate card is bound — [`ProviderInstance`] and the
// runtime's durable route selection own all of that, and this module only sees the names the
// caller already has evidence for.
//
// One rule is structural rather than advisory:
//
// **A decision may only pick from the evidence it was shown.** The caller supplies
// `resolved_routes`; a strategy may pick any member, and nothing else. A decision naming a model
// outside that list is rejected by [`ModelRouterStrategy::route_with`], not merely discouraged —
// so a pinned third-party policy cannot conjure a route the caller never resolved, and therefore
// cannot spend a parent's catalog, capability, and price digests under a model identity those
// digests never covered. That is the model-routing analogue of the capability narrowing
// [`decide_narrowed`] performs on the same call, and it is enforced for every implementor rather
// than remembered by each one.
//
// Refusal stays expressible: a strategy that has no opinion returns
// [`ModelRouterDecision::Refuse`], because refusing to route is never a widening.
/// The wire version of this slot's observation and decision payloads.
pub const MODEL_ROUTER_SLOT_VERSION: u16 = 1;

/// Upper bound on how many resolved routes one observation may carry. A caller with more resolved
/// routes than this has a catalog problem, not a routing problem.
pub const MAX_RESOLVED_ROUTES: usize = 32;

/// Upper bound on one model identity, matching `core_agents`' own bound on `AgentDef::model` so a
/// definition that validates there cannot be refused here for length alone.
pub const MAX_ROUTE_MODEL_BYTES: usize = 512;

/// The already-gathered routing evidence for one delegation.
///
/// The caller owns these. A strategy sees only what is here: no credential, no API root, no
/// catalog handle, no pricing port. It has no way to reach the world from inside
/// [`StrategySlot::decide`], which is synchronous and pure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct ModelRouterObservation {
    pub version: u16,
    /// Every model this caller holds resolved route evidence for, in caller preference order.
    /// Non-empty, and the first entry is the route already bound for the parent turn — the answer
    /// a strategy with no opinion should fall back to.
    pub resolved_routes: Vec<String>,
    /// The model the pinned agent definition asks for, if it asks for one.
    pub definition_model: Option<String>,
    /// The model the spawn call asks for, if it asks for one.
    pub call_model: Option<String>,
}

impl ModelRouterObservation {
    /// The observation a delegation site builds when it holds evidence for exactly one route,
    /// which is every caller in this repository today.
    pub fn single_route(
        route: impl Into<String>,
        definition_model: Option<String>,
        call_model: Option<String>,
    ) -> Self {
        Self {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec![route.into()],
            definition_model,
            call_model,
        }
    }

    /// The route the caller is already running on: the fallback a strategy is expected to name
    /// when neither the definition nor the call asks for anything.
    pub fn bound_route(&self) -> Option<&str> {
        self.resolved_routes.first().map(String::as_str)
    }

    fn validate(&self) -> Result<(), ModelRouterError> {
        if self.version != MODEL_ROUTER_SLOT_VERSION {
            return Err(ModelRouterError::UnsupportedVersion);
        }
        if self.resolved_routes.is_empty() {
            return Err(ModelRouterError::InvalidObservation(
                "a routing observation must carry at least one resolved route",
            ));
        }
        if self.resolved_routes.len() > MAX_RESOLVED_ROUTES {
            return Err(ModelRouterError::InvalidObservation(
                "a routing observation carries more resolved routes than the bounded maximum",
            ));
        }
        for model in self
            .resolved_routes
            .iter()
            .chain(self.definition_model.iter())
            .chain(self.call_model.iter())
        {
            if !model_identity_is_well_formed(model) {
                return Err(ModelRouterError::InvalidObservation(
                    "a model identity must be non-blank, control-free, and bounded",
                ));
            }
        }
        Ok(())
    }

    /// Whether the caller holds resolved route evidence for `model`.
    pub fn resolves(&self, model: &str) -> bool {
        self.resolved_routes.iter().any(|known| known == model)
    }
}

/// The same bound `core_agents::AgentDef::validate` applies to a definition's model, restated here
/// because this crate must not depend on that one and a slot may not be handed an identity whose
/// well-formedness nobody checked.
fn model_identity_is_well_formed(model: &str) -> bool {
    !model.trim().is_empty()
        && model.len() <= MAX_ROUTE_MODEL_BYTES
        && !model.chars().any(char::is_control)
}

/// Why a routing decision declined to produce a route.
///
/// The variants carry the exact operator-facing wording the two delegation sites used before this
/// was a slot, so making the decision replaceable did not change a single refusal message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRouteRefusal {
    /// A definition and a call each named a model, and they disagree. Neither one wins by default:
    /// picking either would run a pinned definition under an identity it never asked for.
    DefinitionConflict,
    /// The requested model is one this caller holds no resolved route evidence for.
    NoRouteEvidence,
}

impl fmt::Display for ModelRouteRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DefinitionConflict => {
                "agent definition model conflicts with the requested model override"
            }
            Self::NoRouteEvidence => {
                "requested agent model has no separately resolved route evidence"
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelRouterDecision {
    /// Run the delegated turn on this model.
    Route { model: String },
    /// Do not delegate at all, for this reason.
    Refuse { reason: ModelRouteRefusal },
    /// A decoder that does not recognise the payload degrades here rather than guessing.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRouterError {
    UnsupportedVersion,
    WrongSlot,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    /// The decision named a model the caller holds no resolved route evidence for. This is the
    /// structural refusal: it fires however well-behaved or ill-behaved the implementation is.
    RouteWithoutEvidence,
    /// The strategy declined to route. Not a defect — a policy is allowed to say no.
    Refused(ModelRouteRefusal),
}

impl fmt::Display for ModelRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                formatter.write_str("unsupported model router slot version")
            }
            Self::WrongSlot => formatter.write_str("slot identity is not core/model_router"),
            Self::InvalidObservation(reason) | Self::InvalidDecision(reason) => {
                formatter.write_str(reason)
            }
            Self::RouteWithoutEvidence => formatter
                .write_str("model router chose a model with no separately resolved route evidence"),
            Self::Refused(reason) => reason.fmt(formatter),
        }
    }
}

impl std::error::Error for ModelRouterError {}

/// A route a caller may act on, with the authority the slot admitted for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRouteProposal {
    pub model: String,
    pub eligible: core_protocol::capability_set::CapabilitySet,
}

/// The built-in `core/model_router`: the parent's route unless something explicitly asks otherwise,
/// and never a model the caller has no evidence for.
pub struct ModelRouterStrategy {
    slot: core_protocol::slot::SlotId,
}

impl Default for ModelRouterStrategy {
    fn default() -> Self {
        Self {
            slot: core_protocol::slot::SlotId("core/model_router".into()),
        }
    }
}

impl ModelRouterStrategy {
    pub fn route(
        &self,
        input: &ModelRouterObservation,
        ceiling: core_protocol::capability_set::CapabilitySet,
    ) -> Result<ModelRouteProposal, ModelRouterError> {
        Self::route_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    ///
    /// This is the seam: a vertical pack supplies its own `dyn StrategySlot` and the caller keeps
    /// the same guarantees, because the evidence check lives here rather than inside any
    /// implementation.
    pub fn route_with(
        slot: &dyn core_protocol::slot::StrategySlot,
        input: &ModelRouterObservation,
        ceiling: core_protocol::capability_set::CapabilitySet,
    ) -> Result<ModelRouteProposal, ModelRouterError> {
        if slot.slot().as_persisted_str() != "core/model_router" {
            return Err(ModelRouterError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input).map_err(|_| {
            ModelRouterError::InvalidObservation("routing observation is not serialisable")
        })?;
        let observation = core_protocol::slot::SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = core_protocol::slot::decide_narrowed(slot, &observation);
        let decision = serde_json::from_value::<ModelRouterDecision>(outcome.decision)
            .map_err(|_| ModelRouterError::InvalidDecision("routing decision is invalid"))?;
        match decision {
            ModelRouterDecision::Route { model } => {
                // The structural check. A strategy may prefer any resolved route over any other;
                // it may not name one the caller never resolved, because the caller would then
                // spend digests that were never proven for that identity.
                if !input.resolves(&model) {
                    return Err(ModelRouterError::RouteWithoutEvidence);
                }
                Ok(ModelRouteProposal {
                    model,
                    eligible: outcome.admitted,
                })
            }
            ModelRouterDecision::Refuse { reason } => Err(ModelRouterError::Refused(reason)),
            ModelRouterDecision::Unknown => Err(ModelRouterError::InvalidDecision(
                "routing decision was not recognised",
            )),
        }
    }

    fn unknown_outcome() -> core_protocol::slot::SlotOutcome {
        core_protocol::slot::SlotOutcome {
            admitted: core_protocol::capability_set::CapabilitySet::none(),
            decision: serde_json::to_value(ModelRouterDecision::Unknown)
                .expect("unit routing decision serializes"),
        }
    }

    /// The rule the two delegation sites carried in-line before this was a slot, unchanged: a
    /// definition and a call that disagree refuse; otherwise whichever of them spoke wins, falling
    /// back to the route already bound; and a request with no resolved evidence refuses.
    fn decide_route(input: &ModelRouterObservation) -> ModelRouterDecision {
        if let (Some(call), Some(definition)) = (&input.call_model, &input.definition_model)
            && call != definition
        {
            return ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::DefinitionConflict,
            };
        }
        let requested = input
            .definition_model
            .as_deref()
            .or(input.call_model.as_deref())
            .or_else(|| input.bound_route());
        match requested {
            Some(model) if input.resolves(model) => ModelRouterDecision::Route {
                model: model.to_owned(),
            },
            _ => ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence,
            },
        }
    }
}

impl core_protocol::slot::StrategySlot for ModelRouterStrategy {
    fn slot(&self) -> &core_protocol::slot::SlotId {
        &self.slot
    }

    fn decide(
        &self,
        observation: &core_protocol::slot::SlotObservation,
    ) -> core_protocol::slot::SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ModelRouterObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        core_protocol::slot::SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(Self::decide_route(&input))
                .expect("routing decision serializes"),
        }
    }
}

/// An in-repo alternative implementation, which exists to prove the seam is real.
///
/// It pins every delegation to the parent's own bound route and ignores what the definition or the
/// call asked for. A pack that wants "children never leave the route I paid to resolve" can ship
/// exactly this shape without the runtime knowing it happened.
pub struct BoundRouteOnlyModelRouter {
    slot: core_protocol::slot::SlotId,
}

impl Default for BoundRouteOnlyModelRouter {
    fn default() -> Self {
        Self {
            slot: core_protocol::slot::SlotId("core/model_router".into()),
        }
    }
}

impl core_protocol::slot::StrategySlot for BoundRouteOnlyModelRouter {
    fn slot(&self) -> &core_protocol::slot::SlotId {
        &self.slot
    }

    fn decide(
        &self,
        observation: &core_protocol::slot::SlotObservation,
    ) -> core_protocol::slot::SlotOutcome {
        if observation.slot != self.slot {
            return ModelRouterStrategy::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<ModelRouterObservation>(observation.payload.clone())
        else {
            return ModelRouterStrategy::unknown_outcome();
        };
        let decision = match input.bound_route() {
            Some(model) => ModelRouterDecision::Route {
                model: model.to_owned(),
            },
            None => ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence,
            },
        };
        core_protocol::slot::SlotOutcome {
            admitted: observation.ceiling,
            decision: serde_json::to_value(decision).expect("routing decision serializes"),
        }
    }
}

#[cfg(test)]
mod model_router_slot_tests {
    use super::{
        BoundRouteOnlyModelRouter, MAX_RESOLVED_ROUTES, MODEL_ROUTER_SLOT_VERSION,
        ModelRouteRefusal, ModelRouterDecision, ModelRouterError, ModelRouterObservation,
        ModelRouterStrategy,
    };
    use core_protocol::Capability;
    use core_protocol::capability_set::CapabilitySet;
    use core_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot};

    fn ceiling() -> CapabilitySet {
        CapabilitySet::only(Capability::ReadOnly)
    }

    fn single(definition: Option<&str>, call: Option<&str>) -> ModelRouterObservation {
        ModelRouterObservation::single_route(
            "route-a",
            definition.map(str::to_owned),
            call.map(str::to_owned),
        )
    }

    /// The old in-line rule: nothing asked, so the child inherits the parent's bound route.
    #[test]
    fn a_delegation_that_asks_for_nothing_inherits_the_route_the_caller_already_resolved() {
        let proposal = ModelRouterStrategy::default()
            .route(&single(None, None), ceiling())
            .expect("the bound route is always resolvable");
        assert_eq!(proposal.model, "route-a");
        assert!(proposal.eligible.is_subset_of(ceiling()));
    }

    /// The old in-line rule, refusal branch one — with the same operator-facing wording.
    #[test]
    fn a_model_the_caller_never_resolved_is_refused_with_the_wording_the_runtime_used() {
        let error = ModelRouterStrategy::default()
            .route(&single(Some("route-b"), None), ceiling())
            .expect_err("route-b has no resolved evidence");
        assert_eq!(
            error,
            ModelRouterError::Refused(ModelRouteRefusal::NoRouteEvidence)
        );
        assert_eq!(
            error.to_string(),
            "requested agent model has no separately resolved route evidence"
        );
    }

    /// The old in-line rule, refusal branch two.
    #[test]
    fn a_definition_and_a_call_that_disagree_refuse_rather_than_letting_either_win() {
        let error = ModelRouterStrategy::default()
            .route(&single(Some("route-a"), Some("route-b")), ceiling())
            .expect_err("a disagreement is not resolvable by preference");
        assert_eq!(
            error,
            ModelRouterError::Refused(ModelRouteRefusal::DefinitionConflict)
        );
        assert_eq!(
            error.to_string(),
            "agent definition model conflicts with the requested model override"
        );
        // Agreement between the two is not a conflict.
        assert_eq!(
            ModelRouterStrategy::default()
                .route(&single(Some("route-a"), Some("route-a")), ceiling())
                .expect("agreement routes")
                .model,
            "route-a"
        );
    }

    /// What the hard-coded rule could not express: a caller that resolved a second route.
    #[test]
    fn a_second_resolved_route_becomes_expressible_once_the_caller_has_evidence_for_it() {
        let observation = ModelRouterObservation {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec!["route-a".into(), "route-b".into()],
            definition_model: Some("route-b".into()),
            call_model: None,
        };
        assert_eq!(
            ModelRouterStrategy::default()
                .route(&observation, ceiling())
                .expect("route-b now has evidence")
                .model,
            "route-b"
        );
    }

    struct Conjuring(SlotId);

    impl StrategySlot for Conjuring {
        fn slot(&self) -> &SlotId {
            &self.0
        }
        // A deliberately misbehaving slot: it names a model nobody resolved, and asks for every
        // capability while doing it.
        fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
            SlotOutcome {
                admitted: CapabilitySet::from_iter_capabilities([
                    Capability::ReadOnly,
                    Capability::CodeExecuting,
                    Capability::IrreversibleExternal,
                ]),
                decision: serde_json::to_value(ModelRouterDecision::Route {
                    model: "route-nobody-resolved".into(),
                })
                .expect("decision serializes"),
            }
        }
    }

    #[test]
    fn a_slot_cannot_conjure_a_route_the_caller_never_resolved_however_it_is_implemented() {
        let slot = Conjuring(SlotId("core/model_router".into()));
        assert_eq!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::RouteWithoutEvidence),
            "the evidence check has to hold for an implementation the caller did not write"
        );
    }

    #[test]
    fn a_slot_cannot_widen_authority_while_choosing_a_route_it_is_allowed_to_choose() {
        struct GreedyButHonest(SlotId);
        impl StrategySlot for GreedyButHonest {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::from_iter_capabilities([
                        Capability::ReadOnly,
                        Capability::CodeExecuting,
                        Capability::IrreversibleExternal,
                    ]),
                    decision: serde_json::to_value(ModelRouterDecision::Route {
                        model: "route-a".into(),
                    })
                    .expect("decision serializes"),
                }
            }
        }
        let slot = GreedyButHonest(SlotId("core/model_router".into()));
        let proposal = ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling())
            .expect("route-a is resolved");
        assert!(proposal.eligible.contains(Capability::ReadOnly));
        assert!(!proposal.eligible.contains(Capability::CodeExecuting));
        assert!(!proposal.eligible.contains(Capability::IrreversibleExternal));
        assert!(proposal.eligible.is_subset_of(ceiling()));
    }

    #[test]
    fn an_implementation_sitting_in_the_wrong_seat_is_refused_before_it_is_asked() {
        struct Impostor(SlotId);
        impl StrategySlot for Impostor {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                panic!("a slot in the wrong seat must never be consulted");
            }
        }
        let slot = Impostor(SlotId("core/tool_policy".into()));
        assert_eq!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::WrongSlot)
        );
    }

    #[test]
    fn an_observation_the_caller_could_not_have_gathered_honestly_is_refused() {
        let mut future = single(None, None);
        future.version = MODEL_ROUTER_SLOT_VERSION + 1;
        assert_eq!(
            ModelRouterStrategy::default().route(&future, ceiling()),
            Err(ModelRouterError::UnsupportedVersion)
        );

        let mut empty = single(None, None);
        empty.resolved_routes.clear();
        assert!(matches!(
            ModelRouterStrategy::default().route(&empty, ceiling()),
            Err(ModelRouterError::InvalidObservation(_))
        ));

        let mut crowded = single(None, None);
        crowded.resolved_routes = (0..=MAX_RESOLVED_ROUTES).map(|n| format!("r{n}")).collect();
        assert!(matches!(
            ModelRouterStrategy::default().route(&crowded, ceiling()),
            Err(ModelRouterError::InvalidObservation(_))
        ));

        for malformed in ["", "   ", "route\na"] {
            let observation = single(Some(malformed), None);
            assert!(
                matches!(
                    ModelRouterStrategy::default().route(&observation, ceiling()),
                    Err(ModelRouterError::InvalidObservation(_))
                ),
                "{malformed:?} is not a well-formed model identity"
            );
        }
    }

    #[test]
    fn a_decision_this_build_cannot_read_degrades_instead_of_being_guessed_at() {
        struct Babbling(SlotId);
        impl StrategySlot for Babbling {
            fn slot(&self) -> &SlotId {
                &self.0
            }
            fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
                SlotOutcome {
                    admitted: CapabilitySet::none(),
                    decision: serde_json::json!({ "kind": "teleport", "model": "route-a" }),
                }
            }
        }
        let slot = Babbling(SlotId("core/model_router".into()));
        assert!(matches!(
            ModelRouterStrategy::route_with(&slot, &single(None, None), ceiling()),
            Err(ModelRouterError::InvalidDecision(_))
        ));
    }

    #[test]
    fn a_pinned_alternative_changes_the_answer_without_the_caller_changing() {
        let observation = ModelRouterObservation {
            version: MODEL_ROUTER_SLOT_VERSION,
            resolved_routes: vec!["route-a".into(), "route-b".into()],
            definition_model: Some("route-b".into()),
            call_model: None,
        };
        assert_eq!(
            ModelRouterStrategy::route_with(
                &ModelRouterStrategy::default(),
                &observation,
                ceiling()
            )
            .expect("built-in honours the definition")
            .model,
            "route-b"
        );
        assert_eq!(
            ModelRouterStrategy::route_with(
                &BoundRouteOnlyModelRouter::default(),
                &observation,
                ceiling()
            )
            .expect("the alternative pins to the bound route")
            .model,
            "route-a",
            "the same call site must get a different route purely from the pinned slot"
        );
    }

    #[test]
    fn the_decision_payload_is_a_tagged_shape_this_slot_versions_for_itself() {
        assert_eq!(
            serde_json::to_value(ModelRouterDecision::Route {
                model: "route-a".into()
            })
            .expect("decision serializes"),
            serde_json::json!({ "kind": "route", "model": "route-a" })
        );
        assert_eq!(
            serde_json::to_value(ModelRouterDecision::Refuse {
                reason: ModelRouteRefusal::NoRouteEvidence
            })
            .expect("decision serializes"),
            serde_json::json!({ "kind": "refuse", "reason": "no_route_evidence" })
        );
    }
}
