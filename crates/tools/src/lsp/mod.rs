//! Live, lazy LSP query tools over the accepted `core-lsp` protocol/state substrate.
//!
//! Known language adapters are admitted as CodeExecuting, confined by Linux bubblewrap or macOS
//! Seatbelt, and owned by one bounded session/workspace pool. Requests recheck target bytes and
//! carry explicit dependency-freshness attribution; timeout, cancellation, restart, and cleanup
//! stay owner-held.

#[cfg(unix)]
mod capability;
mod input;
mod policy;
mod pool;
mod projection;
mod session;
mod supervisor;
mod wire;

use crate::{Registry, ToolError, ToolExecution, effectfut};
use core_lsp::intel::Position;
use core_protocol::{Capability, Purity, ToolResult, ToolSpec, ToolUse, Trust};
use input::SourceDocument;
use pool::Launcher;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use supervisor::run_query;

const DEFAULT_LOCATION_LIMIT: usize = 50;
const MAX_TOOL_OUTPUT_BYTES: usize = 1024 * 1024;
const LSP_TOOL_CLEANUP_RESERVE: std::time::Duration = std::time::Duration::from_secs(3);

pub use policy::{
    LspLanguageRoute, LspPolicyError, LspRecoveryPolicy, LspRuntimePolicy,
    MAX_LSP_BACKOFF_MILLISECONDS, MAX_LSP_POOL_SERVERS, MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS,
    MAX_LSP_RESTARTS,
};

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct LspHealth {
    pub schema_version: u8,
    pub configured_routes: usize,
    pub pool_slots: usize,
    pub running_servers: usize,
    pub restart_count: u64,
    pub unknown_slots: usize,
    pub freshness_attested_servers: usize,
    pub freshness_unattested_servers: usize,
}

#[derive(Clone, Copy, Debug)]
struct LspDeadlines {
    active: tokio::time::Instant,
    total: tokio::time::Instant,
}

impl LspDeadlines {
    fn from_start(started: tokio::time::Instant, request_timeout_milliseconds: u64) -> Self {
        let active = started + std::time::Duration::from_millis(request_timeout_milliseconds);
        Self {
            active,
            total: active + LSP_TOOL_CLEANUP_RESERVE,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum LspToolError {
    #[error("workspace root is unavailable")]
    WorkspaceUnavailable,
    #[error("source file is unavailable")]
    SourceUnavailable,
    #[error("path must be a bounded control-free relative workspace path")]
    InvalidPath,
    #[error("path escapes the workspace or does not name a regular file")]
    PathEscapesWorkspace,
    #[error("source exceeds the fixed {limit}-byte limit")]
    SourceTooLarge { limit: usize },
    #[error("source is not valid UTF-8")]
    SourceNotUtf8,
    #[error("file type has no built-in language-server adapter")]
    UnsupportedLanguage,
    #[error("selected language-server route has no matching workspace marker")]
    RouteWorkspaceMismatch,
    #[error("file path cannot be represented as a file URI")]
    InvalidFileUri,
    #[error("requested UTF-16 position is outside the document")]
    PositionOutsideDocument,
    #[error("tool arguments are invalid")]
    InvalidArguments,
    #[error("language-server identity source is unavailable")]
    IdentityUnavailable,
    #[error("language-server process identity space is exhausted")]
    IdentityExhausted,
    #[error("language-server runtime policy is invalid")]
    InvalidPolicy,
    #[error("language-server runtime policy is immutable after first activation")]
    PolicyLocked,
    #[error("language-server pool reached its fixed {limit}-server ceiling")]
    PoolFull { limit: usize },
    #[error("language-server restart budget exhausted after {attempts} attempts")]
    RestartBudgetExhausted { attempts: u32 },
    #[error("confined persistent processes are unavailable; refusing an unconfined server")]
    SandboxUnavailable,
    #[error("language-server spawn outcome is unknown")]
    SpawnOutcomeUnknown,
    #[error("language-server process did not expose all required pipes")]
    MissingProcessPipe,
    #[error("language-server transport failed")]
    Transport,
    #[error("language-server write timed out")]
    WriteTimeout,
    #[error("language-server response timed out")]
    ResponseTimeout,
    #[error("language-server operation exceeded its fixed wall-clock budget")]
    OperationTimeout,
    #[error("language-server operation was cancelled")]
    OperationCancelled,
    #[error("language-server shutdown timed out")]
    ShutdownTimeout,
    #[error("language-server closed before the matching response")]
    UnexpectedEof,
    #[error("language-server JSON-RPC envelope is malformed")]
    MalformedEnvelope,
    #[error("language-server returned a response for a non-live request")]
    ForeignResponse,
    #[error("language-server returned JSON-RPC error code {code:?}")]
    ServerResponse { code: Option<i64> },
    #[error("language-server interleaved output exceeds {limit} bytes")]
    InterleavedOutputTooLarge { limit: usize },
    #[error("language-server emitted more than {limit} interleaved messages")]
    TooManyInterleavedMessages { limit: usize },
    #[error("language-server stderr exceeded {limit} observed bytes")]
    StderrLimit { limit: u64 },
    #[error("language-server response correlation was rejected")]
    CorrelationRejected,
    #[error("language-server selected an unsupported position encoding")]
    UnsupportedPositionEncoding,
    #[error("source changed while the language server computed the answer")]
    SourceChanged,
    #[error("language-server emitted protocol output after exit")]
    OutputAfterExit,
    #[error("language-server exited unsuccessfully")]
    ServerExitFailure,
    #[error("language-server lifecycle did not reach a verified terminal state")]
    LifecycleIncomplete,
    #[error("language-server cleanup could not be confirmed")]
    CleanupUnknown,
    #[error("language-server response could not be serialized")]
    Serialization,
    #[error("bounded tool output exceeds {limit} bytes")]
    ToolOutputTooLarge { limit: usize },
    #[error("language-server protocol/state validation failed")]
    Protocol(#[from] core_lsp::LspError),
}

#[derive(Debug, Clone, Copy)]
enum QueryKind {
    Definition {
        position: Position,
        limit: usize,
    },
    References {
        position: Position,
        limit: usize,
        include_declaration: bool,
    },
    Hover {
        position: Position,
    },
}

impl QueryKind {
    fn position(self) -> Position {
        match self {
            Self::Definition { position, .. }
            | Self::References { position, .. }
            | Self::Hover { position } => position,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Definition { .. } => "definition",
            Self::References { .. } => "references",
            Self::Hover { .. } => "hover",
        }
    }
}

/// One exact language-id to direct argv override admitted by plugin composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageServerRoute {
    pub language: String,
    pub command: Vec<String>,
}

#[derive(Clone)]
pub struct LspControl {
    launcher: Arc<Launcher>,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct LspControlError {
    pub message: String,
}

impl LspControl {
    pub fn configure_policy(&self, policy: LspRuntimePolicy) -> Result<(), LspControlError> {
        self.launcher
            .configure_policy(policy)
            .map_err(|error| LspControlError {
                message: error.to_string(),
            })
    }

    pub fn policy(&self) -> LspRuntimePolicy {
        self.launcher.policy()
    }

    pub async fn clean(&self) -> Vec<(String, bool)> {
        self.launcher.clean().await
    }

    pub async fn health(&self) -> LspHealth {
        self.launcher.health().await
    }
}

pub(crate) fn register(
    registry: &mut Registry,
    configured: Vec<LanguageServerRoute>,
) -> Result<Option<LspControl>, ToolError> {
    // A tool that is guaranteed to refuse is prompt pollution, not a capability. Windows needs a
    // Job Object + pipe owner before this long-lived CodeExecuting surface can be admitted.
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Ok(None);
    }
    let policy = LspRuntimePolicy::with_command_overrides(configured).map_err(|error| {
        ToolError::Registration(format!("invalid language-server policy: {error}"))
    })?;
    let launcher = Arc::new(Launcher::new(policy).map_err(|error| {
        ToolError::Registration(format!("cannot initialize LSP launcher: {error}"))
    })?);
    let sensitive_env_names = registry.sensitive_env_names_handle();
    let tool_launcher = Arc::clone(&launcher);
    registry.register_external_effect(
        ToolSpec {
            name: "lsp_query".into(),
            description: "Query definition, references, or hover through a lazily started, \
                          confined language server. The third-party server is admitted as \
                          CodeExecuting, target and output bytes are bounded, target freshness is \
                          rechecked, and a bounded session/workspace server pool owns reuse, \
                          cancellation, restart, and cleanup."
                .into(),
            input_schema: input_schema(),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, root| {
            let launcher = Arc::clone(&tool_launcher);
            let sensitive_env_names = Arc::clone(&sensitive_env_names);
            effectfut::box_it(async move {
                let names = sensitive_env_names
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                match execute(call.clone(), root, launcher, names).await {
                    Ok(content) => ToolExecution::Definite(success(call.id, content)),
                    Err((error, unknown)) => {
                        let result = crate::err_result(call.id, error.to_string());
                        if unknown {
                            ToolExecution::Unknown(result)
                        } else {
                            ToolExecution::Definite(result)
                        }
                    }
                }
            })
        },
    )?;
    Ok(Some(LspControl { launcher }))
}

async fn execute(
    call: ToolUse,
    root: PathBuf,
    launcher: Arc<Launcher>,
    sensitive_env_names: Vec<String>,
) -> Result<String, (LspToolError, bool)> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err((LspToolError::SandboxUnavailable, false));
    }
    let policy = launcher.policy();
    let deadlines = LspDeadlines::from_start(
        tokio::time::Instant::now(),
        policy.recovery.request_timeout_milliseconds,
    );
    execute_inner(call, root, launcher, sensitive_env_names, deadlines).await
}

async fn execute_inner(
    call: ToolUse,
    root: PathBuf,
    launcher: Arc<Launcher>,
    sensitive_env_names: Vec<String>,
    deadlines: LspDeadlines,
) -> Result<String, (LspToolError, bool)> {
    let query_name = call
        .input
        .get("query")
        .and_then(Value::as_str)
        .filter(|query| matches!(*query, "definition" | "references" | "hover"))
        .ok_or((LspToolError::InvalidArguments, false))?;
    let path = call
        .input
        .get("path")
        .and_then(Value::as_str)
        .ok_or((LspToolError::InvalidArguments, false))?;
    let line = bounded_u32(&call.input, "line")?;
    let character = bounded_u32(&call.input, "character")?;
    let routes = launcher.routes();
    let document =
        tokio::time::timeout_at(deadlines.active, SourceDocument::load(&root, path, &routes))
            .await
            .map_err(|_| (LspToolError::OperationTimeout, false))?
            .map_err(|error| (error, false))?;
    let document = Arc::new(document);
    let position = document
        .position(line, character)
        .map_err(|error| (error, false))?;
    if call.name != "lsp_query" {
        return Err((LspToolError::InvalidArguments, false));
    }
    let query = match query_name {
        "definition" => QueryKind::Definition {
            position,
            limit: location_limit(&call.input)?,
        },
        "references" => QueryKind::References {
            position,
            limit: location_limit(&call.input)?,
            include_declaration: call
                .input
                .get("include_declaration")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        },
        "hover" => QueryKind::Hover { position },
        _ => return Err((LspToolError::InvalidArguments, false)),
    };
    let live = run_query(
        Arc::clone(&launcher),
        Arc::clone(&document),
        query,
        sensitive_env_names,
        deadlines.active,
        deadlines.total,
    )
    .await
    .map_err(|failure| (failure.error, failure.outcome_unknown))?;
    if tokio::time::Instant::now() >= deadlines.active {
        return Err((LspToolError::OperationTimeout, false));
    }
    let normalized =
        normalize(query, live.value, document.root()).map_err(|error| (error, false))?;
    let output = json!({
        "schema_version": 2,
        "query": query.label(),
        "server": document.server_label(),
        "server_epoch": live.server_epoch,
        "server_id": live.server_id,
        "server_reused": live.reused_server,
        "server_restart_count": live.restart_count,
        "backend": live.backend,
        "document_sha256": document.digest(),
        "target_freshness_rechecked": true,
        "dependency_freshness": "server_observed_not_attested",
        "freshness_attribution": {
            "target": "sha256_rechecked_after_response",
            "dependencies": "server_observed_not_attested",
            "workspace": "canonical_session_root",
            "server_epoch": live.server_epoch
        },
        "run_genesis_bound": false,
        "result": normalized
    });
    let rendered =
        serde_json::to_string_pretty(&output).map_err(|_| (LspToolError::Serialization, false))?;
    if rendered.len() > MAX_TOOL_OUTPUT_BYTES {
        return Err((
            LspToolError::ToolOutputTooLarge {
                limit: MAX_TOOL_OUTPUT_BYTES,
            },
            false,
        ));
    }
    if tokio::time::Instant::now() >= deadlines.active {
        return Err((LspToolError::OperationTimeout, false));
    }
    Ok(rendered)
}

fn normalize(
    query: QueryKind,
    value: Value,
    canonical_root: &std::path::Path,
) -> Result<Value, LspToolError> {
    match query {
        QueryKind::Definition { limit, .. } | QueryKind::References { limit, .. } => {
            projection::locations(&value, limit, canonical_root)
        }
        QueryKind::Hover { .. } => Ok(projection::hover(&value, canonical_root)),
    }
}

fn bounded_u32(input: &Value, field: &str) -> Result<u32, (LspToolError, bool)> {
    input
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value <= core_lsp::MAX_LSP_POSITION)
        .ok_or((LspToolError::InvalidArguments, false))
}

fn location_limit(input: &Value) -> Result<usize, (LspToolError, bool)> {
    let value = input
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_LOCATION_LIMIT as u64);
    usize::try_from(value)
        .ok()
        .filter(|limit| (1..=core_lsp::MAX_LOCATIONS).contains(limit))
        .ok_or((LspToolError::InvalidArguments, false))
}

fn input_schema() -> Value {
    json!({
        "type":"object",
        "properties": {
        // Not an `enum`: `schema::validate` accepts a closed keyword allowlist that does not
        // include it, so declaring one makes `Registry::coding_agent` refuse to build at all. The
        // three values are still the only ones accepted -- `parse_query_kind` rejects anything
        // else as invalid arguments -- so this is where they are named, not where they are
        // enforced.
        "query": {"type":"string", "description":"One of: definition, references, hover."},
        "path": {"type":"string", "description":"Relative workspace source path."},
        "line": {"type":"integer", "description":"Zero-based line; validated against the source and LSP uinteger ceiling."},
        "character": {"type":"integer", "description":"Zero-based UTF-16 code-unit offset; validated against the source and LSP uinteger ceiling."},
        "limit": {
            "type":"integer",
            "description":format!("Maximum normalized locations retained, in [1, {}].", core_lsp::MAX_LOCATIONS)
        },
        "include_declaration": {"type":"boolean", "description":"References only; defaults true."}
        },
        "required":["query","path","line","character"]
    })
}

fn success(id: String, content: String) -> ToolResult {
    ToolResult {
        tool_use_id: id,
        content,
        is_error: false,
        // A language server is a third-party executable and can synthesize arbitrary hover or
        // location content. Confinement limits effects; it does not promote its words to trust.
        trust: Trust::Untrusted,
        latency_ms: 0,
    }
}

#[cfg(test)]
mod tests;
