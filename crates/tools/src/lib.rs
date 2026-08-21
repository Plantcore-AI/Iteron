//! iteron-tools owns the tool ABI, concrete executors, and their generation-scoped memo.
//! Registration enforces that `Pure` means `ReadOnly`; effecting tools carry explicit capability
//! and invalidate cached reads when their attempt completes. Code execution crosses the platform
//! sandbox rather than relying on the model's declaration.

use iteron_protocol::intent::ToolIntent;
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{Capability, Purity, ToolResult, ToolSpec, ToolUse, Trust};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod edit;
mod egress;
mod execution_policy;
mod fs_tools;
mod git;
mod git_changes;
mod git_filters;
mod git_harness;
mod git_observe;
mod grep_tool;
mod lsp;
mod mcp_timing;
mod mem;
mod memo;
mod multi_file_patch;
mod multi_file_patch_error;
mod multi_file_patch_input;
mod process;
mod schema;
mod schema_error;
mod shell;
mod skill;
mod tool_policy;
mod tool_purpose;
mod tool_search;
mod web;
mod workflow_tool;
mod workspace_boundary;
mod write_file;

pub use tool_search::DEFAULT_DEFERRED_TOOL_EAGER_LIMIT;
pub use web::WEB_SEARCH_RESULT_CAP;

pub use edit::apply_unique_edit;
pub use egress::{EgressAllowPolicy, EgressPolicyError, MAX_EGRESS_HOST_BYTES, MAX_EGRESS_HOSTS};
pub use execution_policy::{
    DirectoryListPolicy, GitPolicy, GlobPolicy, GrepPolicy, ObservationToolPolicy,
    ObservationToolPolicyError, ReadFilePolicy, RepoMapPolicy, ShellPolicy, WebFetchPolicy,
};
pub use lsp::{
    LanguageServerRoute, LspControl, LspControlError, LspHealth, LspLanguageRoute, LspPolicyError,
    LspRecoveryPolicy, LspRuntimePolicy, MAX_LSP_BACKOFF_MILLISECONDS, MAX_LSP_POOL_SERVERS,
    MAX_LSP_REQUEST_TIMEOUT_MILLISECONDS, MAX_LSP_RESTARTS,
};
pub use mcp_timing::{McpDispatchClock, McpEffectAttribution};
pub use memo::PureMemoCachePolicy;
use memo::{Lookup, Memo};
pub use process::{
    ChildProcessEnvironmentPolicy, InteractiveStdinWaitPolicy, MAX_BACKGROUND_JOBS,
    MAX_CHILD_ENV_BYTES, MAX_CHILD_ENV_ENTRIES, MAX_IDLE_STALL_MILLISECONDS,
    MAX_STDIN_POLL_MILLISECONDS, PersistentBackendSelection, ProcessControl, ProcessControlError,
    ProcessCwdPolicy, ProcessCwdScope, ProcessHealth, ProcessLaunchPolicy, ProcessLifecycleKind,
    ProcessLifecycleNotice, ProcessLifecycleObserver, ProcessPolicyError, ProcessRuntimePolicy,
};
pub use tool_policy::{
    RegisteredToolPolicy, TOOL_POLICY_SLOT_VERSION, ToolPolicy, ToolPolicyDecision,
    ToolPolicyError, ToolPolicyObservation, ToolPolicyProposal,
};
use tool_purpose::ToolPurpose;

/// Dispatch->terminal interval reported when the clock never observed a dispatch: a typed
/// pre-dispatch rejection spent no time in the MCP transport, so the interval is empty rather
/// than absent.
const MCP_PRE_DISPATCH_TERMINAL_MS: u64 = 0;

/// Shared hardened Git observation used by the registry tool and the operator `/diff` surface.
/// It remains an observable process effect; callers outside the registry must provide their own
/// operator/audit boundary.
pub async fn git_diff_observation(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    git::run_git_diff(root, stat, requested_path).await
}

/// The staged half of the same bounded Git observation. Keeping it distinct prevents a review
/// caller from accidentally presenting bare `git diff` as the complete change set.
pub async fn git_index_diff_observation(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    git::run_git_index_diff(root, stat, requested_path).await
}

/// Bounded, hook/filter/config-neutralized branch and status-count snapshot for a trusted frontend
/// to record as environment context. No repository path or commit text is returned.
pub async fn git_environment_observation(root: &Path) -> Result<String, String> {
    git_observe::run_git_environment(root).await
}

/// Exact, NUL-delimited `git status --porcelain=v1 -z` bytes for the operator review and rewind
/// surfaces. The result is refused rather than truncated, so the typed parser never receives a
/// partial record or mistakes a bounded prefix for the complete workspace.
pub async fn git_status_porcelain_observation(root: &Path) -> Result<Vec<u8>, String> {
    git_changes::run_git_status_porcelain(root).await
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("registration: {0}")]
    Registration(String),
    #[error("unknown tool: {0}")]
    Unknown(String),
}

/// A boxed-future alias so the registry can hold heterogeneous async executors. Public so
/// external tool sources (e.g. the MCP client, wired by the CLI) can register their own tools.
pub mod boxfut {
    use iteron_protocol::ToolResult;
    use std::future::Future;
    use std::pin::Pin;
    pub type BoxFut = Pin<Box<dyn Future<Output = ToolResult> + Send>>;
    pub fn box_it(f: impl Future<Output = ToolResult> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

/// Certainty of an effecting executor attempt. `Definite` covers both success and a failure that
/// is known not to be an unresolved remote/partial outcome. `Unknown` means dispatch may have
/// happened but no authoritative terminal response was observed; the kernel must durably block
/// automatic replay instead of flattening it into `ToolResult::is_error`.
#[derive(Debug, Clone)]
pub enum ToolExecution {
    Definite(ToolResult),
    Unknown(ToolResult),
}

impl ToolExecution {
    fn result_mut(&mut self) -> &mut ToolResult {
        match self {
            Self::Definite(result) | Self::Unknown(result) => result,
        }
    }

    pub fn into_result(self) -> ToolResult {
        match self {
            Self::Definite(result) | Self::Unknown(result) => result,
        }
    }
}

impl From<ToolResult> for ToolExecution {
    fn from(result: ToolResult) -> Self {
        Self::Definite(result)
    }
}

/// Outcome-aware future used only by effect executors that can distinguish a durable terminal
/// from an externally unknown result (currently MCP). Ordinary tools use [`boxfut`] and are
/// conservatively adapted to `Definite` until their own effect family is brokered.
pub mod effectfut {
    use super::ToolExecution;
    use std::future::Future;
    use std::pin::Pin;
    pub type BoxFut = Pin<Box<dyn Future<Output = ToolExecution> + Send>>;
    pub fn box_it(f: impl Future<Output = ToolExecution> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

struct RegisteredExecution {
    outcome: ToolExecution,
    /// Present only for a registry-minted, explicitly attributed MCP dispatch clock.
    dispatch_to_terminal_ms: Option<u64>,
}

mod registeredfut {
    use super::RegisteredExecution;
    use std::future::Future;
    use std::pin::Pin;

    pub type BoxFut = Pin<Box<dyn Future<Output = RegisteredExecution> + Send>>;

    pub fn box_it(f: impl Future<Output = RegisteredExecution> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

/// A registered tool: its spec plus its executor.
pub struct Tool {
    pub spec: ToolSpec,
    run: Box<dyn Fn(ToolUse, PathBuf) -> registeredfut::BoxFut + Send + Sync>,
    output_owner: ToolOutputOwner,
    purpose: ToolPurpose,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToolOutputOwner {
    Runtime,
    Mcp,
}

#[derive(Clone, Copy)]
enum ToolOrigin {
    BuiltIn,
    External,
}

/// The tool registry. Enforces the purity/capability coupling at registration and memoizes PURE
/// tool results in a fixed-bounded generation cache. Every completed EFFECTING attempt advances
/// the generation, so a registry-mediated write invalidates prior reads and raced old-generation
/// results cannot repopulate the cache.
pub struct Registry {
    tools: Vec<Tool>,
    spec_revision: std::sync::atomic::AtomicU64,
    spec_snapshot: std::sync::Mutex<Option<Arc<ToolSpecSnapshot>>>,
    task_spec_snapshot: std::sync::Mutex<Option<TaskToolSpecSnapshot>>,
    root: PathBuf,
    memo: std::sync::Arc<Memo>,
    sensitive_env_names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// When set, `bash` runs in the egress-off platform sandbox instead of with the operator's own
    /// authority. Default false (owner-directed 2026-08-05); the CLI sets it from `--confine`.
    /// Shared exactly like `sensitive_env_names`, so it can be answered after the specs are built
    /// without rebuilding them and invalidating prompt-cache identity.
    confine_execution: std::sync::Arc<std::sync::atomic::AtomicBool>,
    egress_allow_policy: std::sync::Arc<std::sync::OnceLock<Option<EgressAllowPolicy>>>,
    observation_tool_policy: std::sync::Arc<std::sync::OnceLock<ObservationToolPolicy>>,
    process_launch_policy:
        std::sync::Arc<std::sync::OnceLock<process::InstalledProcessLaunchPolicy>>,
    /// Fail-closed path scope used only by a host-provisioned isolated writer. Ordinary operator
    /// registries intentionally retain the owner-directed host-wide path behavior documented by
    /// [`resolve_in_root`].
    workspace_boundary: bool,
    process_control: Option<ProcessControl>,
    lsp_control: Option<LspControl>,
    deferred_tool_catalog: Option<tool_search::DeferredToolCatalog>,
}

/// Immutable, revisioned tool-schema materialization. Provider request builders can retain this
/// object across turns without cloning every JSON schema or serializing an unchanged tool set.
#[derive(Debug)]
pub struct ToolSpecSnapshot {
    revision: u64,
    specs: Arc<[ToolSpec]>,
}

impl ToolSpecSnapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn specs(&self) -> &Arc<[ToolSpec]> {
        &self.specs
    }
}

/// A task filter references an immutable base snapshot by indices. It does not clone schemas.
#[derive(Debug, Clone)]
pub struct TaskToolSpecSnapshot {
    base: Arc<ToolSpecSnapshot>,
    indices: Arc<[usize]>,
    serialized_json: Arc<str>,
    estimated_tokens: usize,
}

impl TaskToolSpecSnapshot {
    pub fn revision(&self) -> u64 {
        self.base.revision()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ToolSpec> {
        self.indices.iter().map(|index| &self.base.specs[*index])
    }

    pub fn serialized_json(&self) -> &Arc<str> {
        &self.serialized_json
    }

    pub fn estimated_tokens(&self) -> usize {
        self.estimated_tokens
    }
}

impl Registry {
    /// Process-wide immutable owner of whether independent PURE calls may overlap. The instance
    /// method below delegates to this owner so resume admission can re-sample the same physical
    /// invariant without constructing a synthetic registry.
    pub const fn pure_overlap_owner() -> bool {
        true
    }

    /// Fixed product invariant consumed by the streaming scheduler before it dispatches a pure
    /// call. Hooks and policy admission may narrow this to deferred execution; they never expand
    /// the set of eligible calls.
    pub const fn pure_overlap_enabled(&self) -> bool {
        Self::pure_overlap_owner()
    }

    /// Exact policy of this registry's physical memo owner.
    pub fn pure_memo_cache_policy(&self) -> PureMemoCachePolicy {
        self.memo.policy()
    }

    pub fn install_pure_memo_cache_policy(
        &self,
        policy: PureMemoCachePolicy,
    ) -> Result<(), &'static str> {
        self.memo.install_policy(policy)
    }

    /// Build the default coding-agent tool set rooted at `root` (the repo the agent works in).
    pub fn coding_agent(root: impl Into<PathBuf>) -> Result<Self, ToolError> {
        Self::coding_agent_with_lsp_routes(root, Vec::new())
    }

    /// Build the coding-agent registry with exact operator-admitted language-server overrides.
    pub fn coding_agent_with_lsp_routes(
        root: impl Into<PathBuf>,
        lsp_routes: Vec<LanguageServerRoute>,
    ) -> Result<Self, ToolError> {
        let root = root.into();
        let mut r = Registry {
            tools: Vec::new(),
            spec_revision: Default::default(),
            spec_snapshot: Default::default(),
            task_spec_snapshot: Default::default(),
            root,
            memo: Default::default(),
            sensitive_env_names: Default::default(),
            confine_execution: Default::default(),
            egress_allow_policy: Default::default(),
            observation_tool_policy: Default::default(),
            process_launch_policy: Default::default(),
            workspace_boundary: false,
            process_control: None,
            lsp_control: None,
            deferred_tool_catalog: None,
        };
        fs_tools::register(&mut r)?;
        git::register(&mut r)?;
        mem::register(&mut r)?;
        skill::register(&mut r)?;
        edit::register(&mut r)?;
        multi_file_patch::register(&mut r)?;
        write_file::register(&mut r)?;
        let process_supervisor = process::new_supervisor()?;
        shell::register(&mut r, std::sync::Arc::clone(&process_supervisor))?;
        r.process_control = Some(process::register_with_supervisor(
            &mut r,
            process_supervisor,
        )?);
        r.lsp_control = lsp::register(&mut r, lsp_routes)?;
        // `lsp_query` uses the outcome-aware external-executor adapter because a third-party
        // language server may leave an uncertain effect. Its ToolSpec is nevertheless compiled
        // into Iteron, so classify just that description as built-in before catalog publication.
        r.resolve_registered_builtin_description("lsp_query");
        // Web egress (web_fetch/web_search): Effecting/IrreversibleExternal, so the capability gate
        // never auto-approves them (ADR-007 §3) and they are absent from the read_only subagent set.
        web::register(&mut r)?;
        register_dispatch_agent(&mut r)?;
        // The Workflow launch tool is a WRITER-only surface: it fans out real sub-agents, so it is
        // registered here and deliberately absent from `read_only` (design §4.1).
        workflow_tool::register(&mut r)?;
        r.deferred_tool_catalog = Some(tool_search::register(&mut r)?);
        Ok(r)
    }

    /// Build the fixed registry for a host-provisioned isolated writer.
    ///
    /// No shell, process, LSP, web, MCP, dispatch, or workflow executor is registered. Every
    /// remaining caller-supplied `path` is checked at dispatch against the canonical worktree
    /// boundary before the ordinary executor can resolve or open it.
    pub fn isolated_writer(root: impl Into<PathBuf>) -> Result<Self, ToolError> {
        let root = root.into();
        workspace_boundary::validate_root(&root).map_err(ToolError::Registration)?;
        let mut registry = Registry {
            tools: Vec::new(),
            spec_revision: Default::default(),
            spec_snapshot: Default::default(),
            task_spec_snapshot: Default::default(),
            root,
            memo: Default::default(),
            sensitive_env_names: Default::default(),
            confine_execution: Default::default(),
            egress_allow_policy: Default::default(),
            observation_tool_policy: Default::default(),
            process_launch_policy: Default::default(),
            workspace_boundary: true,
            process_control: None,
            lsp_control: None,
            deferred_tool_catalog: None,
        };
        fs_tools::register(&mut registry)?;
        git::register(&mut registry)?;
        mem::register(&mut registry)?;
        skill::register(&mut registry)?;
        edit::register(&mut registry)?;
        multi_file_patch::register(&mut registry)?;
        write_file::register(&mut registry)?;
        registry.deferred_tool_catalog = Some(tool_search::register(&mut registry)?);
        Ok(registry)
    }

    /// Build a READ-ONLY tool set (read_file, list_dir, grep, repo_map). This is what a
    /// subagent gets: it explores and reports, it never writes (ADR-001, the single-writer
    /// invariant — the parent is the sole writer).
    pub fn read_only(root: impl Into<PathBuf>) -> Result<Self, ToolError> {
        let root = root.into();
        let mut r = Registry {
            tools: Vec::new(),
            spec_revision: Default::default(),
            spec_snapshot: Default::default(),
            task_spec_snapshot: Default::default(),
            root,
            memo: Default::default(),
            sensitive_env_names: Default::default(),
            confine_execution: Default::default(),
            egress_allow_policy: Default::default(),
            observation_tool_policy: Default::default(),
            process_launch_policy: Default::default(),
            workspace_boundary: false,
            process_control: None,
            lsp_control: None,
            deferred_tool_catalog: None,
        };
        fs_tools::register(&mut r)?; // read_file, list_dir, grep, repo_map only
        git::register(&mut r)?; // confined Git observations (Effecting/ReadOnly)
        mem::register(&mut r)?; // read_memory (Pure/ReadOnly) — progressive-disclosure recall
        skill::register(&mut r)?; // use_skill (Pure/ReadOnly) — on-demand skill load
        r.deferred_tool_catalog = Some(tool_search::register(&mut r)?);
        Ok(r)
    }

    /// Register an externally supplied tool, checking the type rules (ADR-007 R16).
    ///
    /// External and MCP descriptions are untrusted provider input. They deliberately bypass the
    /// built-in description tunables namespace even if their spelling resembles an internal tool.
    pub fn register(&mut self, tool: Tool) -> Result<(), ToolError> {
        self.register_with_origin(tool, ToolOrigin::External)
    }

    fn resolve_registered_builtin_description(&mut self, canonical_name: &str) {
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.spec.name == canonical_name)
        {
            let description =
                iteron_tunables::tool_description(canonical_name, &tool.spec.description)
                    .to_owned();
            replace_description_only(&mut tool.spec, &description);
        }
    }

    /// The one registration boundary. Description resolution is the only mutation performed for
    /// built-ins; name, schema, purity, capability and all downstream permission/trust handling
    /// remain the values supplied by the concrete tool declaration.
    fn register_with_origin(
        &mut self,
        mut tool: Tool,
        origin: ToolOrigin,
    ) -> Result<(), ToolError> {
        if matches!(origin, ToolOrigin::BuiltIn) {
            let description =
                iteron_tunables::tool_description(&tool.spec.name, &tool.spec.description)
                    .to_owned();
            replace_description_only(&mut tool.spec, &description);
        }
        let s = &tool.spec;
        // The load-bearing invariant: purity licenses early dispatch, so a Pure tool that can
        // egress or execute code is a contradiction we refuse at registration.
        if s.purity == Purity::Pure && !matches!(s.capability, Capability::ReadOnly) {
            return Err(ToolError::Registration(format!(
                "tool `{}` is Pure but capability is {:?}; Pure requires ReadOnly (ADR-007 R16)",
                s.name, s.capability
            )));
        }
        schema::validate_schema(&s.input_schema).map_err(|error| {
            ToolError::Registration(format!(
                "tool `{}` has an invalid input schema: {error}",
                s.name
            ))
        })?;
        if self.tools.iter().any(|t| t.spec.name == s.name) {
            return Err(ToolError::Registration(format!(
                "duplicate tool `{}`",
                s.name
            )));
        }
        if let Some(catalog) = &self.deferred_tool_catalog {
            catalog.insert(tool.spec.clone());
        }
        self.tools.push(tool);
        self.invalidate_spec_snapshot();
        Ok(())
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.spec_snapshot().specs.to_vec()
    }

    pub fn spec_snapshot(&self) -> Arc<ToolSpecSnapshot> {
        let revision = self
            .spec_revision
            .load(std::sync::atomic::Ordering::Acquire);
        let mut cached = self
            .spec_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(snapshot) = cached
            .as_ref()
            .filter(|snapshot| snapshot.revision == revision)
        {
            return Arc::clone(snapshot);
        }
        let specs: Arc<[ToolSpec]> = self
            .tools
            .iter()
            .map(|tool| tool.spec.clone())
            .collect::<Vec<_>>()
            .into();
        let snapshot = Arc::new(ToolSpecSnapshot { revision, specs });
        *cached = Some(Arc::clone(&snapshot));
        snapshot
    }

    pub fn specs_for_task_snapshot(
        &self,
        admitted_names: &std::collections::BTreeSet<String>,
        task: &str,
        eager_limit: Option<usize>,
    ) -> TaskToolSpecSnapshot {
        let base = self.spec_snapshot();
        let visible = eager_limit
            .filter(|limit| *limit > 0)
            .filter(|_| admitted_names.contains(tool_search::TOOL_SEARCH))
            .and_then(|limit| {
                self.deferred_tool_catalog
                    .as_ref()
                    .map(|catalog| catalog.visible(admitted_names, task, limit))
            });
        let indices = base
            .specs
            .iter()
            .enumerate()
            .filter(|(_, spec)| {
                admitted_names.contains(&spec.name)
                    && visible
                        .as_ref()
                        .is_none_or(|names| names.contains(&spec.name))
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let mut cached = self
            .task_spec_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(snapshot) = cached.as_ref().filter(|snapshot| {
            snapshot.revision() == base.revision() && snapshot.indices.as_ref() == indices
        }) {
            return snapshot.clone();
        }
        let selected = indices
            .iter()
            .map(|index| &base.specs[*index])
            .collect::<Vec<_>>();
        let serialized_json: Arc<str> = serde_json::to_string(&selected)
            .expect("registered task tool schemas must serialize")
            .into();
        let snapshot = TaskToolSpecSnapshot {
            base,
            indices: indices.into(),
            estimated_tokens: iteron_ctx::estimate_tokens(&serialized_json),
            serialized_json,
        };
        *cached = Some(snapshot.clone());
        snapshot
    }

    fn invalidate_spec_snapshot(&self) {
        self.spec_revision
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        *self
            .spec_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .task_spec_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Whether this result is already governed by the MCP transport's private cap/spill owner.
    /// Ordinary runtime output policy must not re-own or re-spill those bytes.
    pub fn is_mcp_effect(&self, name: &str) -> bool {
        self.tools
            .iter()
            .any(|tool| tool.spec.name == name && tool.output_owner == ToolOutputOwner::Mcp)
    }

    /// Return a bounded task-relevant prefix while preserving a `tool_search` path to every
    /// authority-admitted registered schema. `None` keeps eager compatibility behavior.
    pub fn specs_for_task(
        &self,
        admitted_names: &std::collections::BTreeSet<String>,
        task: &str,
        eager_limit: Option<usize>,
    ) -> Vec<ToolSpec> {
        let Some(limit) = eager_limit
            .filter(|limit| *limit > 0)
            .filter(|_| admitted_names.contains(tool_search::TOOL_SEARCH))
        else {
            return self
                .tools
                .iter()
                .filter(|tool| admitted_names.contains(&tool.spec.name))
                .map(|tool| tool.spec.clone())
                .collect();
        };
        let Some(catalog) = &self.deferred_tool_catalog else {
            return self
                .tools
                .iter()
                .filter(|tool| admitted_names.contains(&tool.spec.name))
                .map(|tool| tool.spec.clone())
                .collect();
        };
        let visible = catalog.visible(admitted_names, task, limit);
        self.tools
            .iter()
            .filter(|tool| visible.contains(&tool.spec.name))
            .map(|tool| tool.spec.clone())
            .collect()
    }

    /// Session-owned job-control view over the exact supervisor backing the process tools.
    pub fn process_control(&self) -> Option<ProcessControl> {
        self.process_control.clone()
    }

    /// Session-owned language-server pool control over the exact launcher backing `lsp_query`.
    pub fn lsp_control(&self) -> Option<LspControl> {
        self.lsp_control.clone()
    }

    /// Retain only the named tools and return the canonical names that remain.
    ///
    /// This is the executable-agent narrowing seam. It can only remove existing registrations:
    /// unknown requested names are ignored and no constructor or registration closure is exposed.
    /// Callers must start from [`Registry::read_only`] when the resulting registry represents a
    /// read-only child.
    pub fn narrow_to(&mut self, allowed: &[String]) -> Vec<String> {
        self.tools
            .retain(|tool| allowed.iter().any(|name| name == &tool.spec.name));
        if let Some(catalog) = &self.deferred_tool_catalog {
            catalog.retain(
                &self
                    .tools
                    .iter()
                    .map(|tool| tool.spec.name.clone())
                    .collect(),
            );
        }
        self.invalidate_spec_snapshot();
        self.tools
            .iter()
            .map(|tool| tool.spec.name.clone())
            .collect()
    }

    /// Narrow to `allowed`, then stably promote the named tools. Promotion can reorder an
    /// admitted set but can never add a tool that the registry or the caller refused.
    pub fn narrow_to_promoting(&mut self, allowed: &[String], leading: &[&str]) -> Vec<String> {
        self.narrow_to(allowed);
        if !leading.is_empty() {
            let rank = |tool: &Tool| {
                leading
                    .iter()
                    .position(|name| *name == tool.spec.name)
                    .unwrap_or(leading.len())
            };
            self.tools.sort_by_key(rank);
            self.invalidate_spec_snapshot();
        }
        self.tools
            .iter()
            .map(|tool| tool.spec.name.clone())
            .collect()
    }

    pub fn purity_of(&self, name: &str) -> Option<Purity> {
        self.tools
            .iter()
            .find(|t| t.spec.name == name)
            .map(|t| t.spec.purity)
    }

    pub fn capability_of(&self, name: &str) -> Option<Capability> {
        self.tools
            .iter()
            .find(|t| t.spec.name == name)
            .map(|t| t.spec.capability)
    }

    /// Classify a model-emitted call through the pure `core/tool_policy` slot.
    ///
    /// Registry metadata is the only source of purity and capability. This method does not
    /// validate arguments or call an executor; the returned intent remains deny-by-default until
    /// the kernel's gate records and applies its admission decision.
    pub fn propose_intent(
        &self,
        policy: &dyn StrategySlot,
        call: ToolUse,
        argument_trust: Trust,
        ceiling: iteron_protocol::capability_set::CapabilitySet,
    ) -> Result<ToolPolicyProposal, ToolPolicyError> {
        let spec = self
            .tools
            .iter()
            .find(|tool| tool.spec.name == call.name)
            .map(|tool| &tool.spec)
            .ok_or_else(|| ToolPolicyError::UnknownTool(call.name.clone()))?;
        ToolPolicy::propose_with(
            policy,
            &ToolPolicyObservation {
                version: TOOL_POLICY_SLOT_VERSION,
                call,
                registered: RegisteredToolPolicy {
                    name: spec.name.clone(),
                    purity: spec.purity,
                    capability: spec.capability,
                },
                argument_trust,
            },
            ceiling,
        )
    }

    /// Dispatch a pure tool only after the policy proposal and caller gate admitted its exact
    /// registry capability. A malformed or stale intent becomes a tool error; no executor future
    /// is constructed.
    pub fn dispatch_intent(&self, intent: ToolIntent) -> boxfut::BoxFut {
        if let Err(reason) = self.validate_admitted_intent(&intent, Some(Purity::Pure)) {
            let id = intent.call.id;
            return boxfut::box_it(async move { err_result(id, reason) });
        }
        self.dispatch(intent.call)
    }

    /// Execute an admitted post-stream call while preserving effect-outcome certainty.
    pub async fn run_admitted_intent(&self, intent: ToolIntent) -> ToolExecution {
        if let Err(reason) = self.validate_admitted_intent(&intent, None) {
            return ToolExecution::Definite(err_result(intent.call.id, reason));
        }
        self.run_effect(intent.call).await
    }

    fn validate_admitted_intent(
        &self,
        intent: &ToolIntent,
        required_purity: Option<Purity>,
    ) -> Result<(), String> {
        intent
            .validate()
            .map_err(|reason| format!("invalid tool intent: {reason}"))?;
        let spec = self
            .tools
            .iter()
            .find(|tool| tool.spec.name == intent.call.name)
            .map(|tool| &tool.spec)
            .ok_or_else(|| format!("unknown tool `{}`", intent.call.name))?;
        if intent.purity != spec.purity || required_purity.is_some_and(|p| p != spec.purity) {
            return Err(format!(
                "tool intent metadata does not match registry purity for `{}`",
                intent.call.name
            ));
        }
        if !intent.admitted.contains(spec.capability) {
            return Err(format!(
                "tool intent lacks registry capability admission for `{}`",
                intent.call.name
            ));
        }
        Ok(())
    }

    /// Install the trusted provider directory's exact credential environment names. The shell
    /// executor holds the same shared cell, so this may be called after provider discovery without
    /// rebuilding tool specs or invalidating prompt-cache identity.
    pub fn set_sensitive_env_names(&mut self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        *self.sensitive_env_names.lock().unwrap() = names;
    }

    pub(crate) fn sensitive_env_names_handle(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        self.sensitive_env_names.clone()
    }

    /// Put `bash` back inside the egress-off platform sandbox (`--confine`). This is the whole
    /// opt-out: the confined backends are unchanged, and this selects them.
    pub fn set_confine_execution(&mut self, confine: bool) {
        self.confine_execution
            .store(confine, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn confine_execution_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.confine_execution.clone()
    }

    /// Install the immutable first-party egress policy before tool activation.
    ///
    /// `None` is the explicit legacy/unconfined posture. `Some(empty)` is materially different: it
    /// denies every destination. Installation is one-shot so a resumed run cannot silently adopt
    /// current config after its tunables checkpoint was pinned.
    pub fn install_egress_allow_policy(
        &self,
        policy: Option<EgressAllowPolicy>,
    ) -> Result<(), EgressPolicyError> {
        self.egress_allow_policy
            .set(policy)
            .map_err(|_| EgressPolicyError::InvalidDestination {
                value: "egress_allow".to_owned(),
                reason: "policy was already installed for this registry",
            })
    }

    pub(crate) fn egress_allow_policy_handle(
        &self,
    ) -> std::sync::Arc<std::sync::OnceLock<Option<EgressAllowPolicy>>> {
        self.egress_allow_policy.clone()
    }

    /// Snapshot the installed immutable egress owner. The outer `Option` distinguishes an
    /// unconfigured registry from the explicitly unconfined `None` policy.
    pub fn installed_egress_allow_policy(&self) -> Option<Option<EgressAllowPolicy>> {
        self.egress_allow_policy.get().cloned()
    }

    /// Install the immutable bounded-observation policy before the first tool dispatch.
    pub fn install_observation_tool_policy(
        &self,
        policy: ObservationToolPolicy,
    ) -> Result<(), ObservationToolPolicyError> {
        let policy = policy
            .validate()
            .map_err(ObservationToolPolicyError::Invalid)?;
        self.observation_tool_policy
            .set(policy)
            .map_err(|_| ObservationToolPolicyError::AlreadyInstalled)
    }

    pub(crate) fn observation_tool_policy_handle(
        &self,
    ) -> std::sync::Arc<std::sync::OnceLock<ObservationToolPolicy>> {
        self.observation_tool_policy.clone()
    }

    pub fn installed_observation_tool_policy(&self) -> Option<ObservationToolPolicy> {
        self.observation_tool_policy.get().copied()
    }

    /// Freeze the process working-directory and bounded ambient-environment owners before any
    /// process effect. The private values are captured once here; later environment mutation or
    /// resume-time config drift cannot change what a child inherits.
    pub fn install_process_launch_policy(
        &self,
        policy: ProcessLaunchPolicy,
    ) -> Result<(), ProcessPolicyError> {
        let policy = ProcessLaunchPolicy::new(policy.cwd, policy.environment)?;
        let sensitive = self
            .sensitive_env_names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let child_environment = iteron_sandbox::bounded_child_environment(
            policy.environment.reuse,
            policy.environment.max_entries,
            policy.environment.max_bytes,
            &policy.environment.blocked_names,
            &sensitive,
        )
        .map_err(|_| ProcessPolicyError::EnvironmentPolicy)?;
        self.process_launch_policy
            .set(process::InstalledProcessLaunchPolicy {
                policy,
                child_environment,
            })
            .map_err(|_| ProcessPolicyError::LaunchPolicyAlreadyInstalled)
    }

    pub fn installed_process_launch_policy(&self) -> Option<ProcessLaunchPolicy> {
        self.process_launch_policy
            .get()
            .map(|installed| installed.policy.clone())
    }

    pub(crate) fn process_launch_policy_handle(
        &self,
    ) -> std::sync::Arc<std::sync::OnceLock<process::InstalledProcessLaunchPolicy>> {
        self.process_launch_policy.clone()
    }

    /// Execute a tool call. `latency_ms` is measured here (tau_wall contribution for obs). An
    /// EFFECTING tool bumps the memo generation on completion, invalidating every cached pure
    /// read (a write must never leave a stale read servable).
    pub async fn run_effect(&self, call: ToolUse) -> ToolExecution {
        let started = Instant::now();
        let id = call.id.clone();
        let Some(tool) = self.tools.iter().find(|tool| tool.spec.name == call.name) else {
            return ToolExecution::Definite(ToolResult {
                tool_use_id: id.clone(),
                content: format!("unknown tool `{}`", call.name),
                is_error: true,
                trust: Trust::Trusted,
                latency_ms: started.elapsed().as_millis() as u64,
            });
        };
        if let Err(error) = schema::validate_arguments(&tool.spec.input_schema, &call.input) {
            return ToolExecution::Definite(err_result(id, error.model_json(&tool.spec.name)));
        }
        if self.workspace_boundary
            && let Err(reason) = workspace_boundary::validate_call(&self.root, &call)
        {
            return ToolExecution::Definite(err_result(id, reason));
        }

        let is_effecting = tool.spec.purity == Purity::Effecting;
        let registered = (tool.run)(call, self.root.clone()).await;
        let mut outcome = registered.outcome;
        // A plugin closure does not own provider correlation identity. Normalize it at the
        // registry boundary so a buggy/malicious implementation cannot mis-associate a result.
        let result = outcome.result_mut();
        result.tool_use_id = id;
        result.latency_ms = registered
            .dispatch_to_terminal_ms
            .unwrap_or_else(|| started.elapsed().as_millis() as u64);
        if is_effecting {
            // An effecting implementation may mutate partially before returning an error. The
            // only safe cache rule is therefore to invalidate on every completed attempt, not
            // only on a success-shaped ToolResult.
            self.memo.invalidate();
        }
        outcome
    }

    /// Compatibility projection for callers that do not own effect recovery. The kernel's
    /// effecting path must use [`Registry::run_effect`] so it cannot erase `Unknown` certainty.
    pub async fn run(&self, call: ToolUse) -> ToolResult {
        self.run_effect(call).await.into_result()
    }

    /// Memo hit/miss counts (for obs telemetry).
    pub fn memo_stats(&self) -> (u64, u64) {
        self.memo.stats()
    }

    /// Install the immutable, run-pinned lifetime of deterministic pure-tool results. Zero turns
    /// reuse off without disabling the pure executor itself.
    pub fn install_tool_result_cache_ttl(&self, ttl_seconds: u64) -> Result<(), ToolError> {
        self.memo
            .install_ttl_seconds(ttl_seconds)
            .map_err(|reason| ToolError::Registration(reason.into()))
    }

    /// Exact live memo-owner value used by tunables activation evidence and adoption checks.
    pub fn tool_result_cache_ttl_seconds(&self) -> u64 {
        self.memo.ttl_seconds()
    }

    /// Invalidate pure observations after an explicit ambient-state mutation that happened outside
    /// the registry's executor boundary. Callers must carry their own authoritative mutation
    /// signal; the registry never guesses from mtimes or unrelated filesystem drift.
    pub fn invalidate_pure_cache(&self) {
        self.memo.invalidate();
    }

    /// Hand back an owned, `'static` future for a tool call — so the scheduler can
    /// `tokio::spawn` a *pure* tool the instant its `content_block_stop` arrives, overlapping
    /// it with the still-decoding turn (ADR-004, the flagship). The borrow of `&self` ends
    /// when this returns; the future it yields owns everything it needs.
    pub fn dispatch(&self, call: ToolUse) -> boxfut::BoxFut {
        let Some(tool) = self.tools.iter().find(|tool| tool.spec.name == call.name) else {
            let id = call.id.clone();
            let name = call.name.clone();
            return boxfut::box_it(async move { err_result(id, format!("unknown tool `{name}`")) });
        };
        if let Err(error) = schema::validate_arguments(&tool.spec.input_schema, &call.input) {
            let result = err_result(call.id.clone(), error.model_json(&tool.spec.name));
            return boxfut::box_it(async move { result });
        }

        let root = self.root.clone();
        let is_pure = tool.spec.purity == Purity::Pure;
        // Memoize pure tools within the current generation: a repeated identical read/grep
        // during exploration is served from cache instead of hitting the filesystem again.
        // Every registry-mediated effect bumps the generation; ambient changes are not inferred.
        if is_pure {
            let pending = match self.memo.key(&call.name, &call.input) {
                Some(key) => match self.memo.lookup(key) {
                    Lookup::Hit(mut hit) => {
                        hit.tool_use_id = call.id.clone(); // this call's id, cached content
                        hit.latency_ms = 0;
                        return boxfut::box_it(async move { hit });
                    }
                    Lookup::Miss(pending) => Some(pending),
                },
                None => None,
            };
            let id = call.id.clone();
            let inner = (tool.run)(call, root);
            let memo = self.memo.clone();
            return boxfut::box_it(async move {
                let started = Instant::now();
                let registered = inner.await;
                let mut r = registered.outcome.into_result();
                r.tool_use_id = id;
                r.latency_ms = registered
                    .dispatch_to_terminal_ms
                    .unwrap_or_else(|| started.elapsed().as_millis() as u64);
                // A generation token prevents a read that raced a completed write from
                // repopulating stale data. Oversized logical keys and errors are never cached.
                if let Some(pending) = pending {
                    memo.complete(pending, &r);
                }
                r
            });
        }
        // Effecting tools are never memoized. Validation above runs before this executor future
        // is even constructed, so malformed calls cannot mutate state or invalidate read caches.
        let id = call.id.clone();
        let inner = (tool.run)(call, root);
        let memo = self.memo.clone();
        boxfut::box_it(async move {
            let started = Instant::now();
            let registered = inner.await;
            let mut r = registered.outcome.into_result();
            r.tool_use_id = id;
            r.latency_ms = registered
                .dispatch_to_terminal_ms
                .unwrap_or_else(|| started.elapsed().as_millis() as u64);
            memo.invalidate();
            r
        })
    }

    pub(crate) fn push_tool(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_tool_with_origin_and_purpose(spec, run, ToolOrigin::BuiltIn, ToolPurpose::General)
    }

    fn push_external_tool(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_tool_with_origin_and_purpose(
            spec,
            run,
            ToolOrigin::External,
            ToolPurpose::General,
        )
    }

    fn push_tool_with_origin_and_purpose(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
        origin: ToolOrigin,
        purpose: ToolPurpose,
    ) -> Result<(), ToolError> {
        let adapted = move |call, root| {
            let future = run(call, root);
            registeredfut::box_it(async move {
                RegisteredExecution {
                    outcome: ToolExecution::Definite(future.await),
                    dispatch_to_terminal_ms: None,
                }
            })
        };
        self.register_with_origin(
            Tool {
                spec,
                run: Box::new(adapted),
                output_owner: ToolOutputOwner::Runtime,
                purpose,
            },
            origin,
        )
    }

    /// Public registration hook for an externally-sourced tool (e.g. an MCP tool wired by the
    /// CLI). The executor receives the call and the workspace root and returns a boxed future.
    /// Purity/capability rules in `register` still apply (ADR-007 R16).
    pub fn register_external(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_external_tool(spec, run)
    }

    /// Register an effect executor that can conservatively report an externally unknown outcome.
    /// This API is intentionally unavailable to `Pure` tools: uncertainty is an effect-state
    /// concern and must never enter the early-dispatch/memoized path.
    pub fn register_external_effect(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> effectfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        if spec.purity != Purity::Effecting {
            return Err(ToolError::Registration(format!(
                "outcome-aware tool `{}` must be Effecting",
                spec.name
            )));
        }
        let adapted = move |call, root| {
            let future = run(call, root);
            registeredfut::box_it(async move {
                RegisteredExecution {
                    outcome: future.await,
                    dispatch_to_terminal_ms: None,
                }
            })
        };
        self.register(Tool {
            spec,
            run: Box::new(adapted),
            output_owner: ToolOutputOwner::Runtime,
            purpose: ToolPurpose::General,
        })
    }

    /// Register one namespaced MCP effect with registry-owned dispatch timing.
    ///
    /// Unlike the general external hook, the executor cannot submit a duration. It receives an
    /// opaque one-shot clock bound to `(server_name, tool_name)` and may only mark the true pipe
    /// dispatch point; the registry samples the terminal time after the future resolves.
    pub fn register_mcp_effect(
        &mut self,
        spec: ToolSpec,
        attribution: McpEffectAttribution,
        run: impl Fn(ToolUse, PathBuf, McpDispatchClock) -> effectfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        let expected_name = attribution.namespaced_name();
        if spec.name != expected_name {
            return Err(ToolError::Registration(format!(
                "MCP attribution `{expected_name}` does not match registered tool `{}`",
                spec.name
            )));
        }
        let adapted = move |call, root| {
            let clock = McpDispatchClock::new(attribution.clone());
            let future = run(call, root, clock.clone());
            registeredfut::box_it(async move {
                let outcome = future.await;
                RegisteredExecution {
                    outcome,
                    // `Some(0)` is intentional for a typed pre-dispatch MCP rejection: there is
                    // no dispatch->terminal interval, and the ordinary registry-wide fallback
                    // would incorrectly include local validation/serialization time.
                    dispatch_to_terminal_ms: Some(clock.elapsed_to_terminal_ms().unwrap_or(
                        iteron_tunables::param_integer(
                            "tools.lib.mcp_pre_dispatch_terminal_ms",
                            MCP_PRE_DISPATCH_TERMINAL_MS,
                        ),
                    )),
                }
            })
        };
        self.register(Tool {
            spec,
            run: Box::new(adapted),
            output_owner: ToolOutputOwner::Mcp,
            purpose: ToolPurpose::General,
        })
    }
}

fn replace_description_only(spec: &mut ToolSpec, description: &str) {
    spec.description = description.to_owned();
}

/// The name the kernel intercepts to spawn a read-only subagent (ADR-001 fan-out). Registered
/// here only so the model sees the spec; its executor is never run (the kernel handles it).
pub const DISPATCH_AGENT: &str = "dispatch_agent";

/// The name the kernel intercepts to launch a model-directed workflow (parallels
/// [`DISPATCH_AGENT`]). Registered only in the writer registry; the kernel handles it by name so
/// the registered executor's fallback message is only reached by a non-kernel caller.
pub use workflow_tool::WORKFLOW_TOOL;

fn register_dispatch_agent(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: DISPATCH_AGENT.into(),
            description: "Delegate a READ-ONLY investigation to a subagent with its own fresh \
                          context: it explores the repo (read/grep/list/repo_map) and returns a \
                          concise summary. Use for wide search or multi-file investigation to \
                          keep your own context clean. The subagent cannot edit or run code; you \
                          remain the only writer. Give it a specific question and the output you \
                          want."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"task":{"type":"string","description":"the investigation question + desired output"}},
                "required":["task"]
            }),
            // Effecting so it is not early-dispatched; the kernel intercepts by name before the
            // normal effecting path and runs the subagent itself.
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, _root| {
            boxfut::box_it(async move {
                // Never reached: the kernel intercepts DISPATCH_AGENT. This is a safety net.
                err_result(call.id, "dispatch_agent must be handled by the kernel".into())
            })
        },
    )
}

/// Resolve a caller-supplied path to an absolute host path.
///
/// **This function no longer confines (owner-directed, 2026-08-05).** It used to reject three
/// things: an absolute path, a lexical `..` escape, and a symlink whose destination canonicalized
/// outside the workspace root. All three are now resolved and returned. A relative path is still
/// resolved against `root`, so every existing caller keeps its meaning; an absolute path addresses
/// the host directly, which is the case that made the agent unusable — the model naturally emits
/// `/Users/me/project/src/main.rs`, and `absolute path not allowed` was the single largest source
/// of tool errors, three of which in a row tripped the consecutive-error floor and killed the run.
///
/// What is surrendered is stated plainly rather than implied: an fs tool can now read and write
/// anywhere the operator's own account can, including `~/.ssh`, and a symlink committed to an
/// untrusted repository is a working pointer out of that repository. The corresponding execution
/// surrender is `Confinement::unconfined`. Path containment is not available behind a flag,
/// because a boundary that only some callers honour is not a boundary.
///
/// Canonicalization is retained, and for a not-yet-existing path (a new file to write) the nearest
/// existing ancestor is canonicalized and the remainder appended. That is no longer a containment
/// check — it is what keeps a returned path stable and comparable for the memo cache and for the
/// symlink-target checks `write_file` performs before it truncates anything.
pub fn resolve_in_root(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    resolve_from_canonical_root(&root, rel)
}

/// Resolve against a root the caller already canonicalized for a multi-step filesystem operation.
pub(crate) fn resolve_from_canonical_root(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let requested = Path::new(rel);
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };

    // Canonicalize the path if it exists; otherwise canonicalize the nearest existing ancestor
    // and append the remainder, so a path to a file that does not exist yet still comes back
    // absolute and symlink-resolved.
    match joined.canonicalize() {
        Ok(resolved) => Ok(resolved),
        Err(_) => {
            let mut ancestor = joined.as_path();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            let canon_ancestor = loop {
                match ancestor.parent() {
                    Some(parent) => {
                        if let Some(name) = ancestor.file_name() {
                            tail.push(name.to_os_string());
                        }
                        if let Ok(c) = parent.canonicalize() {
                            break c;
                        }
                        ancestor = parent;
                    }
                    None => return Err(format!("cannot resolve path: {rel}")),
                }
            };
            let mut resolved = canon_ancestor;
            for name in tail.iter().rev() {
                resolved.push(name);
            }
            Ok(resolved)
        }
    }
}

/// Render a resolved path the way a tool result should show it: workspace-relative when it is
/// under the root, absolute otherwise.
///
/// Every traversal-shaped tool used to `strip_prefix(root)` and treat failure as "impossible",
/// which stopped being true when `resolve_in_root` began addressing the host. The two ways that
/// assumption failed were both worse than the thing they guarded: `list_dir` silently dropped
/// every entry outside the workspace and returned an empty listing, and `grep` failed the whole
/// search. Neither is a boundary — the file had already been resolved and read by then — so this
/// is purely how the path is spelled back to the caller.
pub(crate) fn display_path(root: &Path, path: &Path) -> String {
    let rendered = match path.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.display().to_string(),
        _ => path.display().to_string(),
    };
    rendered.replace('\\', "/")
}

/// Helper: build a successful workspace-trust result.
pub(crate) fn ok_result(id: String, content: String) -> ToolResult {
    ToolResult {
        tool_use_id: id,
        content,
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}
/// Helper: build an error result.
pub(crate) fn err_result(id: String, msg: String) -> ToolResult {
    ToolResult {
        tool_use_id: id,
        content: msg,
        is_error: true,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod schema_tests;

#[cfg(test)]
#[path = "memo_tests.rs"]
mod memo_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_plus_egress_is_a_registration_error() {
        let mut r = Registry {
            tools: Vec::new(),
            spec_revision: Default::default(),
            spec_snapshot: Default::default(),
            task_spec_snapshot: Default::default(),
            root: ".".into(),
            memo: Default::default(),
            sensitive_env_names: Default::default(),
            confine_execution: Default::default(),
            egress_allow_policy: Default::default(),
            observation_tool_policy: Default::default(),
            process_launch_policy: Default::default(),
            process_control: None,
            lsp_control: None,
            deferred_tool_catalog: None,
            workspace_boundary: false,
        };
        let bad = ToolSpec {
            name: "leaky".into(),
            description: "".into(),
            input_schema: serde_json::json!({}),
            purity: Purity::Pure,
            capability: Capability::IrreversibleExternal, // egress + Pure = contradiction
        };
        let err = r.push_tool(bad, |c, _| {
            boxfut::box_it(async move { ok_result(c.id, String::new()) })
        });
        assert!(err.is_err(), "Pure+egress must be refused at registration");
    }

    #[test]
    fn narrowing_a_read_only_registry_can_remove_but_never_add_tools() {
        let mut registry = Registry::read_only(".").unwrap();
        let before: std::collections::BTreeSet<_> =
            registry.specs().into_iter().map(|spec| spec.name).collect();
        let kept = registry.narrow_to(&["read_file".into(), "invented_writer".into()]);
        assert_eq!(kept, vec!["read_file"]);
        let after: std::collections::BTreeSet<_> =
            registry.specs().into_iter().map(|spec| spec.name).collect();
        assert!(after.is_subset(&before));
        assert!(!after.contains("invented_writer"));
    }

    #[test]
    fn candidate_change_semantics_are_registered_not_inferred_from_authority() {
        let registry = Registry::coding_agent(".").unwrap();
        for tool in ["edit", "apply_patch", "write_file"] {
            assert!(registry.is_candidate_change_tool(tool), "{tool}");
        }
        for broader_authority_without_a_candidate_change in ["bash", "dispatch_agent", "Workflow"] {
            assert!(
                !registry.is_candidate_change_tool(broader_authority_without_a_candidate_change),
                "{broader_authority_without_a_candidate_change}"
            );
        }
    }

    #[test]
    fn unchanged_task_tool_set_reuses_the_revisioned_serialization() {
        let mut registry = Registry::read_only(".").unwrap();
        let admitted = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<std::collections::BTreeSet<_>>();

        let first = registry.specs_for_task_snapshot(&admitted, "inspect the repository", None);
        let second = registry.specs_for_task_snapshot(&admitted, "inspect the repository", None);
        assert_eq!(first.revision(), second.revision());
        assert!(Arc::ptr_eq(&first.base, &second.base));
        assert!(Arc::ptr_eq(&first.indices, &second.indices));
        assert!(Arc::ptr_eq(
            first.serialized_json(),
            second.serialized_json()
        ));

        let revision = first.revision();
        registry.narrow_to(&["read_file".into()]);
        let narrowed = registry.specs_for_task_snapshot(&admitted, "inspect the repository", None);
        assert_ne!(narrowed.revision(), revision);
        assert!(!Arc::ptr_eq(&first.base, &narrowed.base));
        assert!(!Arc::ptr_eq(
            first.serialized_json(),
            narrowed.serialized_json()
        ));
    }

    #[test]
    fn a_path_outside_the_workspace_resolves_instead_of_being_refused() {
        let root = std::env::temp_dir().join(format!("core-resolve-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "x").unwrap();
        // A relative path still resolves against the root: every existing caller keeps its meaning.
        let inside = resolve_in_root(&root, "src/main.rs").unwrap();
        assert_eq!(inside, root.canonicalize().unwrap().join("src/main.rs"));
        // A not-yet-existing file still resolves (the write path).
        assert!(resolve_in_root(&root, "src/new_file.rs").is_ok());
        // The three former refusals are now the point of the function. An absolute path is the
        // one the model actually emits, and it must address the host.
        let absolute = root.canonicalize().unwrap().join("src/main.rs");
        assert_eq!(
            resolve_in_root(&root, absolute.to_str().unwrap()).unwrap(),
            absolute
        );
        let lexical = resolve_in_root(&root, "../").expect("a lexical escape now resolves");
        assert_eq!(lexical, root.canonicalize().unwrap().parent().unwrap());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn d2_16_g1_memo_hit_then_write_invalidates_prior_read_through_registry() {
        let root = std::env::temp_dir().join(format!("core-memo-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "v1").unwrap();
        let reg = Registry::coding_agent(&root).unwrap();
        reg.install_observation_tool_policy(ObservationToolPolicy::default())
            .unwrap();

        let read = |n: &str| ToolUse {
            id: n.into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"a.txt"}),
        };
        // first read = miss; second identical read = hit (served from cache)
        let first = reg.dispatch(read("1")).await;
        let second = reg.dispatch(read("2")).await;
        assert!(first.content.contains("v1"));
        assert_eq!(first.content, second.content);
        let (hits, misses) = reg.memo_stats();
        assert_eq!(
            (hits, misses),
            (1, 1),
            "1st read misses+caches, 2nd identical read hits"
        );

        // an effecting edit bumps the generation -> the next read must MISS (no stale serve)
        let edit = ToolUse {
            id: "e".into(),
            name: "edit".into(),
            input: serde_json::json!({"path":"a.txt","old":"v1","new":"v2"}),
        };
        let edited = reg.run(edit).await;
        assert!(
            !edited.is_error,
            "test write must actually complete: {edited:?}"
        );
        let reread = reg.dispatch(read("3")).await;
        assert!(reread.content.contains("v2"));
        assert!(!reread.content.contains("v1"));
        let (hits2, misses2) = reg.memo_stats();
        assert_eq!(hits2, 1, "no new hit after a write");
        assert_eq!(
            misses2, 2,
            "the post-write read must miss, never serve the stale cache"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn d2_16_g1_failed_effect_also_invalidates_prior_reads() {
        let root =
            std::env::temp_dir().join(format!("core-memo-failed-effect-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "v1").unwrap();
        let mut registry = Registry::read_only(&root).unwrap();
        registry
            .install_observation_tool_policy(ObservationToolPolicy::default())
            .unwrap();
        registry
            .register_external(
                ToolSpec {
                    name: "partial_failure".into(),
                    description: "test partial mutation".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::ReversibleLocal,
                },
                |_, root| {
                    boxfut::box_it(async move {
                        std::fs::write(root.join("a.txt"), "partially changed").unwrap();
                        ToolResult {
                            tool_use_id: "plugin-chosen-id".into(),
                            content: "reported failure after mutation".into(),
                            is_error: true,
                            trust: Trust::Workspace,
                            latency_ms: 0,
                        }
                    })
                },
            )
            .unwrap();

        let read = |id: &str| ToolUse {
            id: id.into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"a.txt"}),
        };
        let _ = registry.dispatch(read("read-1")).await;
        let _ = registry.dispatch(read("read-2")).await;
        assert_eq!(registry.memo_stats(), (1, 1));

        let result = registry
            .run(ToolUse {
                id: "effect-call".into(),
                name: "partial_failure".into(),
                input: serde_json::json!({}),
            })
            .await;
        assert!(result.is_error);
        assert_eq!(
            result.tool_use_id, "effect-call",
            "executor output cannot replace provider correlation identity"
        );
        let reread = registry.dispatch(read("read-3")).await;
        assert!(reread.content.contains("partially changed"));
        assert_eq!(registry.memo_stats(), (1, 2));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn outcome_aware_effect_preserves_unknown_and_normalizes_identity() {
        let mut registry = Registry::read_only(".").unwrap();
        registry
            .register_external_effect(
                ToolSpec {
                    name: "uncertain_remote".into(),
                    description: "test-only remote effect".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::IrreversibleExternal,
                },
                |_, _| {
                    effectfut::box_it(async {
                        ToolExecution::Unknown(ToolResult {
                            tool_use_id: "executor-id".into(),
                            content: "remote outcome unknown".into(),
                            is_error: true,
                            trust: Trust::Untrusted,
                            latency_ms: u64::MAX,
                        })
                    })
                },
            )
            .unwrap();

        let outcome = registry
            .run_effect(ToolUse {
                id: "provider-id".into(),
                name: "uncertain_remote".into(),
                input: serde_json::json!({}),
            })
            .await;
        match outcome {
            ToolExecution::Unknown(result) => {
                assert_eq!(result.tool_use_id, "provider-id");
                assert!(result.is_error);
                assert_ne!(
                    result.latency_ms,
                    u64::MAX,
                    "ordinary executors cannot submit their own latency"
                );
            }
            ToolExecution::Definite(_) => panic!("unknown effect was flattened"),
        }
    }

    #[test]
    fn mcp_timing_registration_requires_exact_server_tool_attribution() {
        let mut registry = Registry::read_only(".").unwrap();
        let error = registry
            .register_mcp_effect(
                ToolSpec {
                    name: "server__actual".into(),
                    description: "test".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::IrreversibleExternal,
                },
                McpEffectAttribution::new("server", "different"),
                |_, _, _| {
                    effectfut::box_it(async {
                        unreachable!("mismatched attribution must fail before registration")
                    })
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("server__different"));
        assert!(error.to_string().contains("server__actual"));

        registry
            .register_mcp_effect(
                ToolSpec {
                    name: "server__actual".into(),
                    description: "test".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::IrreversibleExternal,
                },
                McpEffectAttribution::new("server", "actual"),
                |_, _, _| {
                    effectfut::box_it(async {
                        unreachable!("classification does not execute the MCP tool")
                    })
                },
            )
            .unwrap();
        assert!(registry.is_mcp_effect("server__actual"));
        assert!(!registry.is_mcp_effect("read_file"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_workspace_is_followed_to_its_real_target() {
        // This asserts the inverse of the former SEC-1 containment, deliberately and by name: a
        // symlink inside the workspace pointing OUT is now followed. The path still canonicalizes,
        // so what a caller receives is the real destination rather than the link — that part was
        // never containment, it is what makes the returned path comparable.
        let root = std::env::temp_dir().join(format!("core-symlink-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("core-outside-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), "top secret").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let resolved = resolve_in_root(&root, "escape/secret").expect("a symlink is now followed");
        assert_eq!(resolved, outside.canonicalize().unwrap().join("secret"));
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }
}
