//! `KernelSpawner` — the production [`iteron_workflow::AgentSpawner`].
//!
//! Every workflow `agent('...')` call runs a GENUINE child [`Agent`] (its own context, its own
//! read-only tool loop) via `Agent::run_leaf`, not a single provider completion. This is the
//! standalone upgrade of the CLI's first-slice `ProviderSpawner` (see `crates/cli/src/workflow.rs`).
//!
//! Child construction here is the one workflow-investigator path (fresh read-only `Registry`, a
//! child `Rollout` under `subagents/`, inherited route +
//! pricing, bounded delegation depth), but it takes an explicit [`KernelSpawnerContext`] instead of
//! a live parent `&mut self`. That is the "standalone child constructor" the workflow seam needs:
//! the existing child setup was only reachable mid-turn from inside a parent `Agent`, because it
//! emitted a durable `SubagentSpawned` event and parent UI events. This module drops exactly those
//! two parent-transcript side effects (there is no parent transcript to append to) and keeps
//! everything the child itself needs.
//!
//! Concurrency is bounded by the engine's Governor (one global permit pool), so this spawner bounds
//! nothing itself, per the trait contract.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use async_trait::async_trait;
use iteron_agents::AgentCatalog;
use iteron_obs::PricingPort;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::StrategySlot;
use iteron_protocol::{
    Budget, CostAttribution, Effort, Outcome, PermissionMode, PermissionRules, RunId, TenantId,
};
use iteron_provider::Provider;
use iteron_record::Rollout;
use iteron_tools::Registry;
use iteron_workflow::{AgentActivityReporter, AgentCall, AgentOutcome, AgentSpawner};
use sha2::{Digest, Sha256};

use super::Agent;
use super::hooks::Hooks;
use super::hooks::journal::HookEffectJournal;
use super::pricing::SharedUsdBudget;
use iteron_obs::Ledger;

const MAX_AGENT_REFUSAL_BYTES: usize = 512;
const AGENT_REFUSAL_TRUNCATED: &str = " [truncated]";

/// Child-genesis `created_at` written when the host clock reads before the Unix epoch; genesis is
/// recorded with an unusable stamp rather than refused.
const CLOCK_BEFORE_EPOCH_SECS: u64 = 0;

type ChildLedgerCollector = Arc<Mutex<Vec<(u64, Ledger)>>>;
type ChildOutcomeCollector = Arc<Mutex<Vec<(u64, Result<Outcome, String>)>>>;

fn child_provider_governor(
    cx: &KernelSpawnerContext,
) -> Result<iteron_provider::ProviderGovernor, String> {
    cx.provider_governor
        .as_ref()
        .cloned()
        .ok_or_else(|| safe_agent_refusal("workflow provider governor owner is not installed"))
}

mod activity;
mod tunables;
mod worktree;

/// One terminal/journal-safe refusal line. This is the final choke point for child setup and
/// runtime failures: redact credential shapes, render terminal controls visibly, and retain at
/// most 512 UTF-8 bytes. Request metadata is never deliberately interpolated by this module, but
/// this defense also covers OS/library diagnostics returned by later setup stages.
pub(crate) fn safe_agent_refusal(reason: &str) -> String {
    let scrubbed = iteron_record::redact::scrub(reason);
    let content_limit = iteron_tunables::param_integer(
        "cli.runtime.workflow_spawner.max_agent_refusal_bytes",
        MAX_AGENT_REFUSAL_BYTES,
    )
    .saturating_sub(
        iteron_tunables::param_str(
            "cli.runtime.workflow_spawner.agent_refusal_truncated",
            AGENT_REFUSAL_TRUNCATED,
        )
        .len(),
    );
    let mut safe = String::with_capacity(scrubbed.len().min(iteron_tunables::param_integer(
        "cli.runtime.workflow_spawner.max_agent_refusal_bytes",
        MAX_AGENT_REFUSAL_BYTES,
    )));
    let mut truncated = false;
    for character in scrubbed.chars() {
        let codepoint = character as u32;
        let terminal_unsafe = character.is_control()
            || matches!(
                codepoint,
                0x00AD
                    | 0x200B..=0x200F
                    | 0x2028..=0x202E
                    | 0x2066..=0x2069
                    | 0xFEFF
            );
        let rendered = if terminal_unsafe {
            character.escape_default().to_string()
        } else {
            character.to_string()
        };
        if safe.len().saturating_add(rendered.len()) > content_limit {
            truncated = true;
            break;
        }
        safe.push_str(&rendered);
    }
    if truncated {
        safe.push_str(iteron_tunables::param_str(
            "cli.runtime.workflow_spawner.agent_refusal_truncated",
            AGENT_REFUSAL_TRUNCATED,
        ));
    }
    if safe.trim().is_empty() {
        "agent request was refused".into()
    } else {
        safe
    }
}

/// Everything a [`KernelSpawner`] needs to build children WITHOUT a live parent `Agent`. The CLI
/// fills this once from the resolved provider/route/config, then hands it to [`KernelSpawner::new`].
/// Every field is cheap to clone or share (the provider/pricing/stop handles are `Arc`s).
pub struct KernelSpawnerContext {
    /// Shared provider handle (ADR-001 fan-out: every child uses the SAME provider object).
    pub provider: Arc<dyn Provider>,
    /// Default model id; overridden per call by [`AgentCall::model`].
    pub model: String,
    /// The exact durable route the children re-record, byte-for-byte identical to the parent's
    /// `record_model_selection` inputs. Pricing binds only against this exact route.
    pub provider_id: String,
    pub catalog_digest: String,
    pub capability_digest: String,
    /// The exact provider controls/governor/fallback chain inherited by every physical child
    /// attempt. These are resolved once by the composition root; children never consult config.
    pub(crate) provider_controls: iteron_provider::ProviderRequestControls,
    pub(crate) provider_governor_policy: iteron_provider::GovernorPolicy,
    /// One Arc-backed owner for route in-flight, quota, and circuit state. Every child receives a
    /// clone of this exact instance; constructing a governor inside `build_child` would multiply
    /// the resolved per-route ceiling by the workflow width.
    pub(crate) provider_governor: Option<iteron_provider::ProviderGovernor>,
    pub(crate) fallback_provider_routes: Vec<super::GovernedProviderRoute>,
    pub(crate) token_calibration: iteron_ctx::TokenCalibrationStore,
    /// Exact immutable V1/V2 checkpoint inherited from the trusted composition root. `None` is
    /// kept only so construction can finish before a caller supplies the held pin; spawning fails
    /// closed rather than consulting the resolver or ambient defaults when it remains absent.
    pub(crate) tunables_pin: Option<super::tunables_pin::TunablesPin>,
    /// Pure, injected pricing strategy. REQUIRED only if `budget.max_usd` is a positive ceiling; a
    /// child that cannot bind a verified rate card for a positive ceiling resolves to `Null`.
    pub pricing_port: Option<Arc<dyn PricingPort>>,
    /// One aggregate monetary ceiling shared by the parent and every workflow child. A child may
    /// tighten it; no child receives an independent refill.
    pub(super) usd_budget: Option<Arc<SharedUsdBudget>>,
    /// Session owner shared across direct dispatches and every workflow run. The engine's
    /// `RunLimits` is intentionally separate and may only narrow one run.
    pub(super) session_spawn_ledger: Arc<super::SessionSpawnLedger>,
    /// The repo the children read (their sandbox root + read-only registry root).
    pub workspace: PathBuf,
    /// The session runtime-state root: the directory that CONTAINS the parent session rollout
    /// (i.e. `<...>/runs`). Child journals are written under `runtime_state_dir/subagents/`, and the
    /// child inherits this exact value so a drain checkpoint excludes the whole authority tree.
    pub runtime_state_dir: PathBuf,
    pub tenant: TenantId,
    /// Parent session run id + stable workflow id, recorded in each child's cost attribution so a
    /// child's signed cost projection authenticates the terminal that may aggregate it.
    pub parent_run_id: String,
    pub workflow_id: String,
    /// Effort default; `Ultracode` is mapped to `Max` for a leaf child (a leaf never orchestrates).
    pub default_effort: Effort,
    pub(crate) effort_policy: crate::runtime_tunables::effective_core::EffortRuntimePolicy,
    /// Immutable child effort/memory and workflow controls inherited from the parent's checkpoint.
    pub(crate) execution_policy: crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy,
    /// Per-child bounded-loop ceilings. The engine's Governor bounds CONCURRENCY; this bounds each
    /// child's turns/wall/usd. Defaults to `iteron_agents::subagent_budget_ceiling()`.
    pub budget: Budget,
    /// Optional declaration-order budget slices for a kernel-built fan. When present, spawn ordinal
    /// N receives slice N and an ordinal outside the schedule is refused, preserving one aggregate
    /// fan ceiling instead of multiplying a per-child ceiling by the number of `agent()` calls.
    /// General user-authored workflows leave it `None`.
    pub(super) budget_slices: Option<Vec<Budget>>,
    /// Optional parent-owned ledger collector. A built-in in-turn fan merges these child ledgers
    /// back into the writer's shared accounting after the engine joins; standalone workflows have
    /// no live parent ledger and leave it unset.
    pub(super) child_ledgers: Option<ChildLedgerCollector>,
    /// Typed terminal outcomes for the same parent reconciliation path. The workflow engine's JS
    /// value intentionally collapses every degraded child to `null`; the kernel still needs to
    /// distinguish operator drain/interrupt from budget, harness and provider failures in its
    /// durable compatibility record.
    pub(super) child_outcomes: Option<ChildOutcomeCollector>,
    /// Parent drain is orderly quiescence, not workflow cancellation. Sharing this flag lets a
    /// child checkpoint and return `Outcome::Drained`; the engine cancellation token remains the
    /// separate immediate-stop surface.
    pub(super) drain: Option<Arc<std::sync::atomic::AtomicBool>>,
    pub model_context_window: Option<u64>,
    pub model_max_output_tokens: Option<u32>,
    pub sensitive_env_names: Vec<String>,
    /// Standalone workflows deliberately own an empty MCP topology. Retaining and installing the
    /// decoded policy still gives families 149--152 a physical consumer; a historical checkpoint
    /// that names any transport/exposure is rejected before a child rollout or effect exists.
    pub(crate) standalone_mcp_policy: Option<(
        crate::runtime_tunables::effective_mcp::EffectiveMcpSettings,
        crate::runtime_tunables::effective_mcp::McpCapabilityExposure,
    )>,
    /// Pinned strategy/port set inherited by every child; child construction never falls back to
    /// a different policy generation.
    pub context_strategy: Arc<dyn StrategySlot>,
    pub tool_policy: Arc<dyn StrategySlot>,
    pub memory_strategy: Arc<dyn StrategySlot>,
    /// `core/router`. A leaf child never orchestrates, so it never asks; it is inherited anyway so
    /// a child is never constructed against a different policy generation than its parent.
    pub router: Arc<dyn StrategySlot>,
    pub planner: Arc<dyn StrategySlot>,
    pub collaboration: Arc<dyn StrategySlot>,
    pub scheduler: Arc<dyn StrategySlot>,
    pub retry_policy: iteron_sched::BackoffPolicy,
    /// Fail-closed single-writer/worktree/merge admission policy shared with tunable facts.
    pub writer_merge_policy: iteron_workflow::WriterMergePolicy,
    /// Exact operator-admitted command used to validate a sealed writer patch. `None` refuses a
    /// non-empty writer merge; the writer may never nominate its own oracle.
    pub(crate) verify_command: Option<String>,
    pub(crate) verification_feedback: iteron_verify::VerificationFeedbackTailPolicy,
    /// One merge/writer lane for the complete session lineage. The guard is held from worktree
    /// provisioning through child terminal, verification, merge, and cleanup.
    pub(super) writer_merge_lock: Arc<tokio::sync::Mutex<()>>,
    pub verifier: Arc<dyn StrategySlot>,
    /// `core/model_router`. The spawner supplies the parent's already-resolved route as evidence;
    /// the slot may select it or refuse, but cannot invent an unbound provider route.
    pub model_router: Arc<dyn StrategySlot>,
    pub context_port: Arc<dyn iteron_ctx::ContextPort>,
    pub deferred_tool_eager_limit: Option<usize>,
    pub context_budget_policy: iteron_ctx::ContextBudgetPolicy,
    pub context_materialization_policy: iteron_ctx::ContextMaterializationPolicy,
    pub compaction_policy: iteron_ctx::CompactionPolicy,
    /// Operator replacement for `prompt/compaction@v1`, inherited so a child summarizes under the
    /// same instruction its parent does. `None` keeps the compiled default.
    pub compaction_summary_prompt: Option<String>,
    pub context_home_dir: Option<PathBuf>,
    pub dependency_skill_dirs: Vec<(PathBuf, PathBuf)>,
    /// Exact accepted definitions resolved once by the composition root. Every spawned worker
    /// inherits this same immutable set; it never performs filesystem discovery itself.
    pub agent_catalog: Arc<AgentCatalog>,
    /// Policy projection pinned for the entire workflow lineage.
    pub boot_bundle: Arc<iteron_agents::BootBundle>,
    /// Complete typed policy generation behind the projection. The spawner and every child retain
    /// the same Arc so policy identities and implementations cannot drift independently.
    pub(crate) compiled_policy_bundle: Arc<crate::bundle_adapter::CompiledPolicyBundle>,
    /// Permission posture for the read-only child. Registry and capability ceilings independently
    /// prevent this from widening authority.
    pub permission_mode: PermissionMode,
    pub permission_rules: PermissionRules,
    pub authority_ceiling: CapabilitySet,
    pub policy_capabilities: CapabilitySet,
    /// The parent's permission posture, inherited by every child this spawner starts.
    ///
    /// A workflow child has no approval channel, so with the gate running it can only take what the
    /// mode table already auto-approves. Inheriting the bypass is what makes a fan-out under the
    /// operator's own authority behave like the session that launched it. What bounds the child is
    /// the read-only ceiling intersected below, not this flag.
    pub bypass_permissions: bool,
    /// Parent-owned, bounded lifecycle projections. These carry correlation and operator-owned
    /// observation policy into children without widening the child's tool registry or authority.
    pub(super) lifecycle_emitter: Option<iteron_obs::lifecycle::LifecycleEmitter>,
    pub(super) lifecycle_telemetry: Option<iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime>,
    pub(super) lifecycle_hooks: Option<super::lifecycle_hooks::LifecycleHookDispatcher>,
    /// Shared content-free live activity projection. Children and host-owned writer settlement use
    /// the same bounded sink as the parent; no workflow status waits on frontend consumption.
    pub(super) activity: super::turn_activity::ActivitySink,
    /// Trusted operator Hook policy and its session-owned external-effect journal. A read-only
    /// child cannot run model-requested code, but operator Hooks remain host policy and therefore
    /// apply uniformly to every model/tool/context boundary in the lineage.
    pub(super) hooks: Hooks,
    pub(super) hook_effect_journal: Option<HookEffectJournal>,
    pub(super) environment_context: Option<(String, iteron_protocol::Trust)>,
}

impl KernelSpawnerContext {
    /// Install one compiler-owned checkpoint before this context is shared with a spawner. The
    /// method cannot fail after mutation: `CompiledPolicyBundle` construction validated all nine
    /// slot identities, so callers cannot observe a partially replaced generation.
    pub(crate) fn install_compiled_policy_bundle(
        &mut self,
        compiled: Arc<crate::bundle_adapter::CompiledPolicyBundle>,
    ) {
        let slots = compiled.slots();
        self.context_strategy = slots.context.clone();
        self.tool_policy = slots.tool_policy.clone();
        self.memory_strategy = slots.memory.clone();
        self.router = slots.router.clone();
        self.planner = slots.planner.clone();
        self.collaboration = slots.collaboration.clone();
        self.scheduler = slots.scheduler.clone();
        self.verifier = slots.verifier.clone();
        self.model_router = slots.model_router.clone();
        self.boot_bundle = compiled.boot_bundle();
        self.compiled_policy_bundle = compiled;
    }

    /// Install the one operator-trusted pricing authority shared by every workflow child.
    /// A positive resolved ceiling without that authority is not an enforceable budget and is
    /// rejected while the composition context is still effect-free. The shared atomic ledger is
    /// minted once here rather than once per child, so concurrent fan-out cannot each spend the
    /// complete session ceiling.
    pub(crate) fn install_pricing_authority(
        &mut self,
        pricing: Option<Arc<dyn PricingPort>>,
    ) -> Result<(), &'static str> {
        if self.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) && pricing.is_none() {
            return Err(
                "a positive workflow USD ceiling requires an active verified pricing authority",
            );
        }
        self.pricing_port = pricing;
        self.usd_budget = self
            .budget
            .max_usd
            .map(SharedUsdBudget::from_usd)
            .map(Arc::new);
        Ok(())
    }

    /// Materialize the workflow's single provider-governor owner while composition is still
    /// effect-free. Route identities are the exact primary plus bounded fallback chain installed
    /// in this context; children may only narrow that authority.
    pub(crate) fn initialize_provider_governor(
        &mut self,
        policy: iteron_provider::GovernorPolicy,
    ) -> Result<(), &'static str> {
        if self.provider_governor.is_some() {
            return Err("workflow provider governor was already initialized");
        }
        let route_ids = std::iter::once(format!("{}:{}", self.provider_id, self.model)).chain(
            self.fallback_provider_routes
                .iter()
                .map(super::GovernedProviderRoute::id),
        );
        let governor = iteron_provider::ProviderGovernor::new(policy.clone(), route_ids)
            .map_err(|_| "workflow provider governor policy or route set is invalid")?;
        self.provider_governor_policy = policy;
        self.provider_governor = Some(governor);
        Ok(())
    }

    /// The minimal context: the identity/route/paths that have no sensible default, with everything
    /// else defaulted (built-in immutable catalog, `subagent_budget_ceiling()` budget, `Default`
    /// effort/mode, empty env, no pricing, no shared stop flags). Set the remaining `pub` fields
    /// directly for anything the run needs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Arc<dyn Provider>,
        model: String,
        provider_id: String,
        catalog_digest: String,
        capability_digest: String,
        workspace: PathBuf,
        runtime_state_dir: PathBuf,
        tenant: TenantId,
        parent_run_id: String,
        workflow_id: String,
    ) -> Self {
        let all_capabilities = CapabilitySet::from_iter_capabilities([
            iteron_protocol::Capability::ReadOnly,
            iteron_protocol::Capability::ReversibleLocal,
            iteron_protocol::Capability::CodeExecuting,
            iteron_protocol::Capability::TrustMutating,
            iteron_protocol::Capability::IrreversibleExternal,
        ]);
        let compiled_policy_bundle = crate::bundle_adapter::baseline_compiled_bundle();
        KernelSpawnerContext {
            provider,
            model,
            provider_id,
            catalog_digest,
            capability_digest,
            provider_controls: iteron_provider::ProviderRequestControls::default(),
            provider_governor_policy: iteron_provider::GovernorPolicy::default(),
            provider_governor: None,
            fallback_provider_routes: Vec::new(),
            token_calibration: iteron_ctx::TokenCalibrationStore::default(),
            tunables_pin: None,
            pricing_port: None,
            usd_budget: None,
            session_spawn_ledger: Arc::new(super::SessionSpawnLedger::default()),
            workspace,
            runtime_state_dir,
            tenant,
            parent_run_id,
            workflow_id,
            default_effort: Effort::default(),
            effort_policy: crate::runtime_tunables::effective_core::EffortRuntimePolicy::compiled(),
            execution_policy:
                crate::runtime_tunables::execution_policy::ExecutionRuntimePolicy::fail_closed(),
            budget: iteron_agents::subagent_budget_ceiling(),
            budget_slices: None,
            child_ledgers: None,
            child_outcomes: None,
            drain: None,
            model_context_window: None,
            model_max_output_tokens: None,
            sensitive_env_names: Vec::new(),
            standalone_mcp_policy: None,
            context_strategy: compiled_policy_bundle.slots().context.clone(),
            tool_policy: compiled_policy_bundle.slots().tool_policy.clone(),
            memory_strategy: compiled_policy_bundle.slots().memory.clone(),
            router: compiled_policy_bundle.slots().router.clone(),
            planner: compiled_policy_bundle.slots().planner.clone(),
            collaboration: compiled_policy_bundle.slots().collaboration.clone(),
            scheduler: compiled_policy_bundle.slots().scheduler.clone(),
            retry_policy: iteron_sched::BackoffPolicy::default(),
            writer_merge_policy: iteron_workflow::WriterMergePolicy::default(),
            verify_command: None,
            verification_feedback: iteron_verify::VerificationFeedbackTailPolicy::default(),
            writer_merge_lock: Arc::new(tokio::sync::Mutex::new(())),
            verifier: compiled_policy_bundle.slots().verifier.clone(),
            model_router: compiled_policy_bundle.slots().model_router.clone(),
            context_port: Arc::new(iteron_ctx::DefaultContextPort),
            deferred_tool_eager_limit: None,
            context_budget_policy: iteron_ctx::ContextBudgetPolicy::default(),
            context_materialization_policy: iteron_ctx::ContextMaterializationPolicy::default(),
            compaction_policy: iteron_ctx::CompactionPolicy::default(),
            compaction_summary_prompt: None,
            context_home_dir: None,
            dependency_skill_dirs: Vec::new(),
            agent_catalog: Arc::new(AgentCatalog::builtin_only()),
            boot_bundle: compiled_policy_bundle.boot_bundle(),
            compiled_policy_bundle,
            permission_mode: PermissionMode::default(),
            permission_rules: PermissionRules::new(),
            authority_ceiling: all_capabilities,
            policy_capabilities: all_capabilities,
            bypass_permissions: false,
            lifecycle_emitter: None,
            lifecycle_telemetry: None,
            lifecycle_hooks: None,
            activity: super::turn_activity::ActivitySink::default(),
            hooks: Hooks::default(),
            hook_effect_journal: None,
            environment_context: None,
        }
    }
}

/// The production sub-agent spawner: one genuine child [`Agent`] (`run_leaf`) per `agent()` call.
///
/// The CLI builds this once (`KernelSpawner::new(cx)`), wraps it in `Arc<dyn AgentSpawner>`, and
/// passes it to `WorkflowEngine::run`. It is `Send + Sync`; the engine `tokio::spawn`s each `spawn`
/// future onto the shared multi-thread runtime.
pub struct KernelSpawner {
    cx: KernelSpawnerContext,
    /// Monotone per-spawn ordinal so concurrently-spawned children get distinct rollout ids and
    /// distinct cost-attribution task ids. `&self`-safe via interior atomicity.
    next_ordinal: AtomicU64,
}

impl KernelSpawner {
    pub fn new(cx: KernelSpawnerContext) -> Self {
        KernelSpawner {
            cx,
            next_ordinal: AtomicU64::new(0),
        }
    }

    /// A deterministic, filesystem-safe child run id: namespaced by the parent tenant+run+workflow
    /// (so two concurrent workflows never collide) and made unique per spawn by the monotone
    /// ordinal. Mirrors the char classes of the parent's private `subagent_run_id`.
    fn mint_run_id(&self, ordinal: u64) -> RunId {
        let mut digest = Sha256::new();
        for value in [
            self.cx.tenant.0.as_bytes(),
            self.cx.parent_run_id.as_bytes(),
            self.cx.workflow_id.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        let digest = digest.finalize();
        let namespace: String = digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        RunId(format!("workflow-{namespace}-n{ordinal:08x}"))
    }

    /// The child identity the next declaration-order spawn will mint. The built-in fan records its
    /// parent-side `SubagentSpawned`/`ChildStarted` evidence before launching the engine, so the id
    /// calculation is shared rather than duplicated across the boundary.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn run_id_for_ordinal(&self, ordinal: u64) -> RunId {
        self.mint_run_id(ordinal)
    }

    /// Build the fully-wired, owned child. This is the workflow analogue of direct
    /// `spawn_subagent` child setup:
    ///   * a read-only `Registry` narrowed by the selected immutable `AgentDef`,
    ///   * a child `Rollout` under `runtime_state_dir/subagents/`,
    ///   * inherited route + pricing (public `record_model_selection` / `bind_selected_rate_card`),
    ///   * the same non-durable inherited context (workspace, model window, sensitive env,
    ///     cost attribution, bounded delegation depth),
    ///     minus the parent's durable `SubagentSpawned` + UI emission (no parent transcript exists).
    #[cfg(test)]
    fn build_child(&self, call: &AgentCall, ordinal: u64) -> Result<Agent, String> {
        self.build_child_in(call, ordinal, None)
    }

    fn build_child_in(
        &self,
        call: &AgentCall,
        ordinal: u64,
        writer_workspace: Option<&Path>,
    ) -> Result<Agent, String> {
        let cx = &self.cx;

        // `KernelSpawnerContext::new` carries fail-closed placeholder values only while the
        // composition root fills the owned context. Refuse an unpinned context before consulting
        // any of those placeholders, building a registry, opening a child rollout, appending
        // evidence, or admitting a provider effect. The child receives this exact pin below; it
        // never resolves or consults ambient defaults.
        let tunables_pin = cx
            .tunables_pin
            .clone()
            .ok_or_else(|| "child refused: runtime tunables were not pinned".to_string())?;
        let tunables_config_digest = format!("sha256:{}", tunables_pin.resolution_digest_sha256());

        call.validate_request_metadata()
            .map_err(|error| safe_agent_refusal(error.public_reason()))?;

        // Case-sensitive catalog resolution is an authority decision. Unknown names fail before a
        // rollout or provider effect exists; in particular, the historical magic name `writer`
        // can no longer turn model-controlled data into a coding registry.
        let requested_type = call.agent_type.as_deref().unwrap_or("generic");
        let agent_def = cx
            .agent_catalog
            .get(requested_type)
            .cloned()
            .ok_or_else(|| "requested agent type is absent from the pinned catalog".to_string())?;
        agent_def.validate().map_err(|reason| {
            safe_agent_refusal(&format!("pinned agent definition is invalid: {reason}"))
        })?;
        cx.execution_policy
            .per_agent_model
            .validate_owner(&cx.provider_id, &cx.model)
            .map_err(safe_agent_refusal)?;
        cx.execution_policy
            .per_agent_tool_profile
            .validate_owner(&cx.permission_rules)
            .map_err(safe_agent_refusal)?;
        let role_routes = cx
            .execution_policy
            .role_specific_models
            .validate_owner(&cx.agent_catalog, &cx.provider_id, &cx.model)
            .map_err(safe_agent_refusal)?;
        if agent_def.model.is_some() {
            let bound_route = format!("{}:{}", cx.provider_id, cx.model);
            let Some(admitted_route) = role_routes.get(requested_type) else {
                return Err(safe_agent_refusal(
                    "agent definition model override is absent from the pinned role-specific model map",
                ));
            };
            if admitted_route != &bound_route {
                return Err(safe_agent_refusal(
                    "pinned role-specific model route has no bound provider instance",
                ));
            }
        }
        let is_writer = agent_def.is_isolated_writer();
        if is_writer != writer_workspace.is_some() {
            return Err(safe_agent_refusal(
                "isolated writer admission requires its host-owned worktree",
            ));
        }
        let child_workspace = writer_workspace.unwrap_or(&cx.workspace).to_path_buf();

        if self.cx.execution_policy.per_agent_memory
            != crate::runtime_tunables::execution_policy::ChildMemoryPolicy::Isolated
        {
            return Err(safe_agent_refusal(
                "child memory scope is not an executable isolated policy",
            ));
        }

        // Gather the complete bounded observation now, but evaluate it only after the child owns
        // a durable rollout. A refusal is still a real trainable-policy decision and must not
        // disappear merely because no provider turn will follow it.
        let model_router_observation =
            iteron_provider::catalog::ModelRouterObservation::single_route(
                cx.model.clone(),
                agent_def.model.clone(),
                call.model.clone(),
            );

        let mut registry = if is_writer {
            let mut registry = Registry::isolated_writer(child_workspace.clone())
                .map_err(|_| "child isolated-writer registry setup failed".to_string())?;
            registry.narrow_to(
                &iteron_agents::ISOLATED_WRITER_TOOLS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            );
            registry
        } else {
            let mut registry = Registry::read_only(child_workspace.clone())
                .map_err(|_| "child read-only registry setup failed".to_string())?;
            let _effective_tools = crate::bundle_adapter::narrow_child_registry(
                &mut registry,
                &agent_def.tools,
                &cx.boot_bundle,
            );
            registry
        };
        cx.writer_merge_policy
            .admit_child(is_writer, is_writer)
            .map_err(safe_agent_refusal)?;
        registry.set_sensitive_env_names(cx.sensitive_env_names.clone());

        let mcp_runtime = match &cx.standalone_mcp_policy {
            Some((policy, exposure)) => {
                if !policy.is_disabled() || !exposure.is_disabled() {
                    return Err(safe_agent_refusal(
                        "standalone workflow checkpoint enables MCP without a runtime topology",
                    ));
                }
                let runtime = crate::mcp::register_configured_servers(
                    &mut registry,
                    &[],
                    &cx.sensitive_env_names,
                )
                .map_err(|_| safe_agent_refusal("empty MCP runtime registration failed"))?;
                runtime
                    .configure(*policy, exposure.clone())
                    .map_err(|_| safe_agent_refusal("empty MCP checkpoint binding failed"))?;
                Some(runtime)
            }
            None => None,
        };

        let parent_budget = match &cx.budget_slices {
            Some(slices) => slices
                .get(ordinal as usize)
                .ok_or_else(|| "aggregate child budget schedule is exhausted".to_string())?,
            None => &cx.budget,
        };
        let mut budget = intersect_budget(parent_budget, &agent_def.budget)?;
        let child_ceiling = cx
            .execution_policy
            .child_ceiling
            .ok_or_else(|| safe_agent_refusal("pinned child ceiling is inactive"))?;
        if !is_writer {
            budget = child_ceiling.narrow_budget(budget);
        }
        if budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) && cx.pricing_port.is_none() {
            return Err(
                "child has a positive USD ceiling but this exact route has no verified pricing port"
                    .into(),
            );
        }

        let sub_run = self.mint_run_id(ordinal);
        let subagents_dir = cx.runtime_state_dir.join("subagents");
        let rollout = Rollout::open(&subagents_dir, &sub_run, cx.tenant.clone())
            .map_err(|_| "child session record could not be opened".to_string())?;

        let mut sub = Agent::new_with_tunables_pin(
            cx.provider.clone(),
            registry,
            rollout,
            cx.model.clone(),
            agent_def.system.clone(),
            budget.clone(),
            tunables_pin,
        )
        .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
        if let Some(runtime) = mcp_runtime {
            sub.install_mcp_runtime(runtime)
                .map_err(safe_agent_refusal)?;
        }

        // --- Non-durable inherited context. These private fields are set exactly as the in-crate
        //     parent paths set them (this module is a descendant of the crate root, so it shares
        //     `Agent`'s private surface); no new public setter is exposed for them. ---
        sub.projection_attribution = Some(CostAttribution::WorkflowChild {
            parent_run_id: cx.parent_run_id.clone(),
            workflow_id: cx.workflow_id.clone(),
            task_id: ordinal as u32,
            sub_run: sub_run.0.clone(),
        });
        sub.runtime_state_dir = cx.runtime_state_dir.clone();
        sub.lifecycle_emitter = cx.lifecycle_emitter.clone();
        sub.lifecycle_telemetry = cx.lifecycle_telemetry.clone();
        sub.lifecycle_hooks = cx.lifecycle_hooks.clone();
        sub.activity = cx.activity.clone();
        sub.token_calibration = cx.token_calibration.clone();
        if cx.usd_budget.is_some() {
            sub.usd_budget = cx.usd_budget.clone();
        }
        sub.session_spawn_ledger = cx.session_spawn_ledger.clone();
        let child_capabilities = if is_writer {
            CapabilitySet::from_iter_capabilities([
                iteron_protocol::Capability::ReadOnly,
                iteron_protocol::Capability::ReversibleLocal,
                iteron_protocol::Capability::TrustMutating,
            ])
        } else {
            CapabilitySet::only(iteron_protocol::Capability::ReadOnly)
                .intersect(child_ceiling.capabilities)
        };
        sub.authority_ceiling = cx.authority_ceiling.intersect(child_capabilities);
        sub.policy_capabilities = cx.policy_capabilities.intersect(child_capabilities);
        if let Err(error) = sub.install_compiled_policy_bundle(cx.compiled_policy_bundle.clone()) {
            return Err(safe_agent_refusal(&format!(
                "child policy checkpoint rejected: {}",
                error.public_summary()
            )));
        }
        sub.retry_policy = cx.retry_policy;
        sub.context_port = cx.context_port.clone();
        sub.deferred_tool_eager_limit = cx.deferred_tool_eager_limit;
        sub.context_budget_policy = cx.context_budget_policy;
        sub.context_materialization_policy = cx.context_materialization_policy;
        sub.compaction = cx.compaction_policy;
        sub.compaction_summary_prompt = cx.compaction_summary_prompt.clone();
        sub.context_home_dir = cx.context_home_dir.clone();
        sub.dependency_skill_dirs = cx.dependency_skill_dirs.clone();
        // A workflow child is exactly one level below the operator. The read-only registry has no
        // dispatch/workflow tool; depth remains a second defense if that registry evolves.
        sub.delegation_depth = cx
            .execution_policy
            .spawn_depth
            .ok_or_else(|| safe_agent_refusal("pinned spawn-depth policy is inactive"))?;
        if let Some(drain) = &cx.drain {
            sub.drain = drain.clone();
            sub.owns_drain = false;
        }

        // --- Public-surface inherited context ---
        sub.workspace = child_workspace.clone();
        sub.model_context_window = cx.model_context_window;
        sub.model_max_output_tokens = cx.model_max_output_tokens;
        // Hooks are trusted operator-owned host policy, not capabilities offered to the model.
        // Dropping them here silently bypassed canonical Gate hooks for WorkflowEngine children.
        sub.install_hooks(cx.hooks.clone()).map_err(|error| {
            safe_agent_refusal(&format!(
                "child hook checkpoint rejected: {}",
                error.public_summary()
            ))
        })?;
        sub.hook_effect_journal = cx.hook_effect_journal.clone();
        sub.composition_environment_context = cx.environment_context.clone();
        sub.environment_context = cx.environment_context.clone();
        sub.bypass_permissions = cx.bypass_permissions;
        sub.pin_agent_catalog((*cx.agent_catalog).clone())
            .map_err(|error| {
                safe_agent_refusal(&format!(
                    "child agent catalog checkpoint rejected: {}",
                    error.public_summary()
                ))
            })?;
        // Installs the deny-list on the agent, its hooks, and (already, above) its registry.
        sub.set_sensitive_env_names(cx.sensitive_env_names.clone());

        // --- Coherent fresh-run runtime policy, BEFORE any durable append (the rollout is still
        //     empty here; route recording below is the first event). A leaf never orchestrates, so
        //     `Ultracode` collapses to `Max` (max thinking budget, no fan). ---
        let effort = cx
            .execution_policy
            .admit_child_effort(call.effort, &cx.effort_policy)
            .map_err(safe_agent_refusal)?;
        sub.configure_initial_runtime_policy(
            effort,
            cx.permission_mode,
            cx.permission_rules.clone(),
        )
        .map_err(|error| {
            safe_agent_refusal(&format!(
                "child runtime policy rejected: {}",
                error.public_summary()
            ))
        })?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.workflow_spawner.clock_before_epoch_secs",
                CLOCK_BEFORE_EPOCH_SECS,
            ));
        let parent_run = iteron_protocol::RunId(cx.parent_run_id.clone());
        sub.record_child_genesis_with_tunables(
            &parent_run,
            child_workspace.display().to_string(),
            created_at,
            tunables_config_digest,
            Some(agent_def.execution_tag()),
        )
        .map_err(|error| {
            safe_agent_refusal(&format!("child genesis failed: {}", error.public_summary()))
        })?;

        let model_router_opportunity = sub
            .begin_policy_decision(super::policy_evidence::MODEL_ROUTER_SLOT, None)
            .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
        let routed = match iteron_provider::catalog::ModelRouterStrategy::route_with(
            cx.model_router.as_ref(),
            &model_router_observation,
            cx.authority_ceiling,
        ) {
            Ok(routed) => {
                let draft = super::policy_evidence::PolicyDecisionDraft::selected(
                    super::policy_evidence::MODEL_ROUTER_SLOT,
                    &[iteron_protocol::PolicyActionV1::ModelRouterBoundParentRoute],
                    iteron_protocol::PolicyActionV1::ModelRouterBoundParentRoute,
                    "iteron:model-router-features-v1",
                    &(&model_router_observation, &routed.model),
                    &"selected_model_must_have_caller_resolved_route_evidence",
                )
                .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
                sub.append_policy_decision(model_router_opportunity, draft)
                    .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
                routed
            }
            Err(error) => {
                let draft = super::policy_evidence::PolicyDecisionDraft::abstained(
                    super::policy_evidence::MODEL_ROUTER_SLOT,
                    &[iteron_protocol::PolicyActionV1::ModelRouterBoundParentRoute],
                    "iteron:model-router-features-v1",
                    &model_router_observation,
                    &"unresolved_or_conflicting_routes_are_refused",
                )
                .map_err(|evidence_error| safe_agent_refusal(&evidence_error.public_summary()))?;
                sub.append_policy_decision(model_router_opportunity, draft)
                    .map_err(|evidence_error| {
                        safe_agent_refusal(&evidence_error.public_summary())
                    })?;
                return Err(safe_agent_refusal(&error.to_string()));
            }
        };
        sub.model = routed.model;

        // --- Route + pricing. Public API; `record_model_selection` appends the first durable event
        //     (RouteSelected) to the child rollout. Pricing is optional and only load-bearing when a
        //     positive USD ceiling must be enforced. ---
        if let Some(port) = &cx.pricing_port {
            sub.set_pricing_port(port.clone());
        }
        sub.record_model_selection(
            cx.provider_id.clone(),
            sub.model.clone(),
            cx.catalog_digest.clone(),
            cx.capability_digest.clone(),
        )
        .map_err(|error| {
            safe_agent_refusal(&format!(
                "child route selection failed: {}",
                error.public_summary()
            ))
        })?;
        sub.set_provider_controls(cx.provider_controls)
            .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
        sub.install_fallback_provider_routes(cx.fallback_provider_routes.clone())
            .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
        let shared_governor = child_provider_governor(cx)?;
        // The shared owner contains the complete composition-time route set. The child's actual
        // fallback vector above remains its narrower route authority; cloning the owner here only
        // shares load-bearing in-flight/quota/circuit state.
        sub.install_shared_provider_governor(shared_governor)
            .map_err(|error| safe_agent_refusal(&error.public_summary()))?;
        if cx.pricing_port.is_some() {
            let bound = sub.bind_selected_rate_card().map_err(|error| {
                safe_agent_refusal(&format!(
                    "child pricing bind failed: {}",
                    error.public_summary()
                ))
            })?;
            if budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) && !bound {
                return Err("child could not bind a verified rate card for its USD ceiling".into());
            }
        }

        Ok(sub)
    }
}

pub(super) fn intersect_budget(parent: &Budget, definition: &Budget) -> Result<Budget, String> {
    parent
        .validate()
        .map_err(|reason| format!("invalid parent child-budget ceiling: {reason}"))?;
    definition
        .validate()
        .map_err(|reason| format!("invalid agent-definition budget: {reason}"))?;

    let max_usd = match (parent.max_usd, definition.max_usd) {
        (Some(parent), Some(definition)) if definition < parent => {
            return Err(
                "agent definition requests a nested USD ceiling smaller than the shared parent ceiling; dual-ledger enforcement is required"
                    .into(),
            );
        }
        (Some(parent), _) => Some(parent),
        (None, definition) => definition,
    };
    Ok(Budget {
        max_turns: parent.max_turns.min(definition.max_turns),
        max_usd,
        max_tokens: match (parent.max_tokens, definition.max_tokens) {
            (Some(parent), Some(definition)) => Some(parent.min(definition)),
            (Some(parent), None) => Some(parent),
            (None, definition) => definition,
        },
        max_wall_secs: parent.max_wall_secs.min(definition.max_wall_secs),
        max_consecutive_tool_errors: parent
            .max_consecutive_tool_errors
            .min(definition.max_consecutive_tool_errors),
    })
}

/// Every priced request has an atomic conservative reservation, but a positive monetary ceiling
/// still narrows workflow fan-out to one. That makes the scheduler-level choice explainable and
/// prevents a batch of individually admissible upper bounds from consuming all remaining budget
/// before the first terminal can release its unused reservation. The independently resolved
/// lifetime call bound is preserved and this selected concurrency is checkpoint-visible.
pub(crate) fn governed_workflow_limits(
    budget: &Budget,
    limits: iteron_workflow::RunLimits,
) -> Result<iteron_workflow::RunLimits, &'static str> {
    if budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) {
        iteron_workflow::RunLimits::new(1, limits.max_agent_calls())
    } else {
        Ok(limits)
    }
}

#[async_trait]
impl AgentSpawner for KernelSpawner {
    fn execution_class(&self, call: &AgentCall) -> iteron_workflow::AgentExecutionClass {
        let requested_type = call.agent_type.as_deref().unwrap_or("generic");
        if self
            .cx
            .agent_catalog
            .get(requested_type)
            .is_some_and(iteron_agents::AgentDef::is_isolated_writer)
        {
            iteron_workflow::AgentExecutionClass::IsolatedWriter
        } else {
            iteron_workflow::AgentExecutionClass::ReadOnly
        }
    }

    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        self.spawn_reporting(call, None).await
    }

    async fn spawn_with_activity(
        &self,
        call: AgentCall,
        activity: AgentActivityReporter,
    ) -> AgentOutcome {
        self.spawn_reporting(call, Some(activity)).await
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use iteron_protocol::{Capability, EventKind};
    use iteron_provider::{ProviderError, StreamItem, TurnRequest, TurnResult};
    use iteron_workflow::{
        ProgressEvent, ProgressSink, RunId, RunSpec, WorkflowEngine, WorkflowState,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct NoTurnProvider;

    #[async_trait::async_trait]
    impl Provider for NoTurnProvider {
        fn provider_instance_id(&self) -> Option<&str> {
            Some("test-provider")
        }

        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            panic!("build-child tests must not dispatch a provider turn")
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ProgressEvent>>,
    }

    impl ProgressSink for RecordingSink {
        fn emit(&self, event: ProgressEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "core-agent-catalog-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn discovered_catalog(root: &std::path::Path) -> AgentCatalog {
        discovered_catalog_with_model(root, None)
    }

    fn discovered_catalog_with_model(root: &std::path::Path, model: Option<&str>) -> AgentCatalog {
        let home = root.join("home");
        let repo = root.join("repo");
        std::fs::create_dir_all(home.join(".iteron/agents")).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        let model = model.map_or(String::new(), |model| format!("model: {model}\n"));
        std::fs::write(
            home.join(".iteron/agents/reviewer.md"),
            format!(
                "---\nname: reviewer\ndescription: Narrow reviewer\ntools: [read_file]\n\
                 {model}maxTurns: 2\nmaxTokens: 41\nmaxWallSecs: 7\nmaxConsecutiveToolErrors: 1\n---\n\
                 Review exactly one file and report evidence.\n"
            ),
        )
        .unwrap();
        AgentCatalog::discover(&home, &repo)
    }

    fn unbound_context(root: &std::path::Path, catalog: AgentCatalog) -> KernelSpawnerContext {
        let mut context = KernelSpawnerContext::new(
            Arc::new(NoTurnProvider),
            "test-model".into(),
            "test-provider".into(),
            String::new(),
            String::new(),
            root.join("repo"),
            root.join("runs"),
            TenantId("tenant".into()),
            "parent".into(),
            "workflow".into(),
        );
        context.agent_catalog = Arc::new(catalog);
        context.budget.max_turns = 12;
        context.budget.max_tokens = Some(100);
        context.budget.max_wall_secs = 60;
        context.budget.max_consecutive_tool_errors = 3;
        context
    }

    fn context(root: &std::path::Path, catalog: AgentCatalog) -> KernelSpawnerContext {
        let mut context = unbound_context(root, catalog);
        pin_context(root, &mut context);
        context
    }

    fn call(agent_type: Option<&str>, model: Option<&str>) -> AgentCall {
        AgentCall {
            prompt: "inspect".into(),
            label: None,
            phase: None,
            model: model.map(str::to_owned),
            effort: None,
            agent_type: agent_type.map(str::to_owned),
            schema: None,
            cancel: Default::default(),
        }
    }

    #[test]
    fn role_specific_model_map_identity_is_enforced_before_child_effects() {
        let root = scratch("role-model-map");
        let catalog = discovered_catalog_with_model(&root, Some("test-model"));
        let mut cx = context(&root, catalog);
        cx.execution_policy.role_specific_models =
            crate::runtime_tunables::execution_policy::RoleSpecificModelMapIdentity::from_routes(
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
        let error = KernelSpawner::new(cx)
            .build_child(&call(Some("reviewer"), None), 0)
            .err()
            .expect("mismatched map identity must refuse before spawning");
        assert!(
            error.contains("pinned role-specific model map differs"),
            "{error}"
        );

        let alternate_root = scratch("role-model-unavailable");
        let catalog = discovered_catalog_with_model(&alternate_root, Some("other-model"));
        let cx = context(&alternate_root, catalog);
        let error = KernelSpawner::new(cx)
            .build_child(&call(Some("reviewer"), None), 0)
            .err()
            .expect("an unavailable role model must refuse before spawning");
        assert!(
            error.contains("model override is absent from the pinned role-specific model map"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(alternate_root);
    }

    #[test]
    fn unpinned_spawner_context_refuses_before_child_rollout_or_provider_effect() {
        let root = scratch("unpinned-context");
        let catalog = discovered_catalog(&root);
        let spawner = KernelSpawner::new(unbound_context(&root, catalog));

        let error = spawner
            .build_child(&call(None, None), 0)
            .err()
            .expect("a placeholder context without an immutable checkpoint must refuse");
        assert!(
            error.contains("runtime tunables were not pinned"),
            "{error}"
        );
        assert!(
            !root.join("runs/subagents").exists(),
            "refusal must happen before a child journal is opened"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn positive_workflow_usd_ceiling_requires_one_shared_pricing_authority() {
        let root = scratch("workflow-pricing-authority");
        let catalog = discovered_catalog(&root);
        let mut cx = unbound_context(&root, catalog);
        cx.budget.max_usd = Some(1.0);

        let error = cx
            .install_pricing_authority(None)
            .expect_err("an unpriced positive ceiling must fail before a child rollout exists");
        assert!(error.contains("positive workflow USD ceiling"), "{error}");
        assert!(cx.pricing_port.is_none());
        assert!(cx.usd_budget.is_none());

        let authority = iteron_obs::HmacPricingAuthority::new(Vec::new()).unwrap();
        cx.install_pricing_authority(Some(Arc::new(authority)))
            .unwrap();
        assert!(cx.pricing_port.is_some());
        assert!(
            cx.usd_budget
                .as_ref()
                .is_some_and(|budget| budget.requires_pricing()),
            "one shared session ledger must carry the resolved positive ceiling"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn priced_workflow_limits_are_checkpoint_visible_and_serial() {
        let priced = Budget {
            max_usd: Some(1.0),
            ..Budget::default()
        };
        let requested = iteron_workflow::RunLimits::new(8, 23).unwrap();
        let selected = governed_workflow_limits(&priced, requested).unwrap();
        assert_eq!(selected.max_concurrency(), 1);
        assert_eq!(selected.max_agent_calls(), 23);

        let unpriced = Budget::default();
        assert_eq!(
            governed_workflow_limits(&unpriced, requested).unwrap(),
            requested
        );
    }

    #[test]
    fn workflow_children_share_one_physical_route_governor() {
        let root = scratch("shared-provider-governor");
        let catalog = discovered_catalog(&root);
        let mut cx = unbound_context(&root, catalog);
        let policy = iteron_provider::GovernorPolicy {
            max_in_flight_per_route: 1,
            ..iteron_provider::GovernorPolicy::default()
        };
        cx.initialize_provider_governor(policy).unwrap();
        let first_governor = child_provider_governor(&cx).unwrap();
        let second_governor = child_provider_governor(&cx).unwrap();
        let route = "test-provider:test-model";
        let permit = match first_governor.admit(route, std::time::Instant::now()) {
            iteron_provider::ProviderAdmission::Admitted(permit) => permit,
            other => panic!("first shared route admission was not admitted: {other:?}"),
        };
        assert!(matches!(
            second_governor.admit(route, std::time::Instant::now()),
            iteron_provider::ProviderAdmission::Deferred { .. }
                | iteron_provider::ProviderAdmission::Rejected(_)
        ));
        drop(permit);
        assert!(matches!(
            second_governor.admit(route, std::time::Instant::now()),
            iteron_provider::ProviderAdmission::Admitted(_)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    fn production_compatible_resolved_fixture(
        root: &Path,
        catalog: &AgentCatalog,
        hooks: &Hooks,
        provider_id: &str,
        model_id: &str,
    ) -> iteron_tunables::ResolvedTunableSet {
        use iteron_tunables::{ConstraintValue, ResolutionValue};

        let mut input = iteron_record::resolved_fixture::input();

        // The record fixture intentionally samples tiny schema-boundary values. A workflow child
        // installs the real coding registry, whose schemas alone exceed that sample. Give this
        // production-shaped integration fixture one exact 120k provider window and a bounded 20k
        // tool-schema partition; resolution still enforces the cross-family sum before the child
        // can open a provider request.
        let context_window = ResolutionValue::Integer { value: 120_000 };
        let mut context_budget = iteron_ctx::ContextBudgetPolicy::default();
        let schema_growth = 20_000usize.saturating_sub(context_budget.tool_schema_tokens);
        context_budget.tool_schema_tokens = 20_000;
        context_budget.transcript_tokens = context_budget
            .transcript_tokens
            .checked_sub(schema_growth)
            .expect("default transcript partition covers coding schema growth");
        let window = input
            .declared_values
            .iter_mut()
            .find(|value| value.family == "context_window_override_reserve")
            .expect("resolved fixture omitted context-window policy");
        let ResolutionValue::Object { fields } = &mut window.value else {
            panic!("context-window fixture stopped being an object")
        };
        let context_fields = [
            ("model_window_tokens", context_window.clone()),
            (
                "output_reserve_tokens",
                ResolutionValue::Integer {
                    value: i64::from(context_budget.output_reserve_tokens),
                },
            ),
            (
                "verification_reserve_tokens",
                ResolutionValue::Integer {
                    value: i64::from(context_budget.verification_reserve_tokens),
                },
            ),
            (
                "instruction_budget_tokens",
                ResolutionValue::Integer {
                    value: i64::try_from(context_budget.instruction_tokens).unwrap(),
                },
            ),
            (
                "task_context_budget_tokens",
                ResolutionValue::Integer {
                    value: i64::try_from(context_budget.task_context_tokens).unwrap(),
                },
            ),
            (
                "memory_budget_tokens",
                ResolutionValue::Integer {
                    value: i64::try_from(context_budget.memory_tokens).unwrap(),
                },
            ),
            (
                "attachment_budget_tokens",
                ResolutionValue::Integer {
                    value: i64::try_from(context_budget.attachment_tokens).unwrap(),
                },
            ),
            (
                "tool_schema_budget_tokens",
                ResolutionValue::Integer {
                    value: i64::try_from(context_budget.tool_schema_tokens).unwrap(),
                },
            ),
        ];
        for (field, value) in &context_fields {
            fields.insert((*field).into(), value.clone());
        }
        for evidence in input
            .constraint_evidence
            .iter_mut()
            .filter(|evidence| evidence.family == "context_window_override_reserve")
        {
            let value = context_fields
                .iter()
                .find_map(|(field, value)| (*field == evidence.field).then_some(value.clone()))
                .unwrap_or_else(|| {
                    panic!("unexpected context-window ceiling `{}`", evidence.field)
                });
            match &mut evidence.value {
                ConstraintValue::UpperBound { value: ceiling }
                | ConstraintValue::Exact { value: ceiling } => *ceiling = value,
                ConstraintValue::Domain {
                    allowed_values,
                    preferred,
                    ..
                } => {
                    *allowed_values = Some([value.clone()].into_iter().collect());
                    if preferred.is_some() {
                        *preferred = Some(value);
                    }
                }
            }
        }
        for (family, value) in [
            ("system_prefix_budget", context_budget.stable_prefix_tokens),
            (
                "conversation_history_budget",
                context_budget.transcript_tokens,
            ),
            (
                "tool_result_history_budget",
                context_budget.tool_result_tokens,
            ),
            (
                "lsp_result_context_budget",
                context_budget.lsp_result_tokens,
            ),
        ] {
            let value = ResolutionValue::Integer {
                value: i64::try_from(value).unwrap(),
            };
            input
                .declared_values
                .iter_mut()
                .find(|candidate| candidate.family == family)
                .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
                .value = value.clone();
            for evidence in input
                .constraint_evidence
                .iter_mut()
                .filter(|evidence| evidence.family == family)
            {
                match &mut evidence.value {
                    ConstraintValue::UpperBound { value: ceiling }
                    | ConstraintValue::Exact { value: ceiling } => *ceiling = value.clone(),
                    ConstraintValue::Domain {
                        allowed_values,
                        preferred,
                        ..
                    } => {
                        *allowed_values = Some([value.clone()].into_iter().collect());
                        if preferred.is_some() {
                            *preferred = Some(value.clone());
                        }
                    }
                }
            }
        }

        // No operator hook catalog is installed in this build-child fixture. A configured-only
        // family must therefore remain inactive; inventing an identity would correctly make the
        // production `install_hooks` gate reject the child.
        if hooks.is_empty() {
            input
                .declared_values
                .retain(|candidate| candidate.family != "hooks_map");
            input
                .constraint_evidence
                .retain(|evidence| evidence.family != "hooks_map");
        } else {
            let identity = hooks.catalog_identity();
            let value = ResolutionValue::CatalogRef {
                catalog_id: "iteron://tunables/catalogs/hooks_map-v1".into(),
                digest_sha256: identity.digest_sha256,
                entry_count: u64::try_from(identity.entry_count).unwrap(),
                canonical_bytes: u64::try_from(identity.canonical_bytes).unwrap(),
            };
            input
                .declared_values
                .iter_mut()
                .find(|candidate| candidate.family == "hooks_map")
                .expect("resolved fixture omitted hooks_map")
                .value = value.clone();
            for evidence in input
                .constraint_evidence
                .iter_mut()
                .filter(|evidence| evidence.family == "hooks_map")
            {
                let ConstraintValue::Domain {
                    allowed_values,
                    preferred,
                    ..
                } = &mut evidence.value
                else {
                    panic!("hooks-map ceiling stopped being an attested domain")
                };
                *allowed_values = Some([value.clone()].into_iter().collect());
                if preferred.is_some() {
                    *preferred = Some(value.clone());
                }
            }
        }

        // These identities belong to higher-layer binary owners that iteron-record intentionally
        // cannot depend on. Replace the structural resolver samples with the exact production
        // identities before resolving the integration fixture.
        let graph = iteron_workflow::workflow_graph_runtime_identity();
        let workflow_graph = ResolutionValue::CatalogRef {
            catalog_id: "iteron://tunables/catalogs/workflow_graph-v1".into(),
            digest_sha256: graph.digest_sha256,
            entry_count: u64::try_from(graph.entry_count).unwrap(),
            canonical_bytes: u64::try_from(graph.canonical_bytes).unwrap(),
        };
        let environment = iteron_protocol::EnvironmentSnapshotIdentity::from_optional(None);
        let environment_value = ResolutionValue::Object {
            fields: [
                (
                    "present".into(),
                    ResolutionValue::Boolean {
                        value: environment.present,
                    },
                ),
                (
                    "digest_sha256".into(),
                    ResolutionValue::Text {
                        value: environment.digest_sha256,
                    },
                ),
                (
                    "canonical_bytes".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(environment.canonical_bytes).unwrap(),
                    },
                ),
                (
                    "trust".into(),
                    ResolutionValue::Enum {
                        value: "trusted".into(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let child_memory = ResolutionValue::Object {
            fields: [
                (
                    "mode".into(),
                    ResolutionValue::Enum {
                        value: "isolated".into(),
                    },
                ),
                (
                    "inherit_parent".into(),
                    ResolutionValue::Boolean { value: false },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let agent_identity = catalog.runtime_identity();
        let agent_catalog = ResolutionValue::CatalogRef {
            catalog_id: "iteron://tunables/catalogs/agent_catalog-v1".into(),
            digest_sha256: agent_identity.digest_sha256,
            entry_count: u64::try_from(agent_identity.entry_count).unwrap(),
            canonical_bytes: u64::try_from(agent_identity.canonical_bytes).unwrap(),
        };
        let admitted_role_routes =
            crate::runtime_tunables::execution_policy::admitted_role_model_routes(
                catalog,
                provider_id,
                model_id,
            )
            .unwrap();
        let selected_route = format!("{provider_id}:{model_id}");
        let role_specific_models = ResolutionValue::Map {
            entries: admitted_role_routes
                .iter()
                .map(|(role, route)| {
                    (
                        role.clone(),
                        ResolutionValue::Enum {
                            value: route.clone(),
                        },
                    )
                })
                .collect(),
        };
        for (catalog_id, values) in [
            (
                "iteron://tunables/catalogs/agent-roles-v1",
                catalog
                    .defs()
                    .iter()
                    .map(|definition| definition.name.clone())
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            (
                "iteron://tunables/catalogs/model-routes-v1",
                admitted_role_routes
                    .values()
                    .cloned()
                    .chain(std::iter::once(selected_route.clone()))
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
        ] {
            let snapshot = iteron_tunables::runtime_catalog_snapshot(catalog_id, values)
                .expect("test catalog owner must publish bounded route values");
            *input
                .runtime
                .catalogs
                .iter_mut()
                .find(|catalog| catalog.catalog_id == catalog_id)
                .unwrap_or_else(|| panic!("resolved fixture omitted {catalog_id}")) = snapshot;
        }
        let process_launch = iteron_tools::ProcessLaunchPolicy::owner(root).unwrap();
        let process_cwd = ResolutionValue::Object {
            fields: [
                (
                    "scope".into(),
                    ResolutionValue::Enum {
                        value: process_launch.cwd.scope.as_str().into(),
                    },
                ),
                (
                    "initial_cwd".into(),
                    ResolutionValue::Text {
                        value: process_launch
                            .cwd
                            .initial_cwd
                            .to_string_lossy()
                            .into_owned(),
                    },
                ),
                (
                    "preserve_changes".into(),
                    ResolutionValue::Boolean {
                        value: process_launch.cwd.preserve_changes,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let child_environment = ResolutionValue::Object {
            fields: [
                (
                    "reuse".into(),
                    ResolutionValue::Boolean {
                        value: process_launch.environment.reuse,
                    },
                ),
                (
                    "max_entries".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(process_launch.environment.max_entries).unwrap(),
                    },
                ),
                (
                    "max_bytes".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(process_launch.environment.max_bytes).unwrap(),
                    },
                ),
                (
                    "blocked_names".into(),
                    ResolutionValue::List {
                        items: process_launch
                            .environment
                            .blocked_names
                            .iter()
                            .map(|name| ResolutionValue::Text {
                                value: name.clone(),
                            })
                            .collect(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let queue = crate::app_server::AppServerQueuePolicy::owner();
        let app_server_queue = ResolutionValue::Object {
            fields: [
                (
                    "submission_entries".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(queue.submission_entries()).unwrap(),
                    },
                ),
                (
                    "submission_bytes".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(queue.submission_bytes()).unwrap(),
                    },
                ),
                (
                    "event_entries".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(queue.event_entries()).unwrap(),
                    },
                ),
                (
                    "cosmetic_overflow".into(),
                    ResolutionValue::Enum {
                        value: match queue.cosmetic_overflow() {
                            crate::app_server::CosmeticOverflow::Drop => "drop",
                            crate::app_server::CosmeticOverflow::Coalesce => "coalesce",
                        }
                        .into(),
                    },
                ),
                (
                    "authoritative_overflow".into(),
                    ResolutionValue::Enum {
                        value: match queue.authoritative_overflow() {
                            crate::app_server::AuthoritativeOverflow::Wait => "wait",
                            crate::app_server::AuthoritativeOverflow::Reject => "reject",
                        }
                        .into(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        let binary = crate::image_input::BinaryMediaInspectionPolicy::owner();
        let binary_catalog = iteron_tunables::runtime_catalog_snapshot(
            "iteron://tunables/catalogs/binary-inspectors-v1",
            binary.inspector_ids(),
        )
        .expect("binary-media owner must publish a canonical scalar catalog");
        let binary_catalog_id = binary_catalog.catalog_id.clone();
        *input
            .runtime
            .catalogs
            .iter_mut()
            .find(|catalog| catalog.catalog_id == binary_catalog_id)
            .expect("resolved fixture omitted the binary-inspector scalar catalog") =
            binary_catalog;
        let binary_media = ResolutionValue::Object {
            fields: [
                (
                    "mime_routes".into(),
                    ResolutionValue::Map {
                        entries: binary
                            .mime_routes()
                            .into_iter()
                            .map(|(mime, inspector)| {
                                (mime, ResolutionValue::Enum { value: inspector })
                            })
                            .collect(),
                    },
                ),
                (
                    "unknown_mime".into(),
                    ResolutionValue::Enum {
                        value: match binary.unknown_mime() {
                            crate::image_input::UnknownMimePolicy::Reject => "reject",
                            crate::image_input::UnknownMimePolicy::MetadataOnly => "metadata_only",
                        }
                        .into(),
                    },
                ),
                (
                    "max_input_bytes".into(),
                    ResolutionValue::Integer {
                        value: i64::try_from(binary.max_input_bytes()).unwrap(),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        for (family, value) in [
            ("workflow_graph", workflow_graph),
            ("environment_snapshot", environment_value.clone()),
            ("per_agent_memory_scope", child_memory.clone()),
            ("agent_catalog", agent_catalog.clone()),
            ("role_specific_model_map", role_specific_models.clone()),
            (
                "per_agent_model",
                ResolutionValue::Enum {
                    value: selected_route.clone(),
                },
            ),
            ("process_cwd_continuity", process_cwd.clone()),
            ("child_process_environment_reuse", child_environment.clone()),
            ("app_server_sq_eq_backpressure", app_server_queue.clone()),
            ("binary_media_inspection_routing", binary_media.clone()),
        ] {
            input
                .declared_values
                .iter_mut()
                .find(|candidate| candidate.family == family)
                .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
                .value = value;
        }
        for evidence in &mut input.constraint_evidence {
            if evidence.family == "process_cwd_continuity" && evidence.field == "initial_cwd" {
                let ConstraintValue::Domain { allowed_values, .. } = &mut evidence.value else {
                    panic!("process cwd ceiling stopped being an attested domain")
                };
                let ResolutionValue::Object { fields } = &process_cwd else {
                    unreachable!()
                };
                *allowed_values = Some(
                    [fields.get("initial_cwd").unwrap().clone()]
                        .into_iter()
                        .collect(),
                );
                continue;
            }
            if evidence.family == "child_process_environment_reuse" {
                let ResolutionValue::Object { fields } = &child_environment else {
                    unreachable!()
                };
                match (evidence.field.as_str(), &mut evidence.value) {
                    ("max_entries", ConstraintValue::UpperBound { value }) => {
                        *value = fields["max_entries"].clone()
                    }
                    ("blocked_names", ConstraintValue::Domain { allowed_values, .. }) => {
                        *allowed_values =
                            Some([fields["blocked_names"].clone()].into_iter().collect())
                    }
                    (other, _) => {
                        panic!("unexpected child environment ceiling shape for {other}")
                    }
                }
                continue;
            }
            if evidence.family == "app_server_sq_eq_backpressure" {
                let ConstraintValue::UpperBound { value } = &mut evidence.value else {
                    panic!("app-server queue ceiling stopped being an upper bound")
                };
                let ResolutionValue::Object { fields } = &app_server_queue else {
                    unreachable!()
                };
                *value = fields[&evidence.field].clone();
                continue;
            }
            if evidence.family == "binary_media_inspection_routing" {
                let ResolutionValue::Object { fields } = &binary_media else {
                    unreachable!()
                };
                match (evidence.field.as_str(), &mut evidence.value) {
                    ("mime_routes", ConstraintValue::Domain { allowed_values, .. }) => {
                        *allowed_values =
                            Some([fields["mime_routes"].clone()].into_iter().collect())
                    }
                    ("max_input_bytes", ConstraintValue::UpperBound { value }) => {
                        *value = fields["max_input_bytes"].clone()
                    }
                    (other, _) => panic!("unexpected binary-media ceiling shape for {other}"),
                }
                continue;
            }
            let replacement = match evidence.family.as_str() {
                "environment_snapshot" => &environment_value,
                "per_agent_memory_scope" => &child_memory,
                "agent_catalog" => &agent_catalog,
                "role_specific_model_map" => &role_specific_models,
                "per_agent_model" => {
                    let ConstraintValue::Domain {
                        allowed_values,
                        preferred,
                        ..
                    } = &mut evidence.value
                    else {
                        panic!("per-agent model ceiling stopped being an attested domain")
                    };
                    let selected = ResolutionValue::Enum {
                        value: selected_route.clone(),
                    };
                    *allowed_values = Some([selected.clone()].into_iter().collect());
                    if evidence.ceiling == iteron_tunables::ExternalCeiling::ProviderCapability {
                        *preferred = Some(selected);
                    }
                    continue;
                }
                _ => continue,
            };
            let ConstraintValue::Domain {
                allowed_values,
                preferred,
                ..
            } = &mut evidence.value
            else {
                panic!(
                    "{family} ceiling stopped being an attested domain",
                    family = evidence.family
                )
            };
            *allowed_values = Some([replacement.clone()].into_iter().collect());
            if preferred.is_some() {
                *preferred = Some(replacement.clone());
            }
        }

        let resolved = iteron_tunables::resolve(input)
            .expect("production-compatible integration fixture must resolve atomically");
        iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
            .expect("workflow test fixture must bind every effective fixed authority")
    }

    pub(super) fn pin_context(root: &Path, context: &mut KernelSpawnerContext) {
        let resolved = production_compatible_resolved_fixture(
            root,
            context.agent_catalog.as_ref(),
            &context.hooks,
            &context.provider_id,
            &context.model,
        );
        context.pin_resolved_tunables(&resolved).unwrap();
        let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
            context.tunables_pin.as_ref().unwrap().checkpoint(),
            None,
        )
        .unwrap()
        .core;
        context.default_effort = effective.effort;
        context.execution_policy = effective.execution;
        context.retry_policy = effective.retry;
        context.provider_controls = effective.provider_governor.controls;
        context
            .initialize_provider_governor(effective.provider_governor.policy)
            .unwrap();
        context.deferred_tool_eager_limit = effective.deferred_tool_eager_limit;
        context.model_context_window = effective.model_context_window;
        context.model_max_output_tokens = effective.request_output_cap;
        context.context_budget_policy = effective.context_budget;
        context.context_materialization_policy = effective.context_materialization;
        context.compaction_policy = effective.compaction;
        context.permission_mode = effective.permission_mode;
        context.permission_rules = effective.permission_rules;
        context.bypass_permissions = effective.bypass_permissions;
    }

    #[test]
    fn workflow_child_installs_checkpoint_model_limits_instead_of_constructor_defaults() {
        let root = scratch("checkpoint-model-limits");
        let catalog = discovered_catalog(&root);
        let cx = context(&root, catalog);
        let expected_window = cx.model_context_window;
        let expected_output = cx.model_max_output_tokens;
        assert!(expected_window.is_some());
        assert!(expected_output.is_some());

        let child = KernelSpawner::new(cx)
            .build_child(&call(None, None), 0)
            .expect("a completely pinned workflow child must build");
        assert_eq!(child.model_context_window, expected_window);
        assert_eq!(child.model_max_output_tokens, expected_output);
        let _ = std::fs::remove_dir_all(root);
    }

    /// A fan-out child has no approval channel, so a gate it cannot answer is a refusal wearing a
    /// question's clothes: a bypassed session used to delegate work its own children could not do.
    /// The posture is inherited; the read-only CEILING is still intersected, and that is what keeps
    /// the child bounded.
    #[test]
    fn a_child_inherits_the_session_posture_but_never_its_ceiling() {
        let root = scratch("posture");
        let catalog = discovered_catalog(&root);
        let mut cx = context(&root, catalog);
        cx.bypass_permissions = true;
        let spawner = KernelSpawner::new(cx);

        let child = spawner.build_child(&call(None, None), 0).unwrap();
        assert!(
            child.bypass_permissions,
            "a child of an operator-authority session does not stop to ask what it cannot ask"
        );
        assert!(child.authority_ceiling.contains(Capability::ReadOnly));
        assert!(
            !child.authority_ceiling.contains(Capability::CodeExecuting),
            "inheriting the posture must not widen the ceiling"
        );
    }

    #[test]
    fn a_child_inherits_the_exact_nonbaseline_policy_checkpoint() {
        let root = scratch("policy-checkpoint");
        let catalog = discovered_catalog(&root);
        let mut cx = context(&root, catalog);
        let view = crate::runtime_tunables::effective_view::EffectiveTunablesView::from_checkpoint(
            cx.tunables_pin.as_ref().unwrap().checkpoint(),
        )
        .unwrap();
        let tooling =
            crate::runtime_tunables::effective_tooling::EffectiveToolingSettings::decode(&view)
                .unwrap();
        let probe_registry = Registry::read_only(root.join("probe")).unwrap();
        tooling.install(&probe_registry).unwrap();
        cx.execution_policy = crate::runtime_tunables::effective_execution::decode(&view).unwrap();
        crate::runtime_tunables::effective_core::decode_verification_feedback(&view).unwrap();
        crate::runtime_tunables::effective_content::decode(&view).unwrap();
        crate::runtime_tunables::effective_app_server::decode(&view).unwrap();
        crate::runtime_tunables::effective_binary_media::decode(&view).unwrap();
        let identity = crate::bundle_adapter::registered_implementations()
            .unwrap()
            .into_iter()
            .find(|identity| identity.slot == "core/router" && identity.policy_id == "direct-only")
            .expect("direct router is registered");
        let bundle = iteron_evolve::PolicyBundle {
            bundle_id: "child-inheritance".into(),
            digest: "a".repeat(64),
            policies: vec![iteron_evolve::PolicyRef {
                slot: iteron_evolve::StrategySlot::new("core/router").unwrap(),
                policy_id: identity.policy_id,
                version: identity.version,
                digest: identity.digest,
            }],
            rollback_to: None,
        };
        let compiled = crate::bundle_adapter::compile_operator_bundle(Some(&bundle)).unwrap();
        let expected = compiled.policy_runtime_bindings().to_vec();
        let expected_snapshot = compiled.genesis_snapshot().clone();
        cx.install_compiled_policy_bundle(compiled);

        let child = KernelSpawner::new(cx)
            .build_child(&call(None, None), 0)
            .unwrap();
        assert_eq!(child.policy_runtime_bindings(), expected.as_slice());
        assert!(child.policy_runtime_bindings().iter().any(|binding| {
            binding.slot.as_persisted_str() == "core/router"
                && binding.policy.policy_id == "direct-only"
        }));
        let events = iteron_record::replay(child.rollout.path()).unwrap();
        let (recorded_snapshot, inherited_from) = events
            .iter()
            .find_map(|event| match &event.kind {
                iteron_protocol::EventKind::PolicyBundleSnapshot {
                    snapshot,
                    inherited_from,
                    ..
                } => Some((snapshot, inherited_from.as_ref())),
                _ => None,
            })
            .expect("a successfully composed child must durably pin its policy checkpoint");
        assert_eq!(recorded_snapshot, &expected_snapshot);
        let inherited_from = inherited_from
            .expect("a child checkpoint must be bound to its direct parent's receipt identity");
        assert_eq!(inherited_from.parent_run, "parent");
        assert_eq!(
            inherited_from.parent_receipt_digest_sha256,
            expected_snapshot.receipt_digest_sha256
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_child_inherits_operator_hooks_and_the_same_durable_journal() {
        let root = scratch("hooks");
        let catalog = discovered_catalog(&root);
        let mut cx = unbound_context(&root, catalog);
        cx.hooks
            .append_verified_plugin("session.created", ":".into())
            .unwrap();
        pin_context(&root, &mut cx);
        let journal_path = root.join("hooks.jsonl");
        cx.hook_effect_journal = Some(HookEffectJournal::open(&journal_path).unwrap());
        let spawner = KernelSpawner::new(cx);

        let child = spawner.build_child(&call(None, None), 0).unwrap();
        assert!(
            !child.hooks.is_empty(),
            "workflow children must not bypass trusted operator Hook policy"
        );
        assert!(
            child.hook_effect_journal.is_some(),
            "every child Hook command must use the session's durable effect journal"
        );
        drop(child);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn selected_definition_controls_system_tools_budget_authority_and_genesis_tag() {
        let root = scratch("selected");
        let catalog = discovered_catalog(&root);
        let expected = catalog.get("reviewer").unwrap().clone();
        let spawner = KernelSpawner::new(context(&root, catalog));

        let child = spawner
            .build_child(&call(Some("reviewer"), None), 0)
            .unwrap();
        assert_eq!(child.system, "Review exactly one file and report evidence.");
        assert_eq!(child.budget.max_turns, 2);
        assert_eq!(child.budget.max_tokens, Some(41));
        assert_eq!(child.budget.max_wall_secs, 7);
        assert_eq!(child.budget.max_consecutive_tool_errors, 1);
        assert_eq!(
            child
                .registry
                .specs()
                .into_iter()
                .map(|spec| spec.name)
                .collect::<Vec<_>>(),
            vec!["read_file"]
        );
        assert!(child.authority_ceiling.contains(Capability::ReadOnly));
        assert!(!child.authority_ceiling.contains(Capability::CodeExecuting));
        assert!(
            !child
                .policy_capabilities
                .contains(Capability::ReversibleLocal)
        );
        assert!(child.hooks.is_empty());
        assert!(
            child.bypass_permissions,
            "the child inherits the checkpoint's default bypass posture while its read-only \
             authority ceiling still prevents widening"
        );

        let events = iteron_record::replay(child.rollout.path()).unwrap();
        let tag = events.iter().find_map(|event| match &event.kind {
            EventKind::RunStart {
                agent_definition_tag,
                ..
            } => agent_definition_tag.as_deref(),
            _ => None,
        });
        let expected_tag = expected.execution_tag();
        assert_eq!(tag, Some(expected_tag.as_str()));
        drop(child);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn adversarial_request_metadata_fails_before_rollout_or_provider_and_is_safe() {
        let root = scratch("refusals");
        let catalog = discovered_catalog(&root);
        let spawner = KernelSpawner::new(context(&root, catalog));
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let oversized_name = "n".repeat(iteron_workflow::spawner::MAX_AGENT_TYPE_BYTES + 1);
        let oversized_model = "m".repeat(iteron_workflow::spawner::MAX_AGENT_MODEL_BYTES + 1);
        let controlled_name = format!("reviewer\n{secret}\u{1b}[2J");
        let controlled_model = format!("model\r{secret}\u{202e}");

        for call in [
            call(Some("writer"), None),
            call(Some("Reviewer"), None),
            call(Some("reviewer"), Some("other-model")),
            call(Some("reviewer/child"), None),
            call(Some(&oversized_name), None),
            call(Some(&controlled_name), None),
            call(Some(secret), None),
            call(Some("reviewer"), Some(&oversized_model)),
            call(Some("reviewer"), Some(&controlled_model)),
            call(Some("reviewer"), Some(secret)),
        ] {
            let reason = match spawner.spawn(call).await {
                AgentOutcome::Null {
                    reason: Some(reason),
                } => reason,
                _ => panic!("authority-widening, malformed, or unresolved call was admitted"),
            };
            assert!(reason.len() <= MAX_AGENT_REFUSAL_BYTES, "{reason}");
            assert!(!reason.chars().any(char::is_control), "{reason:?}");
            assert!(!reason.contains(secret), "{reason}");
            assert!(!reason.contains("other-model"), "{reason}");
            assert!(!reason.contains(&oversized_name), "{reason}");
            assert!(!reason.contains(&oversized_model), "{reason}");
        }
        let journal_count = std::fs::read_dir(root.join("runs/subagents"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            journal_count, 2,
            "malformed metadata must fail before a journal, while two syntactically valid but \
             policy-refused model selections retain their bounded decision evidence"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn request_refusals_are_safe_across_null_journal_and_progress_surfaces() {
        let root = scratch("refusal-surfaces");
        let catalog = discovered_catalog(&root);
        let spawner = Arc::new(KernelSpawner::new(context(&root, catalog)));
        let sink = Arc::new(RecordingSink::default());
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let oversized_name = "n".repeat(iteron_workflow::spawner::MAX_AGENT_TYPE_BYTES + 1);
        let oversized_model = "m".repeat(iteron_workflow::spawner::MAX_AGENT_MODEL_BYTES + 1);
        let requests = serde_json::json!([
            {"agentType": "reviewer/child"},
            {"agentType": oversized_name.clone()},
            {"agentType": format!("reviewer\n{secret}\u{1b}[2J")},
            {"agentType": secret},
            {"agentType": "reviewer", "model": oversized_model.clone()},
            {"agentType": "reviewer", "model": format!("model\r{secret}\u{202e}")},
            {"agentType": "reviewer", "model": secret},
        ]);
        let request_count = requests.as_array().unwrap().len();
        let script = r#"export const meta = { name: 'refusals', description: '', phases: [] };
const results = [];
for (const request of args.requests) {
  results.push(await agent('inspect', request));
}
return results;
"#;
        let spec = RunSpec::new(script)
            .with_args(serde_json::json!({"requests": requests}))
            .with_run_id(RunId::new("refusal-surfaces"))
            .with_workflows_dir(root.join("workflows"));
        let report = WorkflowEngine::execute(spec, spawner, sink.clone())
            .await
            .expect("every refusal settles as null");
        assert_eq!(
            report.value,
            serde_json::Value::Array(vec![serde_json::Value::Null; request_count])
        );
        let journal_count = std::fs::read_dir(root.join("runs/subagents"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            journal_count, 2,
            "only syntactically valid model-router refusals own durable decision journals"
        );

        let events = sink.events.lock().unwrap();
        let rendered_events = format!("{events:?}");
        assert!(!rendered_events.contains(secret), "{rendered_events}");
        assert!(!rendered_events.contains(&oversized_name));
        assert!(!rendered_events.contains(&oversized_model));
        let errors: Vec<&String> = events
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::AgentFinished {
                    state: WorkflowState::Error,
                    error: Some(error),
                    ..
                } => Some(error),
                _ => None,
            })
            .collect();
        assert_eq!(errors.len(), request_count);
        assert!(errors.iter().all(|error| {
            error.len() <= MAX_AGENT_REFUSAL_BYTES
                && !error.chars().any(char::is_control)
                && !error.contains(secret)
        }));
        drop(events);

        let journal =
            std::fs::read_to_string(root.join("workflows/refusal-surfaces/journal.jsonl")).unwrap();
        assert!(!journal.contains(secret));
        assert!(!journal.contains(&oversized_name));
        assert!(!journal.contains(&oversized_model));
        let reasons: Vec<String> = journal
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|line| {
                line.get("record")?
                    .get("outcome")?
                    .get("reason")?
                    .as_str()
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(reasons.len(), request_count);
        assert!(reasons.iter().all(|reason| {
            reason.len() <= MAX_AGENT_REFUSAL_BYTES
                && !reason.chars().any(char::is_control)
                && !reason.contains(secret)
        }));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refusal_chokepoint_redacts_escapes_and_bounds_arbitrary_diagnostics() {
        let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";
        let safe = safe_agent_refusal(&format!(
            "setup\n{secret}\r\u{1b}[2J\u{202e}{}",
            "界".repeat(2_048)
        ));
        assert!(safe.len() <= MAX_AGENT_REFUSAL_BYTES, "{}", safe.len());
        assert!(safe.ends_with(AGENT_REFUSAL_TRUNCATED), "{safe}");
        assert!(!safe.chars().any(char::is_control), "{safe:?}");
        assert!(!safe.contains(secret), "{safe}");
        assert!(safe.contains("\\n"), "{safe}");
        assert!(safe.contains("\\u{1b}"), "{safe}");
        assert!(safe.contains("\\u{202e}"), "{safe}");
    }

    #[test]
    fn definition_budget_only_narrows_and_never_claims_an_unenforced_nested_usd_ledger() {
        let parent = Budget {
            max_turns: 10,
            max_usd: None,
            max_tokens: Some(100),
            max_wall_secs: 60,
            max_consecutive_tool_errors: 4,
        };
        let definition = Budget {
            max_turns: 3,
            max_usd: Some(2.0),
            max_tokens: Some(40),
            max_wall_secs: 7,
            max_consecutive_tool_errors: 1,
        };
        let local = intersect_budget(&parent, &definition).unwrap();
        assert_eq!(local.max_turns, 3);
        assert_eq!(local.max_usd, Some(2.0));
        assert_eq!(local.max_tokens, Some(40));
        assert_eq!(local.max_wall_secs, 7);
        assert_eq!(local.max_consecutive_tool_errors, 1);

        let mut shared_parent = parent.clone();
        shared_parent.max_usd = Some(1.0);
        let mut no_local_usd = definition.clone();
        no_local_usd.max_usd = None;
        assert_eq!(
            intersect_budget(&shared_parent, &no_local_usd)
                .unwrap()
                .max_usd,
            Some(1.0)
        );

        let mut looser_shared_parent = shared_parent.clone();
        looser_shared_parent.max_usd = Some(3.0);
        let error = intersect_budget(&looser_shared_parent, &definition).unwrap_err();
        assert!(error.contains("dual-ledger enforcement"), "{error}");

        let mut looser_definition = definition;
        looser_definition.max_usd = Some(4.0);
        assert_eq!(
            intersect_budget(&shared_parent, &looser_definition)
                .unwrap()
                .max_usd,
            Some(1.0)
        );
    }
}
