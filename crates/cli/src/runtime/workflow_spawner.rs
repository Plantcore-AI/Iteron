//! `KernelSpawner` — the production [`core_workflow::AgentSpawner`].
//!
//! Every workflow `agent('...')` call runs a GENUINE child [`Agent`] (its own context, its own
//! read-only tool loop) via `Agent::run_leaf`, not a single provider completion. This is the
//! standalone upgrade of the CLI's first-slice `ProviderSpawner` (see `crates/cli/src/workflow.rs`).
//!
//! Child construction here mirrors the parent-internal `spawn_subagent`/`prepare_investigator`
//! paths (fresh read-only `Registry`, a child `Rollout` under `subagents/`, inherited route +
//! pricing, bounded delegation depth), but it takes an explicit [`KernelSpawnerContext`] instead of
//! a live parent `&mut self`. That is the "standalone child constructor" the workflow seam needs:
//! the existing child setup was only reachable mid-turn from inside a parent `Agent`, because it
//! emitted a durable `SubagentSpawned` event and parent UI events. This module drops exactly those
//! two parent-transcript side effects (there is no parent transcript to append to) and keeps
//! everything the child itself needs.
//!
//! Concurrency is bounded by the engine's Governor (one global permit pool), so this spawner bounds
//! nothing itself, per the trait contract.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use async_trait::async_trait;
use core_agents::AgentCatalog;
use core_obs::PricingPort;
use core_protocol::capability_set::CapabilitySet;
use core_protocol::slot::StrategySlot;
use core_protocol::{
    Budget, CostAttribution, Effort, PermissionMode, PermissionRules, RunId, TenantId,
};
use core_provider::Provider;
use core_record::Rollout;
use core_tools::Registry;
use core_workflow::{AgentActivityReporter, AgentCall, AgentOutcome, AgentSpawner};
use sha2::{Digest, Sha256};

use super::Agent;
use super::hooks::Hooks;
use super::pricing::SharedUsdBudget;

const MAX_AGENT_REFUSAL_BYTES: usize = 512;
const AGENT_REFUSAL_TRUNCATED: &str = " [truncated]";

mod activity;

/// One terminal/journal-safe refusal line. This is the final choke point for child setup and
/// runtime failures: redact credential shapes, render terminal controls visibly, and retain at
/// most 512 UTF-8 bytes. Request metadata is never deliberately interpolated by this module, but
/// this defense also covers OS/library diagnostics returned by later setup stages.
pub(crate) fn safe_agent_refusal(reason: &str) -> String {
    let scrubbed = core_record::redact::scrub(reason);
    let content_limit = MAX_AGENT_REFUSAL_BYTES.saturating_sub(AGENT_REFUSAL_TRUNCATED.len());
    let mut safe = String::with_capacity(scrubbed.len().min(MAX_AGENT_REFUSAL_BYTES));
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
        safe.push_str(AGENT_REFUSAL_TRUNCATED);
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
    /// Pure, injected pricing strategy. REQUIRED only if `budget.max_usd` is a positive ceiling; a
    /// child that cannot bind a verified rate card for a positive ceiling resolves to `Null`.
    pub pricing_port: Option<Arc<dyn PricingPort>>,
    /// One aggregate monetary ceiling shared by the parent and every workflow child. A child may
    /// tighten it; no child receives an independent refill.
    pub(super) usd_budget: Option<Arc<SharedUsdBudget>>,
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
    /// Per-child bounded-loop ceilings. The engine's Governor bounds CONCURRENCY; this bounds each
    /// child's turns/wall/usd. Defaults to `core_agents::subagent_budget_ceiling()`.
    pub budget: Budget,
    pub model_context_window: Option<u64>,
    pub model_max_output_tokens: Option<u32>,
    pub sensitive_env_names: Vec<String>,
    /// Pinned strategy/port set inherited by every child; child construction never falls back to
    /// a different policy generation.
    pub context_strategy: Arc<dyn StrategySlot>,
    pub tool_policy: Arc<dyn StrategySlot>,
    pub context_port: Arc<dyn core_ctx::ContextPort>,
    pub context_home_dir: Option<PathBuf>,
    /// Exact accepted definitions resolved once by the composition root. Every spawned worker
    /// inherits this same immutable set; it never performs filesystem discovery itself.
    pub agent_catalog: Arc<AgentCatalog>,
    /// Permission posture for the read-only child. Registry and capability ceilings independently
    /// prevent this from widening authority.
    pub permission_mode: PermissionMode,
    pub permission_rules: PermissionRules,
    pub authority_ceiling: CapabilitySet,
    pub policy_capabilities: CapabilitySet,
}

impl KernelSpawnerContext {
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
            core_protocol::Capability::ReadOnly,
            core_protocol::Capability::ReversibleLocal,
            core_protocol::Capability::CodeExecuting,
            core_protocol::Capability::TrustMutating,
            core_protocol::Capability::IrreversibleExternal,
        ]);
        KernelSpawnerContext {
            provider,
            model,
            provider_id,
            catalog_digest,
            capability_digest,
            pricing_port: None,
            usd_budget: None,
            workspace,
            runtime_state_dir,
            tenant,
            parent_run_id,
            workflow_id,
            default_effort: Effort::default(),
            budget: core_agents::subagent_budget_ceiling(),
            model_context_window: None,
            model_max_output_tokens: None,
            sensitive_env_names: Vec::new(),
            context_strategy: Arc::new(core_ctx::ContextStrategy::default()),
            tool_policy: Arc::new(core_tools::ToolPolicy::default()),
            context_port: Arc::new(core_ctx::DefaultContextPort),
            context_home_dir: None,
            agent_catalog: Arc::new(AgentCatalog::builtin_only()),
            permission_mode: PermissionMode::default(),
            permission_rules: PermissionRules::new(),
            authority_ceiling: all_capabilities,
            policy_capabilities: all_capabilities,
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

    /// Build the fully-wired, owned child. This is the standalone analogue of the parent-internal
    /// `prepare_investigator`/`spawn_subagent` child setup:
    ///   * a read-only `Registry` narrowed by the selected immutable `AgentDef`,
    ///   * a child `Rollout` under `runtime_state_dir/subagents/`,
    ///   * inherited route + pricing (public `record_model_selection` / `bind_selected_rate_card`),
    ///   * the same non-durable inherited context (workspace, model window, sensitive env,
    ///     cost attribution, bounded delegation depth),
    ///     minus the parent's durable `SubagentSpawned` + UI emission (no parent transcript exists).
    fn build_child(&self, call: &AgentCall, ordinal: u64) -> Result<Agent, String> {
        let cx = &self.cx;

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

        // A definition/call may request a model, but this spawner only owns evidence for the
        // parent's exact route. Refuse a different model instead of reusing the parent's catalog,
        // capability, or price digests under a false identity.
        if let (Some(call_model), Some(definition_model)) =
            (call.model.as_deref(), agent_def.model.as_deref())
            && call_model != definition_model
        {
            return Err(
                "agent definition model conflicts with the requested model override".into(),
            );
        }
        let requested_model = agent_def
            .model
            .as_deref()
            .or(call.model.as_deref())
            .unwrap_or(&cx.model);
        if requested_model != cx.model {
            return Err("requested agent model has no separately resolved route evidence".into());
        }

        let mut registry = Registry::read_only(cx.workspace.clone())
            .map_err(|_| "child read-only registry setup failed".to_string())?;
        let allowed_tools = agent_def.tools.narrow();
        let _effective_tools = registry.narrow_to(&allowed_tools);
        registry.set_sensitive_env_names(cx.sensitive_env_names.clone());

        let budget = intersect_budget(&cx.budget, &agent_def.budget)?;
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

        let mut sub = Agent::new(
            cx.provider.clone(),
            registry,
            rollout,
            cx.model.clone(),
            agent_def.system.clone(),
            budget.clone(),
        );

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
        if cx.usd_budget.is_some() {
            sub.usd_budget = cx.usd_budget.clone();
        }
        let read_only =
            CapabilitySet::from_iter_capabilities([core_protocol::Capability::ReadOnly]);
        sub.authority_ceiling = cx.authority_ceiling.intersect(read_only);
        sub.policy_capabilities = cx.policy_capabilities.intersect(read_only);
        sub.context_strategy = cx.context_strategy.clone();
        sub.tool_policy = cx.tool_policy.clone();
        sub.context_port = cx.context_port.clone();
        sub.context_home_dir = cx.context_home_dir.clone();
        // A workflow child is exactly one level below the operator. The read-only registry has no
        // dispatch/workflow tool; depth remains a second defense if that registry evolves.
        sub.delegation_depth = 1;

        // --- Public-surface inherited context ---
        sub.workspace = cx.workspace.clone();
        sub.model_context_window = cx.model_context_window;
        sub.model_max_output_tokens = cx.model_max_output_tokens;
        // Hooks are executable processes, so a read-only child cannot inherit them. Credential
        // names still propagate as deny metadata, never values.
        sub.hooks = Hooks::default();
        sub.bypass_permissions = false;
        sub.agent_catalog = cx.agent_catalog.clone();
        sub.agent_catalog_pinned = true;
        // Installs the deny-list on the agent, its hooks, and (already, above) its registry.
        sub.set_sensitive_env_names(cx.sensitive_env_names.clone());

        // --- Coherent fresh-run runtime policy, BEFORE any durable append (the rollout is still
        //     empty here; route recording below is the first event). A leaf never orchestrates, so
        //     `Ultracode` collapses to `Max` (max thinking budget, no fan). ---
        let effort = match call.effort.unwrap_or(cx.default_effort) {
            Effort::Ultracode => Effort::Max,
            other => other,
        };
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
            .unwrap_or(0);
        sub.record_genesis(
            cx.workspace.display().to_string(),
            created_at,
            cx.agent_catalog.execution_digest(),
            Some(agent_def.execution_tag()),
        )
        .map_err(|error| {
            safe_agent_refusal(&format!("child genesis failed: {}", error.public_summary()))
        })?;

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

#[async_trait]
impl AgentSpawner for KernelSpawner {
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
mod tests {
    use super::*;
    use core_protocol::{Capability, EventKind};
    use core_provider::{ProviderError, StreamItem, TurnRequest, TurnResult};
    use core_workflow::{
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
        let home = root.join("home");
        let repo = root.join("repo");
        std::fs::create_dir_all(home.join(".core/agents")).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            home.join(".core/agents/reviewer.md"),
            "---\nname: reviewer\ndescription: Narrow reviewer\ntools: [read_file]\n\
             maxTurns: 2\nmaxTokens: 41\nmaxWallSecs: 7\nmaxConsecutiveToolErrors: 1\n---\n\
             Review exactly one file and report evidence.\n",
        )
        .unwrap();
        AgentCatalog::discover(&home, &repo)
    }

    fn context(root: &std::path::Path, catalog: AgentCatalog) -> KernelSpawnerContext {
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
        assert!(!child.bypass_permissions);

        let events = core_record::replay(child.rollout.path()).unwrap();
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
        let oversized_name = "n".repeat(core_workflow::spawner::MAX_AGENT_TYPE_BYTES + 1);
        let oversized_model = "m".repeat(core_workflow::spawner::MAX_AGENT_MODEL_BYTES + 1);
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
        assert!(!root.join("runs/subagents").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn request_refusals_are_safe_across_null_journal_and_progress_surfaces() {
        let root = scratch("refusal-surfaces");
        let catalog = discovered_catalog(&root);
        let spawner = Arc::new(KernelSpawner::new(context(&root, catalog)));
        let sink = Arc::new(RecordingSink::default());
        let secret = "ghp_AbCdEf1234567890AbCdEf1234567890";
        let oversized_name = "n".repeat(core_workflow::spawner::MAX_AGENT_TYPE_BYTES + 1);
        let oversized_model = "m".repeat(core_workflow::spawner::MAX_AGENT_MODEL_BYTES + 1);
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
        assert!(!root.join("runs/subagents").exists());

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
