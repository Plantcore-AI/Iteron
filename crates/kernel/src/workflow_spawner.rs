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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use core_agents::AgentDef;
use core_obs::PricingPort;
use core_protocol::{
    Budget, CostAttribution, Effort, PermissionMode, PermissionRules, RunId, TenantId,
};
use core_provider::Provider;
use core_record::Rollout;
use core_tools::Registry;
use core_workflow::{AgentCall, AgentOutcome, AgentSpawner};
use sha2::{Digest, Sha256};

use crate::hooks::Hooks;
use crate::{Agent, usage_tokens};

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
    /// Trusted lifecycle hooks (resolved once at the composition root). Children inherit this exact
    /// value; they never re-read ambient/repository config.
    pub hooks: Hooks,
    /// The child system prompt. Defaults to `AgentDef::generic().system` (the read-only investigator
    /// prompt); the read-only registry, not the prompt, is what enforces the single-writer
    /// invariant. A writer child (see `agent_type`) should be given a writer-appropriate prompt.
    pub system: String,
    /// Permission posture for a WRITER child (a read-only child has no effecting tools to gate).
    pub permission_mode: PermissionMode,
    pub permission_rules: PermissionRules,
    /// Dangerous internal-edition bypass. A WRITER child in a non-interactive workflow otherwise
    /// fails closed on its first `Ask` (there is no approvals channel). Ignored by read-only
    /// children (they have nothing above `ReadOnly` to gate).
    pub bypass_permissions: bool,
    pub allow_tainted_egress: bool,
}

impl KernelSpawnerContext {
    /// The minimal context: the identity/route/paths that have no sensible default, with everything
    /// else defaulted (generic read-only system prompt, `subagent_budget_ceiling()` budget,
    /// `Default` effort/mode, empty hooks/env, no pricing, no shared stop flags). Set the remaining
    /// `pub` fields directly for anything the run needs (pricing, USD ceiling, writer permissions).
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
        KernelSpawnerContext {
            provider,
            model,
            provider_id,
            catalog_digest,
            capability_digest,
            pricing_port: None,
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
            hooks: Hooks::default(),
            system: AgentDef::generic().system,
            permission_mode: PermissionMode::default(),
            permission_rules: PermissionRules::new(),
            bypass_permissions: false,
            allow_tainted_egress: false,
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
    ///   * a read-only `Registry` by default (writer only if `agent_type == "writer"`),
    ///   * a child `Rollout` under `runtime_state_dir/subagents/`,
    ///   * inherited route + pricing (public `record_model_selection` / `bind_selected_rate_card`),
    ///   * the same non-durable inherited context (workspace, model window, hooks, sensitive env,
    ///     cost attribution, bounded delegation depth),
    ///     minus the parent's durable `SubagentSpawned` + UI emission (no parent transcript exists).
    fn build_child(&self, call: &AgentCall, ordinal: u64) -> Result<Agent, String> {
        let cx = &self.cx;

        // Read-only by default (single-writer invariant, ADR-001). A writer is opt-in via an
        // explicit `agent_type: "writer"`; it gets the full coding tool set. Delegation depth (set
        // below) bounds any further recursion its dispatch/workflow tools might attempt.
        let wants_writer = call
            .agent_type
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("writer"));
        let mut registry = if wants_writer {
            Registry::coding_agent(cx.workspace.clone())
                .map_err(|error| format!("child registry setup failed: {error}"))?
        } else {
            Registry::read_only(cx.workspace.clone())
                .map_err(|error| format!("child registry setup failed: {error}"))?
        };
        registry.set_sensitive_env_names(cx.sensitive_env_names.clone());

        let sub_run = self.mint_run_id(ordinal);
        let subagents_dir = cx.runtime_state_dir.join("subagents");
        let rollout = Rollout::open(&subagents_dir, &sub_run, cx.tenant.clone())
            .map_err(|error| format!("child rollout could not be opened: {error}"))?;

        let model = call.model.clone().unwrap_or_else(|| cx.model.clone());
        let mut sub = Agent::new(
            cx.provider.clone(),
            registry,
            rollout,
            model,
            cx.system.clone(),
            cx.budget.clone(),
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
        // A workflow child is exactly one level below the operator. `MAX_DELEGATION_DEPTH` then
        // refuses any deeper dispatch/workflow a writer child might attempt (defense in depth
        // beside the read-only registry's absence of those tools).
        sub.delegation_depth = 1;

        // --- Public-surface inherited context ---
        sub.workspace = cx.workspace.clone();
        sub.model_context_window = cx.model_context_window;
        sub.model_max_output_tokens = cx.model_max_output_tokens;
        sub.hooks = cx.hooks.clone();
        sub.allow_tainted_egress = cx.allow_tainted_egress;
        sub.bypass_permissions = cx.bypass_permissions;
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
        .map_err(|error| format!("child runtime policy rejected: {}", error.public_summary()))?;

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
        .map_err(|error| format!("child route selection failed: {}", error.public_summary()))?;
        if cx.pricing_port.is_some() {
            let bound = sub.bind_selected_rate_card().map_err(|error| {
                format!("child pricing bind failed: {}", error.public_summary())
            })?;
            if cx.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) && !bound {
                return Err("child could not bind a verified rate card for its USD ceiling".into());
            }
        }

        Ok(sub)
    }
}

#[async_trait]
impl AgentSpawner for KernelSpawner {
    async fn spawn(&self, call: AgentCall) -> AgentOutcome {
        let ordinal = self.next_ordinal.fetch_add(1, Ordering::Relaxed);
        let mut child = match self.build_child(&call, ordinal) {
            Ok(child) => child,
            Err(reason) => {
                return AgentOutcome::Null {
                    reason: Some(reason),
                };
            }
        };

        // Cooperate with the run's cancellation token (trait §B3): bridge it onto the child's
        // cooperative interrupt flag, which `run_leaf` polls at every turn-atomic safe point. A
        // cancelled run then stops the child cleanly (durable safe point) rather than relying solely
        // on the engine's hard task-abort backstop — this matters for a writer child mid-effect.
        let interrupt = Arc::new(AtomicBool::new(false));
        child.set_interrupt(interrupt.clone());
        let cancel = call.cancel.clone();
        let cancel_bridge = tokio::spawn(async move {
            cancel.cancelled().await;
            interrupt.store(true, Ordering::SeqCst);
        });

        // `run_leaf` (not `run`): a leaf owns its context and tool loop but never orchestrates, so
        // its future is `Send + 'static` — exactly what lets the engine `tokio::spawn` this.
        let outcome = child.run_leaf(&call.prompt).await;
        cancel_bridge.abort();
        match outcome {
            // Any terminal with a non-empty final report becomes the JS string value (real model
            // output). This mirrors the kernel's own investigator distillation, which treats every
            // `Ok(_)` outcome as carrying a report and only degrades on an empty one.
            Ok(_terminal) => {
                let text = child.last_assistant_text().trim().to_string();
                if text.is_empty() {
                    AgentOutcome::Null {
                        reason: Some("subagent completed without a report".into()),
                    }
                } else {
                    AgentOutcome::Text {
                        text,
                        tokens: usage_tokens(&child.ledger.usage),
                        tool_calls: child.ledger.tool_calls,
                        // The kernel tracks no per-tool human summary; `tool_calls` is the count.
                        last_tool_summary: None,
                    }
                }
            }
            // A harness/provider/budget error resolves to JS `null` (never a thrown rejection) so a
            // surrounding `parallel`/`pipeline` keeps its other items flowing.
            Err(error) => AgentOutcome::Null {
                reason: Some(error.public_summary()),
            },
        }
    }
}
