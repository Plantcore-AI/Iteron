//! Actual bounded script preparation. Host route/config/policy snapshots are immutable; the
//! journal owns decision receipts, while the engine/resident owns physical execution.
use super::controller_engine_children::ControllerEngineChildren;
use super::controller_engine_scope::ControllerEngineScope;
use super::{
    KernelSpawner, KernelSpawnerContext, apply_workflow_execution_policy, in_turn_workflow_budget,
    kernel_dispatch_journal::KernelDispatchJournal, policy_evidence, workflow_spawner,
};
use iteron_protocol::{Capability, PricingRoute, TurnId, capability_set::CapabilitySet};
use std::{path::PathBuf, sync::Arc};
const DEFAULT_WORKFLOW_BACKGROUND: bool = false;
const CLOCK_BEFORE_EPOCH_SECS: u64 = 0;

pub(super) struct WorkflowPreparation {
    pub(super) workspace: PathBuf,
    pub(super) context: KernelSpawnerContext,
    pub(super) route: PricingRoute,
    pub(super) admission: Result<(), String>,
    pub(super) remaining_turns: u32,
    pub(super) remaining_tokens: Option<u64>,
    pub(super) turn: TurnId,
    pub(super) workflows_dir: PathBuf,
    pub(super) profile: Option<Arc<iteron_tunables::ProfileDocument>>,
    pub(super) progress: Option<tokio::sync::mpsc::Sender<crate::workflow::WorkflowRunUiEvent>>,
    pub(super) controller: Option<ControllerEngineScope>,
}
pub(super) struct PreparedKernelWorkflow {
    pub(super) prepared: crate::workflow::PreparedWorkflow,
    pub(super) controller: Option<Arc<ControllerEngineChildren>>,
    pub(super) background_requested: bool,
    pub(super) native_ledgers:
        Arc<std::sync::Mutex<super::kernel_workflow_ledgers::KernelWorkflowLedgers>>,
}
impl WorkflowPreparation {
    pub(super) fn prepare(
        self,
        input: &serde_json::Value,
        resume_run_id: Option<&str>,
        journal: &mut KernelDispatchJournal<'_>,
    ) -> Result<PreparedKernelWorkflow, String> {
        let execution_policy = self.context.execution_policy;
        if execution_policy.task_priority
            != Some(iteron_workflow::TaskPrioritySchedulingPolicy::owner())
        {
            return Err(
                "Workflow: pinned task-priority policy differs from the physical ready queue"
                    .into(),
            );
        }
        self.admission?;
        // Resolve exactly one model-authored workflow source. Resume feeds the persisted script
        // through the same path, so a relaunched run retains identical program bytes.
        let inline = input
            .get("script")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let path = input
            .get("scriptPath")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let selector_count =
            usize::from(inline.is_some()).saturating_add(usize::from(path.is_some()));
        if selector_count != 1 {
            return Err(
                "Workflow: provide exactly one of `script` (inline ESM) or `scriptPath`".into(),
            );
        }
        let script = match (inline, path) {
            (Some(source), None) => {
                if source.len() > iteron_workflow::WORKFLOW_SUBMISSION_LIMITS.script_bytes {
                    return Err("Workflow: inline script exceeds its bounded source ceiling".into());
                }
                normalize_workflow_script(source)
            }
            (None, Some(rel)) => {
                let path = std::path::Path::new(rel);
                let relative = if path.is_absolute() {
                    path.strip_prefix(&self.workspace).map_err(|_| {
                        "Workflow: scriptPath is outside the admitted workspace".to_owned()
                    })?
                } else {
                    path
                };
                let source = iteron_tools::read_contained_utf8(
                    &self.workspace,
                    relative,
                    iteron_workflow::WORKFLOW_SUBMISSION_LIMITS.script_bytes,
                )
                .map_err(|_| {
                    "Workflow: scriptPath is unavailable within the bounded admitted workspace"
                        .to_owned()
                })?;
                normalize_workflow_script(&source)
            }
            _ => unreachable!("selector_count enforces one workflow source"),
        };
        iteron_workflow::validate_script(&script).map_err(|error| {
            format!(
                "Workflow: script rejected before launch: {error}. Fix the ESM and retry \
                 `Workflow` directly; no run started."
            )
        })?;
        let args_source = input.get("args");
        if let Some(value) = args_source {
            let mut counter = ArgsEnvelope {
                remaining: iteron_workflow::WORKFLOW_SUBMISSION_LIMITS.args_bytes,
            };
            serde_json::to_writer(&mut counter, value)
                .map_err(|_| "Workflow: args exceed the bounded serialized envelope".to_owned())?;
        }
        let args = args_source.cloned().unwrap_or(serde_json::Value::Null);
        // Detaching is explicit: omitted `background` keeps prerequisite evidence available to the
        // current turn. Only an installed owner can grant `background: true`; see
        // `crate::workflow::PreparedWorkflow::background`.
        let background_requested = input
            .get("background")
            .and_then(|value| value.as_bool())
            .unwrap_or(iteron_tunables::param_bool(
                "cli.runtime.workflow_prepare.default_workflow_background",
                DEFAULT_WORKFLOW_BACKGROUND,
            ));

        // Children re-record the parent's exact durable route byte-for-byte; a run before any route
        // selection cannot bind one.
        let route = self.route;
        // One parse: `extract_meta` spins up a QuickJS runtime, and the live tree wants the
        // DECLARED phases as well as the name so every phase box exists on the first frame.
        let meta = iteron_workflow::extract_meta(&script);
        let declared_phases = meta
            .as_ref()
            .and_then(|meta| meta.phases.clone())
            .unwrap_or_default();
        let workflow_name = meta
            .and_then(|meta| meta.name)
            .unwrap_or_else(|| "workflow".into());
        // Mint a fresh, time-ordered run id the way the standalone `iteron workflow run` path does.
        // Deriving it from the turn counter made every `Workflow` tool call in ONE assistant
        // response share an id — hence one journal, one child-rollout namespace, and a second call
        // that silently replayed the first's cached outcomes instead of running.
        let run_id = resume_run_id
            .map(str::to_owned)
            .unwrap_or_else(|| iteron_workflow::RunId::generate().to_string());
        let workflows_dir = self.workflows_dir;

        let mut cx = self.context;
        cx.workflow_id = run_id.clone();

        let remaining_turns = self.remaining_turns;
        if remaining_turns == 0 {
            return Err("Workflow: parent turn budget is exhausted".into());
        }
        cx.budget.max_turns = cx.budget.max_turns.min(remaining_turns).max(1);
        // The same soft halving `iteron_agents::subagent_budget` gives a general workflow child.
        cx.budget.max_tokens = self
            .remaining_tokens
            .map(|remaining| execution_policy.fan_token_share.floor_u64(remaining))
            .map(|tokens| {
                execution_policy
                    .workflow
                    .max_tokens
                    .map_or(tokens, |ceiling| tokens.min(ceiling))
            });
        cx.budget.max_wall_secs = cx
            .budget
            .max_wall_secs
            .min(execution_policy.workflow.max_wall_seconds);
        let kernel_limits = in_turn_workflow_budget(execution_policy)
            .map_err(|error| format!("Workflow: invalid kernel aggregate budget: {error}"))?;
        let baseline_engine_limits = iteron_workflow::RunLimits::new(
            kernel_limits.max_concurrency().min(1000),
            kernel_limits.max_agent_calls().min(1000),
        )
        .map_err(|error| format!("Workflow: invalid engine aggregate budget: {error}"))?;
        let mut baseline_engine_limits =
            workflow_spawner::governed_workflow_limits(&cx.budget, baseline_engine_limits)
                .map_err(|error| format!("Workflow: invalid priced engine budget: {error}"))?;
        let bounded_native = self.controller.is_none()
            && (self.remaining_turns != iteron_protocol::Budget::UNLIMITED_TURNS
                || self.remaining_tokens.is_some());
        if bounded_native {
            let calls = if self.remaining_turns == iteron_protocol::Budget::UNLIMITED_TURNS {
                baseline_engine_limits.max_agent_calls()
            } else {
                let aggregate_turns = self
                    .remaining_turns
                    .saturating_sub(execution_policy.admission.minimum_remaining_turns.max(1));
                if aggregate_turns == 0 {
                    return Err("Workflow: writer reserve leaves no child turn".into());
                }
                baseline_engine_limits
                    .max_agent_calls()
                    .min(aggregate_turns as usize)
            };
            baseline_engine_limits = iteron_workflow::RunLimits::new(
                baseline_engine_limits.max_concurrency().min(calls),
                calls,
            )
            .map_err(str::to_owned)?;
            let mut slice = cx.budget.clone();
            if self.remaining_turns != iteron_protocol::Budget::UNLIMITED_TURNS {
                slice.max_turns = slice.max_turns.min(
                    self.remaining_turns
                        .saturating_sub(execution_policy.admission.minimum_remaining_turns.max(1))
                        / (calls as u32),
                );
            }
            slice.max_tokens = slice.max_tokens.map(|tokens| tokens / (calls as u64));
            if slice.max_turns == 0 || slice.max_tokens == Some(0) {
                return Err(
                    "Workflow: bounded aggregate leaves no per-child request budget".into(),
                );
            }
            cx.budget_slices = Some(vec![slice; calls]);
        }
        let positive_usd_serialized = cx
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing());
        let collaboration_observation = iteron_workflow::CollaborationObservation {
            version: iteron_workflow::COLLABORATION_SLOT_VERSION,
            active_workers: baseline_engine_limits.max_agent_calls(),
            max_concurrency: baseline_engine_limits.max_concurrency(),
        };
        let collaboration_opportunity = journal
            .begin_policy_decision(policy_evidence::COLLABORATION_SLOT, Some(self.turn))
            .map_err(|error| error.public_summary())?;
        let selected_concurrency = match iteron_workflow::CollaborationStrategy::select_with(
            cx.compiled_policy_bundle.slots().collaboration.as_ref(),
            &collaboration_observation,
            CapabilitySet::only(Capability::ReadOnly).intersect(cx.authority_ceiling),
        ) {
            Ok(proposal) => {
                let selected_action = if proposal.concurrency == 1 {
                    iteron_protocol::PolicyActionV1::CollaborationSerial
                } else {
                    iteron_protocol::PolicyActionV1::CollaborationBoundedWidth
                };
                journal.append_policy_decision(
                    collaboration_opportunity,
                    policy_evidence::PolicyDecisionDraft::selected(
                        policy_evidence::COLLABORATION_SLOT,
                        &[
                            iteron_protocol::PolicyActionV1::CollaborationBoundedWidth,
                            iteron_protocol::PolicyActionV1::CollaborationSerial,
                        ],
                        selected_action,
                        "iteron:collaboration-features-v1",
                        &(
                            &collaboration_observation,
                            proposal.concurrency,
                            positive_usd_serialized,
                        ),
                        &if positive_usd_serialized {
                            "positive_usd_uses_one_provider_lane_so_a_parallel_batch_cannot_consume_the_remaining_ceiling"
                        } else {
                            "strategy_may_only_narrow_worker_concurrency"
                        },
                    )
                    .map_err(|error| error.public_summary())?,
                )
                .map_err(|error| error.public_summary())?;
                proposal.concurrency
            }
            Err(_) => {
                journal
                    .append_policy_decision(
                        collaboration_opportunity,
                        policy_evidence::PolicyDecisionDraft::baseline_fallback(
                            policy_evidence::COLLABORATION_SLOT,
                            &[
                                iteron_protocol::PolicyActionV1::CollaborationBoundedWidth,
                                iteron_protocol::PolicyActionV1::CollaborationSerial,
                            ],
                            "iteron:collaboration-features-v1",
                            &collaboration_observation,
                            &"strategy_refusal_falls_back_to_serial",
                        )
                        .map_err(|error| error.public_summary())?,
                    )
                    .map_err(|error| error.public_summary())?;
                1
            }
        };
        let engine_limits = iteron_workflow::RunLimits::new(
            selected_concurrency,
            baseline_engine_limits.max_agent_calls(),
        )
        .map_err(|error| format!("Workflow: invalid collaboration budget: {error}"))?;
        let native_ledgers = Arc::new(std::sync::Mutex::new(
            super::kernel_workflow_ledgers::KernelWorkflowLedgers::default(),
        ));
        cx.kernel_workflow_ledgers = Some(native_ledgers.clone());
        let controller = self
            .controller
            .map(|scope| scope.children(&cx, &run_id))
            .transpose()?;
        let spawner: Arc<dyn iteron_workflow::AgentSpawner> = match &controller {
            Some(children) => children.clone(),
            None => Arc::new(KernelSpawner::new(cx)),
        };

        let mut spec = apply_workflow_execution_policy(
            iteron_workflow::RunSpec::new(script.clone())
                .with_args(args.clone())
                .with_run_id(iteron_workflow::RunId::new(run_id.clone()))
                .with_workflows_dir(workflows_dir.clone())
                .with_limits(engine_limits)
                // Prompt artifacts only. With no profile this is `None` and the engine keeps every
                // compiled string.
                .with_tunables_profile(self.profile),
            execution_policy,
        );
        if resume_run_id.is_some() {
            spec = spec.with_resume_from(iteron_workflow::RunId::new(run_id.clone()));
        }
        // A degraded agent resolves to JS `null` and the script's `.filter(Boolean)` deletes it, so
        // a discarded sink turned an exhausted budget into a plausibly-short result. Keep the
        // reasons and hand them to the model with the value.
        let degraded = std::sync::Arc::new(crate::workflow::DegradedAgentSink::new());
        // ADR-0001 step 1: the same events also drive the operator's live phase→agent tree when a
        // frontend installed the progress seam. Both sinks are needed at once and the engine takes
        // exactly one, so they are fanned out; with no frontend attached this is the degraded sink
        // alone, byte-for-byte the previous behavior.
        let sink = crate::workflow::in_turn_progress_sink(degraded.clone(), &run_id, self.progress);

        // Persist the re-launchable inputs BEFORE the run starts, exactly like the standalone path:
        // the kernel writes its journal into the very directory `iteron workflow list` enumerates, so
        // without the manifest every model-launched run listed forever as unnamed, model-less and
        // `running`.
        if resume_run_id.is_none()
            && let Err(error) = crate::workflow::persist_inputs(
                &workflows_dir,
                &crate::workflow::RunManifest {
                    run_id: run_id.clone(),
                    name: workflow_name.clone(),
                    args,
                    provider_id: route.provider_id.clone(),
                    model: route.model_id.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|elapsed| elapsed.as_secs())
                        .unwrap_or(iteron_tunables::param_integer(
                            "cli.runtime.workflow_prepare.clock_before_epoch_secs",
                            CLOCK_BEFORE_EPOCH_SECS,
                        )),
                },
                &script,
            )
        {
            return Err(format!("Workflow: cannot persist run inputs: {error}"));
        }

        Ok(PreparedKernelWorkflow {
            controller,
            background_requested,
            native_ledgers,
            prepared: crate::workflow::PreparedWorkflow {
                run_id,
                name: workflow_name,
                declared_phases,
                workflows_dir,
                spec,
                spawner,
                sink,
                degraded,
                background: background_requested && !bounded_native,
            },
        })
    }
}

pub(super) fn normalize_workflow_script(source: &str) -> String {
    let trimmed = source.trim();
    let Some(first_newline) = trimmed.find('\n') else {
        return source.to_owned();
    };
    let opening = &trimmed[..first_newline];
    if !opening.starts_with("```") || opening[3..].contains('`') {
        return source.to_owned();
    }
    let body_and_fence = &trimmed[first_newline + 1..];
    let Some(last_newline) = body_and_fence.rfind('\n') else {
        return source.to_owned();
    };
    if body_and_fence[last_newline + 1..].trim() != "```" {
        return source.to_owned();
    }
    body_and_fence[..last_newline].to_owned()
}

struct ArgsEnvelope {
    remaining: usize,
}
impl std::io::Write for ArgsEnvelope {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("bounded workflow args"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
