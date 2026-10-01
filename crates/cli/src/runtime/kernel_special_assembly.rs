//! Freeze actual current host sources, then hand disjoint owners to special execution.
use super::context_runtime::TurnResultProjectionBudget;
use super::controller_engine_scope::ControllerEngineScope;
use super::direct_child_execution::{DirectChildExecution, DirectChildWork};
use super::hook_execution::HookExecutionScope;
use super::kernel_dispatch_control::KernelDispatchControl;
use super::kernel_dispatch_journal::{KernelDispatchJournal, KernelPolicyBootstrap};
use super::kernel_special_execution::{
    KernelDispatchWork, KernelSpecialExecution, KernelSpecialKind,
};
use super::kernel_tool_call::{KernelOutputProjection, KernelToolOutputScope};
use super::workflow_execution::{WorkflowExecution, WorkflowProgressProjection};
use super::workflow_preparation::WorkflowPreparation;
use super::workflow_spawner::direct::DirectChildIdentity;
use super::{Agent, KernelError, MAX_DELEGATION_DEPTH};
use iteron_protocol::TurnId;
use std::time::Instant;

impl Agent {
    pub(super) fn kernel_controller_scope(
        &mut self,
        turn: TurnId,
        deadline: Instant,
    ) -> Result<Option<ControllerEngineScope>, String> {
        let host = if let Some(control) = &self.persistent_agents {
            let root = control
                .host_limits()
                .map_err(|_| "controller root identity unavailable")?
                .root
                .agent_id;
            Some((control.clone(), root))
        } else if let Some(mailbox) = &self.persistent_mailbox {
            mailbox
                .child_controller()
                .map_err(|_| "exact child controller identity unavailable")?
        } else {
            None
        };
        if let Some((control, parent)) = &host {
            self.publish_current_native_context(control, *parent, turn)
                .map_err(|error| error.public_summary())?;
        }
        Ok(host.map(|(control, parent)| ControllerEngineScope {
            control,
            parent,
            deadline,
            spawn_ledger: self.session_spawn_ledger.clone(),
            parent_source: iteron_agents::AgentEngineParentSource {
                tenant: self.rollout.tenant().0.clone(),
                run: self.rollout.run_id().0.clone(),
                provider_scope_sha256: self.provider_scope(),
            },
        }))
    }
    pub(super) fn kernel_workflow_preparation(
        &mut self,
        turn: TurnId,
    ) -> Result<WorkflowPreparation, String> {
        let admission = self
            .validate_workflow_graph_identity()
            .map_err(|error| error.public_summary())
            .and_then(|()| {
                if self.delegation_depth
                    >= iteron_tunables::param_integer(
                        "cli.runtime.max_delegation_depth",
                        MAX_DELEGATION_DEPTH,
                    )
                {
                    Err(KernelError::DelegationDepthExceeded.public_summary())
                } else {
                    Ok(())
                }
            });
        let route = self
            .provider_selection
            .selected()
            .map(|selected| selected.route.clone())
            .ok_or("Workflow: no model route is selected yet")?;
        let mut context = self.kernel_spawner_context(&route, "pending-workflow");
        let deadline = self.child_run_deadline(&context.budget);
        context.execution_deadline = Some(deadline);
        Ok(WorkflowPreparation {
            workspace: self.workspace.clone(),
            context,
            route,
            admission,
            remaining_turns: self.remaining_inference_turns(),
            remaining_tokens: self.remaining_provider_tokens(),
            turn,
            workflows_dir: self.runtime_state_dir.join("subagents").join("workflows"),
            profile: self.tunables_profile(),
            progress: self.workflow_progress_tx.clone(),
            controller: self.kernel_controller_scope(turn, deadline)?,
        })
    }
    fn kernel_direct_work(
        &mut self,
        turn: TurnId,
        index: usize,
    ) -> Result<DirectChildWork, String> {
        if self.delegation_depth
            >= iteron_tunables::param_integer(
                "cli.runtime.max_delegation_depth",
                MAX_DELEGATION_DEPTH,
            )
        {
            return Err(KernelError::DelegationDepthExceeded.public_summary());
        }
        if let Some(reason) = self
            .inference_budget_exhaustion()
            .map_err(|error| error.public_summary())?
        {
            return Err(format!(
                "subagent was not started: parent inference budget exhausted ({reason})"
            ));
        }
        let remaining_wall = self
            .run_time_remaining()
            .map(|duration| duration.as_secs().max(1))
            .unwrap_or(300);
        let turns = self.remaining_inference_turns();
        if turns < self.execution_policy.admission.minimum_remaining_turns
            || remaining_wall
                < self
                    .execution_policy
                    .admission
                    .minimum_remaining_wall_seconds
            || self.run_deadline_exhausted()
        {
            return Err(
                "subagent was not started: pinned child-admission floor is not satisfied".into(),
            );
        }
        let budget =
            iteron_agents::subagent_budget(turns, remaining_wall, self.remaining_provider_tokens())
                .ok_or(
                    "subagent was not started: writer-first reserve left no safe child budget",
                )?;
        let budget = self
            .execution_policy
            .direct_child_allocation
            .allocate(
                turns,
                remaining_wall,
                self.remaining_provider_tokens(),
                &budget,
            )
            .ok_or("subagent was not started: writer-first reserve left no safe child budget")?;
        let route = self
            .provider_selection
            .selected()
            .map(|selected| selected.route.clone())
            .ok_or("subagent has no admitted native route")?;
        let run = self.subagent_run_id("direct", turn.0, index);
        let deadline = self.child_run_deadline(&budget);
        let mut context = self.kernel_spawner_context(&route, &run.0);
        context.budget = budget;
        context.default_effort = self.execution_policy.subagent_effort;
        context.execution_deadline = Some(deadline);
        if let Some(scope) = self.kernel_controller_scope(turn, deadline)? {
            return scope
                .children(&context, &run.0)
                .map(DirectChildWork::Controller);
        }
        Ok(DirectChildWork::Native {
            context,
            identity: DirectChildIdentity {
                run,
                directory: self.subagent_directory(),
                depth: self
                    .delegation_depth
                    .checked_add(1)
                    .ok_or("child depth overflow")?,
                effort: self.execution_policy.subagent_effort,
                deadline,
                diagnostics: self.diagnostics.clone(),
            },
        })
    }
    pub(super) fn kernel_special_execution(
        &mut self,
        turn: TurnId,
        index: usize,
        kind: KernelSpecialKind,
        projection: TurnResultProjectionBudget,
    ) -> (KernelSpecialExecution<'_>, KernelToolOutputScope) {
        let events = self.tool_events(turn);
        let output = KernelToolOutputScope {
            events: events.clone(),
            publication: self.tool_output_publication_factory(),
            spill: if matches!(
                kind,
                KernelSpecialKind::Direct | KernelSpecialKind::Workflow
            ) {
                self.ordinary_tool_spill_store(if kind == KernelSpecialKind::Direct {
                    iteron_tools::DISPATCH_AGENT
                } else {
                    iteron_tools::WORKFLOW_TOOL
                })
            } else {
                None
            },
            projection: if matches!(
                kind,
                KernelSpecialKind::Direct | KernelSpecialKind::Workflow
            ) {
                KernelOutputProjection::Bounded(projection)
            } else {
                KernelOutputProjection::Inline
            },
        };
        let work = match kind {
            KernelSpecialKind::Plan => KernelDispatchWork::Plan,
            KernelSpecialKind::Direct => KernelDispatchWork::Direct(DirectChildExecution {
                work: self
                    .kernel_direct_work(turn, index)
                    .unwrap_or_else(DirectChildWork::Refused),
            }),
            KernelSpecialKind::Workflow => {
                let preparation = self.kernel_workflow_preparation(turn);
                KernelDispatchWork::Workflow(WorkflowExecution {
                    deadline: self.run_deadline.current(),
                    preparation,
                    launcher: self.workflow_launcher.clone(),
                    progress: WorkflowProgressProjection {
                        sender: self.workflow_progress_tx.clone(),
                        frontend: self.frontend_saturation.clone(),
                        events: events.clone(),
                    },
                })
            }
            #[cfg(feature = "legacy-plantcore")]
            KernelSpecialKind::Artifact => KernelDispatchWork::Artifact,
        };
        let bootstrap = if self.policy_evidence.is_none() {
            self.tunables_pin.as_ref().map(|pin| KernelPolicyBootstrap {
                digest: pin.resolution_digest_sha256().to_owned(),
                bindings: self.policy_runtime_bindings().to_vec(),
            })
        } else {
            None
        };
        let hooks = HookExecutionScope {
            turn,
            workspace: &self.workspace,
            hooks: &self.hooks,
            command_journal: self.hook_effect_journal.clone(),
            interrupt: self.control.interrupt().cloned(),
            drain: self.control.drain().clone(),
            activity: self.activity.clone(),
            emitter: self.lifecycle_emitter.clone(),
            dispatcher: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        (
            KernelSpecialExecution {
                work,
                journal: KernelDispatchJournal {
                    workspace: &self.workspace,
                    rollout: &mut self.rollout,
                    ledger: &mut self.ledger,
                    effects: &mut self.effect_journal,
                    record_failed: &mut self.record_failed,
                    diagnostics: &self.diagnostics,
                    money: self.usd_budget.clone(),
                    policy: &mut self.policy_evidence,
                    bootstrap,
                    #[cfg(test)]
                    fault: &mut self.fail_next_durable_append,
                },
                failed_actions: &mut self.failed_actions,
                control: KernelDispatchControl {
                    inbox: &mut self.inbox,
                    control: &mut self.control,
                    force_cancel: self.force_cancel_seam.as_mut(),
                    events,
                },
                plan: &mut self.task_plan,
                hooks,
                #[cfg(feature = "legacy-plantcore")]
                artifact: &mut self.plantcore,
            },
            output,
        )
    }
    // Existing external prepare/resume callers receive the same concrete preparation path.
    pub(super) fn prepare_kernel_workflow(
        &mut self,
        input: &serde_json::Value,
        resume: Option<&str>,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        let turn = TurnId(self.seq_turn);
        let preparation = self.kernel_workflow_preparation(turn)?;
        let bootstrap = if self.policy_evidence.is_none() {
            self.tunables_pin.as_ref().map(|pin| KernelPolicyBootstrap {
                digest: pin.resolution_digest_sha256().to_owned(),
                bindings: self.policy_runtime_bindings().to_vec(),
            })
        } else {
            None
        };
        let mut journal = KernelDispatchJournal {
            workspace: &self.workspace,
            rollout: &mut self.rollout,
            ledger: &mut self.ledger,
            effects: &mut self.effect_journal,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            money: self.usd_budget.clone(),
            policy: &mut self.policy_evidence,
            bootstrap,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
        };
        preparation
            .prepare(input, resume, &mut journal)
            .map(|prepared| prepared.prepared)
    }
}
