//! App-server control-plane handlers.

use super::*;

pub(super) fn is_immediate_control(control: &Control) -> bool {
    if let Control::PersistentAgents(command) = control {
        return !command.is_enable();
    }
    matches!(
        control,
        Control::OrdinaryExtensions(_)
            | Control::PluginManagement(_)
            | Control::ActivityCenter(_)
            | Control::OperatorStatus
            | Control::Inventory(_)
            | Control::ProviderCatalog(_)
            | Control::TranscriptExport(_)
            | Control::LiveWorkflow(_)
            | Control::Workflow(WorkflowControl::Inventory | WorkflowControl::Cancel { .. })
            | Control::Job(_)
            | Control::Mcp(_)
    )
}

pub(super) fn is_plantcore_admitted_control(control: &Control) -> bool {
    matches!(
        control,
        Control::PlantcoreRunBootstrapV1(_) | Control::OperatorStatus
    )
}

fn workflow_inventory_reply(
    workflows: &crate::workflow::WorkflowSupervisor,
    notice: Option<String>,
) -> ControlReply {
    ControlReply::Workflows(Box::new(WorkflowControlReply {
        runs: workflows.inventory(),
        notice,
    }))
}

pub(super) fn apply_immediate_workflow_control(
    workflows: &crate::workflow::WorkflowSupervisor,
    request: ControlRequest,
) {
    let reply = match request.control {
        Control::Workflow(WorkflowControl::Inventory) => workflow_inventory_reply(workflows, None),
        Control::Workflow(WorkflowControl::Cancel { run_id }) => {
            let notice = match workflows.cancel_for_operator(&run_id) {
                Ok(_) => format!("stopping workflow `{run_id}` at the engine's next safe point"),
                Err(error) => error,
            };
            workflow_inventory_reply(workflows, Some(notice))
        }
        _ => ControlReply::Refused(
            "this workflow control needs the resident runtime and cannot run mid-turn".into(),
        ),
    };
    let _ = request.reply.send(reply);
}

async fn apply_job_control(
    processes: Option<&iteron_tools::ProcessControl>,
    events: &EventPublisher,
    control: JobControl,
) -> ControlReply {
    let Some(processes) = processes else {
        return ControlReply::Refused("this runtime has no background-process supervisor".into());
    };
    let result = match control {
        JobControl::Inventory => processes.list(),
        JobControl::Clean => processes.clean().await,
        JobControl::Attach {
            job_id,
            stdout_cursor,
            stderr_cursor,
        } => {
            let result = processes
                .poll(&job_id, stdout_cursor, stderr_cursor, 0)
                .await;
            if result.is_ok() {
                events.record_job_lifecycle(
                    "background.attached",
                    &job_id,
                    LifecyclePayload::default(),
                );
            }
            result
        }
        JobControl::Write { job_id, input, eof } => {
            let bytes = u64::try_from(input.len()).unwrap_or(u64::MAX);
            let result = processes.write(&job_id, input, eof).await;
            if result.is_ok() {
                events.record_job_lifecycle(
                    "background.input_written",
                    &job_id,
                    LifecyclePayload {
                        magnitude: Some(bytes),
                        ..LifecyclePayload::default()
                    },
                );
            }
            result
        }
        JobControl::Stop { job_id } => processes.stop(&job_id).await,
    };
    match result {
        Ok(value) => ControlReply::Jobs(value),
        Err(error) => ControlReply::Refused(if error.unknown {
            format!("job control outcome is unknown: {}", error.message)
        } else {
            error.message
        }),
    }
}

async fn apply_memory_control(agent: &mut Agent, control: MemoryControl) -> ControlReply {
    let Some((workspace, memory_strategy, turn)) = agent.memory_control_context() else {
        return ControlReply::Refused("memory is not available in this session".into());
    };
    match control {
        MemoryControl::Add(text) => {
            let report = match agent
                .brokered_lifecycle_gate(
                    turn,
                    "memory.fact.add_requested",
                    LifecyclePayload {
                        magnitude: Some(u64::try_from(text.len()).unwrap_or(u64::MAX)),
                        ..LifecyclePayload::default()
                    },
                )
                .await
            {
                Ok(report) => report,
                Err(error) => return ControlReply::Refused(error.public_summary()),
            };
            if let crate::runtime::hooks::HookDecision::Deny(reason) = report.decision {
                return ControlReply::Refused(reason);
            }
            let proposal = match iteron_ctx::MemoryRecallStrategy::authorize_project_write_with(
                memory_strategy.as_ref(),
                &text,
                iteron_protocol::capability_set::CapabilitySet::only(Capability::TrustMutating),
            ) {
                Ok(proposal) => proposal,
                Err(error) => {
                    agent.lifecycle_event(
                        "memory.fact.add_failed",
                        Some(turn),
                        LifecyclePayload {
                            reason_code: Some("policy_refused".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    return ControlReply::Refused(format!("memory policy refused: {error}"));
                }
            };
            match iteron_ctx::MemoryStore::at(&workspace).add(&proposal.text) {
                Ok(id) => {
                    agent.lifecycle_event(
                        "memory.fact.added",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    agent.lifecycle_event(
                        "memory.visibility.scheduled",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    match agent.activate_session_memory(&id, &proposal.text) {
                        Ok(()) => ControlReply::Memory(MemoryControlReply::Added { id }),
                        Err(reason) => {
                            agent.lifecycle_event(
                                "memory.recall.unused",
                                Some(turn),
                                LifecyclePayload {
                                    reason_code: Some("session_refresh_queue_full".into()),
                                    ..LifecyclePayload::default()
                                },
                            );
                            ControlReply::Refused(format!(
                                "memory was stored, but same-session activation failed: {reason}"
                            ))
                        }
                    }
                }
                Err(error) => {
                    agent.lifecycle_event(
                        "memory.fact.add_failed",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    ControlReply::Refused(format!("memory add failed: {error}"))
                }
            }
        }
        MemoryControl::Update { id, text } => {
            let report = match agent
                .brokered_lifecycle_gate(
                    turn,
                    "memory.fact.update_requested",
                    LifecyclePayload {
                        magnitude: Some(u64::try_from(text.len()).unwrap_or(u64::MAX)),
                        ..LifecyclePayload::default()
                    },
                )
                .await
            {
                Ok(report) => report,
                Err(error) => return ControlReply::Refused(error.public_summary()),
            };
            if let crate::runtime::hooks::HookDecision::Deny(reason) = report.decision {
                return ControlReply::Refused(reason);
            }
            let proposal = match iteron_ctx::MemoryRecallStrategy::authorize_project_write_with(
                memory_strategy.as_ref(),
                &text,
                iteron_protocol::capability_set::CapabilitySet::only(Capability::TrustMutating),
            ) {
                Ok(proposal) => proposal,
                Err(error) => {
                    return ControlReply::Refused(format!("memory policy refused: {error}"));
                }
            };
            match iteron_ctx::MemoryStore::at(&workspace).update(&id, &proposal.text) {
                Ok(Some(new_id)) => {
                    agent.lifecycle_event(
                        "memory.fact.updated",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    if new_id != id {
                        agent.lifecycle_event(
                            "memory.fact.superseded",
                            Some(turn),
                            LifecyclePayload::default(),
                        );
                    }
                    agent.lifecycle_event(
                        "memory.visibility.scheduled",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    match agent.activate_updated_session_memory(&id, &new_id, &proposal.text) {
                        Ok(()) => ControlReply::Memory(MemoryControlReply::Updated {
                            old_id: id,
                            id: new_id,
                        }),
                        Err(reason) => ControlReply::Refused(format!(
                            "memory was updated, but same-session activation failed: {reason}"
                        )),
                    }
                }
                Ok(None) => ControlReply::Memory(MemoryControlReply::Missing { id }),
                Err(error) => ControlReply::Refused(format!("memory update failed: {error}")),
            }
        }
        MemoryControl::Delete(id) => {
            let report = match agent
                .brokered_lifecycle_gate(
                    turn,
                    "memory.fact.delete_requested",
                    LifecyclePayload::default(),
                )
                .await
            {
                Ok(report) => report,
                Err(error) => return ControlReply::Refused(error.public_summary()),
            };
            if let crate::runtime::hooks::HookDecision::Deny(reason) = report.decision {
                return ControlReply::Refused(reason);
            }
            match iteron_ctx::MemoryStore::at(&workspace).remove_checked(&id) {
                Ok(true) => {
                    agent.lifecycle_event(
                        "memory.fact.deleted",
                        Some(turn),
                        LifecyclePayload::default(),
                    );
                    match agent.deactivate_session_memory(&id) {
                        Ok(()) => ControlReply::Memory(MemoryControlReply::Deleted { id }),
                        Err(reason) => ControlReply::Refused(format!(
                            "memory was deleted, but current-session refresh failed: {reason}"
                        )),
                    }
                }
                Ok(false) => ControlReply::Memory(MemoryControlReply::Missing { id }),
                Err(error) => {
                    ControlReply::Refused(format!("memory delete failed or is uncertain: {error}"))
                }
            }
        }
    }
}

pub(super) async fn apply_immediate_control(
    workflows: &crate::workflow::WorkflowSupervisor,
    processes: Option<&iteron_tools::ProcessControl>,
    mcp_runtime: Option<&crate::mcp::McpRuntimeControl>,
    operator_status: &OperatorStatusSources,
    events: &EventPublisher,
    request: ControlRequest,
) {
    match request.control {
        Control::OrdinaryExtensions(command) => {
            operator_status.ordinary_extensions.dispatch(
                &operator_status.activity,
                events.contract.clone(),
                command,
                request.reply,
            );
        }
        Control::PluginManagement(command) => {
            operator_status.plugins.dispatch(
                &operator_status.activity,
                events.contract.clone(),
                command,
                request.reply,
            );
        }
        Control::ActivityCenter(command) => {
            operator_status
                .activity
                .dispatch(events.contract.clone(), command, request.reply);
        }
        Control::TranscriptExport(command) => {
            super::client_export::dispatch(events.contract.clone(), *command, request.reply);
        }
        Control::Inventory(query) => {
            let _ = request.reply.send(operator_status.inventory.read(query));
        }
        Control::ProviderCatalog(command) => {
            let _ = request
                .reply
                .send(operator_status.inventory.catalog(command));
        }
        Control::LiveWorkflow(command) => {
            operator_status
                .live_workflows
                .dispatch(command, request.reply);
        }
        Control::PersistentAgents(command) => {
            operator_status.agents.dispatch(command, request.reply);
        }
        Control::OperatorStatus => {
            let _ = request.reply.send(ControlReply::OperatorStatus(Box::new(
                operator_status.snapshot().await,
            )));
        }
        Control::Job(control) => {
            let _ = request
                .reply
                .send(apply_job_control(processes, events, control).await);
        }
        control @ Control::Workflow(_) => {
            apply_immediate_workflow_control(
                workflows,
                ControlRequest {
                    control,
                    reply: request.reply,
                },
            );
        }
        Control::Mcp(control) => {
            // A stop/restart first cancels the MCP operation and then waits for its actor lock.
            // That operation is part of `running`, so awaiting here would stop polling the very
            // future that must observe cancellation and release the lock. Keep the bounded App
            // Server loop live and let this one reply settle when the shared actor reaches it.
            let runtime = mcp_runtime.cloned();
            tokio::spawn(async move {
                let reply = apply_mcp_control(runtime.as_ref(), control).await;
                let _ = request.reply.send(reply);
            });
        }
        _ => {
            let _ = request.reply.send(ControlReply::Refused(
                "this control needs the resident runtime and cannot run mid-turn".into(),
            ));
        }
    }
}

async fn apply_workflow_control(
    agent: &mut Agent,
    workflows: &crate::workflow::WorkflowSupervisor,
    events: &mut EventPublisher,
    control: WorkflowControl,
) -> ControlReply {
    match control {
        WorkflowControl::Inventory => workflow_inventory_reply(workflows, None),
        WorkflowControl::Cancel { run_id } => {
            let notice = match workflows.cancel_for_operator(&run_id) {
                Ok(_) => format!("stopping workflow `{run_id}` at the engine's next safe point"),
                Err(error) => error,
            };
            workflow_inventory_reply(workflows, Some(notice))
        }
        WorkflowControl::Resume { run_id } => {
            if !workflows.may_resume(&run_id) {
                return workflow_inventory_reply(
                    workflows,
                    Some(format!(
                        "workflow `{run_id}` is still running or cancelling; wait for it to settle"
                    )),
                );
            }
            let prepared = match agent.prepare_workflow_resume(&run_id) {
                Ok(prepared) => prepared,
                Err(error) => return workflow_inventory_reply(workflows, Some(error)),
            };
            let name = prepared.name.clone();
            let phases = prepared.declared_phases.clone();
            // Publish the identity before starting the engine. Its first progress tick can then
            // never overtake `Started` in the frontend's event stream.
            let _ = events
                .publish(ServerEvent::WorkflowRun(
                    crate::workflow::WorkflowRunUiEvent::Started {
                        run_id: run_id.clone(),
                        name,
                        phases,
                    },
                ))
                .await;
            match crate::workflow::WorkflowLauncher::launch(workflows, prepared) {
                crate::workflow::Launched::Detached(_) => workflow_inventory_reply(
                    workflows,
                    Some(format!("resumed workflow `{run_id}` in this session")),
                ),
                crate::workflow::Launched::InTurn(handle) => {
                    // The App Server always holds the supervisor's live `Arc`, so this is a
                    // defensive fail-closed branch. Cancel and reap instead of dropping the sole
                    // join receiver and leaving an unowned engine thread.
                    handle.cancel();
                    let failed_id = run_id.clone();
                    tokio::spawn(async move {
                        let _ = handle.join().await;
                    });
                    let _ = events
                        .publish(ServerEvent::WorkflowRun(
                            crate::workflow::WorkflowRunUiEvent::Finished {
                                run_id: failed_id,
                                terminal: crate::workflow::WorkflowRunTerminal::Failed,
                            },
                        ))
                        .await;
                    workflow_inventory_reply(
                        workflows,
                        Some(format!(
                            "workflow `{run_id}` could not acquire a session owner"
                        )),
                    )
                }
            }
        }
    }
}

/// Apply one control request against the resident runtime.
///
/// Free function rather than a method so it can be called from inside `serve`'s `select!`, where
/// `self` has been destructured and only `agent` is borrowable.
///
/// Every arm answers. A control request that got no reply would hang the frontend's render loop,
/// which is the one failure a control plane must not have.
#[allow(
    clippy::too_many_arguments,
    reason = "the control plane answers every request against the whole live surface; bundling these into a struct would only move the same eight bindings behind one name"
)]
pub(super) async fn apply_control(
    agent: &mut Agent,
    session_factory: Option<&std::sync::Arc<super::session_factory::SessionFactory>>,
    workflows: &crate::workflow::WorkflowSupervisor,
    processes: Option<&iteron_tools::ProcessControl>,
    operator_status: &OperatorStatusSources,
    side: &mut Option<crate::runtime::SideConversation>,
    started: &mut bool,
    plantcore: &mut super::plantcore::PlantcoreAdmission,
    events: &mut EventPublisher,
    request: ControlRequest,
) {
    if plantcore.is_enabled() && !is_plantcore_admitted_control(&request.control) {
        let _ = request.reply.send(ControlReply::Refused(
            "PlantCore resident mode reserves the ordinary control surface for this Run".into(),
        ));
        return;
    }
    // Adoption swaps the runtime journal. Check the public projection before that mutation so
    // the two identities cannot diverge if a live product turn still owns this thread.
    if matches!(
        &request.control,
        Control::AdoptRun(_) | Control::SessionNavigate { .. } | Control::WorkspaceRewind { .. }
    ) && !events.can_rebind_contract_run()
    {
        let _ = request.reply.send(ControlReply::Refused(
            "cannot adopt while the public Thread projection has an active turn".into(),
        ));
        return;
    }
    // A detached owner operation cannot outlive its admitted selection into a new run.
    // Hold the actual generation barrier BEFORE adoption mutates Agent or the public projection.
    let _activity_adoption = if matches!(
        &request.control,
        Control::AdoptRun(_) | Control::SessionNavigate { .. } | Control::WorkspaceRewind { .. }
    ) {
        match operator_status.activity.adoption_barrier().await {
            Ok(lease) => Some(lease),
            Err(reason) => {
                let _ = request.reply.send(ControlReply::Refused(reason.into()));
                return;
            }
        }
    } else {
        None
    };
    if let Control::PersistentAgents(command) = &request.control
        && !command.is_enable()
    {
        let Control::PersistentAgents(command) = request.control else {
            unreachable!()
        };
        operator_status.agents.dispatch(command, request.reply);
        return;
    }
    let mut rewind_presentation = None;
    let (control, navigation) = match request.control {
        Control::WorkspaceRewind { command, cancel } => {
            let prepared = match session_factory {
                Some(factory) => {
                    match super::workspace_rewind_control::origin(agent, &events.contract, &command)
                    {
                        Ok(origin) => {
                            super::workspace_rewind_control::prepare(
                                agent, factory, origin, command, cancel,
                            )
                            .await
                        }
                        Err(reason) => Err(reason),
                    }
                }
                None => Err("trusted session factory unavailable".into()),
            };
            match prepared {
                Ok(super::workspace_rewind_control::RewindControlResult::Observed(
                    presentation,
                )) => {
                    let _ = request.reply.send(ControlReply::WorkspaceRewound(Box::new(
                        super::WorkspaceRewound {
                            presentation,
                            navigation: None,
                        },
                    )));
                    return;
                }
                Ok(super::workspace_rewind_control::RewindControlResult::Adopt {
                    native,
                    presentation,
                    admission,
                    reply,
                }) => {
                    rewind_presentation = Some(reply);
                    (
                        Control::AdoptRun(Box::new(native)),
                        Some((presentation, admission)),
                    )
                }
                Err(reason) => {
                    let _ = request.reply.send(ControlReply::Refused(reason));
                    return;
                }
            }
        }

        Control::SessionNavigate { command, cancel } => {
            let Some(factory) = session_factory else {
                let _ = request.reply.send(ControlReply::Refused(
                    "trusted session factory unavailable".into(),
                ));
                return;
            };
            let Some(scope) = events.contract.snapshot() else {
                let _ = request.reply.send(ControlReply::Refused(
                    "public session scope unavailable".into(),
                ));
                return;
            };
            if scope.run_id != *agent.rollout.run_id()
                || scope.thread_id != *command.thread_id()
                || scope.run_id != *command.run_id()
            {
                let _ = request.reply.send(ControlReply::Refused(
                    "session navigation belongs to a previous thread/run".into(),
                ));
                return;
            }
            let checkpoint = match agent.tunables_checkpoint() {
                Ok(checkpoint) => checkpoint.clone(),
                Err(error) => {
                    let _ = request
                        .reply
                        .send(ControlReply::Refused(error.public_summary().to_owned()));
                    return;
                }
            };
            let origin = super::session_factory::PreparationOrigin {
                thread: scope.thread_id,
                run: scope.run_id,
                checkpoint,
                selection: crate::providers::ModelSelection {
                    provider_id: iteron_provider::Provider::provider_instance_id(
                        agent.provider.as_ref(),
                    )
                    .unwrap_or_default()
                    .to_owned(),
                    model_id: agent.model.clone(),
                },
            };
            let prepared = match factory.prepare(origin, command, cancel.clone()).await {
                Ok(prepared) => prepared,
                Err(reason) => {
                    let _ = request.reply.send(ControlReply::Refused(reason));
                    return;
                }
            };
            if cancel
                .as_ref()
                .is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
            {
                let _ = request.reply.send(ControlReply::Refused(format!(
                    "session navigation cancelled before adoption; retained run {}",
                    prepared.run_id().0
                )));
                return;
            }
            let (native, presentation, admission) = prepared.into_parts();
            (
                Control::AdoptRun(Box::new(native)),
                Some((presentation, admission)),
            )
        }
        other => (other, None),
    };
    let reply = match control {
        Control::SessionNavigate { .. } | Control::WorkspaceRewind { .. } => {
            unreachable!("session navigation and rewind are normalized by the trusted host factory")
        }
        Control::OrdinaryExtensions(command) => {
            operator_status.ordinary_extensions.dispatch(
                &operator_status.activity,
                events.contract.clone(),
                command,
                request.reply,
            );
            return;
        }
        Control::PluginManagement(command) => {
            operator_status.plugins.dispatch(
                &operator_status.activity,
                events.contract.clone(),
                command,
                request.reply,
            );
            return;
        }
        Control::ActivityCenter(command) => {
            operator_status
                .activity
                .dispatch(events.contract.clone(), command, request.reply);
            return;
        }
        Control::Inventory(query) => operator_status.inventory.read(query),
        Control::ProviderCatalog(command) => operator_status.inventory.catalog(command),
        Control::TranscriptExport(command) => {
            super::client_export::dispatch(events.contract.clone(), *command, request.reply);
            return;
        }
        Control::SelectModelV1(request) => match agent
            .client_inventory_owner()
            .ok_or("bootstrap inventory is unavailable".to_owned())
            .and_then(|owner| owner.resolve(&request))
        {
            Ok(selection) => super::model_control::apply(agent, events, selection).await,
            Err(reason) => ControlReply::Refused(reason),
        },
        Control::LiveWorkflow(command) => {
            operator_status
                .live_workflows
                .dispatch(command, request.reply);
            return;
        }
        Control::PersistentAgents(command) => super::agent_control::enable(agent, command),
        Control::ThreadLifecycle(command) => super::thread_lifecycle::apply(agent, command).await,
        Control::PlantcoreRunBootstrapV1(payload) => {
            #[cfg(not(feature = "legacy-plantcore"))]
            {
                match plantcore.admit(*payload, agent, None) {
                    Err(error) => ControlReply::PlantcoreProtocolError(error),
                    Ok(_) => unreachable!("standalone bootstrap cannot be admitted"),
                }
            }
            #[cfg(feature = "legacy-plantcore")]
            if *started {
                ControlReply::PlantcoreProtocolError(super::plantcore::PlantcoreProtocolError {
                    code: "bootstrap_conflict",
                    message: "PlantCore bootstrap cannot change after a turn has started",
                })
            } else {
                let mcp_runtime = agent.mcp_runtime_control();
                match plantcore.admit(*payload, agent, mcp_runtime.as_ref()) {
                    Ok(accepted) => ControlReply::PlantcoreBootstrapAccepted(accepted),
                    Err(error) => ControlReply::PlantcoreProtocolError(error),
                }
            }
        }
        Control::OperatorStatus => {
            ControlReply::OperatorStatus(Box::new(operator_status.snapshot().await))
        }
        Control::SetEffort(next) => {
            match agent.transition_effort(next, iteron_protocol::RuntimePolicySource::Operator) {
                Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                Err(error) => ControlReply::Refused(error.public_summary()),
            }
        }
        Control::SetPermissionMode(next) => {
            match agent
                .transition_permission_mode(next, iteron_protocol::RuntimePolicySource::Operator)
            {
                Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                Err(error) => ControlReply::Refused(error.public_summary()),
            }
        }
        Control::SetCapabilityRule {
            capability,
            verdict,
        } => match agent.transition_permission_capability_rule(
            capability,
            verdict,
            iteron_protocol::RuntimePolicySource::Operator,
        ) {
            Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
            Err(error) => ControlReply::Refused(error.public_summary()),
        },
        Control::SetToolRule { tool, verdict } => {
            if tool.is_empty()
                || tool.len() > 128
                || !tool.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                ControlReply::Refused("tool rule name must be bounded literal text".into())
            } else if agent.permission_rules().tool_rule(&tool).is_none()
                && agent.permission_rules().tool_rules().len() >= 128
            {
                ControlReply::Refused("session tool rule limit reached".into())
            } else {
                let mut rules = agent.permission_rules().clone();
                rules.set_tool(&tool, verdict);
                match agent.transition_permission_rules(
                    rules,
                    iteron_protocol::RuntimePolicySource::Operator,
                ) {
                    Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                    Err(error) => ControlReply::Refused(error.public_summary()),
                }
            }
        }
        Control::SelectModel(selection) => {
            super::model_control::apply(agent, events, *selection).await
        }
        Control::Compact { focus } => {
            let reply = match agent.compact_now(focus).await {
                Ok(report) => ControlReply::Compacted {
                    report: Box::new(report),
                    snapshot: Box::new(snapshot_of(agent)),
                },
                Err(error) => ControlReply::Refused(error.public_summary()),
            };
            agent.settle_standalone_control_interrupt();
            reply
        }
        Control::TurnBudget { set } => match set {
            None => ControlReply::TurnBudget(agent.turn_budget()),
            Some(max_turns) => match agent.set_turn_ceiling(max_turns) {
                Ok(state) => ControlReply::TurnBudget(state),
                Err(error) => ControlReply::Refused(error.public_summary()),
            },
        },
        Control::Side(request) => {
            let reply = apply_side(agent, side, request).await;
            agent.settle_standalone_control_interrupt();
            reply
        }
        Control::AdoptRun(native_request) => {
            let AdoptRun {
                rollout,
                route,
                fresh,
                created_at,
            } = *native_request;
            let adoption = if fresh {
                let Some(created_at) = created_at else {
                    let _ = request.reply.send(ControlReply::Refused(
                        "new session has no host clock receipt".into(),
                    ));
                    return;
                };
                agent.adopt_fresh_run(
                    rollout,
                    agent.workspace.display().to_string(),
                    created_at,
                    None,
                )
            } else {
                agent.adopt_run(rollout)
            };
            match adoption {
                Ok(adopted) => {
                    events.run_id = Some(iteron_protocol::RunId(adopted.run_id.clone()));
                    assert!(
                        events.rebind_contract_run(iteron_protocol::RunId(adopted.run_id.clone())),
                        "adoption preflight keeps the public Thread projection rebindable"
                    );
                    events.contract.bind_artifact_owner(agent);
                    events.record_lifecycle(
                        "session.resumed",
                        None,
                        None,
                        LifecyclePayload {
                            outcome_code: Some(if fresh { "created" } else { "resumed" }.into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    // A resumed transcript must continue at its next turn. A newly created tab has
                    // only its sealed genesis, so its first submission deliberately enters
                    // `Agent::run`; that path appends the first turn but does not append genesis.
                    *started = !fresh;
                    // The side conversation writes into its own journal, minted from the run that
                    // opened it. It does not travel to another run; the next `/side` opens a fresh
                    // one under the adopted identity.
                    *side = None;
                    let ModelSelection {
                        provider,
                        provider_id,
                        model_id,
                        catalog_digest,
                        capability_digest,
                        context_window_tokens,
                        max_output_tokens,
                    } = *route;
                    // The journal is already swapped. Whatever happens to the route from here, the
                    // answer reports the adopted identity, because that is where the session is.
                    let blocked = match agent.record_adopted_model_selection(
                        provider,
                        provider_id,
                        model_id,
                        catalog_digest,
                        capability_digest,
                    ) {
                        Ok(()) => {
                            agent.model_context_window = context_window_tokens;
                            agent.model_max_output_tokens = max_output_tokens;
                            // Usage belongs to the turn that produced it, on the run that produced
                            // it. Nothing carries across an adoption.
                            agent.ledger.last_turn_usage = None;
                            agent.bind_selected_rate_card().err().map(|error| {
                                format!(
                                    "session {} was adopted but its rate card could not be bound, \
                                     so this process cannot continue it: {}. Restart with `iteron \
                                     --resume {}`.",
                                    adopted.run_id,
                                    error.public_summary(),
                                    adopted.run_id
                                )
                            })
                        }
                        // The transcript was adopted and the route was not. The kernel refuses
                        // every provider request in that state rather than dispatching against a
                        // route the record does not carry, so this says restart rather than
                        // pretending the session is usable.
                        Err(error) => Some(format!(
                            "session {} was adopted but its route could not be recorded, so this \
                             process cannot continue it: {error}. Restart with `iteron --resume {}`.",
                            adopted.run_id, adopted.run_id
                        )),
                    };
                    ControlReply::Adopted {
                        adopted: Box::new(adopted),
                        snapshot: Box::new(snapshot_of(agent)),
                        tunables_checkpoint: Box::new(
                            agent
                                .tunables_checkpoint()
                                .expect("a successfully adopted run has a validated checkpoint")
                                .clone(),
                        ),
                        compaction_trigger_tokens: agent.compaction.trigger_tokens,
                        blocked,
                    }
                }
                Err(error) => ControlReply::Refused(format!(
                    "cannot adopt that session here: {}",
                    error.public_summary()
                )),
            }
        }
        Control::Workflow(control) => {
            apply_workflow_control(agent, workflows, events, control).await
        }
        Control::Job(control) => apply_job_control(processes, events, control).await,
        Control::Memory(control) => apply_memory_control(agent, control).await,
        Control::Mcp(control) => {
            let runtime = agent.mcp_runtime_control();
            apply_mcp_control(runtime.as_ref(), control).await
        }
    };
    // A frontend that dropped the receiver has moved on; that is not the server's problem.
    let reply = if let Some((presentation, _admission)) = navigation {
        match reply {
            ControlReply::Adopted {
                adopted,
                snapshot,
                tunables_checkpoint,
                compaction_trigger_tokens,
                blocked,
            } => {
                let public = iteron_protocol::session_navigation::SessionNavigationReplyV1 {
                    version: 1,
                    thread_id: presentation.origin_thread,
                    origin_run_id: presentation.origin_run,
                    run_id: iteron_protocol::RunId(adopted.run_id.clone()),
                    fresh: !*started,
                    provider_id: snapshot.provider_id.clone(),
                    model_id: snapshot.model.clone(),
                    effort: snapshot.effort,
                    context_window_tokens: agent.model_context_window,
                    messages: adopted.messages,
                    turns: adopted.turns,
                    checkpoint_digest_sha256: tunables_checkpoint
                        .snapshot_digest_sha256()
                        .to_owned(),
                    blocked,
                    substituted_route: presentation.substituted,
                    transcript: presentation.projection,
                };
                ControlReply::SessionNavigated(Box::new(NavigatedSession {
                    presentation: public,
                    adopted: *adopted,
                    snapshot: *snapshot,
                    tunables_checkpoint: *tunables_checkpoint,
                    compaction_trigger_tokens,
                }))
            }
            ControlReply::Refused(reason) => ControlReply::Refused(format!(
                "{reason}; target run {} is retained and was not reported as selected",
                presentation.retained_run.0
            )),
            other => other,
        }
    } else {
        reply
    };
    let reply = if let Some(mut presentation) = rewind_presentation {
        let navigation = match reply {
            ControlReply::SessionNavigated(navigation) => {
                if let Some(execution) = presentation.execution.as_mut() {
                    execution.conversation_adopted = true;
                }
                Some(navigation)
            }
            ControlReply::Refused(reason) => {
                if let Some(execution) = presentation.execution.as_mut() {
                    execution.reason = Some(reason);
                }
                None
            }
            _ => {
                if let Some(execution) = presentation.execution.as_mut() {
                    execution.reason =
                        Some("host adoption did not return a selected-state receipt".into());
                }
                None
            }
        };
        ControlReply::WorkspaceRewound(Box::new(super::WorkspaceRewound {
            presentation,
            navigation,
        }))
    } else {
        reply
    };
    let _ = request.reply.send(reply);
}

/// Apply one side-conversation request.
///
/// The side conversation is opened lazily by the first `Ask`, so an operator who never uses `/side`
/// never pays for a second read-only registry scan or a journal file that would record nothing.
pub(super) async fn apply_side(
    agent: &mut Agent,
    side: &mut Option<crate::runtime::SideConversation>,
    request: SideRequest,
) -> ControlReply {
    match request {
        SideRequest::Status => ControlReply::SideStatus {
            status: side
                .as_ref()
                .map(|conversation| Box::new(conversation.status())),
            closed: false,
        },
        SideRequest::Close => {
            // The status is read BEFORE the drop, so the operator is told what the conversation
            // cost by the conversation itself rather than by a number the frontend remembered.
            let status = side.take().map(|conversation| {
                let status = conversation.status();
                drop(conversation);
                Box::new(status)
            });
            ControlReply::SideStatus {
                status,
                closed: true,
            }
        }
        SideRequest::Ask(text) => {
            if side.is_none() {
                match agent.open_side_conversation() {
                    Ok(conversation) => *side = Some(conversation),
                    Err(error) => return ControlReply::Refused(error),
                }
            }
            let Some(conversation) = side.as_mut() else {
                return ControlReply::Refused("the side conversation could not be opened".into());
            };
            match conversation.ask(&text).await {
                Ok(answer) => ControlReply::SideAnswer(Box::new(answer)),
                Err(error) => ControlReply::Refused(error),
            }
        }
    }
}

/// Read the runtime state the frontend mirrors.
pub(super) fn snapshot_of(agent: &mut Agent) -> SessionSnapshot {
    // The kernel inbox has at most KERNEL_INBOUND_CAPACITY entries. The runtime may inspect only
    // one per call under a low inbound_poll_limit, so exhaust that physical queue before another
    // product turn can start. Controls left in the old inbox must never reach the next turn.
    let mut unadmitted_entries = Vec::new();
    let mut unadmitted_client_steers = 0usize;
    for _ in 0..KERNEL_INBOUND_CAPACITY {
        let (entries, client_count) = agent.take_unadmitted_steers_with_client_count();
        unadmitted_entries.extend(entries);
        unadmitted_client_steers = unadmitted_client_steers.saturating_add(client_count);
    }
    let mut unadmitted_steers = Vec::with_capacity(unadmitted_client_steers);
    let mut unadmitted_internal_notifications = Vec::new();
    let mut unadmitted_steer_submission_ids = Vec::new();
    for entry in unadmitted_entries {
        if entry.client_visible {
            unadmitted_steer_submission_ids.push(entry.submission_id);
            unadmitted_steers.push(entry.text);
        } else {
            unadmitted_internal_notifications.push(entry.text);
        }
    }
    SessionSnapshot {
        mode: agent.permission_mode(),
        effort: agent.effort(),
        model: agent.model.clone(),
        // The provider half of the live route. A durable route commit (including the one a
        // failover performs) republishes `agent.provider`, and admission proves that instance id
        // equals the selected route's `provider_id`, so this is the selected route's provider.
        // An unbound route reports the empty string rather than a guess.
        provider_id: iteron_provider::Provider::provider_instance_id(agent.provider.as_ref())
            .unwrap_or_default()
            .to_owned(),
        cost: agent.ledger.cost_state(),
        last_turn_usage: agent.ledger.last_turn_usage,
        unadmitted_steers,
        unadmitted_internal_notifications,
        unadmitted_client_steers,
        unadmitted_steer_submission_ids,
        permission_rules: agent.permission_rules().clone(),
        runtime_policy: agent.runtime_policy_overlay(),
        ledger_summary: agent.ledger.summary(),
        rate_limit: agent
            .last_rate_limit()
            .as_ref()
            .and_then(iteron_provider::RateLimitSnapshot::summary),
        mcp_health: agent.mcp_health(),
    }
}
