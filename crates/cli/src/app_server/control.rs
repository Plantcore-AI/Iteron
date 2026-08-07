//! App-server control-plane handlers.

use super::*;

pub(super) fn is_immediate_control(control: &Control) -> bool {
    matches!(
        control,
        Control::Workflow(WorkflowControl::Inventory | WorkflowControl::Cancel { .. })
            | Control::Job(_)
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
    processes: Option<&core_tools::ProcessControl>,
    control: JobControl,
) -> ControlReply {
    let Some(processes) = processes else {
        return ControlReply::Refused("this runtime has no background-process supervisor".into());
    };
    let result = match control {
        JobControl::Inventory => processes.list(),
        JobControl::Attach {
            job_id,
            stdout_cursor,
            stderr_cursor,
        } => {
            processes
                .poll(&job_id, stdout_cursor, stderr_cursor, 0)
                .await
        }
        JobControl::Write { job_id, input, eof } => processes.write(&job_id, input, eof).await,
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

pub(super) async fn apply_immediate_control(
    workflows: &crate::workflow::WorkflowSupervisor,
    processes: Option<&core_tools::ProcessControl>,
    request: ControlRequest,
) {
    match request.control {
        Control::Job(control) => {
            let _ = request
                .reply
                .send(apply_job_control(processes, control).await);
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
                            crate::workflow::WorkflowRunUiEvent::Finished { run_id: failed_id },
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
pub(super) async fn apply_control(
    agent: &mut Agent,
    workflows: &crate::workflow::WorkflowSupervisor,
    processes: Option<&core_tools::ProcessControl>,
    side: &mut Option<crate::runtime::SideConversation>,
    started: &mut bool,
    events: &mut EventPublisher,
    request: ControlRequest,
) {
    let reply = match request.control {
        Control::SetEffort(next) => {
            match agent.transition_effort(next, core_protocol::RuntimePolicySource::Operator) {
                Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
                Err(error) => ControlReply::Refused(error.public_summary()),
            }
        }
        Control::SetPermissionMode(next) => {
            match agent
                .transition_permission_mode(next, core_protocol::RuntimePolicySource::Operator)
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
            core_protocol::RuntimePolicySource::Operator,
        ) {
            Ok(_) => ControlReply::State(Box::new(snapshot_of(agent))),
            Err(error) => ControlReply::Refused(error.public_summary()),
        },
        Control::SelectModel(selection) => {
            // One transaction, in the kernel's required order: the durable audit append happens
            // FIRST, so a failure leaves the old selection in force rather than a half-applied one.
            let ModelSelection {
                provider,
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
                context_window_tokens,
                max_output_tokens,
            } = *selection;
            let changed = agent.model != model_id;
            match agent.record_provider_model_selection(
                provider,
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            ) {
                Ok(()) => {
                    agent.model_context_window = context_window_tokens;
                    agent.model_max_output_tokens = max_output_tokens;
                    if changed {
                        // Last-turn usage belongs to the model that produced it. Carrying it across
                        // a switch would print the old model's token counts under the new one's
                        // name; the frontend used to clear this itself, back when it held the
                        // ledger.
                        agent.ledger.last_turn_usage = None;
                    }
                    match agent.bind_selected_rate_card() {
                        Ok(bound) => {
                            if !bound && agent.budget.max_usd.is_some_and(|ceiling| ceiling > 0.0) {
                                // Advisory, not a refusal: the route is recorded and in force. The
                                // operator needs to know the ceiling will stop provider calls, so it
                                // goes out on the EQ where every other runtime advisory goes.
                                let _ = events
                                    .publish(ServerEvent::Notice(
                                        "selected route has no active verified rate card; the USD \
                                         ceiling will block provider calls"
                                            .into(),
                                    ))
                                    .await;
                            }
                            ControlReply::State(Box::new(snapshot_of(agent)))
                        }
                        Err(error) => ControlReply::Refused(error.public_summary()),
                    }
                }
                Err(error) => ControlReply::Refused(format!(
                    "cannot record model switch; old selection retained: {error}"
                )),
            }
        }
        Control::Compact { focus } => match agent.compact_now(focus).await {
            Ok(report) => ControlReply::Compacted {
                report: Box::new(report),
                snapshot: Box::new(snapshot_of(agent)),
            },
            Err(error) => ControlReply::Refused(error.public_summary()),
        },
        Control::TurnBudget { set } => match set {
            None => ControlReply::TurnBudget(agent.turn_budget()),
            Some(max_turns) => match agent.set_turn_ceiling(max_turns) {
                Ok(state) => ControlReply::TurnBudget(state),
                Err(error) => ControlReply::Refused(error.public_summary()),
            },
        },
        Control::Side(request) => apply_side(agent, side, request).await,
        Control::AdoptRun(request) => {
            let AdoptRun {
                rollout,
                route,
                fresh,
            } = *request;
            match agent.adopt_run(rollout) {
                Ok(adopted) => {
                    // The adopted transcript IS this session's transcript now, so the next
                    // submission must continue it. Leaving `started` false would send it down
                    // `Agent::run`, which starts from nothing and would silently discard the
                    // history this adoption just took a writer lock on.
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
                    let genesis_error = fresh
                        .then(|| {
                            let created_at = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|duration| duration.as_secs())
                                .unwrap_or(0);
                            agent.record_genesis(
                                agent.workspace.display().to_string(),
                                created_at,
                                "in-process-session-v1".into(),
                                None,
                            )
                        })
                        .transpose()
                        .err();
                    let blocked = if let Some(error) = genesis_error {
                        Some(format!(
                            "session {} was created but its genesis could not be recorded: {}",
                            adopted.run_id,
                            error.public_summary()
                        ))
                    } else {
                        match agent.record_provider_model_selection(
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
                                     so this process cannot continue it: {}. Restart with `core \
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
                             process cannot continue it: {error}. Restart with `core --resume {}`.",
                                adopted.run_id, adopted.run_id
                            )),
                        }
                    };
                    ControlReply::Adopted {
                        adopted: Box::new(adopted),
                        snapshot: Box::new(snapshot_of(agent)),
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
        Control::Job(control) => apply_job_control(processes, control).await,
    };
    // A frontend that dropped the receiver has moved on; that is not the server's problem.
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
    SessionSnapshot {
        mode: agent.permission_mode(),
        effort: agent.effort(),
        model: agent.model.clone(),
        cost: agent.ledger.cost_state(),
        last_turn_usage: agent.ledger.last_turn_usage,
        unadmitted_steers: agent.take_unadmitted_steers(),
        permission_rules: agent.permission_rules().clone(),
        ledger_summary: agent.ledger.summary(),
        rate_limit: agent
            .last_rate_limit()
            .as_ref()
            .and_then(core_provider::RateLimitSnapshot::summary),
    }
}
