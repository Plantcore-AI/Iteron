//! Resident Agent ownership, idle admission, turn barriers and ordered session teardown.

use super::{
    Agent, ControlRequest, EventPublisher, HookExecution, KERNEL_INBOUND_CAPACITY,
    LifecyclePayload, McpInputResponse, Op, Outcome, PROTOCOL_VERSION, PendingKernelSubmission,
    PlantcoreAdmission, QueuedSubmission, Routed, RunInput, RunLifecycleState, ServerEnds,
    ServerEvent, SessionId, SessionLifecycleState, SubmissionDeduplicator,
    SubmissionLifecycleState, TerminalAuthority, TerminalSummary, TurnLifecycleState,
    TurnSubmission, apply_control, clean_session_owned_tools, discard_expired_product_steers,
    expire_pending_turns, expire_queued_after_drain, first_prompt_title,
    forward_runtime_notifications, input_ready_activity, legacy_user_prompt_context, mcp_input,
    mpsc, outcome_name, publish_runtime_event, publish_settled, publish_stop_hook_observation,
    publish_submission, publish_workflow_progress, queue_population, receive_stop_hook_observation,
    reject_replayed_submission, route, run_legacy_hook, run_lifecycle_gate, session_hooks,
    session_services, settle_kernel_submissions_at_turn_end, snapshot_of, turn_pump,
};
use iteron_protocol::LifecycleState;

/// Owns the actual resident Agent and its bounded admission/presentation ports.
pub(crate) struct AppServer {
    pub(super) agent: Agent,
    pub(super) session_factory: Option<std::sync::Arc<super::session_factory::SessionFactory>>,
    pub(super) submissions: mpsc::Receiver<QueuedSubmission>,
    pub(super) priority_submissions: mpsc::Receiver<QueuedSubmission>,
    pub(super) control: mpsc::Receiver<ControlRequest>,
    pub(super) events: EventPublisher,
    pub(super) hook_journal: Option<crate::runtime::hooks::journal::HookEffectJournal>,
    pub(super) stop_hooks: Option<crate::runtime::hooks::StopHookObserverRuntime>,
    pub(super) lifecycle_hook_runtime: crate::runtime::lifecycle_hooks::LifecycleHookRuntime,
    /// Forwarded to the kernel's inbound queue. Every resident App Server installs the receiver;
    /// the separate interactive-approval posture decides whether `Ask` may wait for a human.
    /// The kernel drains commands at its own safe points; the server never reaches into a running
    /// turn.
    pub(super) to_kernel: mpsc::Sender<TurnSubmission>,
    pub(super) activity: mpsc::Receiver<iteron_protocol::ActivityEvent>,
    pub(super) mcp_input_requests: mpsc::Receiver<mcp_input::McpInputRequestEnvelope>,
    pub(super) mcp_input_responses: mpsc::Receiver<McpInputResponse>,
    pub(super) plantcore: PlantcoreAdmission,
}

impl AppServer {
    /// Take ownership of the runtime.
    ///
    /// `set_approvals` installs the kernel's inbound receiver here rather than in the frontend, so
    /// the queue outlives every turn. That is what removes `take_unadmitted_steers`: the reconcile
    /// path existed only because the receiver used to travel with the `Agent` in and out of a task
    /// the frontend owned.
    pub(super) fn new_with_session_factory(
        mut agent: Agent,
        ends: ServerEnds,
        interactive_approvals: bool,
        session_factory: Option<std::sync::Arc<super::session_factory::SessionFactory>>,
    ) -> Self {
        let mut ends = ends;
        if interactive_approvals && let Some(runtime) = agent.mcp_runtime_control() {
            let _ = runtime.install_mrtr_handler(ends.mcp_input.handler.clone());
        }
        let run_id = agent.rollout.run_id().clone();
        ends.events
            .bind_lifecycle_identity(SessionId(format!("session-{}", run_id.0)), run_id);
        ends.events.contract.bind_artifact_owner(&agent);
        let (to_kernel, kernel_rx) = mpsc::channel::<TurnSubmission>(
            iteron_tunables::param_integer(
                "cli.app_server.kernel_inbound_capacity",
                KERNEL_INBOUND_CAPACITY,
            )
            .clamp(1, KERNEL_INBOUND_CAPACITY),
        );
        if interactive_approvals {
            agent.set_approvals(kernel_rx);
        } else {
            agent.set_inbound_control(kernel_rx);
        }
        let session_hooks::SessionHooks {
            hook_journal,
            stop_hooks,
            lifecycle_hook_runtime,
        } = session_hooks::SessionHooks::install(&mut agent, &mut ends);
        Self {
            agent,
            session_factory,
            submissions: ends.submissions,
            priority_submissions: ends.priority_submissions,
            control: ends.control,
            events: ends.events,
            hook_journal,
            stop_hooks,
            lifecycle_hook_runtime,
            to_kernel,
            activity: ends.activity,
            mcp_input_requests: ends.mcp_input.requests,
            mcp_input_responses: ends.mcp_input.responses,
            plantcore: ends.plantcore,
        }
    }

    /// Run the session until every client hangs up.
    ///
    /// # Why this is one task and not a task per turn
    ///
    /// The frontend used to spawn a task per turn, move the `Agent` into it, and take it back
    /// through the `JoinHandle`. That made "a run is in flight" the same fact as "the slot is
    /// empty", which is why every configuration path was reachable only while idle — the borrow
    /// checker, not the design, was enforcing the ordering.
    ///
    /// Here the runtime is resident and the concurrency is explicit. The one borrow that matters is
    /// `agent`, held by the in-flight turn; the submission queue, the kernel's inbound sender and
    /// the event publisher are disjoint locals, so the `select!` below can keep draining the SQ and
    /// republishing the EQ *while* a turn runs. Destructuring `self` is what makes that legal, and
    /// it is the whole trick.
    ///
    /// # The workflow run owner
    ///
    /// [`crate::workflow::WorkflowSupervisor`] is installed here for exactly the same reason. A
    /// `Workflow` run could not outlive its turn because the only thing holding it was a local
    /// binding inside a method that borrows `&mut agent`; the supervisor is an `Arc` reachable from
    /// both sides of that borrow, so a detached run has an owner while the turn that started it
    /// returns. Its settled-run channel is selected on in BOTH loops below, which is what makes a
    /// background run finishing while the operator sits idle still reach the screen.
    ///
    /// Returns what the session did with the runs it still owned when it ended: by that point the
    /// EQ's reader is already gone (the session ends *because* the frontend hung up), so the client
    /// prints it after restoring the terminal rather than receiving it as an event.
    pub(crate) async fn serve(self) -> crate::workflow::ShutdownReport {
        let Self {
            mut agent,
            session_factory,
            mut submissions,
            mut priority_submissions,
            mut control,
            mut events,
            hook_journal,
            mut stop_hooks,
            lifecycle_hook_runtime,
            to_kernel,
            mut activity,
            mut mcp_input_requests,
            mut mcp_input_responses,
            mut plantcore,
        } = self;
        let mut pending_mcp_inputs = std::collections::BTreeMap::new();
        let mut maintenance =
            super::advisory_maintenance::MaintenanceObserver::new(events.contract.clone());

        let session_services::SessionServices {
            mut runtime_ui_rx,
            frontend_channels,
            mut workflow_rx,
            mut settled_rx,
            workflows,
            processes,
            mcp_runtime,
            language_servers,
            mut operator_status,
            hook_cancel,
            drain_signal,
            lifecycle_gate_hooks,
        } = session_services::SessionServices::install(&mut agent, &events);
        let mut session_lifecycle = SessionLifecycleState::Created;
        events.record_lifecycle("session.created", None, None, LifecyclePayload::default());
        events.record_lifecycle(
            "session.record_opened",
            None,
            None,
            LifecyclePayload::default(),
        );
        events.record_lifecycle(
            "session.profile_bound",
            None,
            None,
            LifecyclePayload::default(),
        );
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Configured)
            .expect("new sessions configure before serving");
        events.record_lifecycle(
            "session.configured",
            None,
            None,
            LifecyclePayload::default(),
        );
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Idle)
            .expect("configured sessions become idle");
        run_legacy_hook(
            HookExecution {
                hooks: &lifecycle_gate_hooks,
                journal: hook_journal.as_ref(),
                events: &events,
                cancel: hook_cancel.as_deref(),
                drain: Some(drain_signal.as_ref()),
            },
            crate::runtime::hooks::HookEvent::SessionStart,
            None,
            None,
            serde_json::json!({
                "event": "SessionStart",
                "session_id": format!("session-{}", agent.rollout.run_id().0),
            })
            .to_string(),
        )
        .await;
        events.record_lifecycle("session.started", None, None, LifecyclePayload::default());
        events.record_lifecycle("session.idle", None, None, LifecyclePayload::default());

        // `run` versus `follow_up` was a caller-side boolean the frontend chose. With a resident
        // runtime it is session state and belongs here: the first admitted turn starts the session,
        // every later one continues it.
        let mut started = false;

        // The operator's side conversation, if they have opened one. It is server state for the
        // same reason the `Agent` is: it owns a live runtime with an open journal.
        let mut side: Option<crate::runtime::SideConversation> = None;
        let mut pending_runtime = std::collections::VecDeque::<String>::new();
        let mut pending_turns = std::collections::VecDeque::<QueuedSubmission>::new();
        let mut pending_kernel_submissions =
            std::collections::VecDeque::<PendingKernelSubmission>::new();
        let mut submission_identities = SubmissionDeduplicator::default();

        enum TurnTrigger {
            Submission {
                queued: Box<QueuedSubmission>,
                preprocessed: bool,
            },
            Runtime(String),
        }

        loop {
            let trigger = if let Ok(queued) = priority_submissions.try_recv() {
                events.record_lifecycle(
                    "queue.depth_changed",
                    None,
                    None,
                    LifecyclePayload {
                        count: Some(queue_population(
                            &submissions,
                            &priority_submissions,
                            pending_turns.len(),
                        )),
                        ..LifecyclePayload::default()
                    },
                );
                TurnTrigger::Submission {
                    queued: Box::new(queued),
                    preprocessed: false,
                }
            } else if let Some(queued) = pending_turns.pop_front() {
                TurnTrigger::Submission {
                    queued: Box::new(queued),
                    preprocessed: true,
                }
            } else if let Some(notification) = pending_runtime.pop_front() {
                TurnTrigger::Runtime(notification)
            } else {
                tokio::select! {
                    Some(queued) = priority_submissions.recv() => {
                        events.record_lifecycle(
                            "queue.depth_changed",
                            None,
                            None,
                            LifecyclePayload {
                                count: Some(queue_population(
                                    &submissions,
                                    &priority_submissions,
                                    pending_turns.len(),
                                )),
                                ..LifecyclePayload::default()
                            },
                        );
                        TurnTrigger::Submission { queued: Box::new(queued), preprocessed: false }
                    }
                    request = control.recv() => {
                        match request {
                            Some(request) => {
                                apply_control(
                                    &mut agent,
                                    session_factory.as_ref(),
                                    &workflows,
                                    processes.as_ref(),
                                    &operator_status,
                                    &mut side,
                                    &mut started,
                                    &mut plantcore,
                                    &mut events,
                                    request,
                                ).await;
                                operator_status.refresh_runtime(&agent);
                                continue
                            }
                            None => break,
                        }
                    }
                    // A detached run keeps emitting between turns. Without this arm its tree froze on
                    // the frame the turn ended on and only resumed when the operator typed again —
                    // "the run is invisible while it is the only thing happening", which is precisely
                    // the state detaching would otherwise create.
                    Some(progress) = workflow_rx.recv() => {
                        publish_workflow_progress(&mut events, progress).await;
                        continue
                    }
                    Some(activity_event) = activity.recv() => {
                        let _ = events.publish(ServerEvent::Activity(activity_event)).await;
                        continue
                    }
                    maintenance_event = maintenance.next() => {
                        events.try_publish_maintenance(maintenance_event);
                        continue
                    }
                    Some(runtime_event) = runtime_ui_rx.recv() => {
                        publish_runtime_event(
                            &mut events, &mut pending_kernel_submissions, &frontend_channels, runtime_event,
                        ).await;
                        continue
                    }
                    runtime_event = frontend_channels.recv_authoritative() => {
                        publish_runtime_event(
                            &mut events, &mut pending_kernel_submissions, &frontend_channels, runtime_event,
                        ).await;
                        continue
                    }
                    Some(request) = mcp_input_requests.recv() => {
                        mcp_input::publish_request(
                            request,
                            &mut pending_mcp_inputs,
                            &mut events,
                        ).await;
                        continue
                    }
                    Some(response) = mcp_input_responses.recv() => {
                        if !mcp_input::resolve_response(response, &mut pending_mcp_inputs) {
                            let _ = events.publish(ServerEvent::Notice(
                                "stale MCP input response was refused".into(),
                            )).await;
                        }
                        continue
                    }
                    Some(observation) = receive_stop_hook_observation(&mut stop_hooks) => {
                        publish_stop_hook_observation(&mut events, observation).await;
                        continue
                    }
                    Some(settled) = settled_rx.recv() => {
                        TurnTrigger::Runtime(publish_settled(&mut events, settled).await)
                    }
                    queued = submissions.recv() => {
                        match queued {
                            Some(queued) => {
                                events.record_lifecycle(
                                    "queue.depth_changed",
                                    None,
                                    None,
                                    LifecyclePayload {
                                        count: Some(queue_population(
                                            &submissions,
                                            &priority_submissions,
                                            pending_turns.len(),
                                        )),
                                        ..LifecyclePayload::default()
                                    },
                                );
                                TurnTrigger::Submission { queued: Box::new(queued), preprocessed: false }
                            }
                            None => break,
                        }
                    }
                }
            };
            let (input, runtime_follow_up, turn_submission_id) = match trigger {
                TurnTrigger::Runtime(notification) => (RunInput::Text(notification), true, None),
                TurnTrigger::Submission {
                    queued,
                    preprocessed,
                } => {
                    let queued = *queued;
                    let expected_product_turn_id = queued.envelope.expected_product_turn_id;
                    let envelope = queued.into_envelope();
                    let version = envelope.protocol_version;
                    let submission_id = envelope.submission_id;
                    let Ok((_, op)) = envelope.into_current_identified() else {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("protocol_version_mismatch"),
                        )
                        .await;
                        let _ = events.publish(ServerEvent::Notice(format!(
                            "a submission arrived stamped protocol v{version}; this runtime speaks v{PROTOCOL_VERSION} and discarded it"
                        ))).await;
                        continue;
                    };
                    if !preprocessed
                        && reject_replayed_submission(
                            &mut events,
                            &mut submission_identities,
                            submission_id,
                            None,
                        )
                        .await
                    {
                        continue;
                    }
                    publish_submission(
                        &mut events,
                        submission_id,
                        SubmissionLifecycleState::Received,
                        None,
                    )
                    .await;
                    if expected_product_turn_id.is_some() {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("turn_mismatch_or_terminal"),
                        )
                        .await;
                        continue;
                    }
                    if let Err(error) = plantcore.admit_input(&op) {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some(error.code),
                        )
                        .await;
                        let _ = events
                            .publish(ServerEvent::Notice(error.message.to_owned()))
                            .await;
                        continue;
                    }
                    if !preprocessed
                        && let Some(context) = legacy_user_prompt_context(&op, submission_id)
                    {
                        run_legacy_hook(
                            HookExecution {
                                hooks: &lifecycle_gate_hooks,
                                journal: hook_journal.as_ref(),
                                events: &events,
                                cancel: hook_cancel.as_deref(),
                                drain: Some(drain_signal.as_ref()),
                            },
                            crate::runtime::hooks::HookEvent::UserPromptSubmit,
                            Some(submission_id),
                            None,
                            context,
                        )
                        .await;
                    }
                    let gate_event = match &op {
                        Op::Steer { .. } => Some("steer.requested"),
                        Op::UserInput { .. } | Op::UserInputV2 { .. } | Op::UserInputV3 { .. } => {
                            Some("submission.created")
                        }
                        Op::ApprovalResponse { .. }
                        | Op::Interrupt
                        | Op::ForceCancel
                        | Op::Drain
                        | Op::Unknown => None,
                    };
                    if !preprocessed
                        && let Some(gate_event) = gate_event
                        && let Err(reason) = run_lifecycle_gate(
                            HookExecution {
                                hooks: &lifecycle_gate_hooks,
                                journal: hook_journal.as_ref(),
                                events: &events,
                                cancel: hook_cancel.as_deref(),
                                drain: Some(drain_signal.as_ref()),
                            },
                            gate_event,
                            submission_id,
                            None,
                        )
                        .await
                    {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("hook_blocked"),
                        )
                        .await;
                        let _ = events.publish(ServerEvent::Notice(reason)).await;
                        continue;
                    }
                    if matches!(op, Op::ForceCancel) {
                        let cancelled = stop_hooks
                            .as_ref()
                            .map_or(0, |observer| observer.dispatcher.cancel_active());
                        if cancelled > 0 {
                            events.record_lifecycle(
                                "cancel.forced",
                                None,
                                Some(submission_id),
                                LifecyclePayload {
                                    count: Some(u64::try_from(cancelled).unwrap_or(u64::MAX)),
                                    reason_code: Some("stop_hook_observer".into()),
                                    ..LifecyclePayload::default()
                                },
                            );
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Admitted,
                                None,
                            )
                            .await;
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Applied,
                                None,
                            )
                            .await;
                            continue;
                        }
                    }
                    if matches!(op, Op::Interrupt | Op::ForceCancel) {
                        publish_submission(
                            &mut events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("no_active_turn"),
                        )
                        .await;
                        continue;
                    }
                    match route(&op) {
                        Routed::Refuse(why) => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Rejected,
                                Some("unsupported_operation"),
                            )
                            .await;
                            let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                            continue;
                        }
                        Routed::ToKernel => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Rejected,
                                Some("no_active_turn"),
                            )
                            .await;
                            continue;
                        }
                        Routed::StartTurn(input) => {
                            publish_submission(
                                &mut events,
                                submission_id,
                                SubmissionLifecycleState::Admitted,
                                None,
                            )
                            .await;
                            (input, false, Some(submission_id))
                        }
                    }
                }
            };
            if let Some(submission_id) = turn_submission_id {
                publish_submission(
                    &mut events,
                    submission_id,
                    SubmissionLifecycleState::Applied,
                    None,
                )
                .await;
            }
            if !started && !runtime_follow_up {
                let title = first_prompt_title(&input);
                if !title.is_empty() {
                    events.record_lifecycle(
                        "session.title_selected",
                        None,
                        turn_submission_id,
                        LifecyclePayload {
                            count: Some(u64::try_from(title.chars().count()).unwrap_or(u64::MAX)),
                            magnitude: Some(u64::try_from(title.len()).unwrap_or(u64::MAX)),
                            ..LifecyclePayload::default()
                        },
                    );
                }
            }
            session_lifecycle = session_lifecycle
                .transition(SessionLifecycleState::Running)
                .expect("only an idle session admits a turn");
            let live_turn_id = agent.current_turn_id();
            events.begin_contract_turn(agent.rollout.run_id().clone(), turn_submission_id);
            agent.set_active_product_turn_id(Some(
                iteron_protocol::product_contract::ProductTurnId(events.next_product_turn),
            ));
            let activity_overflow = agent.activity_overflow_port();
            let mut run_lifecycle = RunLifecycleState::Created;
            run_lifecycle = run_lifecycle
                .transition(RunLifecycleState::Admitted)
                .expect("a created run is admitted before activation");
            run_lifecycle = run_lifecycle
                .transition(RunLifecycleState::Active)
                .expect("an admitted run starts exactly once");
            let mut turn_lifecycle = TurnLifecycleState::Received;
            turn_lifecycle = turn_lifecycle
                .transition(TurnLifecycleState::Admitted)
                .expect("a received turn is admitted before it runs");
            turn_lifecycle = turn_lifecycle
                .transition(TurnLifecycleState::Running)
                .expect("an admitted turn starts exactly once");
            // Control requests that arrive mid-turn wait here; see the `select!` arm below.
            let mut deferred: Vec<ControlRequest> = Vec::new();
            let turn_pump::TurnCompletion {
                completion,
                cancel_forwarded,
                cancel_submission_id,
                drain_submission_id,
            } = {
                let running = async {
                    if runtime_follow_up {
                        match &input {
                            RunInput::Text(notification) => {
                                agent.follow_up_runtime_notification(notification).await
                            }
                            _ => unreachable!("runtime notifications are text"),
                        }
                    } else {
                        match (&input, started) {
                            (RunInput::Text(task), false) => agent.run(task).await,
                            (RunInput::Text(task), true) => agent.follow_up(task).await,
                            (RunInput::Content(segments), false) => {
                                agent.run_content(segments).await
                            }
                            (RunInput::Content(segments), true) => {
                                agent.follow_up_content(segments).await
                            }
                            (
                                RunInput::Files {
                                    text,
                                    images,
                                    files,
                                },
                                false,
                            ) => agent.run_files(text, images, files).await,
                            (
                                RunInput::Files {
                                    text,
                                    images,
                                    files,
                                },
                                true,
                            ) => agent.follow_up_files(text, images, files).await,
                        }
                    }
                };
                tokio::pin!(running);
                turn_pump::RunningTurnPump {
                    maintenance: &mut maintenance,
                    runtime_ui_rx: &mut runtime_ui_rx,
                    frontend_channels: &frontend_channels,
                    workflow_rx: &mut workflow_rx,
                    activity: &mut activity,
                    activity_overflow: &activity_overflow,
                    mcp_input_requests: &mut mcp_input_requests,
                    mcp_input_responses: &mut mcp_input_responses,
                    pending_mcp_inputs: &mut pending_mcp_inputs,
                    stop_hooks: &mut stop_hooks,
                    settled_rx: &mut settled_rx,
                    to_kernel: &to_kernel,
                    pending_runtime: &mut pending_runtime,
                    control: &mut control,
                    plantcore: &plantcore,
                    workflows: &workflows,
                    processes: &processes,
                    mcp_runtime: &mcp_runtime,
                    operator_status: &operator_status,
                    events: &mut events,
                    deferred: &mut deferred,
                    priority_submissions: &mut priority_submissions,
                    submissions: &mut submissions,
                    live_turn_id,
                    submission_identities: &mut submission_identities,
                    pending_kernel_submissions: &mut pending_kernel_submissions,
                    pending_turns: &mut pending_turns,
                    lifecycle_gate_hooks: &lifecycle_gate_hooks,
                    hook_journal: &hook_journal,
                    hook_cancel: &hook_cancel,
                    drain_signal: &drain_signal,
                }
                .drive(running.as_mut())
                .await
            };
            started = true;

            // The tail. The turn's completion is the synchronisation barrier for the kernel's
            // sender, so deltas emitted between the last `select!` poll and the return are
            // still queued here. Draining before the terminal event is what keeps the
            // transcript ordered.
            while let Ok(runtime_event) = runtime_ui_rx.try_recv() {
                publish_runtime_event(
                    &mut events,
                    &mut pending_kernel_submissions,
                    &frontend_channels,
                    runtime_event,
                )
                .await;
            }
            while let Some(runtime_event) = frontend_channels.try_pop_authoritative() {
                publish_runtime_event(
                    &mut events,
                    &mut pending_kernel_submissions,
                    &frontend_channels,
                    runtime_event,
                )
                .await;
            }
            // The workflow seam drains with it: an in-turn run settles inside the turn, so
            // its terminal rows and its `Finished` are queued here exactly like the last
            // text deltas, and a tail that skipped them would leave the tree spinning.
            while let Ok(progress) = workflow_rx.try_recv() {
                publish_workflow_progress(&mut events, progress).await;
            }
            while let Ok(settled) = settled_rx.try_recv() {
                pending_runtime.push_back(publish_settled(&mut events, settled).await);
            }
            if let Some(observer) = &mut stop_hooks {
                while let Ok(observation) = observer.observations.try_recv() {
                    publish_stop_hook_observation(&mut events, observation).await;
                }
            }

            // The turn's borrow has ended, so the deferred control plane can run — in
            // arrival order, before the snapshot, so the state the frontend receives
            // already reflects everything it asked for during the turn.
            for request in deferred {
                apply_control(
                    &mut agent,
                    session_factory.as_ref(),
                    &workflows,
                    processes.as_ref(),
                    &operator_status,
                    &mut side,
                    &mut started,
                    &mut plantcore,
                    &mut events,
                    request,
                )
                .await;
            }
            operator_status.refresh_runtime(&agent);

            // The run future is complete, so no producer can append another activity for this
            // turn. Merge the bounded channel tail with terminal snapshots retained when that
            // channel saturated, then publish in the runtime's monotonic source order before the
            // authoritative RunEnded barrier. This prevents a stale Finalizing card from
            // reappearing after the frontend has already returned to input-ready.
            let mut activity_tail = activity_overflow.take_pending_snapshots();
            activity_tail.extend(agent.take_pending_activity_terminals());
            while let Ok(event) = activity.try_recv() {
                activity_tail.push(event);
            }
            activity_tail.sort_by_key(|event| event.updated_at_unix_ms);
            for event in activity_tail {
                let _ = events.publish(ServerEvent::Activity(event)).await;
            }

            agent.set_active_product_turn_id(None);
            let mut snapshot = snapshot_of(&mut agent);
            // `snapshot_of` reclaims the bounded kernel inbox after the product epoch is
            // cleared. That reclaim can emit exact-ID SubmissionRejected events, even though
            // the run's ordinary UI tail was already drained above. Publish and settle those
            // before the generic turn-end fallback consumes pending receipts.
            while let Ok(runtime_event) = runtime_ui_rx.try_recv() {
                publish_runtime_event(
                    &mut events,
                    &mut pending_kernel_submissions,
                    &frontend_channels,
                    runtime_event,
                )
                .await;
            }
            while let Some(runtime_event) = frontend_channels.try_pop_authoritative() {
                publish_runtime_event(
                    &mut events,
                    &mut pending_kernel_submissions,
                    &frontend_channels,
                    runtime_event,
                )
                .await;
            }
            discard_expired_product_steers(&mut snapshot, &pending_kernel_submissions);
            settle_kernel_submissions_at_turn_end(
                &mut events,
                &mut pending_kernel_submissions,
                &snapshot.unadmitted_steer_submission_ids,
            )
            .await;
            forward_runtime_notifications(&mut snapshot, &mut pending_runtime);
            let terminal_evidence =
                Some(agent.terminal_diagnostic_snapshot(live_turn_id, &completion));
            let (outcome, mut error) = match completion {
                Ok(outcome) => (outcome, None),
                Err(error) => {
                    let error = error.public_summary();
                    (Outcome::HarnessError, Some(error))
                }
            };
            // A PlantCore result ends its one admitted Run. Close the reversible dispatch gate
            // before any terminal projection so a concurrent resume can never reopen execution
            // after the runtime has already decided the terminal outcome.
            agent.terminalize_plantcore_dispatch_gate();
            let drain_cleanup_failures = if matches!(outcome, Outcome::Drained) {
                clean_session_owned_tools(processes.as_ref(), language_servers.as_ref()).await
            } else {
                Vec::new()
            };
            if !drain_cleanup_failures.is_empty() {
                let detail = drain_cleanup_failures.join("; ");
                error = Some(match error {
                    Some(existing) => format!("{existing}; {detail}"),
                    None => detail,
                });
            }
            if matches!(outcome, Outcome::Drained) {
                expire_pending_turns(&mut events, &mut pending_turns, "drain_settled").await;
                expire_queued_after_drain(&mut events, &mut submissions, &mut priority_submissions)
                    .await;
            }
            turn_lifecycle = match &outcome {
                Outcome::Done => {
                    if cancel_forwarded {
                        events.record_lifecycle(
                            "cancel.failed",
                            Some(live_turn_id),
                            cancel_submission_id,
                            LifecyclePayload {
                                reason_code: Some("turn_completed_first".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                    }
                    turn_lifecycle
                        .transition(TurnLifecycleState::Completed)
                        .expect("running turn completes once")
                }
                Outcome::Interrupted => {
                    session_lifecycle = session_lifecycle
                        .transition(SessionLifecycleState::Cancelling)
                        .expect("an interrupted running session enters cancelling");
                    events.record_lifecycle(
                        "cancel.completed",
                        Some(live_turn_id),
                        cancel_submission_id,
                        LifecyclePayload::default(),
                    );
                    turn_lifecycle
                        .transition(TurnLifecycleState::Cancelling)
                        .and_then(|state| state.transition(TurnLifecycleState::Interrupted))
                        .expect("a running turn cancels exactly once")
                }
                Outcome::Drained => {
                    session_lifecycle = session_lifecycle
                        .transition(SessionLifecycleState::Draining)
                        .expect("a drained running session enters draining");
                    events.record_lifecycle(
                        "drain.settled",
                        Some(live_turn_id),
                        drain_submission_id,
                        LifecyclePayload {
                            count: (!drain_cleanup_failures.is_empty())
                                .then_some(drain_cleanup_failures.len() as u64),
                            reason_code: (!drain_cleanup_failures.is_empty())
                                .then(|| "owned_tool_cleanup_unknown".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    turn_lifecycle
                        .transition(TurnLifecycleState::Cancelling)
                        .and_then(|state| state.transition(TurnLifecycleState::Interrupted))
                        .expect("a drained turn interrupts exactly once")
                }
                Outcome::Stuck | Outcome::BudgetExhausted(_) | Outcome::HarnessError => {
                    if cancel_forwarded {
                        events.record_lifecycle(
                            "cancel.failed",
                            Some(live_turn_id),
                            cancel_submission_id,
                            LifecyclePayload {
                                reason_code: Some("turn_failed".into()),
                                ..LifecyclePayload::default()
                            },
                        );
                        turn_lifecycle = turn_lifecycle
                            .transition(TurnLifecycleState::Cancelling)
                            .expect("a cancellation was forwarded before failure");
                    }
                    turn_lifecycle
                        .transition(TurnLifecycleState::Failed)
                        .expect("running turn fails once")
                }
            };
            run_lifecycle = match &outcome {
                Outcome::Done => run_lifecycle
                    .transition(RunLifecycleState::Completed)
                    .expect("active run completes once"),
                Outcome::Interrupted | Outcome::Drained => run_lifecycle
                    .transition(RunLifecycleState::Cancelling)
                    .and_then(|state| state.transition(RunLifecycleState::Interrupted))
                    .expect("active run interrupts once"),
                Outcome::Stuck | Outcome::BudgetExhausted(_) | Outcome::HarnessError => {
                    if cancel_forwarded {
                        run_lifecycle = run_lifecycle
                            .transition(RunLifecycleState::Cancelling)
                            .expect("a cancellation was forwarded before run failure");
                    }
                    run_lifecycle
                        .transition(RunLifecycleState::Failed)
                        .expect("active run fails once")
                }
            };
            debug_assert!(turn_lifecycle.is_terminal());
            debug_assert!(run_lifecycle.is_terminal());
            session_lifecycle = session_lifecycle
                .transition(SessionLifecycleState::Idle)
                .expect("a terminal turn returns its session to idle");
            events.record_lifecycle(
                "session.idle",
                Some(live_turn_id),
                turn_submission_id,
                LifecyclePayload {
                    outcome_code: Some(outcome_name(&outcome).into()),
                    ..LifecyclePayload::default()
                },
            );
            let (memo_hits, memo_misses) = agent.registry.memo_stats();
            let kernel_tax = agent
                .ledger
                .kernel_tax()
                .with_failed_run(!matches!(outcome, Outcome::Done | Outcome::Drained));
            let plantcore_runtime = agent.plantcore_runtime_enabled();
            let plantcore_usage_unavailable = agent.plantcore_usage_unavailable();
            let plantcore_harness_error =
                plantcore_runtime && matches!(outcome, Outcome::HarnessError);
            let runtime_product_result = agent.take_product_result();
            // Product data can be prepared before the durability/presentation tail finishes. If
            // that tail changes a would-be success into a harness failure, the typed candidate is
            // no longer terminal truth and must not survive beside a non-done outcome.
            let product_result = matches!(outcome, Outcome::Done)
                .then_some(runtime_product_result)
                .flatten();
            let terminal = if plantcore_usage_unavailable {
                TerminalAuthority::Plantcore(
                    iteron_protocol::PlantcoreTerminalOutcome::UsageUnavailable,
                )
            } else if plantcore_runtime {
                TerminalAuthority::Plantcore(
                    iteron_protocol::PlantcoreTerminalOutcome::from_runtime(
                        outcome,
                        product_result,
                    )
                    .expect("runtime terminal truth is a valid closed PlantCore outcome"),
                )
            } else {
                TerminalAuthority::Runtime(outcome)
            };
            let summary = TerminalSummary {
                terminal,
                terminal_evidence,
                assistant_text: agent.last_assistant_text().to_owned(),
                v7_assistant_text: (agent.run_assistant_text() != agent.last_assistant_text())
                    .then(|| agent.run_assistant_text().to_owned()),
                run_id: agent.rollout.run_id().to_string(),
                cost: agent.ledger.cost_state(),
                turns: agent.ledger.turns,
                kernel_tax,
                error,
                memo_hits,
                memo_misses,
            };
            // Reconcile bounded observations from the actual record owner after the Agent borrow
            // ends. Presentation saturation cannot turn an already confirmed Done into failure.
            events.contract.bind_artifact_owner(&agent);
            if events
                .publish(ServerEvent::RunEnded {
                    snapshot: Box::new(snapshot),
                    summary: Box::new(summary),
                })
                .await
                .is_err()
            {
                events.record_lifecycle(
                    "session.failed",
                    Some(live_turn_id),
                    turn_submission_id,
                    LifecyclePayload {
                        reason_code: Some("terminal_event_delivery_closed".into()),
                        ..LifecyclePayload::default()
                    },
                );
                break;
            }
            if plantcore_harness_error {
                break;
            }
            // Input is genuinely ready only after the authoritative terminal crossed the EQ.
            // Provider admission used to emit this semantic before a request even started, which
            // made a busy session look idle and erased the finalization tail.
            let _ = events
                .publish(ServerEvent::Activity(input_ready_activity(live_turn_id)))
                .await;
        }

        // SESSION EXIT, POSSIBLY WITH A RUN STILL LIVE.
        //
        // The three candidate policies were: refuse to exit, kill, or let it finish alone. The
        // third is not available and saying otherwise would be a lie — a workflow run is an OS
        // thread inside THIS process, so "detached" has never meant "survives the process". The
        // first turns one wedged script into an unquittable session. So: cancel, wait a bounded
        // grace for the engine's own safe point, and write the terminal record either way, so no
        // run is left listing as `running` forever. The operator is told twice — the receipt the
        // model got stated this exact rule up front, and the report below names every run that was
        // stopped together with the `iteron workflow resume` that continues it.
        //
        // This runs on EVERY exit from the loop above, which is what makes "the session cannot end
        // with a run it does not account for" a property of the type rather than of a call site.
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Stopping)
            .unwrap_or(SessionLifecycleState::Stopping);
        mcp_input::reject_all(&mut pending_mcp_inputs);
        events.record_lifecycle("session.stopping", None, None, LifecyclePayload::default());
        let shell_cleanup_observed = events.contract.shutdown_shell().await;
        let init_settlement_observed = events.contract.shutdown_project_init().await;
        let preference_settlement_observed = events.contract.shutdown_model_preferences().await;
        let workspace_read_observed = events.contract.shutdown_workspace_reads().await;
        let lab_observed = events.contract.shutdown_lab().await;
        let completion_observed = events.contract.shutdown_path_completions().await;
        let stop_hook_shutdown_error = if let Some(observer) = stop_hooks.take() {
            match observer.shutdown().await {
                Ok(observations) => {
                    for observation in observations {
                        publish_stop_hook_observation(&mut events, observation).await;
                    }
                    None
                }
                Err(reason) => {
                    events.record_lifecycle(
                        "hook.failed",
                        None,
                        None,
                        LifecyclePayload {
                            reason_code: Some("stop_cleanup_unproven".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    Some(reason.to_owned())
                }
            }
        } else {
            None
        };
        let mut report = workflows
            .shutdown(
                &mut settled_rx,
                iteron_tunables::param_duration(
                    "cli.workflow.shutdown_grace",
                    crate::workflow::SHUTDOWN_GRACE,
                ),
            )
            .await;
        if !shell_cleanup_observed {
            report.lines.push(
                "operator shell cleanup remains unobserved; no successful join is claimed".into(),
            );
        }
        if !init_settlement_observed {
            report.lines.push("project initialization publication remains unobserved; no completed worker is claimed".into());
        }
        if !preference_settlement_observed {
            report
                .lines
                .push("model default configuration write remains unobserved".into());
        }
        if !workspace_read_observed {
            report
                .lines
                .push("workspace source read remains unobserved".into());
        }
        if !lab_observed {
            report
                .lines
                .push("offline lab physical work or publication remains unobserved".into());
        }
        if !completion_observed {
            report
                .lines
                .push("file completion read remains unobserved".into());
        }
        if let Some(reason) = stop_hook_shutdown_error {
            report.lines.push(reason);
        }
        report
            .lines
            .extend(clean_session_owned_tools(processes.as_ref(), language_servers.as_ref()).await);
        if let Some(mut side) = side.take()
            && let Err(error) = side.finalize_policy_run()
        {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("side_policy_run_terminal_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report.lines.push(error.public_summary());
        }
        if let Err(error) = agent.finalize_policy_run() {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("policy_run_terminal_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report.lines.push(error.public_summary());
        }
        if agent.has_memory_benchmark_scope() {
            events.record_lifecycle(
                "memory.benchmark.scope_destroyed",
                None,
                None,
                LifecyclePayload::default(),
            );
        }
        if agent
            .cleanup_mcp_spills(iteron_mcp::McpSpillCleanup::SessionEnd)
            .await
            .is_err()
        {
            events.record_lifecycle(
                "session.failed",
                None,
                None,
                LifecyclePayload {
                    reason_code: Some("mcp_private_spill_cleanup_failed".into()),
                    ..LifecyclePayload::default()
                },
            );
            report
                .lines
                .push("private MCP spill cleanup failed at session end".into());
        }
        session_lifecycle = session_lifecycle
            .transition(SessionLifecycleState::Stopped)
            .expect("a stopping session publishes one terminal");
        debug_assert!(session_lifecycle.is_terminal());
        events.record_lifecycle("session.stopped", None, None, LifecyclePayload::default());
        // `session.stopped` is synchronously admitted above. Release the ordinary agent/publisher
        // references, then let the runtime atomically close the shared admission state; any leaked
        // dispatcher clone is rejected after that transition and cannot extend the shutdown
        // snapshot. If the configured execution budget expires, the runtime explicitly cancels and
        // settles admitted work before raw task abortion is even eligible.
        drop(agent);
        drop(
            events
                .lifecycle_hooks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        if let Err(error) = lifecycle_hook_runtime.shutdown().await {
            events.record_lifecycle(
                "hook.failed",
                None,
                None,
                LifecyclePayload {
                    count: Some(1),
                    reason_code: Some(error.reason_code().into()),
                    ..LifecyclePayload::default()
                },
            );
            report.lines.push(error.public_summary().into());
        }
        report
    }
}
