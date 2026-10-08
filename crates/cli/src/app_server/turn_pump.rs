//! In-flight turn pump: bounded presentation/control ports and exact cancellation receipts.

use super::{
    Arc, AtomicBool, ControlRequest, EventPublisher, HookExecution, KernelSubmissionKind,
    LifecyclePayload, McpInputResponse, Op, OperatorStatusSources, Ordering, Outcome,
    PROTOCOL_VERSION, PendingKernelSubmission, PlantcoreAdmission, QueuedSubmission, Routed,
    ServerEvent, SubmissionDeduplicator, SubmissionId, SubmissionLifecycleState, TurnId,
    TurnSubmission, apply_immediate_control, expire_pending_turns, is_immediate_control,
    is_plantcore_admitted_control, kernel_submission_kind, legacy_user_prompt_context, mcp_input,
    mpsc, product_turn_accepts, publish_runtime_event, publish_settled,
    publish_stop_hook_observation, publish_submission, publish_workflow_progress, queue_population,
    receive_next_submission, receive_stop_hook_observation, reject_replayed_submission, route,
    run_legacy_hook, run_lifecycle_gate,
};

pub(super) struct RunningTurnPump<'a> {
    pub(super) maintenance: &'a mut super::advisory_maintenance::MaintenanceObserver,
    pub(super) runtime_ui_rx: &'a mut mpsc::Receiver<crate::runtime::RuntimeFrontendEvent>,
    pub(super) frontend_channels: &'a crate::runtime::FrontendChannelHealth,
    pub(super) workflow_rx: &'a mut mpsc::Receiver<crate::workflow::WorkflowRunUiEvent>,
    pub(super) activity: &'a mut mpsc::Receiver<iteron_protocol::ActivityEvent>,
    pub(super) activity_overflow: &'a crate::runtime::turn_activity::ActivitySink,
    pub(super) mcp_input_requests: &'a mut mpsc::Receiver<mcp_input::McpInputRequestEnvelope>,
    pub(super) mcp_input_responses: &'a mut mpsc::Receiver<McpInputResponse>,
    pub(super) pending_mcp_inputs: &'a mut std::collections::BTreeMap<
        u64,
        tokio::sync::oneshot::Sender<iteron_mcp::McpInputDecision>,
    >,
    pub(super) stop_hooks: &'a mut Option<crate::runtime::hooks::StopHookObserverRuntime>,
    pub(super) settled_rx: &'a mut mpsc::Receiver<crate::workflow::RunSettled>,
    pub(super) to_kernel: &'a mpsc::Sender<TurnSubmission>,
    pub(super) pending_runtime: &'a mut std::collections::VecDeque<String>,
    pub(super) control: &'a mut mpsc::Receiver<ControlRequest>,
    pub(super) plantcore: &'a PlantcoreAdmission,
    pub(super) workflows: &'a crate::workflow::WorkflowSupervisor,
    pub(super) processes: &'a Option<iteron_tools::ProcessControl>,
    pub(super) mcp_runtime: &'a Option<crate::mcp::McpRuntimeControl>,
    pub(super) operator_status: &'a OperatorStatusSources,
    pub(super) events: &'a mut EventPublisher,
    pub(super) deferred: &'a mut Vec<ControlRequest>,
    pub(super) priority_submissions: &'a mut mpsc::Receiver<QueuedSubmission>,
    pub(super) submissions: &'a mut mpsc::Receiver<QueuedSubmission>,
    pub(super) live_turn_id: TurnId,
    pub(super) submission_identities: &'a mut SubmissionDeduplicator,
    pub(super) pending_kernel_submissions:
        &'a mut std::collections::VecDeque<PendingKernelSubmission>,
    pub(super) pending_turns: &'a mut std::collections::VecDeque<QueuedSubmission>,
    pub(super) lifecycle_gate_hooks: &'a crate::runtime::hooks::Hooks,
    pub(super) hook_journal: &'a Option<crate::runtime::hooks::journal::HookEffectJournal>,
    pub(super) hook_cancel: &'a Option<Arc<AtomicBool>>,
    pub(super) drain_signal: &'a Arc<AtomicBool>,
}

pub(super) struct TurnCompletion {
    pub(super) completion: Result<Outcome, crate::runtime::KernelError>,
    pub(super) cancel_forwarded: bool,
    pub(super) cancel_submission_id: Option<SubmissionId>,
    pub(super) drain_submission_id: Option<SubmissionId>,
}

impl RunningTurnPump<'_> {
    pub(super) async fn drive<
        F: std::future::Future<Output = Result<Outcome, crate::runtime::KernelError>>,
    >(
        self,
        mut running: std::pin::Pin<&mut F>,
    ) -> TurnCompletion {
        let Self {
            maintenance,
            runtime_ui_rx,
            frontend_channels,
            workflow_rx,
            activity,
            activity_overflow,
            mcp_input_requests,
            mcp_input_responses,
            pending_mcp_inputs,
            stop_hooks,
            settled_rx,
            to_kernel,
            pending_runtime,
            control,
            plantcore,
            workflows,
            processes,
            mcp_runtime,
            operator_status,
            events,
            deferred,
            priority_submissions,
            submissions,
            live_turn_id,
            submission_identities,
            pending_kernel_submissions,
            pending_turns,
            lifecycle_gate_hooks,
            hook_journal,
            hook_cancel,
            drain_signal,
        } = self;
        let mut cancel_forwarded = false;
        let mut cancel_submission_id = None;
        let mut drain_submission_id = None;
        let mut drain_admission_closed = false;
        loop {
            tokio::select! {
                // Independent observers share fair polling with the runtime and its completion.
                // SessionHost drains queued runtime observations after the future completes.
                maintenance_event = maintenance.next() => {
                    events.try_publish_maintenance(maintenance_event);
                }
                Some(runtime_event) = runtime_ui_rx.recv() => {
                    publish_runtime_event(
                        events, pending_kernel_submissions, frontend_channels, runtime_event,
                    ).await;
                }
                runtime_event = frontend_channels.recv_authoritative() => {
                    publish_runtime_event(
                        events, pending_kernel_submissions, frontend_channels, runtime_event,
                    ).await;
                }
                Some(progress) = workflow_rx.recv() => {
                    // Same policy as the UI stream: a frontend that hung up never
                    // aborts a run that is already executing.
                    publish_workflow_progress(events, progress).await;
                }
                Some(activity_event) = activity.recv() => {
                    // Activity is a bounded, content-free snapshot stream. It shares the
                    // EQ ordering/byte budget but never holds up the running turn. Merge any
                    // latest-per-id snapshots retained when the producer channel saturated;
                    // source timestamps preserve order and an older state cannot resurrect.
                    let mut ready = activity_overflow.take_pending_snapshots();
                    ready.push(activity_event);
                    ready.sort_by_key(|event| event.updated_at_unix_ms);
                    for activity_event in ready {
                        let _ = events.publish(ServerEvent::Activity(activity_event)).await;
                    }
                }
                Some(request) = mcp_input_requests.recv() => {
                    mcp_input::publish_request(
                        request,
                        pending_mcp_inputs,
                        events,
                    ).await;
                }
                Some(response) = mcp_input_responses.recv() => {
                    if !mcp_input::resolve_response(response, pending_mcp_inputs) {
                        let _ = events.publish(ServerEvent::Notice(
                            "stale MCP input response was refused".into(),
                        )).await;
                    }
                }
                Some(observation) = receive_stop_hook_observation(stop_hooks) => {
                    publish_stop_hook_observation(events, observation).await;
                }
                Some(settled) = settled_rx.recv() => {
                    // A run detached by an EARLIER turn can settle during this one.
                    // Its terminal row belongs in the transcript at the moment it
                    // happened, not at the end of whatever turn is running.
                    let notification = publish_settled(events, settled).await;
                    if to_kernel
                        .try_send(TurnSubmission::current(Op::Steer {
                            text: notification.clone(),
                        }))
                        .is_err()
                    {
                        // Preserve the model-facing terminal notification outside the
                        // saturated bridge. It becomes the next runtime-triggered turn.
                        pending_runtime.push_back(notification);
                    }
                }
                Some(request) = control.recv() => {
                    if is_immediate_control(&request.control)
                        && (!plantcore.is_enabled()
                            || is_plantcore_admitted_control(&request.control))
                    {
                        apply_immediate_control(
                            workflows,
                            processes.as_ref(),
                            mcp_runtime.as_ref(),
                            operator_status,
                            events,
                            request,
                        ).await;
                        continue;
                    }
                    // Configuration DURING a turn is DEFERRED, not applied.
                    //
                    // The borrow checker says so and it is right: the turn holds
                    // `&mut agent` for its whole duration, so there is no instant
                    // at which a mutation could be applied without interleaving it
                    // into the turn's own state. The old design got this ordering
                    // for free — the frontend's `Option<Agent>` was empty while
                    // running, so `/model` and `/effort` were structurally
                    // unreachable — and lost the reason along with the `Option`.
                    //
                    // Deferring makes the same guarantee an explicit decision:
                    // requests are applied at the turn boundary, in arrival order,
                    // and the operator's answer arrives when it is true rather
                    // than when it was asked.
                    deferred.push(request);
                }
                Some(queued) = receive_next_submission(
                    priority_submissions,
                    submissions,
                ) => {
                    events.record_lifecycle(
                        "queue.depth_changed",
                        Some(live_turn_id),
                        None,
                        LifecyclePayload {
                            count: Some(queue_population(
                                submissions,
                                priority_submissions,
                                pending_turns.len(),
                            )),
                            ..LifecyclePayload::default()
                        },
                    );
                    let version = queued.envelope.protocol_version;
                    let submission_id = queued.envelope.submission_id;
                    if version != PROTOCOL_VERSION {
                        publish_submission(
                            events,
                            submission_id,
                            SubmissionLifecycleState::Rejected,
                            Some("protocol_version_mismatch"),
                        ).await;
                        continue;
                    }
                        if reject_replayed_submission(
                            events,
                            submission_identities,
                            submission_id,
                            Some(live_turn_id),
                        ).await {
                            continue;
                        }
                        publish_submission(
                            events,
                            submission_id,
                            SubmissionLifecycleState::Received,
                            None,
                        ).await;
                        if !product_turn_accepts(
                            queued.envelope.expected_product_turn_id,
                            &events.contract,
                        ) {
                            publish_submission(
                                events,
                                submission_id,
                                SubmissionLifecycleState::Rejected,
                                Some("turn_mismatch_or_terminal"),
                            ).await;
                            continue;
                        }
                        let op = &queued.envelope.op;
                        if drain_admission_closed
                            && matches!(
                                op,
                                Op::UserInput { .. }
                                    | Op::UserInputV2 { .. }
                                    | Op::UserInputV3 { .. }
                            )
                        {
                            publish_submission(
                                events,
                                submission_id,
                                SubmissionLifecycleState::Expired,
                                Some("drain_requested"),
                            )
                            .await;
                            continue;
                        }
                        if let Some(context) = legacy_user_prompt_context(op, submission_id) {
                            run_legacy_hook(
                                HookExecution {
                                    hooks: lifecycle_gate_hooks,
                                    journal: hook_journal.as_ref(),
                                    events,
                                    cancel: hook_cancel.as_deref(),
                                    drain: Some(drain_signal.as_ref()),
                                },
                                crate::runtime::hooks::HookEvent::UserPromptSubmit,
                                Some(submission_id),
                                Some(live_turn_id),
                                context,
                            ).await;
                        }
                        let gate_event = match &op {
                            Op::Steer { .. } => Some("steer.requested"),
                            Op::UserInput { .. }
                            | Op::UserInputV2 { .. }
                            | Op::UserInputV3 { .. } => Some("submission.created"),
                            Op::ApprovalResponse { .. }
                            | Op::Interrupt
                            | Op::ForceCancel
                            | Op::Drain
                            | Op::Unknown => None,
                        };
                        if let Some(gate_event) = gate_event
                            && let Err(reason) = run_lifecycle_gate(
                                HookExecution {
                                    hooks: lifecycle_gate_hooks,
                                    journal: hook_journal.as_ref(),
                                    events,
                                    cancel: hook_cancel.as_deref(),
                                    drain: Some(drain_signal.as_ref()),
                                },
                                gate_event,
                                submission_id,
                                Some(live_turn_id),
                            ).await
                        {
                                publish_submission(
                                    events,
                                    submission_id,
                                    SubmissionLifecycleState::Rejected,
                                    Some("hook_blocked"),
                                ).await;
                                if matches!(op, Op::Steer { .. }) {
                                    events.record_lifecycle(
                                        "steer.rejected",
                                        Some(live_turn_id),
                                        Some(submission_id),
                                        LifecyclePayload {
                                            reason_code: Some("hook_blocked".into()),
                                            ..LifecyclePayload::default()
                                        },
                                    );
                                }
                                let _ = events.publish(ServerEvent::Notice(reason)).await;
                                continue;
                        }
                        if matches!(op, Op::ForceCancel)
                            && let Some(observer) = &stop_hooks
                        {
                            observer.dispatcher.cancel_active();
                        }
                        match &op {
                            Op::Interrupt => events.record_lifecycle(
                                "cancel.received",
                                Some(live_turn_id),
                                Some(submission_id),
                                LifecyclePayload::default(),
                            ),
                            Op::ForceCancel => events.record_lifecycle(
                                "cancel.forced",
                                Some(live_turn_id),
                                Some(submission_id),
                                LifecyclePayload::default(),
                            ),
                            Op::Drain => {
                                drain_admission_closed = true;
                                events.record_lifecycle(
                                    "drain.requested",
                                    Some(live_turn_id),
                                    Some(submission_id),
                                    LifecyclePayload::default(),
                                );
                            }
                            _ => {}
                        }
                        match route(op) {
                            Routed::StartTurn(_) => {
                                publish_submission(
                                    events,
                                    submission_id,
                                    SubmissionLifecycleState::Requeued,
                                    Some("turn_safe_point"),
                                ).await;
                                publish_submission(
                                    events,
                                    submission_id,
                                    SubmissionLifecycleState::Enqueued,
                                    None,
                                ).await;
                                pending_turns.push_back(queued);
                            }
                            Routed::ToKernel => {
                                let envelope = queued.into_envelope();
                                let expected_product_turn_id = envelope.expected_product_turn_id;
                                let (_, op) = envelope
                                    .into_current_identified()
                                    .expect("the protocol version was checked above");
                                if matches!(&op, Op::Steer { text } if text.trim().is_empty()) {
                                    publish_submission(
                                        events,
                                        submission_id,
                                        SubmissionLifecycleState::Rejected,
                                        Some("empty_steer"),
                                    )
                                    .await;
                                    continue;
                                }
                                publish_submission(
                                    events,
                                    submission_id,
                                    SubmissionLifecycleState::Admitted,
                                    None,
                                ).await;
                                let kind = kernel_submission_kind(&op);
                                let forced = matches!(op, Op::ForceCancel);
                                let mut kernel_envelope = TurnSubmission::with_version_and_id(
                                    version,
                                    submission_id,
                                    op,
                                );
                                kernel_envelope.expected_product_turn_id = expected_product_turn_id;
                                let kernel_send = to_kernel.try_send(kernel_envelope);
                                if let Err(error) = kernel_send {
                                    let reason = match error {
                                        mpsc::error::TrySendError::Full(_) => {
                                            "runtime_queue_saturated"
                                        }
                                        mpsc::error::TrySendError::Closed(_) => {
                                            "runtime_disconnected"
                                        }
                                    };
                                    publish_submission(
                                        events,
                                        submission_id,
                                        SubmissionLifecycleState::Rejected,
                                        Some(reason),
                                    ).await;
                                    match kind {
                                        Some(KernelSubmissionKind::Steer) => events.record_lifecycle(
                                            "steer.rejected",
                                            Some(live_turn_id),
                                            Some(submission_id),
                                            LifecyclePayload {
                                                reason_code: Some(reason.into()),
                                                ..LifecyclePayload::default()
                                            },
                                        ),
                                        Some(KernelSubmissionKind::Interrupt) => events.record_lifecycle(
                                            "cancel.failed",
                                            Some(live_turn_id),
                                            Some(submission_id),
                                            LifecyclePayload {
                                                reason_code: Some(reason.into()),
                                                ..LifecyclePayload::default()
                                            },
                                        ),
                                        _ => {}
                                    }
                                } else if let Some(kind) = kind {
                                    // The ordered SQ receipt is the typed cancellation
                                    // authority, but the kernel cannot drain that queue
                                    // while it is awaiting provider I/O. Raise the exact
                                    // session-owned signal only after the receipt reaches
                                    // the kernel queue so headless clients get the same
                                    // bounded wake-up as the TUI's eager keyboard path.
                                    match kind {
                                        KernelSubmissionKind::Interrupt => {
                                            if let Some(interrupt) = &hook_cancel {
                                                interrupt.store(true, Ordering::SeqCst);
                                            }
                                        }
                                        KernelSubmissionKind::Drain => {
                                            drain_signal.store(true, Ordering::SeqCst);
                                        }
                                        KernelSubmissionKind::Steer
                                        | KernelSubmissionKind::Approval => {}
                                    }
                                    match kind {
                                        KernelSubmissionKind::Steer => events.record_lifecycle(
                                            "steer.admitted",
                                            Some(live_turn_id),
                                            Some(submission_id),
                                            LifecyclePayload::default(),
                                        ),
                                        KernelSubmissionKind::Interrupt => {
                                            cancel_forwarded = true;
                                            cancel_submission_id = Some(submission_id);
                                            if !forced {
                                                events.record_lifecycle(
                                                    "cancel.cooperative",
                                                    Some(live_turn_id),
                                                    Some(submission_id),
                                                    LifecyclePayload::default(),
                                                );
                                            }
                                        }
                                        KernelSubmissionKind::Drain => {
                                            drain_submission_id = Some(submission_id);
                                        }
                                        KernelSubmissionKind::Approval => {}
                                    }
                                    pending_kernel_submissions.push_back(PendingKernelSubmission {
                                        id: submission_id,
                                        kind,
                                        expected_product_turn_id,
                                    });
                                    if matches!(kind, KernelSubmissionKind::Drain) {
                                        expire_pending_turns(
                                            events,
                                            pending_turns,
                                            "drain_requested",
                                        )
                                        .await;
                                    }
                                }
                            }
                            Routed::Refuse(why) => {
                                publish_submission(
                                    events,
                                    submission_id,
                                    SubmissionLifecycleState::Rejected,
                                    Some("unsupported_operation"),
                                ).await;
                                let _ = events.publish(ServerEvent::Notice(why.to_owned())).await;
                            }
                        }
                }
                outcome = &mut running => break TurnCompletion { completion: outcome, cancel_forwarded, cancel_submission_id, drain_submission_id },
            }
        }
    }
}
