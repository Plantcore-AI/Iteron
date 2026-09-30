//! Versioned bounded SQ client, submission identity observations and queue accounting.

use super::*;

/// Why a submission did not reach the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubmitError {
    /// The server is gone: the run task that owned the receiver has ended.
    Disconnected,
    /// The queue is full. The operation was NOT accepted and must not be assumed applied.
    Busy,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str(
                "the App Server submission queue is closed; the runtime is no longer reachable",
            ),
            Self::Busy => formatter.write_str(
                "the App Server submission queue is full; the runtime has not accepted this operation",
            ),
        }
    }
}

impl std::error::Error for SubmitError {}

/// A version-negotiated client of the runtime App Server.
///
/// The client cannot be constructed without a completed handshake, so a version-skewed frontend can
/// never obtain a handle it would use to push envelopes the server rejects.
#[derive(Debug, Clone)]
pub(crate) struct AppServerClient {
    pub(super) submissions: SubmissionSender,
    pub(super) negotiated_version: u32,
    pub(super) next_submission_id: Arc<AtomicU64>,
    pub(super) lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    pub(super) lifecycle_hooks: LifecycleHookRoute,
    pub(super) lifecycle_session_id: Option<SessionId>,
    pub(super) lifecycle_run_id: Option<RunId>,
    pub(super) contract: product_contract::ContractReader,
}

#[derive(Debug, Clone)]
pub(super) enum SubmissionSender {
    /// Test-only bare wires keep the existing constructor usable by frontend submission tests.
    #[cfg(test)]
    Bare(mpsc::Sender<TurnSubmission>),
    /// Production wires charge every queued submission against the shared heap budget.
    Weighted {
        sender: mpsc::Sender<QueuedSubmission>,
        priority_sender: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        data_slots: Arc<Semaphore>,
        priority_slots: Arc<Semaphore>,
    },
}

/// One weighted SQ entry. Permits are released only when the server consumes or drops the item;
/// moving it into the safe-point queue retains both bounds.
#[derive(Debug)]
pub(crate) struct QueuedSubmission {
    pub(super) envelope: TurnSubmission,
    pub(super) _memory: OwnedSemaphorePermit,
    /// Retained across server-side requeue. Channel capacity alone is not a bound once an item has
    /// been dequeued, so this permit keeps data and priority populations independently bounded.
    pub(super) _slot: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KernelSubmissionKind {
    Steer,
    Interrupt,
    Drain,
    Approval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingKernelSubmission {
    pub(super) id: SubmissionId,
    pub(super) kind: KernelSubmissionKind,
    pub(super) expected_product_turn_id: Option<iteron_protocol::product_contract::ProductTurnId>,
}

const SUBMISSION_DEDUP_WINDOW: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmissionIdentityAdmission {
    Fresh,
    Duplicate,
    Stale,
}

/// Bounded replay protection for the SQ. Client clones may allocate IDs concurrently and enqueue
/// them out of numeric order, so a simple high-water mark would reject valid work. The live window
/// accepts that reordering; once its smallest IDs retire, replay at or below that floor is stale.
#[derive(Debug, Default)]
pub(super) struct SubmissionDeduplicator {
    pub(super) live: std::collections::BTreeSet<u64>,
    pub(super) retired_through: u64,
}

impl SubmissionDeduplicator {
    pub(super) fn admit(&mut self, id: SubmissionId) -> SubmissionIdentityAdmission {
        if id.0 == 0 || id.0 <= self.retired_through {
            return SubmissionIdentityAdmission::Stale;
        }
        if !self.live.insert(id.0) {
            return SubmissionIdentityAdmission::Duplicate;
        }
        if self.live.len()
            > iteron_tunables::param_integer(
                "cli.app_server.submission_dedup_window",
                SUBMISSION_DEDUP_WINDOW,
            )
            && let Some(oldest) = self.live.pop_first()
        {
            self.retired_through = self.retired_through.max(oldest);
        }
        SubmissionIdentityAdmission::Fresh
    }
}

pub(super) fn kernel_submission_kind(op: &Op) -> Option<KernelSubmissionKind> {
    match op {
        Op::Steer { .. } => Some(KernelSubmissionKind::Steer),
        Op::Interrupt | Op::ForceCancel => Some(KernelSubmissionKind::Interrupt),
        Op::Drain => Some(KernelSubmissionKind::Drain),
        Op::ApprovalResponse { .. } => Some(KernelSubmissionKind::Approval),
        Op::UserInput { .. } | Op::UserInputV2 { .. } | Op::UserInputV3 { .. } | Op::Unknown => {
            None
        }
    }
}

pub(super) fn is_priority_submission(op: &Op) -> bool {
    matches!(
        op,
        Op::Steer { .. }
            | Op::Interrupt
            | Op::ForceCancel
            | Op::Drain
            | Op::ApprovalResponse { .. }
    )
}

impl QueuedSubmission {
    pub(super) fn into_envelope(self) -> TurnSubmission {
        self.envelope
    }
}

impl AppServerClient {
    pub(super) fn emit_lifecycle(
        &self,
        event_name: &str,
        mut correlation: iteron_obs::lifecycle::LifecycleCorrelation,
        payload: LifecyclePayload,
    ) {
        correlation
            .session_id
            .clone_from(&self.lifecycle_session_id);
        correlation.run_id.clone_from(&self.lifecycle_run_id);
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload) {
            dispatch_lifecycle_hook(&self.lifecycle_hooks, event);
        }
    }

    pub(super) fn bind_lifecycle_identity(&mut self, session_id: SessionId, run_id: RunId) {
        self.contract
            .bind_identity(session_id.clone(), run_id.clone());
        self.lifecycle_session_id = Some(session_id);
        self.lifecycle_run_id = Some(run_id);
    }

    pub(super) fn queue_depth(&self) -> usize {
        match &self.submissions {
            #[cfg(test)]
            SubmissionSender::Bare(sender) => {
                sender.max_capacity().saturating_sub(sender.capacity())
            }
            SubmissionSender::Weighted {
                sender,
                priority_sender,
                ..
            } => sender
                .max_capacity()
                .saturating_sub(sender.capacity())
                .saturating_add(
                    priority_sender
                        .max_capacity()
                        .saturating_sub(priority_sender.capacity()),
                ),
        }
    }

    /// Complete a versioned handshake with a server advertising `server_version`.
    ///
    /// This is the ONLY constructor. An earlier version also offered `current()`, which stamped
    /// `PROTOCOL_VERSION` without checking anything on the ground that the in-process runtime
    /// "speaks the frontend's own version by construction" — true only for as long as the runtime
    /// stays in-process, which is precisely what this module ends. Skew is refused up front, not
    /// discovered one rejected submission at a time.
    #[cfg(test)]
    pub(crate) fn connect(
        server_version: u32,
        submissions: mpsc::Sender<TurnSubmission>,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_to(
            server_version,
            SubmissionSender::Bare(submissions),
            iteron_obs::lifecycle::LifecycleEmitter::new(
                iteron_obs::lifecycle::LifecycleBus::default(),
            ),
            Arc::new(std::sync::Mutex::new(None)),
        )
    }

    #[cfg(test)]
    pub(super) fn connect_weighted(
        server_version: u32,
        submissions: mpsc::Sender<QueuedSubmission>,
        priority_submissions: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_weighted_with_policy(
            server_version,
            submissions,
            priority_submissions,
            budget,
            lifecycle,
            AppServerQueuePolicy::owner(),
            Arc::new(std::sync::Mutex::new(None)),
        )
    }

    pub(super) fn connect_weighted_with_policy(
        server_version: u32,
        submissions: mpsc::Sender<QueuedSubmission>,
        priority_submissions: mpsc::Sender<QueuedSubmission>,
        budget: Arc<Semaphore>,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        queue_policy: AppServerQueuePolicy,
        lifecycle_hooks: LifecycleHookRoute,
    ) -> Result<Self, ProtocolVersionError> {
        Self::connect_to(
            server_version,
            SubmissionSender::Weighted {
                sender: submissions,
                priority_sender: priority_submissions,
                budget,
                data_slots: Arc::new(Semaphore::new(queue_policy.data_entries())),
                priority_slots: Arc::new(Semaphore::new(queue_policy.priority_entries())),
            },
            lifecycle,
            lifecycle_hooks,
        )
    }

    pub(super) fn connect_to(
        server_version: u32,
        submissions: SubmissionSender,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        lifecycle_hooks: LifecycleHookRoute,
    ) -> Result<Self, ProtocolVersionError> {
        if server_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: server_version,
            });
        }
        Ok(Self {
            submissions,
            negotiated_version: server_version,
            next_submission_id: Arc::new(AtomicU64::new(1)),
            lifecycle,
            lifecycle_hooks,
            lifecycle_session_id: None,
            lifecycle_run_id: None,
            contract: product_contract::ContractReader::default(),
        })
    }

    /// The same bounded Thread/Turn/Item projection used by the interactive and headless clients.
    pub(crate) fn thread_snapshot_v1(
        &self,
    ) -> Option<iteron_protocol::product_contract::ThreadSnapshotV1> {
        self.contract.snapshot()
    }

    pub(crate) fn product_events_read_v1(
        &self,
        after: u64,
    ) -> Option<
        Result<
            iteron_protocol::product_contract::ProductEventsPageV1,
            iteron_protocol::product_contract::ProductEventsReadErrorV1,
        >,
    > {
        self.contract.events_read(after)
    }

    pub(crate) fn product_terminal_diagnostics_v1(
        &self,
        turn_id: iteron_protocol::product_contract::ProductTurnId,
    ) -> Option<iteron_protocol::product_contract::ProductTerminalDiagnosticsV1> {
        self.contract.terminal_diagnostics(turn_id)
    }

    pub(crate) fn product_approval_prompt_complete_v1(&self, id: SubmissionId) -> bool {
        self.contract.approval_prompt_complete(id)
    }

    #[cfg(test)]
    pub(crate) fn seed_contract_identity_for_test(&self, thread_id: SessionId, run_id: RunId) {
        self.contract.bind_identity(thread_id, run_id);
    }

    #[cfg(test)]
    pub(crate) fn observe_contract_event_for_test(&self, seq: u64, event: &ServerEvent) {
        self.contract.observe(seq, event);
    }

    #[cfg(test)]
    pub(crate) fn seed_contract_turn_for_test(
        &self,
        thread_id: SessionId,
        run_id: RunId,
        turn_id: iteron_protocol::product_contract::ProductTurnId,
    ) {
        self.contract.bind_identity(thread_id, run_id.clone());
        self.contract.begin_turn(run_id, turn_id, None);
    }

    pub(crate) fn artifacts_v1(
        &self,
        command: iteron_protocol::client_artifact::ClientArtifactCommandV1,
    ) -> serde_json::Value {
        self.contract.artifacts_v1(command)
    }

    /// The protocol version agreed during the handshake and stamped on every submission.
    #[cfg(test)]
    pub(crate) fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Submit one operation, stamped with the negotiated protocol version.
    ///
    /// Never blocks: a full queue is reported as [`SubmitError::Busy`] so the render loop keeps
    /// running and the operator learns their input did not land.
    pub(crate) fn submit(&self, op: Op) -> Result<(), SubmitError> {
        self.submit_identified(op).map(|_| ())
    }

    /// Submit and return the identity that every receipt/application event will carry.
    pub(crate) fn submit_identified(&self, op: Op) -> Result<SubmissionId, SubmitError> {
        self.submit_identified_with_turn(op, None)
    }

    pub(crate) fn submit_identified_for_turn(
        &self,
        op: Op,
        turn_id: iteron_protocol::product_contract::ProductTurnId,
    ) -> Result<SubmissionId, SubmitError> {
        self.submit_identified_with_turn(op, Some(turn_id))
    }

    pub(super) fn submit_identified_with_turn(
        &self,
        op: Op,
        expected_product_turn_id: Option<iteron_protocol::product_contract::ProductTurnId>,
    ) -> Result<SubmissionId, SubmitError> {
        use mpsc::error::TrySendError;
        let id = SubmissionId(
            self.next_submission_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| SubmitError::Busy)?,
        );
        let requested_event = match &op {
            Op::Steer { .. } => Some("steer.requested"),
            Op::Interrupt | Op::ForceCancel => Some("cancel.requested"),
            Op::Drain => Some("drain.requested"),
            _ => None,
        };
        let mut envelope = TurnSubmission::with_version_and_id(self.negotiated_version, id, op);
        envelope.expected_product_turn_id = expected_product_turn_id;
        let correlation = iteron_obs::lifecycle::LifecycleCorrelation {
            submission_id: Some(id),
            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
        };
        self.emit_lifecycle(
            "submission.created",
            correlation.clone(),
            LifecyclePayload::default(),
        );
        if let Some(event_id) = requested_event {
            self.emit_lifecycle(event_id, correlation.clone(), LifecyclePayload::default());
        }
        let result = match &self.submissions {
            #[cfg(test)]
            SubmissionSender::Bare(submissions) => {
                submissions.try_send(envelope).map_err(|error| match error {
                    TrySendError::Full(_) => SubmitError::Busy,
                    TrySendError::Closed(_) => SubmitError::Disconnected,
                })
            }
            SubmissionSender::Weighted {
                sender,
                priority_sender,
                budget,
                data_slots,
                priority_slots,
            } => (|| {
                let priority = is_priority_submission(&envelope.op);
                let selected = if priority { priority_sender } else { sender };
                let slots = if priority { priority_slots } else { data_slots };
                if selected.is_closed() {
                    return Err(SubmitError::Disconnected);
                }
                let weight = u32::try_from(submission_weight(&envelope.op))
                    .map_err(|_| SubmitError::Busy)?;
                let slot = slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| SubmitError::Busy)?;
                let permit = budget
                    .clone()
                    .try_acquire_many_owned(weight)
                    .map_err(|_| SubmitError::Busy)?;
                selected
                    .try_send(QueuedSubmission {
                        envelope,
                        _memory: permit,
                        _slot: slot,
                    })
                    .map_err(|error| match error {
                        TrySendError::Full(_) => SubmitError::Busy,
                        TrySendError::Closed(_) => SubmitError::Disconnected,
                    })
            })(),
        };
        match result {
            Ok(()) => {
                self.emit_lifecycle(
                    "submission.enqueued",
                    correlation.clone(),
                    LifecyclePayload::default(),
                );
                self.emit_lifecycle(
                    "queue.depth_changed",
                    correlation,
                    LifecyclePayload {
                        count: Some(u64::try_from(self.queue_depth()).unwrap_or(u64::MAX)),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(id)
            }
            Err(error) => {
                let reason = match &error {
                    SubmitError::Busy => "queue_full",
                    SubmitError::Disconnected => "runtime_disconnected",
                };
                self.emit_lifecycle(
                    "submission.rejected",
                    correlation,
                    LifecyclePayload {
                        reason_code: Some(reason.into()),
                        ..LifecyclePayload::default()
                    },
                );
                if matches!(&error, SubmitError::Busy) {
                    self.emit_lifecycle(
                        "queue.overflow",
                        iteron_obs::lifecycle::LifecycleCorrelation {
                            submission_id: Some(id),
                            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
                        },
                        LifecyclePayload {
                            count: Some(u64::try_from(self.queue_depth()).unwrap_or(u64::MAX)),
                            ..LifecyclePayload::default()
                        },
                    );
                }
                Err(error)
            }
        }
    }
}

/// Heap bytes charged to a queued operation.
///
/// The fixed charge covers bounded container/allocation overhead. Every variable-size text and
/// encoded-image allocation visible through `Op` is then charged at its actual byte length.
pub(super) fn submission_weight(op: &Op) -> usize {
    let variable_bytes = match op {
        Op::UserInput { text } | Op::Steer { text } => text.len(),
        Op::UserInputV2 { segments } => {
            segments
                .as_slice()
                .iter()
                .fold(0usize, |bytes, segment| match segment {
                    iteron_protocol::ContentSegment::Text { text } => {
                        bytes.saturating_add(text.len())
                    }
                    iteron_protocol::ContentSegment::Image { image } => {
                        bytes.saturating_add(image.data.encoded_len())
                    }
                    iteron_protocol::ContentSegment::Unknown => bytes,
                })
        }
        // Same rule as the segment list above: every variable-size allocation `Op` exposes is
        // charged at its actual byte length, so a queue full of file chips is bounded in bytes and
        // not merely in entries.
        Op::UserInputV3 {
            text,
            images,
            files,
        } => images
            .iter()
            .fold(text.len(), |bytes, image| {
                bytes.saturating_add(image.data.encoded_len())
            })
            .saturating_add(files.iter().fold(0usize, |bytes, file| {
                bytes
                    .saturating_add(file.path.len())
                    .saturating_add(file.text.len())
            })),
        Op::ApprovalResponse { .. } | Op::Interrupt | Op::ForceCancel | Op::Drain | Op::Unknown => {
            0
        }
    };
    iteron_tunables::param_integer(
        "cli.app_server.sq_entry_overhead_bytes",
        SQ_ENTRY_OVERHEAD_BYTES,
    )
    .saturating_add(variable_bytes)
}
