use super::*;

/// Retain at most one UTF-8 scalar beyond the interrupted-stream display limit. That extra
/// scalar lets `strict_utf8_head` mark truncation without buffering an unbounded provider stream.
pub(super) fn append_interrupted_stream_head(buffer: &mut String, delta: &str, max_bytes: usize) {
    let capacity = max_bytes.saturating_add(4);
    if buffer.len() >= capacity {
        return;
    }
    let mut end = delta.len().min(capacity - buffer.len());
    while end > 0 && !delta.is_char_boundary(end) {
        end -= 1;
    }
    buffer.push_str(&delta[..end]);
}

/// Lifecycle log/span count recorded in the export audit when the payload carries no lifecycle
/// snapshot at all, so the audit argument stays present and content-free.
const ABSENT_LIFECYCLE_COUNT: usize = 0;

pub(super) use super::effect_journal_owner::UnknownCause;

impl Agent {
    /// Admit the compatibility Stop hook to the session-owned observer without putting arbitrary
    /// operator code between AnswerComplete and RunEnded/InputReady. The activity start is emitted
    /// synchronously before this method returns; execution and terminal diagnostics are owned by
    /// the resident AppServer worker.
    pub(super) fn queue_stop_hook(&mut self, turn: TurnId, context_json: &str) {
        let (dispatch, identity) = self.hooks.dispatch_stop(turn, context_json);
        match (dispatch, identity) {
            (hooks::StopHookDispatch::Queued, Some(identity)) => {
                self.activity
                    .emit(identity.activity(iteron_protocol::ActivityState::Running));
                self.lifecycle_event("hook.matched", Some(turn), LifecyclePayload::default());
                self.lifecycle_event(
                    "hook.started",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some("compatibility_stop_observer".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
            (hooks::StopHookDispatch::Disabled, None) => {}
            (reason, _) => {
                let reason_code = match reason {
                    hooks::StopHookDispatch::Saturated => "stop_observer_queue_saturated",
                    hooks::StopHookDispatch::Closed => "stop_observer_closed",
                    hooks::StopHookDispatch::ContextTooLarge => "stop_context_too_large",
                    hooks::StopHookDispatch::Disabled | hooks::StopHookDispatch::Queued => {
                        "stop_observer_invalid_receipt"
                    }
                };
                self.lifecycle_event(
                    "hook.failed",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some(reason_code.into()),
                        ..LifecyclePayload::default()
                    },
                );
                let notice_visible = self.ui(UiEvent::Notice(format!(
                    "Stop hook observer did not start ({reason_code}); the completed answer is unaffected"
                )));
                if !notice_visible {
                    // Stop is observational and is deliberately admitted only after the answer's
                    // durable terminal. It cannot retroactively fail that answer. Consume the
                    // generic structural latch here and leave explicit lifecycle evidence instead,
                    // so this post-terminal notice cannot poison the next operator turn.
                    let _ = self.frontend_saturation.take_structural_refusal();
                    self.lifecycle_event(
                        "queue.overflow",
                        Some(turn),
                        LifecyclePayload {
                            count: Some(1),
                            reason_code: Some("post_terminal_stop_notice_refused".into()),
                            outcome_code: Some("answer_unaffected".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                }
            }
        }
    }

    pub(super) fn emit(&mut self, turn: TurnId, kind: EventKind) {
        // Observations enter a bounded buffer without claiming a durable sequence. The next
        // authoritative append flushes that prefix; either admission or flush failure latches
        // record_failed and stops the run at the existing safe boundary.
        let phase = match &kind {
            EventKind::Phase { phase } => Some(*phase),
            _ => None,
        };
        #[cfg(test)]
        if self.fail_next_durable_append == Some(DurableAppendFault::BestEffort) {
            self.fail_next_durable_append = None;
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return;
        }
        let event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let fsync_started = Instant::now();
        let buffered = matches!(
            &event.kind,
            EventKind::Phase { .. }
                | EventKind::Notice { .. }
                | EventKind::Text { .. }
                | EventKind::Thinking { .. }
        );
        let mut prefix_flushed = false;
        let appended = if buffered {
            self.rollout.queue_observation(event).map(|flushed| {
                prefix_flushed = flushed;
                Seq::ZERO
            })
        } else {
            self.rollout.append(&event)
        };
        if !buffered || prefix_flushed {
            self.ledger
                .record_fsync_latency_us(elapsed_us(fsync_started));
        }
        match appended {
            Ok(_) => {
                if let Some(phase) = phase {
                    // Project only an accepted phase; required record barriers commit the prefix
                    // before effects or a terminal outcome are acknowledged.
                    self.ui(UiEvent::Phase(phase));
                }
            }
            Err(_) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
            }
        }
    }

    pub(super) fn ensure_record_healthy(&self) -> Result<(), KernelError> {
        if self.record_failed {
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other(
                    "provider admission cannot continue after the durable record failed",
                ),
            )));
        }
        Ok(())
    }

    pub(super) fn emit_durable(
        &mut self,
        turn: TurnId,
        kind: EventKind,
    ) -> Result<(), KernelError> {
        self.emit_durable_seq(turn, kind).map(|_| ())
    }

    /// Commit the final visible phase and run terminal as one semantic batch. `Done` is last by
    /// construction, so `Rollout::append_batch` takes exactly one full terminal barrier and the UI
    /// cannot observe Idle without the authoritative terminal in the same confirmed prefix.
    pub(super) fn emit_durable_run_terminal(
        &mut self,
        turn: TurnId,
        outcome: String,
    ) -> Result<Seq, KernelError> {
        #[cfg(test)]
        if self.fail_next_durable_append == Some(DurableAppendFault::RunTerminal) {
            self.fail_next_durable_append = None;
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other("injected durable run-terminal append refusal"),
            )));
        }
        let outcome_observation = outcome.clone();
        let result = self.terminal_record.append_visible_terminal(
            &mut self.rollout,
            &mut self.ledger,
            turn,
            outcome,
        );
        result
            .map_err(|error| {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                KernelError::Record(error)
            })
            .inspect(|source| {
                self.turn_publications.observe_committed(&Event {
                    seq: *source,
                    turn,
                    kind: EventKind::Done {
                        outcome: outcome_observation,
                    },
                });
            })
    }

    /// Append and return the authoritative record sequence for cross-event correlation (workflow
    /// child links and reduce adoption). The sequence is observed only after fsync succeeds.
    pub(super) fn emit_durable_seq(
        &mut self,
        turn: TurnId,
        kind: EventKind,
    ) -> Result<Seq, KernelError> {
        #[cfg(test)]
        if self.fail_next_durable_append.is_some_and(|fault| {
            matches!(
                (fault, &kind),
                (
                    DurableAppendFault::ContextInjection,
                    EventKind::ContextInjection { .. }
                ) | (DurableAppendFault::SteerMessage, EventKind::Message { .. })
                    | (DurableAppendFault::Notice, EventKind::Notice { .. })
                    | (DurableAppendFault::TurnStart, EventKind::TurnStart)
                    | (
                        DurableAppendFault::EffectIntent,
                        EventKind::EffectIntent { .. }
                    )
                    | (DurableAppendFault::ToolDone, EventKind::ToolDone { .. })
                    | (DurableAppendFault::Compaction, EventKind::Compaction { .. })
                    | (
                        DurableAppendFault::SubagentFinished,
                        EventKind::SubagentFinished { .. } | EventKind::SubagentFinishedV2 { .. }
                    )
                    | (
                        DurableAppendFault::UsdCeiling,
                        EventKind::UsdCeilingChanged { .. }
                    )
                    | (
                        DurableAppendFault::TurnCeiling,
                        EventKind::TurnCeilingChanged { .. }
                    )
            )
        }) {
            self.fail_next_durable_append = None;
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other("injected durable append failure"),
            )));
        }
        let turn_started_at_us =
            matches!(&kind, EventKind::TurnStart).then(|| self.rollout.segment_elapsed_us());
        let mut event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let fsync_started = Instant::now();
        let appended = self.rollout.append(&event);
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
        match appended {
            Ok(seq) => {
                event.seq = seq;
                self.turn_publications.observe_committed(&event);
                if let Some(started_at_us) = turn_started_at_us {
                    self.observe_policy_turn_start(turn, started_at_us);
                }
                Ok(seq)
            }
            Err(error) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                Err(KernelError::Record(error))
            }
        }
    }

    /// Enqueue rebuildable sidecars off the turn path. Read and close boundaries rendezvous with
    /// their worker; the durable writer marker makes an interrupted publication discoverable.
    pub(super) fn refresh_session_cache_metered(&mut self) {
        let _ = self.rollout.refresh_session_cache_async();
    }

    pub(super) fn diagnostic_record_append_failed(&self) {
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
    }

    /// Translate a boundary refusal into the kernel's error vocabulary.
    ///
    /// Only a durable-log failure sets `record_failed`; an admission or proposal refusal leaves the
    /// record trustworthy and must not latch the run into "the audit trail is broken" mode.
    pub(super) fn effect_boundary_failed(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => {
                self.record_failed = true;
                KernelError::Record(error)
            }
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }

    /// Mint the next ordinal for one effect class in this turn.
    pub(super) fn next_effect_ordinal(
        &mut self,
        turn: TurnId,
        class: effect_class::EffectClass,
    ) -> usize {
        self.effect_journal.next_ordinal(turn, class)
    }

    /// Mint one physical billing identity from the same restored Provider effect allocator.
    pub(super) fn next_provider_effect_identity(
        &mut self,
        turn: TurnId,
    ) -> Result<(usize, u32), KernelError> {
        let ordinal = self.next_effect_ordinal(turn, effect_class::EffectClass::Provider);
        let physical =
            super::provider_effect_identity::physical_attempt_for_provider_ordinal(ordinal)?;
        Ok((ordinal, physical))
    }

    /// Open a non-registry effect: admit the identity and fsync its write-ahead intent.
    ///
    /// The two-phase form exists for the executors that need `&mut self` while they run — the
    /// provider turn, the verifier's cancellation poll loop, a subagent. They cross the identical
    /// boundary as the closure-shaped callers; only the borrow shape differs.
    pub(super) fn open_kernel_effect(
        &mut self,
        turn: TurnId,
        class: effect_class::EffectClass,
        ordinal: usize,
        capability: Capability,
        audit_arguments: serde_json::Value,
    ) -> Result<effects::EffectTicket, KernelError> {
        if class == effect_class::EffectClass::Provider {
            let workspace = self.workspace.clone();
            return self.provider_attempt_journal().open(
                &workspace,
                provider_attempt_journal::ProviderIntent {
                    turn,
                    ordinal,
                    capability,
                    audit: audit_arguments,
                },
            );
        }
        let effect = effects::BrokeredEffect {
            turn,
            effect_id: effect_class::effect_id(turn, class, ordinal),
            tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
            kind: effect_class_label(class).to_string(),
            capability,
            audit_arguments,
            workspace: effect_workspace(&self.workspace),
            provider_route_attempt: None,
        };
        #[cfg(test)]
        if self.fail_next_durable_append == Some(DurableAppendFault::EffectIntent) {
            self.fail_next_durable_append = None;
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other("injected durable effect-intent append failure"),
            )));
        }
        let started = Instant::now();
        let opened = self.effect_journal.open(&mut self.rollout, effect);
        self.ledger.record_fsync_latency_us(elapsed_us(started));
        opened.map_err(|error| self.effect_boundary_failed(error))
    }

    pub(super) fn provider_attempt_journal(
        &mut self,
    ) -> provider_attempt_journal::ProviderAttemptJournal<'_> {
        let financial = self.provider_financial_context();
        let pricing_now = self.pricing_now();
        provider_attempt_journal::ProviderAttemptJournal {
            rollout: &mut self.rollout,
            effects: &mut self.effect_journal,
            ledger: &mut self.ledger,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            financial,
            pricing_now,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
        }
    }

    /// Settle an opened effect with its one terminal.
    pub(super) fn settle_kernel_effect(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
    ) -> Result<(), KernelError> {
        self.settle_kernel_effect_with_cause(ticket, settlement, UnknownCause::Unobserved)
    }

    /// Same terminal, but says WHY an `Unknown` is unknown.
    ///
    /// The blocking latch exists to refuse blind replay across a crash window: a process died
    /// between a durable intent and its terminal, so nobody can say whether the effect landed.
    /// An operator who pressed Esc twice is none of that. They are present, they caused the stop,
    /// and they are explicitly asking to keep working. Latching on their own cancellation bricked
    /// every later submission in the process — the journal still records the Unknown terminal, so
    /// nothing is hidden and automatic retry stays forbidden; only the gate on FUTURE operator
    /// work is lifted.
    pub(super) fn settle_kernel_effect_with_cause(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
        cause: UnknownCause,
    ) -> Result<(), KernelError> {
        if ticket.provider_route_attempt().is_some() {
            return self
                .provider_attempt_journal()
                .settle(ticket, settlement, cause);
        }
        let started = Instant::now();
        let committed = self
            .effect_journal
            .settle(&mut self.rollout, ticket, settlement, cause);
        self.ledger.record_fsync_latency_us(elapsed_us(started));
        committed.map_err(|error| self.effect_boundary_failed(error))
    }

    /// Run one lifecycle hook across the effect boundary.
    ///
    /// A hook is an operator-configured process the kernel starts, which makes it an externally
    /// visible effect by every definition the boundary uses. Before #16 it was the largest
    /// unbrokered class in the kernel — the comment beside the PostToolUse call site said so in as
    /// many words — so a crash between spawning a hook and returning left no durable trace that
    /// anything had been started.
    ///
    /// # Why a returning hook is a *proven* terminal
    ///
    /// `Hooks::run` always returns: a command that cannot spawn, exits non-zero, or overruns its
    /// timeout is reaped and reported as "no opinion". So when it returns, the process lifecycle is
    /// closed and the terminal is proven, even though the hook's *verdict* may be unknown — those
    /// are different questions and only the first belongs to the boundary. The genuinely
    /// unprovable case is the one the boundary already covers: if this process dies between the
    /// intent and the terminal, recovery finds a pending intent and journals `EffectUnknown`.
    ///
    /// # Why a boundary failure is not swallowed here
    ///
    /// Every existing call site wrote `let _ = self.hooks.run(...)`, because a hook's opinion is
    /// advisory. A *boundary* failure is not: it means either the durable log is broken or a caller
    /// asked for an unrecordable dispatch, and continuing would report a clean outcome over a
    /// broken audit trail.
    pub(super) async fn brokered_hook(
        &mut self,
        turn: TurnId,
        event: HookEvent,
        context_json: &str,
    ) -> Result<hooks::HookDecision, KernelError> {
        self.hook_execution(turn)
            .compatibility(event, context_json)
            .await
    }

    /// Assemble concrete independent hook, journal, measurement and projection owners. No
    /// executor receives mutable Agent state or provider/permission authority.
    pub(super) fn hook_execution(&mut self, turn: TurnId) -> hook_execution::HookExecution<'_> {
        let scope = hook_execution::HookExecutionScope {
            turn,
            workspace: self.workspace.as_path(),
            hooks: &self.hooks,
            command_journal: self.hook_effect_journal.clone(),
            interrupt: self.control.interrupt().cloned(),
            drain: self.control.drain().clone(),
            activity: self.activity.clone(),
            emitter: self.lifecycle_emitter.clone(),
            dispatcher: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        hook_execution::HookExecution {
            rollout: &mut self.rollout,
            effects: &mut self.effect_journal,
            record_failed: &mut self.record_failed,
            ledger: &mut self.ledger,
            diagnostics: &self.diagnostics,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
            scope,
        }
    }

    /// Run one canonical Gate Hook through the durable effect boundary. Observe/Augment hooks are
    /// projected asynchronously; Gates execute here because their owner must know the decision
    /// before admitting the source, budget, mutation, tool, or child they protect.
    pub(crate) async fn brokered_lifecycle_gate(
        &mut self,
        turn: TurnId,
        event_id: &'static str,
        payload: LifecyclePayload,
    ) -> Result<hooks::LifecycleHookReport, KernelError> {
        let correlation = self.lifecycle_correlation(Some(turn));
        self.brokered_lifecycle_gate_correlated(turn, event_id, correlation, payload, true)
            .await
    }

    /// Ask a canonical Gate for its decision without projecting the protected source event yet.
    /// Tool admission uses this form: the subsequent admitted/refused tool boundary publishes
    /// `tool.call_proposed` exactly once with the final effect correlation.
    pub(super) async fn brokered_lifecycle_gate_decision(
        &mut self,
        turn: TurnId,
        event_id: &'static str,
        payload: LifecyclePayload,
    ) -> Result<hooks::LifecycleHookReport, KernelError> {
        let correlation = self.lifecycle_correlation(Some(turn));
        self.brokered_lifecycle_gate_correlated(turn, event_id, correlation, payload, false)
            .await
    }

    pub(super) async fn admit_tool_lifecycle_gate(
        &mut self,
        turn: TurnId,
        tool: &str,
    ) -> Result<Option<String>, KernelError> {
        let report = self
            .brokered_lifecycle_gate_decision(
                turn,
                "tool.call_proposed",
                LifecyclePayload {
                    reason_code: Some(tool.to_owned()),
                    ..LifecyclePayload::default()
                },
            )
            .await?;
        Ok(match report.decision {
            hooks::HookDecision::Allow => None,
            hooks::HookDecision::Deny(reason) => Some(reason),
        })
    }

    pub(super) async fn brokered_child_lifecycle_gate(
        &mut self,
        turn: TurnId,
        event_id: &'static str,
        subagent_id: &str,
        payload: LifecyclePayload,
    ) -> Result<hooks::LifecycleHookReport, KernelError> {
        let mut correlation = self.lifecycle_correlation(Some(turn));
        correlation.subagent_id = Some(iteron_protocol::SubagentId(subagent_id.to_owned()));
        self.brokered_lifecycle_gate_correlated(turn, event_id, correlation, payload, true)
            .await
    }

    async fn brokered_lifecycle_gate_correlated(
        &mut self,
        turn: TurnId,
        event_id: &'static str,
        correlation: iteron_obs::lifecycle::LifecycleCorrelation,
        payload: LifecyclePayload,
        project_source: bool,
    ) -> Result<hooks::LifecycleHookReport, KernelError> {
        if project_source {
            self.lifecycle_event_with_correlation(event_id, correlation, payload);
        }
        self.hook_execution(turn).lifecycle(event_id).await
    }

    /// Export the run's telemetry projection across the effect boundary (#105).
    ///
    /// Returns immediately when no sink is configured, which is the default: no config, no effect,
    /// no journal entry, no measurable difference. That is the whole meaning of "off".
    ///
    /// When it IS configured, the egress crosses the same broker as every other world effect, so a
    /// stalled collector is bounded and reaped, and a crash mid-POST leaves an `EffectUnknown` that
    /// recovery refuses to replay -- a retried export would duplicate spans, and a duplicated span
    /// is a wrong dashboard rather than a missing one.
    ///
    /// The payload is the run-local lifecycle projector's consumed incremental batch. Export never
    /// rereads the rollout: replay on every turn made finalization O(run age), and retrying a drained
    /// batch after an ambiguous POST would duplicate telemetry. Durable record remains authority;
    /// this observer has explicit at-most-once/no-replay semantics.
    pub(super) async fn brokered_telemetry_export(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        let Some(sink) = self.telemetry.clone() else {
            return Ok(());
        };
        self.lifecycle_event("exporter.started", Some(turn), LifecyclePayload::default());
        let Some(lifecycle_telemetry) = self.lifecycle_telemetry.clone() else {
            self.lifecycle_event(
                "exporter.batch_dropped",
                Some(turn),
                LifecyclePayload {
                    count: Some(1),
                    reason_code: Some("incremental_projection_unavailable_no_replay".into()),
                    ..LifecyclePayload::default()
                },
            );
            self.ui(UiEvent::Notice(
                "telemetry export skipped: incremental projection unavailable; rollout replay is intentionally disabled"
                    .into(),
            ));
            return Ok(());
        };
        let lifecycle = match tokio::task::spawn_blocking(move || {
            lifecycle_telemetry.take_snapshot()
        })
        .await
        {
            Ok(snapshot) => snapshot,
            Err(_) => {
                self.lifecycle_event(
                    "exporter.batch_dropped",
                    Some(turn),
                    LifecyclePayload {
                        count: Some(1),
                        reason_code: Some("incremental_snapshot_failed_no_replay".into()),
                        ..LifecyclePayload::default()
                    },
                );
                self.ui(UiEvent::Notice(
                    "telemetry export skipped: incremental snapshot failed; drained data will not be replayed"
                        .into(),
                ));
                return Ok(());
            }
        };
        let dropped = lifecycle
            .dropped_logs
            .saturating_add(lifecycle.dropped_spans)
            .saturating_add(lifecycle.dropped_open_spans);
        let payload = iteron_obs::otel::Export {
            run_id: self.rollout.run_id().0.clone(),
            lifecycle: Some(lifecycle),
            dropped,
            ..iteron_obs::otel::Export::default()
        };
        if payload.dropped > 0 {
            // Counted, never silent. A consumer that saw the cap and no drop count would believe
            // it had seen the whole run.
            self.ui(UiEvent::Notice(format!(
                "telemetry export dropped {} span(s) at the payload bound",
                payload.dropped
            )));
            self.lifecycle_event(
                "exporter.batch_dropped",
                Some(turn),
                LifecyclePayload {
                    count: Some(payload.dropped),
                    ..LifecyclePayload::default()
                },
            );
        }

        let class = effect_class::EffectClass::Telemetry;
        let ordinal = self.next_effect_ordinal(turn, class);
        let effect = KernelEffect {
            turn,
            class,
            ordinal,
            capability: Capability::IrreversibleExternal,
            audit_arguments: serde_json::json!({
                "endpoint": sink.endpoint(),
                "spans": payload.spans.len(),
                "metrics": payload.metrics.len(),
                "lifecycle_logs": payload.lifecycle.as_ref().map(|snapshot| snapshot.logs.len()).unwrap_or(ABSENT_LIFECYCLE_COUNT),
                "lifecycle_spans": payload.lifecycle.as_ref().map(|snapshot| snapshot.spans.len()).unwrap_or(ABSENT_LIFECYCLE_COUNT),
                "dropped": payload.dropped,
            }),
            workspace: self.workspace.as_path(),
        };
        let Agent {
            rollout,
            effect_journal,
            ..
        } = self;
        let outcome = broker_kernel_effect(rollout, effect_journal, effect, || async move {
            match sink.send(&payload).await {
                telemetry::TelemetrySendOutcome::Accepted => effects::EffectDisposition::Definite {
                    terminal: effect_done_terminal(turn, class, ordinal),
                    value: telemetry::TelemetrySendOutcome::Accepted,
                },
                telemetry::TelemetrySendOutcome::Rejected(reason) => {
                    effects::EffectDisposition::Definite {
                        terminal: effect_failed_terminal(turn, class, ordinal, &reason),
                        value: telemetry::TelemetrySendOutcome::Rejected(reason),
                    }
                }
                telemetry::TelemetrySendOutcome::Unknown => effects::EffectDisposition::Unknown {
                    reason: "telemetry collector returned no observable terminal".into(),
                    value: telemetry::TelemetrySendOutcome::Unknown,
                },
            }
        })
        .await;
        match outcome {
            Ok(effects::BrokeredOutcome::Definite(telemetry::TelemetrySendOutcome::Accepted)) => {
                self.lifecycle_event(
                    "exporter.batch_flushed",
                    Some(turn),
                    LifecyclePayload::default(),
                );
                Ok(())
            }
            Ok(effects::BrokeredOutcome::Definite(telemetry::TelemetrySendOutcome::Rejected(
                reason,
            ))) => {
                self.lifecycle_event(
                    "exporter.failed",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some(reason),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(())
            }
            Ok(effects::BrokeredOutcome::Unknown(_)) => {
                self.lifecycle_event(
                    "exporter.failed",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some("outcome_unknown".into()),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(())
            }
            Ok(effects::BrokeredOutcome::Definite(telemetry::TelemetrySendOutcome::Unknown)) => {
                unreachable!("unknown transport outcomes use the unknown effect terminal")
            }
            Err(_) => {
                // Telemetry is opt-in evidence, never turn authority. An admission or journal
                // failure proves no export succeeded and is observable through this lifecycle row;
                // it must not retroactively fail the answer the operator already received.
                self.lifecycle_event(
                    "exporter.failed",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some("effect_boundary_failed".into()),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(())
            }
        }
    }

    /// Refuse blind replay across the edit/process crash window. A durable intent without a
    /// correlated ToolDone is conservatively materialized as EffectUnknown; an existing Unknown
    /// remains blocking until a future broker/reconciler appends authoritative completion.
    pub(super) fn guard_unresolved_effects(&mut self) -> Result<(), KernelError> {
        let result = self
            .effect_journal
            .guard_recovery(&mut self.rollout, &mut self.ledger);
        if matches!(&result, Err(KernelError::Record(_))) {
            self.record_failed = true;
            self.diagnostic_record_append_failed();
        }
        result
    }

    /// Record a transcript message AND push it onto the working set — the two must stay in
    /// lockstep so the rollout is a complete, resumable record.
    /// Durably preserve what a failed turn had already streamed (I-39).
    ///
    /// A mid-stream disconnect used to return before the assistant message was appended, so every
    /// token the operator had watched arrive was destroyed by the failure that interrupted it —
    /// ambiguous transport failures are not retried, so a connection reset, a VPN drop and the
    /// stream idle timeout all took that path. Worse, the `Text`/`Thinking` delta events the
    /// frozen schema declares had no producer anywhere, so streamed text had no durable channel
    /// at all.
    ///
    /// This is that channel, and it writes two different things for two different readers:
    /// the bounded coalesced delta prefix records what began appearing on screen, and the
    /// interrupted assistant message is what resume and rewind replay into the next request.
    /// Both are bounded, both are emitted only on
    /// this path, and neither claims usage: **no billing semantics change here**. An append
    /// failure is swallowed on purpose — the provider error is the one worth reporting, and
    /// losing the record of a partial answer must not also lose the reason it was partial.
    pub(super) fn preserve_interrupted_stream(
        &mut self,
        turn: TurnId,
        messages: &mut Vec<Message>,
        text: &str,
        thinking: &str,
    ) {
        if text.is_empty() && thinking.is_empty() {
            return;
        }
        let max_bytes = iteron_tunables::param_integer(
            "cli.runtime.interrupted_stream_max_bytes",
            INTERRUPTED_STREAM_MAX_BYTES,
        )
        .min(INTERRUPTED_STREAM_MAX_BYTES);
        if !thinking.is_empty() {
            let _ = self.emit_durable(
                turn,
                EventKind::Thinking {
                    delta: strict_utf8_head(thinking, max_bytes),
                },
            );
        }
        if text.is_empty() {
            return;
        }
        let delta = strict_utf8_head(text, max_bytes);
        let _ = self.emit_durable(
            turn,
            EventKind::Text {
                delta: delta.clone(),
            },
        );
        // The marker is inside the text, not beside it: an assistant message that resume replays
        // must tell the model where its own answer stopped, and a sibling field would be dropped
        // the moment the transcript is serialized for a provider.
        let interrupted = Message {
            role: Role::Assistant,
            content: vec![Block::Text {
                text: format!("{delta}\n\n{INTERRUPTED_STREAM_MARKER}"),
            }],
        };
        let _ = self.commit_message(turn, messages, interrupted);
    }

    pub(super) fn commit_message(
        &mut self,
        turn: TurnId,
        messages: &mut Vec<Message>,
        m: Message,
    ) -> Result<(), KernelError> {
        // The working transcript is a projection of durable state, never a parallel authority.
        // If append/fsync fails, do not let the model-visible state advance past the journal.
        let source = self.emit_durable_seq(turn, EventKind::message(m.clone()))?;
        if m.role == Role::Assistant {
            self.last_assistant_source = Some(source);
        }
        if let Some(trust) = Trust::governing(m.content.iter().filter_map(|block| match block {
            Block::ToolResult(result) => Some(result.trust),
            Block::ToolImage(image) => Some(image.trust()),
            _ => None,
        })) {
            self.observed_trust = self.observed_trust.min(trust);
        }
        messages.push(m);
        Ok(())
    }
}
