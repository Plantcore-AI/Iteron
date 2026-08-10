use super::*;

impl Agent {
    pub(super) fn emit(&mut self, turn: TurnId, kind: EventKind) {
        // The rollout assigns the real Seq on write; the placeholder here is overwritten.
        // A durable-append failure is NOT swallowed (code review): it sets record_failed, which
        // the loop checks at the next turn admission and halts at a safe point (audit integrity
        // over silent continuation).
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
        let appended = self.rollout.append(&event);
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
        match appended {
            Ok(_) => {
                if let Some(phase) = phase {
                    // The durable phase transition is the source of truth; only project it after
                    // the append succeeds so the HUD cannot claim a rejected phase.
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
            return Err(KernelError::Record(core_record::RecordError::Io(
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
                ) | (DurableAppendFault::Notice, EventKind::Notice { .. })
                    | (DurableAppendFault::TurnStart, EventKind::TurnStart)
                    | (DurableAppendFault::ToolDone, EventKind::ToolDone { .. })
                    | (
                        DurableAppendFault::SubagentFinished,
                        EventKind::SubagentFinished { .. } | EventKind::SubagentFinishedV2 { .. }
                    )
                    | (
                        DurableAppendFault::UsdCeiling,
                        EventKind::UsdCeilingChanged { .. }
                    )
            )
        }) {
            self.fail_next_durable_append = None;
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(core_record::RecordError::Io(
                std::io::Error::other("injected durable append failure"),
            )));
        }
        let event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let fsync_started = Instant::now();
        let appended = self.rollout.append(&event);
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
        match appended {
            Ok(seq) => Ok(seq),
            Err(error) => {
                self.record_failed = true;
                self.diagnostic_record_append_failed();
                Err(KernelError::Record(error))
            }
        }
    }

    /// Refresh the rebuildable session sidecars, charged to the same meter as a durable append.
    ///
    /// This is not free bookkeeping: `refresh_session_cache` rewrites the per-run `.meta.json` and
    /// `sessions.index`, and each rewrite ends in a directory fsync. Called once per turn from
    /// `advance_turn` and once at each run boundary, it was real durability cost that no meter saw,
    /// so `kernel_tax` under-reported what the record actually costs. Failure stays best-effort:
    /// the cache is rebuildable and the append-only rollout is the sole authoritative result.
    pub(super) fn refresh_session_cache_metered(&mut self) {
        let fsync_started = Instant::now();
        let _ = self.rollout.refresh_session_cache();
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
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
        self.effect_admissions.next_ordinal(turn, class)
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
        let effect = effects::BrokeredEffect {
            turn,
            effect_id: effect_class::effect_id(turn, class, ordinal),
            tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
            kind: effect_class_label(class).to_string(),
            capability,
            audit_arguments,
            workspace: effect_workspace(&self.workspace),
        };
        let Agent {
            rollout,
            effect_admissions,
            ..
        } = self;
        match effects::open_effect(rollout, effect_admissions, effect) {
            Ok(ticket) => Ok(ticket),
            Err(error) => Err(self.effect_boundary_failed(error)),
        }
    }

    /// Settle an opened effect with its one terminal.
    pub(super) fn settle_kernel_effect(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
    ) -> Result<(), KernelError> {
        match effects::settle_effect(&mut self.rollout, ticket, settlement) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.effect_boundary_failed(error)),
        }
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
        // Per EVENT, not per hook map: a run with only a `Stop` hook configured has nothing to say
        // about `PreToolUse`, so brokering it would append an intent and a terminal (and pay their
        // barriers) to call zero commands. The boundary still covers every dispatch that can
        // actually start a process, which is the only thing it was ever protecting.
        if self.hooks.is_empty_for(event) {
            return Ok(hooks::HookDecision::Allow);
        }
        let hook_journal = self.hook_effect_journal.clone().ok_or_else(|| {
            KernelError::ContextResolution(
                "hook command journal is unavailable; command was not started".into(),
            )
        })?;
        self.lifecycle_event("hook.matched", Some(turn), LifecyclePayload::default());
        self.lifecycle_event("hook.started", Some(turn), LifecyclePayload::default());
        let class = effect_class::EffectClass::Hook;
        let ordinal = self.next_effect_ordinal(turn, class);
        let effect = KernelEffect {
            turn,
            class,
            ordinal,
            capability: Capability::CodeExecuting,
            audit_arguments: serde_json::json!({ "event": event.key() }),
            workspace: self.workspace.as_path(),
        };
        let hook_cancel = self.interrupt.clone();
        let hook_drain = self.drain.clone();
        let Agent {
            rollout,
            effect_admissions,
            hooks,
            ..
        } = self;
        let outcome = broker_kernel_effect(rollout, effect_admissions, effect, || {
            Box::pin(async move {
                effects::EffectDisposition::Definite {
                    terminal: effect_done_terminal(turn, class, ordinal),
                    value: hooks
                        .run_cancellable_journaled(
                            event,
                            context_json,
                            hook_cancel.as_deref(),
                            Some(hook_drain.as_ref()),
                            &hook_journal,
                        )
                        .await,
                }
            })
        })
        .await;
        match outcome {
            Ok(outcome) => {
                let decision = outcome.into_value();
                self.lifecycle_event(
                    if matches!(decision, hooks::HookDecision::Deny(_)) {
                        "hook.blocked"
                    } else {
                        "hook.completed"
                    },
                    Some(turn),
                    LifecyclePayload::default(),
                );
                Ok(decision)
            }
            Err(error) => Err(self.effect_boundary_failed(error)),
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
        correlation.subagent_id = Some(core_protocol::SubagentId(subagent_id.to_owned()));
        self.brokered_lifecycle_gate_correlated(turn, event_id, correlation, payload, true)
            .await
    }

    async fn brokered_lifecycle_gate_correlated(
        &mut self,
        turn: TurnId,
        event_id: &'static str,
        correlation: core_obs::lifecycle::LifecycleCorrelation,
        payload: LifecyclePayload,
        project_source: bool,
    ) -> Result<hooks::LifecycleHookReport, KernelError> {
        debug_assert_eq!(
            core_protocol::lifecycle::event_spec(event_id).map(|spec| spec.hook_capability),
            Some(core_protocol::HookCapability::Gate)
        );
        if project_source {
            self.lifecycle_event_with_correlation(event_id, correlation, payload);
        }
        if self.hooks.is_empty_for_lifecycle(event_id) {
            return Ok(hooks::LifecycleHookReport {
                decision: hooks::HookDecision::Allow,
                matched: 0,
                completed: 0,
                failed: 0,
                timed_out: 0,
                augmentations: Vec::new(),
            });
        }
        let hook_journal = self.hook_effect_journal.clone().ok_or_else(|| {
            KernelError::ContextResolution(
                "hook command journal is unavailable; gate command was not started".into(),
            )
        })?;
        let class = effect_class::EffectClass::Hook;
        let ordinal = self.next_effect_ordinal(turn, class);
        let effect = KernelEffect {
            turn,
            class,
            ordinal,
            capability: Capability::CodeExecuting,
            audit_arguments: serde_json::json!({ "event": event_id }),
            workspace: self.workspace.as_path(),
        };
        self.lifecycle_event("hook.matched", Some(turn), LifecyclePayload::default());
        self.lifecycle_event("hook.started", Some(turn), LifecyclePayload::default());
        let context = serde_json::json!({
            "catalog_version": core_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION.0,
            "event_id": event_id,
            "turn_id": turn.0,
        })
        .to_string();
        let hook_cancel = self.interrupt.clone();
        let hook_drain = self.drain.clone();
        let Agent {
            rollout,
            effect_admissions,
            hooks,
            ..
        } = self;
        let result = broker_kernel_effect(rollout, effect_admissions, effect, || {
            Box::pin(async move {
                match hooks
                    .run_lifecycle_cancellable_journaled(
                        event_id,
                        &context,
                        hook_cancel.as_deref(),
                        Some(hook_drain.as_ref()),
                        &hook_journal,
                    )
                    .await
                {
                    Ok(report) => effects::EffectDisposition::Definite {
                        terminal: effect_done_terminal(turn, class, ordinal),
                        value: Ok(report),
                    },
                    Err(reason) => effects::EffectDisposition::Definite {
                        terminal: effect_failed_terminal(turn, class, ordinal, reason),
                        value: Err(reason),
                    },
                }
            })
        })
        .await;
        let report = match result {
            Ok(result) => result
                .into_value()
                .map_err(|reason| KernelError::ContextResolution(reason.to_owned()))?,
            Err(error) => return Err(self.effect_boundary_failed(error)),
        };
        let terminal = if matches!(report.decision, hooks::HookDecision::Deny(_)) {
            "hook.blocked"
        } else if report.timed_out > 0 {
            "hook.timed_out"
        } else if report.failed > 0 {
            "hook.failed"
        } else {
            "hook.completed"
        };
        self.lifecycle_event(
            terminal,
            Some(turn),
            LifecyclePayload {
                count: Some(u64::from(report.completed)),
                ..LifecyclePayload::default()
            },
        );
        Ok(report)
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
    /// The payload is a PROJECTION: `core_obs::otel::project` reads events the record already
    /// holds and measures nothing, so the exporter cannot disagree with the audit log it exports.
    pub(super) async fn brokered_telemetry_export(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        let Some(sink) = self.telemetry.clone() else {
            return Ok(());
        };
        self.lifecycle_event("exporter.started", Some(turn), LifecyclePayload::default());
        self.lifecycle_event("replay.started", Some(turn), LifecyclePayload::default());
        let Ok(timed) = core_record::replay_timed(self.rollout.path()) else {
            // A rollout that will not replay is an audit problem, not a telemetry problem, and it
            // is already reported by every other reader. Exporting a partial projection from bytes
            // the audit path rejected is the one thing this must not do.
            return Ok(());
        };
        self.lifecycle_event(
            "replay.completed",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(timed.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        let events: Vec<&core_protocol::Event> = timed.iter().map(|entry| &entry.event).collect();
        let timeline = core_obs::timeline::fold(timed.iter().map(|e| (e.ts_us, &e.event)));
        let mut payload = core_obs::otel::project(&self.rollout.run_id().0, &events, &timeline);
        payload.lifecycle = self
            .lifecycle_telemetry
            .as_ref()
            .map(core_obs::otel::lifecycle::LifecycleTelemetryRuntime::snapshot);
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
                "lifecycle_logs": payload.lifecycle.as_ref().map(|snapshot| snapshot.logs.len()).unwrap_or(0),
                "lifecycle_spans": payload.lifecycle.as_ref().map(|snapshot| snapshot.spans.len()).unwrap_or(0),
                "dropped": payload.dropped,
            }),
            workspace: self.workspace.as_path(),
        };
        let Agent {
            rollout,
            effect_admissions,
            ..
        } = self;
        let outcome = broker_kernel_effect(rollout, effect_admissions, effect, || async move {
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
        let events = replay_logical_rollout(self.rollout.path())?;
        let journal = effects::EffectJournal::replay(&events)?;
        // At-most-once has to survive the process boundary, not just the turn loop: a resumed run
        // must not be able to re-mint an identity the previous process already admitted.
        self.effect_admissions = effect_admission::EffectAdmissions::from_journal(&journal);
        let newly_unknown = journal.pending();
        for pending in &newly_unknown {
            self.emit_durable(
                pending.turn,
                EventKind::EffectUnknown {
                    id: pending.id.clone(),
                    tool: pending.tool.clone(),
                    reason: "recovery found a durable intent without a durable tool result; automatic retry is forbidden".into(),
                },
            )?;
        }
        let count = journal.unknown_requiring_reconciliation().saturating_add(
            newly_unknown
                .iter()
                .filter(|pending| effect_journal::kind_blocks_resume(&pending.tool))
                .count(),
        );
        if count > 0 {
            return Err(KernelError::UnknownEffects { count });
        }
        Ok(())
    }

    /// Record a transcript message AND push it onto the working set — the two must stay in
    /// lockstep so the rollout is a complete, resumable record.
    /// Durably preserve what a failed turn had already streamed (I-39).
    ///
    /// A mid-stream disconnect used to return before the assistant message was appended, so every
    /// token the operator had watched arrive was destroyed by the failure that interrupted it —
    /// and only 429/529 are retried, so a connection reset, a DNS failure, a VPN drop and the
    /// stream idle timeout all took that path. Worse, the `Text`/`Thinking` delta events the
    /// frozen schema declares had no producer anywhere, so streamed text had no durable channel
    /// at all.
    ///
    /// This is that channel, and it writes two different things for two different readers:
    /// the coalesced deltas are what was on screen, and the interrupted assistant message is what
    /// resume and rewind replay into the next request. Both are bounded, both are emitted only on
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
        if !thinking.is_empty() {
            let _ = self.emit_durable(
                turn,
                EventKind::Thinking {
                    delta: strict_utf8_head(thinking, INTERRUPTED_STREAM_MAX_BYTES),
                },
            );
        }
        if text.is_empty() {
            return;
        }
        let delta = strict_utf8_head(text, INTERRUPTED_STREAM_MAX_BYTES);
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
        self.emit_durable(turn, EventKind::Message { message: m.clone() })?;
        if let Some(trust) = Trust::governing(m.content.iter().filter_map(|block| match block {
            Block::ToolResult(result) => Some(result.trust),
            _ => None,
        })) {
            self.observed_trust = self.observed_trust.min(trust);
        }
        messages.push(m);
        Ok(())
    }
}
