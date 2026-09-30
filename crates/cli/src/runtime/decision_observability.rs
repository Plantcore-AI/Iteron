//! Content-free context/memory decision evidence and lifecycle emission.

use super::*;
use iteron_ctx::{
    ContaminationEvidence, ContextDecision, MemoryBudgetEvidence, MemoryCandidateDecision,
    MemoryCandidateEvidence, MemoryDecisionTrace, MemoryFactId, MemoryInjectionEvidence,
    MemoryQueryEvidence, MemoryQueryId, MemoryRecallAudit, MemoryRecallExclusionKind,
    MemoryScopeClass, MemoryScopeEvidence, MemorySelectionEvidence, MemoryStoreEvidence,
    MemoryTierClass, MemoryVisibilityEvidence, MemoryVisibilityState,
};

/// Recalled fact count reported for a turn whose memory trace carries no injection.
const NO_RECALLED_FACTS: u64 = 0;

/// Query-rewrite count reported when the turn ran without a recall audit.
const NO_QUERY_REWRITES: u16 = 0;

/// Candidate count reported when there is no recall audit, or the real count does not fit the
/// evidence field's `u32`. Evidence stays emitted rather than dropped.
const UNCOUNTED_MEMORY_CANDIDATES: u32 = 0;

/// Score reported for a candidate the audit's score vector has no entry for, which the projection
/// then classifies as below threshold.
const ABSENT_CANDIDATE_SCORE_PPM: i64 = 0;

/// Rank reported for a candidate the audit's rank vector has no entry for.
const ABSENT_CANDIDATE_RANK: u32 = 0;

/// Headroom below `window / this` raises the context high-watermark event — one order of magnitude
/// left is the last point at which an operator can still act before compaction is forced.
const CONTEXT_HIGH_WATERMARK_DIVISOR: u64 = 10;
use iteron_obs::lifecycle::LifecycleCorrelation;
use iteron_protocol::context::{ContextSegment, ContextSource};
use iteron_protocol::{LifecyclePayload, TurnId, Usage};
use sha2::{Digest, Sha256};

pub(super) use super::request_context_evidence::ContextRequestObservation;

#[derive(Clone, Copy)]
pub(super) struct ResolvedContextObservation<'a> {
    pub(super) turn: TurnId,
    pub(super) task: &'a str,
    pub(super) segments: &'a [ContextSegment],
    pub(super) materialization: &'a iteron_ctx::ContextMaterializationAudit,
    pub(super) memory_audit: Option<&'a MemoryRecallAudit>,
    pub(super) memory_benchmark_scope: Option<&'a [u8; 32]>,
    pub(super) benchmark_memory_rejections: u32,
    pub(super) elapsed_us: u64,
}

impl Agent {
    pub(crate) fn activate_session_memory(
        &mut self,
        id: &str,
        text: &str,
    ) -> Result<(), &'static str> {
        self.activate_session_memory_change(id, text, None)
    }

    pub(crate) fn activate_updated_session_memory(
        &mut self,
        old_id: &str,
        new_id: &str,
        text: &str,
    ) -> Result<(), &'static str> {
        self.activate_session_memory_change(new_id, text, Some(old_id))
    }

    fn activate_session_memory_change(
        &mut self,
        id: &str,
        text: &str,
        superseded_id: Option<&str>,
    ) -> Result<(), &'static str> {
        let workspace = self
            .memory_workspace
            .as_deref()
            .ok_or("memory workspace unavailable")?;
        let activation = super::memory_activation::MemoryActivation::capture(
            workspace,
            id,
            text,
            superseded_id,
            TurnId(self.seq_turn),
        )?;
        self.registry.invalidate_pure_cache();
        self.context_refresh_requested = true;
        if let Some(old_id) = superseded_id {
            self.inbox.retire_memory(old_id);
        }
        self.inbox.retire_memory(id);
        self.inbox
            .push(super::inbound_control::PendingSteer::memory(activation))
            .map_err(|_| "the bounded session refresh queue is full")?;
        Ok(())
    }
    pub(crate) fn deactivate_session_memory(&mut self, id: &str) -> Result<(), &'static str> {
        self.registry.invalidate_pure_cache();
        self.context_refresh_requested = true;
        self.inbox.retire_memory(id);
        let workspace = self
            .memory_workspace
            .as_deref()
            .ok_or("memory workspace unavailable")?;
        let activation = super::memory_activation::MemoryActivation::capture_deletion(
            workspace,
            id,
            TurnId(self.seq_turn),
        )?;
        self.inbox
            .push(super::inbound_control::PendingSteer::memory(activation))
            .map_err(|_| "memory was deleted, but the bounded refresh queue is full")?;
        Ok(())
    }
    pub(super) fn record_memory_safe_point(
        &mut self,
        turn: TurnId,
        source_turn: TurnId,
        body_digest: [u8; 32],
    ) {
        if self.session_memory_visibility.len() == iteron_ctx::MAX_MEMORY_TRACE_VISIBILITY {
            self.session_memory_visibility.pop_front();
        }
        self.session_memory_visibility
            .push_back(MemoryVisibilityEvidence {
                fact_id: memory_fact_id(body_digest),
                fact_digest_sha256: body_digest,
                source_turn,
                destination_turn: turn,
                state: MemoryVisibilityState::Scheduled,
            });
    }

    /// Make an operator-added fact part of this turn's in-process context. This is deliberately
    /// distinct from `Used`: a control request can still stop the turn before a provider transport
    /// is admitted, in which case claiming provider exposure would be false.
    pub(super) fn observe_session_memory_activation(&mut self, turn: TurnId, task: &str) {
        let scheduled = self
            .session_memory_visibility
            .iter_mut()
            .filter(|evidence| {
                evidence.destination_turn == turn
                    && evidence.state == MemoryVisibilityState::Scheduled
            })
            .map(|evidence| {
                evidence.state = MemoryVisibilityState::Activated;
                evidence.clone()
            })
            .collect::<Vec<_>>();
        if scheduled.is_empty() {
            return;
        }
        let has_trace = self
            .memory_traces
            .snapshot()
            .traces
            .iter()
            .any(|trace| trace.turn_id == turn);
        if !has_trace {
            self.memory_traces.publish(MemoryDecisionTrace::new(
                turn,
                MemoryQueryEvidence {
                    query_id: MemoryQueryId(u64::from(turn.0)),
                    query_digest_sha256: digest(task.as_bytes()),
                    bytes: u64::try_from(task.len()).unwrap_or(u64::MAX),
                    estimated_tokens: u64::try_from(self.context_estimator.estimate_text(task))
                        .unwrap_or(u64::MAX),
                    rewrite_count: 0,
                },
                MemoryScopeEvidence {
                    class: MemoryScopeClass::Session,
                    scope_digest_sha256: digest(self.workspace.as_os_str().as_encoded_bytes()),
                    isolation_enabled: true,
                    parent_access_rejections: 0,
                },
            ));
        }
        for activated in &scheduled {
            let mut scheduled_evidence = activated.clone();
            scheduled_evidence.state = MemoryVisibilityState::Scheduled;
            for evidence in [scheduled_evidence, activated.clone()] {
                iteron_ctx::MemoryObserver::observe(
                    &self.memory_traces,
                    turn,
                    iteron_ctx::MemoryObservation::Visibility(evidence),
                );
            }
        }
        let count = u64::try_from(scheduled.len()).unwrap_or(u64::MAX);
        self.lifecycle_event(
            "memory.visibility.activated",
            Some(turn),
            LifecyclePayload {
                count: Some(count),
                reason_code: Some("session_context_activated".into()),
                ..LifecyclePayload::default()
            },
        );
    }

    /// The actual native serialized buffer contains this context and its retained publication
    /// succeeded. "Used" proves request inclusion; it does not prove remote processing.
    pub(super) fn observe_memory_provider_exposure(&mut self, turn: TurnId) {
        let used = self
            .session_memory_visibility
            .iter_mut()
            .filter(|evidence| {
                evidence.destination_turn == turn
                    && evidence.state == MemoryVisibilityState::Activated
            })
            .map(|evidence| {
                evidence.state = MemoryVisibilityState::Used;
                evidence.clone()
            })
            .collect::<Vec<_>>();
        for evidence in &used {
            iteron_ctx::MemoryObserver::observe(
                &self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Visibility(evidence.clone()),
            );
            iteron_ctx::MemoryObserver::observe(
                &self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Attribution(iteron_ctx::MemoryAttributionEvidence {
                    fact_id: evidence.fact_id,
                    cited: false,
                    used_by_tool: false,
                    later_turns_visible: 1,
                }),
            );
        }

        // Attribute stable recalled memory only after the actual prepared-buffer proof.
        let recalled = self
            .memory_traces
            .snapshot()
            .traces
            .into_iter()
            .find(|trace| trace.turn_id == turn)
            .filter(|trace| trace.injection.is_some() && trace.attribution.is_empty())
            .map(|trace| trace.selected)
            .unwrap_or_default();
        for selection in &recalled {
            iteron_ctx::MemoryObserver::observe(
                &self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Attribution(iteron_ctx::MemoryAttributionEvidence {
                    fact_id: selection.fact_id,
                    cited: false,
                    used_by_tool: false,
                    later_turns_visible: 0,
                }),
            );
        }
        let count = u64::try_from(used.len().saturating_add(recalled.len())).unwrap_or(u64::MAX);
        if count > 0 {
            for event_id in ["memory.recall.used", "memory.attribution.recorded"] {
                self.lifecycle_event(
                    event_id,
                    Some(turn),
                    LifecyclePayload {
                        count: Some(count),
                        reason_code: Some("serialized_request_inclusion_confirmed".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }

    pub(super) fn observe_memory_provider_refusal(&mut self, turn: TurnId) {
        self.observe_memory_without_inclusion(turn, "provider_dispatch_refused");
    }

    pub(super) fn observe_memory_inclusion_unconfirmed(&mut self, turn: TurnId) {
        self.observe_memory_without_inclusion(turn, "serialized_request_inclusion_unconfirmed");
    }

    fn observe_memory_without_inclusion(&mut self, turn: TurnId, reason: &'static str) {
        let mut count = 0u64;
        for evidence in self
            .session_memory_visibility
            .iter_mut()
            .filter(|evidence| {
                evidence.destination_turn == turn
                    && evidence.state == MemoryVisibilityState::Activated
            })
        {
            evidence.state = MemoryVisibilityState::Unused;
            count = count.saturating_add(1);
            iteron_ctx::MemoryObserver::observe(
                &self.memory_traces,
                turn,
                iteron_ctx::MemoryObservation::Visibility(evidence.clone()),
            );
        }
        let recalled = self
            .memory_traces
            .snapshot()
            .traces
            .into_iter()
            .find(|trace| trace.turn_id == turn)
            .and_then(|trace| trace.injection)
            .map(|injection| u64::from(injection.fact_count))
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.decision_observability.no_recalled_facts",
                NO_RECALLED_FACTS,
            ));
        count = count.saturating_add(recalled);
        if count > 0 {
            self.lifecycle_event(
                "memory.recall.unused",
                Some(turn),
                LifecyclePayload {
                    count: Some(count),
                    reason_code: Some(reason.into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }

    pub(super) fn observe_context_window_denied(&self, turn: TurnId, excess_tokens: u64) {
        for event_id in [
            "context.window.overflow_predicted",
            "context.segment.budget_denied",
        ] {
            self.lifecycle_event(
                event_id,
                Some(turn),
                LifecyclePayload {
                    magnitude: Some(excess_tokens),
                    reason_code: Some("context_window_exhausted".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }

    pub(crate) fn set_lifecycle_emitter(
        &mut self,
        emitter: iteron_obs::lifecycle::LifecycleEmitter,
    ) {
        self.lifecycle_emitter = Some(emitter);
    }

    pub(crate) fn set_lifecycle_telemetry(
        &mut self,
        telemetry: iteron_obs::otel::lifecycle::LifecycleTelemetryRuntime,
    ) {
        self.lifecycle_telemetry = Some(telemetry);
    }

    pub(crate) fn set_lifecycle_hooks(
        &mut self,
        dispatcher: super::lifecycle_hooks::LifecycleHookDispatcher,
    ) {
        self.lifecycle_hooks = Some(dispatcher);
    }

    pub(crate) fn set_hook_effect_journal(
        &mut self,
        journal: Option<super::hooks::journal::HookEffectJournal>,
    ) {
        self.hook_effect_journal = journal;
    }

    pub(crate) fn lifecycle_event(
        &self,
        event_id: &str,
        turn_id: Option<TurnId>,
        payload: LifecyclePayload,
    ) {
        self.lifecycle_event_with_correlation(
            event_id,
            self.lifecycle_correlation(turn_id),
            payload,
        );
    }

    pub(super) fn lifecycle_event_with_correlation(
        &self,
        event_id: &str,
        correlation: LifecycleCorrelation,
        payload: LifecyclePayload,
    ) {
        let Some(emitter) = &self.lifecycle_emitter else {
            return;
        };
        if let Ok(event) = emitter.emit(event_id, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    pub(super) fn child_lifecycle_event(
        &self,
        event_id: &str,
        turn_id: TurnId,
        subagent_id: &str,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(Some(turn_id));
        correlation.subagent_id = Some(iteron_protocol::SubagentId(subagent_id.to_owned()));
        self.lifecycle_event_with_correlation(event_id, correlation, payload);
    }

    pub(super) fn lifecycle_correlation(&self, turn_id: Option<TurnId>) -> LifecycleCorrelation {
        LifecycleCorrelation {
            session_id: Some(iteron_protocol::SessionId(format!(
                "session-{}",
                self.rollout.run_id().0
            ))),
            run_id: Some(self.rollout.run_id().clone()),
            turn_id,
            ..LifecycleCorrelation::default()
        }
    }

    pub(super) fn tool_events(&self, turn: TurnId) -> super::stream_tool_events::StreamToolEvents {
        super::stream_tool_events::StreamToolEvents {
            frontend: self.frontend_saturation.clone(),
            ui: self.ui_tx.clone(),
            resident_ui: self.resident_ui_tx.clone(),
            lifecycle: self.lifecycle_emitter.clone(),
            lifecycle_hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        }
    }

    pub(super) fn tool_lifecycle_event(
        &self,
        event_id: &str,
        turn_id: TurnId,
        effect_id: Option<iteron_protocol::EffectId>,
        payload: LifecyclePayload,
    ) {
        self.tool_events(turn_id).emit(event_id, effect_id, payload);
    }

    pub(super) fn observe_process_tool_started(
        &self,
        turn_id: TurnId,
        effect_id: iteron_protocol::EffectId,
        call: &iteron_protocol::ToolUse,
    ) {
        if matches!(call.name.as_str(), "bash" | "process_start") {
            self.tool_events(turn_id).emit(
                "process.spawn_requested",
                Some(effect_id),
                LifecyclePayload::default(),
            );
        }
    }

    pub(super) fn observe_process_tool_terminal(
        &self,
        turn_id: TurnId,
        effect_id: iteron_protocol::EffectId,
        tool: &str,
        result: &ToolResult,
        definite: bool,
    ) {
        self.tool_events(turn_id)
            .process_terminal(effect_id, tool, result, definite);
    }

    /// Capture live context source decisions as digests and magnitudes before their bytes are
    /// folded into the stable prefix.
    pub(super) fn observe_resolved_context(&mut self, observation: ResolvedContextObservation<'_>) {
        self.observe_memory_resolution(&observation);
        let ResolvedContextObservation {
            turn,
            task: _,
            segments,
            materialization,
            memory_audit: _,
            memory_benchmark_scope: _,
            benchmark_memory_rejections: _,
            elapsed_us,
        } = observation;
        let token_cursor = self
            .context_source_evidence
            .replace_materialized(materialization, elapsed_us);
        let selected = materialization
            .segments
            .iter()
            .filter(|evidence| {
                matches!(
                    evidence.decision,
                    ContextDecision::Selected
                        | ContextDecision::Truncated
                        | ContextDecision::Compacted
                )
            })
            .count();
        let rejected = materialization
            .segments
            .iter()
            .filter(|evidence| evidence.decision == ContextDecision::Rejected)
            .count();
        let truncated = materialization
            .segments
            .iter()
            .filter(|evidence| evidence.decision == ContextDecision::Truncated)
            .collect::<Vec<_>>();
        self.lifecycle_event(
            "context.source.classified",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(materialization.segments.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.source.selected",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(selected).unwrap_or(u64::MAX)),
                duration_us: Some(elapsed_us),
                magnitude: Some(
                    segments
                        .iter()
                        .map(|segment| u64::try_from(segment.text.len()).unwrap_or(u64::MAX))
                        .fold(0, u64::saturating_add),
                ),
                ..LifecyclePayload::default()
            },
        );
        if rejected > 0 {
            self.lifecycle_event(
                "context.source.rejected",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(rejected).unwrap_or(u64::MAX)),
                    reason_code: Some("context_materialization_budget".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if !truncated.is_empty() {
            self.lifecycle_event(
                "context.source.truncated",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(truncated.len()).unwrap_or(u64::MAX)),
                    magnitude: Some(truncated.iter().fold(0u64, |total, evidence| {
                        total.saturating_add(
                            evidence.bytes_before.saturating_sub(evidence.bytes_after),
                        )
                    })),
                    reason_code: Some("context_materialization_budget".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.lifecycle_event(
            "context.source.serialized",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(segments.len()).unwrap_or(u64::MAX)),
                magnitude: Some(token_cursor),
                ..LifecyclePayload::default()
            },
        );
    }

    pub(super) fn observe_recorded_context(&mut self, turn: TurnId, text: &str, trust: Trust) {
        let tokens =
            self.context_source_evidence
                .replace_recorded(text, trust, &self.context_estimator);
        self.lifecycle_event(
            "context.source.classified",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.source.selected",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(text.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.source.serialized",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(tokens),
                ..LifecyclePayload::default()
            },
        );
    }

    pub(super) fn observe_context_request(
        &self,
        turn: TurnId,
        observation: ContextRequestObservation<'_>,
    ) {
        let estimate = observation.estimate;
        let output_reserved_tokens = observation.output_reserved_tokens;
        let elapsed_us = observation.elapsed_us;
        let messages = observation.messages;
        let tools = observation.tools;
        let execution_window = self.execution_context_window();
        let request = self.context_source_evidence.build_request(
            turn,
            super::request_context_evidence::RequestContextScope {
                execution_window,
                request_trust: self.governing_turn_trust(messages),
                estimator: &self.context_estimator,
                file: self.input_file_evidence,
                image: self.input_image_evidence,
            },
            observation,
        );
        let ledger = request.ledger;
        for (event_id, payload) in request.observations {
            self.lifecycle_event(event_id, Some(turn), payload);
        }
        let segment_count = u64::try_from(ledger.segments.len()).unwrap_or(u64::MAX);
        let stable_prefix_tokens = ledger.cache.stable_prefix_tokens;
        let headroom = ledger.headroom_tokens();
        self.context_ledgers.publish(ledger);
        for event_id in ["context.segment.created", "context.segment.ordered"] {
            self.lifecycle_event(
                event_id,
                Some(turn),
                LifecyclePayload {
                    count: Some(segment_count),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.lifecycle_event(
            "context.segment.budget_granted",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        if let Some(window) = execution_window {
            self.lifecycle_event(
                "context.window.capacity_resolved",
                Some(turn),
                LifecyclePayload {
                    magnitude: Some(window),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.lifecycle_event(
            "context.window.output_reserved",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(u64::from(output_reserved_tokens)),
                ..LifecyclePayload::default()
            },
        );
        if let Some(headroom) = headroom {
            self.lifecycle_event(
                "context.window.headroom_updated",
                Some(turn),
                LifecyclePayload {
                    magnitude: Some(headroom),
                    ..LifecyclePayload::default()
                },
            );
            if execution_window.is_some_and(|window| {
                headroom.saturating_mul(iteron_tunables::param_integer(
                    "cli.runtime.decision_observability.context_high_watermark_divisor",
                    CONTEXT_HIGH_WATERMARK_DIVISOR,
                )) < window
            }) {
                self.lifecycle_event(
                    "context.window.high_watermark",
                    Some(turn),
                    LifecyclePayload {
                        magnitude: Some(headroom),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
        self.lifecycle_event(
            "context.tool_schema.admitted",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(tools.len()).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.stable_prefix.computed",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(stable_prefix_tokens),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.cache_region.classified",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(stable_prefix_tokens),
                reason_code: Some("cache_candidate".into()),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.request.serialized",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(messages.len()).unwrap_or(u64::MAX)),
                duration_us: Some(elapsed_us),
                magnitude: Some(u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
    }

    pub(super) fn observe_context_usage(&mut self, turn: TurnId, usage: Usage) {
        use iteron_ctx::{ContextObservation, ContextObserver};
        let actual_input_tokens = usage
            .input
            .saturating_add(usage.cache_read)
            .saturating_add(usage.cache_creation);
        let matching_ledger = self
            .context_ledgers
            .snapshot()
            .ledgers
            .into_iter()
            .find(|ledger| ledger.turn_id == turn);
        let estimated_input_tokens = matching_ledger
            .as_ref()
            .map(|ledger| ledger.totals.estimated_tokens);
        let uncalibrated_input_tokens = self.take_token_estimate_baseline(turn);
        if let Some(mut ledger) = matching_ledger {
            // Provider usage is the first authority that can distinguish an actual cache hit,
            // cache population, and uncached prefill. Replace the pre-dispatch estimate in the
            // same bounded turn slot instead of leaving those three public counters at zero.
            ledger.totals.actual_input_tokens = Some(actual_input_tokens);
            ledger.cache.cache_read_tokens = usage.cache_read;
            ledger.cache.cache_write_tokens = usage.cache_creation;
            ledger.cache.uncached_tokens = usage.input;
            self.context_ledgers.publish(ledger);
        } else {
            self.context_ledgers.observe(
                turn,
                ContextObservation::ProviderUsage {
                    actual_input_tokens,
                    cache_read_tokens: usage.cache_read,
                    cache_write_tokens: usage.cache_creation,
                    uncached_tokens: usage.input,
                },
            );
        }
        self.lifecycle_event(
            "context.tokenizer.actual_observed",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(actual_input_tokens),
                ..LifecyclePayload::default()
            },
        );
        if let Some(estimated) = estimated_input_tokens {
            let (provider_id, model_id) = self.token_calibration_route();
            let calibration = uncalibrated_input_tokens.and_then(|baseline| {
                self.token_calibration
                    .observe_actual_input(provider_id, model_id, baseline, actual_input_tokens)
                    .ok()
            });
            self.lifecycle_event(
                "context.tokenizer.error_calculated",
                Some(turn),
                LifecyclePayload {
                    magnitude: Some(estimated.abs_diff(actual_input_tokens)),
                    outcome_code: Some(
                        match estimated.cmp(&actual_input_tokens) {
                            std::cmp::Ordering::Less => "underestimated",
                            std::cmp::Ordering::Equal => "exact",
                            std::cmp::Ordering::Greater => "overestimated",
                        }
                        .into(),
                    ),
                    ..LifecyclePayload::default()
                },
            );
            match calibration {
                Some(observation) => self.lifecycle_event(
                    "context.tokenizer.error_calculated",
                    Some(turn),
                    LifecyclePayload {
                        magnitude: Some(observation.error_ppm),
                        outcome_code: Some(
                            if observation.drifted {
                                "drifted_conservative"
                            } else {
                                "ewma_updated"
                            }
                            .into(),
                        ),
                        count: Some(observation.ratio_ppm),
                        reason_code: Some("calibration_updated".into()),
                        ..LifecyclePayload::default()
                    },
                ),
                None => self.lifecycle_event(
                    "context.tokenizer.error_calculated",
                    Some(turn),
                    LifecyclePayload {
                        outcome_code: Some("calibration_rejected".into()),
                        ..LifecyclePayload::default()
                    },
                ),
            }
        }
        self.lifecycle_event(
            "context.request.usage_reconciled",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(usage.input),
                ..LifecyclePayload::default()
            },
        );
        for (reason_code, tokens) in [
            ("cache_read", usage.cache_read),
            ("cache_write", usage.cache_creation),
            ("cache_miss", usage.input),
        ] {
            if tokens > 0 {
                self.lifecycle_event(
                    "context.cache_region.classified",
                    Some(turn),
                    LifecyclePayload {
                        magnitude: Some(tokens),
                        reason_code: Some(reason_code.into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }

    fn observe_memory_resolution(&self, observation: &ResolvedContextObservation<'_>) {
        let ResolvedContextObservation {
            turn,
            task,
            segments,
            materialization: _,
            memory_audit,
            memory_benchmark_scope,
            benchmark_memory_rejections,
            elapsed_us,
        } = *observation;
        let memory_segments = segments
            .iter()
            .filter(|segment| segment.source == ContextSource::Memory)
            .collect::<Vec<_>>();
        let requested_bytes = memory_segments.iter().fold(0u64, |total, segment| {
            total.saturating_add(u64::try_from(segment.text.len()).unwrap_or(u64::MAX))
        });
        let requested_tokens = memory_segments.iter().fold(0u64, |total, segment| {
            total.saturating_add(
                u64::try_from(self.context_estimator.estimate_text(&segment.text))
                    .unwrap_or(u64::MAX),
            )
        });
        let query = memory_audit
            .map(|audit| audit.rewritten_query.as_str())
            .unwrap_or(task);
        let rewrite_count = memory_audit.map(|audit| audit.rewrite_count).unwrap_or(
            iteron_tunables::param_integer(
                "cli.runtime.decision_observability.no_query_rewrites",
                NO_QUERY_REWRITES,
            ),
        );
        let parent_access_rejections = memory_audit
            .map(|audit| {
                audit
                    .excluded_candidates
                    .iter()
                    .filter(|candidate| {
                        matches!(candidate.kind, MemoryRecallExclusionKind::ScopeDenied)
                    })
                    .count()
            })
            .and_then(|count| u32::try_from(count).ok())
            .unwrap_or(iteron_tunables::param_integer(
                "cli.runtime.decision_observability.uncounted_memory_candidates",
                UNCOUNTED_MEMORY_CANDIDATES,
            ))
            .saturating_add(benchmark_memory_rejections);
        let mut trace = MemoryDecisionTrace::new(
            turn,
            MemoryQueryEvidence {
                query_id: MemoryQueryId(u64::from(turn.0)),
                query_digest_sha256: digest(query.as_bytes()),
                bytes: u64::try_from(query.len()).unwrap_or(u64::MAX),
                estimated_tokens: u64::try_from(self.context_estimator.estimate_text(query))
                    .unwrap_or(u64::MAX),
                rewrite_count,
            },
            MemoryScopeEvidence {
                class: if memory_benchmark_scope.is_some() {
                    MemoryScopeClass::BenchmarkAttempt
                } else {
                    MemoryScopeClass::Workspace
                },
                scope_digest_sha256: memory_benchmark_scope
                    .copied()
                    .unwrap_or_else(|| digest(self.workspace.as_os_str().as_encoded_bytes())),
                isolation_enabled: true,
                parent_access_rejections,
            },
        );
        if rewrite_count > 0 {
            self.lifecycle_event(
                "memory.query.rewritten",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(rewrite_count)),
                    reason_code: Some("whitespace_normalized".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if memory_benchmark_scope.is_some() {
            self.lifecycle_event(
                "memory.benchmark.scope_created",
                Some(turn),
                LifecyclePayload::default(),
            );
        }
        self.lifecycle_event(
            "memory.scope.resolved",
            Some(turn),
            LifecyclePayload::default(),
        );
        trace.record_store(MemoryStoreEvidence {
            store_id: 0,
            tier: MemoryTierClass::Project,
            store_digest_sha256: digest(self.workspace.as_os_str().as_encoded_bytes()),
            opened: self.memory_workspace.is_some(),
            scanned_items: memory_audit
                .map(|audit| u32::try_from(audit.observation.candidates.len()).unwrap_or(u32::MAX))
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.runtime.decision_observability.uncounted_memory_candidates",
                    UNCOUNTED_MEMORY_CANDIDATES,
                )),
            elapsed_us,
            failure_code: None,
        });
        self.lifecycle_event(
            if self.memory_workspace.is_some() {
                "memory.store.opened"
            } else {
                "memory.store.failed"
            },
            Some(turn),
            LifecyclePayload {
                reason_code: self
                    .memory_workspace
                    .is_none()
                    .then(|| "workspace_memory_unavailable".into()),
                ..LifecyclePayload::default()
            },
        );
        if let Some(audit) = memory_audit {
            let candidate_count = u64::try_from(
                audit.observation.candidates.len().saturating_add(
                    audit
                        .excluded_candidates
                        .iter()
                        .filter(|candidate| {
                            !matches!(candidate.kind, MemoryRecallExclusionKind::ScopeDenied)
                        })
                        .count(),
                ),
            )
            .unwrap_or(u64::MAX);
            for event_id in [
                "memory.store.scanned",
                "memory.candidate.discovered",
                "memory.candidate.scored",
                "memory.candidate.ranked",
            ] {
                self.lifecycle_event(
                    event_id,
                    Some(turn),
                    LifecyclePayload {
                        count: Some(candidate_count),
                        ..LifecyclePayload::default()
                    },
                );
            }
            let deduplicated_candidates = audit.deduplicated_candidates.saturating_add(
                u32::try_from(audit.novelty_deduplicated.len()).unwrap_or(u32::MAX),
            );
            if deduplicated_candidates > 0 {
                for event_id in [
                    "memory.candidate.deduplicated",
                    "context.source.deduplicated",
                ] {
                    self.lifecycle_event(
                        event_id,
                        Some(turn),
                        LifecyclePayload {
                            count: Some(u64::from(deduplicated_candidates)),
                            reason_code: Some("stable_slug_or_novelty_threshold".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                }
            }
            let mut requested_candidate_bytes = 0u64;
            let mut requested_candidate_tokens = 0u64;
            let mut granted_candidate_bytes = 0u64;
            let mut granted_candidate_tokens = 0u64;
            let mut filtered_candidates = 0u64;
            let mut budget_denied_candidates = 0u64;
            for (index, candidate) in audit.observation.candidates.iter().enumerate() {
                let candidate_digest = digest(candidate.text.as_bytes());
                let candidate_tokens =
                    u64::try_from(self.context_estimator.estimate_text(&candidate.text))
                        .unwrap_or(u64::MAX);
                let candidate_bytes = u64::try_from(candidate.framed_bytes).unwrap_or(u64::MAX);
                requested_candidate_bytes =
                    requested_candidate_bytes.saturating_add(candidate_bytes);
                requested_candidate_tokens =
                    requested_candidate_tokens.saturating_add(candidate_tokens);
                let selected_ordinal = audit
                    .selected
                    .iter()
                    .position(|slug| slug == &candidate.slug);
                let scope_denied = audit.excluded_candidates.iter().any(|excluded| {
                    excluded.slug == candidate.slug
                        && matches!(excluded.kind, MemoryRecallExclusionKind::ScopeDenied)
                });
                let decision = if scope_denied {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    MemoryCandidateDecision::ScopeDenied
                } else if selected_ordinal.is_some() {
                    granted_candidate_bytes =
                        granted_candidate_bytes.saturating_add(candidate_bytes);
                    granted_candidate_tokens =
                        granted_candidate_tokens.saturating_add(candidate_tokens);
                    MemoryCandidateDecision::Selected
                } else if candidate.trust < audit.observation.trust_floor {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    MemoryCandidateDecision::TrustDenied
                } else if audit.novelty_deduplicated.contains(&candidate.slug) {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    MemoryCandidateDecision::Duplicate
                } else if audit.scores_ppm.get(index).copied().unwrap_or(
                    iteron_tunables::param_integer(
                        "cli.runtime.decision_observability.absent_candidate_score_ppm",
                        ABSENT_CANDIDATE_SCORE_PPM,
                    ),
                ) <= 0
                {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    MemoryCandidateDecision::BelowThreshold
                } else {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    budget_denied_candidates = budget_denied_candidates.saturating_add(1);
                    MemoryCandidateDecision::BudgetDenied
                };
                let fact_id = memory_fact_id(candidate_digest);
                trace.record_candidate(MemoryCandidateEvidence {
                    fact_id,
                    fact_digest_sha256: candidate_digest,
                    store_id: 0,
                    tier: memory_tier(candidate.trust),
                    trust: candidate.trust,
                    bm25_term_ppm: audit.lexical_scores_ppm.get(index).copied().unwrap_or(
                        iteron_tunables::param_integer(
                            "cli.runtime.decision_observability.absent_candidate_score_ppm",
                            ABSENT_CANDIDATE_SCORE_PPM,
                        ),
                    ),
                    bm25_length_ppm: audit.structural_scores_ppm.get(index).copied().unwrap_or(
                        iteron_tunables::param_integer(
                            "cli.runtime.decision_observability.absent_candidate_score_ppm",
                            ABSENT_CANDIDATE_SCORE_PPM,
                        ),
                    ),
                    semantic_ppm: Some(audit.structural_scores_ppm.get(index).copied().unwrap_or(
                        iteron_tunables::param_integer(
                            "cli.runtime.decision_observability.absent_candidate_score_ppm",
                            ABSENT_CANDIDATE_SCORE_PPM,
                        ),
                    )),
                    recency_ppm: i64::from(
                        audit
                            .recency_multipliers_ppm
                            .get(index)
                            .copied()
                            .unwrap_or(iteron_ctx::SCORE_SCALE),
                    ),
                    confidence_ppm: i64::from(candidate.confidence_ppm),
                    combined_ppm: audit.scores_ppm.get(index).copied().unwrap_or(
                        iteron_tunables::param_integer(
                            "cli.runtime.decision_observability.absent_candidate_score_ppm",
                            ABSENT_CANDIDATE_SCORE_PPM,
                        ),
                    ),
                    threshold_ppm: 1,
                    rank: audit.ranks.get(index).copied().unwrap_or(
                        iteron_tunables::param_integer(
                            "cli.runtime.decision_observability.absent_candidate_rank",
                            ABSENT_CANDIDATE_RANK,
                        ),
                    ),
                    requested_bytes: candidate_bytes,
                    requested_tokens: candidate_tokens,
                    decision,
                    related_fact_id: None,
                });
                if let Some(ordinal) = selected_ordinal {
                    trace.record_selection(MemorySelectionEvidence {
                        fact_id,
                        ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                        granted_bytes: candidate_bytes,
                        granted_tokens: candidate_tokens,
                        segment_id: None,
                        token_range: None,
                    });
                }
            }
            for excluded in audit.excluded_candidates.iter().filter(|candidate| {
                !matches!(candidate.kind, MemoryRecallExclusionKind::ScopeDenied)
            }) {
                let candidate_digest = digest(excluded.evidence_text.as_bytes());
                let related_fact_id = excluded
                    .related_slug
                    .as_ref()
                    .map(|slug| memory_fact_id(digest(slug.as_bytes())));
                let (decision, event_id, reason_code) = match excluded.kind {
                    MemoryRecallExclusionKind::Superseded => (
                        MemoryCandidateDecision::Superseded,
                        "memory.candidate.superseded",
                        "higher_precedence_slug",
                    ),
                    MemoryRecallExclusionKind::Contradiction => (
                        MemoryCandidateDecision::Contradiction,
                        "memory.candidate.contradiction",
                        "conflicting_title_higher_precedence",
                    ),
                    MemoryRecallExclusionKind::Expired => (
                        MemoryCandidateDecision::Expired,
                        "memory.candidate.expired",
                        "indexed_body_unavailable",
                    ),
                    MemoryRecallExclusionKind::ScopeDenied => unreachable!(
                        "scope-denied materialized candidates are recorded in observation order"
                    ),
                };
                let candidate_bytes =
                    u64::try_from(excluded.evidence_text.len()).unwrap_or(u64::MAX);
                let candidate_tokens = u64::try_from(
                    self.context_estimator
                        .estimate_text(&excluded.evidence_text),
                )
                .unwrap_or(u64::MAX);
                requested_candidate_bytes =
                    requested_candidate_bytes.saturating_add(candidate_bytes);
                requested_candidate_tokens =
                    requested_candidate_tokens.saturating_add(candidate_tokens);
                filtered_candidates = filtered_candidates.saturating_add(1);
                trace.record_candidate(MemoryCandidateEvidence {
                    fact_id: memory_fact_id(candidate_digest),
                    fact_digest_sha256: candidate_digest,
                    store_id: 0,
                    tier: memory_tier(excluded.trust),
                    trust: excluded.trust,
                    bm25_term_ppm: 0,
                    bm25_length_ppm: 0,
                    semantic_ppm: None,
                    recency_ppm: 0,
                    confidence_ppm: 0,
                    combined_ppm: 0,
                    threshold_ppm: 1,
                    rank: 0,
                    requested_bytes: candidate_bytes,
                    requested_tokens: candidate_tokens,
                    decision,
                    related_fact_id,
                });
                self.lifecycle_event(
                    event_id,
                    Some(turn),
                    LifecyclePayload {
                        count: Some(1),
                        reason_code: Some(reason_code.into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
            trace.budget = MemoryBudgetEvidence {
                requested_bytes: requested_candidate_bytes,
                granted_bytes: granted_candidate_bytes,
                requested_tokens: requested_candidate_tokens,
                granted_tokens: granted_candidate_tokens,
                candidate_limit: u32::try_from(audit.observation.max_recalled).unwrap_or(u32::MAX),
                selected_count: u32::try_from(audit.selected.len()).unwrap_or(u32::MAX),
            };
            self.lifecycle_event(
                "memory.candidate.filtered",
                Some(turn),
                LifecyclePayload {
                    count: Some(filtered_candidates),
                    ..LifecyclePayload::default()
                },
            );
            if budget_denied_candidates > 0 {
                self.lifecycle_event(
                    "memory.budget.denied",
                    Some(turn),
                    LifecyclePayload {
                        count: Some(budget_denied_candidates),
                        reason_code: Some("candidate_budget_exhausted".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
            self.lifecycle_event(
                "memory.budget.granted",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(audit.selected.len()).unwrap_or(u64::MAX)),
                    magnitude: Some(granted_candidate_bytes),
                    ..LifecyclePayload::default()
                },
            );
            self.lifecycle_event(
                if audit.selected.is_empty() {
                    "memory.recall.rejected"
                } else {
                    "memory.recall.selected"
                },
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(audit.selected.len()).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            );
        } else {
            trace.budget = MemoryBudgetEvidence {
                requested_bytes,
                granted_bytes: requested_bytes,
                requested_tokens,
                granted_tokens: requested_tokens,
                candidate_limit: u32::try_from(iteron_ctx::MAX_MEMORY_CANDIDATES)
                    .unwrap_or(u32::MAX),
                selected_count: u32::try_from(memory_segments.len()).unwrap_or(u32::MAX),
            };
            self.lifecycle_event(
                "memory.budget.granted",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(memory_segments.len()).unwrap_or(u64::MAX)),
                    magnitude: Some(requested_bytes),
                    ..LifecyclePayload::default()
                },
            );
            self.lifecycle_event(
                if memory_segments.is_empty() {
                    "memory.recall.rejected"
                } else {
                    "memory.recall.selected"
                },
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(memory_segments.len()).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            );
        }
        if let Some(scope_digest_sha256) = memory_benchmark_scope {
            let checked_candidates = memory_audit
                .map(|audit| {
                    audit.observation.candidates.len().saturating_add(
                        audit
                            .excluded_candidates
                            .iter()
                            .filter(|candidate| {
                                !matches!(candidate.kind, MemoryRecallExclusionKind::ScopeDenied)
                            })
                            .count(),
                    )
                })
                .and_then(|count| u32::try_from(count).ok())
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.runtime.decision_observability.uncounted_memory_candidates",
                    UNCOUNTED_MEMORY_CANDIDATES,
                ));
            let rejected_candidates = memory_audit
                .map(|audit| {
                    audit
                        .excluded_candidates
                        .iter()
                        .filter(|candidate| {
                            matches!(candidate.kind, MemoryRecallExclusionKind::ScopeDenied)
                        })
                        .count()
                })
                .and_then(|count| u32::try_from(count).ok())
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.runtime.decision_observability.uncounted_memory_candidates",
                    UNCOUNTED_MEMORY_CANDIDATES,
                ))
                .saturating_add(benchmark_memory_rejections);
            let leaked = !memory_segments.is_empty()
                || memory_audit.is_some_and(|audit| !audit.selected.is_empty());
            self.lifecycle_event(
                "memory.contamination.check_started",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(checked_candidates)),
                    ..LifecyclePayload::default()
                },
            );
            self.lifecycle_event(
                if leaked {
                    "memory.contamination.check_failed"
                } else {
                    "memory.contamination.check_passed"
                },
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(rejected_candidates)),
                    outcome_code: Some(if leaked { "contaminated" } else { "isolated" }.into()),
                    ..LifecyclePayload::default()
                },
            );
            trace.contamination = Some(ContaminationEvidence {
                scope_digest_sha256: *scope_digest_sha256,
                checked_candidates,
                rejected_candidates,
                canary_matches: 0,
                passed: !leaked,
            });
        }
        self.lifecycle_event(
            "memory.policy.decision",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(memory_segments.len()).unwrap_or(u64::MAX)),
                magnitude: Some(requested_tokens),
                outcome_code: Some(
                    if memory_segments.is_empty() {
                        "no_recall"
                    } else {
                        "recalled"
                    }
                    .into(),
                ),
                ..LifecyclePayload::default()
            },
        );
        if requested_bytes > 0 {
            let mut digest_input = Sha256::new();
            for segment in &memory_segments {
                digest_input.update(segment.text.as_bytes());
            }
            trace.injection = Some(MemoryInjectionEvidence {
                segment_digest_sha256: digest_input.finalize().into(),
                fact_count: u32::try_from(memory_segments.len()).unwrap_or(u32::MAX),
                bytes: requested_bytes,
                estimated_tokens: requested_tokens,
                actual_tokens: None,
            });
        }
        self.memory_traces.publish(trace);
        if requested_bytes > 0 {
            self.lifecycle_event(
                "memory.recall.serialized",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(memory_segments.len()).unwrap_or(u64::MAX)),
                    magnitude: Some(requested_bytes),
                    ..LifecyclePayload::default()
                },
            );
            self.lifecycle_event(
                "memory.recall.injected",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(memory_segments.len()).unwrap_or(u64::MAX)),
                    duration_us: Some(elapsed_us),
                    magnitude: Some(requested_tokens),
                    ..LifecyclePayload::default()
                },
            );
        } else if memory_audit.is_some_and(|audit| !audit.selected.is_empty()) {
            self.lifecycle_event(
                "memory.recall.unused",
                Some(turn),
                LifecyclePayload {
                    reason_code: Some("not_serialized".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }
}

fn memory_fact_id(digest: [u8; 32]) -> MemoryFactId {
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    MemoryFactId(u64::from_be_bytes(head))
}

fn memory_tier(trust: Trust) -> MemoryTierClass {
    match trust {
        Trust::Trusted => MemoryTierClass::User,
        Trust::Workspace | Trust::Untrusted => MemoryTierClass::Project,
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
