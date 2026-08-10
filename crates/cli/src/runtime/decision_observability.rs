//! Content-free context/memory decision evidence and lifecycle emission.

use super::*;
use iteron_ctx::{
    CacheClass, ContextDecision, ContextDecisionReason, ContextLedger, ContextSegmentEvidence,
    ContextSegmentId, ContextSourceClass, ContextTransformEvidence, ContextTransformKind,
    MemoryBudgetEvidence, MemoryCandidateDecision, MemoryCandidateEvidence, MemoryDecisionTrace,
    MemoryFactId, MemoryInjectionEvidence, MemoryQueryEvidence, MemoryQueryId, MemoryRecallAudit,
    MemoryScopeClass, MemoryScopeEvidence, MemorySelectionEvidence, MemoryStoreEvidence,
    MemoryTierClass, MemoryVisibilityEvidence, MemoryVisibilityState, TokenRange,
    TokenizerIdentity,
};
use iteron_obs::lifecycle::LifecycleCorrelation;
use iteron_protocol::context::{ContextSegment, ContextSource};
use iteron_protocol::{LifecyclePayload, Message, Role, ToolSpec, TurnId, Usage};
use sha2::{Digest, Sha256};

pub(super) struct ContextRequestObservation<'a> {
    pub(super) system: &'a str,
    pub(super) messages: &'a [Message],
    pub(super) tools: &'a [ToolSpec],
    pub(super) images: &'a [iteron_protocol::ImageContent],
    pub(super) estimate: iteron_ctx::ContextEstimate,
    pub(super) output_reserved_tokens: u32,
    pub(super) elapsed_us: u64,
}

impl Agent {
    pub(crate) fn activate_session_memory(
        &mut self,
        id: &str,
        text: &str,
    ) -> Result<(), &'static str> {
        if self.pending_steers.len() >= MAX_INBOUND_OPS_PER_POLL {
            return Err("the bounded session refresh queue is full");
        }
        let source_turn = TurnId(self.seq_turn);
        let destination_turn = if self.working_set.is_some() {
            TurnId(
                self.seq_turn
                    .checked_add(1)
                    .ok_or("turn identity exhausted")?,
            )
        } else {
            source_turn
        };
        let fact_digest_sha256 = digest(text.as_bytes());
        if self.session_memory_visibility.len() == iteron_ctx::MAX_MEMORY_TRACE_VISIBILITY {
            self.session_memory_visibility.pop_front();
        }
        self.session_memory_visibility
            .push_back(MemoryVisibilityEvidence {
                fact_id: memory_fact_id(fact_digest_sha256),
                fact_digest_sha256,
                source_turn,
                destination_turn,
                state: MemoryVisibilityState::Scheduled,
            });
        self.registry.invalidate_pure_cache();
        let fact = strict_utf8_head(text, MAX_STEER_BYTES.saturating_sub(1024));
        self.pending_steers.push_back(format!(
            "{MEMORY_ADDED_NOTIFICATION_PREFIX}\nMemory `{id}` was added explicitly by the operator \
             and is available in this session. Exact fact:\n{fact}\n\nUse this fact when relevant. \
             `read_memory` can retrieve it by id; the stable REC-INJECT prefix remains unchanged."
        ));
        Ok(())
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
                    estimated_tokens: u64::try_from(iteron_ctx::estimate_tokens(task))
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

    /// Commit the exact point at which serialized memory crosses the provider transport boundary.
    /// "Used" here means provider-context exposure; it never claims the model relied on the fact.
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

        // Stable recalled memory is serialized before request construction. Attribute it only now,
        // once the provider boundary is actually admitted, and only once for this physical turn.
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
                        reason_code: Some("provider_transport_admitted".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }

    pub(super) fn observe_memory_provider_refusal(&mut self, turn: TurnId) {
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
            .unwrap_or(0);
        count = count.saturating_add(recalled);
        if count > 0 {
            self.lifecycle_event(
                "memory.recall.unused",
                Some(turn),
                LifecyclePayload {
                    count: Some(count),
                    reason_code: Some("provider_dispatch_refused".into()),
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

    pub(super) fn tool_lifecycle_event(
        &self,
        event_id: &str,
        turn_id: TurnId,
        effect_id: Option<iteron_protocol::EffectId>,
        payload: LifecyclePayload,
    ) {
        let Some(emitter) = &self.lifecycle_emitter else {
            return;
        };
        let mut correlation = self.lifecycle_correlation(Some(turn_id));
        correlation.effect_id = effect_id;
        if let Ok(event) = emitter.emit(event_id, correlation, payload)
            && let Some(dispatcher) = &self.lifecycle_hooks
        {
            dispatcher.dispatch(event);
        }
    }

    pub(super) fn observe_process_tool_started(
        &self,
        turn_id: TurnId,
        effect_id: iteron_protocol::EffectId,
        call: &iteron_protocol::ToolUse,
    ) {
        let event_id = match call.name.as_str() {
            "bash" | "process_start" => "process.spawn_requested",
            _ => return,
        };
        self.tool_lifecycle_event(
            event_id,
            turn_id,
            Some(effect_id),
            LifecyclePayload::default(),
        );
    }

    pub(super) fn observe_process_tool_terminal(
        &self,
        turn_id: TurnId,
        effect_id: iteron_protocol::EffectId,
        tool: &str,
        result: &ToolResult,
        definite: bool,
    ) {
        let value = (!result.is_error)
            .then(|| serde_json::from_str::<serde_json::Value>(&result.content).ok())
            .flatten();
        let job_id = value
            .as_ref()
            .and_then(|value| value.get("job_id"))
            .and_then(serde_json::Value::as_str);
        match tool {
            "bash" => {
                if definite
                    && (result.content.starts_with("[exit ")
                        || result.content.contains("[timed out after"))
                {
                    self.tool_lifecycle_event(
                        "process.spawned",
                        turn_id,
                        Some(effect_id.clone()),
                        LifecyclePayload::default(),
                    );
                    self.tool_lifecycle_event(
                        "process.reaped",
                        turn_id,
                        Some(effect_id),
                        LifecyclePayload {
                            duration_us: Some(result.latency_ms.saturating_mul(1_000)),
                            ..LifecyclePayload::default()
                        },
                    );
                } else if !definite {
                    if result.content.contains("interrupted") {
                        self.tool_lifecycle_event(
                            "process.kill_sent",
                            turn_id,
                            Some(effect_id.clone()),
                            LifecyclePayload::default(),
                        );
                    }
                    self.tool_lifecycle_event(
                        "process.reap_failed",
                        turn_id,
                        Some(effect_id),
                        LifecyclePayload::default(),
                    );
                }
            }
            "process_start" if definite && !result.is_error => {}
            "process_poll" if definite && !result.is_error => {
                let output_bytes = value
                    .as_ref()
                    .map(|value| {
                        ["stdout", "stderr"]
                            .into_iter()
                            .fold(0u64, |total, stream| {
                                total.saturating_add(
                                    value
                                        .get(stream)
                                        .and_then(|stream| stream.get("text"))
                                        .and_then(serde_json::Value::as_str)
                                        .map(|text| u64::try_from(text.len()).unwrap_or(u64::MAX))
                                        .unwrap_or(0),
                                )
                            })
                    })
                    .unwrap_or(0);
                if output_bytes > 0 {
                    self.process_lifecycle_event(
                        "tool.output_chunk",
                        turn_id,
                        effect_id.clone(),
                        job_id,
                        LifecyclePayload {
                            magnitude: Some(output_bytes),
                            ..LifecyclePayload::default()
                        },
                    );
                }
                self.process_lifecycle_event(
                    "background.attached",
                    turn_id,
                    effect_id,
                    job_id,
                    LifecyclePayload::default(),
                );
            }
            "process_write" if definite && !result.is_error => self.process_lifecycle_event(
                "background.input_written",
                turn_id,
                effect_id,
                job_id,
                LifecyclePayload {
                    magnitude: value
                        .as_ref()
                        .and_then(|value| value.get("accepted_bytes"))
                        .and_then(serde_json::Value::as_u64),
                    ..LifecyclePayload::default()
                },
            ),
            "process_stop" if definite && !result.is_error => {}
            _ => {}
        }
    }

    fn process_lifecycle_event(
        &self,
        event_id: &str,
        turn_id: TurnId,
        effect_id: iteron_protocol::EffectId,
        job_id: Option<&str>,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(Some(turn_id));
        correlation.effect_id = Some(effect_id);
        correlation.job_id = job_id.map(|id| iteron_protocol::JobId(id.to_owned()));
        self.lifecycle_event_with_correlation(event_id, correlation, payload);
    }

    /// Capture live context source decisions as digests and magnitudes before their bytes are
    /// folded into the stable prefix.
    pub(super) fn observe_resolved_context(
        &mut self,
        turn: TurnId,
        task: &str,
        segments: &[ContextSegment],
        memory_audit: Option<&MemoryRecallAudit>,
        elapsed_us: u64,
    ) {
        self.context_source_evidence.clear();
        let mut token_cursor = 0u64;
        for (ordinal, segment) in segments.iter().enumerate() {
            let estimated_tokens =
                u64::try_from(iteron_ctx::estimate_tokens(&segment.text)).unwrap_or(u64::MAX);
            let end = token_cursor.saturating_add(estimated_tokens);
            self.context_source_evidence.push(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::try_from(ordinal).unwrap_or(u64::MAX)),
                parent_segment_id: None,
                source_class: context_source_class(segment.source),
                source_digest_sha256: digest(segment.text.as_bytes()),
                trust: segment.trust,
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                bytes_before: u64::try_from(segment.text.len()).unwrap_or(u64::MAX),
                bytes_after: u64::try_from(segment.text.len()).unwrap_or(u64::MAX),
                estimated_tokens,
                actual_tokens: None,
                token_range: Some(TokenRange {
                    start: token_cursor,
                    end,
                }),
                cache_class: CacheClass::StablePrefix,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::WithinBudget,
                elapsed_us,
            });
            token_cursor = end;
        }
        self.observe_memory_resolution(turn, task, segments, memory_audit, elapsed_us);
        self.lifecycle_event(
            "context.source.classified",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(segments.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.source.selected",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(segments.len()).unwrap_or(u64::MAX)),
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
        let tokens = u64::try_from(iteron_ctx::estimate_tokens(text)).unwrap_or(u64::MAX);
        self.context_source_evidence = vec![ContextSegmentEvidence {
            segment_id: ContextSegmentId(0),
            parent_segment_id: None,
            source_class: ContextSourceClass::CompactionSummary,
            source_digest_sha256: digest(text.as_bytes()),
            trust,
            ordinal: 0,
            bytes_before: u64::try_from(text.len()).unwrap_or(u64::MAX),
            bytes_after: u64::try_from(text.len()).unwrap_or(u64::MAX),
            estimated_tokens: tokens,
            actual_tokens: None,
            token_range: Some(TokenRange {
                start: 0,
                end: tokens,
            }),
            cache_class: CacheClass::StablePrefix,
            decision: ContextDecision::Selected,
            reason: ContextDecisionReason::Required,
            elapsed_us: 0,
        }];
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
        let ContextRequestObservation {
            system,
            messages,
            tools,
            images,
            estimate,
            output_reserved_tokens,
            elapsed_us,
        } = observation;
        let mut ledger = ContextLedger::new(
            turn,
            TokenizerIdentity {
                catalog_id: "core.byte-heuristic".into(),
                version: 1,
                exact: false,
            },
        );
        ledger.model_context_window = self.model_context_window;
        ledger.output_reserved_tokens = u64::from(output_reserved_tokens);
        ledger.usable_window = self
            .model_context_window
            .map(|window| window.saturating_sub(u64::from(output_reserved_tokens)));
        for segment in &self.context_source_evidence {
            ledger.record_segment(segment.clone());
        }
        let mut ordinal = u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX);
        record_segment(
            &mut ledger,
            ordinal,
            ContextSourceClass::KernelSystem,
            system.as_bytes(),
            self.system_trust,
            u64::try_from(estimate.system_tokens).unwrap_or(u64::MAX),
            CacheClass::StablePrefix,
        );
        ordinal = ordinal.saturating_add(1);
        if !tools.is_empty() {
            let mut hasher = Sha256::new();
            let mut bytes = 0u64;
            for tool in tools {
                hasher.update(tool.name.as_bytes());
                hasher.update(tool.description.as_bytes());
                let schema = tool.input_schema.to_string();
                hasher.update(schema.as_bytes());
                bytes = bytes
                    .saturating_add(u64::try_from(tool.name.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(tool.description.len()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(schema.len()).unwrap_or(u64::MAX));
            }
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::ToolSchema,
                source_digest_sha256: hasher.finalize().into(),
                trust: Trust::Trusted,
                ordinal,
                bytes_before: bytes,
                bytes_after: bytes,
                estimated_tokens: u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX),
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::StablePrefix,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            ledger.totals.tool_schema_tokens =
                u64::try_from(estimate.tool_tokens).unwrap_or(u64::MAX);
            ordinal = ordinal.saturating_add(1);
        }
        for message in messages {
            let bytes = serde_json::to_vec(message).unwrap_or_default();
            let source = match message.role {
                Role::User => ContextSourceClass::TranscriptUser,
                Role::Assistant => ContextSourceClass::TranscriptAssistant,
            };
            record_segment(
                &mut ledger,
                ordinal,
                source,
                &bytes,
                Trust::Trusted,
                u64::try_from(iteron_ctx::estimate_tokens(&String::from_utf8_lossy(
                    &bytes,
                )))
                .unwrap_or(u64::MAX),
                CacheClass::Uncached,
            );
            ordinal = ordinal.saturating_add(1);
        }
        if let Some(file) = self.input_file_evidence {
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::FileAttachment,
                source_digest_sha256: file.digest_sha256,
                trust: Trust::Trusted,
                ordinal,
                bytes_before: file.bytes,
                bytes_after: file.bytes,
                estimated_tokens: file.estimated_tokens,
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::Uncached,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            ledger.totals.attachment_tokens = ledger
                .totals
                .attachment_tokens
                .saturating_add(file.estimated_tokens);
            ordinal = ordinal.saturating_add(1);
            self.lifecycle_event(
                "context.source.classified",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(file.count)),
                    magnitude: Some(file.bytes),
                    reason_code: Some("file_attachment".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if !images.is_empty() {
            let image_bytes = images.iter().fold(0u64, |total, image| {
                total.saturating_add(u64::try_from(image.data.encoded_len()).unwrap_or(u64::MAX))
            });
            ledger.record_segment(ContextSegmentEvidence {
                segment_id: ContextSegmentId(u64::from(ordinal)),
                parent_segment_id: None,
                source_class: ContextSourceClass::ImageAttachment,
                source_digest_sha256: digest(&image_bytes.to_be_bytes()),
                trust: Trust::Trusted,
                ordinal,
                bytes_before: image_bytes,
                bytes_after: image_bytes,
                estimated_tokens: 0,
                actual_tokens: None,
                token_range: None,
                cache_class: CacheClass::Unknown,
                decision: ContextDecision::Selected,
                reason: ContextDecisionReason::Required,
                elapsed_us: 0,
            });
            // Image token cost is provider/model specific. Preserve the measured encoded bytes
            // and classify the source, but never turn an unknown token cost into a measured zero.
            self.lifecycle_event(
                "context.source.classified",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::try_from(images.len()).unwrap_or(u64::MAX)),
                    magnitude: Some(image_bytes),
                    reason_code: Some("image_attachment".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        ledger.record_transform(ContextTransformEvidence {
            kind: ContextTransformKind::Serialize,
            policy_id: "iteron/context@1".into(),
            input_segments: u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX),
            output_segments: u32::try_from(ledger.segments.len()).unwrap_or(u32::MAX),
            input_bytes: ledger.totals.bytes,
            output_bytes: ledger.totals.bytes,
            input_tokens: u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX),
            output_tokens: u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX),
            elapsed_us,
        });
        ledger.cache.stable_prefix_tokens =
            u64::try_from(estimate.system_tokens.saturating_add(estimate.tool_tokens))
                .unwrap_or(u64::MAX);
        ledger.cache.uncached_tokens = u64::try_from(estimate.total_tokens)
            .unwrap_or(u64::MAX)
            .saturating_sub(ledger.cache.stable_prefix_tokens);
        // The request estimator is the single accounting pass used for admission. Segment-level
        // classification may overlap (a file is also serialized inside a transcript message), so
        // the aggregate must remain that authoritative request estimate rather than their sum.
        ledger.totals.estimated_tokens = u64::try_from(estimate.total_tokens).unwrap_or(u64::MAX);
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
        if let Some(window) = self.model_context_window {
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
            if self
                .model_context_window
                .is_some_and(|window| headroom.saturating_mul(10) < window)
            {
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

    pub(super) fn observe_context_usage(&self, turn: TurnId, usage: Usage) {
        use iteron_ctx::{ContextObservation, ContextObserver};
        let actual_input_tokens = usage
            .input
            .saturating_add(usage.cache_read)
            .saturating_add(usage.cache_creation);
        let estimated_input_tokens = self
            .context_ledgers
            .snapshot()
            .ledgers
            .into_iter()
            .find(|ledger| ledger.turn_id == turn)
            .map(|ledger| ledger.totals.estimated_tokens);
        self.context_ledgers.observe(
            turn,
            ContextObservation::ProviderUsage {
                actual_input_tokens,
            },
        );
        self.lifecycle_event(
            "context.tokenizer.actual_observed",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(actual_input_tokens),
                ..LifecyclePayload::default()
            },
        );
        if let Some(estimated) = estimated_input_tokens {
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

    fn observe_memory_resolution(
        &self,
        turn: TurnId,
        task: &str,
        segments: &[ContextSegment],
        memory_audit: Option<&MemoryRecallAudit>,
        elapsed_us: u64,
    ) {
        let memory_segments = segments
            .iter()
            .filter(|segment| segment.source == ContextSource::Memory)
            .collect::<Vec<_>>();
        let requested_bytes = memory_segments.iter().fold(0u64, |total, segment| {
            total.saturating_add(u64::try_from(segment.text.len()).unwrap_or(u64::MAX))
        });
        let requested_tokens = memory_segments.iter().fold(0u64, |total, segment| {
            total.saturating_add(
                u64::try_from(iteron_ctx::estimate_tokens(&segment.text)).unwrap_or(u64::MAX),
            )
        });
        let mut trace = MemoryDecisionTrace::new(
            turn,
            MemoryQueryEvidence {
                query_id: MemoryQueryId(u64::from(turn.0)),
                query_digest_sha256: digest(task.as_bytes()),
                bytes: u64::try_from(task.len()).unwrap_or(u64::MAX),
                estimated_tokens: u64::try_from(iteron_ctx::estimate_tokens(task))
                    .unwrap_or(u64::MAX),
                rewrite_count: 0,
            },
            MemoryScopeEvidence {
                class: MemoryScopeClass::Workspace,
                scope_digest_sha256: digest(self.workspace.as_os_str().as_encoded_bytes()),
                isolation_enabled: true,
                parent_access_rejections: 0,
            },
        );
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
                .unwrap_or(0),
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
            let candidate_count =
                u64::try_from(audit.observation.candidates.len()).unwrap_or(u64::MAX);
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
            if audit.deduplicated_candidates > 0 {
                for event_id in [
                    "memory.candidate.deduplicated",
                    "context.source.deduplicated",
                ] {
                    self.lifecycle_event(
                        event_id,
                        Some(turn),
                        LifecyclePayload {
                            count: Some(u64::from(audit.deduplicated_candidates)),
                            reason_code: Some("stable_memory_slug".into()),
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
                    u64::try_from(iteron_ctx::estimate_tokens(&candidate.text)).unwrap_or(u64::MAX);
                let candidate_bytes = u64::try_from(candidate.framed_bytes).unwrap_or(u64::MAX);
                requested_candidate_bytes =
                    requested_candidate_bytes.saturating_add(candidate_bytes);
                requested_candidate_tokens =
                    requested_candidate_tokens.saturating_add(candidate_tokens);
                let selected_ordinal = audit
                    .selected
                    .iter()
                    .position(|slug| slug == &candidate.slug);
                let decision = if selected_ordinal.is_some() {
                    granted_candidate_bytes =
                        granted_candidate_bytes.saturating_add(candidate_bytes);
                    granted_candidate_tokens =
                        granted_candidate_tokens.saturating_add(candidate_tokens);
                    MemoryCandidateDecision::Selected
                } else if candidate.trust < audit.observation.trust_floor {
                    filtered_candidates = filtered_candidates.saturating_add(1);
                    MemoryCandidateDecision::TrustDenied
                } else if audit.scores_ppm.get(index).copied().unwrap_or(0) <= 0 {
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
                    bm25_term_ppm: audit.scores_ppm.get(index).copied().unwrap_or(0),
                    bm25_length_ppm: 0,
                    semantic_ppm: None,
                    recency_ppm: 0,
                    confidence_ppm: 0,
                    combined_ppm: audit.scores_ppm.get(index).copied().unwrap_or(0),
                    threshold_ppm: 1,
                    rank: audit.ranks.get(index).copied().unwrap_or(0),
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

fn record_segment(
    ledger: &mut ContextLedger,
    ordinal: u32,
    source_class: ContextSourceClass,
    bytes: &[u8],
    trust: Trust,
    estimated_tokens: u64,
    cache_class: CacheClass,
) {
    ledger.record_segment(ContextSegmentEvidence {
        segment_id: ContextSegmentId(u64::from(ordinal)),
        parent_segment_id: None,
        source_class,
        source_digest_sha256: digest(bytes),
        trust,
        ordinal,
        bytes_before: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes_after: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        estimated_tokens,
        actual_tokens: None,
        token_range: None,
        cache_class,
        decision: ContextDecision::Selected,
        reason: ContextDecisionReason::Required,
        elapsed_us: 0,
    });
}

fn context_source_class(source: ContextSource) -> ContextSourceClass {
    match source {
        ContextSource::RepoOutline => ContextSourceClass::WorkspaceOutline,
        ContextSource::Instructions => ContextSourceClass::ProjectInstructions,
        ContextSource::Memory => ContextSourceClass::WorkspaceMemory,
        ContextSource::Transcript => ContextSourceClass::TranscriptUser,
        ContextSource::Environment => ContextSourceClass::Environment,
        ContextSource::Skills => ContextSourceClass::SkillIndex,
        ContextSource::Unknown => ContextSourceClass::Environment,
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
