//! Content-free context/memory decision evidence and lifecycle emission.

use super::*;
use iteron_ctx::{
    ContaminationEvidence, ContextDecision, MemoryBudgetEvidence, MemoryCandidateDecision,
    MemoryCandidateEvidence, MemoryDecisionTrace, MemoryFactId, MemoryInjectionEvidence,
    MemoryQueryEvidence, MemoryQueryId, MemoryRecallAudit, MemoryRecallExclusionKind,
    MemoryScopeClass, MemoryScopeEvidence, MemorySelectionEvidence, MemoryStoreEvidence,
    MemoryTierClass, MemoryVisibilityState,
};

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

use iteron_obs::lifecycle::LifecycleCorrelation;
use iteron_protocol::context::{ContextSegment, ContextSource};
use iteron_protocol::{LifecyclePayload, TurnId};
use sha2::{Digest, Sha256};

#[cfg(test)]
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

    /// Make an operator-added fact part of this turn's in-process context. This is deliberately
    /// distinct from `Used`: a control request can still stop the turn before a provider transport
    /// is admitted, in which case claiming provider exposure would be false.
    pub(super) fn observe_session_memory_activation(&mut self, turn: TurnId, task: &str) {
        let scheduled = self.session_memory_visibility.activate(turn);
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

    pub(crate) fn set_lifecycle_emitter(
        &mut self,
        emitter: iteron_obs::lifecycle::LifecycleEmitter,
    ) {
        if let Some(owner) = &self.ordinary_extensions {
            // Same optional SDK read Arc follows the actual session bus. Failed rebind leaves
            // prior-generation reads unavailable; it cannot block the Main writer.
            let _ = owner.bind_lifecycle(emitter.bus());
        }
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

    #[cfg(test)]
    pub(super) fn observe_context_request(
        &self,
        turn: TurnId,
        observation: ContextRequestObservation<'_>,
    ) {
        self.request_context_publication(observation.messages)
            .publish(turn, observation);
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
