use super::*;

/// Coverage verdict recorded when the coverage check itself failed to complete: an unproven summary
/// counts as uncovered, never as covered.
const COVERAGE_UNPROVEN: bool = false;

impl Agent {
    /// One-shot summarization turn for compaction. No tools; the model just writes the note.
    pub(super) async fn summarize(
        &mut self,
        middle: &[Message],
        focus: Option<&str>,
    ) -> Result<String, KernelError> {
        if let Some(reason) = self.inference_budget_exhaustion()? {
            return Err(KernelError::InferenceBudgetExhausted(reason));
        }
        // Build a transient message list: the middle history + a summarize instruction.
        let mut msgs = middle.to_vec();
        let prompt = match focus {
            Some(f) if !f.trim().is_empty() => format!(
                "{}\n\nFocus especially on: {f}",
                CompactionPolicy::summary_prompt()
            ),
            _ => CompactionPolicy::summary_prompt().to_string(),
        };
        let prompt = if self.compaction.summary_profile.preserve_tool_evidence {
            format!(
                "{prompt}\n\nPreserve tool names, effect/result identities, exit status, and verification evidence whenever they affect what remains to do."
            )
        } else {
            prompt
        };
        msgs.push(Message::user_text(prompt));
        let req = TurnRequest {
            model: self.model.clone(),
            controls: self.provider_controls,
            system: "You compress a coding-agent transcript into a terse hand-off note.".into(),
            messages: msgs,
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: self.compaction.summary_profile.max_output_tokens,
            cache_system: self.provider_cache_system_enabled(),
            thinking_budget: self.compaction.summary_profile.effort.thinking_budget(),
            reasoning_effort: self.compaction.summary_profile.effort.reasoning_effort(),
        };
        // The hand-off note must not appear as assistant prose, but its provider stream is still
        // live work. Publish only cumulative decode counts through the internal-activity seam.
        let stream_start = Instant::now();
        let mut first_item_at: Option<Instant> = None;
        let mut stream_items: u32 = 0;
        let turn_id = TurnId(self.seq_turn);
        let admission = self.admit_provider_dispatch(turn_id, &req).await?;
        let usd_attempt = admission.attempt_guard;
        let primary_route_permit = admission.primary_route_permit;
        let use_hedge = admission.use_hedge;
        self.emit(
            turn_id,
            EventKind::Phase {
                phase: Phase::Model,
            },
        );
        let mut progress = InternalStreamProgress::new(
            crate::workflow::KernelActivityKind::Compaction,
            self.workflow_progress_tx.clone(),
        );
        progress.start();
        let response = {
            let mut sink = |item: StreamItem| {
                if first_item_at.is_none() {
                    first_item_at = Some(Instant::now());
                }
                stream_items = stream_items.saturating_add(1);
                progress.observe(&item);
            };
            let model_started = Instant::now();
            let response = self
                .brokered_provider_turn(turn_id, &req, &mut sink, primary_route_permit, use_hedge)
                .await;
            (response, model_started)
        };
        let (response, model_started) = response;
        match response {
            Ok(res) => {
                let stream_timing = match first_item_at {
                    Some(first) => StreamTiming {
                        ttft_ms: Some(iteron_obs::duration_ms_ceil(
                            first.saturating_duration_since(stream_start),
                        )),
                        decode_ms: Some(iteron_obs::duration_ms_ceil(first.elapsed())),
                        stream_items: Some(stream_items),
                    },
                    None => StreamTiming::default(),
                };
                let complete_usage = self.record_provider_usage(
                    turn_id,
                    res.usage,
                    model_started.elapsed().as_millis() as u64,
                    usd_attempt.projected_at_unix_secs(),
                    stream_timing,
                )?;
                if complete_usage.is_some() {
                    usd_attempt.complete();
                }
                let text = res.text();
                progress.complete_output(&text);
                self.emit(turn_id, EventKind::Phase { phase: Phase::Idle });
                self.advance_turn().await?;
                Ok(text)
            }
            Err(error) => {
                // `brokered_provider_turn` has already made the physical route's typed
                // Known/Unknown/NotDispatched terminal load-bearing. Do not overwrite a proven
                // known failure or zero-dispatch refusal with a caller-level Unknown.
                self.emit(turn_id, EventKind::Phase { phase: Phase::Idle });
                self.advance_turn().await?;
                Err(error)
            }
        }
    }

    /// Execute the resolved summary topology. Every stage is bounded and goes through the same
    /// provider-attempt accounting as an ordinary single-stage summary.
    pub(super) async fn summarize_compaction(
        &mut self,
        middle: &[Message],
        focus: Option<&str>,
    ) -> Result<String, KernelError> {
        let (max_chunks, reduce_focus) = match self.compaction.summary_topology {
            iteron_ctx::SummaryTopology::SingleStage => return self.summarize(middle, focus).await,
            iteron_ctx::SummaryTopology::Hierarchical => (
                4usize,
                "Merge the bounded child summaries into one chronological hand-off without dropping conflicts or unresolved obligations.",
            ),
            iteron_ctx::SummaryTopology::MapReduce => (
                8usize,
                "Reduce the independent map summaries into one deduplicated hand-off; preserve disagreements explicitly rather than voting them away.",
            ),
        };
        if middle.is_empty() {
            return Ok(String::new());
        }
        let chunk_size = middle.len().div_ceil(max_chunks).max(1);
        let mut partials = Vec::with_capacity(middle.len().div_ceil(chunk_size));
        for (index, chunk) in middle.chunks(chunk_size).enumerate() {
            let stage_focus = format!(
                "Topology stage {} of at most {max_chunks}. Summarize only this contiguous transcript range and retain its unresolved obligations.",
                index.saturating_add(1)
            );
            partials.push(self.summarize(chunk, Some(&stage_focus)).await?);
        }
        if partials.len() == 1 {
            return Ok(partials.pop().unwrap_or_default());
        }
        let reduction = partials
            .into_iter()
            .enumerate()
            .map(|(index, summary)| {
                Message::user_text(format!(
                    "Bounded partial summary {}:\n{summary}",
                    index.saturating_add(1)
                ))
            })
            .collect::<Vec<_>>();
        let final_focus = match focus {
            Some(focus) if !focus.trim().is_empty() => format!("{reduce_focus}\n{focus}"),
            _ => reduce_focus.to_owned(),
        };
        self.summarize(&reduction, Some(&final_focus)).await
    }

    /// Record one compaction. What lands on the record is the summary and its plan range, NOT the
    /// rebuilt transcript: the rebuild is a deterministic function of a transcript the record
    /// already holds, so writing it back out wrote the same bytes twice — one line, audited at
    /// 115949 of them, fsynced inline, inside the operator's turn. `replay_compaction` puts them
    /// back together and `messages_from_rollout` proves the result is identical.
    pub(super) fn record_compaction(
        &mut self,
        turn: TurnId,
        before_messages: &[Message],
        plan: &iteron_ctx::CompactionPlan,
        summary: &str,
        reason_code: &'static str,
        coverage_verified: bool,
    ) {
        let rebuilt = iteron_ctx::CompactionPolicy::rebuild(plan, summary.to_owned());
        let before = before_messages.len();
        let after = rebuilt.len();
        let tools = self.registry.specs();
        let system = self.effective_system();
        let before_estimate =
            self.context_estimator
                .estimate_uncached(&system, before_messages, &tools);
        let after_estimate = self
            .context_estimator
            .estimate_uncached(&system, &rebuilt, &tools);
        let trigger = self.compaction.effective_trigger_tokens(
            self.model_context_window,
            self.model_max_output_tokens
                .unwrap_or(crate::runtime_tunables::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS),
        );
        let compaction = iteron_ctx::CompactionEvidence {
            trigger_tokens: u64::try_from(trigger).unwrap_or(u64::MAX),
            before_tokens: u64::try_from(before_estimate.total_tokens).unwrap_or(u64::MAX),
            after_tokens: u64::try_from(after_estimate.total_tokens).unwrap_or(u64::MAX),
            obligations_preserved: plan.obligations_preserved().saturating_add(
                if coverage_verified {
                    plan.obligations_lost()
                } else {
                    0
                },
            ),
            obligations_lost: if coverage_verified {
                0
            } else {
                plan.obligations_lost()
            },
            reason_code: reason_code.into(),
        };
        let mut ledger =
            iteron_ctx::ContextLedger::new(turn, self.context_estimator.tokenizer_identity());
        ledger.model_context_window = self.model_context_window;
        let output_reserve = self
            .model_max_output_tokens
            .unwrap_or(crate::runtime_tunables::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS);
        ledger.usable_window = self
            .model_context_window
            .map(|window| window.saturating_sub(u64::from(output_reserve)));
        ledger.output_reserved_tokens = u64::from(output_reserve);
        ledger.record_transform(iteron_ctx::ContextTransformEvidence {
            kind: iteron_ctx::ContextTransformKind::Compact,
            policy_id: "core/compaction@1".into(),
            input_segments: u32::try_from(before).unwrap_or(u32::MAX),
            output_segments: u32::try_from(after).unwrap_or(u32::MAX),
            input_bytes: before_messages.iter().fold(0u64, |total, message| {
                total.saturating_add(
                    u64::try_from(serde_json::to_vec(message).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                )
            }),
            output_bytes: rebuilt.iter().fold(0u64, |total, message| {
                total.saturating_add(
                    u64::try_from(serde_json::to_vec(message).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                )
            }),
            input_tokens: compaction.before_tokens,
            output_tokens: compaction.after_tokens,
            elapsed_us: 0,
        });
        ledger.compaction = Some(compaction.clone());
        self.context_ledgers.publish(ledger);
        self.compacted_in_run = true;
        self.last_compaction_turn = Some(u64::from(turn.0));
        self.emit(
            turn,
            EventKind::Compaction {
                messages: iteron_ctx::compaction_seed(plan, summary),
            },
        );
        self.lifecycle_event(
            "context.compaction.completed",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.segment.removed",
            Some(turn),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_range".into()),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.segment.updated",
            Some(turn),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_summary".into()),
                ..LifecyclePayload::default()
            },
        );
        if compaction.obligations_preserved > 0 {
            self.lifecycle_event(
                "context.obligation.preserved",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(compaction.obligations_preserved)),
                    reason_code: Some(reason_code.into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        if compaction.obligations_lost > 0 {
            self.lifecycle_event(
                "context.obligation.lost",
                Some(turn),
                LifecyclePayload {
                    count: Some(u64::from(compaction.obligations_lost)),
                    reason_code: Some("obligation_preservation_bound".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
        self.emit(
            turn,
            EventKind::Notice {
                text: format!("compacted {before} messages -> {after}"),
            },
        );
    }

    /// Compaction at the END of the turn, not inside it (#I-58). The operator already has their
    /// answer and is reading it; the summary is paid out of that thinking time, and the next
    /// submission reaches the model in one round against a prefix that is already rebuilt.
    ///
    /// Best-effort by construction, and deliberately skippable: if the operator is already back
    /// (a queued steer, an interrupt, a drain) their submission is worth more than a summary they
    /// did not ask for, and the emergency valve inside the turn loop still guarantees that
    /// whatever comes next can be admitted.
    pub(super) async fn settle_compaction(&mut self) {
        if self.compacted_in_run
            || self.record_failed
            || self.delegation_depth > 0
            || !self
                .compaction
                .hysteresis
                .cooldown_allows(u64::from(self.seq_turn), self.last_compaction_turn)
        {
            return;
        }
        let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
        if !self.pending_steers.is_empty()
            || !matches!(self.requested_control(), InboundControl::None)
        {
            return;
        }
        // Plan against the PROJECTED transcript, which is exactly what the next submission will
        // load, so the plan the record describes is the plan the next turn inherits.
        let path = self.rollout.path().to_path_buf();
        let Ok(messages) = Self::messages_from_rollout(&path) else {
            return;
        };
        // Same ceiling rule as the request path: a declared capability is used as declared, and
        // 8192 is the default for an UNKNOWN one only (#I-02). Clamping here would plan against a
        // window the route does not actually have.
        let request_max_tokens = self
            .model_max_output_tokens
            .unwrap_or(crate::runtime_tunables::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS);
        let Some(plan) = self.compaction.plan_at_turn_end(
            &self.effective_system(),
            &messages,
            &self.registry.specs(),
            self.model_context_window,
            request_max_tokens,
        ) else {
            return;
        };
        let Ok(report) = self
            .brokered_lifecycle_gate(
                TurnId(self.seq_turn),
                "context.compaction.considered",
                LifecyclePayload {
                    count: Some(u64::try_from(plan.to_summarize.len()).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            )
            .await
        else {
            return;
        };
        if matches!(report.decision, HookDecision::Deny(_)) {
            return;
        }
        let compaction_turn = TurnId(self.seq_turn);
        self.lifecycle_event(
            "context.compaction.started",
            Some(compaction_turn),
            LifecyclePayload::default(),
        );
        match self.summarize_compaction(&plan.to_summarize, None).await {
            Ok(summary) => {
                let covered = if self.compaction.coverage_check {
                    self.verify_compaction_summary(&plan.to_summarize, &summary)
                        .await
                        .unwrap_or(COVERAGE_UNPROVEN)
                } else {
                    true
                };
                let compaction_result_turn =
                    TurnId(self.seq_turn.saturating_sub(1).max(compaction_turn.0));
                if !covered || !self.compaction_exits_hysteresis(&plan, &summary) {
                    self.lifecycle_event(
                        "context.compaction.failed",
                        Some(compaction_result_turn),
                        LifecyclePayload {
                            reason_code: Some(if covered {
                                "hysteresis_exit_not_reached".into()
                            } else {
                                "summary_coverage_missing".into()
                            }),
                            ..LifecyclePayload::default()
                        },
                    );
                    return;
                }
                self.record_compaction(
                    compaction_result_turn,
                    &messages,
                    &plan,
                    &summary,
                    "turn_end",
                    self.compaction.coverage_check && covered,
                );
                // The in-memory working set was captured by `drive_admitted` BEFORE this ran, so it
                // still holds the pre-compaction transcript. Dropping it makes the next follow-up
                // replay from the rollout, which now carries the compaction — the one case where the
                // #I-21 shortcut must not be taken, and it costs one replay per compaction rather
                // than one per turn.
                self.working_set = None;
            }
            Err(_) => self.lifecycle_event(
                "context.compaction.failed",
                Some(TurnId(
                    self.seq_turn.saturating_sub(1).max(compaction_turn.0),
                )),
                LifecyclePayload::default(),
            ),
        }
    }

    /// Force compaction NOW (operator `/compact`), optionally focusing the summary. Reconstructs
    /// the working set from the rollout (same path as follow_up), summarizes the middle, records
    /// the compaction so resume reproduces the compacted state, and returns the delta.
    /// Callable while idle (the TUI guarantees this). Records → replay reproduces it.
    pub async fn compact_now(
        &mut self,
        focus: Option<String>,
    ) -> Result<CompactionReport, KernelError> {
        let path = self.rollout.path().to_path_buf();
        let messages = Self::messages_from_rollout(&path)?;
        let before = messages.len();
        let Some(plan) = self.compaction.force_plan(&messages) else {
            return Ok(CompactionReport {
                before,
                after: before,
            });
        };
        let report = self
            .brokered_lifecycle_gate(
                TurnId(self.seq_turn),
                "context.compaction.considered",
                LifecyclePayload {
                    count: Some(u64::try_from(plan.to_summarize.len()).unwrap_or(u64::MAX)),
                    ..LifecyclePayload::default()
                },
            )
            .await?;
        if let HookDecision::Deny(reason) = report.decision {
            return Err(KernelError::ContextResolution(reason));
        }
        let compaction_turn = TurnId(self.seq_turn);
        self.lifecycle_event(
            "context.compaction.started",
            Some(compaction_turn),
            LifecyclePayload {
                reason_code: Some("operator_forced".into()),
                ..LifecyclePayload::default()
            },
        );
        let summary = match self
            .summarize_compaction(&plan.to_summarize, focus.as_deref())
            .await
        {
            Ok(summary) => summary,
            Err(error) => {
                self.lifecycle_event(
                    "context.compaction.failed",
                    Some(TurnId(
                        self.seq_turn.saturating_sub(1).max(compaction_turn.0),
                    )),
                    LifecyclePayload {
                        reason_code: Some("operator_forced".into()),
                        ..LifecyclePayload::default()
                    },
                );
                return Err(error);
            }
        };
        if self.compaction.coverage_check
            && !self
                .verify_compaction_summary(&plan.to_summarize, &summary)
                .await?
        {
            self.lifecycle_event(
                "context.compaction.failed",
                Some(TurnId(
                    self.seq_turn.saturating_sub(1).max(compaction_turn.0),
                )),
                LifecyclePayload {
                    reason_code: Some("summary_coverage_missing".into()),
                    ..LifecyclePayload::default()
                },
            );
            return Err(KernelError::ContextResolution(
                "compaction summary failed the resolved coverage check".into(),
            ));
        }
        let after = 2 + plan.keep_verbatim.len();
        self.record_compaction(
            TurnId(self.seq_turn.saturating_sub(1).max(compaction_turn.0)),
            &messages,
            &plan,
            &summary,
            "operator_forced",
            self.compaction.coverage_check,
        );
        self.emit(
            TurnId(self.seq_turn),
            EventKind::Notice {
                text: format!("operator /compact: {before} -> {after} messages"),
            },
        );
        Ok(CompactionReport { before, after })
    }
}
