use super::*;

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
        msgs.push(Message::user_text(prompt));
        let req = TurnRequest {
            model: self.model.clone(),
            system: "You compress a coding-agent transcript into a terse hand-off note.".into(),
            messages: msgs,
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 2048,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        };
        // The hand-off note must not appear as assistant prose, but its provider stream is still
        // live work. Publish only cumulative decode counts through the internal-activity seam.
        let stream_start = Instant::now();
        let mut first_item_at: Option<Instant> = None;
        let mut stream_items: u32 = 0;
        let turn_id = TurnId(self.seq_turn);
        let usd_attempt = self.admit_provider_effect(turn_id, &req)?;
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
            let response = self.brokered_provider_turn(turn_id, &req, &mut sink).await;
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
                self.advance_turn()?;
                Ok(text)
            }
            Err(error) => {
                self.mark_usd_unknown();
                self.emit(turn_id, EventKind::Phase { phase: Phase::Idle });
                self.advance_turn()?;
                Err(error)
            }
        }
    }

    /// Record one compaction. What lands on the record is the summary and its plan range, NOT the
    /// rebuilt transcript: the rebuild is a deterministic function of a transcript the record
    /// already holds, so writing it back out wrote the same bytes twice — one line, audited at
    /// 115949 of them, fsynced inline, inside the operator's turn. `replay_compaction` puts them
    /// back together and `messages_from_rollout` proves the result is identical.
    pub(super) fn record_compaction(
        &mut self,
        before: usize,
        plan: &iteron_ctx::CompactionPlan,
        summary: &str,
        after: usize,
    ) {
        self.compacted_in_run = true;
        self.emit(
            TurnId(self.seq_turn),
            EventKind::Compaction {
                messages: iteron_ctx::compaction_seed(plan, summary),
            },
        );
        self.lifecycle_event(
            "context.compaction.completed",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.segment.removed",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_range".into()),
                ..LifecyclePayload::default()
            },
        );
        self.lifecycle_event(
            "context.segment.updated",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(1),
                magnitude: Some(u64::try_from(summary.len()).unwrap_or(u64::MAX)),
                reason_code: Some("compaction_summary".into()),
                ..LifecyclePayload::default()
            },
        );
        self.emit(
            TurnId(self.seq_turn),
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
        if self.compacted_in_run || self.record_failed || self.delegation_depth > 0 {
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
        let request_max_tokens = self.model_max_output_tokens.unwrap_or(8192);
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
        let before = messages.len();
        let after = 2 + plan.keep_verbatim.len();
        self.lifecycle_event(
            "context.compaction.started",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload::default(),
        );
        match self.summarize(&plan.to_summarize, None).await {
            Ok(summary) => {
                self.record_compaction(before, &plan, &summary, after);
                // The in-memory working set was captured by `drive_admitted` BEFORE this ran, so it
                // still holds the pre-compaction transcript. Dropping it makes the next follow-up
                // replay from the rollout, which now carries the compaction — the one case where the
                // #I-21 shortcut must not be taken, and it costs one replay per compaction rather
                // than one per turn.
                self.working_set = None;
            }
            Err(_) => self.lifecycle_event(
                "context.compaction.failed",
                Some(TurnId(self.seq_turn)),
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
        let summary = self.summarize(&plan.to_summarize, focus.as_deref()).await?;
        let after = 2 + plan.keep_verbatim.len();
        self.emit(
            TurnId(self.seq_turn),
            EventKind::Compaction {
                messages: iteron_ctx::compaction_seed(&plan, &summary),
            },
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
