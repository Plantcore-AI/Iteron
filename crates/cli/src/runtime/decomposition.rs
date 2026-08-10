use super::*;

impl Agent {
    /// One bounded, recorded model turn that emits up to `FAN_CAP` read-only investigation
    /// sub-questions (the leaves). The model fills the leaves; the harness owns the topology
    /// (Agentless's discipline — control flow is never the model's). Output is line-parsed + capped.
    #[cfg(test)]
    pub(super) async fn decompose(
        &mut self,
        task: &str,
        class: iteron_agents::TaskClass,
    ) -> Result<Vec<String>, KernelError> {
        let coverage = match class {
            iteron_agents::TaskClass::RunToUnderstand => {
                "Cover static failure-path localization, existing tests/reproduction definitions, \
                 state/data flow, and verification options that do not require this read-only \
                 worker to execute commands."
            }
            iteron_agents::TaskClass::MultiFile => {
                "Cover ownership boundaries, callers/consumers, shared data or protocol flow, \
                 migration compatibility, and affected tests/verification."
            }
            iteron_agents::TaskClass::UnderSpecified => {
                "Cover entry-point localization, ownership/data flow, nearby analogous code, \
                 invariants/risks, and existing tests/verification."
            }
            iteron_agents::TaskClass::Localized => {
                "Confirm the named location, its callers/data flow, and affected tests."
            }
        };
        let sys = "You decompose a coding task into a READ-ONLY repository investigation. Return \
            mutually distinct, non-overlapping, self-contained assignments. Every line must name a \
            concrete search scope and the evidence/deliverable expected from that worker. Cover \
            different causal surfaces rather than paraphrasing the task. Do not propose edits. \
            Output exactly one assignment per line with no preamble or conclusion.";
        let prompt = format!(
            "Original operator goal:\n{task}\n\nTask class: {}\nCoverage contract: {coverage}\n\n\
             List up to {} complementary investigation assignments, one per line.",
            workflow_class_label(class),
            iteron_agents::FAN_CAP,
        );
        let req = TurnRequest {
            model: self.model.clone(),
            system: sys.into(),
            messages: vec![Message::user_text(prompt)],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 1024,
            // The decomposition prefix is a fixed literal, so it is exactly the stable prefix the
            // cache discipline exists for (ADR-002). Leaving it uncached made every ultracode run
            // pay a cold round the rest of the kernel does not (I-62).
            cache_system: true,
            thinking_budget: 0,
            reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        };
        // The draft itself stays private to the planner, but decode progress is real operator
        // evidence. Publish bounded cumulative counts instead of dropping the stream or leaking
        // candidate assignments into the main assistant transcript.
        let stream_start = Instant::now();
        let mut first_item_at: Option<Instant> = None;
        let mut stream_items: u32 = 0;
        let turn_id = TurnId(self.seq_turn);
        self.lifecycle_event(
            "workflow.planning_started",
            Some(turn_id),
            LifecyclePayload::default(),
        );
        let usd_attempt = self.admit_provider_effect(turn_id, &req)?;
        self.emit(
            turn_id,
            EventKind::Phase {
                phase: Phase::Model,
            },
        );
        let mut progress = InternalStreamProgress::new(
            crate::workflow::KernelActivityKind::Planning,
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
        let text = match response {
            Ok(r) => {
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
                    r.usage,
                    model_started.elapsed().as_millis() as u64,
                    usd_attempt.projected_at_unix_secs(),
                    stream_timing,
                )?;
                if complete_usage.is_some() {
                    usd_attempt.complete();
                }
                let text = r.text();
                progress.complete_output(&text);
                self.lifecycle_event(
                    "workflow.planning_completed",
                    Some(turn_id),
                    LifecyclePayload {
                        count: Some(u64::from(stream_items)),
                        duration_us: Some(elapsed_us(stream_start)),
                        ..LifecyclePayload::default()
                    },
                );
                text
            }
            Err(error) => {
                self.mark_usd_unknown();
                self.lifecycle_event(
                    "workflow.planning_failed",
                    Some(turn_id),
                    LifecyclePayload {
                        duration_us: Some(elapsed_us(stream_start)),
                        ..LifecyclePayload::default()
                    },
                );
                self.emit(
                    turn_id,
                    EventKind::Notice {
                        text: format!(
                            "ultracode: decomposition unavailable; falling back to the single writer ({})",
                            error.public_summary()
                        ),
                    },
                );
                self.emit(turn_id, EventKind::Phase { phase: Phase::Idle });
                self.advance_turn()?;
                return Ok(Vec::new());
            }
        };
        self.emit(turn_id, EventKind::Phase { phase: Phase::Idle });
        self.advance_turn()?;
        // Keep raw lines. Decomposer owns legal list-prefix stripping, visibility checks, bounds,
        // deduplication, and FAN_CAP accounting; doing any of that here previously corrupted
        // legitimate assignments beginning with paths such as `.github/workflows/ci.yml`.
        let leaves: Vec<String> = text.lines().map(str::to_owned).collect();
        self.emit(
            TurnId(self.seq_turn),
            EventKind::Notice {
                text: format!(
                    "ultracode: decomposed into {} candidate leaves",
                    leaves.len()
                ),
            },
        );
        Ok(leaves)
    }
}
