use super::*;

impl Agent {
    /// Bind attachments to one admitted top-level submission. A route without verified image
    /// support refuses the whole submission before its text is recorded; silently stripping the
    /// binary payload would make the model answer placeholders as if it saw the image.
    pub(super) fn admit_input_images<'a>(
        &self,
        input_images: &'a [iteron_protocol::ImageContent],
    ) -> Result<&'a [iteron_protocol::ImageContent], KernelError> {
        if input_images.is_empty() || self.provider.supports_image_input() {
            return Ok(input_images);
        }
        self.lifecycle_event(
            "context.source.rejected",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(input_images.len()).unwrap_or(u64::MAX)),
                reason_code: Some("image_input_unsupported".into()),
                ..LifecyclePayload::default()
            },
        );
        Err(KernelError::InvalidSubmission(
            IMAGE_INPUT_UNSUPPORTED_REASON,
        ))
    }

    /// The system prompt for a turn: the base plus ONCE-resolved context (REC-INJECT).
    /// This reads `self.injected` (resolved at run start, recorded, reused from the record on
    /// resume) — it does NOT touch the disk, so the stable prefix is byte-stable across a run and a
    /// replay reproduces instructions, memory, and skills exactly.
    pub(super) fn effective_system(&self) -> String {
        iteron_ctx::assemble_system_prompt(&self.system, self.injected.as_deref())
    }

    /// The tool set advertised to the model for this turn.
    ///
    /// I-63: a measured nine-token task paid 3671 prompt tokens, 2730 of them tool schemas, while
    /// the fleet average is 8967 input tokens per turn. Describing a tool the current posture can
    /// NEVER admit is pure waste — every call the model makes to it is refused by the gate.
    ///
    /// Only the two UNCONDITIONAL denials are filtered, so nothing that could be admitted is
    /// hidden: `iteron_protocol::gate` makes Plan a hard read-only overlay that no session rule may
    /// punch through (and `bypass_permissions` explicitly excludes Plan), and
    /// `iteron_kernel::admission::constrain` denies any capability outside the intersection of the
    /// admitted task ceiling and the selected policy manifest. An `Ask` is not filtered: the
    /// operator can still answer it.
    ///
    /// The ceiling test is over every capability a call to the tool can PRESENT, not just the
    /// declared one. `effective_capability` elevates a `ReversibleLocal` write to `TrustMutating`
    /// when the path is trust-mutating, and a `CapabilitySet` is a set rather than a downward-closed
    /// prefix, so a ceiling holding `TrustMutating` without `ReversibleLocal` still admits that
    /// tool for exactly those paths. Filtering on the declared capability alone would hide it.
    ///
    /// Stated cost: `TurnRequest.tools` now depends on the permission mode, so entering or leaving
    /// Plan rewrites the stable prefix and breaks the prompt cache for that one turn. That is a
    /// rare operator action; carrying an unusable schema block on every turn of a read-only session
    /// is not.
    pub(super) fn advertised_tool_specs(&self) -> Vec<iteron_protocol::ToolSpec> {
        let admitted = self.authority_ceiling.intersect(self.policy_capabilities);
        let all = self.registry.specs();
        let total = all.len();
        self.lifecycle_event(
            "context.tool_catalog.discovered",
            Some(TurnId(self.seq_turn)),
            LifecyclePayload {
                count: Some(u64::try_from(total).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
        let visible = all
            .into_iter()
            .filter(|spec| {
                let reachable = admitted.contains(spec.capability)
                    || (spec.capability == Capability::ReversibleLocal
                        && admitted.contains(Capability::TrustMutating));
                reachable
                    && (spec.capability == Capability::ReadOnly
                        || self.permission_mode != PermissionMode::Plan)
            })
            .collect::<Vec<_>>();
        let filtered = total.saturating_sub(visible.len());
        if filtered > 0 {
            let payload = LifecyclePayload {
                count: Some(u64::try_from(filtered).unwrap_or(u64::MAX)),
                reason_code: Some("authority_or_permission".into()),
                ..LifecyclePayload::default()
            };
            self.lifecycle_event(
                "context.tool_catalog.filtered",
                Some(TurnId(self.seq_turn)),
                payload.clone(),
            );
            self.lifecycle_event(
                "context.tool_schema.rejected",
                Some(TurnId(self.seq_turn)),
                payload,
            );
        }
        visible
    }

    pub(super) fn proposed_durable_frontend_context(
        &self,
        genesis_environment: Option<&DurableEnvironmentContext>,
    ) -> Option<DurableInstructionContext> {
        let environment = genesis_environment.cloned().or_else(|| {
            self.environment_context
                .as_ref()
                .map(|(text, trust)| DurableEnvironmentContext {
                    text: text.clone(),
                    trust: *trust,
                })
        });
        match &self.instruction_context {
            Some((text, trust)) => Some(DurableInstructionContext {
                text: text.clone(),
                trust: *trust,
                environment,
            }),
            None if environment.is_some() => Some(DurableInstructionContext {
                text: String::new(),
                trust: Trust::Trusted,
                environment,
            }),
            None => None,
        }
    }

    pub(super) fn clear_frontend_context_proposals(&mut self) {
        self.instruction_context = None;
        self.environment_context = None;
    }

    /// REC-INJECT (R5-review item 1; ADR-011 context seam). Resolve the complete context segment for
    /// this run EXACTLY ONCE and record it, so replay re-materializes context from the record, never
    /// from live instruction/memory/skill files. Idempotent: a follow-up keeps the cached segment.
    pub(super) fn resolve_injection(
        &mut self,
        turn: TurnId,
        task: &str,
    ) -> Result<(), KernelError> {
        if self.injected.is_some() {
            return Ok(());
        }
        let resolution_started = Instant::now();
        // Resume/replay: complete durable instruction bytes are authoritative. A legacy event has
        // only memory/skills in `text`; combine it with the live proposal once, append an upgraded
        // event before provider admission, and use that event on every later resume.
        let recorded = self.recorded_context_history()?;
        if let Some((context_text, context_trust, durable_instructions)) = recorded.injection {
            if let Some(instructions) = durable_instructions {
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    &instructions,
                    context_text,
                    context_trust,
                );
                self.observe_recorded_context(turn, &text, trust);
                self.injected = Some(text);
                self.injected_trust = Some(trust);
                self.clear_frontend_context_proposals();
                return Ok(());
            }
            if let Some(instructions) =
                self.proposed_durable_frontend_context(recorded.genesis_environment.as_ref())
            {
                self.emit_durable(
                    turn,
                    EventKind::ContextInjection {
                        text: context_text.clone(),
                        trust: context_trust,
                        instructions: Some(instructions.clone()),
                    },
                )?;
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    &instructions,
                    context_text,
                    context_trust,
                );
                self.observe_recorded_context(turn, &text, trust);
                self.injected = Some(text);
                self.injected_trust = Some(trust);
                self.clear_frontend_context_proposals();
                return Ok(());
            }
            self.observe_recorded_context(turn, &context_text, context_trust);
            self.injected = Some(context_text);
            self.injected_trust = Some(context_trust);
            self.clear_frontend_context_proposals();
            return Ok(());
        }

        let durable_instructions =
            self.proposed_durable_frontend_context(recorded.genesis_environment.as_ref());
        let mut context_text = String::new();
        let mut context_sources = Vec::with_capacity(2);

        if let Some(ws) = self.memory_workspace.clone() {
            // The frontend already owns instruction/environment gathering. Preserve that durable
            // split while routing the remaining lexical-memory + skill-index selection through
            // the pure frozen slot and the injected world adapter.
            let resolved = strategy_runtime::resolve_live_context(
                self.context_strategy.as_ref(),
                self.memory_strategy.as_ref(),
                self.context_port.as_ref(),
                strategy_runtime::LiveContextRequest {
                    workspace: &ws,
                    home_dir: self.context_home_dir.as_deref(),
                    dependency_skill_dirs: &self.dependency_skill_dirs,
                    turn,
                    task,
                },
            )
            .map_err(KernelError::ContextResolution)?;
            self.observe_resolved_context(
                turn,
                task,
                &resolved.segments,
                resolved.memory_audit.as_ref(),
                elapsed_us(resolution_started),
            );
            if !resolved.text.is_empty() {
                context_sources.push(resolved.governing_trust);
                context_text.push_str(&resolved.text);
            }
        }

        let context_trust =
            Trust::governing(context_sources).unwrap_or(if context_text.is_empty() {
                Trust::Trusted
            } else {
                // Non-empty bytes without provenance are a bug, never Trusted by default.
                Trust::Untrusted
            });
        let should_record = durable_instructions.is_some() || !context_text.is_empty();
        if should_record {
            self.emit_durable(
                turn,
                EventKind::ContextInjection {
                    text: context_text.clone(),
                    trust: context_trust,
                    instructions: durable_instructions.clone(),
                },
            )?;
        }
        let (text, trust) = match &durable_instructions {
            Some(instructions) => {
                let (text, trust) = iteron_ctx::assemble_recorded_context(
                    instructions,
                    context_text,
                    context_trust,
                );
                (text, Some(trust))
            }
            None => (context_text, should_record.then_some(context_trust)),
        };
        self.injected = Some(text);
        self.injected_trust = trust;
        self.clear_frontend_context_proposals();
        Ok(())
    }

    /// The last `ContextInjection` plus the latest inherited genesis environment snapshot, if any.
    /// Reads one fork-aware logical projection, never live instruction, memory, clock, or Git
    /// sources. Genesis is the crash-safe fallback only until ContextInjection becomes durable;
    /// any record/replay failure propagates instead of reopening a live-context fallback.
    pub(super) fn recorded_context_history(&self) -> Result<RecordedContextHistory, KernelError> {
        // Route through the fork-aware loader (not a raw child-file replay) so a FORKED run finds
        // the parent's recorded ContextInjection instead of silently re-deriving from live disk —
        // the exact disk re-derivation REC-INJECT exists to prevent (code review).
        let events = replay_logical_rollout(self.rollout.path())?;
        let mut history = RecordedContextHistory::default();
        for e in events {
            match e.kind {
                EventKind::RunStart {
                    environment: Some(environment),
                    ..
                } => history.genesis_environment = Some(environment),
                EventKind::ContextInjection {
                    text,
                    trust,
                    instructions,
                } => history.injection = Some((text, trust, instructions)),
                _ => {}
            }
        }
        Ok(history)
    }

    /// Coarse ADR-007 taint projection for the context that can influence the next proposal.
    /// Direct operator/system text is Trusted; injected sources and tool observations can lower
    /// it. Empty provenance explicitly means only direct input is in scope.
    pub(super) fn governing_turn_trust(&self, messages: &[Message]) -> Trust {
        let tool_trust = messages.iter().flat_map(|message| {
            message.content.iter().filter_map(|block| match block {
                Block::ToolResult(result) => Some(result.trust),
                _ => None,
            })
        });
        Trust::governing(
            std::iter::once(self.system_trust)
                .chain(std::iter::once(self.observed_trust))
                .chain(self.injected_trust)
                .chain(tool_trust),
        )
        .unwrap_or(Trust::Trusted)
    }
}
