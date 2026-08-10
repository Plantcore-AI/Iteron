use super::*;

impl Agent {
    /// Reconstruct the working message set from a rollout — the resume path (invariant #2,
    /// recoverable). Replays recorded Message events in order; a Compaction event resets the
    /// reconstruction to its snapshot (so resume reproduces the compacted state that actually
    /// ran, code review). Then reconciles a torn mid-turn tail so the result is a valid,
    /// API-acceptable transcript.
    pub fn messages_from_rollout(path: &std::path::Path) -> Result<Vec<Message>, KernelError> {
        // Route through `session::load_forked`: a forked run resumes from its parent's prefix
        // (replayed up to the fork point and VERIFIED against the recorded parent_hash_at_seq, so a
        // tampered parent is detected — ADR-008 §4). A non-forked run's genesis has no parent, so
        // this returns just its own chain (identical to a plain replay).
        let events = replay_logical_rollout(path)?;
        Ok(project_messages_from_events(events))
    }

    /// Load a prior run's transcript so `run` continues it instead of starting fresh.
    pub fn set_resume(&mut self, messages: Vec<Message>) -> Result<(), KernelError> {
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        // An explicit resume replaces the transcript outright; a working set left over from an
        // earlier run in this process must never outrank it on the next follow-up.
        self.working_set = None;
        // Redaction is applied on the RECORD path (ADR-008 §1). Resuming from that record can
        // therefore give the model masked tool output where the live turn saw the original bytes.
        // Emit only a bounded count through the injected port; neither transcript content nor a
        // record/parser error is diagnostic-safe.
        let mut redacted_tool_results = 0_u32;
        let mut count_saturated = false;
        for result in messages.iter().flat_map(|message| {
            message.content.iter().filter_map(|block| match block {
                Block::ToolResult(result) => Some(result),
                _ => None,
            })
        }) {
            if result.content.contains("[REDACTED") {
                if let Some(next) = redacted_tool_results.checked_add(1) {
                    redacted_tool_results = next;
                } else {
                    count_saturated = true;
                }
            }
        }
        if redacted_tool_results > 0 {
            self.diagnostics
                .emit(KernelDiagnostic::ResumeRedactionDegraded {
                    redacted_tool_results,
                    count_saturated,
                });
        }
        let requested_max_usd = self.budget.max_usd;
        // The compacted working transcript may no longer contain the original ToolResult block.
        // Recover taint from the append-only record, which retains ToolDone events. If that read
        // unexpectedly fails, do not widen authority on the resume path.
        match replay_scoped_rollout(self.rollout.path()) {
            Ok(scoped_events) => {
                let mut committed_provider_run_notices = std::collections::BTreeSet::new();
                for scoped in &scoped_events {
                    if &scoped.run_id != self.rollout.run_id() {
                        continue;
                    }
                    let EventKind::Notice { text } = &scoped.event.kind else {
                        continue;
                    };
                    let Some(key) = provider_run_notice_key_from_text(text) else {
                        continue;
                    };
                    if !committed_provider_run_notices.contains(&key)
                        && committed_provider_run_notices.len()
                            >= MAX_COMMITTED_PROVIDER_RUN_NOTICES
                    {
                        return Err(KernelError::ProviderRunNoticeLimit);
                    }
                    committed_provider_run_notices.insert(key);
                }
                self.committed_provider_run_notices = committed_provider_run_notices;
                let events = scoped_events
                    .iter()
                    .map(|scoped| scoped.event.clone())
                    .collect::<Vec<_>>();
                let mut legacy_ceiling_microusd: Option<u64> = None;
                for max_usd in events.iter().filter_map(|event| match &event.kind {
                    EventKind::RunStart {
                        max_usd: Some(max_usd),
                        ..
                    } => Some(*max_usd),
                    _ => None,
                }) {
                    if !max_usd.is_finite() {
                        return Err(KernelError::InvalidBudget("max_usd must be finite"));
                    }
                    if max_usd < 0.0 {
                        return Err(KernelError::InvalidBudget("max_usd must be non-negative"));
                    }
                    let candidate = legacy_usd_to_microusd_floor(max_usd);
                    legacy_ceiling_microusd = Some(
                        legacy_ceiling_microusd.map_or(candidate, |current| current.min(candidate)),
                    );
                }
                let mut exact_ceiling_microusd: Option<u64> = None;
                for candidate in events.iter().filter_map(|event| match &event.kind {
                    EventKind::UsdCeilingChanged { max_microusd, .. } => Some(*max_microusd),
                    _ => None,
                }) {
                    exact_ceiling_microusd = Some(
                        exact_ceiling_microusd.map_or(candidate, |current| current.min(candidate)),
                    );
                }
                // Exact fixed-point events are authoritative whenever present. The floating
                // genesis field exists only to read pre-policy journals safely.
                let recorded_ceiling_microusd = exact_ceiling_microusd.or(legacy_ceiling_microusd);
                if let Some(recorded_ceiling) = recorded_ceiling_microusd {
                    if let Some(shared) = &self.usd_budget {
                        shared.tighten_microusd(recorded_ceiling);
                    } else {
                        self.usd_budget = Some(std::sync::Arc::new(
                            SharedUsdBudget::from_microusd(recorded_ceiling),
                        ));
                    }
                    self.usd_budget_persisted_microusd = Some(recorded_ceiling);
                }
                // Reapply the invocation request only after logical history establishes its
                // durable floor. A smaller request is appended as a monotone policy transition;
                // None or a larger value cannot widen the inherited ceiling.
                self.budget.max_usd = requested_max_usd;
                // Runtime policy is a projection of the verified logical history, including the
                // bounded parent prefix of a fork. Restore it before any subsequent provider or
                // capability-gate decision; live CLI/config defaults cannot override the branch.
                let has_policy_record = events.iter().any(|event| {
                    matches!(
                        event.kind,
                        EventKind::RunStart { .. }
                            | EventKind::EffortChanged { .. }
                            | EventKind::PolicyChanged { .. }
                    )
                });
                if has_policy_record {
                    let runtime_policy = RuntimePolicyState::from_events(&events);
                    self.effort = runtime_policy.effort;
                    self.permission_mode = runtime_policy.permission_mode;
                    self.permission_rules = runtime_policy.permission_rules;
                }
                // Turn ids are canonical effect/correlation identities, not an invocation-local
                // counter. Resume and in-process follow-up therefore continue after the greatest
                // durable id across the verified fork history instead of silently reusing turn 0.
                self.seq_turn = events
                    .iter()
                    .map(|event| event.turn.0)
                    .max()
                    .map_or(0, |turn| turn.saturating_add(1));
                self.approval_seq = events
                    .iter()
                    .filter_map(|event| match &event.kind {
                        EventKind::Approval { id, .. } => Some(id.0),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                self.selected_route = events.iter().rev().find_map(|event| match &event.kind {
                    EventKind::ModelSelected {
                        provider_id,
                        model_id,
                        catalog_digest,
                        capability_digest,
                    } => Some(SelectedRoute {
                        route: PricingRoute {
                            provider_id: provider_id.clone(),
                            model_id: model_id.clone(),
                            catalog_digest: catalog_digest.clone(),
                            capability_digest: capability_digest.clone(),
                        },
                    }),
                    _ => None,
                });
                self.selected_provider =
                    self.selected_route.as_ref().map(|_| self.provider.clone());
                // A newly constructed Agent has an empty in-memory ledger. Rebuild completed
                // usage/cost and admitted provider attempts from the verified logical record so
                // resume cannot reset max_turns/max_usd. A live TUI follow-up already owns a
                // richer ledger (including child attribution), so never replace it with the
                // parent-file projection.
                if self.ledger.provider_attempts == 0 && self.ledger.turns == 0 {
                    let mut restored = Ledger::new();
                    let mut pricing_replay = self
                        .pricing_port
                        .as_ref()
                        .map(|pricing| iteron_obs::PricingReplay::trusted(pricing.clone()))
                        .unwrap_or_default();
                    for scoped in &scoped_events {
                        pricing_replay.observe(
                            &scoped.event,
                            &scoped.tenant,
                            &scoped.run_id,
                            &mut restored,
                        )?;
                    }
                    // Historical compaction/decomposition records may have a TurnEnd without a
                    // matching TurnStart. Count at least every completed billable response.
                    restored.provider_attempts = restored.provider_attempts.max(restored.turns);
                    self.ledger = restored;
                    if let Some(budget) = &self.usd_budget {
                        budget.restore(&self.ledger.cost_state());
                    }
                }
                self.observed_trust = Trust::governing(events.into_iter().flat_map(|event| {
                    match event.kind {
                        EventKind::ToolDone { result, .. } => vec![result.trust],
                        EventKind::Message { message } => message
                            .content
                            .into_iter()
                            .filter_map(|block| match block {
                                Block::ToolResult(result) => Some(result.trust),
                                _ => None,
                            })
                            .collect(),
                        _ => Vec::new(),
                    }
                }))
                .unwrap_or(Trust::Trusted);
                self.synchronize_usd_budget()?;
            }
            Err(_) => {
                // Reusing an identity or widening taint after a replay failure is unsafe. The
                // saturated turn id trips admission ceilings while the least-trusted tier blocks
                // egress, and run() independently returns the underlying record failure.
                self.seq_turn = u32::MAX;
                self.approval_seq = u64::MAX;
                self.observed_trust = Trust::Untrusted;
            }
        }
        self.resumed = Some(messages);
        Ok(())
    }

    /// Adopt another recorded run into THIS live process: the session continues that run's journal,
    /// identity and transcript without the operator leaving the terminal.
    ///
    /// # The per-process / per-run boundary
    ///
    /// Everything an `Agent` holds is one of two things, and adoption is exactly the line between
    /// them.
    ///
    /// **Per-process** — built once by the composition root from the environment, not from any
    /// run's record, and therefore PRESERVED here: the provider handle and registry, the workspace,
    /// the pinned agent catalog, the system prompt and its trust, hooks, telemetry, the diagnostic
    /// port, the pricing port, the interrupt/drain atomics, the approvals receiver, the context
    /// ports and tunables, and the invocation's budget ceilings.
    ///
    /// **Per-run** — a projection of one journal, and therefore REPLACED: the rollout itself, the
    /// working transcript, the ledger, the runtime policy (effort/mode/rules), the turn and
    /// approval identity counters, taint, the durable route, the injected context segment, the
    /// at-most-once effect ledger, and the run-scoped provider notices.
    ///
    /// Most of the second list is restored from the record by [`Self::set_resume`], which reads
    /// `self.rollout` — so the swap has to happen first, and the fields `set_resume` does NOT own
    /// are cleared here so they cannot leak across runs. The one field it owns conditionally is the
    /// ledger: it rebuilds only an EMPTY one, because an in-process follow-up already holds a richer
    /// one. Adoption is the case where that live ledger belongs to a different run, so it is reset
    /// to empty first and the record becomes the authority again.
    ///
    /// # What this does not do
    ///
    /// It does not bind a route. `set_resume` restores the adopted run's recorded `selected_route`
    /// but cannot resolve a provider, so `self.model` still names the previous run's model and
    /// `validate_provider_request_route` will refuse the next provider request until the caller
    /// records a selection (`record_provider_model_selection`) for the route the session will
    /// actually use. That refusal is the safe direction: no request is dispatched against a route
    /// the record does not carry.
    ///
    /// # Failure
    ///
    /// The replay happens BEFORE anything is mutated, so a torn or unreadable record leaves the live
    /// run completely untouched and the previous rollout's writer lock still held. After the swap,
    /// an error means the session is between two runs and the process must be restarted; the
    /// returned error says so.
    pub fn adopt_run(&mut self, rollout: Rollout) -> Result<AdoptedRun, KernelError> {
        // Replay first: this is the only step that can fail without leaving the session between two
        // runs, so it happens while the live run is still entirely intact.
        let messages = Self::messages_from_rollout(rollout.path())?;
        let message_count = messages.len();

        // Dropping the previous rollout releases its exclusive writer lock, so the run this session
        // is leaving becomes resumable by another process the moment this returns.
        let previous = std::mem::replace(&mut self.rollout, rollout);

        // Per-run state `set_resume` does not own. Every one of these describes the run being left.
        self.working_set = None;
        self.resumed = None;
        self.ledger = Ledger::new();
        self.injected = None;
        self.injected_trust = None;
        // Re-offer the operator instructions this process was started with. A recorded
        // ContextInjection in the adopted journal still outranks it — which is every run that has
        // taken a turn — so this only reaches a run that never resolved one, and keeps it from
        // resolving with less than `--resume` would have given it. The environment snapshot is NOT
        // re-proposed: it describes a fresh start, and this is not one.
        self.instruction_context = self.composition_instruction_context.clone();
        self.last_assistant_text.clear();
        self.failed_actions.clear();
        self.pending_steers.clear();
        self.verify_attempts = 0;
        self.compacted_in_run = false;
        self.interrupt_requested = false;
        self.pricing = None;
        // At-most-once identities are per-journal. `guard_unresolved_effects` reseeds this from the
        // adopted record before the next turn dispatches anything; clearing it now means the window
        // in between cannot admit an effect against the previous run's ledger.
        self.effect_admissions = effect_admission::EffectAdmissions::default();
        // The estimator caches a per-message token estimate for a transcript that is being replaced.
        self.context_estimator.invalidate_transcript();
        // A failed append belongs to the journal it failed on. The adopted journal was just replayed
        // and opened with its own writer descriptor, so the halt does not carry over.
        self.record_failed = false;

        self.set_resume(messages)?;

        let adopted = AdoptedRun {
            run_id: self.rollout.run_id().0.clone(),
            rollout_path: self.rollout.path().to_path_buf(),
            previous_run_id: previous.run_id().0.clone(),
            messages: message_count,
            turns: self.ledger.turns,
            recorded_route: self.selected_route.as_ref().map(|selected| {
                (
                    selected.route.provider_id.clone(),
                    selected.route.model_id.clone(),
                )
            }),
        };
        drop(previous);
        Ok(adopted)
    }

    /// Record the seq-0 session genesis header (SESS-4): cwd/model/effort/created_at, so a session
    /// listing has metadata without replaying the whole rollout and a fork inherits it. `created_at`
    /// crosses the record boundary ONCE here (read from the record on replay, ADR-006 rule 1). The
    /// frontend calls this on a FRESH run, before `run`, so it is the first event on the chain.
    pub fn record_genesis(
        &mut self,
        cwd: String,
        created_at: u64,
        config_digest: String,
        agent_definition_tag: Option<String>,
    ) -> Result<(), KernelError> {
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        self.reconcile_usd_budget_for_genesis();
        if !self.model.is_empty() {
            validate_route_identifier("model_id", &self.model, 512, false)?;
        }
        validate_route_digest("config_digest", &config_digest)?;
        if let Some(tag) = &agent_definition_tag {
            validate_route_identifier(
                "agent_definition_tag",
                tag,
                iteron_protocol::MAX_AGENT_DEFINITION_TAG_BYTES,
                false,
            )?;
        }
        self.emit_durable(
            TurnId(0),
            EventKind::RunStart {
                cwd,
                model: self.model.clone(),
                effort: self.effort,
                created_at,
                environment: self.environment_context.as_ref().map(|(text, trust)| {
                    DurableEnvironmentContext {
                        text: text.clone(),
                        trust: *trust,
                    }
                }),
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest,
                agent_definition_tag,
                max_usd: self.effective_max_usd(),
            },
        )?;
        if let Some(max_microusd) = self
            .usd_budget
            .as_ref()
            .map(|budget| budget.ceiling_microusd())
        {
            // `RunStart.max_usd` remains a compatibility projection only. Persist the exact
            // fixed-point authority before treating the ceiling as durable so a resume/fork can
            // never widen it through an f64 round trip.
            self.emit_durable(
                TurnId(0),
                EventKind::UsdCeilingChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Startup,
                    max_microusd,
                },
            )?;
            self.usd_budget_persisted_microusd = Some(max_microusd);
        }
        // Genesis is followed by explicit v1 policy snapshots. `RunStart.effort` remains for
        // legacy readers; these events make the runtime-policy schema uniform and give forks an
        // independently materializable baseline.
        self.emit_durable(
            TurnId(0),
            EventKind::EffortChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Startup,
                effort: self.effort,
            },
        )?;
        self.emit_durable(
            TurnId(0),
            EventKind::PolicyChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Startup,
                mode: self.permission_mode,
                rules: self.permission_rules.clone(),
            },
        )
    }
}
