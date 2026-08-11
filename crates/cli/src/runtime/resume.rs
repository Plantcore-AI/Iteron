use super::*;

/// Complete fallible projection of an adopted journal. Construction may verify signatures,
/// validate identities, allocate bounded state, and append a monotone USD tightening to the target
/// journal; applying it to the resident `Agent` is assignments only.
struct StagedAdoptedResume {
    messages: Vec<Message>,
    redacted_tool_results: u32,
    redaction_count_saturated: bool,
    committed_provider_run_notices: std::collections::BTreeSet<String>,
    composition_environment_context: Option<(String, Trust)>,
    budget: Budget,
    usd_budget: Option<std::sync::Arc<SharedUsdBudget>>,
    usd_budget_persisted_microusd: Option<u64>,
    effort: Effort,
    permission_mode: PermissionMode,
    permission_rules: PermissionRules,
    runtime_policy_provenance: runtime_policy_overlay::RuntimePolicyProvenance,
    seq_turn: u32,
    last_compaction_turn: Option<u64>,
    approval_seq: u64,
    selected_route: Option<SelectedRoute>,
    ledger: Ledger,
    observed_trust: Trust,
}

impl Agent {
    /// Reconstruct the working message set from a rollout — the resume path (invariant #2,
    /// recoverable). Replays recorded Message events in order; a Compaction event resets the
    /// reconstruction to its snapshot (so resume reproduces the compacted state that actually
    /// ran, code review). Then reconciles a torn mid-turn tail so the result is a valid,
    /// API-acceptable transcript.
    pub fn messages_from_rollout(path: &std::path::Path) -> Result<Vec<Message>, KernelError> {
        // A V2 runtime checkpoint is usable only after its complete policy tail is durable. This
        // physical-root gate makes a failed fresh-session construction permanently unadoptable;
        // later transcript events cannot masquerade as the missing genesis seal.
        let physical = iteron_record::replay(path)?;
        validate_complete_runtime_genesis(&physical)?;
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
        self.last_compaction_turn = None;
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
                let runtime_policy_provenance = self
                    .runtime_policy_provenance
                    .replay_preserving_handle(&events, RuntimePolicyObservation::ResumeReplay);
                let recorded_environment = scoped_events.iter().find_map(|scoped| {
                    if &scoped.run_id != self.rollout.run_id() {
                        return None;
                    }
                    match &scoped.event.kind {
                        EventKind::RunStart { environment, .. } => Some(environment.clone()),
                        _ => None,
                    }
                });
                let recorded_environment = recorded_environment.flatten();
                self.validate_environment_identity(recorded_environment.as_ref())?;
                self.composition_environment_context =
                    recorded_environment.map(|environment| (environment.text, environment.trust));
                if let Some(recorded) = scoped_events.iter().find_map(|scoped| {
                    if &scoped.run_id != self.rollout.run_id() {
                        return None;
                    }
                    match &scoped.event.kind {
                        EventKind::PolicyBundleSnapshot { snapshot, .. } => Some(snapshot),
                        _ => None,
                    }
                }) && recorded != self.compiled_policy_bundle.genesis_snapshot()
                {
                    return Err(KernelError::ContextResolution(
                        "installed policy checkpoint differs from the resumed run genesis".into(),
                    ));
                }
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
                            | EventKind::TurnCeilingChanged { .. }
                            | EventKind::EffortChanged { .. }
                            | EventKind::PolicyChanged { .. }
                    )
                });
                if has_policy_record {
                    let runtime_policy = RuntimePolicyState::from_events(&events);
                    self.effort = runtime_policy.effort;
                    self.permission_mode = runtime_policy.permission_mode;
                    self.permission_rules = runtime_policy.permission_rules;
                    if let Some(max_turns) = runtime_policy.turn_ceiling {
                        self.budget.max_turns = max_turns;
                    }
                    self.runtime_policy_provenance = runtime_policy_provenance;
                }
                // Turn ids are canonical effect/correlation identities, not an invocation-local
                // counter. Resume and in-process follow-up therefore continue after the greatest
                // durable id across the verified fork history instead of silently reusing turn 0.
                self.seq_turn = events
                    .iter()
                    .map(|event| event.turn.0)
                    .max()
                    .map_or(0, |turn| turn.saturating_add(1));
                self.last_compaction_turn = events.iter().rev().find_map(|event| {
                    matches!(event.kind, EventKind::Compaction { .. })
                        .then_some(u64::from(event.turn.0))
                });
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
                if let Some(selected) = &self.selected_route {
                    self.context_estimator
                        .set_route(Some(&selected.route.provider_id), &selected.route.model_id);
                }
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
                    self.restore_usd_budget_from_route_receipts(&scoped_events)?;
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
                self.runtime_policy_provenance =
                    runtime_policy_overlay::RuntimePolicyProvenance::default();
            }
        }
        self.resumed = Some(messages);
        Ok(())
    }

    /// Build the complete target-run projection before changing any resident per-run state. All
    /// record I/O, pricing authentication, bounded allocation, and identity checks happen here.
    /// The only target mutation this may perform is a monotone USD-ceiling event, committed to the
    /// target writer before adoption; a failure still leaves the live run and its writer intact.
    fn stage_adopted_resume(
        &mut self,
        rollout: &mut Rollout,
        messages: Vec<Message>,
        effective_core: &crate::runtime_tunables::effective_core::EffectiveCoreSettings,
        compiled_policy_bundle: &crate::bundle_adapter::CompiledPolicyBundle,
    ) -> Result<StagedAdoptedResume, KernelError> {
        effective_core
            .budget
            .validate()
            .map_err(KernelError::InvalidBudget)?;
        let scoped_events = replay_scoped_rollout(rollout.path())?;
        let mut events = scoped_events
            .iter()
            .map(|scoped| scoped.event.clone())
            .collect::<Vec<_>>();

        let mut redacted_tool_results = 0_u32;
        let mut redaction_count_saturated = false;
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
                    redaction_count_saturated = true;
                }
            }
        }

        let mut committed_provider_run_notices = std::collections::BTreeSet::new();
        for scoped in &scoped_events {
            if &scoped.run_id != rollout.run_id() {
                continue;
            }
            let EventKind::Notice { text } = &scoped.event.kind else {
                continue;
            };
            let Some(key) = provider_run_notice_key_from_text(text) else {
                continue;
            };
            if !committed_provider_run_notices.contains(&key)
                && committed_provider_run_notices.len() >= MAX_COMMITTED_PROVIDER_RUN_NOTICES
            {
                return Err(KernelError::ProviderRunNoticeLimit);
            }
            committed_provider_run_notices.insert(key);
        }

        let recorded_environment = scoped_events.iter().find_map(|scoped| {
            if &scoped.run_id != rollout.run_id() {
                return None;
            }
            match &scoped.event.kind {
                EventKind::RunStart { environment, .. } => Some(environment.clone()),
                _ => None,
            }
        });
        let recorded_environment = recorded_environment.flatten();
        self.validate_environment_identity(recorded_environment.as_ref())?;

        if let Some(recorded) = scoped_events.iter().find_map(|scoped| {
            if &scoped.run_id != rollout.run_id() {
                return None;
            }
            match &scoped.event.kind {
                EventKind::PolicyBundleSnapshot { snapshot, .. } => Some(snapshot),
                _ => None,
            }
        }) && recorded != compiled_policy_bundle.genesis_snapshot()
        {
            return Err(KernelError::ContextResolution(
                "installed policy checkpoint differs from the adopted run genesis".into(),
            ));
        }

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
            legacy_ceiling_microusd =
                Some(legacy_ceiling_microusd.map_or(candidate, |current| current.min(candidate)));
        }

        let mut exact_ceiling_microusd: Option<u64> = None;
        for candidate in events.iter().filter_map(|event| match &event.kind {
            EventKind::UsdCeilingChanged { max_microusd, .. } => Some(*max_microusd),
            _ => None,
        }) {
            exact_ceiling_microusd =
                Some(exact_ceiling_microusd.map_or(candidate, |current| current.min(candidate)));
        }
        let recorded_ceiling_microusd = exact_ceiling_microusd.or(legacy_ceiling_microusd);

        let mut budget = effective_core.budget.clone();
        let requested_ceiling_microusd = budget.max_usd.map(usd_to_microusd_ceiling);
        let effective_ceiling_microusd =
            match (recorded_ceiling_microusd, requested_ceiling_microusd) {
                (None, None) => None,
                (Some(recorded), None) => Some(recorded),
                (None, Some(requested)) => Some(requested),
                (Some(recorded), Some(requested)) => Some(recorded.min(requested)),
            };

        let seq_turn = events
            .iter()
            .map(|event| event.turn.0)
            .max()
            .map_or(0, |turn| turn.saturating_add(1));
        let mut usd_budget_persisted_microusd = recorded_ceiling_microusd;
        if let Some(target) = effective_ceiling_microusd
            && recorded_ceiling_microusd.is_none_or(|recorded| target < recorded)
        {
            let kind = EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: if recorded_ceiling_microusd.is_some() {
                    RuntimePolicySource::Operator
                } else {
                    RuntimePolicySource::Startup
                },
                max_microusd: target,
            };
            let sequence = rollout.append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(seq_turn),
                kind: kind.clone(),
            })?;
            events.push(Event {
                seq: sequence,
                turn: TurnId(seq_turn),
                kind,
            });
            usd_budget_persisted_microusd = Some(target);
        }
        budget.max_usd = effective_ceiling_microusd.map(|value| value as f64 / 1_000_000.0);

        let has_policy_record = events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::RunStart { .. }
                    | EventKind::TurnCeilingChanged { .. }
                    | EventKind::EffortChanged { .. }
                    | EventKind::PolicyChanged { .. }
            )
        });
        let runtime_policy = RuntimePolicyState::from_events(&events);
        let effort = if has_policy_record {
            runtime_policy.effort
        } else {
            effective_core.effort
        };
        let permission_mode = if has_policy_record {
            runtime_policy.permission_mode
        } else {
            effective_core.permission_mode
        };
        let permission_rules = if has_policy_record {
            runtime_policy.permission_rules
        } else {
            effective_core.permission_rules.clone()
        };
        if let Some(max_turns) = runtime_policy.turn_ceiling {
            budget.max_turns = max_turns;
        }

        let runtime_policy_provenance = self
            .runtime_policy_provenance
            .replay_preserving_handle(&events, RuntimePolicyObservation::ResumeReplay);
        let last_compaction_turn = events.iter().rev().find_map(|event| {
            matches!(event.kind, EventKind::Compaction { .. }).then_some(u64::from(event.turn.0))
        });
        let approval_seq = events
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::Approval { id, .. } => Some(id.0),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let selected_route = events.iter().rev().find_map(|event| match &event.kind {
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

        let mut restored = Ledger::new();
        let mut pricing_replay = self
            .pricing_port
            .as_ref()
            .map(|pricing| iteron_obs::PricingReplay::trusted(pricing.clone()))
            .unwrap_or_default();
        for scoped in &scoped_events {
            pricing_replay.observe(&scoped.event, &scoped.tenant, &scoped.run_id, &mut restored)?;
        }
        // Historical compaction/decomposition records may have a TurnEnd without a matching
        // TurnStart. Count at least every completed billable response.
        restored.provider_attempts = restored.provider_attempts.max(restored.turns);
        let usd_budget = effective_ceiling_microusd
            .map(|ceiling| {
                let budget = std::sync::Arc::new(SharedUsdBudget::from_microusd(ceiling));
                let route_replay = route_attempt_accounting::replay_route_charges(
                    &scoped_events,
                    self.pricing_port.as_deref(),
                )?;
                budget
                    .restore_provider_route_charges(&restored.cost_state(), route_replay)
                    .map_err(KernelError::PricingLedger)?;
                Ok::<_, KernelError>(budget)
            })
            .transpose()?;
        let observed_trust = Trust::governing(events.iter().flat_map(|event| {
            match &event.kind {
                EventKind::ToolDone { result, .. } => vec![result.trust],
                EventKind::Message { message } => message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        Block::ToolResult(result) => Some(result.trust),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        }))
        .unwrap_or(Trust::Trusted);

        // Exercise the last fallible point of the staging transaction. This is deliberately after
        // replay, pricing receipt verification, policy projection, and bounded allocations but
        // before the resident writer or any resident per-run owner changes.
        #[cfg(test)]
        if self.fail_next_durable_append == Some(DurableAppendFault::AdoptProjection) {
            self.fail_next_durable_append = None;
            return Err(KernelError::Record(iteron_record::RecordError::Io(
                std::io::Error::other("injected adopted-resume projection failure"),
            )));
        }

        Ok(StagedAdoptedResume {
            messages,
            redacted_tool_results,
            redaction_count_saturated,
            committed_provider_run_notices,
            composition_environment_context: recorded_environment
                .map(|environment| (environment.text, environment.trust)),
            budget,
            usd_budget,
            usd_budget_persisted_microusd,
            effort,
            permission_mode,
            permission_rules,
            runtime_policy_provenance,
            seq_turn,
            last_compaction_turn,
            approval_seq,
            selected_route,
            ledger: restored,
            observed_trust,
        })
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
    /// ports, and the invocation's budget ceilings.
    ///
    /// **Per-run** — a projection of one journal, and therefore REPLACED: the rollout itself, the
    /// working transcript, the ledger, the immutable tunables checkpoint, the runtime policy
    /// (effort/mode/rules), the turn and approval identity counters, taint, the durable route, the
    /// injected context segment, the at-most-once effect ledger, and the run-scoped provider
    /// notices.
    ///
    /// The complete target projection is built while the current rollout and every current per-run
    /// field remain untouched. Only after all record, pricing, policy, environment, and bounded
    /// state checks succeed does one assignment-only commit swap the writer and projection.
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
    /// Every fallible operation happens before the writer swap. A refusal therefore leaves the live
    /// run, its policy publication handle, and its writer lock intact. The target may contain a
    /// successfully committed monotone USD tightening, but is never reported as the active run.
    pub fn adopt_run(&mut self, mut rollout: Rollout) -> Result<AdoptedRun, KernelError> {
        // Replay first: this is the only step that can fail without leaving the session between two
        // runs, so it happens while the live run is still entirely intact.
        let messages = Self::messages_from_rollout(rollout.path())?;
        let checkpoint = rollout
            .tunables_checkpoint()?
            .ok_or(KernelError::TunablesNotResolved)?;
        let tunables_pin = tunables_pin::TunablesPin::from_checkpoint(checkpoint)?;
        let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
            tunables_pin.checkpoint(),
            None,
        )
        .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
        let tooling = effective.tooling;
        tooling
            .verify_installed(&self.registry)
            .map_err(|error| KernelError::ToolingPolicy(error.to_string()))?;
        if self.effective_content.as_ref() != Some(&effective.content) {
            return Err(KernelError::ExecutionPolicy(
                "adopted content-owner identities differ from the running process".into(),
            ));
        }
        let effective_content = effective.content;
        let effective_core = effective.core;
        let adopted_token_estimator = effective_core.token_estimator;
        // Some owners are physically process-scoped: the resident queues already exist, the
        // instruction proposal has already been read/rendered, and the provider fallback objects
        // were constructed by the composition root. An in-process adoption may replace every
        // ordinary run owner below, but it cannot pretend these objects changed merely because a
        // different checkpoint was selected in the frontend. Compare their executable values
        // before touching either process state or the live rollout. A restart can reconstruct an
        // incompatible run from its own checkpoint.
        if let Some(current_pin) = &self.tunables_pin {
            require_same_adoption_families(
                current_pin.checkpoint(),
                tunables_pin.checkpoint(),
                &[
                    "instruction_discovery_render",
                    "app_server_sq_eq_backpressure",
                    "model_fallback_chain",
                    "failover_eligible_error_taxonomy",
                    "route_quality_cost_latency_objective_weights",
                    "provider_health_circuit_breaker_state_policy",
                    "hedged_request_policy",
                    "provider_service_tier",
                    "response_verbosity",
                    "request_compression_policy",
                    "rate_limit_aware_admission",
                    "prompt_cache_ttl_breakpoint_strategy",
                    "prompt_cache",
                    "mcp_topology_tool_catalog",
                    "mcp_transport_selection",
                    "deferred_discovery_threshold",
                    "mcp_reconnect_backoff",
                    "per_server_startup_deadline",
                    "per_tool_mcp_deadline",
                    "mcp_result_cap_spill_policy",
                    "oauth_auth_lifecycle_policy",
                    "resource_prompt_plugin_capability_exposure",
                    "session_isolation_profile",
                ],
            )?;
        }
        if effective_core.app_server_queue != self.app_server_queue_policy {
            return Err(KernelError::ExecutionPolicy(
                "adopted app-server queue owner differs from the resident process; restart to resume that run"
                    .into(),
            ));
        }
        let primary_route_id =
            format!("{}:{}", effective_core.provider_id, effective_core.model_id);
        let fallback_start = effective_core
            .provider_governor
            .fallback_routes
            .iter()
            .position(|route| route == &primary_route_id)
            .map_or(0, |index| index.saturating_add(1));
        let expected_fallback_ids = effective_core
            .provider_governor
            .fallback_routes
            .iter()
            .skip(fallback_start)
            .filter(|route| *route != &primary_route_id)
            .cloned()
            .collect::<Vec<_>>();
        let installed_fallback_ids = self
            .fallback_provider_routes
            .iter()
            .map(GovernedProviderRoute::id)
            .collect::<Vec<_>>();
        if installed_fallback_ids != expected_fallback_ids {
            return Err(KernelError::ExecutionPolicy(
                "adopted fallback-route topology differs from the resident process; restart to resume that run"
                    .into(),
            ));
        }
        self.provider
            .control_capabilities()
            .validate(&effective_core.provider_governor.controls)
            .map_err(|_| KernelError::InvalidRouteMetadata {
                field: "provider_controls",
                reason: "resident provider does not attest the adopted request controls",
            })?;
        for route in &self.fallback_provider_routes {
            route
                .provider
                .control_capabilities()
                .validate(&effective_core.provider_governor.controls)
                .map_err(|_| KernelError::InvalidRouteMetadata {
                    field: "provider_fallback_routes",
                    reason: "a resident fallback does not attest the adopted request controls",
                })?;
        }
        effective_core
            .verify_model_capability_ceiling(
                self.model_context_window,
                self.model_max_output_tokens,
            )
            .map_err(|error| KernelError::ExecutionPolicy(error.to_string()))?;
        let adopted_governor = iteron_provider::ProviderGovernor::new(
            effective_core.provider_governor.policy.clone(),
            std::iter::once(primary_route_id).chain(expected_fallback_ids.iter().cloned()),
        )
        .map_err(|_| KernelError::InvalidRouteMetadata {
            field: "provider_governor",
            reason: "adopted governor policy or route set is invalid",
        })?;
        let adopted_spawn_ledger = std::sync::Arc::new(
            SessionSpawnLedger::new(effective_core.session_spawn_cap)
                .map_err(|reason| KernelError::ExecutionPolicy(reason.into()))?,
        );
        let adopted_authority_ceiling =
            effective_core.constrain_authority_ceiling(self.authority_ceiling);
        let tool_output_spill = std::sync::Arc::new(
            tool_output_spill::ToolOutputSpillStore::create_for_run(
                tooling.tool_output_spill,
                rollout.path().parent().ok_or(KernelError::ToolOutputSpill(
                    "record store resolution failed",
                ))?,
                rollout.tenant().clone(),
                rollout.run_id().clone(),
            )
            .map_err(|_| KernelError::ToolOutputSpill("private store creation failed"))?,
        );
        let policy_checkpoint = rollout.policy_bundle_checkpoint()?.ok_or_else(|| {
            KernelError::ContextResolution(
                "adopted run has no immutable policy-bundle checkpoint".into(),
            )
        })?;
        let compiled_policy_bundle = crate::bundle_adapter::compile_recorded_bundle(
            &policy_checkpoint,
        )
        .map_err(|error| {
            KernelError::ContextResolution(format!(
                "adopted policy-bundle checkpoint is not executable: {error}"
            ))
        })?;
        Self::validate_compiled_policy_bundle_shape(compiled_policy_bundle.as_ref())?;
        match &self.mcp_runtime {
            Some(runtime) => runtime
                .validate_configuration(&effective_core.mcp, &effective_core.mcp_exposure)
                .map_err(|_| {
                    KernelError::McpLifecycle(
                        "adopted MCP checkpoint differs from the resident session runtime",
                    )
                })?,
            None if effective_core.mcp.is_disabled()
                && effective_core.mcp_exposure.is_disabled() =>
            {
                // An entirely disabled checkpoint has no MCP actor or exposed capability to
                // mutate. Active policies must have the resident runtime below; absence is never
                // interpreted as a process-local default.
            }
            None => {
                return Err(KernelError::McpLifecycle(
                    "adopted MCP checkpoint is active but no resident session runtime is installed",
                ));
            }
        }
        let staged = self.stage_adopted_resume(
            &mut rollout,
            messages,
            &effective_core,
            compiled_policy_bundle.as_ref(),
        )?;
        let message_count = staged.messages.len();

        // Dropping the previous rollout releases its exclusive writer lock, so the run this session
        // is leaving becomes resumable by another process the moment this returns.
        let previous = std::mem::replace(&mut self.rollout, rollout);

        // Per-run state `set_resume` does not own. Every one of these describes the run being left.
        self.working_set = None;
        self.resumed = None;
        self.tunables_pin = Some(tunables_pin);
        self.tool_output_spill = Some(tool_output_spill);
        self.budget = staged.budget;
        self.usd_budget = staged.usd_budget;
        self.usd_budget_persisted_microusd = staged.usd_budget_persisted_microusd;
        self.retry_policy = effective_core.retry;
        self.provider_controls = effective_core.provider_governor.controls;
        self.provider_governor = Some(adopted_governor);
        self.last_rate_limit = None;
        self.session_spawn_ledger = adopted_spawn_ledger;
        self.deferred_tool_eager_limit = effective_core.deferred_tool_eager_limit;
        self.execution_policy = effective_core.execution;
        self.verification_policy = effective_core.verification;
        self.verify_command = effective_core.verify_command;
        self.compaction = effective_core.compaction;
        self.context_budget_policy = effective_core.context_budget;
        self.context_materialization_policy = effective_core.context_materialization;
        self.model_context_window = effective_core.model_context_window;
        self.model_max_output_tokens = effective_core.request_output_cap;
        self.effective_content = Some(effective_content);
        self.app_server_queue_policy = effective_core.app_server_queue;
        self.binary_media_policy = effective_core.binary_media;
        self.multimodal_decode_envelope = effective_core.multimodal_decode;
        self.bypass_permissions = effective_core.bypass_permissions;
        self.memory_workspace = effective_core
            .memory_enabled
            .then(|| self.workspace.clone());
        self.narrow_authority_ceiling(adopted_authority_ceiling);
        self.ledger = staged.ledger;
        self.effort = staged.effort;
        self.permission_mode = staged.permission_mode;
        self.permission_rules = staged.permission_rules;
        self.runtime_policy_provenance = staged.runtime_policy_provenance;
        self.committed_provider_run_notices = staged.committed_provider_run_notices;
        self.composition_environment_context = staged.composition_environment_context.clone();
        self.environment_context = staged.composition_environment_context;
        self.selected_route = staged.selected_route;
        self.selected_provider = self.selected_route.as_ref().map(|_| self.provider.clone());
        self.seq_turn = staged.seq_turn;
        self.approval_seq = staged.approval_seq;
        self.observed_trust = staged.observed_trust;
        self.injected = None;
        self.injected_trust = None;
        self.apply_validated_compiled_policy_bundle(compiled_policy_bundle);
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
        self.verification_quarantine.clear();
        self.verification_quarantine_restored = false;
        self.compacted_in_run = false;
        self.last_compaction_turn = staged.last_compaction_turn;
        self.interrupt_requested = false;
        self.pricing = None;
        // At-most-once identities are per-journal. `guard_unresolved_effects` reseeds this from the
        // adopted record before the next turn dispatches anything; clearing it now means the window
        // in between cannot admit an effect against the previous run's ledger.
        self.effect_admissions = effect_admission::EffectAdmissions::default();
        // The estimator caches a per-message token estimate for a transcript that is being replaced.
        self.context_estimator.invalidate_transcript();
        self.context_estimator.pin_policy(adopted_token_estimator);
        self.context_source_evidence.clear();
        self.input_file_evidence = None;
        self.context_ledgers = iteron_ctx::ContextLedgerStore::default();
        self.memory_traces = iteron_ctx::MemoryTraceStore::default();
        self.session_memory_visibility.clear();
        // A failed append belongs to the journal it failed on. The adopted journal was just replayed
        // and opened with its own writer descriptor, so the halt does not carry over.
        self.record_failed = false;
        self.resumed = Some(staged.messages);
        if let Some(selected) = &self.selected_route {
            self.context_estimator
                .set_route(Some(&selected.route.provider_id), &selected.route.model_id);
        }
        if staged.redacted_tool_results > 0 {
            self.diagnostics
                .emit(KernelDiagnostic::ResumeRedactionDegraded {
                    redacted_tool_results: staged.redacted_tool_results,
                    count_saturated: staged.redaction_count_saturated,
                });
        }
        // Publish through the preserved process-owned handle after every enforced field changed.
        let _ = self.runtime_policy_overlay();

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

    /// Mint and adopt a new in-process session from this session's already-pinned execution
    /// identity.
    ///
    /// A new tab is a fresh root run, but it is not a new process boot: consulting live config or
    /// rebuilding defaults here would let two tabs in one process execute under different harness
    /// checkpoints. Seal the target journal with the exact current V2 tunables checkpoint and
    /// compiler-validated nine-slot policy bundle before swapping the live writer. Any validation
    /// or append failure therefore leaves `self.rollout` untouched; a partially written target is
    /// rejected by the ordinary genesis replay gates and is never adopted.
    pub fn adopt_fresh_run(
        &mut self,
        mut rollout: Rollout,
        cwd: String,
        created_at: u64,
        agent_definition_tag: Option<String>,
    ) -> Result<AdoptedRun, KernelError> {
        let pin = self.tunables_pin_snapshot()?;
        let resolution_digest = match pin.checkpoint() {
            iteron_record::TunablesCheckpoint::V2(snapshot) => {
                snapshot.resolution_digest_sha256.clone()
            }
            iteron_record::TunablesCheckpoint::V1(_) => {
                return Err(KernelError::ContextResolution(
                    "a fresh in-process session requires a complete V2 tunables checkpoint".into(),
                ));
            }
        };
        let policy_snapshot = self.compiled_policy_bundle.genesis_snapshot().clone();
        iteron_record::policy_bundle::validate_policy_bundle_snapshot(&policy_snapshot).map_err(
            |error| {
                KernelError::ContextResolution(format!(
                    "current policy-bundle checkpoint cannot seed a fresh session: {error}"
                ))
            },
        )?;

        let config_digest = format!("sha256:{resolution_digest}");
        // Fresh adoption is a transaction against another writer. Derive the ceiling that an
        // ordinary genesis reconciliation would install, but do not mutate the resident shared
        // budget: a later target append may still fail and leave this session on its old run.
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        let fresh_usd_ceiling_microusd = self.prospective_genesis_usd_ceiling_microusd();
        let run_start = self.genesis_event_with_usd_ceiling(
            cwd,
            created_at,
            config_digest,
            agent_definition_tag,
            fresh_usd_ceiling_microusd,
        )?;
        let policy_tail = self.genesis_policy_tail_events_with_usd_ceiling(
            RuntimePolicySource::Startup,
            fresh_usd_ceiling_microusd,
        );
        #[cfg(test)]
        let inject_tail_failure =
            if self.fail_next_durable_append == Some(DurableAppendFault::GenesisPolicyTail) {
                self.fail_next_durable_append = None;
                true
            } else {
                false
            };
        #[cfg(not(test))]
        let inject_tail_failure = false;
        let sealed = (|| -> Result<(), iteron_record::RecordError> {
            pin.append_genesis(&mut rollout, &run_start, None)?;
            rollout.append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::PolicyBundleSnapshot {
                    version: iteron_protocol::RunGenesisPolicyBundleVersion::V1,
                    snapshot: policy_snapshot,
                    inherited_from: None,
                },
            })?;
            for kind in policy_tail {
                // Fail after a real tail prefix, immediately before its final seal, so the oracle
                // exercises the exact dangerous state rather than an empty-target shortcut.
                if inject_tail_failure && matches!(kind, EventKind::PolicyChanged { .. }) {
                    return Err(iteron_record::RecordError::Io(std::io::Error::other(
                        "injected fresh-genesis policy-tail failure",
                    )));
                }
                rollout.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind,
                })?;
            }
            Ok(())
        })();
        if let Err(error) = sealed {
            return Err(KernelError::Record(error));
        }

        // Replay and reconstruct through the same fail-closed path as every resumed session. Only
        // a fully sealed target reaches the swap; no post-swap append can turn an adoption reply
        // into a refusal while leaving the agent on the new writer.
        self.adopt_run(rollout)
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
        let run_start = self.genesis_event(cwd, created_at, config_digest, agent_definition_tag)?;
        self.emit_durable(TurnId(0), run_start.kind)?;
        self.record_genesis_policy_tail()
    }

    /// Production fresh-genesis path. The already-pinned atomic tunables result is appended at
    /// physical sequence 1 immediately after `run_start`; no route, policy, or user event can
    /// interleave. A missing runtime binding is a startup refusal rather than a legacy default.
    pub fn record_genesis_with_tunables(
        &mut self,
        cwd: String,
        created_at: u64,
        config_digest: String,
        agent_definition_tag: Option<String>,
    ) -> Result<(), KernelError> {
        let pin = self.tunables_pin_snapshot()?;
        let run_start = self.genesis_event(cwd, created_at, config_digest, agent_definition_tag)?;
        let fsync_started = Instant::now();
        let appended = pin.append_genesis(&mut self.rollout, &run_start, None);
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
        if let Err(error) = appended {
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(error));
        }
        self.record_policy_bundle_genesis(None)?;
        self.record_genesis_policy_tail()
    }

    /// Production child-genesis path. A spawned child owns an independent transcript and record,
    /// while physical sequence one binds the exact parent run and inherited V1/V2 checkpoint.
    pub fn record_child_genesis_with_tunables(
        &mut self,
        parent_run: &RunId,
        cwd: String,
        created_at: u64,
        config_digest: String,
        agent_definition_tag: Option<String>,
    ) -> Result<(), KernelError> {
        let pin = self.tunables_pin_snapshot()?;
        let run_start = self.genesis_event(cwd, created_at, config_digest, agent_definition_tag)?;
        let fsync_started = Instant::now();
        let appended = pin.append_genesis(&mut self.rollout, &run_start, Some(parent_run));
        self.ledger
            .record_fsync_latency_us(elapsed_us(fsync_started));
        if let Err(error) = appended {
            self.record_failed = true;
            self.diagnostic_record_append_failed();
            return Err(KernelError::Record(error));
        }
        self.record_policy_bundle_genesis(Some(parent_run))?;
        self.record_genesis_policy_tail()
    }

    fn genesis_event(
        &mut self,
        cwd: String,
        created_at: u64,
        config_digest: String,
        agent_definition_tag: Option<String>,
    ) -> Result<Event, KernelError> {
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        self.reconcile_usd_budget_for_genesis();
        self.genesis_event_with_usd_ceiling(
            cwd,
            created_at,
            config_digest,
            agent_definition_tag,
            self.usd_budget
                .as_ref()
                .map(|budget| budget.ceiling_microusd()),
        )
    }

    fn genesis_event_with_usd_ceiling(
        &self,
        cwd: String,
        created_at: u64,
        config_digest: String,
        agent_definition_tag: Option<String>,
        usd_ceiling_microusd: Option<u64>,
    ) -> Result<Event, KernelError> {
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
        let environment =
            self.environment_context
                .as_ref()
                .map(|(text, trust)| DurableEnvironmentContext {
                    text: text.clone(),
                    trust: *trust,
                });
        self.validate_environment_identity(environment.as_ref())?;
        Ok(Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd,
                model: self.model.clone(),
                effort: self.effort,
                created_at,
                environment,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest,
                agent_definition_tag,
                max_usd: usd_ceiling_microusd.map(|value| value as f64 / 1_000_000.0),
            },
        })
    }

    fn record_genesis_policy_tail(&mut self) -> Result<(), KernelError> {
        for kind in self.genesis_policy_tail_events(RuntimePolicySource::Startup) {
            let persisted_usd = match &kind {
                EventKind::UsdCeilingChanged { max_microusd, .. } => Some(*max_microusd),
                _ => None,
            };
            let observed = kind.clone();
            let sequence = self.emit_durable_seq(TurnId(0), kind)?;
            self.observe_runtime_policy_commit(
                &observed,
                sequence,
                RuntimePolicyObservation::Genesis,
            );
            if let Some(max_microusd) = persisted_usd {
                self.usd_budget_persisted_microusd = Some(max_microusd);
            }
        }
        Ok(())
    }

    fn genesis_policy_tail_events(&self, source: RuntimePolicySource) -> Vec<EventKind> {
        self.genesis_policy_tail_events_with_usd_ceiling(
            source,
            self.usd_budget
                .as_ref()
                .map(|budget| budget.ceiling_microusd()),
        )
    }

    fn genesis_policy_tail_events_with_usd_ceiling(
        &self,
        source: RuntimePolicySource,
        usd_ceiling_microusd: Option<u64>,
    ) -> Vec<EventKind> {
        let mut events = Vec::with_capacity(4);
        events.push(EventKind::TurnCeilingChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            max_turns: self.budget.max_turns,
        });
        if let Some(max_microusd) = usd_ceiling_microusd {
            // `RunStart.max_usd` remains a compatibility projection only. Persist the exact
            // fixed-point authority before treating the ceiling as durable so a resume/fork can
            // never widen it through an f64 round trip.
            events.push(EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source,
                max_microusd,
            });
        }
        // PolicyChanged is deliberately last: its presence is the durable completeness seal used
        // by every V2 resume/adoption path.
        events.push(EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            effort: self.effort,
        });
        events.push(EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source,
            mode: self.permission_mode,
            rules: self.permission_rules.clone(),
        });
        events
    }

    fn prospective_genesis_usd_ceiling_microusd(&self) -> Option<u64> {
        let resident = self
            .usd_budget
            .as_ref()
            .map(|budget| budget.ceiling_microusd());
        let requested = self.budget.max_usd.map(usd_to_microusd_ceiling);
        match (resident, requested) {
            (None, None) => None,
            (Some(resident), None) => Some(resident),
            (None, Some(requested)) => Some(requested),
            (Some(resident), Some(requested)) => Some(resident.min(requested)),
        }
    }

    fn record_policy_bundle_genesis(
        &mut self,
        parent_run: Option<&RunId>,
    ) -> Result<(), KernelError> {
        let snapshot = self.compiled_policy_bundle.genesis_snapshot().clone();
        let inherited_from =
            parent_run.map(
                |parent| iteron_protocol::RunGenesisPolicyBundleInheritance {
                    parent_run: parent.0.clone(),
                    parent_receipt_digest_sha256: snapshot.receipt_digest_sha256.clone(),
                },
            );
        self.emit_durable(
            TurnId(0),
            EventKind::PolicyBundleSnapshot {
                version: iteron_protocol::RunGenesisPolicyBundleVersion::V1,
                snapshot,
                inherited_from,
            },
        )?;
        Ok(())
    }
}

fn require_same_adoption_families(
    resident: &iteron_record::TunablesCheckpoint,
    adopted: &iteron_record::TunablesCheckpoint,
    families: &[&str],
) -> Result<(), KernelError> {
    let (Some(resident), Some(adopted)) = (resident.as_v2(), adopted.as_v2()) else {
        if resident.effective_digest_sha256() == adopted.effective_digest_sha256() {
            return Ok(());
        }
        return Err(KernelError::ExecutionPolicy(
            "a legacy in-process adoption cannot replace process-scoped tunables; restart to resume that run"
                .into(),
        ));
    };
    for family in families {
        let resident = resident
            .entries
            .iter()
            .find(|entry| entry.family_id == *family);
        let adopted = adopted
            .entries
            .iter()
            .find(|entry| entry.family_id == *family);
        let same = match (resident, adopted) {
            (Some(resident), Some(adopted)) => {
                resident.state == adopted.state
                    && resident.effective_value == adopted.effective_value
            }
            (None, None) => true,
            _ => false,
        };
        if !same {
            return Err(KernelError::ExecutionPolicy(format!(
                "adopted process-scoped tunable `{family}` differs from the resident owner; restart to resume that run"
            )));
        }
    }
    Ok(())
}

fn validate_complete_runtime_genesis(events: &[Event]) -> Result<(), KernelError> {
    let checkpoint = iteron_record::tunables_checkpoint_from_events(events).map_err(|error| {
        KernelError::ContextResolution(format!(
            "V2 runtime genesis tunables checkpoint is invalid: {error}"
        ))
    })?;
    if !matches!(checkpoint, Some(iteron_record::TunablesCheckpoint::V2(_))) {
        return Ok(());
    }
    let Some(Event {
        kind:
            EventKind::RunStart {
                parent_run,
                max_usd,
                ..
            },
        ..
    }) = events.first()
    else {
        return Err(KernelError::ContextResolution(
            "V2 runtime genesis has no run_start".into(),
        ));
    };
    if !matches!(
        events.get(2).map(|event| &event.kind),
        Some(EventKind::PolicyBundleSnapshot { .. })
    ) {
        return Err(KernelError::ContextResolution(
            "V2 runtime genesis has no immutable policy-bundle checkpoint".into(),
        ));
    }

    let source = if parent_run.is_some() {
        RuntimePolicySource::Fork
    } else {
        RuntimePolicySource::Startup
    };
    let mut index = 3;
    if source == RuntimePolicySource::Fork {
        if max_usd.is_some() {
            require_runtime_genesis_event(
                events,
                index,
                |kind| matches!(kind, EventKind::UsdCeilingChanged { source: actual, .. } if *actual == source),
            )?;
            index += 1;
        }
        if matches!(
            events.get(index).map(|event| &event.kind),
            Some(EventKind::TurnCeilingChanged { source: actual, .. }) if *actual == source
        ) {
            index += 1;
        }
    } else {
        require_runtime_genesis_event(
            events,
            index,
            |kind| matches!(kind, EventKind::TurnCeilingChanged { source: actual, .. } if *actual == source),
        )?;
        index += 1;
        if max_usd.is_some() {
            require_runtime_genesis_event(
                events,
                index,
                |kind| matches!(kind, EventKind::UsdCeilingChanged { source: actual, .. } if *actual == source),
            )?;
            index += 1;
        }
    }
    require_runtime_genesis_event(
        events,
        index,
        |kind| matches!(kind, EventKind::EffortChanged { source: actual, .. } if *actual == source),
    )?;
    index += 1;
    require_runtime_genesis_event(
        events,
        index,
        |kind| matches!(kind, EventKind::PolicyChanged { source: actual, .. } if *actual == source),
    )?;
    Ok(())
}

fn require_runtime_genesis_event(
    events: &[Event],
    index: usize,
    matches_expected: impl FnOnce(&EventKind) -> bool,
) -> Result<(), KernelError> {
    let complete = events
        .get(index)
        .is_some_and(|event| event.turn == TurnId(0) && matches_expected(&event.kind));
    if complete {
        Ok(())
    } else {
        Err(KernelError::ContextResolution(
            "V2 runtime genesis policy tail is incomplete or out of order".into(),
        ))
    }
}
