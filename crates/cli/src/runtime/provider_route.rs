use super::*;

pub(super) struct ProviderDispatchAdmission {
    pub attempt_guard: ProviderAttemptGuard,
    pub primary_route_permit: Option<iteron_provider::AttemptPermit>,
    pub use_hedge: bool,
}

impl Agent {
    pub(super) fn provider_output_proof_required(&self) -> bool {
        self.usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
            || self.persistent_mailbox.is_some()
            || self.persistent_agents.is_some()
    }

    /// Unified provider-effect admission. Every model path, including operator compaction and
    /// orchestration helpers, must cross this check before a durable intent or transport call.
    pub(super) fn validate_provider_request_route(
        &self,
        request: &TurnRequest,
    ) -> Result<(), KernelError> {
        let capabilities = self.provider.control_capabilities();
        let controls = if self.plantcore_runtime_enabled() {
            request.controls
        } else {
            capabilities.adapt_optional_cache_breakpoint(request.controls)
        };
        capabilities.validate(&controls).map_err(|error| {
            KernelError::Provider(iteron_provider::ProviderError::Configuration(
                error.to_string(),
            ))
        })?;
        if let Some(selected) = &self.selected_route
            && (self.model != selected.route.model_id || request.model != selected.route.model_id)
        {
            return Err(KernelError::InvalidRoute(
                "request model changed without a durable model selection",
            ));
        }
        if self.selected_route.is_some()
            && self
                .selected_provider
                .as_ref()
                .is_none_or(|selected| !std::sync::Arc::ptr_eq(selected, &self.provider))
        {
            return Err(KernelError::InvalidRoute(
                "provider instance changed without a durable provider selection",
            ));
        }
        if let Some(selected) = &self.selected_route
            && self.pricing.is_some()
            && self.provider.provider_instance_id() != Some(selected.route.provider_id.as_str())
        {
            return Err(KernelError::InvalidRoute(
                "provider instance identity does not match the priced durable route",
            ));
        }
        Ok(())
    }

    pub(super) fn pricing_now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.pricing_now_unix_secs {
            return now;
        }
        unix_now_secs()
    }

    pub(super) fn provider_run_notice_key(&self, durable_proposal: &str) -> String {
        fn field(hasher: &mut Sha256, value: &str) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"iteron.provider-run-notice-key.v1");
        field(&mut hasher, &self.rollout.run_id().0);
        if let Some(selected) = &self.selected_route {
            field(&mut hasher, "durable-route");
            field(&mut hasher, &selected.route.provider_id);
            field(&mut hasher, &selected.route.model_id);
            field(&mut hasher, &selected.route.catalog_digest);
            field(&mut hasher, &selected.route.capability_digest);
        } else {
            field(&mut hasher, "unbound-route");
            field(
                &mut hasher,
                self.provider.provider_instance_id().unwrap_or(""),
            );
            field(&mut hasher, &self.model);
        }
        field(&mut hasher, durable_proposal);

        let digest = hasher.finalize();
        let mut key = String::with_capacity("sha256:".len() + digest.len() * 2 + 7);
        key.push_str("sha256:");
        for (index, byte) in digest.into_iter().enumerate() {
            use std::fmt::Write as _;
            if index > 0 && index % 4 == 0 {
                key.push('-');
            }
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    pub(super) fn admit_provider_effect(
        &mut self,
        turn: TurnId,
        request: &TurnRequest,
    ) -> Result<ProviderAttemptGuard, KernelError> {
        let started = Instant::now();
        let fsync_before = self.ledger.kernel_tax().record_fsync_latency_us;
        let result = self.admit_provider_effect_inner(turn, request);
        let fsync_delta = self
            .ledger
            .kernel_tax()
            .record_fsync_latency_us
            .saturating_sub(fsync_before);
        self.ledger
            .record_admission_latency_us(elapsed_us(started).saturating_sub(fsync_delta));
        result
    }

    /// Resolve every deterministic zero-dispatch gate before charging a logical attempt. The
    /// returned primary permit is held until the first physical request settles; descendants and
    /// siblings therefore observe the same session-owned governor state.
    pub(super) async fn admit_provider_dispatch(
        &mut self,
        turn: TurnId,
        request: &TurnRequest,
    ) -> Result<ProviderDispatchAdmission, KernelError> {
        if let Some(refusal) = self.provider_dispatch_refusal() {
            return Err(refusal);
        }
        let use_hedge = self.provider_hedging_for_turn(turn)?;
        let route_id = self.governed_route_id();
        let primary_route_permit = self.admit_governed_route_attempt(turn, &route_id).await?;
        if let Some(refusal) = self.provider_dispatch_refusal() {
            drop(primary_route_permit);
            return Err(refusal);
        }
        let attempt_guard = self.admit_provider_effect(turn, request)?;
        Ok(ProviderDispatchAdmission {
            attempt_guard,
            primary_route_permit,
            use_hedge,
        })
    }

    pub(super) fn admit_provider_effect_inner(
        &mut self,
        turn: TurnId,
        request: &TurnRequest,
    ) -> Result<ProviderAttemptGuard, KernelError> {
        let mut governed_request = request.clone();
        governed_request.controls = self.provider_controls_for(self.provider.as_ref());
        governed_request.cache_system = governed_request.controls.prompt_cache.breakpoint
            != iteron_provider::CacheBreakpoint::None;
        let request = &governed_request;
        // This is the single paid-inference choke point. Public fields may have changed since
        // construction, and operator compaction/decomposition can enter without `Agent::run`, so
        // revalidate and reconcile immediately before the durable intent.
        self.ensure_record_healthy()?;
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        self.synchronize_usd_budget()?;
        self.close_usd_budget_on_unknown_cost();
        if self
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
            && (self.pricing_port.is_none()
                || self.pricing.is_none()
                || matches!(self.ledger.cost_state(), CostState::Unknown { .. }))
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        let projected_at_unix_secs = self.pricing_now();
        if let Some(rate_card) = &self.pricing {
            if projected_at_unix_secs < rate_card.rate_card.issued_at_unix_secs {
                return Err(iteron_obs::PricingError::RateCardNotYetValid.into());
            }
            if projected_at_unix_secs >= rate_card.rate_card.expires_at_unix_secs {
                return Err(iteron_obs::PricingError::RateCardExpired.into());
            }
        }
        self.validate_provider_request_route(request)?;
        if self.provider.attempt_semantics() != ProviderAttemptSemantics::Single {
            return Err(KernelError::OpaqueProviderRetries);
        }
        if let Some(refusal) = self.provider_dispatch_refusal() {
            return Err(refusal);
        }
        if let Some(notice) = self.provider.run_notice(request) {
            let proposal = bounded_provider_notice(PROVIDER_RUN_NOTICE_LABEL, &notice);
            let key = self.provider_run_notice_key(&proposal);
            if !self.committed_provider_run_notices.contains(&key) {
                if self.committed_provider_run_notices.len()
                    >= iteron_tunables::param_integer(
                        "cli.runtime.max_committed_provider_run_notices",
                        MAX_COMMITTED_PROVIDER_RUN_NOTICES,
                    )
                {
                    return Err(KernelError::ProviderRunNoticeLimit);
                }
                // The provider only proposes this evidence. Commit the kernel-owned suppression
                // state after the append, never before it, so a fault can be retried safely by a
                // reused provider or reconstructed run. The key binds the physical run, exact
                // durable route, and bounded evidence bytes rather than trusting text equality.
                let text = bounded_provider_run_notice(&notice, &key);
                self.emit_durable(turn, EventKind::Notice { text: text.clone() })?;
                self.committed_provider_run_notices.insert(key);
                self.ui(UiEvent::Notice(text));
            }
        }
        if let Some(notice) = self.provider.preflight_notice(request) {
            // Request-level notices remain observable on later requests even after a run-level
            // notice has committed. Both cross the same fail-closed audit boundary.
            let text = bounded_provider_notice("provider notice", &notice);
            self.emit_durable(turn, EventKind::Notice { text: text.clone() })?;
            self.ui(UiEvent::Notice(text));
        }
        let reservation_microusd = self.provider_request_cost_reservation(request)?;
        let attempt_guard = ProviderAttemptGuard::new(
            self.usd_budget.as_ref(),
            projected_at_unix_secs,
            reservation_microusd,
        )
        .map_err(KernelError::PricingLedger)?;
        Ok(attempt_guard)
    }

    /// Open logical billing only after the first physical provider intent is durable.  This
    /// ordering makes an intent-append refusal provably zero-cost: there is neither a transport
    /// call nor an unmatched `TurnStart` that replay would have to classify as missing billing
    /// evidence.
    pub(super) fn begin_provider_attempt_after_intent(
        &mut self,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.emit_durable(turn, EventKind::TurnStart)?;
        self.ledger.attempt();
        Ok(())
    }

    /// Settle an already-durable provider intent when a later local gate fails before transport.
    pub(super) fn close_provider_intent_without_dispatch(
        &mut self,
        turn: TurnId,
        ordinal: usize,
        route_id: &str,
        physical_attempt: u32,
        ticket: effects::EffectTicket,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        let accounting =
            route_attempt_accounting::not_dispatched_accounting(route_id, physical_attempt)?;
        self.settle_kernel_effect(
            ticket,
            effects::Settlement::Definite(EventKind::EffectFailed {
                id: effect_class::effect_id(turn, effect_class::EffectClass::Provider, ordinal),
                tool: effect_class_label(effect_class::EffectClass::Provider).to_string(),
                reason: reason.into(),
                duration_ms: None,
                provider_route_attempt: Some(accounting),
            }),
        )
    }

    /// Would a dispatch be refused before the transport is even opened?
    ///
    /// Kept separate so [`Agent::brokered_provider_turn`] can run it *before* opening the effect.
    /// Both refusals — an exhausted wall deadline and an already
    /// pending interrupt — are proven non-events: `turn_cancellable` returns without opening the
    /// stream. Journalling them inside the boundary would manufacture an unknown effect out of a
    /// request that never left the process.
    pub(super) fn provider_dispatch_refusal(&self) -> Option<KernelError> {
        self.control.provider_refusal(self.run_deadline)
    }

    /// One paid inference request, across the effect boundary.
    ///
    /// A provider request is the most expensive externally visible thing the kernel does and the
    /// one whose outcome is least observable: the D1-16 contract drops the stream mid-flight on
    /// Ctrl-C, so the model may have been billed for a turn whose result nobody will ever see.
    /// Before #16 that left `TurnStart` with no counterpart and nothing for recovery to report.
    ///
    /// # How a provider error is classified
    ///
    /// * A dropped in-flight stream (`Interrupted`, `DeadlineExceeded`) and a broken or unreadable
    ///   response (`Http`, `Stream`, `Decode`) are **unknown**: the request may have reached the
    ///   endpoint and no authoritative outcome exists. Recovery reports them and never re-sends.
    /// * A structured answer from the endpoint (`Api`, `ApiResponse`, `Refusal`,
    ///   `UnknownStopReason`) is a **proven failure**: the turn is closed, just not successfully.
    ///
    /// The pre-flight refusal above removes the two cases that would otherwise be misfiled, so the
    /// only residual imprecision is a flag that flips between the pre-flight check and
    /// `turn_cancellable`'s own — which lands on the conservative side.
    pub(super) async fn brokered_provider_turn(
        &mut self,
        turn: TurnId,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
        mut primary_route_permit: Option<iteron_provider::AttemptPermit>,
        use_hedge: bool,
    ) -> Result<iteron_provider::TurnResult, KernelError> {
        let mut governed_request = request.clone();
        governed_request.controls = self.provider_controls_for(self.provider.as_ref());
        governed_request.cache_system = governed_request.controls.prompt_cache.breakpoint
            != iteron_provider::CacheBreakpoint::None;
        let physical = match super::provider_output_request::normalize(
            self.provider.as_ref(),
            governed_request,
            self.provider_output_proof_required(),
        ) {
            Ok(physical) => physical,
            Err(error) => {
                if let Some(budget) = &self.usd_budget {
                    budget.settle_not_dispatched();
                }
                return Err(error);
            }
        };
        let mut requested_max_tokens = physical.requested_max_tokens;
        let mut governed_request = physical.request;
        let class = effect_class::EffectClass::Provider;
        let mut retry_index = 0u32;
        let mut provider = self.provider.clone();
        let mut route_id = self.governed_route_id();
        let mut fallback_index = self
            .fallback_provider_routes
            .iter()
            .position(|route| route.id() == route_id)
            .map_or(0, |index| index.saturating_add(1));
        let mut transition_reason: Option<&'static str> = None;
        let mut jitter = iteron_sched::backoff::Jitter::new();
        let mut first_attempt = true;
        loop {
            if let Some(refusal) = self.provider_dispatch_refusal() {
                if let Some(budget) = &self.usd_budget {
                    budget.settle_not_dispatched();
                }
                return Err(refusal);
            }
            let mut semantic_output_observed = false;
            let mut observed_rate_limit = None;
            let mut guarded = |item: StreamItem| {
                semantic_output_observed |= stream_item_has_semantic_output(&item);
                if let StreamItem::RateLimit(snapshot) = &item {
                    observed_rate_limit = Some(*snapshot);
                }
                on_item(item);
            };
            let (result, monetary_followup_safe) = if use_hedge {
                let dispatch = self
                    .execute_hedged_provider_turn(
                        turn,
                        provider.clone(),
                        &route_id,
                        &governed_request,
                        self.run_deadline.unwrap_or_else(|| {
                            Instant::now()
                                .checked_add(Duration::from_secs(self.budget.max_wall_secs))
                                .unwrap_or_else(Instant::now)
                        }),
                        transition_reason,
                        retry_index,
                        first_attempt,
                        primary_route_permit.take(),
                    )
                    .await?;
                let monetary_followup_safe = dispatch.monetary_followup_safe;
                for item in dispatch.items {
                    guarded(item);
                }
                (dispatch.result, monetary_followup_safe)
            } else {
                let route_permit = if first_attempt {
                    primary_route_permit.take()
                } else {
                    self.admit_governed_route_attempt(turn, &route_id).await?
                };
                let dispatch_permit = match self.enter_plantcore_external_dispatch().await {
                    Ok(permit) => permit,
                    Err(()) => {
                        drop(route_permit);
                        if let Some(budget) = &self.usd_budget {
                            budget.settle_not_dispatched();
                        }
                        return Err(iteron_provider::ProviderError::Interrupted.into());
                    }
                };
                if let Some(refusal) = self.provider_dispatch_refusal() {
                    drop(dispatch_permit);
                    drop(route_permit);
                    if let Some(budget) = &self.usd_budget {
                        budget.settle_not_dispatched();
                    }
                    return Err(refusal);
                }
                if !first_attempt {
                    self.reserve_provider_followup_if_needed(&governed_request)?;
                }
                let (ordinal, physical_attempt) = match self.next_provider_effect_identity(turn) {
                    Ok(identity) => identity,
                    Err(error) => {
                        drop(dispatch_permit);
                        drop(route_permit);
                        if let Some(budget) = &self.usd_budget {
                            budget.settle_not_dispatched();
                        }
                        return Err(error);
                    }
                };
                let (objective_score, objective_evidence) = self.objective_rank_evidence(&route_id);
                let broker_started = Instant::now();
                let ticket = match self.open_kernel_effect(
                    turn,
                    class,
                    ordinal,
                    Capability::IrreversibleExternal,
                    serde_json::json!({
                        "model": governed_request.model,
                        "route_id": route_id,
                        "route_transition": transition_reason,
                        "messages": governed_request.messages.len(),
                        "tools": governed_request.tools.len(),
                        "max_tokens": governed_request.max_tokens,
                        "requested_max_tokens": requested_max_tokens,
                        "physical_attempt": physical_attempt,
                        "route_retry_index": retry_index,
                        "route_objective_score_millionths": objective_score,
                        "route_objective_evidence": objective_evidence,
                    }),
                ) {
                    Ok(ticket) => ticket,
                    Err(error) => {
                        // The provider transport cannot exist until the intent append succeeds.
                        // Close the monetary reservation as a proved zero-dispatch outcome before
                        // the outer logical-attempt guard is dropped; otherwise its fail-safe Drop
                        // path would incorrectly poison the session as an unknown billed request.
                        drop(route_permit);
                        if let Some(budget) = &self.usd_budget {
                            budget.settle_not_dispatched();
                        }
                        return Err(error);
                    }
                };
                self.ledger
                    .record_broker_latency_us(elapsed_us(broker_started));
                if first_attempt && let Err(error) = self.begin_provider_attempt_after_intent(turn)
                {
                    let settlement = self.close_provider_intent_without_dispatch(
                        turn,
                        ordinal,
                        &route_id,
                        physical_attempt,
                        ticket,
                        "logical provider turn could not become durable before dispatch",
                    );
                    drop(route_permit);
                    if let Some(budget) = &self.usd_budget {
                        budget.settle_not_dispatched();
                    }
                    settlement?;
                    return Err(error);
                }
                if let Some(mailbox) = &self.persistent_mailbox
                    && let Err(error) = mailbox.confirm_request(&governed_request.messages)
                {
                    let settlement = self.close_provider_intent_without_dispatch(
                        turn,
                        ordinal,
                        &route_id,
                        physical_attempt,
                        ticket,
                        "durable mailbox inclusion failed before internal provider dispatch",
                    );
                    drop(route_permit);
                    drop(dispatch_permit);
                    if let Some(budget) = &self.usd_budget {
                        budget.settle_not_dispatched();
                    }
                    settlement?;
                    return Err(KernelError::AgentControl(error));
                }
                let request_observer = self
                    .request_manifest_factory()
                    .for_ticket(&ticket, governed_request.max_tokens);
                let result = execute_admitted_provider_turn_observed(
                    provider.clone(),
                    self.run_deadline.unwrap_or_else(|| {
                        Instant::now()
                            .checked_add(Duration::from_secs(self.budget.max_wall_secs))
                            .unwrap_or_else(Instant::now)
                    }),
                    ProviderCancellation {
                        interrupt: self.control.interrupt().cloned(),
                        force_cancel: self.control.force_cancel().clone(),
                        drain: self.control.drain().clone(),
                        attempt: None,
                        allow_in_flight_past_deadline: self.plantcore_runtime_enabled(),
                    },
                    &governed_request,
                    &mut guarded,
                    Some(request_observer.as_ref()),
                )
                .await;
                let accounting = self.route_attempt_accounting(
                    turn,
                    &route_id,
                    physical_attempt,
                    &result,
                    self.pricing_now(),
                )?;
                let monetary_followup_safe =
                    route_attempt_accounting::monetary_followup_safe(&accounting);
                let broker_started = Instant::now();
                self.settle_kernel_effect(
                    ticket,
                    provider_settlement(turn, ordinal, &result, accounting.clone()),
                )?;
                self.observe_plantcore_provider_attempt(turn, &accounting)
                    .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
                self.commit_provider_route_charge(turn, &accounting)?;
                self.ledger
                    .record_broker_latency_us(elapsed_us(broker_started));
                self.observe_governed_route_attempt(turn, &route_id, &result, observed_rate_limit)?;
                drop(route_permit);
                drop(dispatch_permit);
                (result, monetary_followup_safe)
            };
            first_attempt = false;
            transition_reason = None;

            if let Some(error) =
                retryable_before_semantic_output_provider_error(&result, semantic_output_observed)
                && retry_index.saturating_add(1) < self.retry_policy.max_attempts
            {
                self.admit_followup_after_route_attempt_set(monetary_followup_safe)?;
                let random = jitter.next01();
                let jitter_delay =
                    iteron_sched::full_jitter(&self.retry_policy, retry_index, random);
                let interactive_retry_ceiling = iteron_provider::max_interactive_retry_after();
                if let Some(hint) = error.retry_after()
                    && hint > interactive_retry_ceiling
                {
                    self.lifecycle_event(
                        "model.retry_cancelled",
                        Some(turn),
                        LifecyclePayload {
                            duration_us: Some(u64::try_from(hint.as_micros()).unwrap_or(u64::MAX)),
                            reason_code: Some("retry_after_exceeds_interactive_ceiling".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    return Err(iteron_provider::ProviderError::RetryAfterTooLong {
                        retry_after_ms: u64::try_from(hint.as_millis()).unwrap_or(u64::MAX),
                        limit_ms: u64::try_from(interactive_retry_ceiling.as_millis())
                            .unwrap_or(u64::MAX),
                    }
                    .into());
                }
                let delay = error
                    .retry_after()
                    .map(|hint| hint.max(jitter_delay))
                    .unwrap_or(jitter_delay);
                self.lifecycle_event(
                    "model.retry_scheduled",
                    Some(turn),
                    LifecyclePayload {
                        count: Some(u64::from(retry_index.saturating_add(1))),
                        duration_us: Some(u64::try_from(delay.as_micros()).unwrap_or(u64::MAX)),
                        reason_code: Some("typed_transient_pre_stream_failure".into()),
                        ..LifecyclePayload::default()
                    },
                );
                self.activity.retry(
                    turn,
                    retry_index.saturating_add(1),
                    self.retry_policy.max_attempts,
                    delay,
                );
                let wait_started = Instant::now();
                if let Err(cancelled) = self.wait_provider_retry(delay).await {
                    self.lifecycle_event(
                        "model.retry_cancelled",
                        Some(turn),
                        LifecyclePayload {
                            count: Some(u64::from(retry_index.saturating_add(1))),
                            duration_us: Some(elapsed_us(wait_started)),
                            reason_code: Some("run_cancelled_during_backoff".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    return Err(cancelled);
                }
                self.ledger.record_provider_retries(
                    1,
                    u64::try_from(delay.as_millis().max(1)).unwrap_or(u64::MAX),
                );
                retry_index = retry_index.saturating_add(1);
                continue;
            }

            let Some(error) = result.as_ref().err() else {
                return result;
            };
            let Some(failover_class) = self.admitted_failover(error, semantic_output_observed)
            else {
                return result;
            };
            let Some(index) = super::provider_governor_state::next_admitted_fallback_index(
                &self.fallback_provider_routes,
                fallback_index,
                &governed_request,
            ) else {
                self.record_model_router_abstention(
                    Some(turn),
                    failover_class.label(),
                    "fallback_chain_exhausted",
                )?;
                return result;
            };
            if !monetary_followup_safe {
                self.mark_usd_unknown();
                return Err(KernelError::UnpricedUsdCeiling);
            }
            if self.usd_budget_exhausted() {
                return Err(KernelError::InferenceBudgetExhausted("max_usd"));
            }
            fallback_index = index.saturating_add(1);
            let failover_activity = self
                .activity
                .span(super::turn_activity::ActivityStage::Failover, Some(turn));
            let candidate = &self.fallback_provider_routes[index];
            let mut candidate_request = governed_request.clone();
            candidate_request.model = candidate.route.model_id.clone();
            candidate_request.max_tokens = requested_max_tokens;
            let physical = super::provider_output_request::normalize(
                candidate.provider.as_ref(),
                candidate_request,
                self.provider_output_proof_required(),
            )?;
            let next = self.activate_fallback_provider_route(turn, index, failover_class)?;
            requested_max_tokens = physical.requested_max_tokens;
            governed_request = physical.request;
            failover_activity.complete();
            provider = next.provider.clone();
            route_id = next.id();
            governed_request.model = next.route.model_id;
            governed_request.controls = self.provider_controls_for(provider.as_ref());
            governed_request.cache_system = governed_request.controls.prompt_cache.breakpoint
                != iteron_provider::CacheBreakpoint::None;
            self.admit_followup_after_route_attempt_set(true)?;
            retry_index = 0;
            jitter = iteron_sched::backoff::Jitter::new();
            transition_reason = Some(failover_class.label());
        }
    }

    pub(super) async fn wait_provider_retry(&self, delay: Duration) -> Result<(), KernelError> {
        self.control
            .wait_retry(
                delay,
                self.run_deadline,
                iteron_tunables::param_duration(
                    "cli.runtime.provider_interrupt_poll_interval",
                    PROVIDER_INTERRUPT_POLL_INTERVAL,
                ),
            )
            .await
    }
}

// Existing ordinary/auxiliary/hedge call sites enter the same physical transport owner.
pub(super) use super::provider_transport_attempt::{
    ProviderCancellation, execute_admitted_provider_turn_observed,
};

/// Classify one paid physical attempt after it crosses the effect boundary.
pub(super) fn provider_settlement(
    turn: TurnId,
    ordinal: usize,
    result: &Result<iteron_provider::TurnResult, KernelError>,
    accounting: iteron_protocol::ProviderRouteAttemptAccounting,
) -> effects::Settlement {
    let class = effect_class::EffectClass::Provider;
    let id = effect_class::effect_id(turn, class, ordinal);
    let tool = effect_class_label(class).to_string();
    match result {
        Ok(_) => effects::Settlement::Definite(EventKind::EffectDone {
            id,
            tool,
            duration_ms: None,
            provider_route_attempt: Some(accounting),
        }),
        Err(KernelError::Provider(error)) if provider_outcome_is_unobservable(error) => {
            effects::Settlement::Definite(EventKind::EffectUnknown {
                id,
                tool,
                reason: format!(
                    "provider request was dispatched and produced no authoritative outcome ({}); \
                     billing remains unknown and continuation requires separate budget admission",
                    error.public_summary()
                ),
                provider_route_attempt: Some(accounting),
            })
        }
        Err(error) => effects::Settlement::Definite(EventKind::EffectFailed {
            id,
            tool,
            reason: strict_utf8_head(&error.public_summary(), EFFECT_REASON_MAX_BYTES),
            duration_ms: None,
            provider_route_attempt: Some(accounting),
        }),
    }
}

pub(super) fn provider_outcome_is_unobservable(error: &iteron_provider::ProviderError) -> bool {
    matches!(
        error,
        iteron_provider::ProviderError::Interrupted
            | iteron_provider::ProviderError::DeadlineExceeded
            | iteron_provider::ProviderError::Timeout { .. }
            | iteron_provider::ProviderError::Http(_)
            | iteron_provider::ProviderError::Stream(_)
            | iteron_provider::ProviderError::Decode(_)
    )
}

pub(super) fn provider_failure_stage(error: &KernelError) -> &'static str {
    match error {
        KernelError::Provider(iteron_provider::ProviderError::Timeout { stage }) => match stage {
            iteron_provider::ProviderTimeoutStage::DnsConnect => "timeout_dns_or_connect",
            iteron_provider::ProviderTimeoutStage::ResponseHeaders => "timeout_headers",
            iteron_provider::ProviderTimeoutStage::StreamIdle => "timeout_stream_idle",
            iteron_provider::ProviderTimeoutStage::RequestTotal => "timeout_request_total",
            iteron_provider::ProviderTimeoutStage::ErrorBody => "timeout_error_body",
        },
        KernelError::Provider(iteron_provider::ProviderError::DeadlineExceeded) => {
            "timeout_run_deadline"
        }
        KernelError::Provider(iteron_provider::ProviderError::Interrupted) => "interrupted",
        KernelError::Provider(iteron_provider::ProviderError::ConnectFailed) => {
            "connect_failed_pre_acceptance"
        }
        KernelError::Provider(iteron_provider::ProviderError::Decode(_)) => "decode",
        KernelError::Provider(iteron_provider::ProviderError::Stream(_)) => "stream",
        KernelError::Provider(iteron_provider::ProviderError::Http(_)) => "transport",
        _ => "provider_error",
    }
}

pub(super) fn stream_item_has_semantic_output(item: &StreamItem) -> bool {
    matches!(
        item,
        StreamItem::TextDelta(_) | StreamItem::ToolUseComplete(_)
    )
}

pub(super) fn retryable_before_semantic_output_provider_error(
    result: &Result<iteron_provider::TurnResult, KernelError>,
    semantic_output_observed: bool,
) -> Option<&iteron_provider::ProviderError> {
    if semantic_output_observed {
        return None;
    }
    let Err(KernelError::Provider(error)) = result else {
        return None;
    };
    let proven_terminal = matches!(
        error,
        iteron_provider::ProviderError::ConnectFailed
            | iteron_provider::ProviderError::Api { .. }
            | iteron_provider::ProviderError::ApiResponse(_)
    );
    (proven_terminal && error.retry_disposition() == iteron_provider::RetryDisposition::Transient)
        .then_some(error)
}

/// A dropped response may be continued from committed conversation/tool results. This is a
/// new, separately accounted request, never proof that the failed request was free.
pub(super) fn recoverable_response_stream_error(error: &KernelError) -> bool {
    use iteron_provider::{ProviderError, ProviderTimeoutStage, RetryDisposition};
    if let KernelError::Provider(error) = error
        && error
            .retry_after()
            .is_some_and(|delay| delay > iteron_provider::MAX_INTERACTIVE_RETRY_AFTER)
    {
        return false;
    }
    match error {
        KernelError::Provider(ProviderError::Http(_)) => true,
        KernelError::Provider(ProviderError::Timeout { stage }) => matches!(
            stage,
            ProviderTimeoutStage::ResponseHeaders
                | ProviderTimeoutStage::StreamIdle
                | ProviderTimeoutStage::RequestTotal
        ),
        KernelError::Provider(
            error @ (ProviderError::Stream(_)
            | ProviderError::Api { .. }
            | ProviderError::ApiResponse(_)),
        ) => error.retry_disposition() == RetryDisposition::Transient,
        _ => false,
    }
}
