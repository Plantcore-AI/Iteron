use super::*;

impl Agent {
    /// Unified provider-effect admission. Every model path, including operator compaction and
    /// orchestration helpers, must cross this check before a durable intent or transport call.
    pub(super) fn validate_provider_request_route(
        &self,
        request: &TurnRequest,
    ) -> Result<(), KernelError> {
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
        hasher.update(b"core.provider-run-notice-key.v1");
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

    pub(super) fn admit_provider_effect_inner(
        &mut self,
        turn: TurnId,
        request: &TurnRequest,
    ) -> Result<ProviderAttemptGuard, KernelError> {
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
        if let Some(notice) = self.provider.run_notice(request) {
            let proposal = bounded_provider_notice(PROVIDER_RUN_NOTICE_LABEL, &notice);
            let key = self.provider_run_notice_key(&proposal);
            if !self.committed_provider_run_notices.contains(&key) {
                if self.committed_provider_run_notices.len() >= MAX_COMMITTED_PROVIDER_RUN_NOTICES {
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
        self.emit_durable(turn, EventKind::TurnStart)?;
        self.ledger.attempt();
        Ok(ProviderAttemptGuard::new(
            self.usd_budget.as_ref(),
            projected_at_unix_secs,
        ))
    }

    /// Would a dispatch be refused before the transport is even opened?
    ///
    /// Pulled out of [`Agent::bounded_provider_turn`] so [`Agent::brokered_provider_turn`] can run
    /// it *before* opening the effect. Both refusals — an exhausted wall deadline and an already
    /// pending interrupt — are proven non-events: `turn_cancellable` returns without opening the
    /// stream. Journalling them inside the boundary would manufacture an unknown effect out of a
    /// request that never left the process.
    pub(super) fn provider_dispatch_refusal(&self) -> Option<KernelError> {
        let deadline = self.run_deadline?;
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Some(KernelError::Provider(
                iteron_provider::ProviderError::DeadlineExceeded,
            ));
        }
        let interrupted = self.drain.load(std::sync::atomic::Ordering::Relaxed)
            || self
                .interrupt
                .as_ref()
                .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
        interrupted.then_some(KernelError::Provider(
            iteron_provider::ProviderError::Interrupted,
        ))
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
    ///   response (`Stream`, `Decode`) are **unknown**: the request reached the endpoint and no
    ///   authoritative outcome exists. Recovery reports them and never re-sends.
    /// * A structured answer from the endpoint (`Http`, `Api`, `ApiResponse`, `Refusal`,
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
    ) -> Result<iteron_provider::TurnResult, KernelError> {
        if let Some(refusal) = self.provider_dispatch_refusal() {
            return Err(refusal);
        }
        let class = effect_class::EffectClass::Provider;
        let ordinal = self.next_effect_ordinal(turn, class);
        let broker_started = Instant::now();
        let ticket = self.open_kernel_effect(
            turn,
            class,
            ordinal,
            Capability::IrreversibleExternal,
            serde_json::json!({
                "model": request.model,
                "messages": request.messages.len(),
                "tools": request.tools.len(),
                "max_tokens": request.max_tokens,
            }),
        )?;
        self.ledger
            .record_broker_latency_us(elapsed_us(broker_started));
        let result = self.bounded_provider_turn(request, on_item).await;
        let broker_started = Instant::now();
        self.settle_kernel_effect(ticket, provider_settlement(turn, ordinal, &result))?;
        self.ledger
            .record_broker_latency_us(elapsed_us(broker_started));
        result
    }

    pub(super) async fn bounded_provider_turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<iteron_provider::TurnResult, KernelError> {
        // Defense in depth for future callers that fail to use `admit_provider_effect`.
        self.validate_provider_request_route(request)?;
        if self.provider.attempt_semantics() != ProviderAttemptSemantics::Single {
            return Err(KernelError::OpaqueProviderRetries);
        }
        let deadline = self.run_deadline.unwrap_or_else(|| {
            Instant::now()
                .checked_add(Duration::from_secs(self.budget.max_wall_secs))
                .unwrap_or_else(Instant::now)
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(iteron_provider::ProviderError::DeadlineExceeded.into());
        }
        // A cooperative interrupt (Ctrl-C) must be able to abort a stream that is already in
        // flight, not just at the between-turn safe points. Race the turn against the interrupt
        // flag: when it flips true mid-stream, `turn_cancellable` drops the provider future —
        // closing the transport — and returns `Interrupted`, which the turn loop converts into an
        // `Outcome::Interrupted` at the next boundary. When no interrupt is installed this is a
        // plain awaited turn. The run wall-clock deadline still bounds the whole race.
        let mut cancels = vec![self.drain.as_ref()];
        if let Some(interrupt) = self.interrupt.as_deref() {
            cancels.push(interrupt);
        }
        let turn = iteron_provider::turn_cancellable_any(
            self.provider.as_ref(),
            request,
            on_item,
            &cancels,
            PROVIDER_INTERRUPT_POLL_INTERVAL,
        );
        tokio::time::timeout(remaining, turn)
            .await
            .map_err(|_| KernelError::Provider(iteron_provider::ProviderError::DeadlineExceeded))?
            .map_err(KernelError::Provider)
    }
}
