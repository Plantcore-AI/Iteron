//! Bounded duplicate-safe provider hedging with one durable effect ticket per scheduled attempt.
//!
//! A winner cancels every duplicate: delayed siblings are suppressed before dispatch and
//! in-flight siblings have their transport future dropped. An in-flight cancellation is settled
//! as an unknown external effect and makes aggregate usage incomplete; it is never misreported as
//! a proven-unbilled request.

use super::*;
use futures_util::stream::{FuturesUnordered, StreamExt};
use iteron_provider::{AttemptPermit, ProviderAdmission as Admission};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_BUFFERED_HEDGE_ITEMS: usize = 131_072;

pub(super) struct HedgedProviderDispatch {
    pub result: Result<iteron_provider::TurnResult, KernelError>,
    pub items: Vec<StreamItem>,
    pub scheduled_attempts: u32,
    /// True only when every scheduled attempt has known cost or proved it never dispatched.
    pub monetary_followup_safe: bool,
}

struct PreparedAttempt {
    index: u8,
    ordinal: usize,
    physical_attempt: u32,
    delay: Duration,
    provider: Arc<dyn Provider>,
    request: TurnRequest,
    deadline: Instant,
    interrupt: Option<Arc<AtomicBool>>,
    drain: Arc<AtomicBool>,
    attempt_cancel: Arc<AtomicBool>,
    ticket: effects::EffectTicket,
    permit: Option<AttemptPermit>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "one terminal outcome exists per attempt and is consumed immediately; boxing it would move the ticket and permit behind a pointer for no lifetime benefit"
)]
enum AttemptTerminal {
    Suppressed {
        index: u8,
        ordinal: usize,
        physical_attempt: u32,
        ticket: effects::EffectTicket,
        permit: Option<AttemptPermit>,
    },
    Completed {
        index: u8,
        ordinal: usize,
        physical_attempt: u32,
        ticket: effects::EffectTicket,
        permit: Option<AttemptPermit>,
        items: Vec<StreamItem>,
        rate_limit: Option<iteron_provider::RateLimitSnapshot>,
        result: Result<iteron_provider::TurnResult, KernelError>,
    },
}

type AttemptFuture = Pin<Box<dyn Future<Output = AttemptTerminal> + Send>>;

impl Agent {
    pub(super) fn provider_hedging_enabled(&self) -> bool {
        self.provider_governor
            .as_ref()
            .is_some_and(|governor| governor.policy().hedge.enabled)
    }

    pub(super) fn provider_hedging_for_turn(&mut self, turn: TurnId) -> Result<bool, KernelError> {
        if !self.provider_hedging_enabled() {
            return Ok(false);
        }
        if self
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
        {
            self.emit_durable(
                turn,
                EventKind::ProviderGovernorDecision {
                    decision: iteron_protocol::ProviderGovernorDecision::HedgeSuppressed {
                        version: iteron_protocol::ProviderGovernorDecisionVersion::V1,
                        reason: iteron_protocol::ProviderHedgeSuppressionReason::PositiveUsdCeiling,
                    },
                },
            )?;
            return Ok(false);
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_hedged_provider_turn(
        &mut self,
        turn: TurnId,
        provider: Arc<dyn Provider>,
        route_id: &str,
        request: &TurnRequest,
        deadline: Instant,
        route_transition: Option<&str>,
        route_retry_index: u32,
        physical_attempt_base: u32,
        primary_admission_preacquired: bool,
        mut primary_permit: Option<AttemptPermit>,
    ) -> Result<HedgedProviderDispatch, KernelError> {
        if self
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
        {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor.hedge",
                reason: "physical hedging is unavailable under a positive USD ceiling",
            });
        }
        let hedge = self
            .provider_governor
            .as_ref()
            .map(|governor| governor.policy().hedge)
            .filter(|policy| policy.enabled)
            .ok_or(KernelError::InvalidRouteMetadata {
                field: "provider_governor.hedge",
                reason: "hedged dispatch requires an enabled immutable hedge policy",
            })?;
        if !request.controls.idempotent
            || !provider.control_capabilities().idempotent_requests
            || provider.attempt_semantics() != ProviderAttemptSemantics::Single
        {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_governor.hedge",
                reason: "the active request and adapter are not duplicate-safe single attempts",
            });
        }
        if let Some(refusal) = self.provider_dispatch_refusal() {
            return Ok(HedgedProviderDispatch {
                result: Err(refusal),
                items: Vec::new(),
                scheduled_attempts: 0,
                monetary_followup_safe: true,
            });
        }

        let total = hedge.max_duplicates.saturating_add(1);
        let mut prepared = Vec::with_capacity(usize::from(total));
        let mut cancellation = Vec::with_capacity(usize::from(total));
        for index in 0..total {
            let permit = if index == 0 && primary_admission_preacquired {
                primary_permit.take()
            } else if index == 0 {
                match self.admit_governed_route_attempt(turn, route_id).await {
                    Ok(permit) => permit,
                    Err(error) => {
                        self.close_prepared_hedges_without_dispatch(
                            turn,
                            route_id,
                            prepared,
                            "hedge admission failed before provider dispatch",
                        )?;
                        return Err(error);
                    }
                }
            } else {
                let admitted = match self.try_admit_optional_hedge(turn, route_id) {
                    Ok(admitted) => admitted,
                    Err(error) => {
                        self.close_prepared_hedges_without_dispatch(
                            turn,
                            route_id,
                            prepared,
                            "hedge admission failed before provider dispatch",
                        )?;
                        return Err(error);
                    }
                };
                let Some(permit) = admitted else {
                    continue;
                };
                Some(permit)
            };
            let attempt_cancel = Arc::new(AtomicBool::new(false));
            let ordinal = self.next_effect_ordinal(turn, effect_class::EffectClass::Provider);
            let physical_attempt = physical_attempt_base
                .saturating_add(u32::try_from(prepared.len()).unwrap_or(u32::MAX))
                .saturating_add(1);
            let delay = hedge
                .delay
                .checked_mul(u32::from(index))
                .unwrap_or(Duration::MAX);
            let (objective_score, objective_evidence) = self.objective_rank_evidence(route_id);
            let ticket = match self.open_kernel_effect(
                turn,
                effect_class::EffectClass::Provider,
                ordinal,
                Capability::IrreversibleExternal,
                serde_json::json!({
                    "model": request.model,
                    "route_id": route_id,
                    "route_transition": route_transition,
                    "messages": request.messages.len(),
                    "tools": request.tools.len(),
                    "max_tokens": request.max_tokens,
                    "physical_attempt": physical_attempt,
                    "route_retry_index": route_retry_index,
                    "hedge_attempt": index,
                    "hedge_delay_ms": u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "route_objective_score_millionths": objective_score,
                    "route_objective_evidence": objective_evidence,
                }),
            ) {
                Ok(ticket) => ticket,
                Err(error) => {
                    drop(permit);
                    self.close_prepared_hedges_without_dispatch(
                        turn,
                        route_id,
                        prepared,
                        "hedge intent preparation failed before provider dispatch",
                    )?;
                    return Err(error);
                }
            };
            cancellation.push((index, attempt_cancel.clone()));
            prepared.push(PreparedAttempt {
                index,
                ordinal,
                physical_attempt,
                delay,
                provider: provider.clone(),
                request: request.clone(),
                deadline,
                interrupt: self.interrupt.clone(),
                drain: self.drain.clone(),
                attempt_cancel,
                ticket,
                permit,
            });
        }

        let scheduled_attempts = u32::try_from(prepared.len()).unwrap_or(u32::MAX);
        if primary_admission_preacquired
            && let Err(error) = self.begin_provider_attempt_after_intent(turn)
        {
            let closed = self.close_prepared_hedges_without_dispatch(
                turn,
                route_id,
                prepared,
                "logical provider turn could not become durable before dispatch",
            );
            if let Some(budget) = &self.usd_budget {
                budget.settle_not_dispatched();
            }
            closed?;
            return Err(error);
        }
        let mut attempts = prepared
            .into_iter()
            .map(|attempt| Box::pin(run_attempt(attempt)) as AttemptFuture)
            .collect::<FuturesUnordered<_>>();
        let mut winner: Option<(u8, iteron_provider::TurnResult, Vec<StreamItem>)> = None;
        let mut errors = BTreeMap::new();
        let mut aggregate = UsageAggregate::default();
        let mut monetary_followup_safe = true;

        while let Some(terminal) = attempts.next().await {
            match terminal {
                AttemptTerminal::Suppressed {
                    index,
                    ordinal,
                    physical_attempt,
                    ticket,
                    permit,
                } => {
                    let accounting = route_attempt_accounting::not_dispatched_accounting(
                        route_id,
                        physical_attempt,
                    )?;
                    self.settle_kernel_effect(
                        ticket,
                        effects::Settlement::Definite(EventKind::EffectFailed {
                            id: effect_class::effect_id(
                                turn,
                                effect_class::EffectClass::Provider,
                                ordinal,
                            ),
                            tool: effect_class_label(effect_class::EffectClass::Provider)
                                .to_string(),
                            reason: "hedge duplicate was cancelled before provider dispatch".into(),
                            duration_ms: None,
                            provider_route_attempt: Some(accounting),
                        }),
                    )?;
                    drop(permit);
                    let _ = index;
                }
                AttemptTerminal::Completed {
                    index,
                    ordinal,
                    physical_attempt,
                    ticket,
                    permit,
                    items,
                    rate_limit,
                    result,
                } => {
                    let accounting = self.route_attempt_accounting(
                        turn,
                        route_id,
                        physical_attempt,
                        &result,
                        self.pricing_now(),
                    )?;
                    monetary_followup_safe &=
                        route_attempt_accounting::monetary_followup_safe(&accounting);
                    self.settle_kernel_effect(
                        ticket,
                        provider_route::provider_settlement(
                            turn,
                            ordinal,
                            &result,
                            accounting.clone(),
                        ),
                    )?;
                    self.commit_provider_route_charge(turn, &accounting)?;
                    self.observe_governed_route_attempt(turn, route_id, &result, rate_limit)?;
                    drop(permit);
                    match result {
                        Ok(result) => {
                            aggregate.observe_success(result.usage);
                            if winner.is_none() {
                                for (other, cancel) in &cancellation {
                                    if *other != index {
                                        cancel.store(true, Ordering::Release);
                                    }
                                }
                                winner = Some((index, result, items));
                            }
                        }
                        Err(error) => {
                            aggregate.observe_dispatched_without_usage();
                            errors.insert(index, (error, items));
                        }
                    }
                }
            }
        }

        let (result, items) = if let Some((_index, mut result, items)) = winner {
            result.usage = aggregate.report();
            (Ok(result), items)
        } else if let Some((_index, (error, items))) = errors.pop_first() {
            (Err(error), items)
        } else {
            (
                Err(KernelError::Provider(
                    iteron_provider::ProviderError::Configuration(
                        "hedge dispatcher produced no terminal".into(),
                    ),
                )),
                Vec::new(),
            )
        };
        Ok(HedgedProviderDispatch {
            result,
            items,
            scheduled_attempts,
            monetary_followup_safe,
        })
    }

    /// Close every intent prepared for a hedge batch when a later admission or intent append
    /// fails before the futures are constructed. None of these attempts can have reached a
    /// provider, so each terminal carries exact `NotDispatched` cost truth instead of relying on
    /// ticket Drop/crash reconciliation to conservatively manufacture an unknown external effect.
    fn close_prepared_hedges_without_dispatch(
        &mut self,
        turn: TurnId,
        route_id: &str,
        prepared: Vec<PreparedAttempt>,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        for attempt in prepared {
            let accounting = route_attempt_accounting::not_dispatched_accounting(
                route_id,
                attempt.physical_attempt,
            )?;
            self.settle_kernel_effect(
                attempt.ticket,
                effects::Settlement::Definite(EventKind::EffectFailed {
                    id: effect_class::effect_id(
                        turn,
                        effect_class::EffectClass::Provider,
                        attempt.ordinal,
                    ),
                    tool: effect_class_label(effect_class::EffectClass::Provider).to_string(),
                    reason: reason.into(),
                    duration_ms: None,
                    provider_route_attempt: Some(accounting),
                }),
            )?;
            drop(attempt.permit);
        }
        Ok(())
    }

    fn try_admit_optional_hedge(
        &mut self,
        turn: TurnId,
        route_id: &str,
    ) -> Result<Option<AttemptPermit>, KernelError> {
        let Some(governor) = self.provider_governor.as_ref() else {
            return Ok(None);
        };
        match governor.admit(route_id, Instant::now()) {
            Admission::Admitted(permit) => {
                self.emit_circuit_transition(turn, permit.transition);
                self.record_provider_governor_state(turn, route_id, permit.transition, None)?;
                Ok(Some(permit))
            }
            Admission::Deferred { wait, reason } => {
                self.lifecycle_event(
                    "model.route_rejected",
                    Some(turn),
                    LifecyclePayload {
                        duration_us: Some(u64::try_from(wait.as_micros()).unwrap_or(u64::MAX)),
                        reason_code: Some(format!(
                            "hedge_deferred:{}",
                            super::provider_governor_state::admission_reason(reason)
                        )),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(None)
            }
            Admission::Rejected(reason) => {
                self.lifecycle_event(
                    "model.route_rejected",
                    Some(turn),
                    LifecyclePayload {
                        reason_code: Some(format!(
                            "hedge_suppressed:{}",
                            super::provider_governor_state::admission_reason(reason)
                        )),
                        ..LifecyclePayload::default()
                    },
                );
                Ok(None)
            }
        }
    }
}

async fn run_attempt(attempt: PreparedAttempt) -> AttemptTerminal {
    if !attempt.delay.is_zero() {
        tokio::time::sleep(attempt.delay).await;
    }
    if attempt.attempt_cancel.load(Ordering::Acquire)
        || attempt.drain.load(Ordering::Acquire)
        || attempt
            .interrupt
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    {
        return AttemptTerminal::Suppressed {
            index: attempt.index,
            ordinal: attempt.ordinal,
            physical_attempt: attempt.physical_attempt,
            ticket: attempt.ticket,
            permit: attempt.permit,
        };
    }

    let mut items = Vec::new();
    let mut rate_limit = None;
    let result = {
        let mut on_item = |item: StreamItem| {
            if let StreamItem::RateLimit(snapshot) = &item {
                rate_limit = Some(*snapshot);
            }
            if items.len() < MAX_BUFFERED_HEDGE_ITEMS {
                items.push(item);
            }
        };
        provider_route::execute_admitted_provider_turn(
            attempt.provider,
            attempt.deadline,
            attempt.interrupt,
            attempt.drain,
            Some(attempt.attempt_cancel),
            &attempt.request,
            &mut on_item,
        )
        .await
    };
    AttemptTerminal::Completed {
        index: attempt.index,
        ordinal: attempt.ordinal,
        physical_attempt: attempt.physical_attempt,
        ticket: attempt.ticket,
        permit: attempt.permit,
        items,
        rate_limit,
        result,
    }
}

struct UsageAggregate {
    usage: iteron_protocol::Usage,
    saw_success: bool,
    complete: bool,
    cache_creation_reported: bool,
}

impl Default for UsageAggregate {
    fn default() -> Self {
        Self {
            usage: iteron_protocol::Usage::default(),
            saw_success: false,
            complete: true,
            cache_creation_reported: true,
        }
    }
}

impl UsageAggregate {
    fn observe_success(&mut self, report: UsageReport) {
        self.saw_success = true;
        match report {
            UsageReport::Complete(usage) => self.usage.add(&usage),
            UsageReport::CacheCreationUnreported(usage) => {
                self.usage.add(&usage);
                self.cache_creation_reported = false;
            }
            UsageReport::Incomplete { .. } => self.complete = false,
        }
    }

    fn observe_dispatched_without_usage(&mut self) {
        self.complete = false;
    }

    fn report(self) -> UsageReport {
        if !self.complete || !self.saw_success {
            UsageReport::provider_omitted()
        } else if self.cache_creation_reported {
            UsageReport::complete(self.usage)
        } else {
            UsageReport::cache_creation_unreported(self.usage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hedge_usage_counts_each_success_once_and_preserves_incompleteness() {
        let mut aggregate = UsageAggregate::default();
        aggregate.observe_success(UsageReport::complete(iteron_protocol::Usage {
            input: 10,
            output: 2,
            ..iteron_protocol::Usage::default()
        }));
        aggregate.observe_success(UsageReport::cache_creation_unreported(
            iteron_protocol::Usage {
                input: 10,
                output: 3,
                ..iteron_protocol::Usage::default()
            },
        ));
        assert_eq!(
            aggregate.report(),
            UsageReport::cache_creation_unreported(iteron_protocol::Usage {
                input: 20,
                output: 5,
                ..iteron_protocol::Usage::default()
            })
        );

        let mut incomplete = UsageAggregate::default();
        incomplete.observe_success(UsageReport::complete(iteron_protocol::Usage::default()));
        incomplete.observe_dispatched_without_usage();
        assert_eq!(incomplete.report(), UsageReport::provider_omitted());
    }
}
