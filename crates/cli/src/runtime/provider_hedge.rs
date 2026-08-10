//! Bounded duplicate-safe provider hedging with one durable effect ticket per scheduled attempt.
//!
//! A winner cancels every duplicate: delayed siblings are suppressed before dispatch and
//! in-flight siblings have their transport future dropped. An in-flight cancellation is settled
//! as an unknown external effect and makes aggregate usage incomplete; it is never misreported as
//! a proven-unbilled request.

use super::*;
use core_provider::{AttemptPermit, ProviderAdmission as Admission};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_BUFFERED_HEDGE_ITEMS: usize = 131_072;

pub(super) struct HedgedProviderDispatch {
    pub result: Result<core_provider::TurnResult, KernelError>,
    pub items: Vec<StreamItem>,
    pub scheduled_attempts: u32,
}

struct PreparedAttempt {
    index: u8,
    ordinal: usize,
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
        ticket: effects::EffectTicket,
        permit: Option<AttemptPermit>,
    },
    Completed {
        index: u8,
        ordinal: usize,
        ticket: effects::EffectTicket,
        permit: Option<AttemptPermit>,
        items: Vec<StreamItem>,
        rate_limit: Option<core_provider::RateLimitSnapshot>,
        result: Result<core_provider::TurnResult, KernelError>,
    },
}

type AttemptFuture = Pin<Box<dyn Future<Output = AttemptTerminal> + Send>>;

impl Agent {
    pub(super) fn provider_hedging_enabled(&self) -> bool {
        self.provider_governor
            .as_ref()
            .is_some_and(|governor| governor.policy().hedge.enabled)
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
    ) -> Result<HedgedProviderDispatch, KernelError> {
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
            });
        }

        let total = hedge.max_duplicates.saturating_add(1);
        let mut prepared = Vec::with_capacity(usize::from(total));
        let mut cancellation = Vec::with_capacity(usize::from(total));
        for index in 0..total {
            let permit = if index == 0 {
                self.admit_governed_route_attempt(turn, route_id).await?
            } else {
                let Some(permit) = self.try_admit_optional_hedge(turn, route_id) else {
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
            let ticket = self.open_kernel_effect(
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
                }),
            )?;
            cancellation.push((index, attempt_cancel.clone()));
            prepared.push(PreparedAttempt {
                index,
                ordinal,
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
        let mut attempts = prepared
            .into_iter()
            .map(|attempt| Box::pin(run_attempt(attempt)) as AttemptFuture)
            .collect::<FuturesUnordered<_>>();
        let mut winner: Option<(u8, core_provider::TurnResult, Vec<StreamItem>)> = None;
        let mut errors = BTreeMap::new();
        let mut aggregate = UsageAggregate::default();

        while let Some(terminal) = attempts.next().await {
            match terminal {
                AttemptTerminal::Suppressed {
                    index,
                    ordinal,
                    ticket,
                    permit,
                } => {
                    self.settle_kernel_effect(
                        ticket,
                        effects::Settlement::Definite(effect_failed_terminal(
                            turn,
                            effect_class::EffectClass::Provider,
                            ordinal,
                            "hedge duplicate was cancelled before provider dispatch",
                        )),
                    )?;
                    drop(permit);
                    let _ = index;
                }
                AttemptTerminal::Completed {
                    index,
                    ordinal,
                    ticket,
                    permit,
                    items,
                    rate_limit,
                    result,
                } => {
                    self.settle_kernel_effect(
                        ticket,
                        provider_route::provider_settlement(turn, ordinal, &result),
                    )?;
                    self.observe_governed_route_attempt(turn, route_id, &result, rate_limit);
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
                    core_provider::ProviderError::Configuration(
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
        })
    }

    fn try_admit_optional_hedge(&self, turn: TurnId, route_id: &str) -> Option<AttemptPermit> {
        let governor = self.provider_governor.as_ref()?;
        match governor.admit(route_id, Instant::now()) {
            Admission::Admitted(permit) => {
                self.emit_circuit_transition(turn, permit.transition);
                Some(permit)
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
                None
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
                None
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
        ticket: attempt.ticket,
        permit: attempt.permit,
        items,
        rate_limit,
        result,
    }
}

struct UsageAggregate {
    usage: core_protocol::Usage,
    saw_success: bool,
    complete: bool,
    cache_creation_reported: bool,
}

impl Default for UsageAggregate {
    fn default() -> Self {
        Self {
            usage: core_protocol::Usage::default(),
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
        aggregate.observe_success(UsageReport::complete(core_protocol::Usage {
            input: 10,
            output: 2,
            ..core_protocol::Usage::default()
        }));
        aggregate.observe_success(UsageReport::cache_creation_unreported(
            core_protocol::Usage {
                input: 10,
                output: 3,
                ..core_protocol::Usage::default()
            },
        ));
        assert_eq!(
            aggregate.report(),
            UsageReport::cache_creation_unreported(core_protocol::Usage {
                input: 20,
                output: 5,
                ..core_protocol::Usage::default()
            })
        );

        let mut incomplete = UsageAggregate::default();
        incomplete.observe_success(UsageReport::complete(core_protocol::Usage::default()));
        incomplete.observe_dispatched_without_usage();
        assert_eq!(incomplete.report(), UsageReport::provider_omitted());
    }
}
