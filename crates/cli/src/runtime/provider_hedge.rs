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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MAX_BUFFERED_HEDGE_ITEMS: usize = 131_072;
const HEDGE_LIVE_QUEUE_ITEMS: usize = 4_096;
/// Includes both the retained semantic copy and the live-forward clone across every physical
/// attempt in one hedge. The hard ceiling is deliberately not tunable upward: a provider frame may
/// itself be tens of MiB, so an item-count bound alone can otherwise retain GiB.
const DEFAULT_HEDGE_AGGREGATE_BYTES: usize = 72 * 1024 * 1024;
const MAX_HEDGE_AGGREGATE_BYTES: usize = 128 * 1024 * 1024;

struct AttemptLiveItem {
    index: u8,
    item: StreamItem,
    retained_bytes: usize,
}

struct HedgeByteBudget {
    used: AtomicUsize,
    limit: usize,
}

impl HedgeByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    fn release(&self, bytes: usize) {
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes, "hedge byte reservations are balanced");
    }

    #[cfg(test)]
    fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HedgeBufferOverflow {
    AggregateBytes,
    ItemCount,
    LiveQueue,
}

impl HedgeBufferOverflow {
    const fn reason(self) -> &'static str {
        match self {
            Self::AggregateBytes => "aggregate byte budget",
            Self::ItemCount => "retained item budget",
            Self::LiveQueue => "live forwarding queue",
        }
    }
}

pub(super) struct HedgedProviderDispatch {
    pub result: Result<iteron_provider::TurnResult, KernelError>,
    pub items: Vec<StreamItem>,
    pub scheduled_attempts: u32,
    /// True only when every scheduled attempt has known cost or proved it never dispatched.
    pub monetary_followup_safe: bool,
    /// Text/reasoning deltas were forwarded at winner selection, before loser cleanup. The caller
    /// still replays items through the semantic accumulator but must not render them twice.
    pub ui_deltas_forwarded: bool,
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
    force_cancel: Arc<AtomicBool>,
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
                ui_deltas_forwarded: false,
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
                force_cancel: self.force_cancel.clone(),
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
        let live_capacity = iteron_tunables::param_integer(
            "cli.runtime.provider_hedge.hedge_live_queue_items",
            HEDGE_LIVE_QUEUE_ITEMS,
        )
        .clamp(
            1,
            iteron_tunables::param_integer(
                "cli.runtime.provider_hedge.max_buffered_hedge_items",
                MAX_BUFFERED_HEDGE_ITEMS,
            )
            .clamp(1, MAX_BUFFERED_HEDGE_ITEMS),
        );
        let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(live_capacity);
        let max_aggregate_bytes = iteron_tunables::param_integer(
            "cli.runtime.provider_hedge.max_hedge_aggregate_bytes",
            MAX_HEDGE_AGGREGATE_BYTES,
        )
        .clamp(1, MAX_HEDGE_AGGREGATE_BYTES);
        let byte_budget = Arc::new(HedgeByteBudget::new(
            iteron_tunables::param_usize(
                "cli.runtime.provider_hedge.default_hedge_aggregate_bytes",
                DEFAULT_HEDGE_AGGREGATE_BYTES,
            )
            .clamp(1, max_aggregate_bytes),
        ));
        let mut attempts = prepared
            .into_iter()
            .map(|attempt| {
                let live_tx = live_tx.clone();
                Box::pin(run_attempt(attempt, live_tx, byte_budget.clone())) as AttemptFuture
            })
            .collect::<FuturesUnordered<_>>();
        drop(live_tx);
        let mut winner: Option<(u8, iteron_provider::TurnResult, Vec<StreamItem>)> = None;
        let mut selected_index = None;
        let mut errors = BTreeMap::new();
        let mut aggregate = UsageAggregate::default();
        let mut monetary_followup_safe = true;
        let mut ui_deltas_forwarded = false;

        while !attempts.is_empty() {
            let terminal = tokio::select! {
                // Deltas win ties with a terminal from the same adapter. This makes TTFT and
                // rendering independent of loser settlement while retaining terminal evidence in
                // the FuturesUnordered branch below.
                biased;
                live = live_rx.recv() => {
                    if let Some(live) = live {
                        byte_budget.release(live.retained_bytes);
                        let selects_winner = matches!(
                            &live.item,
                            StreamItem::TextDelta(_)
                                | StreamItem::ThinkingDelta(_)
                                | StreamItem::ToolUseComplete(_)
                                | StreamItem::TurnComplete { .. }
                        );
                        if selected_index.is_none() && selects_winner {
                            selected_index = Some(live.index);
                            for (other, cancel) in &cancellation {
                                if *other != live.index {
                                    cancel.store(true, Ordering::Release);
                                }
                            }
                        }
                        if selected_index == Some(live.index)
                            && let Some(tx) = &self.ui_tx
                        {
                            match live.item {
                                StreamItem::TextDelta(text) => {
                                    let _ = self.frontend_saturation.try_send_ui(
                                        tx,
                                        UiEvent::Text(iteron_record::redact::scrub(&text)),
                                    );
                                    ui_deltas_forwarded = true;
                                }
                                StreamItem::ThinkingDelta(text) => {
                                    let _ = self.frontend_saturation.try_send_ui(
                                        tx,
                                        UiEvent::Thinking(iteron_record::redact::scrub(&text)),
                                    );
                                    ui_deltas_forwarded = true;
                                }
                                StreamItem::Accepted
                                | StreamItem::CompatibilityNotice(_)
                                | StreamItem::ToolUseComplete(_)
                                | StreamItem::RateLimit(_)
                                | StreamItem::TurnComplete { .. } => {}
                            }
                        }
                    }
                    continue;
                }
                terminal = attempts.next() => terminal,
            };
            let Some(terminal) = terminal else { break };
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
                            if selected_index.is_none() {
                                selected_index = Some(index);
                                for (other, cancel) in &cancellation {
                                    if *other != index {
                                        cancel.store(true, Ordering::Release);
                                    }
                                }
                                // Winner selection is the success terminal for this physical
                                // stream. Rendering its already-validated deltas must not wait for
                                // duplicate cancellation/accounting to settle.
                                if let Some(tx) = &self.ui_tx {
                                    for item in &items {
                                        match item {
                                            StreamItem::TextDelta(text) => {
                                                let _ = self.frontend_saturation.try_send_ui(
                                                    tx,
                                                    UiEvent::Text(iteron_record::redact::scrub(
                                                        text,
                                                    )),
                                                );
                                                ui_deltas_forwarded = true;
                                            }
                                            StreamItem::ThinkingDelta(text) => {
                                                let _ = self.frontend_saturation.try_send_ui(
                                                    tx,
                                                    UiEvent::Thinking(
                                                        iteron_record::redact::scrub(text),
                                                    ),
                                                );
                                                ui_deltas_forwarded = true;
                                            }
                                            StreamItem::Accepted
                                            | StreamItem::CompatibilityNotice(_)
                                            | StreamItem::ToolUseComplete(_)
                                            | StreamItem::RateLimit(_)
                                            | StreamItem::TurnComplete { .. } => {}
                                        }
                                    }
                                }
                            }
                            if selected_index == Some(index) && winner.is_none() {
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
        } else if let Some(index) = selected_index
            && let Some((error, items)) = errors.remove(&index)
        {
            (Err(error), items)
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
            ui_deltas_forwarded,
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

async fn run_attempt(
    attempt: PreparedAttempt,
    live_tx: tokio::sync::mpsc::Sender<AttemptLiveItem>,
    byte_budget: Arc<HedgeByteBudget>,
) -> AttemptTerminal {
    if !attempt.delay.is_zero() {
        tokio::time::sleep(attempt.delay).await;
    }
    if attempt.attempt_cancel.load(Ordering::Acquire)
        || attempt.drain.load(Ordering::Acquire)
        || attempt.force_cancel.load(Ordering::Acquire)
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
    let mut buffer_overflow = None;
    let max_items = iteron_tunables::param_usize(
        "cli.runtime.provider_hedge.max_buffered_hedge_items",
        MAX_BUFFERED_HEDGE_ITEMS,
    )
    .clamp(1, MAX_BUFFERED_HEDGE_ITEMS);
    let mut result = {
        let mut on_item = |item: StreamItem| {
            if let StreamItem::RateLimit(snapshot) = &item {
                rate_limit = Some(*snapshot);
            }
            if buffer_overflow.is_none()
                && let Err(overflow) = admit_hedge_item(
                    attempt.index,
                    item,
                    &live_tx,
                    &byte_budget,
                    &mut items,
                    max_items,
                )
            {
                buffer_overflow = Some(overflow);
            }
        };
        provider_route::execute_admitted_provider_turn(
            attempt.provider,
            attempt.deadline,
            provider_route::ProviderCancellation {
                interrupt: attempt.interrupt,
                force_cancel: attempt.force_cancel,
                drain: attempt.drain,
                attempt: Some(attempt.attempt_cancel),
            },
            &attempt.request,
            &mut on_item,
        )
        .await
    };
    if let Some(overflow) = buffer_overflow {
        result = Err(KernelError::Provider(
            iteron_provider::ProviderError::Decode(format!(
                "hedged provider stream exceeded its bounded {}",
                overflow.reason()
            )),
        ));
    }
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

fn admit_hedge_item(
    index: u8,
    item: StreamItem,
    live_tx: &tokio::sync::mpsc::Sender<AttemptLiveItem>,
    byte_budget: &HedgeByteBudget,
    items: &mut Vec<StreamItem>,
    max_items: usize,
) -> Result<(), HedgeBufferOverflow> {
    if items.len() >= max_items {
        return Err(HedgeBufferOverflow::ItemCount);
    }
    let retained_bytes = stream_item_retained_bytes(&item);
    let retained_and_live = retained_bytes
        .checked_mul(2)
        .ok_or(HedgeBufferOverflow::AggregateBytes)?;
    if !byte_budget.try_reserve(retained_and_live) {
        return Err(HedgeBufferOverflow::AggregateBytes);
    }
    let live = AttemptLiveItem {
        index,
        item: item.clone(),
        retained_bytes,
    };
    let live_sent = live_tx.try_send(live).is_ok();
    if !live_sent {
        // The failed send returns and drops the clone; only the semantic copy retained below still
        // occupies the shared budget.
        byte_budget.release(retained_bytes);
    }
    items.push(item);
    if live_sent {
        Ok(())
    } else {
        Err(HedgeBufferOverflow::LiveQueue)
    }
}

fn stream_item_retained_bytes(item: &StreamItem) -> usize {
    let inline = std::mem::size_of::<StreamItem>();
    let dynamic = match item {
        StreamItem::Accepted | StreamItem::CompatibilityNotice(_) | StreamItem::RateLimit(_) => 0,
        StreamItem::TextDelta(text) | StreamItem::ThinkingDelta(text) => text.len(),
        StreamItem::ToolUseComplete(tool) => tool_use_retained_bytes(tool),
        StreamItem::TurnComplete { blocks, .. } => blocks.iter().fold(0usize, |total, block| {
            total.saturating_add(block_retained_bytes(block))
        }),
    };
    // A second inline charge plus fixed allocator/channel-node headroom covers geometric Vec
    // capacity and the bounded mpsc slot; payload allocations are charged below.
    inline
        .saturating_mul(2)
        .saturating_add(128)
        .saturating_add(dynamic)
}

fn block_retained_bytes(block: &Block) -> usize {
    let inline = std::mem::size_of::<Block>();
    let dynamic = match block {
        Block::Text { text } => text.len(),
        Block::Thinking { thinking } => thinking.len(),
        Block::ProviderState(state) => state
            .route_scope
            .len()
            .saturating_add(state.format.as_str().len())
            .saturating_add(json_retained_bytes(&state.payload)),
        Block::ToolUse(tool) => tool_use_retained_bytes(tool),
        Block::ToolResult(result) => result
            .tool_use_id
            .len()
            .saturating_add(result.content.len()),
    };
    inline
        .saturating_mul(2)
        .saturating_add(64)
        .saturating_add(dynamic)
}

fn tool_use_retained_bytes(tool: &ToolUse) -> usize {
    std::mem::size_of::<ToolUse>()
        .saturating_mul(2)
        .saturating_add(64)
        .saturating_add(tool.id.len())
        .saturating_add(tool.name.len())
        .saturating_add(json_retained_bytes(&tool.input))
}

/// Conservative owned-tree charge. Container/node overhead is intentionally over-counted so a
/// deeply nested object cannot evade the aggregate budget merely because its wire strings are
/// short.
fn json_retained_bytes(value: &serde_json::Value) -> usize {
    let inline = std::mem::size_of::<serde_json::Value>();
    let dynamic = match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => 0,
        serde_json::Value::String(text) => text.len(),
        serde_json::Value::Array(values) => values.iter().fold(0usize, |total, value| {
            total.saturating_add(json_retained_bytes(value))
        }),
        serde_json::Value::Object(values) => values.iter().fold(0usize, |total, (key, value)| {
            total
                .saturating_add(64)
                .saturating_add(key.len())
                .saturating_add(json_retained_bytes(value))
        }),
    };
    inline.saturating_mul(2).saturating_add(dynamic)
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

    #[tokio::test]
    async fn aggregate_byte_budget_rejects_one_large_frame_before_cloning_it() {
        let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(1);
        let item = StreamItem::TextDelta("x".repeat(1_024));
        let one_copy = stream_item_retained_bytes(&item);
        let budget = HedgeByteBudget::new(one_copy.saturating_mul(2).saturating_sub(1));
        let mut retained = Vec::new();

        assert_eq!(
            admit_hedge_item(0, item, &live_tx, &budget, &mut retained, 8),
            Err(HedgeBufferOverflow::AggregateBytes)
        );
        assert!(retained.is_empty(), "the semantic copy was not admitted");
        assert!(
            live_rx.try_recv().is_err(),
            "the live clone was not admitted"
        );
        assert_eq!(budget.used(), 0, "a refused frame leaves no reservation");
    }

    #[tokio::test]
    async fn live_clone_has_an_independent_released_byte_reservation() {
        let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(1);
        let item = StreamItem::TextDelta("bounded".repeat(32));
        let one_copy = stream_item_retained_bytes(&item);
        let budget = HedgeByteBudget::new(one_copy.saturating_mul(2));
        let mut retained = Vec::new();

        admit_hedge_item(0, item, &live_tx, &budget, &mut retained, 8).unwrap();
        assert_eq!(budget.used(), one_copy * 2);
        let live = live_rx.try_recv().expect("live copy was admitted");
        budget.release(live.retained_bytes);
        assert_eq!(budget.used(), one_copy, "the retained copy remains charged");
    }

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
