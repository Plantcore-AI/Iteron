//! Actual provider usage reconciles the existing context turn slot and bounded calibration
//! baselines. It cannot create request authority, call a provider or substitute estimated usage.
use super::context_preparation_events::ContextPreparationEvents;
use iteron_ctx::{ContextLedgerStore, TokenCalibrationStore};
use iteron_protocol::{LifecyclePayload, TurnId, Usage};
use std::collections::VecDeque;

pub(super) struct ContextUsageReconciliation<'a> {
    pub(super) ledgers: &'a ContextLedgerStore,
    pub(super) baselines: &'a mut VecDeque<(TurnId, u64)>,
    pub(super) calibration: &'a mut TokenCalibrationStore,
    pub(super) provider_id: &'a str,
    pub(super) model_id: &'a str,
    pub(super) events: ContextPreparationEvents,
}
impl ContextUsageReconciliation<'_> {
    fn take_baseline(&mut self, turn: TurnId) -> Option<u64> {
        let index = self
            .baselines
            .iter()
            .position(|(candidate, _)| *candidate == turn)?;
        self.baselines.remove(index).map(|(_, tokens)| tokens)
    }
    pub(super) fn observe(&mut self, turn: TurnId, usage: Usage) {
        use iteron_ctx::{ContextObservation, ContextObserver};
        let actual_input_tokens = usage
            .input
            .saturating_add(usage.cache_read)
            .saturating_add(usage.cache_creation);
        let matching_ledger = self
            .ledgers
            .snapshot()
            .ledgers
            .into_iter()
            .find(|ledger| ledger.turn_id == turn);
        let estimated_input_tokens = matching_ledger
            .as_ref()
            .map(|ledger| ledger.totals.estimated_tokens);
        let uncalibrated_input_tokens = self.take_baseline(turn);
        if let Some(mut ledger) = matching_ledger {
            // Provider usage is the first authority that can distinguish an actual cache hit,
            // cache population, and uncached prefill. Replace the pre-dispatch estimate in the
            // same bounded turn slot instead of leaving those three public counters at zero.
            ledger.totals.actual_input_tokens = Some(actual_input_tokens);
            ledger.cache.cache_read_tokens = usage.cache_read;
            ledger.cache.cache_write_tokens = usage.cache_creation;
            ledger.cache.uncached_tokens = usage.input;
            self.ledgers.publish(ledger);
        } else {
            self.ledgers.observe(
                turn,
                ContextObservation::ProviderUsage {
                    actual_input_tokens,
                    cache_read_tokens: usage.cache_read,
                    cache_write_tokens: usage.cache_creation,
                    uncached_tokens: usage.input,
                },
            );
        }
        self.events.emit_optional(
            "context.tokenizer.actual_observed",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(actual_input_tokens),
                ..LifecyclePayload::default()
            },
        );
        if let Some(estimated) = estimated_input_tokens {
            let (provider_id, model_id) = (self.provider_id, self.model_id);
            let calibration = uncalibrated_input_tokens.and_then(|baseline| {
                self.calibration
                    .observe_actual_input(provider_id, model_id, baseline, actual_input_tokens)
                    .ok()
            });
            self.events.emit_optional(
                "context.tokenizer.error_calculated",
                Some(turn),
                LifecyclePayload {
                    magnitude: Some(estimated.abs_diff(actual_input_tokens)),
                    outcome_code: Some(
                        match estimated.cmp(&actual_input_tokens) {
                            std::cmp::Ordering::Less => "underestimated",
                            std::cmp::Ordering::Equal => "exact",
                            std::cmp::Ordering::Greater => "overestimated",
                        }
                        .into(),
                    ),
                    ..LifecyclePayload::default()
                },
            );
            match calibration {
                Some(observation) => self.events.emit_optional(
                    "context.tokenizer.error_calculated",
                    Some(turn),
                    LifecyclePayload {
                        magnitude: Some(observation.error_ppm),
                        outcome_code: Some(
                            if observation.drifted {
                                "drifted_conservative"
                            } else {
                                "ewma_updated"
                            }
                            .into(),
                        ),
                        count: Some(observation.ratio_ppm),
                        reason_code: Some("calibration_updated".into()),
                        ..LifecyclePayload::default()
                    },
                ),
                None => self.events.emit_optional(
                    "context.tokenizer.error_calculated",
                    Some(turn),
                    LifecyclePayload {
                        outcome_code: Some("calibration_rejected".into()),
                        ..LifecyclePayload::default()
                    },
                ),
            }
        }
        self.events.emit_optional(
            "context.request.usage_reconciled",
            Some(turn),
            LifecyclePayload {
                magnitude: Some(usage.input),
                ..LifecyclePayload::default()
            },
        );
        for (reason_code, tokens) in [
            ("cache_read", usage.cache_read),
            ("cache_write", usage.cache_creation),
            ("cache_miss", usage.input),
        ] {
            if tokens > 0 {
                self.events.emit_optional(
                    "context.cache_region.classified",
                    Some(turn),
                    LifecyclePayload {
                        magnitude: Some(tokens),
                        reason_code: Some(reason_code.into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }
}
