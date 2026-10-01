//! Logical usage publication consumes sealed physical truth. This journal is the actual writer,
//! token ledger and already-charged USD observer; it cannot mint prices or dispatch a request.
use super::KernelError;
use super::pricing::SharedUsdBudget;
use super::provider_attempt_journal::ProviderLogicalUsageEvidence;
use super::provider_logical_usage::{LogicalUsageScope, exact_projection};
use super::session_transcript::TranscriptAdmissionJournal;
use super::stream_progress::StreamTiming;
use super::stream_tool_events::StreamToolEvents;
use super::{INCOMPLETE_USAGE_NOTICE, UNPRICEABLE_CACHE_CREATION_NOTICE};
use iteron_obs::{PricingPort, ProjectionAdmissionError};
use iteron_protocol::{CostAttribution, TurnId, Usage};
use iteron_provider::UsageReport;
use std::sync::Arc;

#[cfg(all(test, unix))]
#[path = "provider_usage_journal_tests.rs"]
mod tests;

pub(super) struct ProviderUsageJournal<'a> {
    pub(super) transcript: TranscriptAdmissionJournal<'a>,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) pricing: Option<Arc<dyn PricingPort>>,
    pub(super) attribution: Option<CostAttribution>,
    pub(super) events: StreamToolEvents,
}

impl ProviderUsageJournal<'_> {
    fn close_usd_if_physical_charge_is_unproved(&self, turn: TurnId) {
        let known = self.usd.as_ref().is_some_and(|budget| {
            budget.has_known_provider_charge_for(
                self.transcript.rollout.tenant(),
                self.transcript.rollout.run_id(),
                turn,
            )
        });
        if !known {
            self.mark_unknown();
        }
    }
    fn mark_unknown(&self) {
        if let Some(budget) = &self.usd {
            budget.mark_unknown();
        }
    }
    pub(super) fn complete(
        &mut self,
        turn: TurnId,
        usage: Usage,
        model_ms: u64,
        evidence: &ProviderLogicalUsageEvidence,
        stream: StreamTiming,
        cache_creation_reported: bool,
    ) -> Result<(), KernelError> {
        let projection = exact_projection(
            evidence,
            LogicalUsageScope {
                tenant: self.transcript.rollout.tenant(),
                run: self.transcript.rollout.run_id(),
                turn,
                attribution: &self.attribution,
            },
            usage,
            self.pricing.as_deref(),
        )?;
        if let Err(error) = self.transcript.turn_end(turn, usage, stream) {
            self.close_usd_if_physical_charge_is_unproved(turn);
            return Err(error);
        }
        if !cache_creation_reported {
            let notice = iteron_tunables::param_str(
                "cli.runtime.unpriceable_cache_creation_notice",
                UNPRICEABLE_CACHE_CREATION_NOTICE,
            );
            if let Err(error) = self.transcript.notice(turn, notice.into()) {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(error);
            }
            self.events
                .present(super::frontend_events::UiEvent::Notice(notice.into()));
        }
        self.transcript.ledger.turn(&usage, model_ms);
        if let Some(projection) = projection {
            if let Err(error) = self.transcript.cost_projection(turn, projection.clone()) {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(error);
            }
            let Some(port) = self.pricing.as_deref() else {
                self.close_usd_if_physical_charge_is_unproved(turn);
                return Err(KernelError::PricingLedger(
                    "signed projection lost its pricing authority",
                ));
            };
            let identity = projection
                .identity
                .as_ref()
                .ok_or(KernelError::PricingLedger(
                    "physical terminal projection lost its authenticated identity",
                ))?;
            match iteron_obs::admit_verified_projection_by_digest(
                port,
                identity,
                &projection,
                &mut *self.transcript.ledger,
            ) {
                Ok(()) => {}
                Err(ProjectionAdmissionError::Pricing(error)) => {
                    self.close_usd_if_physical_charge_is_unproved(turn);
                    return Err(error.into());
                }
                Err(ProjectionAdmissionError::Ledger(reason)) => {
                    self.close_usd_if_physical_charge_is_unproved(turn);
                    return Err(KernelError::PricingLedger(reason));
                }
            }
        } else {
            self.close_usd_if_physical_charge_is_unproved(turn);
        }
        Ok(())
    }
    pub(super) fn record(
        &mut self,
        turn: TurnId,
        report: UsageReport,
        model_ms: u64,
        evidence: &ProviderLogicalUsageEvidence,
        stream: StreamTiming,
    ) -> Result<Option<Usage>, KernelError> {
        match report {
            UsageReport::Complete(usage) | UsageReport::CacheCreationUnreported(usage) => {
                self.complete(
                    turn,
                    usage,
                    model_ms,
                    evidence,
                    stream,
                    report.cache_creation_reported(),
                )?;
                Ok(Some(usage))
            }
            UsageReport::Incomplete { .. } => {
                if let Err(error) = self.transcript.notice(turn, INCOMPLETE_USAGE_NOTICE.into()) {
                    self.mark_unknown();
                    return Err(error);
                }
                self.transcript.ledger.turn_without_usage(model_ms);
                self.mark_unknown();
                Ok(None)
            }
        }
    }
}
