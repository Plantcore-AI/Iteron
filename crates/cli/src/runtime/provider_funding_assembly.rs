//! Composition of signed output quotes with the existing sole physical admission boundary.
//! Quotes are never transport authority, and already reserved requests are never quoted twice.
use super::provider_governor_state::GovernedProviderRoute;
use super::provider_output_request::{self, PhysicalProviderRequest};
use super::provider_route::ProviderDispatchAdmission;
use super::{Agent, KernelError};
use iteron_protocol::TurnId;
use iteron_provider::TurnRequest;

impl Agent {
    pub(super) async fn admit_funded_provider_dispatch(
        &mut self,
        turn: TurnId,
        mut request: TurnRequest,
    ) -> Result<(PhysicalProviderRequest, ProviderDispatchAdmission), KernelError> {
        self.ensure_record_healthy()?;
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        self.synchronize_usd_budget()?;
        self.close_usd_budget_on_unknown_cost();
        request.controls = self.provider_controls_for(self.provider.as_ref());
        request.cache_system =
            request.controls.prompt_cache.breakpoint != iteron_provider::CacheBreakpoint::None;
        let financial = self.provider_financial_context();
        let funding = financial.output_funding(&self.governed_route_id(), self.pricing_now())?;
        let physical = provider_output_request::normalize_funded(
            self.provider.as_ref(),
            request,
            self.provider_output_proof_required(),
            funding.as_ref(),
        )?;
        let admission = self
            .admit_provider_dispatch(turn, &physical.request)
            .await?;
        Ok((physical, admission))
    }

    pub(super) fn quote_candidate_provider_request(
        &self,
        candidate: &GovernedProviderRoute,
        request: TurnRequest,
    ) -> Result<PhysicalProviderRequest, KernelError> {
        let now = self.pricing_now();
        let financial = self.provider_financial_source().candidate(
            &self.provider_selection,
            &candidate.provider,
            &candidate.route,
            now,
        )?;
        let funding = financial.output_funding(&candidate.id(), now)?;
        provider_output_request::normalize_funded(
            candidate.provider.as_ref(),
            request,
            self.provider_output_proof_required(),
            funding.as_ref(),
        )
    }
}
