//! Authenticated immutable financial scope. Each physical admission freezes a fresh pricing
//! view of the sole selected route; this source never owns money or a dispatch counter.
use super::KernelError;
use super::persistent_agents::RuntimeProviderBudgetPort;
use super::pricing::SharedUsdBudget;
use super::provider_financial_context::{
    ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
    ProviderPricingEvidence,
};
use super::provider_selection::ProviderSelectionOwner;
use iteron_agents::ControllerError;
use iteron_protocol::{CostAttribution, PricingRoute, RunId, TenantId};
use iteron_provider::Provider;
use std::sync::Arc;

pub(super) struct ProviderFinancialSource {
    pub(super) tenant: TenantId,
    pub(super) run: RunId,
    pub(super) attribution: Option<CostAttribution>,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) cohort: Result<Option<Arc<dyn RuntimeProviderBudgetPort>>, ControllerError>,
}
impl ProviderFinancialSource {
    /// A fallback quote reads the candidate's exact signed artifact, never the current route's
    /// card. This does not select a route, reserve money or authorize physical dispatch.
    pub(super) fn candidate(
        &self,
        selection: &ProviderSelectionOwner,
        provider: &Arc<dyn Provider>,
        route: &PricingRoute,
        now: u64,
    ) -> Result<ProviderFinancialContext, KernelError> {
        ProviderSelectionOwner::validate_selection(provider, route)?;
        let required = self.usd.as_ref().is_some_and(|usd| usd.requires_pricing())
            || self.cohort.as_ref().map_or(true, |port| port.is_some());
        let port = selection.pricing_port().cloned();
        let card = if required {
            let port = port.as_ref().ok_or(KernelError::UnpricedUsdCeiling)?;
            let signed = port
                .resolve_rate_card(route, now)?
                .ok_or(KernelError::UnpricedUsdCeiling)?;
            port.verify_rate_card(&signed)?;
            if &signed.rate_card.route != route {
                return Err(KernelError::UnpricedUsdCeiling);
            }
            Some(signed)
        } else {
            None
        };
        Ok(ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: self.tenant.clone(),
                run_id: self.run.clone(),
                attribution: self.attribution.clone(),
            },
            ProviderPricingEvidence {
                port,
                card,
                context_window: provider.physical_input_token_ceiling(&route.model_id),
                usage_bounds: provider.usage_bound_semantics(),
            },
            ProviderFinancialOwners {
                usd: self.usd.clone(),
                cohort: self.cohort.clone(),
            },
        ))
    }
    pub(super) fn selected(
        &self,
        selection: &ProviderSelectionOwner,
        provider: &dyn Provider,
        model: &str,
    ) -> ProviderFinancialContext {
        ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: self.tenant.clone(),
                run_id: self.run.clone(),
                attribution: self.attribution.clone(),
            },
            ProviderPricingEvidence {
                port: selection.pricing_port().cloned(),
                card: selection.card().cloned(),
                context_window: provider.physical_input_token_ceiling(model),
                usage_bounds: provider.usage_bound_semantics(),
            },
            ProviderFinancialOwners {
                usd: self.usd.clone(),
                cohort: self.cohort.clone(),
            },
        )
    }
}
