//! Authenticated immutable financial scope. Each physical admission freezes a fresh pricing
//! view of the sole selected route; this source never owns money or a dispatch counter.
use super::persistent_agents::RuntimeProviderBudgetPort;
use super::pricing::SharedUsdBudget;
use super::provider_financial_context::{
    ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
    ProviderPricingEvidence,
};
use super::provider_selection::ProviderSelectionOwner;
use iteron_agents::ControllerError;
use iteron_protocol::{CostAttribution, RunId, TenantId};
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
