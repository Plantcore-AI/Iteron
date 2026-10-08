//! Immutable result projection against the admitted component allowance and actual spill bound.
//! All callers share this policy; it cannot create schemas or tool/execution authority.
use super::context_runtime::{ContextBudgetInspection, TurnResultProjectionBudget};
use iteron_ctx::{ContextBudgetClass, ContextBudgetPolicy};

pub(super) struct ToolResultProjectionPolicy<'a> {
    pub(super) budget: &'a ContextBudgetPolicy,
    pub(super) visible_bytes: usize,
    pub(super) inspection: ContextBudgetInspection,
}
impl ToolResultProjectionPolicy<'_> {
    pub(super) fn calculate(
        &self,
        calls: &[iteron_protocol::ToolUse],
    ) -> TurnResultProjectionBudget {
        let (ordinary, lsp) = calls
            .iter()
            .fold((0usize, 0usize), |(ordinary, lsp), call| {
                if iteron_ctx::result_budget_class(&call.name) == ContextBudgetClass::LspResults {
                    (ordinary, lsp.saturating_add(1))
                } else {
                    (ordinary.saturating_add(1), lsp)
                }
            });
        TurnResultProjectionBudget::from_component_allowances(
            self.budget,
            self.inspection,
            ordinary,
            lsp,
            self.visible_bytes,
        )
    }
}
