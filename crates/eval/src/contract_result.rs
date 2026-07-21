//! Semantic projections of a strictly decoded Core CLI result.

use crate::contract::{CliFinalResult, ContractError};
use crate::types::{CostObservation, RunStatus};

impl CliFinalResult {
    pub fn run_status(&self) -> RunStatus {
        match self.outcome.as_str() {
            "done" | "drained" if self.success => RunStatus::Completed,
            "budget_exhausted" | "interrupted" | "stuck" => RunStatus::Censored,
            _ => RunStatus::Errored,
        }
    }

    pub fn cost(&self) -> Result<CostObservation, ContractError> {
        match self.cost_status.as_str() {
            "known" => {
                let usd = self.cost_usd.ok_or(ContractError::KnownCostMissing)?;
                if !usd.is_finite() || usd < 0.0 {
                    return Err(ContractError::InvalidKnownCost);
                }
                Ok(CostObservation::known(usd))
            }
            "zero" => Ok(CostObservation::zero()),
            "unknown" => Ok(CostObservation::unknown(self.cost_reason.clone())),
            other => Err(ContractError::UnknownCostStatus(other.to_owned())),
        }
    }
}
