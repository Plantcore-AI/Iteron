use iteron_obs::CostState;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One monetary ceiling shared by a parent and every descendant runtime agent. Projection commits update
/// it immediately, before a child ledger is merged, so no later provider admission can observe a
/// stale parent total. Atomic saturation keeps concurrent future fan-out fail-closed as well.
pub(super) struct SharedUsdBudget {
    ceiling_microusd: AtomicU64,
    spent_microusd: AtomicU64,
    unknown: AtomicBool,
}

impl SharedUsdBudget {
    pub(super) fn from_usd(ceiling_usd: f64) -> Self {
        Self::from_microusd(usd_to_microusd_ceiling(ceiling_usd))
    }

    pub(super) fn from_microusd(ceiling_microusd: u64) -> Self {
        Self {
            ceiling_microusd: AtomicU64::new(ceiling_microusd),
            spent_microusd: AtomicU64::new(0),
            unknown: AtomicBool::new(false),
        }
    }

    pub(super) fn requires_pricing(&self) -> bool {
        self.ceiling_microusd.load(Ordering::Acquire) > 0
    }

    /// Public `Agent::budget` remains source-compatible, but a caller may mutate it after
    /// construction. Synchronization is monotone: a new value can establish or tighten a ceiling,
    /// never widen or remove one already shared with descendants.
    pub(super) fn tighten_microusd(&self, proposed: u64) {
        let _ =
            self.ceiling_microusd
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.min(proposed))
                });
    }

    pub(super) fn ceiling_usd(&self) -> f64 {
        self.ceiling_microusd() as f64 / 1_000_000.0
    }

    pub(super) fn ceiling_microusd(&self) -> u64 {
        self.ceiling_microusd.load(Ordering::Acquire)
    }

    pub(super) fn record_projection(&self, amount_microusd: u64) {
        let _ = self
            .spent_microusd
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(amount_microusd))
            });
    }

    pub(super) fn restore(&self, state: &CostState) {
        match state {
            CostState::Known {
                amount_microusd, ..
            } => {
                self.spent_microusd
                    .store(*amount_microusd, Ordering::Release);
            }
            CostState::Zero => {
                self.spent_microusd.store(0, Ordering::Release);
            }
            CostState::Unknown { .. } => self.unknown.store(true, Ordering::Release),
        }
    }

    pub(super) fn mark_unknown(&self) {
        self.unknown.store(true, Ordering::Release);
    }

    pub(super) fn exhausted(&self) -> bool {
        let ceiling = self.ceiling_microusd.load(Ordering::Acquire);
        self.unknown.load(Ordering::Acquire)
            || self.spent_microusd.load(Ordering::Acquire) >= ceiling
    }
}

/// Cancellation-safe proof obligation for one dispatched provider request. Every successful path
/// explicitly completes the guard only after authoritative Usage and its signed projection enter
/// the ledger; an error, panic, or dropped async future leaves it armed and closes the ceiling.
pub(super) struct ProviderAttemptGuard {
    budget: Option<Arc<SharedUsdBudget>>,
    projected_at_unix_secs: u64,
    completed: bool,
}

impl ProviderAttemptGuard {
    pub(super) fn new(budget: Option<&Arc<SharedUsdBudget>>, projected_at_unix_secs: u64) -> Self {
        Self {
            budget: budget.filter(|budget| budget.requires_pricing()).cloned(),
            projected_at_unix_secs,
            completed: false,
        }
    }

    pub(super) fn projected_at_unix_secs(&self) -> u64 {
        self.projected_at_unix_secs
    }

    pub(super) fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for ProviderAttemptGuard {
    fn drop(&mut self) {
        if !self.completed
            && let Some(budget) = &self.budget
        {
            budget.mark_unknown();
        }
    }
}

pub(super) fn usd_to_microusd_ceiling(value: f64) -> u64 {
    let scaled = value * 1_000_000.0;
    if !scaled.is_finite() || scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.ceil() as u64
    }
}

/// Legacy `RunStart.max_usd` passed through binary floating point. Reconstruct it without ever
/// widening the recorded ceiling; new journals carry an exact fixed-point policy event instead.
pub(super) fn legacy_usd_to_microusd_floor(value: f64) -> u64 {
    let scaled = value * 1_000_000.0;
    if !scaled.is_finite() || scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.floor() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_projection_total_saturates_and_closes_at_the_ceiling() {
        let budget = SharedUsdBudget::from_usd(0.000_010);
        assert!(!budget.exhausted());
        budget.record_projection(4);
        budget.record_projection(6);
        assert!(budget.exhausted());
        budget.record_projection(u64::MAX);
        assert!(budget.exhausted());
    }

    #[test]
    fn dropped_provider_attempt_guard_closes_but_completed_guard_preserves_budget() {
        let budget = Arc::new(SharedUsdBudget::from_usd(1.0));
        ProviderAttemptGuard::new(Some(&budget), 1).complete();
        assert!(!budget.exhausted());
        drop(ProviderAttemptGuard::new(Some(&budget), 1));
        assert!(budget.exhausted());
    }
}
