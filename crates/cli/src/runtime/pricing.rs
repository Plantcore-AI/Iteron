use iteron_obs::CostState;
use iteron_protocol::TurnId;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::route_attempt_accounting::{
    ProviderRouteChargeLedger, ProviderRouteChargeReplay, VerifiedProviderRouteCharge,
};

/// One monetary ceiling shared by a parent and every descendant runtime agent. Projection commits update
/// it immediately, before a child ledger is merged, so no later provider admission can observe a
/// stale parent total. Atomic saturation keeps concurrent future fan-out fail-closed as well.
pub(super) struct SharedUsdBudget {
    parent: Option<Arc<SharedUsdBudget>>,
    depth: usize,
    ceiling_microusd: AtomicU64,
    spent_microusd: AtomicU64,
    unknown: AtomicBool,
    provider_dispatch_in_flight: AtomicBool,
    reserved_microusd: AtomicU64,
    reservation_settled: AtomicBool,
    route_charges: Mutex<ProviderRouteChargeLedger>,
}

impl SharedUsdBudget {
    pub(super) fn from_usd(ceiling_usd: f64) -> Self {
        Self::from_microusd(usd_to_microusd_ceiling(ceiling_usd))
    }

    pub(super) fn from_microusd(ceiling_microusd: u64) -> Self {
        Self {
            parent: None,
            depth: 0,
            ceiling_microusd: AtomicU64::new(ceiling_microusd),
            spent_microusd: AtomicU64::new(0),
            unknown: AtomicBool::new(false),
            provider_dispatch_in_flight: AtomicBool::new(false),
            reserved_microusd: AtomicU64::new(0),
            reservation_settled: AtomicBool::new(true),
            route_charges: Mutex::new(ProviderRouteChargeLedger::default()),
        }
    }

    /// Separate child ceiling with the same exact charge identity admitted into every ancestor.
    /// The host constructs the acyclic parent chain; model/client JSON cannot supply a parent.
    pub(super) fn child(ceiling_microusd: u64, parent: Arc<Self>) -> Result<Self, &'static str> {
        if parent.depth >= 64 {
            return Err("monetary ancestry exceeds its hard depth");
        }
        let mut child = Self::from_microusd(ceiling_microusd);
        child.depth = parent.depth + 1;
        child.parent = Some(parent);
        Ok(child)
    }
    pub(super) fn remaining_microusd(&self) -> Result<u64, &'static str> {
        if self.unknown.load(Ordering::Acquire) {
            return Err("monetary usage is unresolved");
        }
        let remaining = self
            .ceiling_microusd()
            .saturating_sub(self.spent_microusd.load(Ordering::Acquire))
            .saturating_sub(self.reserved_microusd.load(Ordering::Acquire));
        Ok(match &self.parent {
            Some(parent) => remaining.min(parent.remaining_microusd()?),
            None => remaining,
        })
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

    /// Commit a verified physical charge exactly once. The mutex protects identity admission and
    /// the atomic total update as one operation; another child cannot observe admission room
    /// between them.
    pub(super) fn commit_provider_route_charge(
        &self,
        charge: VerifiedProviderRouteCharge,
    ) -> Result<(), &'static str> {
        let amount = charge.amount_microusd;
        let mut ledger = self
            .route_charges
            .lock()
            .map_err(|_| "provider route charge ledger lock was poisoned")?;
        match ledger.contains_exact(&charge) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                self.mark_unknown();
                return Err(error);
            }
        }
        let reserved = self.reserved_microusd.load(Ordering::Acquire);
        if amount > reserved {
            self.mark_unknown();
            return Err("provider route charge exceeded its pre-dispatch reservation");
        }
        if let Some(parent) = &self.parent
            && let Err(error) = parent.commit_provider_route_charge(charge.clone())
        {
            self.mark_unknown();
            return Err(error);
        }
        if ledger.admit(charge)? {
            let Some(total) = self
                .spent_microusd
                .load(Ordering::Acquire)
                .checked_add(amount)
            else {
                self.mark_unknown();
                return Err("shared provider route charge total overflowed");
            };
            self.spent_microusd.store(total, Ordering::Release);
        }
        self.reserved_microusd.store(0, Ordering::Release);
        self.reservation_settled.store(true, Ordering::Release);
        Ok(())
    }

    /// Close one admitted route that provably never reached transport. It spends nothing and
    /// releases the current request reservation before any retry/fallback may reserve again.
    pub(super) fn settle_not_dispatched(&self) {
        if let Some(parent) = &self.parent {
            parent.settle_not_dispatched()
        }
        self.reserved_microusd.store(0, Ordering::Release);
        self.reservation_settled.store(true, Ordering::Release);
    }

    /// Restore a logical replay plus the independently verified physical route receipts. Exact
    /// logical-winner matches are subtracted from the physical total; every other physical charge
    /// remains additive. This is idempotent because the full route identity ledger is replaced,
    /// not appended to the process-local state.
    pub(super) fn restore_provider_route_charges(
        &self,
        logical: &CostState,
        replay: ProviderRouteChargeReplay,
    ) -> Result<(), &'static str> {
        let mut unknown = replay.ledger.is_unknown();
        let logical_amount = match logical {
            CostState::Known {
                amount_microusd, ..
            } => *amount_microusd,
            CostState::Zero => 0,
            CostState::Unknown { .. } => {
                unknown = true;
                0
            }
        };
        let extra = replay
            .ledger
            .amount_microusd()
            .checked_sub(replay.logical_winner_microusd)
            .ok_or("logical winner exceeds verified physical provider charges")?;
        let total = logical_amount
            .checked_add(extra)
            .ok_or("restored provider route charge total overflowed")?;
        if let Some(parent) = &self.parent {
            // Child replay merges exact verified physical identities. It never replaces the
            // parent's aggregate with one child's logical ledger or resurrects unknown effects.
            if total != replay.ledger.amount_microusd() {
                unknown = true;
            }
            parent.merge_recovered_charges(&replay.ledger)?;
            if unknown {
                parent.mark_unknown();
            }
        }
        let mut ledger = self
            .route_charges
            .lock()
            .map_err(|_| "provider route charge ledger lock was poisoned")?;
        *ledger = replay.ledger;
        self.spent_microusd.store(total, Ordering::Release);
        if !unknown && !self.unknown.load(Ordering::Acquire) {
            self.reserved_microusd.store(0, Ordering::Release);
            self.reservation_settled.store(true, Ordering::Release);
        }
        self.provider_dispatch_in_flight
            .store(false, Ordering::Release);
        self.unknown.fetch_or(unknown, Ordering::AcqRel);
        Ok(())
    }

    pub(super) fn merge_recovered_charges(
        &self,
        recovered: &ProviderRouteChargeLedger,
    ) -> Result<(), &'static str> {
        let result = self.merge_recovered_charges_inner(recovered);
        if result.is_err() {
            self.mark_unknown();
        }
        result
    }
    fn merge_recovered_charges_inner(
        &self,
        recovered: &ProviderRouteChargeLedger,
    ) -> Result<(), &'static str> {
        if let Some(parent) = &self.parent {
            parent.merge_recovered_charges(recovered)?
        }
        let mut ledger = self
            .route_charges
            .lock()
            .map_err(|_| "parent charge ledger lock was poisoned")?;
        for charge in recovered.verified_charges() {
            if ledger.contains_exact(charge)? {
                continue;
            }
            if ledger.admit(charge.clone())? {
                let total = self
                    .spent_microusd
                    .load(Ordering::Acquire)
                    .checked_add(charge.amount_microusd)
                    .ok_or("parent recovered charge overflowed")?;
                self.spent_microusd.store(total, Ordering::Release);
            }
        }
        if recovered.is_unknown() {
            self.unknown.store(true, Ordering::Release)
        }
        Ok(())
    }

    pub(super) fn mark_unknown(&self) {
        if let Some(parent) = &self.parent {
            parent.mark_unknown()
        }
        self.unknown.store(true, Ordering::Release);
    }

    pub(super) fn exhausted(&self) -> bool {
        let ceiling = self.ceiling_microusd.load(Ordering::Acquire);
        self.parent
            .as_ref()
            .is_some_and(|parent| parent.exhausted())
            || self.unknown.load(Ordering::Acquire)
            || self.spent_microusd.load(Ordering::Acquire) >= ceiling
    }

    fn try_acquire_provider_dispatch(&self, reservation_microusd: u64) -> Result<(), &'static str> {
        if self
            .provider_dispatch_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(
                "positive USD provider concurrency is serialized until signed per-attempt reservations are available",
            );
        }
        if let Some(parent) = &self.parent
            && let Err(error) = parent.try_acquire_provider_dispatch(reservation_microusd)
        {
            self.provider_dispatch_in_flight
                .store(false, Ordering::Release);
            return Err(error);
        }
        if let Err(error) = self.reserve_local(reservation_microusd) {
            if let Some(parent) = &self.parent {
                parent.settle_not_dispatched();
                parent.release_provider_dispatch()
            }
            self.provider_dispatch_in_flight
                .store(false, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn reserve_provider_attempt(
        &self,
        reservation_microusd: u64,
    ) -> Result<(), &'static str> {
        if let Some(parent) = &self.parent {
            parent.reserve_provider_attempt(reservation_microusd)?
        }
        if let Err(error) = self.reserve_local(reservation_microusd) {
            if let Some(parent) = &self.parent {
                parent.settle_not_dispatched()
            }
            return Err(error);
        }
        Ok(())
    }
    fn reserve_local(&self, reservation_microusd: u64) -> Result<(), &'static str> {
        let _ledger = self
            .route_charges
            .lock()
            .map_err(|_| "provider route charge ledger lock was poisoned")?;
        if self.unknown.load(Ordering::Acquire) {
            return Err("provider monetary effects remain unresolved");
        }
        if self.reservation_is_unsettled() {
            return Err("a provider cost reservation is already active");
        }
        let spent = self.spent_microusd.load(Ordering::Acquire);
        let required = spent
            .checked_add(reservation_microusd)
            .ok_or("provider cost reservation overflowed")?;
        if required > self.ceiling_microusd.load(Ordering::Acquire) {
            return Err("remaining USD ceiling cannot cover the provider request upper bound");
        }
        self.reserved_microusd
            .store(reservation_microusd, Ordering::Release);
        self.reservation_settled.store(false, Ordering::Release);
        Ok(())
    }

    fn release_provider_dispatch(&self) {
        // Unknown reservation evidence stays charged until independently reconciled.
        if self.reservation_settled.load(Ordering::Acquire) {
            self.reserved_microusd.store(0, Ordering::Release)
        }
        if let Some(parent) = &self.parent {
            parent.release_provider_dispatch()
        }
        self.provider_dispatch_in_flight
            .store(false, Ordering::Release);
    }

    pub(super) fn active_reservation_microusd(&self) -> Option<u64> {
        self.reservation_is_unsettled()
            .then(|| self.reserved_microusd.load(Ordering::Acquire))
    }

    pub(super) fn has_known_provider_charge_for(
        &self,
        tenant: &iteron_protocol::TenantId,
        run_id: &iteron_protocol::RunId,
        turn: TurnId,
    ) -> bool {
        self.route_charges
            .lock()
            .is_ok_and(|ledger| ledger.has_known_charge_for(tenant, run_id, turn))
    }

    fn reservation_is_unsettled(&self) -> bool {
        !self.reservation_settled.load(Ordering::Acquire)
    }

    pub(super) fn spent_microusd(&self) -> u64 {
        self.spent_microusd.load(Ordering::Acquire)
    }
}

/// Cancellation-safe proof obligation for one dispatched provider request. Every successful path
/// explicitly completes the guard only after authoritative Usage and its signed projection enter
/// the ledger; an error, panic, or dropped async future leaves it armed and closes the ceiling.
pub(super) struct ProviderAttemptGuard {
    budget: Option<Arc<SharedUsdBudget>>,
    #[cfg(test)]
    projected_at_unix_secs: u64,
    completed: bool,
    owns_dispatch_lane: bool,
}

impl ProviderAttemptGuard {
    pub(super) fn new(
        budget: Option<&Arc<SharedUsdBudget>>,
        _projected_at_unix_secs: u64,
        reservation_microusd: Option<u64>,
    ) -> Result<Self, &'static str> {
        let budget = budget.filter(|budget| budget.requires_pricing()).cloned();
        let owns_dispatch_lane = match &budget {
            Some(budget) => {
                let reservation = reservation_microusd
                    .ok_or("positive USD request has no conservative cost reservation")?;
                budget.try_acquire_provider_dispatch(reservation)?;
                true
            }
            None => false,
        };
        Ok(Self {
            budget,
            #[cfg(test)]
            projected_at_unix_secs: _projected_at_unix_secs,
            completed: false,
            owns_dispatch_lane,
        })
    }

    #[cfg(test)]
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
            && budget.reservation_is_unsettled()
        {
            budget.mark_unknown();
        }
        if self.owns_dispatch_lane
            && let Some(budget) = &self.budget
        {
            budget.release_provider_dispatch();
            self.owns_dispatch_lane = false;
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
        budget.mark_unknown();
        assert!(budget.exhausted());
    }

    #[test]
    fn dropped_provider_attempt_guard_closes_but_completed_guard_preserves_budget() {
        let budget = Arc::new(SharedUsdBudget::from_usd(1.0));
        let first = ProviderAttemptGuard::new(Some(&budget), 1, Some(1)).unwrap();
        budget.settle_not_dispatched();
        first.complete();
        assert!(!budget.exhausted());
        drop(ProviderAttemptGuard::new(Some(&budget), 1, Some(1)).unwrap());
        assert!(budget.exhausted());
    }

    #[test]
    fn definite_zero_dispatch_releases_reservation_without_poisoning_budget() {
        let budget = Arc::new(SharedUsdBudget::from_microusd(10));
        let guard = ProviderAttemptGuard::new(Some(&budget), 1, Some(6)).unwrap();
        budget.settle_not_dispatched();
        drop(guard);
        assert_eq!(budget.spent_microusd(), 0);
        assert!(!budget.exhausted());
        assert!(budget.active_reservation_microusd().is_none());
    }

    #[test]
    fn one_logical_lane_can_reserve_each_followup_after_a_settled_route() {
        let budget = Arc::new(SharedUsdBudget::from_microusd(10));
        let guard = ProviderAttemptGuard::new(Some(&budget), 1, Some(6)).unwrap();
        budget.settle_not_dispatched();
        assert!(budget.active_reservation_microusd().is_none());
        budget.reserve_provider_attempt(4).unwrap();
        assert_eq!(budget.active_reservation_microusd(), Some(4));
        budget.settle_not_dispatched();
        drop(guard);
        assert!(!budget.exhausted());
    }

    #[test]
    fn reservation_gate_refuses_oversize_and_concurrent_attempts_without_unknown_cost() {
        let budget = Arc::new(SharedUsdBudget::from_microusd(10));
        assert!(ProviderAttemptGuard::new(Some(&budget), 1, Some(11)).is_err());
        assert_eq!(budget.spent_microusd(), 0);
        assert!(!budget.exhausted());

        let first = ProviderAttemptGuard::new(Some(&budget), 1, Some(6)).unwrap();
        assert!(ProviderAttemptGuard::new(Some(&budget), 1, Some(4)).is_err());
        assert_eq!(budget.spent_microusd(), 0);
        assert!(!budget.exhausted());
        budget.settle_not_dispatched();
        drop(first);
        assert!(!budget.exhausted());
    }
}

#[cfg(test)]
mod child_chain_tests {
    use super::*;
    fn charge(run: &str, amount: u64) -> VerifiedProviderRouteCharge {
        VerifiedProviderRouteCharge {
            identity: iteron_protocol::CostProjectionIdentity {
                tenant_id: "tenant".into(),
                run_id: run.into(),
                turn_id: 1,
                provider_attempt: 1,
                attribution: None,
            },
            projection_digest: format!("digest-{run}"),
            amount_microusd: amount,
        }
    }
    #[test]
    fn separate_child_caps_do_not_tighten_parent_and_charge_once() {
        let parent = Arc::new(SharedUsdBudget::from_microusd(20));
        let child = Arc::new(SharedUsdBudget::child(6, parent.clone()).unwrap());
        assert!(ProviderAttemptGuard::new(Some(&child), 1, Some(7)).is_err());
        assert_eq!(parent.ceiling_microusd(), 20);
        assert_eq!(parent.active_reservation_microusd(), None);
        let guard = ProviderAttemptGuard::new(Some(&child), 1, Some(6)).unwrap();
        let known = charge("child", 4);
        child.commit_provider_route_charge(known.clone()).unwrap();
        child.commit_provider_route_charge(known).unwrap();
        guard.complete();
        assert_eq!(child.spent_microusd(), 4);
        assert_eq!(parent.spent_microusd(), 4);
        assert!(ProviderAttemptGuard::new(Some(&child), 2, Some(3)).is_err());
        let sibling = Arc::new(SharedUsdBudget::child(16, parent.clone()).unwrap());
        let guard = ProviderAttemptGuard::new(Some(&sibling), 2, Some(16)).unwrap();
        sibling.settle_not_dispatched();
        guard.complete();
        assert_eq!(parent.spent_microusd(), 4);
    }
    #[test]
    fn unknown_child_retains_reserved_upper_bound_in_every_ancestor() {
        let parent = Arc::new(SharedUsdBudget::from_microusd(20));
        let child = Arc::new(SharedUsdBudget::child(10, parent.clone()).unwrap());
        drop(ProviderAttemptGuard::new(Some(&child), 1, Some(8)).unwrap());
        assert!(child.exhausted());
        assert!(parent.exhausted());
        assert_eq!(child.active_reservation_microusd(), Some(8));
        assert_eq!(parent.active_reservation_microusd(), Some(8));
        let sibling = Arc::new(SharedUsdBudget::child(10, parent.clone()).unwrap());
        assert!(ProviderAttemptGuard::new(Some(&sibling), 2, Some(1)).is_err());
    }
    #[test]
    fn replay_merges_exact_physical_identity_without_replacing_siblings() {
        let parent = Arc::new(SharedUsdBudget::from_microusd(20));
        let mut first = ProviderRouteChargeLedger::default();
        first.admit(charge("first", 4)).unwrap();
        let mut second = ProviderRouteChargeLedger::default();
        second.admit(charge("second", 5)).unwrap();
        parent.merge_recovered_charges(&first).unwrap();
        parent.merge_recovered_charges(&second).unwrap();
        parent.merge_recovered_charges(&first).unwrap();
        assert_eq!(parent.spent_microusd(), 9);
    }
}
