//! Actual invocation/parent deadline ownership. Dropping a lease releases only its own bound;
//! borrowed parent deadlines remain live. The default owner allocates no heap or clock.
use super::KernelError;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const MAX_DEADLINE_LEASES: usize = 16;

#[derive(Default)]
pub(super) struct ExecutionDeadlineOwner {
    inherited: Option<Instant>,
    active: Vec<Weak<DeadlineBound>>,
}
struct DeadlineBound {
    deadline: Instant,
}
/// Private, non-cloneable proof of one in-process deadline's actual lifetime. No destructor can
/// clear a parent's lease; the owner observes only the bounds that still have physical owners.
pub(super) struct DeadlineLease {
    _bound: Option<Arc<DeadlineBound>>,
}

impl ExecutionDeadlineOwner {
    pub(super) fn current(&self) -> Option<Instant> {
        self.active
            .iter()
            .filter_map(Weak::upgrade)
            .map(|bound| bound.deadline)
            .chain(self.inherited)
            .min()
    }

    /// Only trusted child/operator composition binds an external deadline. This never erases or
    /// widens a separately held Main/ancestor lease.
    pub(super) fn bind_external(&mut self, deadline: Option<Instant>) {
        self.inherited = deadline;
    }

    pub(super) fn begin_invocation(
        &mut self,
        wall_secs: u64,
    ) -> Result<DeadlineLease, KernelError> {
        if self.current().is_some() {
            return Ok(DeadlineLease { _bound: None });
        }
        self.tighten(
            Instant::now()
                .checked_add(Duration::from_secs(wall_secs))
                .unwrap_or_else(Instant::now),
        )
    }

    pub(super) fn tighten(&mut self, deadline: Instant) -> Result<DeadlineLease, KernelError> {
        self.active.retain(|lease| lease.strong_count() != 0);
        if self.active.len() == MAX_DEADLINE_LEASES {
            return Err(KernelError::ContextResolution(
                "bounded execution deadline ownership is full".into(),
            ));
        }
        let bound = Arc::new(DeadlineBound { deadline });
        self.active.push(Arc::downgrade(&bound));
        Ok(DeadlineLease {
            _bound: Some(bound),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionDeadlineOwner, MAX_DEADLINE_LEASES};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn cancelled_actual_invocation_future_releases_only_its_owned_deadline() {
        let mut owner = ExecutionDeadlineOwner::default();
        let lease = owner.begin_invocation(30).unwrap();
        assert!(owner.current().is_some());
        let (entered, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _lease = lease;
            let _ = entered.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(owner.current(), None);
        let parent = Instant::now() + Duration::from_secs(10);
        owner.bind_external(Some(parent));
        let child = owner.begin_invocation(30).unwrap();
        drop(child);
        assert_eq!(owner.current(), Some(parent));
    }

    #[test]
    fn parent_tightening_drop_restores_exact_live_ancestor_without_copied_ownership() {
        let mut owner = ExecutionDeadlineOwner::default();
        let ancestor = Instant::now() + Duration::from_secs(30);
        let ancestor_lease = owner.tighten(ancestor).unwrap();
        let parent = Instant::now() + Duration::from_secs(10);
        let parent_lease = owner.tighten(parent).unwrap();
        let child = owner.begin_invocation(50).unwrap();
        drop(child);
        assert_eq!(owner.current(), Some(parent));
        drop(parent_lease);
        assert_eq!(owner.current(), Some(ancestor));
        owner.bind_external(None);
        assert_eq!(owner.current(), Some(ancestor));
        drop(ancestor_lease);
        assert_eq!(owner.current(), None);
    }

    #[test]
    fn expired_leases_are_retired_and_live_parent_bounds_remain_finite() {
        let mut owner = ExecutionDeadlineOwner::default();
        for _ in 0..1_000 {
            drop(owner.tighten(Instant::now()).unwrap());
        }
        let held = (0..MAX_DEADLINE_LEASES)
            .map(|_| owner.tighten(Instant::now()).unwrap())
            .collect::<Vec<_>>();
        assert!(owner.tighten(Instant::now()).is_err());
        drop(held);
        assert!(owner.tighten(Instant::now()).is_ok());
    }
}
