//! Bounded admission liveness for an explicitly requested orchestration invocation. A cancelled
//! invocation cannot leave the resident stuck in the previous invocation's topology flag.
use super::KernelError;
use std::sync::{Arc, Weak};

#[derive(Default)]
pub(super) struct OrchestrationLifetime {
    active: Weak<()>,
}
pub(super) struct OrchestrationLease {
    _active: Arc<()>,
}
impl OrchestrationLifetime {
    pub(super) fn active(&self) -> bool {
        self.active.strong_count() != 0
    }
    pub(super) fn enter(&mut self) -> Result<OrchestrationLease, KernelError> {
        if self.active() {
            return Err(KernelError::ContextResolution(
                "an orchestration invocation is already owned".into(),
            ));
        }
        let active = Arc::new(());
        self.active = Arc::downgrade(&active);
        Ok(OrchestrationLease { _active: active })
    }
}

#[cfg(test)]
mod tests {
    use super::OrchestrationLifetime;
    #[test]
    fn error_or_future_drop_releases_only_the_actual_orchestration_invocation() {
        let mut owner = OrchestrationLifetime::default();
        let lease = owner.enter().unwrap();
        assert!(owner.active());
        assert!(owner.enter().is_err());
        drop(lease);
        assert!(!owner.active());
        assert!(owner.enter().is_ok());
    }
}
