//! The scheduler's time capability port.
//!
//! Backoff waits used to be a direct `tokio::time::sleep` call buried in the
//! retry layer, so the scheduler's only clock was the ambient runtime clock —
//! unmediated and impossible to broker or virtualize from outside the crate.
//! [`Clock`] turns that seam into an injected port with a single default backed
//! by tokio ([`TokioClock`]); the retry scheduler sleeps through the injected
//! port instead of constructing the wait itself (D2-21).

use async_trait::async_trait;
use std::time::Duration;

/// Injected time port for the scheduler. The retry/backoff layer waits through
/// this seam, so a host can broker, virtualize, or observe scheduler sleeps
/// without the scheduler reaching for the runtime clock directly.
#[async_trait]
pub trait Clock: Send + Sync {
    /// Sleep for `dur`. The default port awaits the real runtime timer; a test or
    /// virtual clock may return immediately while recording the requested wait.
    async fn sleep(&self, dur: Duration);
}

/// Default clock port, backed by the tokio runtime timer. This is the only place
/// the scheduler is permitted to touch the ambient wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioClock;

#[async_trait]
impl Clock for TokioClock {
    async fn sleep(&self, dur: Duration) {
        tokio::time::sleep(dur).await;
    }
}
