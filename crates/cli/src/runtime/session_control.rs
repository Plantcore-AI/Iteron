//! Single mutable cooperative control owner. Transport/child/tool ports receive cloned signals;
//! only the admitted runtime owner clears a control after its actual terminal barrier.
use super::KernelError;
use iteron_provider::ProviderError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum InboundControl {
    #[default]
    None,
    Interrupt,
    ForceCancel,
    Drain,
}

impl InboundControl {
    pub(super) fn interrupts(self) -> bool {
        matches!(self, Self::Interrupt | Self::ForceCancel | Self::Drain)
    }
}

#[derive(Clone)]
pub(super) struct InterruptSignalBinding {
    flag: Option<Arc<AtomicBool>>,
    owns_signal: bool,
}
impl InterruptSignalBinding {
    pub(super) fn flag(&self) -> Option<&Arc<AtomicBool>> {
        self.flag.as_ref()
    }
}

pub(super) struct SessionControlState {
    interrupt: Option<Arc<AtomicBool>>,
    force_cancel: Arc<AtomicBool>,
    drain: Arc<AtomicBool>,
    interrupt_requested: bool,
    force_cancel_requested: bool,
    drain_requested: bool,
    owns_drain: bool,
    owns_interrupt: bool,
    owns_force_cancel: bool,
}
impl Default for SessionControlState {
    fn default() -> Self {
        Self {
            interrupt: None,
            force_cancel: Arc::new(AtomicBool::new(false)),
            drain: Arc::new(AtomicBool::new(false)),
            interrupt_requested: false,
            force_cancel_requested: false,
            drain_requested: false,
            owns_drain: true,
            owns_interrupt: true,
            owns_force_cancel: true,
        }
    }
}
impl SessionControlState {
    pub(super) fn requested(&self) -> InboundControl {
        if self.force_cancel_requested || self.force_cancel.load(Ordering::Acquire) {
            InboundControl::ForceCancel
        } else if self.drain_requested || self.drain.load(Ordering::Relaxed) {
            InboundControl::Drain
        } else if self.interrupt_requested
            || self
                .interrupt
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            InboundControl::Interrupt
        } else {
            InboundControl::None
        }
    }
    pub(super) fn request(&mut self, control: InboundControl) {
        match control {
            InboundControl::Interrupt => {
                self.interrupt_requested = true;
                if let Some(flag) = &self.interrupt {
                    flag.store(true, Ordering::Relaxed);
                }
            }
            InboundControl::ForceCancel => {
                self.force_cancel_requested = true;
                self.force_cancel.store(true, Ordering::Release);
            }
            InboundControl::Drain => {
                self.drain_requested = true;
                self.drain.store(true, Ordering::Relaxed);
            }
            InboundControl::None => {}
        }
    }
    pub(super) fn interrupt(&self) -> Option<&Arc<AtomicBool>> {
        self.interrupt.as_ref()
    }
    pub(super) fn force_cancel(&self) -> &Arc<AtomicBool> {
        &self.force_cancel
    }
    pub(super) fn drain(&self) -> &Arc<AtomicBool> {
        &self.drain
    }
    pub(super) fn interrupt_binding(&self) -> InterruptSignalBinding {
        InterruptSignalBinding {
            flag: self.interrupt.clone(),
            owns_signal: self.owns_interrupt,
        }
    }
    pub(super) fn restore_interrupt_binding(&mut self, binding: InterruptSignalBinding) {
        self.interrupt = binding.flag;
        self.owns_interrupt = binding.owns_signal;
    }
    pub(super) fn bind_interrupt(&mut self, flag: Arc<AtomicBool>) {
        self.interrupt = Some(flag);
        self.owns_interrupt = true;
    }
    pub(super) fn bind_force_cancel(&mut self, flag: Arc<AtomicBool>) {
        self.force_cancel = flag;
        self.owns_force_cancel = true;
    }
    pub(super) fn inherit_interrupt(&mut self, flag: Arc<AtomicBool>) {
        self.interrupt = Some(flag);
        self.owns_interrupt = false;
    }
    pub(super) fn inherit_force_cancel(&mut self, flag: Arc<AtomicBool>) {
        self.force_cancel = flag;
        self.owns_force_cancel = false;
    }
    pub(super) fn bind_drain(&mut self, flag: Arc<AtomicBool>) {
        self.drain = flag;
        self.owns_drain = true;
    }
    pub(super) fn inherit_drain(&mut self, flag: Arc<AtomicBool>) {
        self.drain = flag;
        self.owns_drain = false;
    }
    pub(super) fn clear_interrupt_after_terminal(&mut self) {
        self.interrupt_requested = false;
        if self.owns_interrupt
            && let Some(flag) = &self.interrupt
        {
            flag.store(false, Ordering::SeqCst);
        }
    }
    pub(super) fn clear_force_cancel_after_terminal(&mut self) {
        self.force_cancel_requested = false;
        if self.owns_force_cancel {
            self.force_cancel.store(false, Ordering::SeqCst);
        }
    }
    pub(super) fn clear_drain_after_terminal(&mut self) {
        self.drain_requested = false;
        if self.owns_drain {
            self.drain.store(false, Ordering::Relaxed);
        }
    }
    /// Adoption resets local prior-run requests. Every external atomic retains its current
    /// value; adoption is not a receipt of physical shutdown or authority to erase a new stop.
    pub(super) fn reset_after_adoption(&mut self) {
        self.interrupt_requested = false;
        self.force_cancel_requested = false;
    }
    pub(super) fn clear_cancel_after_terminal(&mut self) {
        self.clear_force_cancel_after_terminal();
        self.clear_interrupt_after_terminal();
    }
    pub(super) fn provider_refusal(&self, deadline: Option<Instant>) -> Option<KernelError> {
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Some(ProviderError::DeadlineExceeded.into());
        }
        (self.requested() != InboundControl::None).then(|| ProviderError::Interrupted.into())
    }
    /// No paid request or queue mutation occurs during this wait. The same actual local latches
    /// and inherited signals are checked, including embedders without an interrupt atomic.
    pub(super) async fn wait_retry(
        &self,
        delay: Duration,
        run_deadline: Option<Instant>,
        poll: Duration,
    ) -> Result<(), KernelError> {
        let until = Instant::now()
            .checked_add(delay)
            .unwrap_or_else(Instant::now);
        loop {
            if let Some(error) = self.provider_refusal(run_deadline) {
                return Err(error);
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            tokio::time::sleep(remaining.min(poll.max(Duration::from_millis(1)))).await;
        }
    }
}

#[cfg(test)]
#[path = "session_control_tests.rs"]
mod tests;
