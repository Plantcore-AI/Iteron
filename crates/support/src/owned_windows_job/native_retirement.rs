//! One optional isolation lease and transport resource retained until actual physical retirement.
//! A caller/worker must first observe a waited leader and zero processes in its private Job.
use super::conpty::console::Console;
use crate::windows_process_isolation::WindowsProcessIsolation;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

pub(super) struct NativeLaunchRetirement {
    console: Option<Arc<Console>>,
    isolation: Option<Arc<WindowsProcessIsolation>>,
    claimed: bool,
    retirement_failed: bool,
    completion: Arc<RetirementCompletion>,
}
pub(super) struct RetirementCompletion {
    known: AtomicBool,
    notify: Notify,
}
impl RetirementCompletion {
    pub(super) async fn observe(&self, allowance: Duration) -> bool {
        tokio::time::timeout(allowance, async {
            loop {
                let notified = self.notify.notified();
                if self.known.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}
impl NativeLaunchRetirement {
    pub(super) fn new(
        console: Option<Arc<Console>>,
        isolation: Option<Arc<WindowsProcessIsolation>>,
    ) -> Self {
        Self {
            console,
            isolation,
            claimed: false,
            retirement_failed: false,
            completion: Arc::new(RetirementCompletion {
                known: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }
    pub(super) fn isolation(&self) -> Option<&WindowsProcessIsolation> {
        self.isolation.as_deref()
    }
    pub(super) fn claim(&mut self) -> io::Result<()> {
        if let Some(isolation) = &self.isolation {
            isolation.claim_launch()?;
            self.claimed = true;
        }
        Ok(())
    }
    pub(super) fn observation(&self) -> Arc<RetirementCompletion> {
        self.completion.clone()
    }
    pub(super) fn needs_worker(&self) -> bool {
        self.claimed && self.isolation.is_some()
    }
    pub(super) fn begin_close(&self) {
        if let Some(console) = &self.console {
            console.begin_close();
        }
    }
    pub(super) fn retire(&mut self) -> bool {
        if self
            .console
            .as_ref()
            .is_some_and(|console| !console.closed())
            || self.retirement_failed
        {
            return false;
        }
        if self.claimed {
            if let Some(isolation) = &self.isolation {
                if isolation.retire_after_terminal().is_err() {
                    // Keep this exact lease/physical admission after an uncertain ACL transaction.
                    self.retirement_failed = true;
                    return false;
                }
            }
            self.claimed = false;
        }
        self.isolation = None;
        self.completion.known.store(true, Ordering::Release);
        self.completion.notify.notify_waiters();
        true
    }
}
