//! One optional isolation lease and transport resource retained until actual physical retirement.
//! A caller/worker must first observe a waited leader and zero processes in its private Job.
use super::conpty::console::Console;
use crate::durable_windows_state::WindowsPrivateScratch;
use crate::windows_process_isolation::{WindowsIsolationLaunch, WindowsProcessIsolation};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

pub(super) struct NativeLaunchRetirement {
    console: Option<Arc<Console>>,
    launch: Option<WindowsIsolationLaunch>,
    scratch: Option<WindowsPrivateScratch>,
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
                tokio::pin!(notified);
                notified.as_mut().enable();
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
    ) -> io::Result<Self> {
        let launch = isolation
            .as_ref()
            .map(WindowsProcessIsolation::reserve_launch)
            .transpose()?;
        Ok(Self {
            console,
            launch,
            scratch: None,
            completion: Arc::new(RetirementCompletion {
                known: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        })
    }
    pub(super) fn isolation(&self) -> Option<&WindowsProcessIsolation> {
        self.launch.as_ref().map(WindowsIsolationLaunch::isolation)
    }
    pub(super) fn install(&self) -> io::Result<()> {
        if let Some(launch) = &self.launch {
            launch.install()?;
        }
        Ok(())
    }
    pub(super) fn bind_scratch(&mut self, scratch: WindowsPrivateScratch) {
        self.scratch = Some(scratch);
    }
    pub(super) fn provision_scratch(&mut self) -> io::Result<()> {
        self.scratch
            .as_mut()
            .ok_or_else(|| io::Error::other("native scratch custody missing"))?
            .provision()
    }
    pub(super) fn scratch_file(&self) -> io::Result<&std::fs::File> {
        self.scratch
            .as_ref()
            .ok_or_else(|| io::Error::other("native scratch custody missing"))?
            .file()
    }
    pub(super) fn bind_isolation(
        &mut self,
        isolation: &Arc<WindowsProcessIsolation>,
    ) -> io::Result<()> {
        if self.launch.is_some() {
            return Err(io::Error::other("native isolation already reserved"));
        }
        self.launch = Some(isolation.reserve_launch()?);
        Ok(())
    }
    pub(super) fn bind_console(&mut self, console: Arc<Console>) {
        self.console = Some(console);
    }
    pub(super) fn observation(&self) -> Arc<RetirementCompletion> {
        self.completion.clone()
    }
    pub(super) fn needs_worker(&self) -> bool {
        self.launch.is_some() || self.scratch.is_some()
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
        {
            return false;
        }
        if let Some(launch) = &self.launch {
            if launch.retire_after_terminal().is_err() {
                // Only this sealed reservation owns cleanup; a reused Arc never mints it.
                // Retain the same reservation for the physical worker's bounded later probes.
                // The backend removes only this fresh SID and tracks each completed revocation.
                return false;
            }
        }
        self.launch = None;
        if let Some(scratch) = &mut self.scratch {
            if scratch.retire().is_err() {
                return false;
            }
        }
        self.scratch = None;
        self.completion.known.store(true, Ordering::Release);
        self.completion.notify.notify_waiters();
        true
    }
}
