//! The actual process handles consumed by the shared native collector.

use std::future::Future;
use std::io;
use std::process::ExitStatus;

/// Concrete child methods, with no callbacks into a runtime or presentation owner.
pub(crate) trait CollectedChild: Send {
    fn process_id(&self) -> Option<u32>;
    fn request_kill(&mut self) -> io::Result<()>;
    fn wait_status(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send;

    #[cfg(windows)]
    fn retained_job(
        &self,
    ) -> Option<std::sync::Arc<iteron_support::owned_windows_job::OwnedWindowsJob>> {
        None
    }
}

impl CollectedChild for tokio::process::Child {
    fn process_id(&self) -> Option<u32> {
        self.id()
    }
    fn request_kill(&mut self) -> io::Result<()> {
        self.start_kill()
    }
    fn wait_status(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send {
        self.wait()
    }
}

#[cfg(windows)]
impl CollectedChild for iteron_support::owned_windows_job::OwnedWindowsChild {
    fn process_id(&self) -> Option<u32> {
        self.id()
    }
    fn request_kill(&mut self) -> io::Result<()> {
        self.start_kill()
    }
    fn wait_status(&mut self) -> impl Future<Output = io::Result<ExitStatus>> + Send {
        self.wait()
    }
    fn retained_job(
        &self,
    ) -> Option<std::sync::Arc<iteron_support::owned_windows_job::OwnedWindowsJob>> {
        Some(self.job())
    }
}
