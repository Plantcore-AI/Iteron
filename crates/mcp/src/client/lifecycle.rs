use super::McpClient;
use tokio::process::Child;

pub(super) async fn terminate_and_reap(child: &mut Child) {
    core_sandbox::terminate_process_group_and_reap(child).await;
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };

        // Move the process into a reaper task so dropping in Tokio both kills and waits instead of
        // leaving a Unix zombie. Outside Tokio, the process driver gets the handle after kill.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                terminate_and_reap(&mut child).await;
            });
        } else {
            let _ = child.start_kill();
        }
    }
}
