use super::input::SourceDocument;
use super::session::{Launcher, LiveResult, RunFailure, run_query_owned};
use super::{LspToolError, QueryKind};
use std::sync::Arc;

/// Keep lifecycle cleanup owned after the registry future is cancelled. Dropping the caller-side
/// future signals the owned task; the owned task then spends the process-group capability, reaps
/// the direct child, and joins stderr before it retires.
pub(super) async fn run_query(
    launcher: &Launcher,
    document: Arc<SourceDocument>,
    query: QueryKind,
    sensitive_env_names: Vec<String>,
    deadline: tokio::time::Instant,
) -> Result<LiveResult, RunFailure> {
    let epoch = launcher
        .mint_epoch()
        .map_err(|error| RunFailure::new(error, false))?;
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let mut cancellation = CancellationOnDrop(Some(cancel_tx));
    let operation = tokio::spawn(run_query_owned(
        epoch,
        document,
        query,
        sensitive_env_names,
        deadline,
        cancel_rx,
    ));
    let result = operation
        .await
        .map_err(|_| RunFailure::new(LspToolError::CleanupUnknown, true))?;
    cancellation.disarm();
    result
}

struct CancellationOnDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl CancellationOnDrop {
    fn disarm(&mut self) {
        drop(self.0.take());
    }
}

impl Drop for CancellationOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CancellationOnDrop;

    #[tokio::test]
    async fn dropping_the_guard_notifies_the_owned_supervisor() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        drop(CancellationOnDrop(Some(sender)));
        receiver.await.unwrap();
    }

    #[tokio::test]
    async fn disarming_the_guard_does_not_report_cancellation() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut guard = CancellationOnDrop(Some(sender));
        guard.disarm();
        drop(guard);
        assert!(receiver.await.is_err());
    }
}
