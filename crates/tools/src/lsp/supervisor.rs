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
    active_deadline: tokio::time::Instant,
    total_deadline: tokio::time::Instant,
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
        active_deadline,
        cancel_rx,
    ));
    let result = await_owned_until(operation, total_deadline).await?;
    cancellation.disarm();
    result
}

/// Wait for the runtime-owned lifecycle task through the inclusive user-visible deadline.
///
/// A timeout deliberately drops (detaches) rather than aborts the join handle. The caller's
/// cancellation guard then notifies the still-owned task. That task spends the process-group
/// capability before any direct-child reap and completes the bounded reap/stderr retirement
/// attempts. Since that cleanup is not yet proven, the returned effect outcome is Unknown.
async fn await_owned_until<T>(
    mut operation: tokio::task::JoinHandle<T>,
    total_deadline: tokio::time::Instant,
) -> Result<T, RunFailure> {
    tokio::select! {
        biased;
        joined = &mut operation => joined
            .map_err(|_| RunFailure::new(LspToolError::CleanupUnknown, true)),
        _ = tokio::time::sleep_until(total_deadline) =>
            Err(RunFailure::new(LspToolError::CleanupUnknown, true)),
    }
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
    use super::{CancellationOnDrop, await_owned_until};
    use crate::lsp::LspToolError;
    use std::time::Duration;

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

    #[tokio::test(start_paused = true)]
    async fn total_deadline_returns_unknown_without_aborting_owned_cleanup() {
        let (cancel_sender, cancel_receiver) = tokio::sync::oneshot::channel();
        let cancellation = CancellationOnDrop(Some(cancel_sender));
        let (cancel_seen_sender, cancel_seen_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        let (retired_sender, retired_receiver) = tokio::sync::oneshot::channel();
        let operation = tokio::spawn(async move {
            cancel_receiver.await.unwrap();
            cancel_seen_sender.send(()).unwrap();
            release_receiver.await.unwrap();
            retired_sender.send(()).unwrap();
        });
        let started = tokio::time::Instant::now();
        let waiter = tokio::spawn(await_owned_until(
            operation,
            started + Duration::from_secs(70),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(69)).await;
        assert!(!waiter.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        let failure = waiter.await.unwrap().unwrap_err();
        assert!(matches!(failure.error, LspToolError::CleanupUnknown));
        assert!(failure.outcome_unknown);

        drop(cancellation);
        cancel_seen_receiver.await.unwrap();
        release_sender.send(()).unwrap();
        retired_receiver.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn completed_owned_task_wins_at_the_inclusive_deadline() {
        let operation = tokio::spawn(async { 42_u8 });
        while !operation.is_finished() {
            tokio::task::yield_now().await;
        }
        let value = await_owned_until(operation, tokio::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(value, 42);
    }
}
