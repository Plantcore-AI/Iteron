//! Process-wide bounded executor for background workflow runs.

use crate::events::ProgressSink;
use crate::spawner::AgentSpawner;
use crate::{RunReport, RunSpec};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

const DEFAULT_DISPATCH_THREADS: usize = 4;
const DEFAULT_QUEUE_CAPACITY: usize = 64;

pub(super) struct ExecutorJob {
    pub(super) spec: RunSpec,
    pub(super) spawner: Arc<dyn AgentSpawner>,
    pub(super) sink: Arc<dyn ProgressSink>,
    pub(super) cancel: CancellationToken,
    pub(super) result: oneshot::Sender<anyhow::Result<RunReport>>,
}

struct WorkflowExecutor {
    sender: std::sync::mpsc::SyncSender<ExecutorJob>,
}

impl WorkflowExecutor {
    fn new() -> Result<Self, String> {
        let queue_capacity = iteron_tunables::param_usize(
            "workflow.executor.default_queue_capacity",
            DEFAULT_QUEUE_CAPACITY,
        )
        .clamp(1, 1_024);
        let dispatch_threads = iteron_tunables::param_usize(
            "workflow.executor.default_dispatch_threads",
            DEFAULT_DISPATCH_THREADS,
        )
        .clamp(1, 16);
        let runtime_threads = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4)
            .saturating_sub(1)
            .clamp(1, 16);
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(runtime_threads)
                .enable_all()
                .thread_name("iteron-workflow-runtime")
                .build()
                .map_err(|error| error.to_string())?,
        );
        let (sender, receiver) = std::sync::mpsc::sync_channel::<ExecutorJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..dispatch_threads {
            let receiver = Arc::clone(&receiver);
            let runtime = Arc::clone(&runtime);
            std::thread::Builder::new()
                .name(format!("iteron-workflow-dispatch-{index}"))
                .spawn(move || worker_loop(receiver, runtime))
                .map_err(|error| error.to_string())?;
        }
        Ok(Self { sender })
    }

    fn submit(&self, job: ExecutorJob) {
        match self.sender.try_send(job) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                let _ = job
                    .result
                    .send(Err(anyhow::anyhow!("workflow executor queue is full")));
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(job)) => {
                let _ = job
                    .result
                    .send(Err(anyhow::anyhow!("workflow executor is unavailable")));
            }
        }
    }
}

fn worker_loop(
    receiver: Arc<Mutex<std::sync::mpsc::Receiver<ExecutorJob>>>,
    runtime: Arc<tokio::runtime::Runtime>,
) {
    loop {
        let job = receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
        let Ok(job) = job else { break };
        let result = crate::run_executor_job(job.spec, job.spawner, job.sink, job.cancel, &runtime);
        let _ = job.result.send(result);
    }
}

pub(super) fn submit(job: ExecutorJob) {
    if let Err(error) = job.spec.validate_submission_size() {
        let _ = job.result.send(Err(error.into()));
        return;
    }
    static EXECUTOR: OnceLock<Result<WorkflowExecutor, String>> = OnceLock::new();
    match EXECUTOR.get_or_init(WorkflowExecutor::new) {
        Ok(executor) => executor.submit(job),
        Err(error) => {
            let _ = job.result.send(Err(anyhow::anyhow!(
                "workflow executor initialization failed: {error}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentCall, AgentOutcome, WORKFLOW_SUBMISSION_LIMITS, WorkflowSubmissionComponent,
        WorkflowSubmissionTooLarge,
    };
    use async_trait::async_trait;

    struct NeverSpawner;

    #[async_trait]
    impl AgentSpawner for NeverSpawner {
        async fn spawn(&self, _call: AgentCall) -> AgentOutcome {
            panic!("an oversized submission must be refused before executor dispatch")
        }
    }

    #[test]
    fn oversized_script_is_typed_and_never_enters_the_executor_queue() {
        let spec = RunSpec::new("x".repeat(WORKFLOW_SUBMISSION_LIMITS.script_bytes + 1));
        let (result, receiver) = oneshot::channel();
        submit(ExecutorJob {
            spec,
            spawner: Arc::new(NeverSpawner),
            sink: Arc::new(crate::events::NullSink),
            cancel: CancellationToken::new(),
            result,
        });
        let error = receiver
            .blocking_recv()
            .expect("the refusal channel remains live")
            .expect_err("oversized source must fail before dispatch");
        let refusal = error
            .downcast_ref::<WorkflowSubmissionTooLarge>()
            .expect("the size refusal is typed");
        assert_eq!(refusal.component, WorkflowSubmissionComponent::Script);

        let args = RunSpec::new("return null").with_args(serde_json::Value::String(
            "x".repeat(WORKFLOW_SUBMISSION_LIMITS.args_bytes),
        ));
        assert_eq!(
            args.validate_submission_size().unwrap_err().component,
            WorkflowSubmissionComponent::Args
        );

        let half = WORKFLOW_SUBMISSION_LIMITS.total_bytes / 2 + 1;
        let total =
            RunSpec::new("x".repeat(half)).with_args(serde_json::Value::String("x".repeat(half)));
        assert_eq!(
            total.validate_submission_size().unwrap_err().component,
            WorkflowSubmissionComponent::Total
        );
    }
}
