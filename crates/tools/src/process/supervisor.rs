use super::actor::{StopControl, WriteControl, spawn_actor};
use super::output::OutputRing;
use super::policy::{
    InstalledProcessLaunchPolicy, PersistentBackendSelection, ProcessRuntimePolicy,
};
use super::types::{
    ActionError, JobId, JobShared, JobState, ProcessHealth, ProcessSnapshot, ProcessSummary,
    WriteReceipt, lock,
};
use super::{CONTROL_RESPONSE_SECS, ProcessLifecycleObserver};
use futures_util::future::join_all;
use iteron_sandbox::{
    ConfinedProcessControl, ConfinedPtyProcess, ConfinedPtyResize, Confinement, PersistentBackend,
    SandboxError, pty::WindowSize, spawn_confined_pty_process,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};

/// Sequence value that marks the job-ID space as spent. Allocation wraps here on overflow instead
/// of reusing a live ID, and the next request is refused rather than served a duplicate.
const EXHAUSTED_JOB_SEQUENCE: u32 = 0;

struct SupervisorState {
    next_sequence: u32,
    jobs: BTreeMap<JobId, Arc<Job>>,
}

pub(super) struct Supervisor {
    instance: u64,
    state: Mutex<SupervisorState>,
    start_gate: AsyncMutex<()>,
    policy: Mutex<ProcessRuntimePolicy>,
    lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
}

impl Supervisor {
    pub(super) fn new() -> Result<Self, String> {
        let mut instance = [0_u8; 8];
        getrandom::fill(&mut instance)
            .map_err(|error| format!("cannot mint process supervisor identity: {error}"))?;
        Ok(Self {
            instance: u64::from_le_bytes(instance),
            state: Mutex::new(SupervisorState {
                next_sequence: 1,
                jobs: BTreeMap::new(),
            }),
            start_gate: AsyncMutex::new(()),
            policy: Mutex::new(ProcessRuntimePolicy::default()),
            lifecycle_observer: Arc::new(Mutex::new(None)),
        })
    }

    pub(super) fn configure_policy(
        &self,
        requested: ProcessRuntimePolicy,
    ) -> Result<(), ActionError> {
        let policy = ProcessRuntimePolicy::new(
            requested.backend,
            requested.max_background_jobs,
            requested.idle_stall_milliseconds,
            requested.stdin_wait,
        )
        .map_err(|error| ActionError::Definite(error.to_string()))?;
        if !lock(&self.state).jobs.is_empty() {
            return Err(ActionError::Definite(
                "process policy is immutable after this session admits its first job".into(),
            ));
        }
        *lock(&self.policy) = policy;
        Ok(())
    }

    pub(super) fn policy(&self) -> ProcessRuntimePolicy {
        *lock(&self.policy)
    }

    pub(super) fn bind_lifecycle_observer(&self, observer: ProcessLifecycleObserver) {
        *lock(&self.lifecycle_observer) = Some(observer);
    }

    pub(super) async fn start(
        &self,
        root: &Path,
        command: &str,
        rows: u16,
        cols: u16,
        launch: InstalledProcessLaunchPolicy,
    ) -> Result<ProcessSnapshot, ActionError> {
        let _start = self.start_gate.lock().await;
        launch
            .policy
            .validate_root(root)
            .map_err(|error| ActionError::Definite(error.to_string()))?;
        let policy = self.policy();
        if policy.backend == PersistentBackendSelection::Disabled {
            return Err(ActionError::Definite(
                "process backend is disabled by the immutable session policy".into(),
            ));
        }
        let id = self.reserve_id(policy.max_background_jobs)?;
        let mut confinement = Confinement::egress_off(&launch.policy.cwd.initial_cwd);
        confinement.timeout_secs = crate::process::max_job_runtime_secs();
        confinement.child_environment = Some(launch.child_environment);
        let window = WindowSize::new(rows, cols)
            .map_err(|error| ActionError::Definite(error.to_string()))?;
        let process = spawn_confined_pty_process(command, &confinement, window)
            .await
            .map_err(spawn_error)?;
        let job = Job::spawn(
            id,
            command.to_owned(),
            process,
            policy,
            Arc::clone(&self.lifecycle_observer),
        )
        .await?;
        let snapshot = job.snapshot(0, 0)?;
        lock(&self.state).jobs.insert(id, job);
        Ok(snapshot)
    }

    pub(super) async fn poll(
        &self,
        raw_id: &str,
        stdout_cursor: u64,
        stderr_cursor: u64,
        wait_ms: u64,
    ) -> Result<ProcessSnapshot, ActionError> {
        self.lookup(raw_id)?
            .poll(stdout_cursor, stderr_cursor, wait_ms)
            .await
    }

    pub(super) async fn write(
        &self,
        raw_id: &str,
        bytes: Vec<u8>,
        eof: bool,
    ) -> Result<WriteReceipt, ActionError> {
        self.lookup(raw_id)?.write(bytes, eof).await
    }

    pub(super) async fn stop(&self, raw_id: &str) -> Result<ProcessSnapshot, ActionError> {
        self.lookup(raw_id)?.stop().await
    }

    pub(super) fn resize(
        &self,
        raw_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<ProcessSnapshot, ActionError> {
        self.lookup(raw_id)?.resize(rows, cols)
    }

    /// Stop every retained job without holding the registry lock across an await.
    ///
    /// The snapshot is finite (`MAX_JOB_RECORDS`), every job still owns its own terminal, and all
    /// stops are attempted even when one controller reports an unknown outcome.
    pub(super) async fn clean(&self) -> Result<Vec<ProcessSnapshot>, ActionError> {
        let jobs = lock(&self.state).jobs.values().cloned().collect::<Vec<_>>();
        let results = join_all(jobs.iter().map(|job| job.stop())).await;
        let mut snapshots = Vec::with_capacity(results.len());
        let mut failures = Vec::new();
        let mut unknown = false;
        for result in results {
            match result {
                Ok(snapshot) => snapshots.push(snapshot),
                Err(ActionError::Definite(error)) => failures.push(error),
                Err(ActionError::Unknown(error)) => {
                    unknown = true;
                    failures.push(error);
                }
            }
        }
        if failures.is_empty() {
            Ok(snapshots)
        } else {
            let detail = failures.join("; ");
            Err(if unknown {
                ActionError::Unknown(format!(
                    "background cleanup attempted every retained job; {detail}"
                ))
            } else {
                ActionError::Definite(format!(
                    "background cleanup attempted every retained job; {detail}"
                ))
            })
        }
    }

    pub(super) fn list(&self) -> Vec<ProcessSummary> {
        lock(&self.state)
            .jobs
            .values()
            .map(|job| job.summary())
            .collect()
    }

    pub(super) fn health(&self) -> ProcessHealth {
        let policy = self.policy();
        let state = lock(&self.state);
        let mut active_jobs = 0;
        let mut terminal_jobs = 0;
        let mut cleanup_unknown_jobs = 0;
        let mut awaiting_stdin_jobs = 0;
        for job in state.jobs.values() {
            match &*lock(&job.shared.state) {
                JobState::Running | JobState::Stopping => active_jobs += 1,
                JobState::CleanupUnknown { .. } => {
                    terminal_jobs += 1;
                    cleanup_unknown_jobs += 1;
                }
                _ => terminal_jobs += 1,
            }
            awaiting_stdin_jobs += usize::from(
                job.shared
                    .awaiting_stdin
                    .load(std::sync::atomic::Ordering::Acquire),
            );
        }
        ProcessHealth {
            schema_version: 1,
            policy,
            retained_jobs: state.jobs.len(),
            active_jobs,
            terminal_jobs,
            cleanup_unknown_jobs,
            awaiting_stdin_jobs,
        }
    }

    fn reserve_id(&self, max_active_jobs: usize) -> Result<JobId, ActionError> {
        let mut state = lock(&self.state);
        let max_job_records = super::max_job_records();
        while state.jobs.len() >= max_job_records {
            let Some(id) = state
                .jobs
                .iter()
                .find_map(|(id, job)| job.is_reconciled_terminal().then_some(*id))
            else {
                return Err(ActionError::Definite(format!(
                    "job table is full ({max_job_records} retained records)"
                )));
            };
            state.jobs.remove(&id);
        }
        let active = state
            .jobs
            .values()
            .filter(|job| !job.is_reconciled_terminal())
            .count();
        if active >= max_active_jobs {
            return Err(ActionError::Definite(format!(
                "active process limit reached ({max_active_jobs})"
            )));
        }
        if state.next_sequence == EXHAUSTED_JOB_SEQUENCE {
            return Err(ActionError::Definite("job ID space exhausted".into()));
        }
        let id = JobId {
            instance: self.instance,
            sequence: state.next_sequence,
        };
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .unwrap_or(EXHAUSTED_JOB_SEQUENCE);
        Ok(id)
    }

    fn lookup(&self, raw_id: &str) -> Result<Arc<Job>, ActionError> {
        let id = JobId::parse(raw_id)?;
        if id.instance != self.instance {
            return Err(ActionError::Definite(format!(
                "job_id `{raw_id}` belongs to a previous or different runtime and is no longer attachable"
            )));
        }
        lock(&self.state)
            .jobs
            .get(&id)
            .cloned()
            .ok_or_else(|| ActionError::Definite(format!("unknown or expired job_id `{raw_id}`")))
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn abort_actor(&self, raw_id: &str) -> Result<(), ActionError> {
        self.lookup(raw_id)?.actor_abort.abort();
        Ok(())
    }
}

fn spawn_error(error: SandboxError) -> ActionError {
    match error {
        SandboxError::Unsupported | SandboxError::Profile(_) => {
            ActionError::Definite(error.to_string())
        }
        SandboxError::Spawn(_) => ActionError::Unknown(format!(
            "persistent process spawn outcome is unknown; Core will not retry automatically: {error}"
        )),
    }
}

struct Job {
    id: JobId,
    command: String,
    backend: PersistentBackend,
    process_control: ConfinedProcessControl,
    resize: ConfinedPtyResize,
    runtime_policy: ProcessRuntimePolicy,
    shared: Arc<JobShared>,
    writes: mpsc::Sender<WriteControl>,
    stop: mpsc::Sender<StopControl>,
    #[cfg(all(test, target_os = "linux"))]
    actor_abort: tokio::task::AbortHandle,
}

enum StopAdmission {
    Dispatch,
    Wait,
    Terminal,
}

impl Job {
    async fn spawn(
        id: JobId,
        command: String,
        mut process: ConfinedPtyProcess,
        runtime_policy: ProcessRuntimePolicy,
        lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
    ) -> Result<Arc<Self>, ActionError> {
        let backend = process.backend();
        let process_control = process.control();
        let resize = process.resize_control();
        let Some(stdin) = process.take_input() else {
            return failed_process_setup(process, "input").await;
        };
        let Some(stdout) = process.take_output() else {
            return failed_process_setup(process, "output").await;
        };

        let (revision, _) = watch::channel(0);
        let shared = Arc::new(JobShared {
            state: Mutex::new(JobState::Running),
            stdout: Arc::new(Mutex::new(OutputRing::default())),
            stderr: Arc::new(Mutex::new(OutputRing::default())),
            awaiting_stdin: AtomicBool::new(false),
            revision,
        });
        let channels = spawn_actor(
            id,
            process,
            stdin,
            stdout,
            Arc::clone(&shared),
            runtime_policy,
            lifecycle_observer,
        );
        #[cfg(all(test, target_os = "linux"))]
        let actor_abort = channels.task.abort_handle();
        // Dropping a JoinHandle detaches the actor. Its own exit guard owns state truth and group
        // cleanup if the task is later aborted or panics.
        drop(channels.task);
        Ok(Arc::new(Self {
            id,
            command,
            backend,
            process_control,
            resize,
            shared,
            writes: channels.writes,
            stop: channels.stop,
            runtime_policy,
            #[cfg(all(test, target_os = "linux"))]
            actor_abort,
        }))
    }

    fn is_reconciled_terminal(&self) -> bool {
        lock(&self.shared.state).is_reconciled_terminal()
    }

    fn snapshot(
        &self,
        stdout_cursor: u64,
        stderr_cursor: u64,
    ) -> Result<ProcessSnapshot, ActionError> {
        let state = lock(&self.shared.state).clone();
        let stdout = lock(&self.shared.stdout)
            .frame(stdout_cursor)
            .map_err(ActionError::Definite)?;
        let stderr = lock(&self.shared.stderr)
            .frame(stderr_cursor)
            .map_err(ActionError::Definite)?;
        Ok(ProcessSnapshot {
            schema_version: 2,
            job_id: self.id.to_string(),
            backend: self.backend.as_str(),
            runtime_policy: self.runtime_policy,
            awaiting_stdin: self
                .shared
                .awaiting_stdin
                .load(std::sync::atomic::Ordering::Acquire),
            state,
            stdout,
            stderr,
        })
    }

    fn summary(&self) -> ProcessSummary {
        ProcessSummary {
            schema_version: 2,
            job_id: self.id.to_string(),
            backend: self.backend.as_str(),
            runtime_policy: self.runtime_policy,
            awaiting_stdin: self
                .shared
                .awaiting_stdin
                .load(std::sync::atomic::Ordering::Acquire),
            command: self.command.clone(),
            state: lock(&self.shared.state).clone(),
            stdout_cursor: lock(&self.shared.stdout).end_cursor(),
            stderr_cursor: lock(&self.shared.stderr).end_cursor(),
        }
    }

    async fn poll(
        &self,
        stdout_cursor: u64,
        stderr_cursor: u64,
        wait_ms: u64,
    ) -> Result<ProcessSnapshot, ActionError> {
        let mut revisions = self.shared.revision.subscribe();
        let snapshot = self.snapshot(stdout_cursor, stderr_cursor)?;
        if wait_ms == 0 || !snapshot.should_wait() {
            return Ok(snapshot);
        }
        let _ = tokio::time::timeout(Duration::from_millis(wait_ms), revisions.changed()).await;
        self.snapshot(stdout_cursor, stderr_cursor)
    }

    async fn write(&self, bytes: Vec<u8>, eof: bool) -> Result<WriteReceipt, ActionError> {
        if self.runtime_policy.backend == PersistentBackendSelection::OneShot {
            return Err(ActionError::Definite(format!(
                "job `{}` uses the one-shot backend and has no interactive stdin",
                self.id
            )));
        }
        if !matches!(*lock(&self.shared.state), JobState::Running) {
            return Err(ActionError::Definite(format!(
                "job `{}` is not accepting stdin because it is stopping or terminal",
                self.id
            )));
        }
        let accepted_bytes = bytes.len();
        let (reply, response) = oneshot::channel();
        self.writes
            .try_send(WriteControl { bytes, eof, reply })
            .map_err(|error| send_error(self.id, error))?;
        let delivered = match tokio::time::timeout(
            Duration::from_secs(iteron_tunables::param_integer(
                "tools.process.mod.control_response_secs",
                CONTROL_RESPONSE_SECS,
            )),
            response,
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                self.abort_after_unknown();
                return Err(controller_closed(self.id));
            }
            Err(_) => {
                self.abort_after_unknown();
                return Err(ActionError::Unknown(format!(
                    "stdin outcome for job `{}` is unknown after the controller deadline; the job was force-stopped",
                    self.id
                )));
            }
        };
        if matches!(&delivered, Err(ActionError::Unknown(_))) {
            // The actor reports Unknown only when a write may have been partially applied. Make
            // the response effect-terminal by spending the group cleanup capability before the
            // uncertainty is exposed to the caller; the actor then reaps and publishes state.
            self.abort_after_unknown();
        }
        delivered?;
        Ok(WriteReceipt {
            schema_version: 1,
            job_id: self.id.to_string(),
            accepted_bytes,
            stdin_closed: eof,
            state: lock(&self.shared.state).clone(),
        })
    }

    fn resize(&self, rows: u16, cols: u16) -> Result<ProcessSnapshot, ActionError> {
        if !matches!(*lock(&self.shared.state), JobState::Running) {
            return Err(ActionError::Definite(format!(
                "job `{}` is not running and cannot be resized",
                self.id
            )));
        }
        self.resize
            .resize(rows, cols)
            .map_err(|error| ActionError::Definite(format!("resize pty: {error}")))?;
        self.snapshot(0, 0)
    }

    async fn stop(&self) -> Result<ProcessSnapshot, ActionError> {
        let admission = {
            let mut state = lock(&self.shared.state);
            match &*state {
                JobState::Running => {
                    *state = JobState::Stopping;
                    StopAdmission::Dispatch
                }
                JobState::Stopping => StopAdmission::Wait,
                _ => StopAdmission::Terminal,
            }
        };
        match admission {
            StopAdmission::Terminal => return self.snapshot(0, 0),
            StopAdmission::Wait => return self.wait_for_terminal("concurrent stop").await,
            StopAdmission::Dispatch => self.shared.notify(),
        }
        let (reply, response) = oneshot::channel();
        if self.stop.try_send(StopControl::Request(reply)).is_err() {
            return self.wait_for_terminal("closed stop controller").await;
        }
        let authoritative = match tokio::time::timeout(
            Duration::from_secs(iteron_tunables::param_integer(
                "tools.process.mod.control_response_secs",
                CONTROL_RESPONSE_SECS,
            )),
            response,
        )
        .await
        {
            Ok(Ok(authoritative)) => authoritative,
            Ok(Err(_)) => {
                self.abort_after_unknown();
                return Err(controller_closed(self.id));
            }
            Err(_) => {
                self.abort_after_unknown();
                return Err(ActionError::Unknown(format!(
                    "stop outcome for job `{}` is unknown after the controller deadline; cleanup was forced",
                    self.id
                )));
            }
        };
        if !authoritative {
            return Err(ActionError::Unknown(format!(
                "job `{}` did not produce an authoritative reaped stop",
                self.id
            )));
        }
        self.snapshot(0, 0)
    }

    async fn wait_for_terminal(&self, reason: &str) -> Result<ProcessSnapshot, ActionError> {
        let mut revisions = self.shared.revision.subscribe();
        let terminal = async {
            loop {
                if lock(&self.shared.state).is_terminal() {
                    return self.snapshot(0, 0);
                }
                revisions.changed().await.map_err(|_| {
                    ActionError::Unknown(format!(
                        "job `{}` lost its lifecycle observer while waiting for {reason}",
                        self.id
                    ))
                })?;
            }
        };
        tokio::time::timeout(
            Duration::from_secs(iteron_tunables::param_integer(
                "tools.process.mod.control_response_secs",
                CONTROL_RESPONSE_SECS,
            )),
            terminal,
        )
        .await
        .map_err(|_| {
            self.abort_after_unknown();
            ActionError::Unknown(format!(
                "job `{}` did not terminalize after {reason}; cleanup was forced",
                self.id
            ))
        })?
    }

    fn abort_after_unknown(&self) {
        {
            let mut state = lock(&self.shared.state);
            if !state.is_terminal() {
                *state = JobState::Stopping;
            }
        }
        self.shared.notify();
        self.process_control.force_kill();
        let _ = self.stop.try_send(StopControl::Cleanup);
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.process_control.force_kill();
        let _ = self.stop.try_send(StopControl::Cleanup);
    }
}

async fn failed_process_setup<T>(
    mut process: ConfinedPtyProcess,
    stream: &str,
) -> Result<T, ActionError> {
    process.control().force_kill();
    let _ = process.terminate_and_reap().await;
    Err(ActionError::Unknown(format!(
        "persistent process crossed spawn without a pty {stream}; it was terminated"
    )))
}

fn send_error<T>(id: JobId, error: mpsc::error::TrySendError<T>) -> ActionError {
    match error {
        mpsc::error::TrySendError::Full(_) => {
            ActionError::Definite(format!("job `{id}` control queue is full"))
        }
        mpsc::error::TrySendError::Closed(_) => {
            ActionError::Definite(format!("job `{id}` controller is not accepting stdin"))
        }
    }
}

fn controller_closed(id: JobId) -> ActionError {
    ActionError::Unknown(format!(
        "job `{id}` controller closed before an authoritative response"
    ))
}
