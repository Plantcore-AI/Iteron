use super::actor::{StopControl, WriteControl, spawn_actor};
use super::output::OutputRing;
use super::types::{
    ActionError, JobId, JobShared, JobState, ProcessSnapshot, ProcessSummary, WriteReceipt, lock,
};
use super::{
    CONTROL_RESPONSE_SECS, MAX_ACTIVE_JOBS, MAX_JOB_RECORDS, MAX_JOB_RUNTIME_SECS,
    ProcessLifecycleObserver,
};
use futures_util::future::join_all;
use iteron_sandbox::{
    ConfinedProcess, ConfinedProcessControl, Confinement, PersistentBackend, SandboxError,
    spawn_confined_process,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};

struct SupervisorState {
    next_sequence: u32,
    jobs: BTreeMap<JobId, Arc<Job>>,
}

pub(super) struct Supervisor {
    instance: u64,
    state: Mutex<SupervisorState>,
    start_gate: AsyncMutex<()>,
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
            lifecycle_observer: Arc::new(Mutex::new(None)),
        })
    }

    pub(super) fn bind_lifecycle_observer(&self, observer: ProcessLifecycleObserver) {
        *lock(&self.lifecycle_observer) = Some(observer);
    }

    pub(super) async fn start(
        &self,
        root: &Path,
        command: &str,
        sensitive_env_names: Vec<String>,
    ) -> Result<ProcessSnapshot, ActionError> {
        let _start = self.start_gate.lock().await;
        let id = self.reserve_id()?;
        let mut confinement = Confinement::egress_off(root);
        confinement.timeout_secs = MAX_JOB_RUNTIME_SECS;
        confinement.sensitive_env_names = sensitive_env_names;
        let process = spawn_confined_process(command, &confinement)
            .await
            .map_err(spawn_error)?;
        let job = Job::spawn(
            id,
            command.to_owned(),
            process,
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

    fn reserve_id(&self) -> Result<JobId, ActionError> {
        let mut state = lock(&self.state);
        while state.jobs.len() >= MAX_JOB_RECORDS {
            let Some(id) = state
                .jobs
                .iter()
                .find_map(|(id, job)| job.is_reconciled_terminal().then_some(*id))
            else {
                return Err(ActionError::Definite(format!(
                    "job table is full ({MAX_JOB_RECORDS} retained records)"
                )));
            };
            state.jobs.remove(&id);
        }
        let active = state
            .jobs
            .values()
            .filter(|job| !job.is_reconciled_terminal())
            .count();
        if active >= MAX_ACTIVE_JOBS {
            return Err(ActionError::Definite(format!(
                "active process limit reached ({MAX_ACTIVE_JOBS})"
            )));
        }
        if state.next_sequence == 0 {
            return Err(ActionError::Definite("job ID space exhausted".into()));
        }
        let id = JobId {
            instance: self.instance,
            sequence: state.next_sequence,
        };
        state.next_sequence = state.next_sequence.checked_add(1).unwrap_or(0);
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
        mut process: ConfinedProcess,
        lifecycle_observer: Arc<Mutex<Option<ProcessLifecycleObserver>>>,
    ) -> Result<Arc<Self>, ActionError> {
        let backend = process.backend();
        let process_control = process.control();
        let Some(stdin) = process.take_stdin() else {
            return failed_process_setup(process, "stdin").await;
        };
        let Some(stdout) = process.take_stdout() else {
            return failed_process_setup(process, "stdout").await;
        };
        let Some(stderr) = process.take_stderr() else {
            return failed_process_setup(process, "stderr").await;
        };

        let (revision, _) = watch::channel(0);
        let shared = Arc::new(JobShared {
            state: Mutex::new(JobState::Running),
            stdout: Arc::new(Mutex::new(OutputRing::default())),
            stderr: Arc::new(Mutex::new(OutputRing::default())),
            revision,
        });
        let channels = spawn_actor(
            id,
            process,
            stdin,
            stdout,
            stderr,
            Arc::clone(&shared),
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
            shared,
            writes: channels.writes,
            stop: channels.stop,
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
            schema_version: 1,
            job_id: self.id.to_string(),
            backend: self.backend.as_str(),
            state,
            stdout,
            stderr,
        })
    }

    fn summary(&self) -> ProcessSummary {
        ProcessSummary {
            schema_version: 1,
            job_id: self.id.to_string(),
            backend: self.backend.as_str(),
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
            Duration::from_secs(CONTROL_RESPONSE_SECS),
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
            Duration::from_secs(CONTROL_RESPONSE_SECS),
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
        tokio::time::timeout(Duration::from_secs(CONTROL_RESPONSE_SECS), terminal)
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
    mut process: ConfinedProcess,
    stream: &str,
) -> Result<T, ActionError> {
    process.control().force_kill();
    let _ = process.terminate_and_reap().await;
    Err(ActionError::Unknown(format!(
        "persistent process crossed spawn without a {stream} pipe; it was terminated"
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
