use super::input::SourceDocument;
use super::wire::{read_response, write_value};
use super::{LspToolError, QueryKind};
use core_lsp::documents::DocumentStore;
use core_lsp::intel::{Query, ensure_fresh};
use core_lsp::lifecycle::{Event, RestartPolicy, Session, State};
use core_lsp::pending::{PendingRequests, ReplyDisposition};
use core_lsp::{ServerEpoch, framing};
use core_sandbox::{
    ConfinedProcess, Confinement, PersistentBackend, SandboxError,
    spawn_confined_process_from_workspace,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, BufReader};

const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(15);
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const STDERR_OBSERVED_LIMIT: u64 = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS: u64 = 30_000;

pub(super) struct Launcher {
    instance: u32,
    next_sequence: AtomicU32,
}

impl Launcher {
    pub(super) fn new() -> Result<Self, LspToolError> {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| LspToolError::IdentityUnavailable)?;
        let instance = u32::from_le_bytes(bytes) | 1;
        Ok(Self {
            instance,
            next_sequence: AtomicU32::new(1),
        })
    }

    pub(super) fn mint_epoch(&self) -> Result<u64, LspToolError> {
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| LspToolError::IdentityExhausted)?;
        Ok((u64::from(self.instance) << 32) | u64::from(sequence))
    }
}

#[derive(Debug)]
pub(super) struct LiveResult {
    pub(super) value: Value,
    pub(super) server_epoch: u64,
    pub(super) backend: &'static str,
}

#[derive(Debug)]
pub(super) struct RunFailure {
    pub(super) error: LspToolError,
    pub(super) outcome_unknown: bool,
}

pub(super) async fn run_query_owned(
    epoch: u64,
    document: Arc<SourceDocument>,
    query: QueryKind,
    sensitive_env_names: Vec<String>,
    deadline: tokio::time::Instant,
    mut cancelled: tokio::sync::oneshot::Receiver<()>,
) -> Result<LiveResult, RunFailure> {
    let mut confinement = Confinement::egress_off(document.root());
    confinement.timeout_secs = 60;
    confinement.sensitive_env_names = sensitive_env_names;
    let root_capability = document
        .root_capability()
        .map_err(|error| RunFailure::new(error, false))?;
    let spawn = spawn_confined_process_from_workspace(
        document.adapter().command(),
        &confinement,
        root_capability,
    );
    let process = match tokio::select! {
        biased;
        _ = &mut cancelled => return Err(RunFailure::new(LspToolError::OperationCancelled, false)),
        _ = tokio::time::sleep_until(deadline) => return Err(RunFailure::new(LspToolError::OperationTimeout, false)),
        result = spawn => result,
    } {
        Ok(process) => process,
        Err(SandboxError::Unsupported | SandboxError::Profile(_)) => {
            return Err(RunFailure::new(LspToolError::SandboxUnavailable, false));
        }
        Err(SandboxError::Spawn(_)) => {
            return Err(RunFailure::new(LspToolError::SpawnOutcomeUnknown, true));
        }
    };

    let mut driver = match Driver::new(process, epoch).await {
        Ok(driver) => driver,
        Err(failure) => return Err(failure),
    };
    let result = tokio::select! {
        biased;
        _ = &mut cancelled => Err(LspToolError::OperationCancelled),
        _ = tokio::time::sleep_until(deadline) => Err(LspToolError::OperationTimeout),
        result = driver.execute(&document, query) => result,
    };
    match result {
        Ok(value) => match tokio::select! {
            biased;
            _ = &mut cancelled => Err(LspToolError::OperationCancelled),
            _ = tokio::time::sleep_until(deadline) => Err(LspToolError::OperationTimeout),
            result = driver.shutdown() => result,
        } {
            Ok(backend) => Ok(LiveResult {
                value,
                server_epoch: epoch,
                backend,
            }),
            Err(error) => {
                let _cleanup_confirmed = driver.force_cleanup().await;
                // Once a CodeExecuting peer has spawned, a forced or abnormal terminal path cannot
                // prove which workspace effects it performed, even when the exact child was reaped.
                Err(RunFailure::new(error, true))
            }
        },
        Err(error) => {
            let _cleanup_confirmed = driver.force_cleanup().await;
            Err(RunFailure::new(error, true))
        }
    }
}

impl RunFailure {
    pub(super) fn new(error: LspToolError, outcome_unknown: bool) -> Self {
        Self {
            error,
            outcome_unknown,
        }
    }
}

struct Driver {
    process: Option<ConfinedProcess>,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: BufReader<tokio::process::ChildStdout>,
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    stderr_limit_hit: Arc<AtomicBool>,
    backend: PersistentBackend,
    epoch: ServerEpoch,
    lifecycle: Session,
    pending: PendingRequests,
    documents: DocumentStore,
    clock: Instant,
}

impl Drop for Driver {
    fn drop(&mut self) {
        drop(self.stdin.take());
        drop(self.process.take());
        if let Some(task) = self.stderr_task.take() {
            task.abort();
        }
    }
}

impl Driver {
    async fn new(mut process: ConfinedProcess, epoch: u64) -> Result<Self, RunFailure> {
        let backend = process.backend();
        let stdin = process.take_stdin();
        let stdout = process.take_stdout();
        let stderr = process.take_stderr();
        let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
            let _cleanup_confirmed = process.terminate_and_reap().await.is_some();
            return Err(RunFailure::new(LspToolError::MissingProcessPipe, true));
        };
        let stderr_limit_hit = Arc::new(AtomicBool::new(false));
        let stderr_task = tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_limit_hit)));
        let epoch = ServerEpoch::new(epoch);
        Ok(Self {
            process: Some(process),
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            stderr_task: Some(stderr_task),
            stderr_limit_hit,
            backend,
            epoch,
            lifecycle: Session::new(RestartPolicy::default()),
            pending: PendingRequests::new(epoch.generation()),
            documents: DocumentStore::new(epoch),
            clock: Instant::now(),
        })
    }

    async fn execute(
        &mut self,
        document: &SourceDocument,
        query: QueryKind,
    ) -> Result<Value, LspToolError> {
        self.initialize(&document.root_uri()?).await?;
        let snapshot = self.documents.open(document.uri(), 1)?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": document.uri(),
                    "languageId": document.adapter().language_id(),
                    "version": snapshot.wire_version(),
                    "text": document.text()
                }
            }
        }))
        .await?;

        self.lifecycle.guard_request()?;
        let lsp_query = query.as_lsp_query();
        let correlation = self.pending.issue_for_document(
            lsp_query.method(),
            snapshot,
            self.now_ms(),
            REQUEST_TIMEOUT_MS,
        )?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": lsp_query.method(),
            "params": lsp_query.params(document.uri(), query.position())?
        }))
        .await?;
        let value = self.read(correlation.id(), QUERY_TIMEOUT).await?;
        let completed = accepted(self.pending.resolve(
            self.epoch.generation(),
            correlation.id(),
            self.now_ms(),
        )?)?;
        ensure_fresh(&self.documents, &completed)?;
        document.recheck().await?;
        self.lifecycle
            .note_request_succeeded(&completed, self.now_ms())?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": document.uri()}}
        }))
        .await?;
        if !self.documents.close(document.uri()) {
            return Err(LspToolError::LifecycleIncomplete);
        }
        if self.stderr_limit_hit.load(Ordering::Acquire) {
            return Err(LspToolError::StderrLimit {
                limit: STDERR_OBSERVED_LIMIT,
            });
        }
        Ok(value)
    }

    async fn initialize(&mut self, root_uri: &str) -> Result<(), LspToolError> {
        self.lifecycle
            .apply(Event::InitializeSent(self.epoch), self.now_ms())?;
        let correlation = self.pending.issue(
            "initialize",
            self.now_ms(),
            INITIALIZE_TIMEOUT.as_millis() as u64,
        )?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": "initialize",
            "params": {
                "processId": null,
                "clientInfo": {"name": "core", "version": env!("CARGO_PKG_VERSION")},
                "rootUri": root_uri,
                "workspaceFolders": [{"uri": root_uri, "name": "workspace"}],
                "capabilities": {"general": {"positionEncodings": ["utf-16"]}}
            }
        }))
        .await?;
        let result = self.read(correlation.id(), INITIALIZE_TIMEOUT).await?;
        let completed = accepted(self.pending.resolve(
            self.epoch.generation(),
            correlation.id(),
            self.now_ms(),
        )?)?;
        if completed.document_snapshot().is_some() {
            return Err(LspToolError::MalformedEnvelope);
        }
        validate_position_encoding(&result)?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }))
        .await?;
        self.lifecycle
            .apply(Event::Initialized(self.epoch), self.now_ms())?;
        Ok(())
    }

    async fn write(&mut self, value: &Value) -> Result<(), LspToolError> {
        let writer = self.stdin.as_mut().ok_or(LspToolError::Transport)?;
        write_value(writer, value).await
    }

    async fn read(&mut self, id: u32, timeout: Duration) -> Result<Value, LspToolError> {
        let writer = self.stdin.as_mut().ok_or(LspToolError::Transport)?;
        read_response(&mut self.stdout, writer, id, timeout).await
    }

    async fn shutdown(&mut self) -> Result<&'static str, LspToolError> {
        if self.lifecycle.state() != State::Ready {
            return Err(LspToolError::LifecycleIncomplete);
        }
        self.lifecycle.apply(Event::ShutdownSent, self.now_ms())?;
        let correlation = self.pending.issue(
            "shutdown",
            self.now_ms(),
            SHUTDOWN_TIMEOUT.as_millis() as u64,
        )?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": "shutdown",
            "params": null
        }))
        .await?;
        let _ = self.read(correlation.id(), SHUTDOWN_TIMEOUT).await?;
        let _ = accepted(self.pending.resolve(
            self.epoch.generation(),
            correlation.id(),
            self.now_ms(),
        )?)?;
        self.write(&json!({"jsonrpc":"2.0","method":"exit","params":null}))
            .await?;
        self.lifecycle.apply(Event::ExitSent, self.now_ms())?;
        drop(self.stdin.take());

        let eof = tokio::time::timeout(SHUTDOWN_TIMEOUT, framing::read_message(&mut self.stdout))
            .await
            .map_err(|_| LspToolError::ShutdownTimeout)?
            .map_err(LspToolError::Protocol)?;
        if eof.is_some() {
            return Err(LspToolError::OutputAfterExit);
        }
        self.lifecycle.apply(Event::StreamClosed, self.now_ms())?;

        let mut process = self.process.take().ok_or(LspToolError::CleanupUnknown)?;
        let status = match tokio::time::timeout(PROCESS_EXIT_TIMEOUT, process.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                self.process = Some(process);
                return Err(LspToolError::CleanupUnknown);
            }
            Err(_) => {
                self.process = Some(process);
                return Err(LspToolError::ShutdownTimeout);
            }
        };
        if !status.success() {
            self.lifecycle.apply(Event::ProcessFailed, self.now_ms())?;
            return Err(LspToolError::ServerExitFailure);
        }
        self.lifecycle
            .apply(Event::ProcessExitedSuccessfully, self.now_ms())?;
        self.finish_stderr().await;
        if self.lifecycle.state() != State::Exited {
            return Err(LspToolError::LifecycleIncomplete);
        }
        Ok(self.backend.as_str())
    }

    async fn force_cleanup(&mut self) -> bool {
        drop(self.stdin.take());
        let process = self.process.take();
        let process_cleanup = async move {
            if let Some(mut process) = process {
                process.terminate_and_reap().await.is_some()
            } else {
                true
            }
        };
        let (confirmed, ()) = join_cleanup(process_cleanup, self.finish_stderr()).await;
        confirmed
    }

    async fn finish_stderr(&mut self) {
        let Some(mut task) = self.stderr_task.take() else {
            return;
        };
        if tokio::time::timeout(Duration::from_secs(1), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

pub(super) async fn join_cleanup<Process, Stderr>(
    process: Process,
    stderr: Stderr,
) -> (Process::Output, Stderr::Output)
where
    Process: std::future::Future,
    Stderr: std::future::Future,
{
    tokio::join!(process, stderr)
}

async fn drain_stderr(mut stderr: tokio::process::ChildStderr, limit_hit: Arc<AtomicBool>) {
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let Ok(read) = stderr.read(&mut buffer).await else {
            return;
        };
        if read == 0 {
            return;
        }
        observed = observed.saturating_add(read as u64);
        if observed > STDERR_OBSERVED_LIMIT {
            limit_hit.store(true, Ordering::Release);
            return;
        }
    }
}

fn accepted(
    disposition: ReplyDisposition,
) -> Result<core_lsp::pending::CompletedRequest, LspToolError> {
    match disposition {
        ReplyDisposition::Accepted(completed) => Ok(completed),
        _ => Err(LspToolError::CorrelationRejected),
    }
}

fn validate_position_encoding(result: &Value) -> Result<(), LspToolError> {
    let encoding = result
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("positionEncoding"));
    match encoding.and_then(Value::as_str) {
        None | Some("utf-16") => Ok(()),
        _ => Err(LspToolError::UnsupportedPositionEncoding),
    }
}

impl QueryKind {
    fn as_lsp_query(self) -> Query {
        match self {
            Self::Definition { .. } => Query::Definition,
            Self::References {
                include_declaration,
                ..
            } => Query::References {
                include_declaration,
            },
            Self::Hover { .. } => Query::Hover,
        }
    }
}
