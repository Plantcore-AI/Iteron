use super::input::SourceDocument;
use super::multiplex::ResponseRouter;
use super::wire::write_value;
use super::{LspToolError, QueryKind};
use iteron_lsp::ServerEpoch;
use iteron_lsp::documents::DocumentStore;
use iteron_lsp::intel::{Query, ensure_fresh};
use iteron_lsp::lifecycle::{Event, RestartPolicy, Session, State};
use iteron_lsp::pending::{PendingRequests, ReplyDisposition};
use iteron_sandbox::{ConfinedProcess, PersistentBackend};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex as AsyncMutex;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const STDERR_OBSERVED_LIMIT: u64 = 64 * 1024 * 1024;
/// Grace given to the stderr reader task after the process is gone. Short, because the pipe is
/// already closed at this point and the task is aborted rather than waited on further.
const STDERR_JOIN_TIMEOUT: Duration = Duration::from_secs(1);
#[derive(Debug)]
pub(super) struct LiveResult {
    pub(super) value: Value,
    pub(super) server_epoch: u64,
    pub(super) backend: &'static str,
    pub(super) reused_server: bool,
    pub(super) restart_count: u32,
    pub(super) server_id: String,
}

#[derive(Debug)]
pub(super) struct RunFailure {
    pub(super) error: LspToolError,
    pub(super) outcome_unknown: bool,
}

impl RunFailure {
    pub(super) fn new(error: LspToolError, outcome_unknown: bool) -> Self {
        Self {
            error,
            outcome_unknown,
        }
    }
}

pub(super) struct Driver {
    process: AsyncMutex<Option<ConfinedProcess>>,
    stdin: Arc<AsyncMutex<Option<tokio::process::ChildStdin>>>,
    responses: ResponseRouter,
    stderr_task: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
    stderr_limit_hit: Arc<AtomicBool>,
    backend: PersistentBackend,
    epoch: ServerEpoch,
    lifecycle: Mutex<Session>,
    pending: Mutex<PendingRequests>,
    documents: Mutex<DocumentStore>,
    clock: Instant,
}

/// Cleans the request-local registries when the caller cancels the `execute` future. The response
/// router independently drops its receiver and emits `$/cancelRequest`; this lease releases the
/// logical admission slot and closes only this document, without touching server lifecycle state.
struct RequestLease<'a> {
    pending: &'a Mutex<PendingRequests>,
    documents: &'a Mutex<DocumentStore>,
    stdin: Arc<AsyncMutex<Option<tokio::process::ChildStdin>>>,
    clock: &'a Instant,
    generation: u64,
    id: u32,
    uri: String,
    server_document_open: bool,
    armed: bool,
}

impl RequestLease<'_> {
    fn note_server_document_open(&mut self) {
        self.server_document_open = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RequestLease<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let now_ms = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = lock(self.pending).cancel_and_release(self.generation, self.id, now_ms);
        let _ = lock(self.documents).close(&self.uri);
        if !self.server_document_open {
            return;
        }
        let stdin = Arc::clone(&self.stdin);
        let uri = self.uri.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut writer = stdin.lock().await;
                if let Some(writer) = writer.as_mut() {
                    let _ = write_value(
                        writer,
                        &json!({
                            "jsonrpc": "2.0",
                            "method": "textDocument/didClose",
                            "params": {"textDocument": {"uri": uri}}
                        }),
                    )
                    .await;
                }
            });
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.responses.abort();
        if let Ok(mut stdin) = self.stdin.try_lock() {
            drop(stdin.take());
        }
        if let Ok(mut process) = self.process.try_lock() {
            drop(process.take());
        }
        if let Ok(mut stderr_task) = self.stderr_task.try_lock()
            && let Some(task) = stderr_task.take()
        {
            task.abort();
        }
    }
}

impl Driver {
    pub(super) async fn new(mut process: ConfinedProcess, epoch: u64) -> Result<Self, RunFailure> {
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
        let stdin = Arc::new(AsyncMutex::new(Some(stdin)));
        let responses = ResponseRouter::spawn(stdout, Arc::clone(&stdin));
        Ok(Self {
            process: AsyncMutex::new(Some(process)),
            stdin,
            responses,
            stderr_task: AsyncMutex::new(Some(stderr_task)),
            stderr_limit_hit,
            backend,
            epoch,
            lifecycle: Mutex::new(Session::new(RestartPolicy::default())),
            pending: Mutex::new(PendingRequests::new(epoch.generation())),
            documents: Mutex::new(DocumentStore::new(epoch)),
            clock: Instant::now(),
        })
    }

    pub(super) async fn execute(
        &self,
        document: &SourceDocument,
        query: QueryKind,
        request_timeout: Duration,
    ) -> Result<Value, LspToolError> {
        lock(&self.lifecycle).guard_request()?;
        let snapshot = lock(&self.documents).open(document.uri(), 1)?;
        let wire_version = snapshot.wire_version();
        let lsp_query = query.as_lsp_query();
        let correlation = lock(&self.pending).issue_for_document(
            lsp_query.method(),
            snapshot,
            self.now_ms(),
            u64::try_from(request_timeout.as_millis()).unwrap_or(u64::MAX),
        )?;
        let mut lease = RequestLease {
            pending: &self.pending,
            documents: &self.documents,
            stdin: Arc::clone(&self.stdin),
            clock: &self.clock,
            generation: self.epoch.generation(),
            id: correlation.id(),
            uri: document.uri().to_owned(),
            server_document_open: false,
            armed: true,
        };
        let response = self.responses.register(correlation.id()).await?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": document.uri(),
                    "languageId": document.adapter().language_id(),
                    "version": wire_version,
                    "text": document.text()
                }
            }
        }))
        .await?;
        lease.note_server_document_open();
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": lsp_query.method(),
            "params": lsp_query.params(document.uri(), query.position())?
        }))
        .await?;
        let value = tokio::time::timeout(request_timeout, response.receive())
            .await
            .map_err(|_| LspToolError::ResponseTimeout)??;
        let completed = accepted(lock(&self.pending).resolve(
            self.epoch.generation(),
            correlation.id(),
            self.now_ms(),
        )?)?;
        ensure_fresh(&lock(&self.documents), &completed)?;
        document.recheck().await?;
        lock(&self.lifecycle).note_request_succeeded(&completed, self.now_ms())?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": document.uri()}}
        }))
        .await?;
        if !lock(&self.documents).close(document.uri()) {
            return Err(LspToolError::LifecycleIncomplete);
        }
        lease.disarm();
        if self.stderr_limit_hit.load(Ordering::Acquire) {
            return Err(LspToolError::StderrLimit {
                limit: iteron_tunables::param_integer(
                    "tools.lsp.session.stderr_observed_limit",
                    STDERR_OBSERVED_LIMIT,
                ),
            });
        }
        Ok(value)
    }

    pub(super) async fn initialize(
        &self,
        root_uri: &str,
        request_timeout: Duration,
    ) -> Result<(), LspToolError> {
        lock(&self.lifecycle).apply(Event::InitializeSent(self.epoch), self.now_ms())?;
        let correlation = lock(&self.pending).issue(
            "initialize",
            self.now_ms(),
            u64::try_from(request_timeout.as_millis()).unwrap_or(u64::MAX),
        )?;
        let response = self.responses.register(correlation.id()).await?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": "initialize",
            "params": {
                "processId": null,
                "clientInfo": {"name": "iteron", "version": env!("CARGO_PKG_VERSION")},
                "rootUri": root_uri,
                "workspaceFolders": [{"uri": root_uri, "name": "workspace"}],
                "capabilities": {"general": {"positionEncodings": ["utf-16"]}}
            }
        }))
        .await?;
        let result = tokio::time::timeout(request_timeout, response.receive())
            .await
            .map_err(|_| LspToolError::ResponseTimeout)??;
        let completed = accepted(lock(&self.pending).resolve(
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
        lock(&self.lifecycle).apply(Event::Initialized(self.epoch), self.now_ms())?;
        Ok(())
    }

    async fn write(&self, value: &Value) -> Result<(), LspToolError> {
        let mut writer = self.stdin.lock().await;
        let writer = writer.as_mut().ok_or(LspToolError::Transport)?;
        write_value(writer, value).await
    }

    pub(super) async fn shutdown(&self) -> Result<&'static str, LspToolError> {
        if lock(&self.lifecycle).state() != State::Ready {
            return Err(LspToolError::LifecycleIncomplete);
        }
        lock(&self.lifecycle).apply(Event::ShutdownSent, self.now_ms())?;
        let correlation = lock(&self.pending).issue(
            "shutdown",
            self.now_ms(),
            iteron_tunables::param_duration("tools.lsp.session.shutdown_timeout", SHUTDOWN_TIMEOUT)
                .as_millis() as u64,
        )?;
        let response = self.responses.register(correlation.id()).await?;
        self.write(&json!({
            "jsonrpc": "2.0",
            "id": correlation.wire_id(),
            "method": "shutdown",
            "params": null
        }))
        .await?;
        let _ = tokio::time::timeout(
            iteron_tunables::param_duration("tools.lsp.session.shutdown_timeout", SHUTDOWN_TIMEOUT),
            response.receive(),
        )
        .await
        .map_err(|_| LspToolError::ShutdownTimeout)??;
        let _ = accepted(lock(&self.pending).resolve(
            self.epoch.generation(),
            correlation.id(),
            self.now_ms(),
        )?)?;
        self.write(&json!({"jsonrpc":"2.0","method":"exit","params":null}))
            .await?;
        lock(&self.lifecycle).apply(Event::ExitSent, self.now_ms())?;
        drop(self.stdin.lock().await.take());

        tokio::time::timeout(
            iteron_tunables::param_duration("tools.lsp.session.shutdown_timeout", SHUTDOWN_TIMEOUT),
            self.responses.wait_closed(),
        )
        .await
        .map_err(|_| LspToolError::ShutdownTimeout)?;
        lock(&self.lifecycle).apply(Event::StreamClosed, self.now_ms())?;

        let mut process = self
            .process
            .lock()
            .await
            .take()
            .ok_or(LspToolError::CleanupUnknown)?;
        let status = match tokio::time::timeout(
            iteron_tunables::param_duration(
                "tools.lsp.session.process_exit_timeout",
                PROCESS_EXIT_TIMEOUT,
            ),
            process.wait(),
        )
        .await
        {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                *self.process.lock().await = Some(process);
                return Err(LspToolError::CleanupUnknown);
            }
            Err(_) => {
                *self.process.lock().await = Some(process);
                return Err(LspToolError::ShutdownTimeout);
            }
        };
        if !status.success() {
            lock(&self.lifecycle).apply(Event::ProcessFailed, self.now_ms())?;
            return Err(LspToolError::ServerExitFailure);
        }
        lock(&self.lifecycle).apply(Event::ProcessExitedSuccessfully, self.now_ms())?;
        self.finish_stderr().await;
        if lock(&self.lifecycle).state() != State::Exited {
            return Err(LspToolError::LifecycleIncomplete);
        }
        Ok(self.backend.as_str())
    }

    pub(super) async fn force_cleanup(&self) -> bool {
        self.responses.abort();
        drop(self.stdin.lock().await.take());
        let process = self.process.lock().await.take();
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

    async fn finish_stderr(&self) {
        let Some(mut task) = self.stderr_task.lock().await.take() else {
            return;
        };
        if tokio::time::timeout(
            iteron_tunables::param_duration(
                "tools.lsp.session.stderr_join_timeout",
                STDERR_JOIN_TIMEOUT,
            ),
            &mut task,
        )
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

    pub(super) fn backend(&self) -> &'static str {
        self.backend.as_str()
    }

    pub(super) fn epoch(&self) -> u64 {
        self.epoch.generation()
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
        if observed
            > iteron_tunables::param_integer(
                "tools.lsp.session.stderr_observed_limit",
                STDERR_OBSERVED_LIMIT,
            )
        {
            limit_hit.store(true, Ordering::Release);
            return;
        }
    }
}

fn accepted(
    disposition: ReplyDisposition,
) -> Result<iteron_lsp::pending::CompletedRequest, LspToolError> {
    match disposition {
        ReplyDisposition::Accepted(completed) => Ok(completed),
        _ => Err(LspToolError::CorrelationRejected),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
