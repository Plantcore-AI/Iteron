//! Concurrent bounded LSP response router.

use super::LspToolError;
use super::wire::{safe_server_request_result, validate_server_request_id, write_value};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::BufReader;
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore, oneshot};

const DEFAULT_CONCURRENT_REQUESTS: usize = 8;
const MAX_INTERLEAVED_MESSAGES: usize = 64;
const CANCEL_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

fn cancel_write_timeout() -> std::time::Duration {
    iteron_tunables::param_duration(
        "tools.lsp.multiplex.cancel_write_timeout",
        CANCEL_WRITE_TIMEOUT,
    )
    .clamp(std::time::Duration::from_millis(1), CANCEL_WRITE_TIMEOUT)
}

fn max_interleaved_messages() -> usize {
    iteron_tunables::param_usize(
        "tools.lsp.multiplex.max_interleaved_messages",
        MAX_INTERLEAVED_MESSAGES,
    )
    .clamp(1, MAX_INTERLEAVED_MESSAGES)
}

type Writer = Arc<AsyncMutex<Option<ChildStdin>>>;
type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<Value, LspToolError>>>>>;

pub(super) struct ResponseRouter {
    pending: Pending,
    writer: Writer,
    permits: Arc<Semaphore>,
    terminal: Arc<std::sync::atomic::AtomicBool>,
    closed: Arc<Notify>,
    reader: tokio::task::JoinHandle<()>,
}

impl ResponseRouter {
    pub(super) fn spawn(stdout: ChildStdout, writer: Writer) -> Self {
        Self::spawn_reader(BufReader::new(stdout), writer)
    }

    fn spawn_reader<R>(mut reader: R, writer: Writer) -> Self
    where
        R: tokio::io::AsyncBufRead + Unpin + Send + 'static,
    {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed = Arc::new(Notify::new());
        let reader_pending = Arc::clone(&pending);
        let reader_terminal = Arc::clone(&terminal);
        let reader_closed = Arc::clone(&closed);
        let reader_writer = Arc::clone(&writer);
        let task = tokio::spawn(async move {
            let mut unmatched = 0usize;
            loop {
                let Some((mut message, _wire_bytes)) =
                    iteron_lsp::framing::read_message_with_size(&mut reader)
                        .await
                        .unwrap_or_default()
                else {
                    break;
                };
                let Some(object) = message.as_object_mut() else {
                    break;
                };
                if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    break;
                }
                if let Some(id) = object
                    .get("id")
                    .and_then(Value::as_u64)
                    .and_then(|id| u32::try_from(id).ok())
                    && (object.contains_key("result") || object.contains_key("error"))
                    && let Some(sender) = lock(&reader_pending).remove(&id)
                {
                    let result = if object.contains_key("result") == object.contains_key("error") {
                        Err(LspToolError::MalformedEnvelope)
                    } else if object.contains_key("error") {
                        let code = object
                            .get("error")
                            .and_then(Value::as_object)
                            .and_then(|error| error.get("code"))
                            .and_then(Value::as_i64);
                        Err(LspToolError::ServerResponse { code })
                    } else {
                        object
                            .remove("result")
                            .ok_or(LspToolError::MalformedEnvelope)
                    };
                    let _ = sender.send(result);
                    unmatched = 0;
                    continue;
                }
                if let Some(method) = object.get("method").and_then(Value::as_str) {
                    if let Some(id) = object.get("id").cloned() {
                        if validate_server_request_id(&id).is_err() {
                            break;
                        }
                        let response = safe_server_request_result(method, object.get("params"))
                            .map(|result| json!({"jsonrpc":"2.0","id":id,"result":result}))
                            .unwrap_or_else(|| {
                                json!({
                                    "jsonrpc":"2.0","id":id,
                                    "error":{"code":-32601,"message":"unsupported server request"}
                                })
                            });
                        let mut writer = reader_writer.lock().await;
                        let Some(writer) = writer.as_mut() else {
                            break;
                        };
                        if write_value(writer, &response).await.is_err() {
                            break;
                        }
                    }
                    unmatched = unmatched.saturating_add(1);
                } else {
                    unmatched = unmatched.saturating_add(1);
                }
                if unmatched > max_interleaved_messages() {
                    break;
                }
            }
            reader_terminal.store(true, std::sync::atomic::Ordering::Release);
            for (_, sender) in std::mem::take(&mut *lock(&reader_pending)) {
                let _ = sender.send(Err(LspToolError::Transport));
            }
            reader_closed.notify_waiters();
        });
        Self {
            pending,
            writer,
            permits: Arc::new(Semaphore::new(
                iteron_tunables::param_usize(
                    "tools.lsp.multiplex.default_concurrent_requests",
                    DEFAULT_CONCURRENT_REQUESTS,
                )
                .clamp(1, 64),
            )),
            terminal,
            closed,
            reader: task,
        }
    }

    pub(super) async fn register(&self, id: u32) -> Result<PendingResponse, LspToolError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| LspToolError::Transport)?;
        if self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            return Err(LspToolError::Transport);
        }
        let (sender, receiver) = oneshot::channel();
        let mut pending = lock(&self.pending);
        if pending.contains_key(&id) {
            return Err(LspToolError::CorrelationRejected);
        }
        pending.insert(id, sender);
        drop(pending);
        Ok(PendingResponse {
            id: Some(id),
            receiver,
            pending: Arc::clone(&self.pending),
            writer: Arc::clone(&self.writer),
            permit: Some(permit),
        })
    }

    pub(super) async fn wait_closed(&self) {
        if !self.terminal.load(std::sync::atomic::Ordering::Acquire) {
            self.closed.notified().await;
        }
    }

    pub(super) fn abort(&self) {
        self.reader.abort();
        self.terminal
            .store(true, std::sync::atomic::Ordering::Release);
        for (_, sender) in std::mem::take(&mut *lock(&self.pending)) {
            let _ = sender.send(Err(LspToolError::Transport));
        }
        self.closed.notify_waiters();
    }
}

pub(super) struct PendingResponse {
    id: Option<u32>,
    receiver: oneshot::Receiver<Result<Value, LspToolError>>,
    pending: Pending,
    writer: Writer,
    permit: Option<OwnedSemaphorePermit>,
}

impl PendingResponse {
    pub(super) async fn receive(mut self) -> Result<Value, LspToolError> {
        let result = (&mut self.receiver)
            .await
            .unwrap_or(Err(LspToolError::Transport));
        self.id = None;
        result
    }
}

impl Drop for PendingResponse {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        lock(&self.pending).remove(&id);
        let permit = self.permit.take();
        let writer = Arc::clone(&self.writer);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                // Cancellation retains its request permit until the bounded writer attempt ends,
                // so repeated drops cannot create an unbounded queue behind this mutex.
                let _permit = permit;
                let _ = tokio::time::timeout(cancel_write_timeout(), async move {
                    let mut writer = writer.lock().await;
                    if let Some(writer) = writer.as_mut() {
                        let _ = write_value(
                            writer,
                            &json!({
                                "jsonrpc":"2.0",
                                "method":"$/cancelRequest",
                                "params":{"id":id}
                            }),
                        )
                        .await;
                    }
                })
                .await;
            });
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[tokio::test]
    async fn fast_response_is_not_blocked_by_an_earlier_slow_id() {
        let (mut peer, stream) = duplex(4_096);
        let router =
            ResponseRouter::spawn_reader(BufReader::new(stream), Arc::new(AsyncMutex::new(None)));
        let slow = router.register(1).await.unwrap();
        let fast = router.register(2).await.unwrap();

        async fn reply(peer: &mut tokio::io::DuplexStream, id: u32, result: &str) {
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            }))
            .unwrap();
            peer.write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
                .await
                .unwrap();
            peer.write_all(&body).await.unwrap();
        }

        reply(&mut peer, 2, "fast").await;
        assert_eq!(fast.receive().await.unwrap(), json!("fast"));
        reply(&mut peer, 1, "slow").await;
        assert_eq!(slow.receive().await.unwrap(), json!("slow"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_request_retains_admission_until_bounded_writer_completion() {
        use std::process::Stdio;

        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "cat >/dev/null"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let writer = Arc::new(AsyncMutex::new(Some(child.stdin.take().unwrap())));
        let guard = writer.lock().await;
        let (_peer, stream) = duplex(4_096);
        let router = ResponseRouter::spawn_reader(BufReader::new(stream), Arc::clone(&writer));
        let available = router.permits.available_permits();
        let pending = router.register(9).await.unwrap();
        assert_eq!(router.permits.available_permits(), available - 1);
        drop(pending);
        tokio::task::yield_now().await;
        assert_eq!(router.permits.available_permits(), available - 1);
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while router.permits.available_permits() != available {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let _ = child.kill().await;
    }
}
