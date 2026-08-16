//! Bounded JSON-RPC response demultiplexing for one MCP connection.

use super::transport::{ResponseLimits, read_frame};
use crate::{McpError, parse_response};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufRead, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, oneshot};

const DEFAULT_CONCURRENT_CALLS: usize = 8;
const CANCEL_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

fn cancel_write_timeout() -> std::time::Duration {
    iteron_tunables::param_duration(
        "mcp.client.multiplex.cancel_write_timeout",
        CANCEL_WRITE_TIMEOUT,
    )
    .clamp(std::time::Duration::from_millis(1), CANCEL_WRITE_TIMEOUT)
}

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, McpError>>>>>;
type Writer = Arc<AsyncMutex<ChildStdin>>;

pub(super) struct ResponseRouter {
    pending: PendingMap,
    terminal_error: Arc<Mutex<Option<RouterTerminalError>>>,
    permits: Arc<Semaphore>,
    writer: Option<Writer>,
    reader: tokio::task::JoinHandle<()>,
}

impl ResponseRouter {
    pub(super) fn spawn(reader: BufReader<ChildStdout>, writer: Writer) -> Self {
        Self::spawn_reader(reader, Some(writer))
    }

    fn spawn_reader<R>(mut reader: R, writer: Option<Writer>) -> Self
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let terminal_error = Arc::new(Mutex::new(None));
        let reader_pending = Arc::clone(&pending);
        let reader_error = Arc::clone(&terminal_error);
        let reader = tokio::spawn(async move {
            let limits = ResponseLimits::default();
            let mut unmatched = 0usize;
            loop {
                let frame = match read_frame(&mut reader, limits.frame_bytes).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        fail_all(
                            &reader_pending,
                            &reader_error,
                            RouterTerminalError::TransportClosed,
                        );
                        break;
                    }
                    Err(error) => {
                        fail_all(
                            &reader_pending,
                            &reader_error,
                            RouterTerminalError::from_reader_error(error),
                        );
                        break;
                    }
                };
                if frame.len() > limits.aggregate_bytes {
                    fail_all(
                        &reader_pending,
                        &reader_error,
                        RouterTerminalError::ResponseTooLarge {
                            limit: limits.aggregate_bytes,
                        },
                    );
                    break;
                }
                let text = match std::str::from_utf8(&frame) {
                    Ok(text) => text.trim(),
                    Err(_) => {
                        fail_all(
                            &reader_pending,
                            &reader_error,
                            RouterTerminalError::InvalidUtf8,
                        );
                        break;
                    }
                };
                if text.is_empty() {
                    unmatched = unmatched.saturating_add(1);
                } else {
                    let parsed: Value = match serde_json::from_str(text) {
                        Ok(value) => value,
                        Err(error) => {
                            fail_all(
                                &reader_pending,
                                &reader_error,
                                RouterTerminalError::Json(error.to_string()),
                            );
                            break;
                        }
                    };
                    if let Some(id) = parsed.get("id").and_then(Value::as_u64) {
                        let sender = lock(&reader_pending).remove(&id);
                        if let Some(sender) = sender {
                            let _ = sender.send(parse_response(text));
                            unmatched = 0;
                            continue;
                        }
                    }
                    // Notifications and late replies are permitted but bounded. They cannot steal
                    // another request's response or grow an unbounded side queue.
                    unmatched = unmatched.saturating_add(1);
                }
                if unmatched > limits.frames {
                    fail_all(
                        &reader_pending,
                        &reader_error,
                        RouterTerminalError::TooManyFrames {
                            limit: limits.frames,
                        },
                    );
                    break;
                }
            }
        });
        Self {
            pending,
            terminal_error,
            permits: Arc::new(Semaphore::new(
                iteron_tunables::param_usize(
                    "mcp.client.multiplex.default_concurrent_calls",
                    DEFAULT_CONCURRENT_CALLS,
                )
                .clamp(1, 64),
            )),
            writer,
            reader,
        }
    }

    pub(super) async fn register(&self, id: u64) -> Result<PendingResponse, McpError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| McpError::TransportClosed)?;
        if let Some(error) = lock(&self.terminal_error).as_ref() {
            return Err(error.to_mcp_error());
        }
        let (sender, receiver) = oneshot::channel();
        let mut pending = lock(&self.pending);
        if pending.contains_key(&id) {
            return Err(McpError::Protocol("duplicate MCP request id".into()));
        }
        pending.insert(id, sender);
        drop(pending);
        Ok(PendingResponse {
            id: Some(id),
            receiver,
            pending: Arc::clone(&self.pending),
            writer: self.writer.clone(),
            permit: Some(permit),
        })
    }

    pub(super) fn abort(&mut self) {
        self.reader.abort();
        fail_all(
            &self.pending,
            &self.terminal_error,
            RouterTerminalError::TransportClosed,
        );
    }
}

impl Drop for ResponseRouter {
    fn drop(&mut self) {
        self.abort();
    }
}

pub(super) struct PendingResponse {
    id: Option<u64>,
    receiver: oneshot::Receiver<Result<Value, McpError>>,
    pending: PendingMap,
    writer: Option<Writer>,
    permit: Option<OwnedSemaphorePermit>,
}

impl PendingResponse {
    pub(super) async fn receive(mut self) -> Result<Value, McpError> {
        let result = (&mut self.receiver)
            .await
            .unwrap_or(Err(McpError::TransportClosed));
        self.id = None;
        result
    }
}

impl Drop for PendingResponse {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            lock(&self.pending).remove(&id);
            let permit = self.permit.take();
            if let (Some(writer), Ok(runtime)) =
                (self.writer.clone(), tokio::runtime::Handle::try_current())
            {
                runtime.spawn(async move {
                    // Retaining the call permit makes cancellation work part of the same bounded
                    // per-server admission set. A wedged writer cannot accumulate detached tasks.
                    let _permit = permit;
                    let _ = tokio::time::timeout(cancel_write_timeout(), async move {
                        let notification = serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": {
                                "requestId": id,
                                "reason": "caller cancelled"
                            }
                        });
                        let Ok(mut encoded) = serde_json::to_vec(&notification) else {
                            return;
                        };
                        encoded.push(b'\n');
                        let mut writer = writer.lock().await;
                        let _ = writer.write_all(&encoded).await;
                        let _ = writer.flush().await;
                    })
                    .await;
                });
            }
        }
    }
}

#[derive(Clone)]
enum RouterTerminalError {
    Io(String),
    TransportClosed,
    FrameTooLarge { limit: usize },
    ResponseTooLarge { limit: usize },
    TooManyFrames { limit: usize },
    InvalidUtf8,
    Json(String),
}

impl RouterTerminalError {
    fn from_reader_error(error: McpError) -> Self {
        match error {
            McpError::Io(reason) => Self::Io(reason),
            McpError::TransportClosed => Self::TransportClosed,
            McpError::FrameTooLarge { limit } => Self::FrameTooLarge { limit },
            other => Self::Io(other.to_string()),
        }
    }

    fn to_mcp_error(&self) -> McpError {
        match self {
            Self::Io(reason) => McpError::Io(reason.clone()),
            Self::TransportClosed => McpError::TransportClosed,
            Self::FrameTooLarge { limit } => McpError::FrameTooLarge { limit: *limit },
            Self::ResponseTooLarge { limit } => McpError::ResponseTooLarge { limit: *limit },
            Self::TooManyFrames { limit } => McpError::TooManyFrames { limit: *limit },
            Self::InvalidUtf8 => McpError::InvalidUtf8,
            Self::Json(reason) => McpError::Json(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                reason.clone(),
            ))),
        }
    }
}

fn fail_all(
    pending: &PendingMap,
    terminal: &Mutex<Option<RouterTerminalError>>,
    error: RouterTerminalError,
) {
    *lock(terminal) = Some(error.clone());
    for (_, sender) in std::mem::take(&mut *lock(pending)) {
        let _ = sender.send(Err(error.to_mcp_error()));
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
    async fn slow_and_fast_responses_are_delivered_by_id_without_head_of_line_blocking() {
        let (mut peer, stream) = duplex(4096);
        let router = ResponseRouter::spawn_reader(BufReader::new(stream), None);
        let slow = router.register(1).await.unwrap();
        let fast = router.register(2).await.unwrap();
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"fast\"}\n")
            .await
            .unwrap();
        assert_eq!(fast.receive().await.unwrap(), Value::String("fast".into()));
        peer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"slow\"}\n")
            .await
            .unwrap();
        assert_eq!(slow.receive().await.unwrap(), Value::String("slow".into()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_call_retains_admission_until_bounded_writer_completion() {
        use std::process::Stdio;

        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "cat >/dev/null"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let writer = Arc::new(AsyncMutex::new(child.stdin.take().unwrap()));
        let guard = writer.lock().await;
        let (_peer, stream) = duplex(4_096);
        let router =
            ResponseRouter::spawn_reader(BufReader::new(stream), Some(Arc::clone(&writer)));
        let available = router.permits.available_permits();
        let pending = router.register(7).await.unwrap();
        assert_eq!(router.permits.available_permits(), available - 1);
        drop(pending);
        tokio::task::yield_now().await;
        assert_eq!(
            router.permits.available_permits(),
            available - 1,
            "a queued cancellation must remain inside the call semaphore"
        );
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
