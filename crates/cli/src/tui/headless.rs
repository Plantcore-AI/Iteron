//! Bounded loopback transport for headless App Server clients.
//!
//! The runtime and its SQ/EQ semantics remain in `tui::app_server`; this module is only a framed
//! transport adapter. A client must complete the version handshake before it can submit an op.

use super::app_server::{AppServerClient, Attached, ServerEvent, TerminalSummary};
use crate::output;
use crate::runtime::UiEvent;
use anyhow::{Context, Result, bail};
use core_protocol::{
    Op, PROTOCOL_VERSION, input::MAX_TOTAL_IMAGE_BASE64_BYTES, task::MAX_TASK_TEXT_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio::task::JoinSet;

const MAX_SERVER_FRAME_BYTES: usize = 1024 * 1024;
/// One multimodal SQ frame may contain the aggregate encoded-image ceiling plus a maximally
/// escaped task string. Keep the transport bound derived and finite rather than making the
/// protocol's valid image envelope impossible to submit.
const MAX_CLIENT_FRAME_BYTES: usize =
    MAX_TOTAL_IMAGE_BASE64_BYTES + (MAX_TASK_TEXT_BYTES * 6) + (64 * 1024);
/// Bound aggregate bytes retained by all partially read client frames. Per-reader limits still
/// reject any single oversized frame; this process-wide budget prevents many connections from
/// retaining one almost-maximal frame apiece.
const MAX_PENDING_CLIENT_BYTES: usize = MAX_CLIENT_FRAME_BYTES * 2;
const MAX_CONNECTIONS: usize = 32;
const REPLAY_CAPACITY: usize = 4096;
const LIVE_CAPACITY: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientFrame {
    Hello {
        protocol_version: u32,
        #[serde(default)]
        resume_from: Option<u64>,
    },
    Submit {
        protocol_version: u32,
        op: Op,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Hello {
        protocol_version: u32,
        cursor: u64,
        replay_source: &'static str,
    },
    Event {
        protocol_version: u32,
        seq: u64,
        event: Value,
    },
    Result {
        protocol_version: u32,
        seq: u64,
        result: Value,
    },
    Rollout {
        protocol_version: u32,
        rollout_seq: u64,
        event: Value,
    },
    Error {
        protocol_version: u32,
        code: &'static str,
        message: String,
    },
}

impl ServerFrame {
    fn live_seq(&self) -> Option<u64> {
        match self {
            Self::Event { seq, .. } | Self::Result { seq, .. } => Some(*seq),
            Self::Hello { .. } | Self::Rollout { .. } | Self::Error { .. } => None,
        }
    }
}

fn terminal_result_frame(seq: u64, summary: &TerminalSummary) -> ServerFrame {
    ServerFrame::Result {
        protocol_version: PROTOCOL_VERSION,
        seq,
        result: summary.result_v5(),
    }
}

#[cfg(test)]
pub(super) fn capture_terminal_result_frame(
    seq: u64,
    summary: &TerminalSummary,
) -> (u32, u64, Value) {
    match terminal_result_frame(seq, summary) {
        ServerFrame::Result {
            protocol_version,
            seq,
            result,
        } => (protocol_version, seq, result),
        _ => unreachable!("terminal_result_frame always constructs a result frame"),
    }
}

struct Shared {
    client: AppServerClient,
    ring: Mutex<VecDeque<ServerFrame>>,
    live: broadcast::Sender<ServerFrame>,
    cursor: AtomicU64,
    rollout_path: PathBuf,
}

impl Shared {
    async fn publish(&self, frame: ServerFrame) {
        let Some(seq) = frame.live_seq() else {
            return;
        };
        self.cursor.store(seq, Ordering::Release);
        let mut ring = self.ring.lock().await;
        ring.push_back(frame.clone());
        while ring.len() > REPLAY_CAPACITY {
            ring.pop_front();
        }
        drop(ring);
        let _ = self.live.send(frame);
    }
}

/// Run a local-only multi-client listener until interrupted.
pub(crate) async fn serve(attached: Attached, listen: SocketAddr) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("headless App Server refuses non-loopback listen address {listen}");
    }
    let Attached {
        handle,
        task: server_task,
        facts,
        ..
    } = attached;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind headless App Server at {listen}"))?;
    let bound = listener.local_addr().context("read bound listen address")?;
    log(json!({
        "component": "app_server",
        "event": "listening",
        "protocol_version": PROTOCOL_VERSION,
        "listen": bound.to_string(),
        "transport": "loopback_tcp_jsonl",
    }));

    let (live, _) = broadcast::channel(LIVE_CAPACITY);
    let shared = Arc::new(Shared {
        client: handle.client,
        ring: Mutex::new(VecDeque::with_capacity(REPLAY_CAPACITY)),
        live,
        cursor: AtomicU64::new(0),
        rollout_path: facts.rollout_path,
    });
    let mut events = handle.events;
    let pump_shared = shared.clone();
    let pump = tokio::spawn(async move {
        let mut turn = 0;
        let mut last_seq = 0;
        while let Some(envelope) = events.recv().await {
            let seq = envelope.sequence();
            if seq <= last_seq {
                log(json!({
                    "component": "app_server",
                    "event": "event_order_error",
                    "seq": seq,
                    "previous_seq": last_seq,
                }));
                break;
            }
            last_seq = seq;
            let event = match envelope.into_current() {
                Ok(event) => event,
                Err(error) => {
                    log(json!({
                        "component": "app_server",
                        "event": "protocol_error",
                        "message": error.to_string(),
                    }));
                    break;
                }
            };
            let frame = match event {
                ServerEvent::Ui(event) => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(event, &mut turn),
                },
                ServerEvent::Notice(message) => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(UiEvent::Notice(message), &mut turn),
                },
                ServerEvent::Lagged { dropped } => ServerFrame::Event {
                    protocol_version: PROTOCOL_VERSION,
                    seq,
                    event: output::stream_event(
                        UiEvent::Notice(format!(
                            "{dropped} streamed update(s) were dropped by the bounded event queue"
                        )),
                        &mut turn,
                    ),
                },
                ServerEvent::RunEnded { summary, .. } => terminal_result_frame(seq, &summary),
            };
            pump_shared.publish(frame).await;
        }
    });

    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let frame_budget = Arc::new(Semaphore::new(MAX_PENDING_CLIENT_BYTES));
    let mut connections = JoinSet::new();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, _) = result.context("accept headless client")?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    connections.spawn(async move {
                        let (_, mut writer) = socket.into_split();
                        let _ = send_frame(&mut writer, &error_frame(
                            "connection_limit",
                            "the headless App Server connection limit is full",
                        )).await;
                    });
                    continue;
                };
                let shared = shared.clone();
                let frame_budget = frame_budget.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(socket, shared, frame_budget).await {
                        log(json!({
                            "component": "app_server",
                            "event": "client_error",
                            "message": core_record::redact::scrub(&error.to_string()),
                        }));
                    }
                });
            }
            _ = &mut shutdown => break,
        }
    }

    log(json!({
        "component": "app_server",
        "event": "stopping",
        "protocol_version": PROTOCOL_VERSION,
    }));
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    drop(handle.control);
    drop(shared);
    server_task.await.context("App Server task join")?;
    pump.await.context("headless event pump join")?;
    Ok(())
}

async fn serve_connection(
    socket: TcpStream,
    shared: Arc<Shared>,
    frame_budget: Arc<Semaphore>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = FrameReader::new(reader, frame_budget);
    let hello = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.next_frame())
        .await
        .context("headless handshake timed out")??
        .context("client disconnected before handshake")?;
    let (version, resume_from) = match parse_client_frame(&hello)? {
        ClientFrame::Hello {
            protocol_version,
            resume_from,
        } => (protocol_version, resume_from),
        ClientFrame::Submit { .. } => {
            send_frame(
                &mut writer,
                &error_frame("handshake_required", "hello must be the first frame"),
            )
            .await?;
            return Ok(());
        }
    };
    // A syntactically valid hello can contain a large amount of insignificant JSON whitespace.
    // Do not let its completed-frame permit live for the lifetime of the connection.
    drop(hello);
    if version != PROTOCOL_VERSION {
        send_frame(
            &mut writer,
            &error_frame(
                "protocol_version_mismatch",
                &format!(
                    "unsupported SQ/EQ protocol version {version}; expected {PROTOCOL_VERSION}"
                ),
            ),
        )
        .await?;
        return Ok(());
    }

    let mut live = shared.live.subscribe();
    let ring = shared.ring.lock().await.clone();
    let cursor = shared.cursor.load(Ordering::Acquire);
    let requested = resume_from.unwrap_or(cursor);
    if requested > cursor {
        send_frame(
            &mut writer,
            &error_frame(
                "cursor_ahead",
                &format!("resume cursor {requested} is ahead of server cursor {cursor}"),
            ),
        )
        .await?;
        return Ok(());
    }
    let oldest = ring.front().and_then(ServerFrame::live_seq);
    let fallback = oldest.is_some_and(|oldest| requested < oldest.saturating_sub(1));
    send_frame(
        &mut writer,
        &ServerFrame::Hello {
            protocol_version: PROTOCOL_VERSION,
            cursor,
            replay_source: if fallback { "rollout" } else { "ring" },
        },
    )
    .await?;
    if fallback {
        send_rollout(&mut writer, &shared.rollout_path).await?;
    }
    let mut delivered = requested;
    for frame in ring {
        if frame.live_seq().is_some_and(|seq| seq > delivered) {
            delivered = frame.live_seq().unwrap_or(delivered);
            send_frame(&mut writer, &frame).await?;
        }
    }

    loop {
        tokio::select! {
            inbound = reader.next_frame_with_partial_timeout(PARTIAL_FRAME_TIMEOUT) => {
                let Some(bytes) = inbound? else { return Ok(()); };
                match parse_client_frame(&bytes)? {
                    ClientFrame::Hello { .. } => {
                        send_frame(&mut writer, &error_frame(
                            "duplicate_handshake",
                            "the version handshake is already complete",
                        )).await?;
                        return Ok(());
                    }
                    ClientFrame::Submit { protocol_version, op } => {
                        if protocol_version != PROTOCOL_VERSION {
                            send_frame(&mut writer, &error_frame(
                                "protocol_version_mismatch",
                                &format!(
                                    "submission uses protocol version {protocol_version}; expected {PROTOCOL_VERSION}"
                                ),
                            )).await?;
                            continue;
                        }
                        if let Err(error) = shared.client.submit(op) {
                            send_frame(
                                &mut writer,
                                &error_frame("submission_refused", &error.to_string()),
                            ).await?;
                        }
                    }
                }
            }
            outbound = live.recv() => {
                match outbound {
                    Ok(frame) => {
                        if frame.live_seq().is_some_and(|seq| seq > delivered) {
                            delivered = frame.live_seq().unwrap_or(delivered);
                            send_frame(&mut writer, &frame).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        send_frame(&mut writer, &error_frame(
                            "slow_client",
                            "client fell behind the bounded live queue; reconnect with resume_from",
                        )).await?;
                        return Ok(());
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn send_rollout<W: AsyncWrite + Unpin>(writer: &mut W, path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    let events = tokio::task::spawn_blocking(move || core_record::replay(&path))
        .await
        .context("Rollout replay task join")?
        .context("replay Rollout for reconnect fallback")?;
    for event in events {
        send_frame(
            writer,
            &ServerFrame::Rollout {
                protocol_version: PROTOCOL_VERSION,
                rollout_seq: event.seq.0,
                event: serde_json::to_value(event).context("serialize Rollout event")?,
            },
        )
        .await?;
    }
    Ok(())
}

fn parse_client_frame(bytes: &[u8]) -> Result<ClientFrame> {
    serde_json::from_slice(bytes).context("decode bounded headless client frame")
}

fn error_frame(code: &'static str, message: &str) -> ServerFrame {
    ServerFrame::Error {
        protocol_version: PROTOCOL_VERSION,
        code,
        message: core_record::redact::scrub(message),
    }
}

async fn send_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &ServerFrame) -> Result<()> {
    let mut bytes = serde_json::to_vec(frame).context("encode headless server frame")?;
    if bytes.len() > MAX_SERVER_FRAME_BYTES {
        bail!("headless server frame exceeds {MAX_SERVER_FRAME_BYTES} bytes");
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .context("write headless server frame")
}

struct FrameReader<R> {
    inner: R,
    pending: Vec<u8>,
    max_frame_bytes: usize,
    pending_budget: Arc<Semaphore>,
    reserved_bytes: usize,
    partial_started_at: Option<tokio::time::Instant>,
}

/// One completed client frame that keeps its share of the global input budget until parsing and
/// submission admission are finished. Releasing permits inside `FrameReader` before returning the
/// bytes would let every connection deserialize a maximum-sized frame concurrently.
struct FrameBytes {
    bytes: Box<[u8]>,
    pending_budget: Arc<Semaphore>,
    reserved_bytes: usize,
}

impl std::fmt::Debug for FrameBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrameBytes")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl AsRef<[u8]> for FrameBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for FrameBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Drop for FrameBytes {
    fn drop(&mut self) {
        if self.reserved_bytes > 0 {
            self.pending_budget.add_permits(self.reserved_bytes);
            self.reserved_bytes = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R, pending_budget: Arc<Semaphore>) -> Self {
        Self::with_limit(inner, MAX_CLIENT_FRAME_BYTES, pending_budget)
    }

    fn with_limit(inner: R, max_frame_bytes: usize, pending_budget: Arc<Semaphore>) -> Self {
        Self {
            inner,
            pending: Vec::with_capacity(4096),
            max_frame_bytes,
            pending_budget,
            reserved_bytes: 0,
            partial_started_at: None,
        }
    }

    async fn next_frame(&mut self) -> Result<Option<FrameBytes>> {
        self.next_frame_inner(None).await
    }

    async fn next_frame_with_partial_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<FrameBytes>> {
        self.next_frame_inner(Some(timeout)).await
    }

    async fn next_frame_inner(&mut self, timeout: Option<Duration>) -> Result<Option<FrameBytes>> {
        loop {
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                if end > self.max_frame_bytes {
                    bail!(
                        "headless client frame exceeds {} bytes",
                        self.max_frame_bytes
                    );
                }
                // Move the potentially large allocation out with the completed frame. Retaining
                // its capacity in this long-lived reader would bypass the shared byte budget
                // after the logical bytes were released.
                let mut frame = std::mem::take(&mut self.pending);
                self.pending = frame.split_off(end + 1);
                self.transfer_pending_bytes(end + 1);
                frame.pop();
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                if self.pending.is_empty() {
                    self.partial_started_at = None;
                }
                return Ok(Some(FrameBytes {
                    bytes: frame.into_boxed_slice(),
                    pending_budget: Arc::clone(&self.pending_budget),
                    reserved_bytes: end + 1,
                }));
            }
            if self.pending.len() > self.max_frame_bytes {
                bail!(
                    "headless client frame exceeds {} bytes",
                    self.max_frame_bytes
                );
            }
            let mut chunk = [0_u8; 8192];
            let read = if let (Some(timeout), Some(started_at)) = (timeout, self.partial_started_at)
            {
                tokio::time::timeout_at(started_at + timeout, self.inner.read(&mut chunk))
                    .await
                    .context("headless partial client frame timed out")?
                    .context("read client frame")?
            } else {
                self.inner
                    .read(&mut chunk)
                    .await
                    .context("read client frame")?
            };
            if read == 0 {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                if self.pending.len() > self.max_frame_bytes {
                    bail!(
                        "headless client frame exceeds {} bytes",
                        self.max_frame_bytes
                    );
                }
                let frame = std::mem::take(&mut self.pending);
                let reserved_bytes = frame.len();
                self.transfer_pending_bytes(reserved_bytes);
                self.partial_started_at = None;
                return Ok(Some(FrameBytes {
                    bytes: frame.into_boxed_slice(),
                    pending_budget: Arc::clone(&self.pending_budget),
                    reserved_bytes,
                }));
            }
            let permit_count =
                u32::try_from(read).expect("the fixed client read chunk fits in u32");
            let permits = self
                .pending_budget
                .clone()
                .try_acquire_many_owned(permit_count)
                .context("aggregate headless partial-frame byte budget exhausted")?;
            permits.forget();
            self.reserved_bytes += read;
            if self.pending.is_empty() {
                self.partial_started_at = Some(tokio::time::Instant::now());
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    fn transfer_pending_bytes(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.reserved_bytes);
        self.reserved_bytes -= bytes;
    }
}

impl<R> Drop for FrameReader<R> {
    fn drop(&mut self) {
        if self.reserved_bytes > 0 {
            self.pending_budget.add_permits(self.reserved_bytes);
            self.reserved_bytes = 0;
        }
    }
}

fn log(value: Value) {
    eprintln!("{}", serde_json::to_string(&value).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_reader_keeps_coalesced_frames_separate() {
        let bytes = b"{\"type\":\"hello\"}\n{\"type\":\"submit\"}\r\n".as_slice();
        let budget = Arc::new(Semaphore::new(MAX_PENDING_CLIENT_BYTES));
        let mut reader = FrameReader::new(bytes, budget.clone());
        assert_eq!(
            reader.next_frame().await.unwrap().unwrap().as_ref(),
            b"{\"type\":\"hello\"}"
        );
        assert_eq!(
            reader.next_frame().await.unwrap().unwrap().as_ref(),
            b"{\"type\":\"submit\"}"
        );
        assert!(reader.next_frame().await.unwrap().is_none());
        assert_eq!(budget.available_permits(), MAX_PENDING_CLIENT_BYTES);
    }

    #[tokio::test]
    async fn frame_reader_rejects_an_oversized_unterminated_frame() {
        let bytes = vec![b'x'; 33];
        let budget = Arc::new(Semaphore::new(64));
        let mut reader = FrameReader::with_limit(bytes.as_slice(), 32, budget);
        assert!(reader.next_frame().await.is_err());
    }

    #[tokio::test]
    async fn frame_reader_enforces_and_releases_the_shared_pending_byte_budget() {
        let budget = Arc::new(Semaphore::new(8));
        let first_bytes = b"a\n123456".as_slice();
        let mut first = FrameReader::with_limit(first_bytes, 32, budget.clone());
        assert_eq!(first.next_frame().await.unwrap().unwrap().as_ref(), b"a");
        assert_eq!(budget.available_permits(), 2);

        let second_bytes = b"xx\n".as_slice();
        let mut second = FrameReader::with_limit(second_bytes, 32, budget.clone());
        let error = second.next_frame().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("aggregate headless partial-frame byte budget exhausted")
        );
        assert_eq!(budget.available_permits(), 2);

        drop(first);
        assert_eq!(budget.available_permits(), 8);
        let third_bytes = b"xx\n".as_slice();
        let mut third = FrameReader::with_limit(third_bytes, 32, budget.clone());
        assert_eq!(third.next_frame().await.unwrap().unwrap().as_ref(), b"xx");
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn completed_frame_keeps_its_global_budget_until_parsing_drops_it() {
        let budget = Arc::new(Semaphore::new(8));
        let mut reader = FrameReader::with_limit(b"hello\n".as_slice(), 32, budget.clone());
        let frame = reader.next_frame().await.unwrap().unwrap();
        assert_eq!(frame.as_ref(), b"hello");
        assert_eq!(
            budget.available_permits(),
            2,
            "the returned frame still owns its five bytes plus newline"
        );
        drop(frame);
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn frame_reader_budget_and_deadline_survive_cancelled_reads() {
        let budget = Arc::new(Semaphore::new(64));
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"unfinished").await.unwrap();
        let mut reader = FrameReader::with_limit(reader, 32, budget.clone());

        let cancelled = tokio::time::timeout(
            Duration::from_secs(1),
            reader.next_frame_with_partial_timeout(Duration::from_secs(10)),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(budget.available_permits(), 54);

        tokio::time::advance(Duration::from_secs(8)).await;
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            reader.next_frame_with_partial_timeout(Duration::from_secs(10)),
        )
        .await
        .expect("the original partial-frame deadline precedes the outer timeout")
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("headless partial client frame timed out")
        );
        assert_eq!(budget.available_permits(), 54);
        drop(reader);
        assert_eq!(budget.available_permits(), 64);
    }

    #[test]
    fn client_frame_bound_covers_the_protocol_image_and_escaped_text_ceilings() {
        const {
            assert!(
                MAX_CLIENT_FRAME_BYTES > MAX_TOTAL_IMAGE_BASE64_BYTES + (MAX_TASK_TEXT_BYTES * 6)
            );
            assert!(MAX_SERVER_FRAME_BYTES == 1024 * 1024);
            assert!(MAX_PENDING_CLIENT_BYTES == MAX_CLIENT_FRAME_BYTES * 2);
        }
    }
}
