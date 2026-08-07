use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub(super) const MAX_SERVER_FRAME_BYTES: usize = 1024 * 1024;
const MAX_ENCODED_SERVER_FRAME_BYTES: usize = MAX_SERVER_FRAME_BYTES + 1;
const MAX_ASSEMBLED_PROVIDER_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
/// A 32 MiB provider output can expand sixfold when every byte requires a JSON `\u00xx` escape.
/// One additional MiB covers the typed result/event envelope and bounded diagnostics.
const MAX_LOGICAL_SERVER_FRAME_BYTES: usize =
    (MAX_ASSEMBLED_PROVIDER_OUTPUT_BYTES * 6) + MAX_SERVER_FRAME_BYTES;
const FRAME_CHUNK_SOURCE_BYTES: usize = 512 * 1024;
const FRAME_CHUNK_CHANNEL_CAPACITY: usize = 2;
const FRAME_CHUNK_OVERHEAD_CHARGE: usize = 1024;
pub(super) const REPLAY_CAPACITY: usize = 4096;
pub(super) const REPLAY_BYTE_CAPACITY: usize = MAX_ENCODED_SERVER_FRAME_BYTES * 16;
pub(super) const MAX_IN_FLIGHT_SERVER_BYTES: usize = MAX_ENCODED_SERVER_FRAME_BYTES * 8;
/// A replay lease charges the worst-case encoded size of one logical frame. This admits one legal
/// maximum frame while preventing staggered slow clients from pinning distinct evicted ring
/// generations without a process-wide byte authority.
pub(super) const MAX_PINNED_REPLAY_BYTES: usize = (MAX_LOGICAL_SERVER_FRAME_BYTES.div_ceil(3) * 4)
    + (MAX_LOGICAL_SERVER_FRAME_BYTES.div_ceil(FRAME_CHUNK_SOURCE_BYTES)
        * FRAME_CHUNK_OVERHEAD_CHARGE);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const FRAGMENTED_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum ServerFrame {
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
    ControlReply {
        protocol_version: u32,
        request_id: u64,
        reply: Value,
    },
    Error {
        protocol_version: u32,
        code: &'static str,
        message: String,
    },
    FrameChunk {
        protocol_version: u32,
        stream: &'static str,
        logical_type: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rollout_seq: Option<u64>,
        logical_bytes: usize,
        chunk_index: u32,
        chunk_count: u32,
        encoding: &'static str,
        data: String,
    },
}

impl ServerFrame {
    pub(super) fn live_seq(&self) -> Option<u64> {
        match self {
            Self::Event { seq, .. } | Self::Result { seq, .. } => Some(*seq),
            Self::Hello { .. }
            | Self::Rollout { .. }
            | Self::ControlReply { .. }
            | Self::Error { .. }
            | Self::FrameChunk { .. } => None,
        }
    }

    fn logical_identity(&self) -> Result<LogicalIdentity> {
        let identity = match self {
            Self::Hello { .. } => LogicalIdentity::control("hello"),
            Self::Event { seq, .. } => LogicalIdentity::live("event", *seq),
            Self::Result { seq, .. } => LogicalIdentity::live("result", *seq),
            Self::Rollout { rollout_seq, .. } => LogicalIdentity::rollout(*rollout_seq),
            Self::ControlReply { .. } => LogicalIdentity::control("control_reply"),
            Self::Error { .. } => LogicalIdentity::control("error"),
            Self::FrameChunk { .. } => {
                bail!("an already-fragmented frame cannot be fragmented recursively")
            }
        };
        Ok(identity)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveFrameKind {
    Event,
    Result,
}

#[derive(Clone, Copy)]
struct LogicalIdentity {
    stream: &'static str,
    logical_type: &'static str,
    seq: Option<u64>,
    rollout_seq: Option<u64>,
}

#[derive(Clone, Copy)]
struct FragmentPlan {
    identity: LogicalIdentity,
    logical_bytes: usize,
    chunk_count: u32,
}

impl LogicalIdentity {
    fn control(logical_type: &'static str) -> Self {
        Self {
            stream: "control",
            logical_type,
            seq: None,
            rollout_seq: None,
        }
    }

    fn live(logical_type: &'static str, seq: u64) -> Self {
        Self {
            stream: "live",
            logical_type,
            seq: Some(seq),
            rollout_seq: None,
        }
    }

    fn rollout(rollout_seq: u64) -> Self {
        Self {
            stream: "rollout",
            logical_type: "rollout",
            seq: None,
            rollout_seq: Some(rollout_seq),
        }
    }
}

enum PreparedPayload {
    Single(Box<[u8]>),
    Fragmented {
        frame: Arc<ServerFrame>,
        identity: LogicalIdentity,
        logical_bytes: usize,
        chunk_count: u32,
    },
}

pub(super) struct EncodedServerFrame {
    pub(super) seq: u64,
    kind: LiveFrameKind,
    payload: PreparedPayload,
    serialized_bytes: usize,
}

pub(super) struct LeasedServerFrame {
    frame: Arc<EncodedServerFrame>,
    retention: OwnedSemaphorePermit,
}

impl LeasedServerFrame {
    pub(super) fn seq(&self) -> u64 {
        self.frame.seq
    }
}

impl EncodedServerFrame {
    pub(super) fn from_live(frame: ServerFrame) -> Result<Self> {
        let seq = frame
            .live_seq()
            .context("only live event/result frames may enter the replay ring")?;
        let kind = match frame {
            ServerFrame::Event { .. } => LiveFrameKind::Event,
            ServerFrame::Result { .. } => LiveFrameKind::Result,
            _ => bail!("only live event/result frames may enter the replay ring"),
        };
        let (payload, serialized_bytes) = prepare(frame)?;
        Ok(Self {
            seq,
            kind,
            payload,
            serialized_bytes,
        })
    }
}

pub(super) struct ReplayRing {
    frames: VecDeque<Arc<EncodedServerFrame>>,
    serialized_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    evicted_result_through: Option<u64>,
}

impl ReplayRing {
    pub(super) fn production() -> Self {
        Self::with_limits(REPLAY_CAPACITY, REPLAY_BYTE_CAPACITY)
    }

    fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(max_entries),
            serialized_bytes: 0,
            max_entries,
            max_bytes,
            evicted_result_through: None,
        }
    }

    pub(super) fn push(&mut self, frame: Arc<EncodedServerFrame>) {
        self.serialized_bytes = self.serialized_bytes.saturating_add(frame.serialized_bytes);
        self.frames.push_back(frame);
        // Evict complete logical frames only. Retain the newest even if it alone exceeds the soft
        // byte cap; the upstream-derived logical hard cap remains the absolute allocation bound.
        while self.frames.len() > 1
            && (self.frames.len() > self.max_entries || self.serialized_bytes > self.max_bytes)
        {
            if let Some(evicted) = self.frames.pop_front() {
                self.serialized_bytes = self
                    .serialized_bytes
                    .saturating_sub(evicted.serialized_bytes);
                if evicted.kind == LiveFrameKind::Result {
                    self.evicted_result_through = Some(
                        self.evicted_result_through
                            .map_or(evicted.seq, |prior| prior.max(evicted.seq)),
                    );
                }
            }
        }
    }

    pub(super) fn oldest_seq(&self) -> Option<u64> {
        self.frames.front().map(|frame| frame.seq)
    }

    /// Lease one exact retained frame without waiting while holding the ring lock. The permit is
    /// acquired before cloning the Arc, so a client that cannot obtain aggregate retention
    /// authority never pins an evicted payload generation.
    pub(super) fn try_lease(
        &self,
        seq: u64,
        retention_budget: &Arc<Semaphore>,
    ) -> Option<LeasedServerFrame> {
        let frame = self.frames.iter().find(|frame| frame.seq == seq)?;
        let charge = u32::try_from(frame.serialized_bytes)
            .expect("the bounded logical frame replay charge fits in u32");
        let retention = retention_budget
            .clone()
            .try_acquire_many_owned(charge)
            .ok()?;
        Some(LeasedServerFrame {
            frame: frame.clone(),
            retention,
        })
    }

    /// Resolve one live notification only when it is the exact successor and still retained.
    /// Broadcast carries only this sequence number, so the byte-capped ring remains the sole
    /// owner of payload memory.
    pub(super) fn notified_next(
        &self,
        delivered: u64,
        notified: u64,
        retention_budget: &Arc<Semaphore>,
    ) -> Option<LeasedServerFrame> {
        if delivered.checked_add(1) != Some(notified) {
            return None;
        }
        self.try_lease(notified, retention_budget)
    }

    pub(super) fn rollout_required(&self, requested: u64, cursor: u64) -> bool {
        requested < cursor
            && self
                .frames
                .front()
                .is_none_or(|oldest| requested < oldest.seq.saturating_sub(1))
    }

    pub(super) fn lost_result_after(&self, requested: u64) -> bool {
        self.evicted_result_through
            .is_some_and(|evicted| requested < evicted)
    }
}

fn prepare(frame: ServerFrame) -> Result<(PreparedPayload, usize)> {
    let logical_bytes = serialized_len(&frame)?;
    if logical_bytes <= MAX_SERVER_FRAME_BYTES {
        let bytes = encode_physical(&frame)?;
        let serialized_bytes = bytes.len();
        return Ok((PreparedPayload::Single(bytes), serialized_bytes));
    }
    let identity = frame.logical_identity()?;
    let chunks = logical_bytes.div_ceil(FRAME_CHUNK_SOURCE_BYTES);
    let chunk_count =
        u32::try_from(chunks).context("fragmented server frame has too many chunks")?;
    let base64_bytes = logical_bytes.div_ceil(3).saturating_mul(4);
    let serialized_bytes =
        base64_bytes.saturating_add(chunks.saturating_mul(FRAME_CHUNK_OVERHEAD_CHARGE));
    Ok((
        PreparedPayload::Fragmented {
            frame: Arc::new(frame),
            identity,
            logical_bytes,
            chunk_count,
        },
        serialized_bytes,
    ))
}

fn serialized_len(frame: &ServerFrame) -> Result<usize> {
    let mut counter = LimitedCounter::default();
    let result = serde_json::to_writer(&mut counter, frame);
    if counter.exceeded {
        bail!(
            "headless logical server frame exceeds {MAX_LOGICAL_SERVER_FRAME_BYTES} serialized bytes"
        );
    }
    result.context("measure headless logical server frame")?;
    Ok(counter.written)
}

#[derive(Default)]
struct LimitedCounter {
    written: usize,
    exceeded: bool,
}

impl io::Write for LimitedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("logical frame byte counter overflow"));
        };
        if next > MAX_LOGICAL_SERVER_FRAME_BYTES {
            self.exceeded = true;
            return Err(io::Error::other("logical frame byte ceiling exceeded"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_physical(frame: &ServerFrame) -> Result<Box<[u8]>> {
    let mut bytes = serde_json::to_vec(frame).context("encode headless server frame")?;
    if bytes.len() > MAX_SERVER_FRAME_BYTES {
        bail!("headless physical server frame exceeds {MAX_SERVER_FRAME_BYTES} bytes");
    }
    bytes.push(b'\n');
    Ok(bytes.into_boxed_slice())
}

pub(super) async fn send_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    frame_preparers: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    frame: ServerFrame,
) -> Result<()> {
    let prepare_permit = frame_preparers
        .clone()
        .acquire_owned()
        .await
        .context("headless frame-preparation gate closed")?;
    // The permit moves into the worker. If a whole-replay deadline cancels this await, no later
    // replay can detach another maximum serializer until this one actually unwinds.
    let (prepare_permit, prepared) =
        tokio::task::spawn_blocking(move || (prepare_permit, prepare(frame)))
            .await
            .context("headless frame-preparation task join")?;
    let (payload, _) = prepared?;
    drop(prepare_permit);
    send_payload(writer, outbound_budget, fragment_encoders, &payload, None).await
}

pub(super) async fn send_encoded_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    frame: LeasedServerFrame,
) -> Result<()> {
    send_payload(
        writer,
        outbound_budget,
        fragment_encoders,
        &frame.frame.payload,
        Some(frame.retention),
    )
    .await
}

async fn send_payload<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    payload: &PreparedPayload,
    retention: Option<OwnedSemaphorePermit>,
) -> Result<()> {
    match payload {
        PreparedPayload::Single(bytes) => {
            let _retention = retention;
            send_physical_bytes(writer, outbound_budget, bytes).await
        }
        PreparedPayload::Fragmented {
            frame,
            identity,
            logical_bytes,
            chunk_count,
        } => tokio::time::timeout(
            FRAGMENTED_FRAME_TIMEOUT,
            send_fragmented(
                writer,
                outbound_budget,
                fragment_encoders,
                frame.clone(),
                FragmentPlan {
                    identity: *identity,
                    logical_bytes: *logical_bytes,
                    chunk_count: *chunk_count,
                },
                retention,
            ),
        )
        .await
        .context("fragmented headless server frame timed out")?,
    }
}

async fn send_fragmented<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    fragment_encoders: &Arc<Semaphore>,
    frame: Arc<ServerFrame>,
    plan: FragmentPlan,
    retention: Option<OwnedSemaphorePermit>,
) -> Result<()> {
    // Only one logical serializer may materialize raw/base64 chunks at a time. Other clients hold
    // only shared `Arc`s while waiting, so 32 slow clients cannot multiply the largest Value.
    let encoder_permit = fragment_encoders
        .clone()
        .acquire_owned()
        .await
        .context("headless fragment encoder gate closed")?;
    let (sender, mut receiver) = mpsc::channel(FRAME_CHUNK_CHANNEL_CAPACITY);
    // The owned permit lives inside the blocking worker. If the async consumer is cancelled by
    // the logical-frame deadline, dropping the receiver wakes `blocking_send`; no successor can
    // start until that worker has actually unwound and released the permit.
    let encoder = tokio::task::spawn_blocking(move || {
        let encoded = stream_json_chunks(frame, sender);
        (encoder_permit, retention, encoded)
    });

    for chunk_index in 0..plan.chunk_count {
        let raw = receiver
            .recv()
            .await
            .context("fragment encoder ended before the declared chunk count")??;
        let chunk = ServerFrame::FrameChunk {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            stream: plan.identity.stream,
            logical_type: plan.identity.logical_type,
            seq: plan.identity.seq,
            rollout_seq: plan.identity.rollout_seq,
            logical_bytes: plan.logical_bytes,
            chunk_index,
            chunk_count: plan.chunk_count,
            encoding: "base64_json_utf8",
            data: base64::engine::general_purpose::STANDARD.encode(raw),
        };
        let bytes = encode_physical(&chunk)?;
        send_physical_bytes(writer, outbound_budget, &bytes).await?;
    }
    if receiver.recv().await.is_some() {
        bail!("fragment encoder exceeded the declared chunk count");
    }
    let (_encoder_permit, _retention, encoded) = encoder
        .await
        .context("headless fragment encoder task join")?;
    encoded?;
    Ok(())
}

fn stream_json_chunks(
    frame: Arc<ServerFrame>,
    sender: mpsc::Sender<Result<Box<[u8]>>>,
) -> Result<()> {
    let mut writer = ChunkWriter::new(sender);
    let encoded = serde_json::to_writer(&mut writer, frame.as_ref())
        .context("stream-encode fragmented headless server frame");
    match encoded {
        Ok(()) => writer.finish(),
        Err(error) => {
            writer.send_error(anyhow::anyhow!(error.to_string()));
            Err(error)
        }
    }
}

struct ChunkWriter {
    sender: mpsc::Sender<Result<Box<[u8]>>>,
    pending: Vec<u8>,
}

impl ChunkWriter {
    fn new(sender: mpsc::Sender<Result<Box<[u8]>>>) -> Self {
        Self {
            sender,
            pending: Vec::with_capacity(FRAME_CHUNK_SOURCE_BYTES),
        }
    }

    fn send_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::replace(
            &mut self.pending,
            Vec::with_capacity(FRAME_CHUNK_SOURCE_BYTES),
        );
        self.sender
            .blocking_send(Ok(chunk.into_boxed_slice()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fragment receiver closed"))
    }

    fn send_error(&self, error: anyhow::Error) {
        let _ = self.sender.blocking_send(Err(error));
    }

    fn finish(mut self) -> Result<()> {
        self.send_pending()
            .context("send final headless frame fragment")
    }
}

impl io::Write for ChunkWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let original = bytes.len();
        while !bytes.is_empty() {
            let available = FRAME_CHUNK_SOURCE_BYTES - self.pending.len();
            let take = available.min(bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() == FRAME_CHUNK_SOURCE_BYTES {
                self.send_pending()?;
            }
        }
        Ok(original)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn send_physical_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    outbound_budget: &Arc<Semaphore>,
    bytes: &[u8],
) -> Result<()> {
    let permits = u32::try_from(bytes.len()).expect("a bounded physical server frame fits in u32");
    let _reservation = outbound_budget
        .clone()
        .acquire_many_owned(permits)
        .await
        .context("headless outbound byte budget closed")?;
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(bytes))
        .await
        .context("headless server-frame write timed out")?
        .context("write headless server frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::AsyncReadExt as _;

    fn event(seq: u64, text: String) -> ServerFrame {
        ServerFrame::Event {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            seq,
            event: json!({"text": text}),
        }
    }

    #[test]
    fn oversized_live_frame_is_fragmented_and_ring_entries_are_atomic_and_byte_bounded() {
        let large = EncodedServerFrame::from_live(event(
            1,
            "x".repeat(MAX_SERVER_FRAME_BYTES + FRAME_CHUNK_SOURCE_BYTES),
        ))
        .unwrap();
        assert!(matches!(large.payload, PreparedPayload::Fragmented { .. }));
        assert!(large.serialized_bytes > MAX_SERVER_FRAME_BYTES);

        let large = Arc::new(large);
        let mut ring = ReplayRing::with_limits(4, MAX_SERVER_FRAME_BYTES);
        ring.push(large.clone());
        let retention = Arc::new(Semaphore::new(MAX_PINNED_REPLAY_BYTES));
        let replay = ring.try_lease(1, &retention).unwrap();
        assert!(Arc::ptr_eq(&large, &replay.frame));
        assert!(
            ring.serialized_bytes > ring.max_bytes,
            "the newest logical frame remains whole above the soft cap"
        );
    }

    #[test]
    fn maximum_protocol_task_rollout_uses_fragments_below_the_physical_cap() {
        let rollout = ServerFrame::Rollout {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            rollout_seq: 11,
            event: json!({"task": "x".repeat(core_protocol::task::MAX_TASK_TEXT_BYTES)}),
        };
        let (payload, _) = prepare(rollout).unwrap();
        let PreparedPayload::Fragmented {
            logical_bytes,
            chunk_count,
            ..
        } = payload
        else {
            panic!("the valid maximum task must use logical fragmentation");
        };
        assert!(logical_bytes > MAX_SERVER_FRAME_BYTES);
        assert!(chunk_count >= 2);
        let sample = ServerFrame::FrameChunk {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            stream: "rollout",
            logical_type: "rollout",
            seq: None,
            rollout_seq: Some(11),
            logical_bytes,
            chunk_index: 0,
            chunk_count,
            encoding: "base64_json_utf8",
            data: base64::engine::general_purpose::STANDARD
                .encode(vec![b'x'; FRAME_CHUNK_SOURCE_BYTES]),
        };
        assert!(encode_physical(&sample).unwrap().len() <= MAX_ENCODED_SERVER_FRAME_BYTES);
    }

    #[tokio::test]
    async fn streamed_fragments_round_trip_to_the_exact_logical_json() {
        let logical = event(19, "fragment me".repeat((MAX_SERVER_FRAME_BYTES / 11) + 1));
        let expected = serde_json::to_vec(&logical).unwrap();
        assert!(expected.len() > MAX_SERVER_FRAME_BYTES);

        let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
        let budget = Arc::new(Semaphore::new(MAX_IN_FLIGHT_SERVER_BYTES));
        let preparers = Arc::new(Semaphore::new(1));
        let fragments = Arc::new(Semaphore::new(1));
        let sender = tokio::spawn(async move {
            send_frame(&mut writer, &budget, &preparers, &fragments, logical).await
        });
        let mut wire = Vec::new();
        reader.read_to_end(&mut wire).await.unwrap();
        sender.await.unwrap().unwrap();

        let mut rebuilt = Vec::new();
        let mut expected_index = 0_u64;
        for line in wire
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            assert!(line.len() <= MAX_SERVER_FRAME_BYTES);
            let frame: Value = serde_json::from_slice(line).unwrap();
            assert_eq!(frame["type"], "frame_chunk");
            assert_eq!(frame["stream"], "live");
            assert_eq!(frame["logical_type"], "event");
            assert_eq!(frame["seq"], 19);
            assert_eq!(frame["chunk_index"], expected_index);
            assert_eq!(frame["encoding"], "base64_json_utf8");
            expected_index += 1;
            rebuilt.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(frame["data"].as_str().unwrap())
                    .unwrap(),
            );
        }
        assert!(expected_index >= 2);
        assert_eq!(rebuilt, expected);
    }

    #[test]
    fn valid_maximum_provider_result_is_measured_without_a_whole_encoded_allocation() {
        let result = ServerFrame::Result {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            seq: 7,
            result: json!({"assistant_text": "\u{0000}".repeat(MAX_ASSEMBLED_PROVIDER_OUTPUT_BYTES)}),
        };
        let measured = serialized_len(&result).unwrap();
        assert!(measured > 9 * MAX_SERVER_FRAME_BYTES);
        assert!(measured <= MAX_LOGICAL_SERVER_FRAME_BYTES);
        let prepared = EncodedServerFrame::from_live(result).unwrap();
        assert!(matches!(
            prepared.payload,
            PreparedPayload::Fragmented { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_physical_writer_hits_the_central_write_timeout() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let budget = Arc::new(Semaphore::new(MAX_IN_FLIGHT_SERVER_BYTES));
        let bytes = encode_physical(&ServerFrame::Error {
            protocol_version: core_protocol::PROTOCOL_VERSION,
            code: "fixture",
            message: "x".repeat(1024),
        })
        .unwrap();
        let task_budget = budget.clone();
        let task =
            tokio::spawn(
                async move { send_physical_bytes(&mut writer, &task_budget, &bytes).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(WRITE_TIMEOUT + Duration::from_millis(1)).await;
        let error = task.await.unwrap().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("headless server-frame write timed out")
        );
        assert_eq!(budget.available_permits(), MAX_IN_FLIGHT_SERVER_BYTES);
    }

    #[test]
    fn evicted_terminal_result_is_an_explicit_exact_replay_gap() {
        let mut ring = ReplayRing::with_limits(1, usize::MAX);
        ring.push(Arc::new(
            EncodedServerFrame::from_live(ServerFrame::Result {
                protocol_version: core_protocol::PROTOCOL_VERSION,
                seq: 1,
                result: json!({"assistant_text":"first"}),
            })
            .unwrap(),
        ));
        ring.push(Arc::new(
            EncodedServerFrame::from_live(event(2, "next".into())).unwrap(),
        ));
        assert!(ring.lost_result_after(0));
        assert!(!ring.lost_result_after(1));
        assert!(ring.rollout_required(0, 2));
    }

    #[test]
    fn sequence_notification_requires_contiguity_and_a_retained_exact_frame() {
        let mut ring = ReplayRing::with_limits(1, usize::MAX);
        let retention = Arc::new(Semaphore::new(MAX_PINNED_REPLAY_BYTES));
        ring.push(Arc::new(
            EncodedServerFrame::from_live(event(1, "first".into())).unwrap(),
        ));
        ring.push(Arc::new(
            EncodedServerFrame::from_live(event(2, "second".into())).unwrap(),
        ));

        assert!(
            ring.notified_next(0, 1, &retention).is_none(),
            "an evicted notified frame must fail closed"
        );
        assert!(
            ring.notified_next(0, 2, &retention).is_none(),
            "a notification gap must fail closed even when the later frame remains"
        );
        assert_eq!(ring.notified_next(1, 2, &retention).unwrap().seq(), 2);
    }
}
