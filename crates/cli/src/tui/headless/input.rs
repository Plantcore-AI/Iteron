use super::auth::BearerToken;
use anyhow::{Context, Result, bail};
use core_protocol::{Op, input::MAX_TOTAL_IMAGE_BASE64_BYTES, task::MAX_TASK_TEXT_BYTES};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};

pub(super) const MAX_HELLO_FRAME_BYTES: usize = 4 * 1024;
/// One multimodal SQ frame may contain the aggregate encoded-image ceiling plus a maximally
/// escaped task string. Keep the transport bound derived and finite rather than making the
/// protocol's valid image envelope impossible to submit.
pub(super) const MAX_CLIENT_FRAME_BYTES: usize =
    MAX_TOTAL_IMAGE_BASE64_BYTES + (MAX_TASK_TEXT_BYTES * 6) + (64 * 1024);
/// Bound aggregate bytes retained by all partially read client frames. Per-reader limits still
/// reject any single oversized frame; this process-wide budget prevents many connections from
/// retaining one almost-maximal frame apiece.
pub(super) const MAX_PENDING_CLIENT_BYTES: usize = MAX_CLIENT_FRAME_BYTES * 2;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ClientFrame {
    Hello {
        bearer_token: BearerToken,
        protocol_version: u32,
        #[serde(default)]
        resume_from: Option<u64>,
    },
    Submit {
        protocol_version: u32,
        op: Op,
    },
}

pub(super) fn parse(bytes: &[u8]) -> Result<ClientFrame> {
    serde_json::from_slice(bytes).context("decode bounded headless client frame")
}

pub(super) struct FrameReader<R> {
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
pub(super) struct FrameBytes {
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
        // The first frame carries the bearer token; later frames can carry operator text. Clear the
        // completed buffer before releasing its allocation as well as its global byte permits.
        self.bytes.zeroize();
        if self.reserved_bytes > 0 {
            self.pending_budget.add_permits(self.reserved_bytes);
            self.reserved_bytes = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub(super) fn new(inner: R, pending_budget: Arc<Semaphore>) -> Self {
        Self::with_limit(inner, MAX_HELLO_FRAME_BYTES, pending_budget)
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

    pub(super) fn set_max_frame_bytes(&mut self, max_frame_bytes: usize) {
        self.max_frame_bytes = max_frame_bytes;
    }

    pub(super) async fn next_frame(&mut self) -> Result<Option<FrameBytes>> {
        self.next_frame_inner(None).await
    }

    pub(super) async fn next_frame_with_partial_timeout(
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
                // `split_off` copies the coalesced suffix into `self.pending` but can leave the
                // original bytes in this Vec's spare capacity. Clear that spare storage before
                // `into_boxed_slice` is allowed to release or shrink the allocation.
                frame.spare_capacity_mut().zeroize();
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
            let mut chunk = Zeroizing::new([0_u8; 8192]);
            let remaining_with_delimiter = self
                .max_frame_bytes
                .saturating_add(1)
                .saturating_sub(self.pending.len());
            let read_capacity = chunk.len().min(remaining_with_delimiter);
            if read_capacity == 0 {
                bail!(
                    "headless client frame exceeds {} bytes",
                    self.max_frame_bytes
                );
            }
            let read = if let (Some(timeout), Some(started_at)) = (timeout, self.partial_started_at)
            {
                tokio::time::timeout_at(
                    started_at + timeout,
                    self.inner.read(&mut chunk[..read_capacity]),
                )
                .await
                .context("headless partial client frame timed out")?
                .context("read client frame")?
            } else {
                self.inner
                    .read(&mut chunk[..read_capacity])
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
        // A timeout or disconnect can leave a partial first frame (and therefore part of the
        // bearer token) in this allocation. Clear it before returning either memory or permits.
        self.pending.zeroize();
        if self.reserved_bytes > 0 {
            self.pending_budget.add_permits(self.reserved_bytes);
            self.reserved_bytes = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

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
}
