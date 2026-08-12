//! Bounded, frontend-side loading of explicitly named local raster images.
//!
//! This module does no provider shaping and performs no implicit filesystem discovery. Callers
//! must first obtain a path from an explicit flag, a whole-input path paste, or an `@image(...)`
//! mention parsed here.

use base64::Engine as _;
use iteron_protocol::input::{
    ContentSegment, ContentSegments, ImageContent, ImageMediaType, MAX_IMAGE_BASE64_BYTES,
    MAX_INPUT_IMAGES, MAX_TOTAL_IMAGE_BASE64_BYTES,
};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, LazyLock, Mutex, mpsc};
use std::time::{Duration, Instant};

pub const MAX_IMAGE_FILE_BYTES: usize = (MAX_IMAGE_BASE64_BYTES / 4) * 3;
pub const MAX_TOTAL_IMAGE_FILE_BYTES: usize = (MAX_TOTAL_IMAGE_BASE64_BYTES / 4) * 3;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const FILE_READ_TIMEOUT: Duration = Duration::from_secs(3);
static FILE_READ_GATE: LazyLock<Arc<FileReadGate>> =
    LazyLock::new(|| Arc::new(FileReadGate::default()));

#[path = "image_input/decode.rs"]
mod decode;
#[path = "image_input/heic.rs"]
mod heic;
#[path = "image_input/parse.rs"]
mod parse;
#[path = "image_input/routing.rs"]
mod routing;
#[path = "image_input/sniff.rs"]
mod sniff;
#[path = "image_input/types.rs"]
mod types;

pub use parse::{parse_explicit_image_path, parse_image_mentions};
pub(crate) use routing::{BinaryMediaInspectionPolicy, UnknownMimePolicy};
use sniff::{SourceFormat, extension_format, sniff_image};
pub use types::{ImageInputError, ImageInputErrorKind, SafeDisplayName};

/// Exact fixed decode/admission owner sampled by tunables composition. Keeping this query beside
/// the loader prevents the registry projection from copying literals that can drift away from the
/// limits which actually reject bytes and decoder work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct MultimodalDecodeEnvelope {
    pub max_images: usize,
    pub per_image_raw_bytes: usize,
    pub aggregate_raw_bytes: usize,
    pub max_dimension: u32,
    pub max_frames: u32,
}

impl MultimodalDecodeEnvelope {
    pub(crate) fn try_new(
        max_images: usize,
        per_image_raw_bytes: usize,
        aggregate_raw_bytes: usize,
        max_dimension: u32,
        max_frames: u32,
    ) -> Result<Self, &'static str> {
        if max_images > MAX_INPUT_IMAGES {
            return Err("multimodal image count exceeds the protocol envelope");
        }
        if per_image_raw_bytes == 0
            || per_image_raw_bytes > MAX_IMAGE_FILE_BYTES
            || aggregate_raw_bytes == 0
            || aggregate_raw_bytes > MAX_TOTAL_IMAGE_FILE_BYTES
            || per_image_raw_bytes > aggregate_raw_bytes
        {
            return Err("multimodal raw-byte limits exceed the protocol envelope");
        }
        if max_dimension == 0
            || max_dimension > decode::MAX_IMAGE_DIMENSION
            || max_frames == 0
            || max_frames > decode::MAX_ANIMATION_FRAMES
        {
            return Err("multimodal decode work exceeds the fixed safety envelope");
        }
        Ok(Self {
            max_images,
            per_image_raw_bytes,
            aggregate_raw_bytes,
            max_dimension,
            max_frames,
        })
    }
}

pub(crate) const fn multimodal_decode_envelope() -> MultimodalDecodeEnvelope {
    MultimodalDecodeEnvelope {
        max_images: MAX_INPUT_IMAGES,
        per_image_raw_bytes: MAX_IMAGE_FILE_BYTES,
        aggregate_raw_bytes: MAX_TOTAL_IMAGE_FILE_BYTES,
        max_dimension: decode::MAX_IMAGE_DIMENSION,
        max_frames: decode::MAX_ANIMATION_FRAMES,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageLoadLimits {
    max_attachments: usize,
    max_file_bytes: usize,
    max_total_file_bytes: usize,
    max_file_encoded_bytes: usize,
    max_total_encoded_bytes: usize,
}

impl ImageLoadLimits {
    #[allow(
        dead_code,
        reason = "kept as a lower-limit test seam while production uses the protocol maxima"
    )]
    pub fn new(
        max_attachments: usize,
        max_file_bytes: usize,
        max_total_file_bytes: usize,
        max_file_encoded_bytes: usize,
        max_total_encoded_bytes: usize,
    ) -> Result<Self, ImageInputError> {
        if max_attachments == 0
            || max_attachments > MAX_INPUT_IMAGES
            || max_file_bytes == 0
            || max_file_bytes > MAX_IMAGE_FILE_BYTES
            || max_total_file_bytes == 0
            || max_total_file_bytes > MAX_TOTAL_IMAGE_FILE_BYTES
            || max_file_encoded_bytes == 0
            || max_file_encoded_bytes > MAX_IMAGE_BASE64_BYTES
            || max_total_encoded_bytes == 0
            || max_total_encoded_bytes > MAX_TOTAL_IMAGE_BASE64_BYTES
        {
            return Err(ImageInputError::unnamed(ImageInputErrorKind::InvalidLimits));
        }
        Ok(Self {
            max_attachments,
            max_file_bytes,
            max_total_file_bytes,
            max_file_encoded_bytes,
            max_total_encoded_bytes,
        })
    }
}

impl Default for ImageLoadLimits {
    fn default() -> Self {
        Self {
            max_attachments: MAX_INPUT_IMAGES,
            max_file_bytes: MAX_IMAGE_FILE_BYTES,
            max_total_file_bytes: MAX_TOTAL_IMAGE_FILE_BYTES,
            max_file_encoded_bytes: MAX_IMAGE_BASE64_BYTES,
            max_total_encoded_bytes: MAX_TOTAL_IMAGE_BASE64_BYTES,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ImageAttachment {
    /// Draft-local identity, shown on the chip as `#N` and named by the in-line
    /// `[Image #N]` anchor. See [`ImageAttachments::next_id`] for why it is monotonic.
    id: u32,
    display_name: SafeDisplayName,
    content: ImageContent,
    file_bytes: usize,
}

impl ImageAttachment {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    pub const fn media_type(&self) -> ImageMediaType {
        self.content.media_type
    }

    pub fn encoded(&self) -> &str {
        self.content.data.as_str()
    }

    pub fn content(&self) -> &ImageContent {
        &self.content
    }

    pub fn into_content(self) -> ImageContent {
        self.content
    }

    pub const fn file_bytes(&self) -> usize {
        self.file_bytes
    }
}

impl fmt::Debug for ImageAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageAttachment")
            .field("id", &self.id)
            .field("display_name", &self.display_name())
            .field("media_type", &self.media_type())
            .field("file_bytes", &self.file_bytes())
            .field("encoded_bytes", &self.encoded().len())
            .finish()
    }
}

#[derive(Clone)]
pub struct ImageAttachments {
    limits: ImageLoadLimits,
    routing: BinaryMediaInspectionPolicy,
    items: Vec<ImageAttachment>,
    file_bytes: usize,
    encoded_bytes: usize,
    /// Monotonic for the life of this collection, and deliberately *not* reset by
    /// [`Self::clear`] — exactly the rule [`crate::paste_input::PastedTexts`] follows, for exactly
    /// the reason. An id names a moment, so an `[Image #1]` anchor left over in a restored draft can
    /// never be answered by a later, unrelated screenshot that happened to reuse the number.
    next_id: u32,
}

impl ImageAttachments {
    pub fn new(limits: ImageLoadLimits) -> Self {
        Self::new_with_routing(limits, BinaryMediaInspectionPolicy::owner())
    }

    pub(crate) fn new_with_routing(
        limits: ImageLoadLimits,
        routing: BinaryMediaInspectionPolicy,
    ) -> Self {
        Self {
            limits,
            routing,
            items: Vec::new(),
            file_bytes: 0,
            encoded_bytes: 0,
            next_id: 0,
        }
    }

    pub fn as_slice(&self) -> &[ImageAttachment] {
        &self.items
    }

    pub fn get(&self, id: u32) -> Option<&ImageAttachment> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Put the images an anchored draft names first, in the order it names them, and leave every
    /// unanchored image behind them in the order the operator attached it.
    ///
    /// This is the whole substance of an anchor at submission time. The protocol's segment list is
    /// frozen at one text segment plus images, so position cannot be expressed by interleaving;
    /// it is expressed by making the image order agree with the anchor order, which is what lets a
    /// reader tie `[Image #2]` in the sentence to a specific picture beside it.
    pub fn order_by_anchors(&mut self, ids: &[u32]) {
        if ids.is_empty() {
            return;
        }
        let mut ordered = Vec::with_capacity(self.items.len());
        for id in ids {
            if let Some(index) = self.items.iter().position(|item| item.id == *id) {
                ordered.push(self.items.remove(index));
            }
        }
        ordered.append(&mut self.items);
        self.items = ordered;
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn attach_path(&mut self, path: &Path) -> Result<&ImageAttachment, ImageInputError> {
        let name = SafeDisplayName::from_path(path);
        if self.items.len() >= self.limits.max_attachments {
            return Err(ImageInputError::named(
                ImageInputErrorKind::TooManyAttachments,
                name,
            ));
        }
        let source_format = extension_format(path).ok_or_else(|| {
            ImageInputError::named(ImageInputErrorKind::UnsupportedExtension, name.clone())
        })?;
        let remaining = self
            .limits
            .max_total_file_bytes
            .saturating_sub(self.file_bytes);
        if remaining == 0 {
            return Err(ImageInputError::named(
                ImageInputErrorKind::AggregateTooLarge,
                name,
            ));
        }
        let read_limit = self.limits.max_file_bytes.min(remaining);
        let bytes = read_path_capped(path, read_limit)
            .map_err(|kind| ImageInputError::named(kind, name.clone()))?;
        if bytes.len() > read_limit {
            let kind = if remaining < self.limits.max_file_bytes {
                ImageInputErrorKind::AggregateTooLarge
            } else {
                ImageInputErrorKind::FileTooLarge
            };
            return Err(ImageInputError::named(kind, name));
        }
        match source_format {
            SourceFormat::Provider(expected) => self.admit_bytes(name, Some(expected), &bytes),
            SourceFormat::Heic => {
                let normalized = match heic::transcode_to_jpeg(&bytes) {
                    Ok(normalized) => normalized,
                    Err(
                        ImageInputErrorKind::InvalidImage | ImageInputErrorKind::TruncatedImage,
                    ) if sniff_image(&bytes).is_ok() => {
                        return Err(ImageInputError::named(
                            ImageInputErrorKind::ExtensionMismatch,
                            name,
                        ));
                    }
                    Err(kind) => return Err(ImageInputError::named(kind, name)),
                };
                if normalized.len() > self.limits.max_file_bytes {
                    return Err(ImageInputError::named(
                        ImageInputErrorKind::FileTooLarge,
                        name,
                    ));
                }
                if normalized.len()
                    > self
                        .limits
                        .max_total_file_bytes
                        .saturating_sub(self.file_bytes)
                {
                    return Err(ImageInputError::named(
                        ImageInputErrorKind::AggregateTooLarge,
                        name,
                    ));
                }
                self.admit_bytes(name, Some(ImageMediaType::Jpeg), &normalized)
            }
        }
    }

    /// Attach bytes already obtained from a bounded clipboard or terminal API.
    ///
    /// The label is display-only, sanitized, and never interpreted as a filesystem path.
    pub fn attach_bytes(
        &mut self,
        display_label: &str,
        bytes: &[u8],
    ) -> Result<&ImageAttachment, ImageInputError> {
        let name = SafeDisplayName::from_label(display_label);
        if self.items.len() >= self.limits.max_attachments {
            return Err(ImageInputError::named(
                ImageInputErrorKind::TooManyAttachments,
                name,
            ));
        }
        if bytes.len() > self.limits.max_file_bytes {
            return Err(ImageInputError::named(
                ImageInputErrorKind::FileTooLarge,
                name,
            ));
        }
        if bytes.len()
            > self
                .limits
                .max_total_file_bytes
                .saturating_sub(self.file_bytes)
        {
            return Err(ImageInputError::named(
                ImageInputErrorKind::AggregateTooLarge,
                name,
            ));
        }
        self.admit_bytes(name, None, bytes)
    }

    pub fn remove(&mut self, index: usize) -> Option<ImageAttachment> {
        if index >= self.items.len() {
            return None;
        }
        let item = self.items.remove(index);
        self.file_bytes = self.file_bytes.saturating_sub(item.file_bytes);
        self.encoded_bytes = self
            .encoded_bytes
            .saturating_sub(item.content.data.encoded_len());
        Some(item)
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.file_bytes = 0;
        self.encoded_bytes = 0;
    }

    /// Guarantee that no id this store mints from now on is `id` or below — the image half of
    /// [`crate::paste_input::PastedTexts::reserve_id`], for the same restored-draft reason.
    pub fn reserve_id(&mut self, id: u32) {
        self.next_id = self.next_id.max(id);
    }

    pub fn to_content_segments(&self, text: String) -> Result<ContentSegments, ImageInputError> {
        let mut segments = Vec::with_capacity(self.items.len() + 1);
        segments.push(ContentSegment::Text { text });
        segments.extend(self.items.iter().map(|item| ContentSegment::Image {
            image: item.content().clone(),
        }));
        ContentSegments::new(segments)
            .map_err(|_| ImageInputError::unnamed(ImageInputErrorKind::ProtocolRejected))
    }

    fn admit_bytes(
        &mut self,
        name: SafeDisplayName,
        expected: Option<ImageMediaType>,
        bytes: &[u8],
    ) -> Result<&ImageAttachment, ImageInputError> {
        let actual = self
            .routing
            .inspect_raw(bytes)
            .map_err(|kind| ImageInputError::named(kind, name.clone()))?;
        if expected.is_some_and(|expected| actual != expected) {
            return Err(ImageInputError::named(
                ImageInputErrorKind::ExtensionMismatch,
                name,
            ));
        }
        let encoded_len = canonical_base64_len(bytes.len()).ok_or_else(|| {
            ImageInputError::named(ImageInputErrorKind::EncodedPayloadTooLarge, name.clone())
        })?;
        let aggregate_encoded = self.encoded_bytes.checked_add(encoded_len).ok_or_else(|| {
            ImageInputError::named(ImageInputErrorKind::EncodedPayloadTooLarge, name.clone())
        })?;
        if encoded_len > self.limits.max_file_encoded_bytes
            || aggregate_encoded > self.limits.max_total_encoded_bytes
        {
            return Err(ImageInputError::named(
                ImageInputErrorKind::EncodedPayloadTooLarge,
                name,
            ));
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        debug_assert_eq!(encoded.len(), encoded_len);
        let content = ImageContent::new(actual, encoded).map_err(|_| {
            ImageInputError::named(ImageInputErrorKind::ProtocolRejected, name.clone())
        })?;
        self.file_bytes += bytes.len();
        self.encoded_bytes = aggregate_encoded;
        let id = self.next_id.wrapping_add(1);
        self.next_id = id;
        self.items.push(ImageAttachment {
            id,
            display_name: name,
            content,
            file_bytes: bytes.len(),
        });
        Ok(self.items.last().expect("an attachment was just appended"))
    }

    pub fn into_content_segments(self, text: String) -> Result<ContentSegments, ImageInputError> {
        let mut segments = Vec::with_capacity(self.items.len() + 1);
        segments.push(ContentSegment::Text { text });
        segments.extend(self.items.into_iter().map(|item| ContentSegment::Image {
            image: item.into_content(),
        }));
        ContentSegments::new(segments)
            .map_err(|_| ImageInputError::unnamed(ImageInputErrorKind::ProtocolRejected))
    }
}

impl Default for ImageAttachments {
    fn default() -> Self {
        Self::new(ImageLoadLimits::default())
    }
}

impl fmt::Debug for ImageAttachments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageAttachments")
            .field("limits", &self.limits)
            .field("routing", &self.routing)
            .field("items", &self.items)
            .field("file_bytes", &self.file_bytes)
            .field("encoded_bytes", &self.encoded_bytes)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedImagePath {
    path: PathBuf,
    display_name: SafeDisplayName,
}

impl ParsedImagePath {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }
}

impl fmt::Debug for ParsedImagePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedImagePath")
            .field("display_name", &self.display_name())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ImageMention {
    pub byte_range: Range<usize>,
    reference: ParsedImagePath,
}

impl ImageMention {
    pub fn reference(&self) -> &ParsedImagePath {
        &self.reference
    }
}

impl fmt::Debug for ImageMention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageMention")
            .field("byte_range", &self.byte_range)
            .field("display_name", &self.reference.display_name)
            .finish()
    }
}

fn canonical_base64_len(input_bytes: usize) -> Option<usize> {
    input_bytes.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

#[cfg(unix)]
fn open_regular_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure_regular_file(file.metadata()?.file_type().is_file())?;
    Ok(file)
}

#[cfg(windows)]
fn open_regular_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let lowercase = path.as_os_str().to_string_lossy().to_ascii_lowercase();
    if lowercase
        .as_bytes()
        .get(..2)
        .is_some_and(|prefix| prefix.iter().all(|byte| matches!(byte, b'\\' | b'/')))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows device and network paths are not local image files",
        ));
    }

    // This flag makes CreateFile open the final reparse point itself rather than its target. The
    // attribute check is then made against that same handle, closing the name-check/open race.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure_windows_regular_file(metadata.file_attributes(), metadata.file_type().is_file())?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file(path: &Path) -> io::Result<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(not_regular_file_error());
    }
    let file = OpenOptions::new().read(true).open(path)?;
    ensure_regular_file(file.metadata()?.file_type().is_file())?;
    Ok(file)
}

fn ensure_regular_file(is_file: bool) -> io::Result<()> {
    if !is_file {
        return Err(not_regular_file_error());
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn ensure_windows_regular_file(file_attributes: u32, is_file: bool) -> io::Result<()> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    ensure_regular_file(is_file && file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0)
}

fn not_regular_file_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "image input is not a regular file",
    )
}

fn read_capped(mut reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let ceiling = limit
        .checked_add(1)
        .expect("image limits are capped below usize::MAX");
    let mut bytes = Vec::with_capacity(ceiling.min(READ_CHUNK_BYTES));
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    while bytes.len() < ceiling {
        let remaining = ceiling - bytes.len();
        let read = reader.read(&mut chunk[..remaining.min(READ_CHUNK_BYTES)])?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

#[derive(Default)]
struct FileReadGate {
    occupied: Mutex<bool>,
    released: Condvar,
}

struct FileReadPermit {
    gate: Arc<FileReadGate>,
}

impl FileReadGate {
    fn acquire(self: &Arc<Self>, deadline: Instant) -> Option<FileReadPermit> {
        let mut occupied = self
            .occupied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *occupied {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, timed_out) = self
                .released
                .wait_timeout(occupied, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            occupied = next;
            if timed_out.timed_out() && *occupied {
                return None;
            }
        }
        *occupied = true;
        Some(FileReadPermit {
            gate: Arc::clone(self),
        })
    }
}

impl Drop for FileReadPermit {
    fn drop(&mut self) {
        let mut occupied = self
            .gate
            .occupied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *occupied = false;
        self.gate.released.notify_one();
    }
}

/// Read at most `limit + 1` bytes of a regular file, off the render thread, behind the
/// process-wide single-flight gate.
///
/// `pub(crate)` because the file-attachment chips (UX-6) need the same three properties this
/// composes — no symlink follow, no device open, a bounded read that stops one byte past the limit
/// so "too large" is observable without loading the file — and a second copy of it is a second
/// place for one of the three to go missing.
pub(crate) fn read_path_capped(path: &Path, limit: usize) -> Result<Vec<u8>, ImageInputErrorKind> {
    let path = path.to_path_buf();
    run_file_read_helper(Arc::clone(&FILE_READ_GATE), FILE_READ_TIMEOUT, move || {
        let file = open_regular_file(&path).map_err(|_| ImageInputErrorKind::OpenFailed)?;
        read_capped(file, limit).map_err(|_| ImageInputErrorKind::ReadFailed)
    })
}

/// Run one potentially blocking path open/read behind the process-wide single-flight gate.
///
/// A timeout detaches the worker because a blocked filesystem syscall cannot be cancelled
/// portably. The permit lives in that worker, so subsequent calls cannot create an unbounded pile
/// of equally stuck threads; they wait only until their own deadline and receive a fixed error.
fn run_file_read_helper(
    gate: Arc<FileReadGate>,
    timeout: Duration,
    job: impl FnOnce() -> Result<Vec<u8>, ImageInputErrorKind> + Send + 'static,
) -> Result<Vec<u8>, ImageInputErrorKind> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let permit = gate
        .acquire(deadline)
        .ok_or(ImageInputErrorKind::ReaderBusy)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("core-image-read".into())
        .spawn(move || {
            let _permit = permit;
            let _ = sender.send(job());
        })
        .map_err(|_| ImageInputErrorKind::ReadFailed)?;
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => ImageInputErrorKind::ReadTimedOut,
            mpsc::RecvTimeoutError::Disconnected => ImageInputErrorKind::ReadFailed,
        })?
}

#[cfg(test)]
mod tests {
    use super::{
        FileReadGate, ImageInputErrorKind, ensure_windows_regular_file, read_capped,
        run_file_read_helper,
    };
    use std::cell::Cell;
    use std::io::{self, Read};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct CountingReader {
        bytes: Vec<u8>,
        cursor: usize,
        consumed: Rc<Cell<usize>>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.bytes.len() - self.cursor);
            buffer[..count].copy_from_slice(&self.bytes[self.cursor..self.cursor + count]);
            self.cursor += count;
            self.consumed.set(self.cursor);
            Ok(count)
        }
    }

    #[test]
    fn capped_reader_never_requests_or_retains_more_than_limit_plus_one() {
        let consumed = Rc::new(Cell::new(0));
        let reader = CountingReader {
            bytes: vec![7; 1_000],
            cursor: 0,
            consumed: Rc::clone(&consumed),
        };
        let loaded = read_capped(reader, 31).unwrap();
        assert_eq!(loaded.len(), 32);
        assert_eq!(consumed.get(), 32);
    }

    #[test]
    fn windows_opened_handle_filter_rejects_every_reparse_point() {
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

        assert!(ensure_windows_regular_file(FILE_ATTRIBUTE_NORMAL, true).is_ok());
        assert!(
            ensure_windows_regular_file(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_REPARSE_POINT, true)
                .is_err()
        );
        assert!(ensure_windows_regular_file(FILE_ATTRIBUTE_DIRECTORY, false).is_err());
    }

    #[test]
    fn timed_out_file_helper_holds_its_only_slot_until_the_worker_exits() {
        let gate = Arc::new(FileReadGate::default());
        let (release, wait_for_release) = std::sync::mpsc::channel();
        assert_eq!(
            run_file_read_helper(Arc::clone(&gate), Duration::ZERO, move || {
                wait_for_release.recv().expect("test releases worker");
                Ok(vec![1])
            }),
            Err(ImageInputErrorKind::ReadTimedOut)
        );

        let second_job_ran = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&second_job_ran);
        assert_eq!(
            run_file_read_helper(Arc::clone(&gate), Duration::ZERO, move || {
                observed.store(true, Ordering::Relaxed);
                Ok(vec![2])
            }),
            Err(ImageInputErrorKind::ReaderBusy)
        );
        assert!(!second_job_ran.load(Ordering::Relaxed));

        release.send(()).expect("release detached worker");
        assert_eq!(
            run_file_read_helper(gate, Duration::from_secs(1), || Ok(vec![3])),
            Ok(vec![3])
        );
    }
}
