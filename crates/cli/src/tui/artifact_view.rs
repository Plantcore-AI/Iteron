//! One presentation owner for an entire served object. Native reads retain their finite worker
//! slot after modal cancellation; scope changes discard the result rather than rebinding its bytes.
use super::{App, block, ui_safe_text};
use crate::app_server::AppServerClient;
use base64::Engine as _;
use crossterm::event::KeyCode;
use iteron_protocol::client_artifact::{
    CLIENT_ARTIFACT_VERSION, ClientArtifactCommandV1, ClientArtifactDescriptorV1,
    MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES,
};
use iteron_protocol::{RunId, SessionId};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use serde::Deserialize as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, oneshot};
const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARTIFACT_DESCRIPTORS: usize = 512;
const TEXT_PAGE_BYTES: usize = 8 * 1024;
const MAX_IMAGE_PIXELS: u64 = 8 * 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 8192;
const MAX_DECODE_BYTES: usize = 32 * 1024 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(5);

pub(super) struct Transfer {
    thread: SessionId,
    descriptor: ClientArtifactDescriptorV1,
    bytes: Vec<u8>,
    finished: bool,
}
impl Transfer {
    pub(super) fn select(
        thread: SessionId,
        prefix: &str,
        listing: &Value,
    ) -> Result<Self, &'static str> {
        if !(8..=64).contains(&prefix.len())
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("artifact prefix must contain 8–64 lowercase hexadecimal characters");
        }
        if listing["type"] != "artifacts_v1"
            || listing["contract_version"] != CLIENT_ARTIFACT_VERSION
        {
            return Err("artifact listing unavailable");
        }
        let entries = listing["artifacts"]
            .as_array()
            .filter(|entries| entries.len() <= MAX_ARTIFACT_DESCRIPTORS)
            .ok_or("artifact listing exceeds its bound")?;
        let mut matches = entries.iter().filter(|entry| {
            entry["artifact_id"]
                .as_str()
                .is_some_and(|id| id.starts_with(prefix))
        });
        let entry = matches
            .next()
            .ok_or("artifact prefix does not match a published object")?;
        if matches.next().is_some() {
            return Err("artifact prefix is ambiguous");
        }
        let descriptor = bounded_descriptor(entry)?;
        ClientArtifactCommandV1::Read {
            thread_id: thread.clone(),
            artifact_id: descriptor.artifact_id.clone(),
            offset: 0,
            max_bytes: 1,
        }
        .validate()?;
        if descriptor.bytes > MAX_ARTIFACT_BYTES as u64
            || descriptor.source_event_seq == 0
            || descriptor.schema.len() > 256
            || descriptor.mime_type.len() > 128
            || descriptor
                .schema
                .chars()
                .chain(descriptor.mime_type.chars())
                .any(char::is_control)
        {
            return Err("artifact descriptor exceeds its bound");
        }
        Ok(Self {
            thread,
            descriptor,
            bytes: Vec::new(),
            finished: false,
        })
    }
    pub(super) fn command(&self) -> ClientArtifactCommandV1 {
        ClientArtifactCommandV1::Read {
            thread_id: self.thread.clone(),
            artifact_id: self.descriptor.artifact_id.clone(),
            offset: self.bytes.len() as u64,
            max_bytes: MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES as u32,
        }
    }
    pub(super) fn accept(&mut self, reply: &Value) -> Result<bool, &'static str> {
        if self.finished {
            return Err("artifact transfer is already complete");
        }
        if reply["type"] != "artifact_chunk_v1"
            || reply["contract_version"] != CLIENT_ARTIFACT_VERSION
        {
            return Err("artifact chunk unavailable");
        }
        let actual = bounded_descriptor(&reply["artifact"])?;
        if actual != self.descriptor || reply["offset"].as_u64() != Some(self.bytes.len() as u64) {
            return Err("artifact identity or byte offset changed");
        }
        let encoded = reply["content_base64"]
            .as_str()
            .filter(|value| value.len() <= MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES.div_ceil(3) * 4)
            .ok_or("artifact chunk exceeds its bound")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "artifact chunk encoding invalid")?;
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or("artifact byte count overflow")?;
        if bytes.len() > MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES
            || end > self.descriptor.bytes as usize
            || reply["next_offset"].as_u64() != Some(end as u64)
            || reply["eof"].as_bool() != Some(end == self.descriptor.bytes as usize)
            || (bytes.is_empty() && end != self.descriptor.bytes as usize)
        {
            return Err("artifact chunk progress or completion invalid");
        }
        self.bytes.extend_from_slice(&bytes);
        if end == self.descriptor.bytes as usize {
            if hex::encode(Sha256::digest(&self.bytes)) != self.descriptor.artifact_id {
                return Err("artifact content hash does not match the served descriptor");
            }
            self.finished = true;
        }
        Ok(self.finished)
    }
    fn into_content(self) -> Result<Content, &'static str> {
        if !self.finished {
            return Err("artifact transfer is incomplete");
        }
        let display = if self.descriptor.mime_type == "image/png" {
            Display::Png(decode_png(&self.bytes)?)
        } else if self.descriptor.mime_type.starts_with("text/")
            || self.descriptor.mime_type == "application/json"
        {
            Display::Text(String::from_utf8(self.bytes).map_err(|_| "served text is not UTF-8")?)
        } else {
            return Err(
                "this binary type has no terminal viewer; full bytes remain available through the artifact read port",
            );
        };
        Ok(Content {
            descriptor: self.descriptor,
            display,
        })
    }
}
fn bounded_descriptor(value: &Value) -> Result<ClientArtifactDescriptorV1, &'static str> {
    let object = value
        .as_object()
        .filter(|object| object.len() == 7)
        .ok_or("artifact descriptor shape invalid")?;
    for (key, bound) in [
        ("artifact_id", 64),
        ("schema", 256),
        ("mime_type", 128),
        ("required_capability", 32),
    ] {
        if !object
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|text| text.len() <= bound && !text.chars().any(char::is_control))
        {
            return Err("artifact descriptor string exceeds its bound");
        }
    }
    if !object
        .get("bytes")
        .and_then(Value::as_u64)
        .is_some_and(|bytes| bytes <= MAX_ARTIFACT_BYTES as u64)
        || object
            .get("source_event_seq")
            .and_then(Value::as_u64)
            .is_none_or(|seq| seq == 0)
        || object.get("complete").and_then(Value::as_bool).is_none()
    {
        return Err("artifact descriptor scalar invalid");
    }
    ClientArtifactDescriptorV1::deserialize(value).map_err(|_| "artifact descriptor invalid")
}
struct Bitmap {
    width: u32,
    height: u32,
    color: png::ColorType,
    pixels: Vec<u8>,
}
fn decode_png(bytes: &[u8]) -> Result<Bitmap, &'static str> {
    let mut decoder = png::Decoder::new_with_limits(
        BufReader::new(Cursor::new(bytes)),
        png::Limits {
            bytes: MAX_DECODE_BYTES,
        },
    );
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|_| "PNG metadata unavailable")?;
    let info = reader.info();
    if info.width == 0
        || info.height == 0
        || info.width > MAX_IMAGE_DIMENSION
        || info.height > MAX_IMAGE_DIMENSION
        || u64::from(info.width) * u64::from(info.height) > MAX_IMAGE_PIXELS
        || info.animation_control.is_some()
    {
        return Err("PNG exceeds the bounded still-image view");
    }
    let capacity = reader
        .output_buffer_size()
        .filter(|bytes| *bytes <= MAX_DECODE_BYTES)
        .ok_or("PNG decode exceeds its byte bound")?;
    let mut pixels = vec![0; capacity];
    let output = reader
        .next_frame(&mut pixels)
        .map_err(|_| "PNG pixels unavailable")?;
    reader.finish().map_err(|_| "PNG stream is incomplete")?;
    if output.bit_depth != png::BitDepth::Eight || output.color_type == png::ColorType::Indexed {
        return Err("PNG pixel format unavailable");
    }
    pixels.truncate(output.buffer_size());
    Ok(Bitmap {
        width: output.width,
        height: output.height,
        color: output.color_type,
        pixels,
    })
}
impl Bitmap {
    fn rgb(&self, x: u32, y: u32) -> Color {
        let channels = match self.color {
            png::ColorType::Rgb => 3,
            png::ColorType::Rgba => 4,
            png::ColorType::Grayscale => 1,
            png::ColorType::GrayscaleAlpha => 2,
            png::ColorType::Indexed => unreachable!("decode rejects indexed output"),
        };
        let i = (y as usize * self.width as usize + x as usize) * channels;
        let (r, g, b, a) = match self.color {
            png::ColorType::Rgb => (self.pixels[i], self.pixels[i + 1], self.pixels[i + 2], 255),
            png::ColorType::Rgba => (
                self.pixels[i],
                self.pixels[i + 1],
                self.pixels[i + 2],
                self.pixels[i + 3],
            ),
            png::ColorType::Grayscale => (self.pixels[i], self.pixels[i], self.pixels[i], 255),
            png::ColorType::GrayscaleAlpha => (
                self.pixels[i],
                self.pixels[i],
                self.pixels[i],
                self.pixels[i + 1],
            ),
            png::ColorType::Indexed => unreachable!("decode rejects indexed output"),
        };
        let blend = |c: u8| ((u16::from(c) * u16::from(a) + 32 * (255 - u16::from(a))) / 255) as u8;
        Color::Rgb(blend(r), blend(g), blend(b))
    }
}
enum Display {
    Text(String),
    Png(Bitmap),
}
struct Content {
    descriptor: ClientArtifactDescriptorV1,
    display: Display,
}
struct Pending {
    generation: u64,
    run: RunId,
    receive: oneshot::Receiver<Result<Content, &'static str>>,
}
#[derive(Default)]
pub(super) struct Viewer {
    open: bool,
    generation: u64,
    content: Option<Content>,
    notice: Option<&'static str>,
    pending: Option<Pending>,
    capacity: Option<Arc<Semaphore>>,
    page: usize,
    scroll: u16,
}
impl Viewer {
    pub(super) fn is_open(&self) -> bool {
        self.open
    }
    pub(super) fn close(&mut self) {
        self.open = false;
        self.content = None;
        self.notice = None;
        self.generation = self.generation.wrapping_add(1);
    }
    pub(super) fn open_local(
        &mut self,
        client: AppServerClient,
        thread: SessionId,
        run: RunId,
        prefix: String,
    ) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("an artifact read is still completing");
        }
        let capacity = self
            .capacity
            .get_or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone();
        let permit = capacity
            .try_acquire_owned()
            .map_err(|_| "artifact reader busy")?;
        self.close();
        self.open = true;
        self.page = 0;
        self.scroll = 0;
        let generation = self.generation;
        let (send, receive) = oneshot::channel();
        let observed_run = run.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = (|| {
                let deadline = Instant::now() + READ_DEADLINE;
                let current = || {
                    client
                        .thread_snapshot_v1()
                        .is_some_and(|scope| scope.thread_id == thread && scope.run_id == run)
                };
                if !current() {
                    return Err("artifact scope changed");
                }
                let listing = client.artifacts_v1(ClientArtifactCommandV1::List {
                    thread_id: thread.clone(),
                });
                let mut transfer = Transfer::select(thread.clone(), prefix.as_str(), &listing)?;
                for _ in 0..MAX_ARTIFACT_BYTES
                    .div_ceil(MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES)
                    .max(1)
                {
                    if Instant::now() >= deadline || !current() {
                        return Err("artifact observation deadline or scope changed");
                    }
                    let reply = client.artifacts_v1(transfer.command());
                    if !current() {
                        return Err("artifact scope changed");
                    }
                    if transfer.accept(&reply)? {
                        return transfer.into_content();
                    }
                }
                Err("artifact transfer did not complete within its chunk bound")
            })();
            let _ = send.send(result);
        });
        self.pending = Some(Pending {
            generation,
            run: observed_run,
            receive,
        });
        Ok(())
    }
    pub(super) fn poll(&mut self, run: &RunId) -> bool {
        let Some(pending) = self.pending.as_mut() else {
            return false;
        };
        let result = match pending.receive.try_recv() {
            Ok(result) => result,
            Err(oneshot::error::TryRecvError::Empty) => return false,
            Err(_) => Err("artifact worker unavailable"),
        };
        let pending = self.pending.take().expect("checked above");
        if !self.open || pending.generation != self.generation {
            return false;
        }
        if pending.run != *run {
            self.close();
            return true;
        }
        match result {
            Ok(content) => self.content = Some(content),
            Err(reason) => self.notice = Some(reason),
        };
        true
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    pub(super) fn unavailable(&mut self, reason: &'static str) {
        self.content = None;
        self.notice = Some(reason);
    }
    pub(super) fn begin_remote(&mut self) {
        self.close();
        self.open = true;
        self.page = 0;
        self.scroll = 0;
    }
    pub(super) fn finish_remote(
        &mut self,
        transfer: Transfer,
        run: RunId,
    ) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("artifact decoder is still completing");
        }
        let capacity = self
            .capacity
            .get_or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone();
        let permit = capacity
            .try_acquire_owned()
            .map_err(|_| "artifact decoder busy")?;
        let generation = self.generation;
        let (send, receive) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _ = send.send(transfer.into_content());
        });
        self.pending = Some(Pending {
            generation,
            run,
            receive,
        });
        Ok(())
    }
    pub(super) fn key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc | KeyCode::Char('q') => self.close(),
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Down => {
                self.scroll = self.scroll.saturating_add(1).min(TEXT_PAGE_BYTES as u16)
            }
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(10).min(TEXT_PAGE_BYTES as u16)
            }
            KeyCode::Left | KeyCode::Char('[') => {
                if let Some(Content {
                    display: Display::Text(text),
                    ..
                }) = &self.content
                {
                    self.page = previous_page(text, self.page);
                    self.scroll = 0;
                }
            }
            KeyCode::Right | KeyCode::Char(']') => {
                if let Some(Content {
                    display: Display::Text(text),
                    ..
                }) = &self.content
                {
                    self.page = page_end(text, self.page);
                    self.scroll = 0;
                }
            }
            _ => {}
        }
    }
}
fn page_end(text: &str, start: usize) -> usize {
    let mut end = start.saturating_add(TEXT_PAGE_BYTES).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}
fn previous_page(text: &str, end: usize) -> usize {
    let mut start = end.saturating_sub(TEXT_PAGE_BYTES);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    start
}
pub(super) fn render(frame: &mut Frame, viewer: &Viewer) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let title = viewer
        .content
        .as_ref()
        .map(|content| {
            format!(
                "artifact {} · {} bytes · {}",
                &content.descriptor.artifact_id[..12],
                content.descriptor.bytes,
                if content.descriptor.complete {
                    "complete served object"
                } else {
                    "source truncated by host"
                }
            )
        })
        .unwrap_or_else(|| "artifact · loading…".into());
    let border = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_bottom("↑↓ scroll · [ ] byte pages · Esc close");
    let body = border.inner(area);
    frame.render_widget(border, area);
    if body.width == 0 || body.height == 0 {
        return;
    }
    if let Some(reason) = viewer.notice {
        frame.render_widget(Paragraph::new(reason), body);
        return;
    }
    let Some(content) = &viewer.content else {
        return;
    };
    match &content.display {
        Display::Text(text) => {
            let end = page_end(text, viewer.page);
            let header = format!(
                "bytes {}..{} / {} · SHA-256 verified\n",
                viewer.page,
                end,
                text.len()
            );
            let visible = ui_safe_text(&text[viewer.page..end]);
            frame.render_widget(
                Paragraph::new(header + &visible)
                    .wrap(Wrap { trim: false })
                    .scroll((viewer.scroll, 0)),
                body,
            );
        }
        Display::Png(image) => {
            let width = u32::from(body.width).min(image.width);
            let pixels = u32::from(body.height.saturating_sub(1)) * 2;
            let height = (u64::from(image.height) * u64::from(width) / u64::from(image.width))
                .max(1)
                .min(u64::from(pixels)) as u32;
            let width = (u64::from(image.width) * u64::from(height) / u64::from(image.height))
                .max(1)
                .min(u64::from(width)) as u32;
            frame.render_widget(
                Paragraph::new(format!(
                    "PNG {}×{} · scaled pixel view · SHA-256 verified",
                    image.width, image.height
                )),
                Rect { height: 1, ..body },
            );
            if height == 0 {
                return;
            }
            for row in 0..height.div_ceil(2) {
                let mut spans = Vec::with_capacity(width as usize);
                for column in 0..width {
                    let x = column * image.width / width;
                    let y = (row * 2).min(height - 1) * image.height / height;
                    let below = (row * 2 + 1).min(height - 1) * image.height / height;
                    spans.push(Span::styled(
                        "▀",
                        Style::default().fg(image.rgb(x, y)).bg(image.rgb(x, below)),
                    ));
                }
                frame.render_widget(
                    Paragraph::new(Line::from(spans)),
                    Rect {
                        x: body.x,
                        y: body.y.saturating_add(1 + row as u16),
                        width: width as u16,
                        height: 1,
                    },
                );
            }
        }
    }
}
pub(super) fn note_open_result(app: &mut App, result: Result<(), &'static str>) {
    if let Err(reason) = result {
        app.note(block::NoticeLevel::Warn, reason);
    }
}
#[cfg(test)]
mod tests;
