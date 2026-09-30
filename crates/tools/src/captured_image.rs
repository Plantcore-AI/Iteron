//! Bounded native raster data, separate from text scrubbing and all effect/admission authority.
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct CapturedToolImage {
    bytes: Arc<[u8]>,
    sha256: String,
    width: u32,
    height: u32,
    observation: Option<CapturedImageObservation>,
}
/// Data provenance only. This value is not effect, admission or secret-redaction authority.
#[derive(Clone)]
pub struct CapturedImageObservation {
    source_url: String,
    observed_unix_ms: u64,
}
impl std::fmt::Debug for CapturedImageObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedImageObservation")
            .field("source_url_bytes", &self.source_url.len())
            .field("observed_unix_ms", &self.observed_unix_ms)
            .finish_non_exhaustive()
    }
}
impl CapturedImageObservation {
    pub fn source_url(&self) -> &str {
        &self.source_url
    }
    pub fn observed_unix_ms(&self) -> u64 {
        self.observed_unix_ms
    }
    pub fn execution_scope(&self) -> &'static str {
        "isolated_browser_viewport"
    }
    pub fn evidence_source(&self) -> &'static str {
        "actual_w3c_screenshot_reply"
    }
}
impl std::fmt::Debug for CapturedToolImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedToolImage")
            .field("bytes", &self.bytes.len())
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}
impl CapturedToolImage {
    /// PNG wire header bounds only, not a claim that untrusted pixels or ancillary chunks are safe.
    pub fn png(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() < 33
            || bytes.len() > 8 * 1024 * 1024
            || !bytes.starts_with(b"\x89PNG\r\n\x1a\n")
            || bytes[8..12] != 13u32.to_be_bytes()
            || &bytes[12..16] != b"IHDR"
        {
            return Err("captured_png_header_invalid");
        }
        let width = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| "captured_png_header_invalid")?,
        );
        let height = u32::from_be_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| "captured_png_header_invalid")?,
        );
        if width == 0
            || height == 0
            || width > 4096
            || height > 4096
            || u64::from(width) * u64::from(height) > 16 * 1024 * 1024
        {
            return Err("captured_png_dimensions_exceed_bound");
        }
        Ok(Self {
            sha256: hex_digest(&bytes),
            bytes: bytes.into(),
            width,
            height,
            observation: None,
        })
    }
    pub fn with_browser_observation(
        mut self,
        source_url: String,
        observed_unix_ms: u64,
    ) -> Result<Self, &'static str> {
        if source_url.len() > 2048
            || source_url.chars().any(char::is_control)
            || observed_unix_ms == 0
        {
            return Err("captured_image_source_bounds");
        }
        let url = url::Url::parse(&source_url).map_err(|_| "captured_image_source_invalid")?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
        {
            return Err("captured_image_source_invalid");
        }
        self.observation = Some(CapturedImageObservation {
            source_url,
            observed_unix_ms,
        });
        Ok(self)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn media_type(&self) -> &'static str {
        "image/png"
    }
    pub fn observation(&self) -> Option<&CapturedImageObservation> {
        self.observation.as_ref()
    }
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
