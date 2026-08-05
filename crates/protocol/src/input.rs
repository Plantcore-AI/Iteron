//! Neutral, provider-independent content carried by a multimodal user submission.
//!
//! This module owns only the SQ representation and its bounds. It deliberately does not inspect
//! image bytes or shape provider-specific content blocks: frontends authenticate the file type
//! before encoding, and provider adapters decide whether and how to consume an admitted segment.

use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::fmt;

pub use crate::{
    ContentSegment, ContentSegments, FileContent, ImageBase64, ImageContent, ImageMediaType,
};

/// Maximum number of segments in one multimodal submission: one text prompt and up to eight
/// images.
pub const MAX_INPUT_SEGMENTS: usize = 9;
/// Maximum number of image attachments in one multimodal submission.
pub const MAX_INPUT_IMAGES: usize = 8;
/// Maximum encoded bytes in one image's canonical RFC 4648 base64 payload.
pub const MAX_IMAGE_BASE64_BYTES: usize = 8 * 1024 * 1024;
/// Maximum encoded image bytes across one submission.
pub const MAX_TOTAL_IMAGE_BASE64_BYTES: usize = 32 * 1024 * 1024;
/// Maximum number of file attachments in one `Op::UserInputV3` submission.
pub const MAX_INPUT_FILES: usize = 8;
/// Maximum UTF-8 bytes in one attached file's text.
pub const MAX_FILE_TEXT_BYTES: usize = 256 * 1024;
/// Maximum attached-file text across one submission.
pub const MAX_TOTAL_FILE_TEXT_BYTES: usize = 512 * 1024;
/// Maximum bytes in one attachment's workspace-relative path.
pub const MAX_FILE_PATH_BYTES: usize = 1024;
/// Bytes charged per attachment for the delimiters a frontend wraps it in before the model reads
/// it.
///
/// The bound exists so that "the files fit" is decided here, once, against
/// [`crate::task::MAX_TASK_TEXT_BYTES`] — rather than by whichever renderer happens to run, which
/// is how a bound becomes a truncation.
pub const FILE_ATTACHMENT_FRAMING_BYTES: usize = 128;

impl ImageMediaType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }
}

impl ImageBase64 {
    pub fn new(encoded: impl Into<String>) -> Result<Self, &'static str> {
        let encoded = encoded.into();
        validate_base64(&encoded)?;
        Ok(Self(encoded))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn encoded_len(&self) -> usize {
        self.0.len()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        validate_base64(&self.0)
    }
}

impl fmt::Debug for ImageBase64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImageBase64(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ImageBase64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::new(encoded).map_err(D::Error::custom)
    }
}

impl ImageContent {
    pub fn new(media_type: ImageMediaType, data: impl Into<String>) -> Result<Self, &'static str> {
        Ok(Self {
            media_type,
            data: ImageBase64::new(data)?,
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.data.validate()
    }
}

impl FileContent {
    pub fn new(path: impl Into<String>, text: impl Into<String>) -> Result<Self, &'static str> {
        let content = Self {
            path: path.into(),
            text: text.into(),
        };
        content.validate()?;
        Ok(content)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        validate_file_path(&self.path)?;
        validate_file_text(&self.text)
    }
}

impl fmt::Debug for FileContent {
    /// Content-free in the payload, exact in the identity. File bytes are operator data and must
    /// not leak through a log line; the path is already proven free of control characters by
    /// [`validate_file_path`], so it is safe to print and is the only useful thing here.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileContent")
            .field("path", &self.path)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}

/// Refuse anything that is not a plain workspace-relative path.
///
/// This is a *shape* check on a value that already crossed a frontend's containment gate; it is
/// not itself the containment gate. It exists so a path that reached the queue by another route
/// still cannot name an absolute location or climb out of a workspace, and so the string is safe
/// for a terminal to print.
fn validate_file_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("attached file path must not be empty");
    }
    if path.len() > MAX_FILE_PATH_BYTES {
        return Err("attached file path exceeds its declared bound");
    }
    if path.chars().any(unsafe_path_character) {
        return Err("attached file path contains a control or bidi-format character");
    }
    if path.contains('\\') {
        // Both a separator this contract does not speak and, on Windows, a UNC/device prefix.
        return Err("attached file path must use forward slashes");
    }
    if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') {
        return Err("attached file path must be workspace-relative");
    }
    if path
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err("attached file path must not contain an empty, `.`, or `..` component");
    }
    Ok(())
}

fn validate_file_text(text: &str) -> Result<(), &'static str> {
    if text.len() > MAX_FILE_TEXT_BYTES {
        return Err("attached file text exceeds its declared bound");
    }
    if text.contains('\0') {
        return Err("attached file is not text");
    }
    Ok(())
}

/// Control and bidi/zero-width format characters, which corrupt a terminal's column math and can
/// make a path render as something other than what it names.
fn unsafe_path_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// The admission check for an [`crate::Op::UserInputV3`] payload.
///
/// Every failure is a refusal. Nothing here shortens a value to make it fit: a submission that
/// does not fit is not a smaller submission, it is a different one, and only the operator gets to
/// decide which files to drop.
pub fn validate_file_submission(
    text: &str,
    images: &[ImageContent],
    files: &[FileContent],
) -> Result<(), &'static str> {
    if text.len() > crate::task::MAX_TASK_TEXT_BYTES {
        return Err("task text exceeds its declared bound");
    }
    if images.len() > MAX_INPUT_IMAGES {
        return Err("too many input images");
    }
    let mut image_base64_bytes = 0usize;
    for image in images {
        image.validate()?;
        image_base64_bytes = image_base64_bytes
            .checked_add(image.data.encoded_len())
            .ok_or("image base64 byte count overflowed")?;
    }
    if image_base64_bytes > MAX_TOTAL_IMAGE_BASE64_BYTES {
        return Err("input image payloads exceed their aggregate bound");
    }

    if files.is_empty() {
        return Err("a file submission must carry at least one file");
    }
    if files.len() > MAX_INPUT_FILES {
        return Err("too many input files");
    }
    let mut file_text_bytes = 0usize;
    // What the model will actually be handed: the prompt plus every file inside its framing.
    let mut carried_bytes = text.len();
    for (index, file) in files.iter().enumerate() {
        file.validate()?;
        if files[..index]
            .iter()
            .any(|earlier| earlier.path == file.path)
        {
            return Err("input files repeat a path");
        }
        file_text_bytes = file_text_bytes
            .checked_add(file.text.len())
            .ok_or("attached file byte count overflowed")?;
        carried_bytes = carried_bytes
            .checked_add(file.text.len())
            .and_then(|bytes| bytes.checked_add(file.path.len()))
            .and_then(|bytes| bytes.checked_add(FILE_ATTACHMENT_FRAMING_BYTES))
            .ok_or("attached file byte count overflowed")?;
    }
    if file_text_bytes > MAX_TOTAL_FILE_TEXT_BYTES {
        return Err("attached file text exceeds its aggregate bound");
    }
    if carried_bytes > crate::task::MAX_TASK_TEXT_BYTES {
        return Err("prompt plus attached files exceed the task text bound");
    }
    Ok(())
}

impl ContentSegments {
    pub fn new(segments: Vec<ContentSegment>) -> Result<Self, &'static str> {
        let content = Self(segments);
        content.validate()?;
        Ok(content)
    }

    pub fn as_slice(&self) -> &[ContentSegment] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<ContentSegment> {
        self.0
    }

    pub fn text(&self) -> &str {
        self.0
            .iter()
            .find_map(|segment| match segment {
                ContentSegment::Text { text } => Some(text.as_str()),
                ContentSegment::Image { .. } | ContentSegment::Unknown => None,
            })
            .expect("ContentSegments construction proves exactly one text segment")
    }

    pub fn images(&self) -> impl Iterator<Item = &ImageContent> {
        self.0.iter().filter_map(|segment| match segment {
            ContentSegment::Image { image } => Some(image),
            ContentSegment::Text { .. } | ContentSegment::Unknown => None,
        })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.0.len() > MAX_INPUT_SEGMENTS {
            return Err("too many input content segments");
        }

        let mut text_count = 0usize;
        let mut text_bytes = 0usize;
        let mut image_count = 0usize;
        let mut image_base64_bytes = 0usize;
        for segment in &self.0 {
            match segment {
                ContentSegment::Text { text } => {
                    text_count += 1;
                    text_bytes = text_bytes
                        .checked_add(text.len())
                        .ok_or("input text byte count overflowed")?;
                }
                ContentSegment::Image { image } => {
                    image.validate()?;
                    image_count += 1;
                    image_base64_bytes = image_base64_bytes
                        .checked_add(image.data.encoded_len())
                        .ok_or("image base64 byte count overflowed")?;
                }
                ContentSegment::Unknown => return Err("unrecognised input content segment"),
            }
        }

        if text_count != 1 {
            return Err("multimodal input must contain exactly one text segment");
        }
        if text_bytes > crate::task::MAX_TASK_TEXT_BYTES {
            return Err("task text exceeds its declared bound");
        }
        if image_count == 0 {
            return Err("multimodal input must contain at least one image segment");
        }
        if image_count > MAX_INPUT_IMAGES {
            return Err("too many input images");
        }
        if image_base64_bytes > MAX_TOTAL_IMAGE_BASE64_BYTES {
            return Err("input image payloads exceed their aggregate bound");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ContentSegments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let segments = Vec::<ContentSegment>::deserialize(deserializer)?;
        Self::new(segments).map_err(D::Error::custom)
    }
}

fn validate_base64(encoded: &str) -> Result<(), &'static str> {
    if encoded.is_empty() {
        return Err("image base64 payload must not be empty");
    }
    if encoded.len() > MAX_IMAGE_BASE64_BYTES {
        return Err("image base64 payload exceeds its declared bound");
    }
    if !encoded.len().is_multiple_of(4) {
        return Err("image base64 payload must use padded RFC 4648 encoding");
    }

    let bytes = encoded.as_bytes();
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return Err("image base64 payload has invalid padding");
    }
    let body_len = bytes.len() - padding;
    if !bytes[..body_len]
        .iter()
        .all(|byte| base64_value(*byte).is_some())
    {
        return Err("image base64 payload contains a non-alphabet byte");
    }
    if bytes[body_len..].iter().any(|byte| *byte != b'=') {
        return Err("image base64 payload has invalid padding");
    }

    match padding {
        0 => {}
        1 => {
            let Some(last) = base64_value(bytes[bytes.len() - 2]) else {
                return Err("image base64 payload has invalid padding");
            };
            if last & 0b11 != 0 {
                return Err("image base64 payload is not canonical");
            }
        }
        2 => {
            let Some(last) = base64_value(bytes[bytes.len() - 3]) else {
                return Err("image base64 payload has invalid padding");
            };
            if last & 0b1111 != 0 {
                return Err("image base64 payload is not canonical");
            }
        }
        _ => return Err("image base64 payload has invalid padding"),
    }
    Ok(())
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContentSegment, ContentSegments, FILE_ATTACHMENT_FRAMING_BYTES, FileContent, ImageBase64,
        ImageContent, ImageMediaType, MAX_FILE_PATH_BYTES, MAX_FILE_TEXT_BYTES,
        MAX_IMAGE_BASE64_BYTES, MAX_INPUT_FILES, MAX_INPUT_IMAGES, MAX_INPUT_SEGMENTS,
        MAX_TOTAL_FILE_TEXT_BYTES, MAX_TOTAL_IMAGE_BASE64_BYTES, validate_file_submission,
    };

    fn image() -> ImageContent {
        ImageContent::new(ImageMediaType::Png, "iVBORw0KGgo=").expect("canonical PNG signature")
    }

    fn content() -> ContentSegments {
        ContentSegments::new(vec![
            ContentSegment::Text {
                text: "describe this image".into(),
            },
            ContentSegment::Image { image: image() },
        ])
        .expect("valid text plus image")
    }

    #[test]
    fn multimodal_segments_have_one_canonical_neutral_wire_shape() {
        let encoded = serde_json::to_value(content()).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!([
                {"type": "text", "text": "describe this image"},
                {
                    "type": "image",
                    "image": {
                        "media_type": "image/png",
                        "data": "iVBORw0KGgo="
                    }
                }
            ])
        );
        assert_eq!(
            serde_json::from_value::<ContentSegments>(encoded).unwrap(),
            content()
        );
        assert_eq!(content().text(), "describe this image");
        assert_eq!(content().images().count(), 1);
    }

    #[test]
    fn base64_is_bounded_canonical_and_content_free_in_debug() {
        for invalid in [
            "", "A", "AAA", "AAAA=", "AA=A", "A===", "AA A", "AA_A", "AB==", "AAB=",
        ] {
            assert!(
                ImageBase64::new(invalid).is_err(),
                "{invalid:?} is not canonical padded standard base64"
            );
            assert!(serde_json::from_value::<ImageBase64>(serde_json::json!(invalid)).is_err());
        }
        for valid in ["AA==", "AAA=", "AAAA", "iVBORw0KGgo="] {
            assert!(ImageBase64::new(valid).is_ok(), "{valid:?}");
        }

        let marker = "c2VjcmV0LWltYWdlLWJ5dGVz";
        let payload = ImageBase64::new(marker).unwrap();
        let debug = format!("{payload:?}");
        assert_eq!(debug, "ImageBase64(<redacted>)");
        assert!(!debug.contains(marker));

        let oversized = "A".repeat(MAX_IMAGE_BASE64_BYTES + 4);
        assert!(ImageBase64::new(oversized).is_err());
    }

    #[test]
    fn only_allowlisted_raster_media_types_decode() {
        for (media_type, expected) in [
            ("image/png", ImageMediaType::Png),
            ("image/jpeg", ImageMediaType::Jpeg),
            ("image/gif", ImageMediaType::Gif),
            ("image/webp", ImageMediaType::Webp),
        ] {
            let decoded: ImageMediaType =
                serde_json::from_value(serde_json::json!(media_type)).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.as_str(), media_type);
        }
        for rejected in ["image/svg+xml", "text/html", "image/avif", "IMAGE/PNG"] {
            assert!(serde_json::from_value::<ImageMediaType>(serde_json::json!(rejected)).is_err());
        }
    }

    #[test]
    fn list_validation_is_exhaustive_and_bounded() {
        let text = || ContentSegment::Text {
            text: "prompt".into(),
        };
        let image_segment = || ContentSegment::Image { image: image() };

        for rejected in [
            vec![],
            vec![text()],
            vec![image_segment()],
            vec![text(), text(), image_segment()],
            vec![text(), ContentSegment::Unknown],
        ] {
            assert!(ContentSegments::new(rejected).is_err());
        }

        let mut maximum = vec![text()];
        maximum.extend((0..MAX_INPUT_IMAGES).map(|_| image_segment()));
        assert_eq!(maximum.len(), MAX_INPUT_SEGMENTS);
        assert!(ContentSegments::new(maximum).is_ok());

        let mut too_many = vec![text()];
        too_many.extend((0..=MAX_INPUT_IMAGES).map(|_| image_segment()));
        assert!(ContentSegments::new(too_many).is_err());

        assert!(
            ContentSegments::new(vec![
                ContentSegment::Text {
                    text: "x".repeat(crate::task::MAX_TASK_TEXT_BYTES + 1)
                },
                image_segment(),
            ])
            .is_err()
        );

        let per_image = "A".repeat(MAX_IMAGE_BASE64_BYTES);
        let bounded_image =
            ImageContent::new(ImageMediaType::Png, per_image).expect("per-image maximum");
        let mut aggregate = vec![text()];
        aggregate.extend(
            (0..=MAX_TOTAL_IMAGE_BASE64_BYTES / MAX_IMAGE_BASE64_BYTES).map(|_| {
                ContentSegment::Image {
                    image: bounded_image.clone(),
                }
            }),
        );
        assert!(ContentSegments::new(aggregate).is_err());
    }

    fn file() -> FileContent {
        FileContent::new("src/main.rs", "fn main() {}\n").expect("a plain workspace file")
    }

    #[test]
    fn an_attached_file_has_one_canonical_wire_shape_and_a_content_free_debug() {
        let encoded = serde_json::to_value(file()).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"path": "src/main.rs", "text": "fn main() {}\n"})
        );
        assert_eq!(
            serde_json::from_value::<FileContent>(encoded).unwrap(),
            file()
        );

        let secret = FileContent::new("config/creds.env", "TOKEN=hunter2").unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("config/creds.env"), "{debug}");
        assert!(debug.contains("text_bytes"), "{debug}");
    }

    #[test]
    fn an_attached_path_is_workspace_relative_plain_and_terminal_safe() {
        for rejected in [
            "",
            "/etc/passwd",
            "../outside.txt",
            "src/../../outside.txt",
            "./src/main.rs",
            "src//main.rs",
            "src/main.rs/",
            r"src\main.rs",
            r"\\server\share\x.txt",
            "C:/Windows/win.ini",
            "src/ma\u{202e}in.rs",
            "src/ma\u{200b}in.rs",
            "src/ma\nin.rs",
        ] {
            assert!(
                FileContent::new(rejected, "x").is_err(),
                "{rejected:?} is not a plain workspace-relative path"
            );
            assert!(
                serde_json::from_value::<FileContent>(
                    serde_json::json!({"path": rejected, "text": "x"})
                )
                .map_or(true, |decoded| decoded.validate().is_err()),
                "{rejected:?} must not survive admission"
            );
        }
        for accepted in ["a", "src/main.rs", "docs/spec/abi.md", "a.b/c-d_e/f.rs"] {
            assert!(FileContent::new(accepted, "x").is_ok(), "{accepted:?}");
        }
        assert!(FileContent::new("a".repeat(MAX_FILE_PATH_BYTES), "x").is_ok());
        assert!(FileContent::new("a".repeat(MAX_FILE_PATH_BYTES + 1), "x").is_err());
    }

    #[test]
    fn an_oversized_or_binary_file_is_refused_never_shortened() {
        assert!(FileContent::new("a.txt", "x".repeat(MAX_FILE_TEXT_BYTES)).is_ok());
        let oversized = FileContent::new("a.txt", "x".repeat(MAX_FILE_TEXT_BYTES + 1));
        assert_eq!(
            oversized,
            Err("attached file text exceeds its declared bound"),
            "an oversized file is a refusal, not a shorter file"
        );
        assert!(FileContent::new("a.bin", "ELF\0\0\0").is_err());
        // An empty file is a fact about the workspace, not an error.
        assert!(FileContent::new("empty.txt", "").is_ok());
    }

    #[test]
    fn a_file_submission_is_bounded_non_empty_and_free_of_repeated_paths() {
        assert!(validate_file_submission("review", &[], &[file()]).is_ok());
        assert_eq!(
            validate_file_submission("review", &[], &[]),
            Err("a file submission must carry at least one file")
        );
        assert!(
            validate_file_submission("review", &[], &[file(), file()]).is_err(),
            "the same path twice is a chip list bug, not two references"
        );

        let many = (0..=MAX_INPUT_FILES)
            .map(|index| FileContent::new(format!("f{index}.txt"), "x").unwrap())
            .collect::<Vec<_>>();
        assert!(validate_file_submission("review", &[], &many[..MAX_INPUT_FILES]).is_ok());
        assert_eq!(
            validate_file_submission("review", &[], &many),
            Err("too many input files")
        );

        // Aggregate text: four maximum-size files clear the per-file bound and trip the total.
        let bulky = (0..4)
            .map(|index| {
                FileContent::new(format!("f{index}.txt"), "x".repeat(MAX_FILE_TEXT_BYTES)).unwrap()
            })
            .collect::<Vec<_>>();
        const _: () = assert!(4 * MAX_FILE_TEXT_BYTES > MAX_TOTAL_FILE_TEXT_BYTES);
        assert_eq!(
            validate_file_submission("review", &[], &bulky),
            Err("attached file text exceeds its aggregate bound")
        );

        // Prompt plus files must fit the task-text bound, framing included, or nothing is sent.
        let prompt = "x".repeat(crate::task::MAX_TASK_TEXT_BYTES - MAX_FILE_TEXT_BYTES);
        let one = [FileContent::new("f.txt", "x".repeat(MAX_FILE_TEXT_BYTES)).unwrap()];
        assert_eq!(
            validate_file_submission(&prompt, &[], &one),
            Err("prompt plus attached files exceed the task text bound"),
            "framing is charged, so a renderer can never be the thing that overflows"
        );
        const _: () = assert!(FILE_ATTACHMENT_FRAMING_BYTES > 0);
        assert!(
            validate_file_submission(&prompt[..prompt.len() - MAX_FILE_PATH_BYTES], &[], &one)
                .is_ok()
        );
    }

    #[test]
    fn a_file_submission_carries_images_under_the_same_bounds_as_a_segment_list() {
        assert!(validate_file_submission("both", &[image()], &[file()]).is_ok());

        let too_many = (0..=MAX_INPUT_IMAGES).map(|_| image()).collect::<Vec<_>>();
        assert_eq!(
            validate_file_submission("both", &too_many, &[file()]),
            Err("too many input images")
        );

        let bounded = ImageContent::new(ImageMediaType::Png, "A".repeat(MAX_IMAGE_BASE64_BYTES))
            .expect("per-image maximum");
        let aggregate = (0..=MAX_TOTAL_IMAGE_BASE64_BYTES / MAX_IMAGE_BASE64_BYTES)
            .map(|_| bounded.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            validate_file_submission("both", &aggregate, &[file()]),
            Err("input image payloads exceed their aggregate bound")
        );
    }

    #[test]
    fn an_unknown_nested_segment_drops_its_payload_then_fails_admission() {
        let marker = "foreign-image-credential";
        let segment: ContentSegment = serde_json::from_value(serde_json::json!({
            "type": "video",
            "data": marker
        }))
        .unwrap();
        assert_eq!(segment, ContentSegment::Unknown);
        assert!(!format!("{segment:?}").contains(marker));
        assert_eq!(
            serde_json::to_value(&segment).unwrap(),
            serde_json::json!({"type": "unknown"})
        );
        assert!(
            serde_json::from_value::<ContentSegments>(serde_json::json!([
                {"type": "text", "text": "inspect"},
                {"type": "video", "data": marker}
            ]))
            .is_err()
        );
    }
}
