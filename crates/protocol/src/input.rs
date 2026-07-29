//! Neutral, provider-independent content carried by a multimodal user submission.
//!
//! This module owns only the SQ representation and its bounds. It deliberately does not inspect
//! image bytes or shape provider-specific content blocks: frontends authenticate the file type
//! before encoding, and provider adapters decide whether and how to consume an admitted segment.

use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::fmt;

pub use crate::{ContentSegment, ContentSegments, ImageBase64, ImageContent, ImageMediaType};

/// Maximum number of segments in one multimodal submission: one text prompt and up to eight
/// images.
pub const MAX_INPUT_SEGMENTS: usize = 9;
/// Maximum number of image attachments in one multimodal submission.
pub const MAX_INPUT_IMAGES: usize = 8;
/// Maximum encoded bytes in one image's canonical RFC 4648 base64 payload.
pub const MAX_IMAGE_BASE64_BYTES: usize = 8 * 1024 * 1024;
/// Maximum encoded image bytes across one submission.
pub const MAX_TOTAL_IMAGE_BASE64_BYTES: usize = 32 * 1024 * 1024;

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
        ContentSegment, ContentSegments, ImageBase64, ImageContent, ImageMediaType,
        MAX_IMAGE_BASE64_BYTES, MAX_INPUT_IMAGES, MAX_INPUT_SEGMENTS, MAX_TOTAL_IMAGE_BASE64_BYTES,
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
