//! Curated MIME-to-inspector routing for bounded raster input.
//!
//! The selected route is executable: it chooses the exact structural/full decoder invoked for an
//! attachment.  A claimed MIME, detected signature, or checkpoint catalog mismatch is refused
//! before provider request construction.

use super::{ImageInputErrorKind, MAX_IMAGE_FILE_BYTES, MultimodalDecodeEnvelope, sniff};
use base64::Engine as _;
use iteron_protocol::{ImageContent, ImageMediaType};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) enum BinaryInspector {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl BinaryInspector {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Png => "iteron.binary.png-v1",
            Self::Jpeg => "iteron.binary.jpeg-v1",
            Self::Gif => "iteron.binary.gif-v1",
            Self::Webp => "iteron.binary.webp-v1",
        }
    }

    pub(crate) const fn media_type(self) -> ImageMediaType {
        match self {
            Self::Png => ImageMediaType::Png,
            Self::Jpeg => ImageMediaType::Jpeg,
            Self::Gif => ImageMediaType::Gif,
            Self::Webp => ImageMediaType::Webp,
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        [Self::Png, Self::Jpeg, Self::Gif, Self::Webp]
            .into_iter()
            .find(|inspector| inspector.id() == id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum UnknownMimePolicy {
    Reject,
    MetadataOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BinaryMediaInspectionPolicy {
    routes: BTreeMap<String, BinaryInspector>,
    unknown_mime: UnknownMimePolicy,
    max_input_bytes: usize,
}

impl BinaryMediaInspectionPolicy {
    pub(crate) fn new(
        routes: BTreeMap<String, String>,
        unknown_mime: UnknownMimePolicy,
        max_input_bytes: usize,
    ) -> Result<Self, &'static str> {
        if routes.len() > 1_024 || max_input_bytes == 0 || max_input_bytes > 1_073_741_824 {
            return Err("binary inspection policy is outside its bounded owner envelope");
        }
        let mut decoded = BTreeMap::new();
        for (mime, id) in routes {
            let inspector = BinaryInspector::from_id(&id)
                .ok_or("binary inspection policy names an unknown inspector")?;
            if mime != inspector.media_type().as_str() || decoded.insert(mime, inspector).is_some()
            {
                return Err("binary inspection policy contains a mismatched MIME route");
            }
        }
        // The neutral provider protocol has no metadata-only binary segment.  Admitting that mode
        // would silently discard the bytes, so the current executable owner rejects it.
        if unknown_mime != UnknownMimePolicy::Reject || decoded.len() != 4 {
            return Err(
                "binary inspection policy must cover every admitted raster MIME and reject unknown MIME",
            );
        }
        Ok(Self {
            routes: decoded,
            unknown_mime,
            max_input_bytes,
        })
    }

    pub(crate) fn owner() -> Self {
        Self::new(
            [
                BinaryInspector::Png,
                BinaryInspector::Jpeg,
                BinaryInspector::Gif,
                BinaryInspector::Webp,
            ]
            .into_iter()
            .map(|inspector| {
                (
                    inspector.media_type().as_str().to_owned(),
                    inspector.id().to_owned(),
                )
            })
            .collect(),
            UnknownMimePolicy::Reject,
            MAX_IMAGE_FILE_BYTES,
        )
        .expect("fixed binary inspection policy")
    }

    pub(crate) fn mime_routes(&self) -> BTreeMap<String, String> {
        self.routes
            .iter()
            .map(|(mime, inspector)| (mime.clone(), inspector.id().to_owned()))
            .collect()
    }

    pub(crate) fn inspector_ids(&self) -> BTreeSet<String> {
        self.routes
            .values()
            .map(|inspector| inspector.id().to_owned())
            .collect()
    }

    pub(crate) const fn unknown_mime(&self) -> UnknownMimePolicy {
        self.unknown_mime
    }

    pub(crate) const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub(crate) fn inspect_raw(&self, bytes: &[u8]) -> Result<ImageMediaType, ImageInputErrorKind> {
        if bytes.len() > self.max_input_bytes {
            return Err(ImageInputErrorKind::FileTooLarge);
        }
        let media_type = sniff::detect_image(bytes)?;
        self.inspect_as(media_type, bytes)?;
        Ok(media_type)
    }

    /// Decode and inspect one protocol image under both independently pinned envelopes.
    ///
    /// Returning the decoded byte count lets the caller enforce the aggregate family-68 ceiling
    /// without decoding attacker-controlled base64 a second time.
    pub(crate) fn inspect_content_with_envelope(
        &self,
        image: &ImageContent,
        envelope: MultimodalDecodeEnvelope,
    ) -> Result<usize, ImageInputErrorKind> {
        let per_image_limit = self.max_input_bytes.min(envelope.per_image_raw_bytes);
        let max_encoded = per_image_limit
            .checked_add(2)
            .and_then(|value| value.checked_div(3))
            .and_then(|value| value.checked_mul(4))
            .ok_or(ImageInputErrorKind::EncodedPayloadTooLarge)?;
        if image.data.encoded_len() > max_encoded {
            return Err(ImageInputErrorKind::EncodedPayloadTooLarge);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(image.data.as_str())
            .map_err(|_| ImageInputErrorKind::InvalidImage)?;
        if bytes.len() > per_image_limit {
            return Err(ImageInputErrorKind::FileTooLarge);
        }
        self.inspect_as_with_envelope(image.media_type, &bytes, envelope)?;
        Ok(bytes.len())
    }

    fn inspect_as(
        &self,
        media_type: ImageMediaType,
        bytes: &[u8],
    ) -> Result<(), ImageInputErrorKind> {
        let inspector = self
            .routes
            .get(media_type.as_str())
            .copied()
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if inspector.media_type() != media_type {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        sniff::inspect_as(bytes, inspector.media_type())
    }

    fn inspect_as_with_envelope(
        &self,
        media_type: ImageMediaType,
        bytes: &[u8],
        envelope: MultimodalDecodeEnvelope,
    ) -> Result<(), ImageInputErrorKind> {
        let inspector = self
            .routes
            .get(media_type.as_str())
            .copied()
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if inspector.media_type() != media_type {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        sniff::inspect_as_with_limits(
            bytes,
            inspector.media_type(),
            envelope.max_dimension,
            envelope.max_frames,
        )
    }
}

impl Default for BinaryMediaInspectionPolicy {
    fn default() -> Self {
        Self::owner()
    }
}
