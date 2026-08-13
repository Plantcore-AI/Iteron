use std::fmt;
use std::path::Path;

const MAX_DISPLAY_CHARS: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageInputErrorKind {
    InvalidLimits,
    InvalidReference,
    TooManyMentions,
    TooManyAttachments,
    UnsupportedExtension,
    OpenFailed,
    ReadFailed,
    ReaderBusy,
    ReadTimedOut,
    FileTooLarge,
    AggregateTooLarge,
    EncodedPayloadTooLarge,
    DecodeLimitExceeded,
    InvalidImage,
    TruncatedImage,
    ExtensionMismatch,
    HeicConversionUnavailable,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            dead_code,
            reason = "the cross-platform error vocabulary includes macOS conversion failures"
        )
    )]
    HeicConversionFailed,
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            dead_code,
            reason = "the cross-platform error vocabulary includes macOS conversion timeouts"
        )
    )]
    HeicConversionTimedOut,
    ProtocolRejected,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ImageInputError {
    kind: ImageInputErrorKind,
    name: Option<SafeDisplayName>,
}

impl ImageInputError {
    pub(super) fn unnamed(kind: ImageInputErrorKind) -> Self {
        Self { kind, name: None }
    }

    pub(super) fn named(kind: ImageInputErrorKind, name: SafeDisplayName) -> Self {
        Self {
            kind,
            name: Some(name),
        }
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "integration tests compile this module separately from the binary test target"
    )]
    pub const fn kind(&self) -> ImageInputErrorKind {
        self.kind
    }
}

impl fmt::Display for ImageInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ImageInputErrorKind::InvalidLimits => "invalid image attachment limits",
            ImageInputErrorKind::InvalidReference => "invalid local image reference",
            ImageInputErrorKind::TooManyMentions => "too many image mentions",
            ImageInputErrorKind::TooManyAttachments => "too many image attachments",
            ImageInputErrorKind::UnsupportedExtension => "unsupported image extension",
            ImageInputErrorKind::OpenFailed => "could not open image",
            ImageInputErrorKind::ReadFailed => "could not read image",
            ImageInputErrorKind::ReaderBusy => "another image file read is still in progress",
            ImageInputErrorKind::ReadTimedOut => "image file read timed out",
            ImageInputErrorKind::FileTooLarge => "image exceeds the per-file limit",
            ImageInputErrorKind::AggregateTooLarge => "images exceed the aggregate limit",
            ImageInputErrorKind::EncodedPayloadTooLarge => {
                "image base64 payload exceeds its encoded limit"
            }
            ImageInputErrorKind::DecodeLimitExceeded => {
                "image dimensions, frames, or decoded pixels exceed the decode limit"
            }
            ImageInputErrorKind::InvalidImage => "file is not a supported raster image",
            ImageInputErrorKind::TruncatedImage => "image file is truncated",
            ImageInputErrorKind::ExtensionMismatch => {
                "image bytes do not match the filename extension"
            }
            ImageInputErrorKind::HeicConversionUnavailable => {
                "HEIC conversion is unavailable on this platform"
            }
            ImageInputErrorKind::HeicConversionFailed => "could not convert HEIC image to JPEG",
            ImageInputErrorKind::HeicConversionTimedOut => "HEIC conversion timed out",
            ImageInputErrorKind::ProtocolRejected => "image submission failed validation",
        };
        formatter.write_str(message)?;
        if let Some(name) = &self.name {
            write!(formatter, ": {name}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ImageInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ImageInputError {}

#[derive(Clone, PartialEq, Eq)]
pub struct SafeDisplayName(String);

impl SafeDisplayName {
    pub(crate) fn from_path(path: &Path) -> Self {
        let raw = path
            .file_name()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| std::ffi::OsStr::new("image"))
            .to_string_lossy();
        Self::from_label(&raw)
    }

    pub(crate) fn from_label(raw: &str) -> Self {
        let mut safe = String::new();
        let mut characters = raw.chars();
        for character in characters.by_ref().take(MAX_DISPLAY_CHARS) {
            safe.push(if unsafe_display_character(character) {
                '\u{fffd}'
            } else {
                character
            });
        }
        if characters.next().is_some() {
            safe.push('…');
        }
        if safe.is_empty() {
            safe.push_str("image");
        }
        Self(safe)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeDisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for SafeDisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SafeDisplayName")
            .field(&self.0)
            .finish()
    }
}

fn unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
        )
}
