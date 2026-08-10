//! Hash-covered event-field reference encoding.

use super::ContentStoreError;
use super::model::MARKER_PREFIX;
use core_protocol::ErasureContentDigest;

#[derive(Clone, Copy)]
pub(super) enum FieldEncoding {
    Text,
    Json,
}

pub(super) fn encode(
    value: &serde_json::Value,
) -> Result<(Vec<u8>, FieldEncoding), ContentStoreError> {
    match value {
        serde_json::Value::String(text) => Ok((text.as_bytes().to_vec(), FieldEncoding::Text)),
        other => Ok((serde_json::to_vec(other)?, FieldEncoding::Json)),
    }
}

pub(super) fn decode(
    bytes: &[u8],
    encoding: FieldEncoding,
) -> Result<serde_json::Value, &'static str> {
    match encoding {
        FieldEncoding::Text => std::str::from_utf8(bytes)
            .map(|text| serde_json::Value::String(text.to_owned()))
            .map_err(|_| "invalid_utf8"),
        FieldEncoding::Json => serde_json::from_slice(bytes).map_err(|_| "invalid_json"),
    }
}

pub(super) fn marker(digest: &ErasureContentDigest, encoding: FieldEncoding) -> String {
    let encoding = match encoding {
        FieldEncoding::Text => "text",
        FieldEncoding::Json => "json",
    };
    format!("{MARKER_PREFIX}{encoding}:{}", digest.as_str())
}

pub(super) fn parse_marker(
    value: &str,
) -> Result<Option<(ErasureContentDigest, FieldEncoding)>, ContentStoreError> {
    let Some(raw) = value.strip_prefix(MARKER_PREFIX) else {
        return Ok(None);
    };
    let (encoding, raw) = raw.split_once(':').ok_or(ContentStoreError::Corrupt)?;
    let encoding = match encoding {
        "text" => FieldEncoding::Text,
        "json" => FieldEncoding::Json,
        _ => return Err(ContentStoreError::Corrupt),
    };
    ErasureContentDigest::new(raw.to_owned())
        .map(|digest| Some((digest, encoding)))
        .map_err(|_| ContentStoreError::Corrupt)
}
