//! Bounded code-intelligence normalization: definition, references, and hover.
//!
//! Servers emit several legal union shapes and do not promise result order. This module normalizes
//! those shapes into deterministic answers while preserving explicit malformed, duplicate,
//! truncated, and uninspected counts. It does not spawn or own a language-server process.

use crate::{
    LspError, MAX_DOCUMENT_URI_BYTES, MAX_HOVER_BYTES, MAX_HOVER_FRAGMENTS, MAX_LOCATION_INPUTS,
    MAX_LOCATIONS, documents::DocumentStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

/// What a caller asked for. The method string is derived here so a typo cannot produce a request
/// that a server answers with silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    Definition,
    References { include_declaration: bool },
    Hover,
}

impl Query {
    pub fn method(self) -> &'static str {
        match self {
            Self::Definition => "textDocument/definition",
            Self::References { .. } => "textDocument/references",
            Self::Hover => "textDocument/hover",
        }
    }

    /// Build a bounded `params` object. URI encoding remains the caller's responsibility; this
    /// layer preserves already-correct percent encoding rather than rewriting it.
    pub fn params(self, uri: &str, at: Position) -> Result<Value, LspError> {
        validate_uri_bound(uri)?;
        let mut params = json!({
            "textDocument": { "uri": uri },
            "position": { "line": at.line, "character": at.character },
        });
        if let Self::References {
            include_declaration,
        } = self
        {
            params["context"] = json!({ "includeDeclaration": include_declaration });
        }
        Ok(params)
    }
}

/// A normalized location answer. For an array input, these counters form an audit trail:
/// retained + truncated + malformed + duplicates + uninspected equals the wire entry count.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Locations {
    pub locations: Vec<Location>,
    /// Unique, valid inspected results beyond the requested output limit.
    pub truncated: usize,
    pub malformed: usize,
    pub duplicates: usize,
    /// Wire entries beyond the hard inspection ceiling. Nothing is claimed about their shape.
    pub uninspected: usize,
}

/// Normalize `Location | Location[] | LocationLink[] | null` into a deterministic bounded list.
pub fn parse_locations(value: &Value, limit: usize) -> Result<Locations, LspError> {
    if !(1..=MAX_LOCATIONS).contains(&limit) {
        return Err(LspError::InvalidLocationLimit {
            value: limit,
            max: MAX_LOCATIONS,
        });
    }
    match value {
        Value::Null => Ok(Locations::default()),
        Value::Array(items) => Ok(parse_location_items(items, limit)),
        single => Ok(parse_location_items(std::slice::from_ref(single), limit)),
    }
}

fn parse_location_items(items: &[Value], limit: usize) -> Locations {
    let inspected = items.len().min(MAX_LOCATION_INPUTS);
    let mut out = Locations {
        uninspected: items.len() - inspected,
        ..Locations::default()
    };
    let mut unique = BTreeSet::new();
    for item in &items[..inspected] {
        match location_from(item) {
            Some(location) => {
                if !unique.insert(location) {
                    out.duplicates = out.duplicates.saturating_add(1);
                }
            }
            None => out.malformed = out.malformed.saturating_add(1),
        }
    }

    out.truncated = unique.len().saturating_sub(limit);
    out.locations = unique.into_iter().take(limit).collect();
    out
}

fn location_from(item: &Value) -> Option<Location> {
    if let Some(uri) = item.get("uri").and_then(Value::as_str) {
        return location(uri, range_from(item.get("range")?)?);
    }

    let uri = item.get("targetUri").and_then(Value::as_str)?;
    // If a selection range is present but malformed, reject the link. Falling back in that case
    // would let a bad preferred coordinate silently choose the much broader body range.
    let range = match item.get("targetSelectionRange") {
        Some(value) => range_from(value)?,
        None => range_from(item.get("targetRange")?)?,
    };
    location(uri, range)
}

fn location(uri: &str, range: Range) -> Option<Location> {
    if uri.is_empty() || uri.len() > MAX_DOCUMENT_URI_BYTES || range.start > range.end {
        return None;
    }
    Some(Location {
        uri: uri.to_owned(),
        range,
    })
}

fn range_from(value: &Value) -> Option<Range> {
    Some(Range {
        start: position_from(value.get("start")?)?,
        end: position_from(value.get("end")?)?,
    })
}

fn position_from(value: &Value) -> Option<Position> {
    Some(Position {
        // `as_u64` rejects negative and fractional values instead of wrapping or rounding.
        line: u32::try_from(value.get("line")?.as_u64()?).ok()?,
        character: u32::try_from(value.get("character")?.as_u64()?).ok()?,
    })
}

/// Bounded hover text plus observable loss.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HoverText {
    pub text: Option<String>,
    /// Encoded UTF-8 bytes omitted from inspected, otherwise-valid fragments.
    pub truncated_bytes: usize,
    pub malformed: usize,
    /// Array fragments beyond the hard inspection ceiling.
    pub uninspected: usize,
}

/// Flatten `MarkupContent`, `MarkedString`, a bare string, or an array of those into plain text.
pub fn parse_hover_text(value: &Value) -> HoverText {
    let Some(contents) = value.get("contents") else {
        return HoverText::default();
    };
    let mut output = String::new();
    let mut result = HoverText::default();
    match contents {
        Value::Array(items) => {
            let inspected = items.len().min(MAX_HOVER_FRAGMENTS);
            result.uninspected = items.len() - inspected;
            for item in &items[..inspected] {
                append_hover_item(item, &mut output, &mut result);
            }
        }
        item => append_hover_item(item, &mut output, &mut result),
    }
    if !output.is_empty() {
        result.text = Some(output);
    }
    result
}

fn append_hover_item(item: &Value, output: &mut String, result: &mut HoverText) {
    let fragment = match item {
        Value::String(text) => Some(text.as_str()),
        Value::Object(_) => item.get("value").and_then(Value::as_str),
        _ => None,
    };
    let Some(fragment) = fragment else {
        result.malformed = result.malformed.saturating_add(1);
        return;
    };
    let fragment = fragment.trim();
    if fragment.is_empty() {
        return;
    }

    let separator = if output.is_empty() { "" } else { "\n\n" };
    let remaining = MAX_HOVER_BYTES.saturating_sub(output.len());
    if separator.len() > remaining {
        result.truncated_bytes = result
            .truncated_bytes
            .saturating_add(separator.len())
            .saturating_add(fragment.len());
        return;
    }
    let prefix_bytes = utf8_prefix_len(fragment, remaining - separator.len());
    if prefix_bytes == 0 {
        result.truncated_bytes = result
            .truncated_bytes
            .saturating_add(separator.len())
            .saturating_add(fragment.len());
        return;
    }
    output.push_str(separator);
    output.push_str(&fragment[..prefix_bytes]);
    result.truncated_bytes = result
        .truncated_bytes
        .saturating_add(fragment.len() - prefix_bytes);
}

fn utf8_prefix_len(text: &str, max_bytes: usize) -> usize {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Snapshot freshness check for a positional answer. A future driver must repeat this check at the
/// effect/commit boundary; this pure helper does not make a later edit atomic with the check.
pub fn ensure_fresh(
    store: &DocumentStore,
    uri: &str,
    issued_at_version: i32,
) -> Result<(), LspError> {
    validate_uri_bound(uri)?;
    match store.version(uri) {
        Some(current) if current == issued_at_version => Ok(()),
        Some(current) if issued_at_version < current => Err(LspError::StaleResult {
            have: current,
            issued: issued_at_version,
        }),
        Some(current) => Err(LspError::FutureResult {
            have: current,
            issued: issued_at_version,
        }),
        None => Err(LspError::UnknownDocument {
            uri: uri.to_owned(),
        }),
    }
}

fn validate_uri_bound(uri: &str) -> Result<(), LspError> {
    if uri.len() > MAX_DOCUMENT_URI_BYTES {
        return Err(LspError::DocumentUriTooLong {
            value: uri.len(),
            limit: MAX_DOCUMENT_URI_BYTES,
        });
    }
    Ok(())
}

pub fn default_limit() -> usize {
    MAX_LOCATIONS
}

#[cfg(test)]
#[path = "intel_tests.rs"]
mod tests;
