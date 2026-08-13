//! Bounded code-intelligence normalization: definition, references, and hover.
//!
//! Servers emit several legal union shapes and do not promise result order. This module normalizes
//! those shapes into deterministic answers while preserving explicit malformed, duplicate,
//! truncated, and uninspected counts. It does not spawn or own a language-server process.

use crate::{
    LspError, MAX_HOVER_BYTES, MAX_HOVER_FRAGMENTS, MAX_LOCATION_INPUTS, MAX_LOCATIONS,
    MAX_LSP_POSITION,
    documents::{DocumentStore, range_components, validate_document_uri},
    pending::CompletedRequest,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Position {
    line: u32,
    character: u32,
}

impl Position {
    pub fn new(line: u32, character: u32) -> Result<Self, LspError> {
        if line > MAX_LSP_POSITION || character > MAX_LSP_POSITION {
            return Err(LspError::InvalidPosition {
                line,
                character,
                max: MAX_LSP_POSITION,
            });
        }
        Ok(Self { line, character })
    }

    pub fn line(self) -> u32 {
        self.line
    }

    pub fn character(self) -> u32 {
        self.character
    }
}

impl<'de> Deserialize<'de> for Position {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WirePosition {
            line: u64,
            character: u64,
        }

        let wire = WirePosition::deserialize(deserializer)?;
        if wire.line > u64::from(MAX_LSP_POSITION) || wire.character > u64::from(MAX_LSP_POSITION) {
            return Err(de::Error::custom("position exceeds the LSP uinteger range"));
        }
        Ok(Self {
            line: wire.line as u32,
            character: wire.character as u32,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Range {
    start: Position,
    end: Position,
}

impl Range {
    pub fn new(start: Position, end: Position) -> Result<Self, LspError> {
        if start > end {
            return Err(LspError::InvalidRange);
        }
        Ok(Self { start, end })
    }

    pub fn start(self) -> Position {
        self.start
    }

    pub fn end(self) -> Position {
        self.end
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRange {
            start: Position,
            end: Position,
        }

        let wire = WireRange::deserialize(deserializer)?;
        Self::new(wire.start, wire.end).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Location {
    uri: String,
    range: Range,
}

impl Location {
    pub fn new(uri: impl Into<String>, range: Range) -> Result<Self, LspError> {
        let uri = uri.into();
        validate_document_uri(&uri)?;
        Ok(Self { uri, range })
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn range(&self) -> Range {
        self.range
    }
}

impl<'de> Deserialize<'de> for Location {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireLocation {
            uri: String,
            range: Range,
        }

        let wire = WireLocation::deserialize(deserializer)?;
        Self::new(wire.uri, wire.range).map_err(de::Error::custom)
    }
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
        validate_document_uri(uri)?;
        let mut params = json!({
            "textDocument": { "uri": uri },
            "position": { "line": at.line(), "character": at.character() },
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
    if !(1..=iteron_tunables::param_integer("lsp.lib.max_locations", MAX_LOCATIONS))
        .contains(&limit)
    {
        return Err(LspError::InvalidLocationLimit {
            value: limit,
            max: iteron_tunables::param_integer("lsp.lib.max_locations", MAX_LOCATIONS),
        });
    }
    match value {
        Value::Null => Ok(Locations::default()),
        Value::Array(items) => Ok(parse_location_items(items, limit)),
        single => Ok(parse_location_items(std::slice::from_ref(single), limit)),
    }
}

fn parse_location_items(items: &[Value], limit: usize) -> Locations {
    let inspected = items.len().min(iteron_tunables::param_integer(
        "lsp.lib.max_location_inputs",
        MAX_LOCATION_INPUTS,
    ));
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
    // All three fields are required by LocationLink. The narrower selection must be contained in
    // the target range; otherwise consumers could navigate outside the server's claimed target.
    let target = range_from(item.get("targetRange")?)?;
    let selection = range_from(item.get("targetSelectionRange")?)?;
    if target.start() > selection.start() || selection.end() > target.end() {
        return None;
    }
    location(uri, selection)
}

fn location(uri: &str, range: Range) -> Option<Location> {
    Location::new(uri, range).ok()
}

fn range_from(value: &Value) -> Option<Range> {
    let (start, end) = range_components(value)?;
    let start = Position::new(start.0, start.1).ok()?;
    let end = Position::new(end.0, end.1).ok()?;
    Range::new(start, end).ok()
}

/// Bounded hover text plus observable loss.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HoverText {
    pub text: Option<String>,
    pub range: Option<Range>,
    /// Source UTF-8 bytes seen in otherwise-valid inspected fragments.
    pub source_bytes: usize,
    /// Source bytes actually retained. `retained_source_bytes + truncated_bytes == source_bytes`.
    pub retained_source_bytes: usize,
    /// Encoded source bytes omitted from inspected, otherwise-valid fragments. Synthesized
    /// separators are deliberately excluded.
    pub truncated_bytes: usize,
    /// Separator bytes synthesized and retained between fragments.
    pub separator_bytes: usize,
    pub malformed: usize,
    /// Array fragments beyond the hard inspection ceiling.
    pub uninspected: usize,
}

/// Flatten `MarkupContent`, `MarkedString`, a bare string, or an array of those into plain text.
pub fn parse_hover_text(value: &Value) -> HoverText {
    if value.is_null() {
        return HoverText::default();
    }
    let Some(object) = value.as_object() else {
        return HoverText {
            malformed: 1,
            ..HoverText::default()
        };
    };
    let mut result = HoverText::default();
    if let Some(range) = object.get("range") {
        match range_from(range) {
            Some(range) => result.range = Some(range),
            None => result.malformed = result.malformed.saturating_add(1),
        }
    }
    let Some(contents) = object.get("contents") else {
        result.malformed = result.malformed.saturating_add(1);
        return result;
    };
    let mut output = String::new();
    match contents {
        Value::Array(items) => {
            let inspected = items.len().min(iteron_tunables::param_integer(
                "lsp.lib.max_hover_fragments",
                MAX_HOVER_FRAGMENTS,
            ));
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
    let fragment = hover_fragment(item);
    let Some(fragment) = fragment else {
        result.malformed = result.malformed.saturating_add(1);
        return;
    };
    result.source_bytes = result.source_bytes.saturating_add(fragment.len());
    if fragment.is_empty() {
        return;
    }

    let separator = if output.is_empty() { "" } else { "\n\n" };
    let remaining = iteron_tunables::param_integer("lsp.lib.max_hover_bytes", MAX_HOVER_BYTES)
        .saturating_sub(output.len());
    if separator.len() > remaining {
        result.truncated_bytes = result.truncated_bytes.saturating_add(fragment.len());
        return;
    }
    let prefix_bytes = utf8_prefix_len(fragment, remaining - separator.len());
    if prefix_bytes == 0 {
        result.truncated_bytes = result.truncated_bytes.saturating_add(fragment.len());
        return;
    }
    output.push_str(separator);
    output.push_str(&fragment[..prefix_bytes]);
    result.separator_bytes = result.separator_bytes.saturating_add(separator.len());
    result.retained_source_bytes = result.retained_source_bytes.saturating_add(prefix_bytes);
    result.truncated_bytes = result
        .truncated_bytes
        .saturating_add(fragment.len() - prefix_bytes);
}

fn hover_fragment(item: &Value) -> Option<&str> {
    match item {
        Value::String(text) => Some(text),
        Value::Object(object) => {
            let value = object.get("value")?.as_str()?;
            match (object.get("kind"), object.get("language")) {
                (Some(kind), None) if matches!(kind.as_str(), Some("plaintext" | "markdown")) => {
                    Some(value)
                }
                (None, Some(language)) if language.as_str().is_some() => Some(value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn utf8_prefix_len(text: &str, max_bytes: usize) -> usize {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Freshness check for a completed positional answer. The pending registry captured the snapshot
/// at admission and returned it inside this unforgeable completion capability. A future driver
/// must repeat this check at the effect/commit boundary; this pure helper does not make a later
/// edit atomic with the check.
pub fn ensure_fresh(store: &DocumentStore, completed: &CompletedRequest) -> Result<(), LspError> {
    let issued = completed
        .document_snapshot()
        .ok_or(LspError::ResultNotBoundToDocument)?;
    if completed.generation() != issued.server_generation() {
        return Err(LspError::ServerEpochMismatch {
            expected: issued.server_generation(),
            received: completed.generation(),
        });
    }
    validate_document_uri(issued.uri())?;
    let current = store.snapshot(issued.uri())?;
    if current.server_epoch() != issued.server_epoch() {
        return Err(LspError::StaleServerGeneration {
            have: current.server_generation(),
            issued: issued.server_generation(),
        });
    }
    if current.incarnation() != issued.incarnation() {
        return Err(LspError::StaleDocumentIncarnation {
            have: current.incarnation(),
            issued: issued.incarnation(),
        });
    }
    if current.wire_version() == issued.wire_version() {
        Ok(())
    } else if issued.wire_version() < current.wire_version() {
        Err(LspError::StaleResult {
            have: current.wire_version(),
            issued: issued.wire_version(),
        })
    } else {
        Err(LspError::FutureResult {
            have: current.wire_version(),
            issued: issued.wire_version(),
        })
    }
}

pub fn default_limit() -> usize {
    iteron_tunables::param_integer("lsp.lib.max_locations", MAX_LOCATIONS)
}

#[cfg(test)]
#[path = "intel_tests.rs"]
mod tests;
