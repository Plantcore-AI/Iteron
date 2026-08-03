//! Document incarnations, versions, and bounded diagnostic retention.
//!
//! A URI/version pair is not a stable identity: a document can be closed and reopened at the same
//! or a lower version while an old server result is still in flight. Every open lifetime therefore
//! receives a never-reused incarnation. Freshness-sensitive APIs require the complete
//! URI/incarnation/version snapshot instead of reconstructing identity from the URI alone.

use crate::{
    LspError, MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT, MAX_DIAGNOSTIC_BYTES_TOTAL,
    MAX_DIAGNOSTIC_CODE_BYTES, MAX_DIAGNOSTIC_JSON_DEPTH, MAX_DIAGNOSTIC_JSON_NODES,
    MAX_DIAGNOSTIC_JSON_NODES_TOTAL, MAX_DIAGNOSTIC_MESSAGE_BYTES,
    MAX_DIAGNOSTIC_RELATED_INFORMATION, MAX_DIAGNOSTIC_RELATED_MESSAGE_BYTES,
    MAX_DIAGNOSTIC_SOURCE_BYTES, MAX_DIAGNOSTICS_PER_DOCUMENT, MAX_DOCUMENT_URI_BYTES,
    MAX_LSP_POSITION, MAX_OPEN_DOCUMENTS,
};
use serde_json::Value;
use std::{collections::HashMap, io::Write};

/// Complete identity of the text against which a request or notification was observed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentSnapshot {
    pub uri: String,
    pub incarnation: u64,
    pub version: i32,
}

/// Outcome of an observed `didChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A strictly greater version became current.
    Accepted(DocumentSnapshot),
    /// An equal-version change is protocol-invalid. It did not advance the version, but it did
    /// invalidate diagnostics and old snapshots because the caller says the text changed.
    EqualVersionInvalidated(DocumentSnapshot),
    /// A lower version is an already-obsolete notification and did not mutate current state.
    Stale {
        have: i32,
        incoming: i32,
    },
    Unknown,
}

/// Freshness evidence retained alongside diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticProvenance {
    /// Exact LSP version plus the document incarnation.
    Versioned { snapshot: DocumentSnapshot },
    /// LSP permits the version to be omitted. Such diagnostics are explicitly weaker: they are
    /// accepted only against an exact current snapshot and ordered by local successful arrival.
    Unversioned {
        snapshot: DocumentSnapshot,
        arrival: u64,
    },
}

/// What happened to a `publishDiagnostics` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publish {
    Accepted(DiagnosticProvenance),
    Stale { have: i32, incoming: i32 },
    Future { have: i32, incoming: i32 },
    PriorIncarnation { have: u64, incoming: u64 },
    Unknown,
}

#[derive(Debug, Clone)]
struct Document {
    version: i32,
    incarnation: u64,
    diagnostics: Vec<Value>,
    provenance: Option<DiagnosticProvenance>,
    diagnostic_bytes: usize,
    diagnostic_nodes: usize,
}

/// Tracks open documents and diagnostics with explicit freshness provenance.
#[derive(Debug, Clone)]
pub struct DocumentStore {
    docs: HashMap<String, Document>,
    next_incarnation: Option<u64>,
    next_arrival: Option<u64>,
    diagnostic_bytes: usize,
    diagnostic_nodes: usize,
    stale_drops: u64,
    future_drops: u64,
    prior_incarnation_drops: u64,
    unversioned_accepts: u64,
    unknown_drops: u64,
    limit_rejections: u64,
}

impl Default for DocumentStore {
    fn default() -> Self {
        Self {
            docs: HashMap::new(),
            next_incarnation: Some(1),
            next_arrival: Some(1),
            diagnostic_bytes: 0,
            diagnostic_nodes: 0,
            stale_drops: 0,
            future_drops: 0,
            prior_incarnation_drops: 0,
            unversioned_accepts: 0,
            unknown_drops: 0,
            limit_rejections: 0,
        }
    }
}

impl DocumentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a new open lifetime, even if the URI is already tracked.
    pub fn open(&mut self, uri: &str, version: i32) -> Result<DocumentSnapshot, LspError> {
        validate_document_uri(uri)?;
        if !self.docs.contains_key(uri) && self.docs.len() >= MAX_OPEN_DOCUMENTS {
            self.limit_rejections = self.limit_rejections.saturating_add(1);
            return Err(LspError::DocumentLimit {
                limit: MAX_OPEN_DOCUMENTS,
            });
        }
        let incarnation = allocate_sequence(&mut self.next_incarnation, "document incarnation")?;
        if let Some(previous) = self.docs.remove(uri) {
            self.release_budget(&previous);
        }
        self.docs.insert(
            uri.to_owned(),
            Document {
                version,
                incarnation,
                diagnostics: Vec::new(),
                provenance: None,
                diagnostic_bytes: 0,
                diagnostic_nodes: 0,
            },
        );
        Ok(DocumentSnapshot {
            uri: uri.to_owned(),
            incarnation,
            version,
        })
    }

    /// Record an edit. Only a strictly greater LSP version is accepted.
    pub fn change(&mut self, uri: &str, version: i32) -> Result<Change, LspError> {
        validate_document_uri(uri)?;
        let Some(current) = self.docs.get(uri) else {
            return Ok(Change::Unknown);
        };
        if version < current.version {
            return Ok(Change::Stale {
                have: current.version,
                incoming: version,
            });
        }

        let replacement_incarnation = if version == current.version {
            Some(allocate_sequence(
                &mut self.next_incarnation,
                "document incarnation",
            )?)
        } else {
            None
        };
        let doc = self
            .docs
            .get_mut(uri)
            .expect("document cannot disappear during an exclusive borrow");
        self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(doc.diagnostic_bytes);
        self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(doc.diagnostic_nodes);
        doc.diagnostics.clear();
        doc.provenance = None;
        doc.diagnostic_bytes = 0;
        doc.diagnostic_nodes = 0;

        if let Some(incarnation) = replacement_incarnation {
            doc.incarnation = incarnation;
            return Ok(Change::EqualVersionInvalidated(DocumentSnapshot {
                uri: uri.to_owned(),
                incarnation,
                version: doc.version,
            }));
        }
        doc.version = version;
        Ok(Change::Accepted(DocumentSnapshot {
            uri: uri.to_owned(),
            incarnation: doc.incarnation,
            version,
        }))
    }

    pub fn close(&mut self, uri: &str) -> bool {
        if validate_document_uri(uri).is_err() {
            return false;
        }
        let Some(doc) = self.docs.remove(uri) else {
            return false;
        };
        self.release_budget(&doc);
        true
    }

    pub fn snapshot(&self, uri: &str) -> Result<DocumentSnapshot, LspError> {
        validate_document_uri(uri)?;
        let Some(doc) = self.docs.get(uri) else {
            return Err(LspError::UnknownDocument {
                uri: uri.to_owned(),
            });
        };
        Ok(DocumentSnapshot {
            uri: uri.to_owned(),
            incarnation: doc.incarnation,
            version: doc.version,
        })
    }

    pub fn version(&self, uri: &str) -> Option<i32> {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return None;
        }
        self.docs.get(uri).map(|doc| doc.version)
    }

    pub fn diagnostics(&self, uri: &str) -> &[Value] {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return &[];
        }
        self.docs
            .get(uri)
            .map(|doc| doc.diagnostics.as_slice())
            .unwrap_or(&[])
    }

    pub fn diagnostic_provenance(&self, uri: &str) -> Option<&DiagnosticProvenance> {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return None;
        }
        self.docs.get(uri).and_then(|doc| doc.provenance.as_ref())
    }

    pub fn open_documents(&self) -> usize {
        self.docs.len()
    }

    pub fn diagnostic_bytes(&self) -> usize {
        self.diagnostic_bytes
    }

    pub fn diagnostic_nodes(&self) -> usize {
        self.diagnostic_nodes
    }

    pub fn stale_drops(&self) -> u64 {
        self.stale_drops
    }

    pub fn future_drops(&self) -> u64 {
        self.future_drops
    }

    pub fn prior_incarnation_drops(&self) -> u64 {
        self.prior_incarnation_drops
    }

    pub fn unversioned_accepts(&self) -> u64 {
        self.unversioned_accepts
    }

    pub fn unknown_drops(&self) -> u64 {
        self.unknown_drops
    }

    pub fn limit_rejections(&self) -> u64 {
        self.limit_rejections
    }

    /// Apply a diagnostics payload atomically against the snapshot at which it was observed.
    pub fn publish(
        &mut self,
        observed: &DocumentSnapshot,
        version: Option<i32>,
        diagnostics: Vec<Value>,
    ) -> Result<Publish, LspError> {
        validate_document_uri(&observed.uri)?;
        let Some(doc) = self.docs.get(&observed.uri) else {
            self.unknown_drops = self.unknown_drops.saturating_add(1);
            return Ok(Publish::Unknown);
        };
        if observed.incarnation != doc.incarnation {
            self.prior_incarnation_drops = self.prior_incarnation_drops.saturating_add(1);
            return Ok(Publish::PriorIncarnation {
                have: doc.incarnation,
                incoming: observed.incarnation,
            });
        }
        if observed.version < doc.version {
            self.stale_drops = self.stale_drops.saturating_add(1);
            return Ok(Publish::Stale {
                have: doc.version,
                incoming: observed.version,
            });
        }
        if observed.version > doc.version {
            self.future_drops = self.future_drops.saturating_add(1);
            return Ok(Publish::Future {
                have: doc.version,
                incoming: observed.version,
            });
        }
        let have = doc.version;
        let old_bytes = doc.diagnostic_bytes;
        let old_nodes = doc.diagnostic_nodes;
        match version {
            Some(incoming) if incoming < have => {
                self.stale_drops = self.stale_drops.saturating_add(1);
                return Ok(Publish::Stale { have, incoming });
            }
            Some(incoming) if incoming > have => {
                self.future_drops = self.future_drops.saturating_add(1);
                return Ok(Publish::Future { have, incoming });
            }
            Some(_) | None => {}
        }

        let (canonical, encoded_bytes, nodes) = match canonicalize_diagnostics(&diagnostics) {
            Ok(value) => value,
            Err(error) => {
                self.limit_rejections = self.limit_rejections.saturating_add(1);
                return Err(error);
            }
        };
        let projected = self
            .diagnostic_bytes
            .saturating_sub(old_bytes)
            .saturating_add(encoded_bytes);
        if projected > MAX_DIAGNOSTIC_BYTES_TOTAL {
            self.limit_rejections = self.limit_rejections.saturating_add(1);
            return Err(LspError::DiagnosticStoreFull {
                value: projected,
                limit: MAX_DIAGNOSTIC_BYTES_TOTAL,
            });
        }
        let projected_nodes = self
            .diagnostic_nodes
            .saturating_sub(old_nodes)
            .saturating_add(nodes);
        if projected_nodes > MAX_DIAGNOSTIC_JSON_NODES_TOTAL {
            self.limit_rejections = self.limit_rejections.saturating_add(1);
            return Err(LspError::DiagnosticNodeStoreFull {
                value: projected_nodes,
                limit: MAX_DIAGNOSTIC_JSON_NODES_TOTAL,
            });
        }

        let provenance = match version {
            Some(_) => DiagnosticProvenance::Versioned {
                snapshot: observed.clone(),
            },
            None => {
                let arrival = allocate_sequence(&mut self.next_arrival, "diagnostic arrival")?;
                self.unversioned_accepts = self.unversioned_accepts.saturating_add(1);
                DiagnosticProvenance::Unversioned {
                    snapshot: observed.clone(),
                    arrival,
                }
            }
        };
        let doc = self
            .docs
            .get_mut(&observed.uri)
            .expect("document cannot disappear during an exclusive borrow");
        doc.diagnostics = canonical;
        doc.provenance = Some(provenance.clone());
        doc.diagnostic_bytes = encoded_bytes;
        doc.diagnostic_nodes = nodes;
        self.diagnostic_bytes = projected;
        self.diagnostic_nodes = projected_nodes;
        Ok(Publish::Accepted(provenance))
    }

    fn release_budget(&mut self, doc: &Document) {
        self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(doc.diagnostic_bytes);
        self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(doc.diagnostic_nodes);
    }
}

fn allocate_sequence(sequence: &mut Option<u64>, kind: &'static str) -> Result<u64, LspError> {
    let Some(value) = *sequence else {
        return Err(LspError::SequenceExhausted { kind });
    };
    *sequence = value.checked_add(1);
    Ok(value)
}

pub(crate) fn validate_document_uri(uri: &str) -> Result<(), LspError> {
    if uri.len() > MAX_DOCUMENT_URI_BYTES {
        return Err(LspError::DocumentUriTooLong {
            value: uri.len(),
            limit: MAX_DOCUMENT_URI_BYTES,
        });
    }
    let Some((scheme, _)) = uri.split_once(':') else {
        return Err(LspError::InvalidDocumentUri);
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        || uri.chars().any(char::is_control)
    {
        return Err(LspError::InvalidDocumentUri);
    }
    Ok(())
}

/// Parse an LSP position under the protocol's signed 31-bit ceiling.
pub(crate) fn position_components(value: &Value) -> Option<(u32, u32)> {
    let object = value.as_object()?;
    let line = object.get("line")?.as_u64()?;
    let character = object.get("character")?.as_u64()?;
    if line > u64::from(MAX_LSP_POSITION) || character > u64::from(MAX_LSP_POSITION) {
        return None;
    }
    Some((line as u32, character as u32))
}

/// Parse an ordered LSP range.
pub(crate) fn range_components(value: &Value) -> Option<((u32, u32), (u32, u32))> {
    let object = value.as_object()?;
    let start = position_components(object.get("start")?)?;
    let end = position_components(object.get("end")?)?;
    (start <= end).then_some((start, end))
}

fn canonicalize_diagnostics(diagnostics: &[Value]) -> Result<(Vec<Value>, usize, usize), LspError> {
    if diagnostics.len() > MAX_DIAGNOSTICS_PER_DOCUMENT {
        return Err(LspError::DiagnosticsTooMany {
            value: diagnostics.len(),
            limit: MAX_DIAGNOSTICS_PER_DOCUMENT,
        });
    }
    for (index, diagnostic) in diagnostics.iter().enumerate() {
        validate_diagnostic(index, diagnostic)?;
    }
    let nodes = inspect_structure(diagnostics)?;

    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, diagnostics)
        .map_err(|error| LspError::Json(error.to_string()))?;
    if counter.bytes > MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT {
        return Err(LspError::DiagnosticsTooLarge {
            value: counter.bytes,
            limit: MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT,
        });
    }
    let bytes =
        serde_json::to_vec(diagnostics).map_err(|error| LspError::Json(error.to_string()))?;
    debug_assert_eq!(bytes.len(), counter.bytes);
    let canonical =
        serde_json::from_slice(&bytes).map_err(|error| LspError::Json(error.to_string()))?;
    Ok((canonical, bytes.len(), nodes))
}

fn validate_diagnostic(index: usize, value: &Value) -> Result<(), LspError> {
    let malformed = |reason| LspError::MalformedDiagnostic { index, reason };
    let object = value
        .as_object()
        .ok_or_else(|| malformed("diagnostic is not an object"))?;
    if object.get("range").and_then(range_components).is_none() {
        return Err(malformed("range is missing or invalid"));
    }
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("message is missing or not a string"))?;
    if message.len() > MAX_DIAGNOSTIC_MESSAGE_BYTES {
        return Err(malformed("message exceeds its byte limit"));
    }
    if let Some(severity) = object.get("severity")
        && !matches!(severity.as_u64(), Some(1..=4))
    {
        return Err(malformed("severity is not an integer in 1..=4"));
    }
    if let Some(code) = object.get("code") {
        let valid = match code {
            Value::String(code) => code.len() <= MAX_DIAGNOSTIC_CODE_BYTES,
            Value::Number(_) => code
                .as_i64()
                .is_some_and(|code| i64::from(i32::MIN) <= code && code <= i64::from(i32::MAX)),
            _ => false,
        };
        if !valid {
            return Err(malformed("code is not a bounded string or LSP integer"));
        }
    }
    if let Some(description) = object.get("codeDescription") {
        let href = description
            .as_object()
            .and_then(|description| description.get("href"))
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("codeDescription.href is missing or invalid"))?;
        validate_document_uri(href)
            .map_err(|_| malformed("codeDescription.href is not a bounded URI"))?;
    }
    if let Some(source) = object.get("source")
        && source
            .as_str()
            .is_none_or(|source| source.len() > MAX_DIAGNOSTIC_SOURCE_BYTES)
    {
        return Err(malformed("source is not a bounded string"));
    }
    if let Some(tags) = object.get("tags") {
        let tags = tags
            .as_array()
            .filter(|tags| tags.len() <= 2)
            .ok_or_else(|| malformed("tags is not a bounded array"))?;
        if tags.iter().any(|tag| !matches!(tag.as_u64(), Some(1 | 2))) {
            return Err(malformed("tag is not an allowed DiagnosticTag"));
        }
    }
    if let Some(related) = object.get("relatedInformation") {
        let related = related
            .as_array()
            .filter(|related| related.len() <= MAX_DIAGNOSTIC_RELATED_INFORMATION)
            .ok_or_else(|| malformed("relatedInformation is not a bounded array"))?;
        for information in related {
            validate_related_information(information).map_err(malformed)?;
        }
    }
    Ok(())
}

fn validate_related_information(value: &Value) -> Result<(), &'static str> {
    let object = value
        .as_object()
        .ok_or("related information is not an object")?;
    let location = object
        .get("location")
        .and_then(Value::as_object)
        .ok_or("related location is missing or invalid")?;
    let uri = location
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("related location URI is missing")?;
    validate_document_uri(uri).map_err(|_| "related location URI is invalid")?;
    if location.get("range").and_then(range_components).is_none() {
        return Err("related location range is missing or invalid");
    }
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .ok_or("related message is missing or invalid")?;
    if message.len() > MAX_DIAGNOSTIC_RELATED_MESSAGE_BYTES {
        return Err("related message exceeds its byte limit");
    }
    Ok(())
}

/// Reject pathological trees before serialization recurses through them.
fn inspect_structure(diagnostics: &[Value]) -> Result<usize, LspError> {
    let mut nodes = 1usize;
    let mut text_bytes = 0usize;
    let mut stack: Vec<(&Value, usize)> = Vec::with_capacity(diagnostics.len().min(256));
    if diagnostics.len() > MAX_DIAGNOSTIC_JSON_NODES.saturating_sub(nodes) {
        return Err(LspError::DiagnosticsTooComplex {
            limit: MAX_DIAGNOSTIC_JSON_NODES,
        });
    }
    stack.extend(diagnostics.iter().rev().map(|value| (value, 1)));

    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_DIAGNOSTIC_JSON_NODES {
            return Err(LspError::DiagnosticsTooComplex {
                limit: MAX_DIAGNOSTIC_JSON_NODES,
            });
        }
        if depth > MAX_DIAGNOSTIC_JSON_DEPTH {
            return Err(LspError::DiagnosticsTooDeep {
                value: depth,
                limit: MAX_DIAGNOSTIC_JSON_DEPTH,
            });
        }
        let children = match value {
            Value::String(text) => {
                text_bytes = text_bytes.saturating_add(text.len());
                0
            }
            Value::Array(values) => values.len(),
            Value::Object(values) => {
                for key in values.keys() {
                    text_bytes = text_bytes.saturating_add(key.len());
                }
                values.len()
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        };
        if text_bytes > MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT {
            return Err(LspError::DiagnosticsTooLarge {
                value: text_bytes,
                limit: MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT,
            });
        }
        if children > MAX_DIAGNOSTIC_JSON_NODES.saturating_sub(nodes + stack.len()) {
            return Err(LspError::DiagnosticsTooComplex {
                limit: MAX_DIAGNOSTIC_JSON_NODES,
            });
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().rev().map(|child| (child, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().rev().map(|child| (child, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(nodes)
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "documents_tests.rs"]
mod tests;
