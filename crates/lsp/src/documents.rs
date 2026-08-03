//! Document wire versions, synchronization state, and bounded diagnostic retention.
//!
//! LSP diagnostics carry only a URI and an optional client-assigned document version. This store
//! owns a monotonic, never-reused wire-version sequence for one server generation. Close/reopen
//! never recycles an old number, so delayed versioned notifications are stale using only fields
//! that actually existed on the wire. Versionless diagnostics remain visible but are explicitly
//! freshness-unknown and cannot cross the actionable-diagnostics gate.

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

/// Complete identity of text against which a positional request was issued.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocumentSnapshot {
    pub uri: String,
    pub server_generation: u64,
    pub incarnation: u64,
    pub source_revision: i32,
    pub wire_version: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentState {
    Synced,
    Desynchronized,
}

/// Outcome of a local revision presented for `didChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A strictly greater source revision received a fresh global wire version.
    Accepted(DocumentSnapshot),
    /// Equal/lower source revisions are ambiguous. Results were cleared and an explicit full-text
    /// resync is required before this document can accept diagnostics again.
    Desynchronized {
        have: i32,
        incoming: i32,
    },
    NeedsResync,
    Unknown,
}

/// Freshness evidence derived only from real wire fields plus the owning server generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticFreshness {
    Exact {
        server_generation: u64,
        wire_version: i32,
    },
    Unknown {
        server_generation: u64,
        wire_version_at_arrival: i32,
        arrival: u64,
    },
}

/// A diagnostics payload cannot be detached from its freshness evidence.
#[derive(Debug, Clone)]
pub struct DiagnosticSet {
    diagnostics: Vec<Value>,
    freshness: DiagnosticFreshness,
    encoded_bytes: usize,
    nodes: usize,
}

impl DiagnosticSet {
    pub fn diagnostics(&self) -> &[Value] {
        &self.diagnostics
    }

    pub fn freshness(&self) -> &DiagnosticFreshness {
        &self.freshness
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publish {
    Accepted(DiagnosticFreshness),
    Stale { have: i32, incoming: i32 },
    Future { have: i32, incoming: i32 },
    Desynchronized,
    Unknown,
}

#[derive(Debug, Clone)]
struct Document {
    source_revision: i32,
    wire_version: i32,
    incarnation: u64,
    state: DocumentState,
    diagnostic_set: Option<DiagnosticSet>,
}

/// Tracks documents for exactly one supervised language-server generation.
#[derive(Debug, Clone)]
pub struct DocumentStore {
    server_generation: u64,
    docs: HashMap<String, Document>,
    next_incarnation: Option<u64>,
    next_wire_version: Option<i32>,
    next_arrival: Option<u64>,
    diagnostic_bytes: usize,
    diagnostic_nodes: usize,
    stale_drops: u64,
    future_drops: u64,
    desynchronized_drops: u64,
    unversioned_accepts: u64,
    unknown_drops: u64,
    limit_rejections: u64,
}

impl DocumentStore {
    pub fn new(server_generation: u64) -> Self {
        Self {
            server_generation,
            docs: HashMap::new(),
            next_incarnation: Some(1),
            next_wire_version: Some(1),
            next_arrival: Some(1),
            diagnostic_bytes: 0,
            diagnostic_nodes: 0,
            stale_drops: 0,
            future_drops: 0,
            desynchronized_drops: 0,
            unversioned_accepts: 0,
            unknown_drops: 0,
            limit_rejections: 0,
        }
    }

    pub fn server_generation(&self) -> u64 {
        self.server_generation
    }

    /// Begin a new open lifetime and allocate the version that must be sent in `didOpen`.
    pub fn open(&mut self, uri: &str, source_revision: i32) -> Result<DocumentSnapshot, LspError> {
        validate_document_uri(uri)?;
        if !self.docs.contains_key(uri) && self.docs.len() >= MAX_OPEN_DOCUMENTS {
            self.limit_rejections = self.limit_rejections.saturating_add(1);
            return Err(LspError::DocumentLimit {
                limit: MAX_OPEN_DOCUMENTS,
            });
        }
        let replacing = self.docs.contains_key(uri);
        let incarnation =
            match allocate_sequence(&mut self.next_incarnation, "document incarnation") {
                Ok(incarnation) => incarnation,
                Err(error) => {
                    if replacing {
                        self.mark_desynchronized(uri);
                    }
                    return Err(error);
                }
            };
        let wire_version = match allocate_wire_version(&mut self.next_wire_version) {
            Ok(wire_version) => wire_version,
            Err(error) => {
                if replacing {
                    self.mark_desynchronized(uri);
                }
                return Err(error);
            }
        };
        if let Some(previous) = self.docs.remove(uri) {
            self.release_budget(&previous);
        }
        self.docs.insert(
            uri.to_owned(),
            Document {
                source_revision,
                wire_version,
                incarnation,
                state: DocumentState::Synced,
                diagnostic_set: None,
            },
        );
        Ok(self.snapshot_unchecked(uri))
    }

    /// Record a local edit and allocate its `didChange` wire version.
    pub fn change(&mut self, uri: &str, source_revision: i32) -> Result<Change, LspError> {
        validate_document_uri(uri)?;
        let Some(current) = self.docs.get(uri) else {
            return Ok(Change::Unknown);
        };
        if current.state == DocumentState::Desynchronized {
            return Ok(Change::NeedsResync);
        }
        let have = current.source_revision;
        if source_revision <= have {
            let incarnation = allocate_sequence(&mut self.next_incarnation, "document incarnation");
            self.mark_desynchronized(uri);
            let incarnation = incarnation?;
            self.docs
                .get_mut(uri)
                .expect("document cannot disappear during an exclusive borrow")
                .incarnation = incarnation;
            return Ok(Change::Desynchronized {
                have,
                incoming: source_revision,
            });
        }
        let wire_version = match allocate_wire_version(&mut self.next_wire_version) {
            Ok(wire_version) => wire_version,
            Err(error) => {
                self.mark_desynchronized(uri);
                return Err(error);
            }
        };
        self.clear_document_diagnostics(uri);
        let doc = self
            .docs
            .get_mut(uri)
            .expect("document cannot disappear during an exclusive borrow");
        doc.source_revision = source_revision;
        doc.wire_version = wire_version;
        Ok(Change::Accepted(self.snapshot_unchecked(uri)))
    }

    /// Restore synchronization after sending full text with the returned wire version.
    pub fn resync(
        &mut self,
        uri: &str,
        source_revision: i32,
    ) -> Result<DocumentSnapshot, LspError> {
        validate_document_uri(uri)?;
        if !self.docs.contains_key(uri) {
            return Err(LspError::UnknownDocument {
                uri: uri.to_owned(),
            });
        }
        let incarnation =
            match allocate_sequence(&mut self.next_incarnation, "document incarnation") {
                Ok(incarnation) => incarnation,
                Err(error) => {
                    self.mark_desynchronized(uri);
                    return Err(error);
                }
            };
        let wire_version = match allocate_wire_version(&mut self.next_wire_version) {
            Ok(wire_version) => wire_version,
            Err(error) => {
                self.mark_desynchronized(uri);
                return Err(error);
            }
        };
        self.clear_document_diagnostics(uri);
        let doc = self
            .docs
            .get_mut(uri)
            .expect("document cannot disappear during an exclusive borrow");
        doc.source_revision = source_revision;
        doc.wire_version = wire_version;
        doc.incarnation = incarnation;
        doc.state = DocumentState::Synced;
        Ok(self.snapshot_unchecked(uri))
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
        if doc.state == DocumentState::Desynchronized {
            return Err(LspError::DocumentDesynchronized {
                uri: uri.to_owned(),
            });
        }
        Ok(self.snapshot_unchecked(uri))
    }

    pub fn wire_version(&self, uri: &str) -> Option<i32> {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return None;
        }
        self.docs.get(uri).map(|doc| doc.wire_version)
    }

    pub fn state(&self, uri: &str) -> Option<DocumentState> {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return None;
        }
        self.docs.get(uri).map(|doc| doc.state)
    }

    pub fn diagnostic_set(&self, uri: &str) -> Option<&DiagnosticSet> {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return None;
        }
        self.docs
            .get(uri)
            .and_then(|doc| doc.diagnostic_set.as_ref())
    }

    /// The only API intended for navigation/edit/automation decisions.
    pub fn actionable_diagnostics(&self, uri: &str) -> Result<&[Value], LspError> {
        validate_document_uri(uri)?;
        let Some(doc) = self.docs.get(uri) else {
            return Err(LspError::UnknownDocument {
                uri: uri.to_owned(),
            });
        };
        if doc.state == DocumentState::Desynchronized {
            return Err(LspError::DocumentDesynchronized {
                uri: uri.to_owned(),
            });
        }
        let Some(set) = doc.diagnostic_set.as_ref() else {
            return Ok(&[]);
        };
        match set.freshness {
            DiagnosticFreshness::Exact {
                server_generation,
                wire_version,
            } if server_generation == self.server_generation
                && wire_version == doc.wire_version =>
            {
                Ok(&set.diagnostics)
            }
            DiagnosticFreshness::Exact { .. } | DiagnosticFreshness::Unknown { .. } => {
                Err(LspError::DiagnosticsNotActionable {
                    uri: uri.to_owned(),
                })
            }
        }
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

    pub fn desynchronized_drops(&self) -> u64 {
        self.desynchronized_drops
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

    /// Apply the actual wire fields from `textDocument/publishDiagnostics` atomically.
    pub fn publish(
        &mut self,
        uri: &str,
        version: Option<i32>,
        diagnostics: Vec<Value>,
    ) -> Result<Publish, LspError> {
        validate_document_uri(uri)?;
        let Some(doc) = self.docs.get(uri) else {
            self.unknown_drops = self.unknown_drops.saturating_add(1);
            return Ok(Publish::Unknown);
        };
        if doc.state == DocumentState::Desynchronized {
            self.desynchronized_drops = self.desynchronized_drops.saturating_add(1);
            return Ok(Publish::Desynchronized);
        }
        let have = doc.wire_version;
        let (old_bytes, old_nodes) = doc
            .diagnostic_set
            .as_ref()
            .map_or((0, 0), |set| (set.encoded_bytes, set.nodes));
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

        let freshness = match version {
            Some(_) => DiagnosticFreshness::Exact {
                server_generation: self.server_generation,
                wire_version: have,
            },
            None => {
                let arrival = allocate_sequence(&mut self.next_arrival, "diagnostic arrival")?;
                self.unversioned_accepts = self.unversioned_accepts.saturating_add(1);
                DiagnosticFreshness::Unknown {
                    server_generation: self.server_generation,
                    wire_version_at_arrival: have,
                    arrival,
                }
            }
        };
        let doc = self
            .docs
            .get_mut(uri)
            .expect("document cannot disappear during an exclusive borrow");
        doc.diagnostic_set = Some(DiagnosticSet {
            diagnostics: canonical,
            freshness: freshness.clone(),
            encoded_bytes,
            nodes,
        });
        self.diagnostic_bytes = projected;
        self.diagnostic_nodes = projected_nodes;
        Ok(Publish::Accepted(freshness))
    }

    fn release_budget(&mut self, doc: &Document) {
        if let Some(set) = doc.diagnostic_set.as_ref() {
            self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(set.encoded_bytes);
            self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(set.nodes);
        }
    }

    fn clear_document_diagnostics(&mut self, uri: &str) {
        let doc = self
            .docs
            .get_mut(uri)
            .expect("clearing diagnostics requires an open document");
        if let Some(set) = doc.diagnostic_set.take() {
            self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(set.encoded_bytes);
            self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(set.nodes);
        }
    }

    fn mark_desynchronized(&mut self, uri: &str) {
        self.clear_document_diagnostics(uri);
        self.docs
            .get_mut(uri)
            .expect("desynchronization requires an open document")
            .state = DocumentState::Desynchronized;
    }

    fn snapshot_unchecked(&self, uri: &str) -> DocumentSnapshot {
        let doc = self
            .docs
            .get(uri)
            .expect("snapshot construction requires an open document");
        DocumentSnapshot {
            uri: uri.to_owned(),
            server_generation: self.server_generation,
            incarnation: doc.incarnation,
            source_revision: doc.source_revision,
            wire_version: doc.wire_version,
        }
    }
}

fn allocate_sequence(sequence: &mut Option<u64>, kind: &'static str) -> Result<u64, LspError> {
    let Some(value) = *sequence else {
        return Err(LspError::SequenceExhausted { kind });
    };
    *sequence = value.checked_add(1);
    Ok(value)
}

fn allocate_wire_version(sequence: &mut Option<i32>) -> Result<i32, LspError> {
    let Some(value) = *sequence else {
        return Err(LspError::SequenceExhausted {
            kind: "wire document version",
        });
    };
    *sequence = if value < i32::MAX {
        Some(value + 1)
    } else {
        None
    };
    Ok(value)
}

pub(crate) fn validate_document_uri(uri: &str) -> Result<(), LspError> {
    if uri.len() > MAX_DOCUMENT_URI_BYTES {
        return Err(LspError::DocumentUriTooLong {
            value: uri.len(),
            limit: MAX_DOCUMENT_URI_BYTES,
        });
    }
    if !uri.is_ascii() {
        return Err(LspError::InvalidDocumentUri);
    }
    let Some((scheme, remainder)) = uri.split_once(':') else {
        return Err(LspError::InvalidDocumentUri);
    };
    if remainder.bytes().filter(|byte| *byte == b'#').count() > 1 {
        return Err(LspError::InvalidDocumentUri);
    }
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(LspError::InvalidDocumentUri);
    }
    let bytes = remainder.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(LspError::InvalidDocumentUri);
            }
            index += 3;
            continue;
        }
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        let reserved = matches!(
            byte,
            b':' | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        );
        if !unreserved && !reserved {
            return Err(LspError::InvalidDocumentUri);
        }
        index += 1;
    }
    url::Url::parse(uri).map_err(|_| LspError::InvalidDocumentUri)?;
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
