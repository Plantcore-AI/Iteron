//! Document versions and bounded diagnostic retention.
//!
//! Diagnostics are asynchronous: the agent edits a file, and the server publishes results computed
//! against whatever text it had when it started analysing. A publish is retained only when its
//! version exactly matches the current document. Unversioned results fail closed because the agent
//! cannot prove their positions refer to the current text.

use crate::{
    LspError, MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT, MAX_DIAGNOSTIC_BYTES_TOTAL,
    MAX_DIAGNOSTIC_JSON_DEPTH, MAX_DIAGNOSTIC_JSON_NODES, MAX_DIAGNOSTIC_JSON_NODES_TOTAL,
    MAX_DIAGNOSTICS_PER_DOCUMENT, MAX_DOCUMENT_URI_BYTES, MAX_OPEN_DOCUMENTS,
};
use serde_json::Value;
use std::{collections::HashMap, io::Write};

/// What happened to a `publishDiagnostics` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publish {
    /// Stored; it describes the current text.
    Accepted,
    /// Dropped: computed against text the agent has already replaced.
    Stale { have: i32, incoming: i32 },
    /// Dropped: claims a version the client has not opened or produced.
    Future { have: i32, incoming: i32 },
    /// Dropped: no version means freshness cannot be established.
    Unversioned { have: i32 },
    /// Dropped: the agent is not tracking this document.
    Unknown,
}

#[derive(Debug, Clone, Default)]
struct Document {
    version: i32,
    diagnostics: Vec<Value>,
    diagnostic_bytes: usize,
    diagnostic_nodes: usize,
}

/// Tracks open documents and the newest diagnostics that are provably current.
#[derive(Debug, Clone, Default)]
pub struct DocumentStore {
    docs: HashMap<String, Document>,
    diagnostic_bytes: usize,
    diagnostic_nodes: usize,
    stale_drops: u64,
    future_drops: u64,
    unversioned_drops: u64,
    unknown_drops: u64,
    limit_rejections: u64,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin tracking a bounded URI. Re-opening replaces its incarnation and releases any retained
    /// diagnostic budget before installing the new version.
    pub fn open(&mut self, uri: &str, version: i32) -> Result<(), LspError> {
        validate_uri(uri)?;
        if !self.docs.contains_key(uri) && self.docs.len() >= MAX_OPEN_DOCUMENTS {
            self.limit_rejections = self.limit_rejections.saturating_add(1);
            return Err(LspError::DocumentLimit {
                limit: MAX_OPEN_DOCUMENTS,
            });
        }

        if let Some(previous) = self.docs.remove(uri) {
            self.diagnostic_bytes = self
                .diagnostic_bytes
                .saturating_sub(previous.diagnostic_bytes);
            self.diagnostic_nodes = self
                .diagnostic_nodes
                .saturating_sub(previous.diagnostic_nodes);
        }
        self.docs.insert(
            uri.to_owned(),
            Document {
                version,
                diagnostics: Vec::new(),
                diagnostic_bytes: 0,
                diagnostic_nodes: 0,
            },
        );
        Ok(())
    }

    /// Record an edit. A version regression is refused; every accepted edit clears results for the
    /// old text and immediately returns their bytes to the global budget.
    pub fn change(&mut self, uri: &str, version: i32) -> Result<bool, LspError> {
        validate_uri(uri)?;
        let Some(doc) = self.docs.get_mut(uri) else {
            return Ok(false);
        };
        if version < doc.version {
            return Ok(false);
        }
        self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(doc.diagnostic_bytes);
        self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(doc.diagnostic_nodes);
        doc.version = version;
        doc.diagnostics.clear();
        doc.diagnostic_bytes = 0;
        doc.diagnostic_nodes = 0;
        Ok(true)
    }

    pub fn close(&mut self, uri: &str) -> bool {
        if uri.len() > MAX_DOCUMENT_URI_BYTES {
            return false;
        }
        let Some(doc) = self.docs.remove(uri) else {
            return false;
        };
        self.diagnostic_bytes = self.diagnostic_bytes.saturating_sub(doc.diagnostic_bytes);
        self.diagnostic_nodes = self.diagnostic_nodes.saturating_sub(doc.diagnostic_nodes);
        true
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

    pub fn unversioned_drops(&self) -> u64 {
        self.unversioned_drops
    }

    pub fn unknown_drops(&self) -> u64 {
        self.unknown_drops
    }

    pub fn limit_rejections(&self) -> u64 {
        self.limit_rejections
    }

    /// Apply a `textDocument/publishDiagnostics` payload atomically.
    ///
    /// Count, structure, per-document bytes and cross-document bytes are checked before replacing
    /// the previous payload. Accepted JSON is serialized and parsed once into a canonical bounded
    /// allocation; this prevents a caller-created `String`/`Vec` with tiny length but huge spare
    /// capacity from becoming retained store memory.
    pub fn publish(
        &mut self,
        uri: &str,
        version: Option<i32>,
        diagnostics: Vec<Value>,
    ) -> Result<Publish, LspError> {
        validate_uri(uri)?;
        let Some(doc) = self.docs.get(uri) else {
            self.unknown_drops = self.unknown_drops.saturating_add(1);
            return Ok(Publish::Unknown);
        };

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
            None => {
                self.unversioned_drops = self.unversioned_drops.saturating_add(1);
                return Ok(Publish::Unversioned { have });
            }
            Some(_) => {}
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

        let doc = self
            .docs
            .get_mut(uri)
            .expect("document cannot disappear during an exclusive borrow");
        doc.diagnostics = canonical;
        doc.diagnostic_bytes = encoded_bytes;
        doc.diagnostic_nodes = nodes;
        self.diagnostic_bytes = projected;
        self.diagnostic_nodes = projected_nodes;
        Ok(Publish::Accepted)
    }
}

fn validate_uri(uri: &str) -> Result<(), LspError> {
    if uri.len() > MAX_DOCUMENT_URI_BYTES {
        return Err(LspError::DocumentUriTooLong {
            value: uri.len(),
            limit: MAX_DOCUMENT_URI_BYTES,
        });
    }
    Ok(())
}

fn canonicalize_diagnostics(diagnostics: &[Value]) -> Result<(Vec<Value>, usize, usize), LspError> {
    if diagnostics.len() > MAX_DIAGNOSTICS_PER_DOCUMENT {
        return Err(LspError::DiagnosticsTooMany {
            value: diagnostics.len(),
            limit: MAX_DIAGNOSTICS_PER_DOCUMENT,
        });
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

/// Reject pathological trees before serialization recurses through them. `stack` itself is bounded
/// by the same node limit, and direct child counts are checked before they are pushed.
fn inspect_structure(diagnostics: &[Value]) -> Result<usize, LspError> {
    let mut nodes = 1usize; // the top-level diagnostics array
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
