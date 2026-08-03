//! Document versions and the staleness rule for diagnostics.
//!
//! Diagnostics are asynchronous: the agent edits a file, and the server publishes results computed
//! against whatever text it had when it started analysing. Those two orders are unrelated, so
//! without a version check the agent will read line/column positions that refer to text that no
//! longer exists and "fix" the wrong line. Every publish is therefore matched against the version
//! the document is currently at, and anything older is dropped and counted.

use crate::intel::Range;
use std::collections::HashMap;

/// Diagnostics kept per document. A server in a broken state can publish a diagnostic per token;
/// storing them all turns a syntax error into unbounded memory held for the life of the session.
pub const MAX_DIAGNOSTICS_PER_DOC: usize = 1_000;

/// Longest diagnostic message retained.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;

/// A validated diagnostic.
///
/// Stored typed rather than as raw JSON. An opaque `Value` means no caller can rely on a range or
/// a message being present, so every consumer re-validates or -- more often -- does not, and reads
/// `null` as a position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub range: Range,
    pub message: String,
    pub severity: Option<u8>,
    pub source: Option<String>,
}

impl Diagnostic {
    /// Validate one payload. Returns `None` when the entry lacks a usable range or message, which
    /// is counted by the caller rather than silently skipped.
    pub fn parse(value: &serde_json::Value) -> Option<Self> {
        let range = crate::intel::range_of(value.get("range")?)?;
        let message = value.get("message")?.as_str()?;
        if message.is_empty() {
            return None;
        }
        let mut message = message.to_owned();
        if message.len() > MAX_MESSAGE_BYTES {
            let mut end = MAX_MESSAGE_BYTES;
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
            message.push_str("[truncated]");
        }
        Some(Diagnostic {
            range,
            message,
            severity: value
                .get("severity")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u8::try_from(n).ok())
                .filter(|n| (1..=4).contains(n)),
            source: value
                .get("source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }
}

/// What happened to a `publishDiagnostics` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publish {
    /// Stored; it describes the current text.
    Accepted,
    /// Dropped: computed against text the agent has already replaced.
    Stale { have: i32, incoming: i32 },
    /// Dropped: the agent is not tracking this document.
    Unknown,
}

#[derive(Debug, Clone, Default)]
struct Document {
    version: i32,
    /// Bumped on every open. Version numbers restart when an editor reopens a file, so `(uri,
    /// version)` alone cannot distinguish "version 1 of the file I have now" from "version 1 of
    /// the file I closed a minute ago" -- and a diagnostic from the previous incarnation would
    /// match on both fields and be accepted as current.
    incarnation: u64,
    diagnostics: Vec<Diagnostic>,
}

/// Tracks open documents and the newest diagnostics that are not stale.
#[derive(Debug, Clone, Default)]
pub struct DocumentStore {
    docs: HashMap<String, Document>,
    next_incarnation: u64,
    stale_drops: u64,
    unknown_drops: u64,
    invalid_drops: u64,
    overflow_drops: u64,
}

impl DocumentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin tracking a document. Re-opening resets it: the server is told the text afresh, so any
    /// diagnostics held from the previous incarnation describe text that is no longer authoritative.
    pub fn open(&mut self, uri: impl Into<String>, version: i32) -> u64 {
        self.next_incarnation += 1;
        let incarnation = self.next_incarnation;
        self.docs.insert(
            uri.into(),
            Document {
                version,
                incarnation,
                diagnostics: Vec::new(),
            },
        );
        incarnation
    }

    /// The token identifying the *current* incarnation of a document, if it is open.
    ///
    /// A caller that issued a request against a document should carry this alongside the version
    /// and present it when the answer arrives; see [`publish_for`].
    pub fn incarnation(&self, uri: &str) -> Option<u64> {
        self.docs.get(uri).map(|d| d.incarnation)
    }

    /// Apply a publish that names the incarnation it was computed against.
    ///
    /// Rejects anything from a previous incarnation even when the version matches, which is the
    /// case plain version comparison cannot see: close a file, reopen it, and the editor's version
    /// numbering starts again from the beginning.
    pub fn publish_for(
        &mut self,
        uri: &str,
        incarnation: u64,
        version: Option<i32>,
        diagnostics: Vec<serde_json::Value>,
    ) -> Publish {
        match self.docs.get(uri) {
            Some(doc) if doc.incarnation != incarnation => {
                self.stale_drops += 1;
                Publish::Stale {
                    have: doc.version,
                    incoming: version.unwrap_or(doc.version),
                }
            }
            Some(_) => self.publish(uri, version, diagnostics),
            None => {
                self.unknown_drops += 1;
                Publish::Unknown
            }
        }
    }

    /// Record an edit.
    ///
    /// Diagnostics held for the old version are cleared immediately rather than left visible until
    /// the server republishes. Showing a stale error against edited text is worse than showing
    /// none, because the agent cannot tell that it is stale.
    pub fn change(&mut self, uri: &str, version: i32) -> bool {
        let Some(doc) = self.docs.get_mut(uri) else {
            return false;
        };
        // Version numbers are monotonic per the spec; a regression means a confused server, and
        // accepting it would let an old edit win over a new one.
        if version < doc.version {
            return false;
        }
        doc.version = version;
        doc.diagnostics.clear();
        true
    }

    pub fn close(&mut self, uri: &str) -> bool {
        self.docs.remove(uri).is_some()
    }

    pub fn version(&self, uri: &str) -> Option<i32> {
        self.docs.get(uri).map(|d| d.version)
    }

    /// Diagnostics discarded because they carried no usable range or message.
    pub fn invalid_drops(&self) -> u64 {
        self.invalid_drops
    }

    /// Diagnostics discarded because the document was already at its retention ceiling.
    pub fn overflow_drops(&self) -> u64 {
        self.overflow_drops
    }

    pub fn diagnostics(&self, uri: &str) -> &[Diagnostic] {
        self.docs
            .get(uri)
            .map(|d| d.diagnostics.as_slice())
            .unwrap_or(&[])
    }

    /// Number of publishes discarded because they were computed against superseded text.
    pub fn stale_drops(&self) -> u64 {
        self.stale_drops
    }

    /// Number of publishes discarded because they named a document we do not track.
    pub fn unknown_drops(&self) -> u64 {
        self.unknown_drops
    }

    /// Apply a `textDocument/publishDiagnostics` payload.
    ///
    /// `version` is optional in the protocol. When absent the payload is accepted, because a
    /// server that never versions its publishes would otherwise be silently useless -- but the
    /// moment a server does send versions, the stale rule applies strictly.
    pub fn publish(
        &mut self,
        uri: &str,
        version: Option<i32>,
        diagnostics: Vec<serde_json::Value>,
    ) -> Publish {
        let Some(doc) = self.docs.get_mut(uri) else {
            self.unknown_drops += 1;
            return Publish::Unknown;
        };
        if let Some(incoming) = version
            && incoming < doc.version
        {
            self.stale_drops += 1;
            return Publish::Stale {
                have: doc.version,
                incoming,
            };
        }

        // Validated on the way in. One malformed entry does not discard the publish -- a server
        // with a bug in one diagnostic still has useful ones -- but the loss is counted, and a
        // caller reading `diagnostics()` can rely on every entry having a range and a message.
        let mut kept = Vec::new();
        let (mut invalid, mut overflow) = (0u64, 0u64);
        for raw in &diagnostics {
            match Diagnostic::parse(raw) {
                Some(_) if kept.len() >= MAX_DIAGNOSTICS_PER_DOC => overflow += 1,
                Some(d) => kept.push(d),
                None => invalid += 1,
            }
        }
        self.invalid_drops += invalid;
        self.overflow_drops += overflow;
        doc.diagnostics = kept;
        Publish::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn diag(msg: &str) -> serde_json::Value {
        json!({
            "message": msg,
            "range": { "start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1} }
        })
    }

    #[test]
    fn diagnostics_for_superseded_text_are_dropped_and_counted() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        store.change("file:///a.rs", 2);

        let outcome = store.publish("file:///a.rs", Some(1), vec![diag("old")]);
        assert_eq!(
            outcome,
            Publish::Stale {
                have: 2,
                incoming: 1
            }
        );
        assert!(store.diagnostics("file:///a.rs").is_empty());
        assert_eq!(store.stale_drops(), 1);
    }

    #[test]
    fn diagnostics_for_the_current_version_are_kept() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 7);
        assert_eq!(
            store.publish("file:///a.rs", Some(7), vec![diag("current")]),
            Publish::Accepted
        );
        assert_eq!(store.diagnostics("file:///a.rs").len(), 1);
        assert_eq!(store.stale_drops(), 0);
    }

    #[test]
    fn an_edit_clears_diagnostics_rather_than_leaving_them_visible() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        store.publish("file:///a.rs", Some(1), vec![diag("e")]);
        assert_eq!(store.diagnostics("file:///a.rs").len(), 1);

        store.change("file:///a.rs", 2);
        assert!(
            store.diagnostics("file:///a.rs").is_empty(),
            "stale diagnostics must not survive the edit that invalidated them"
        );
    }

    #[test]
    fn unversioned_publishes_are_accepted() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 3);
        assert_eq!(
            store.publish("file:///a.rs", None, vec![diag("x")]),
            Publish::Accepted
        );
    }

    #[test]
    fn publishes_for_untracked_documents_are_dropped_and_counted() {
        let mut store = DocumentStore::new();
        assert_eq!(
            store.publish("file:///gone.rs", Some(1), vec![diag("x")]),
            Publish::Unknown
        );
        assert_eq!(store.unknown_drops(), 1);
    }

    #[test]
    fn a_diagnostic_without_a_range_or_message_is_dropped_and_counted() {
        // Stored opaquely, every consumer either re-validates or reads `null` as a position.
        // One bad entry does not discard the publish -- a server with one buggy diagnostic still
        // has useful ones -- but the loss is counted rather than silent.
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        let outcome = store.publish(
            "file:///a.rs",
            Some(1),
            vec![
                diag("good"),
                json!({ "message": "no range" }),
                json!({ "range": { "start": {"line":0,"character":0}, "end": {"line":0,"character":1} } }),
            ],
        );
        assert_eq!(outcome, Publish::Accepted);
        assert_eq!(store.diagnostics("file:///a.rs").len(), 1);
        assert_eq!(store.invalid_drops(), 2);
        assert_eq!(store.diagnostics("file:///a.rs")[0].message, "good");
    }

    #[test]
    fn diagnostics_are_bounded_per_document_and_the_excess_is_counted() {
        // A server in a broken state can publish one per token; keeping them all turns a syntax
        // error into unbounded memory held for the life of the session.
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        let many: Vec<_> = (0..MAX_DIAGNOSTICS_PER_DOC + 25)
            .map(|i| diag(&format!("d{i}")))
            .collect();
        store.publish("file:///a.rs", Some(1), many);
        assert_eq!(
            store.diagnostics("file:///a.rs").len(),
            MAX_DIAGNOSTICS_PER_DOC
        );
        assert_eq!(store.overflow_drops(), 25);
    }

    #[test]
    fn an_invalid_severity_is_dropped_rather_than_passed_through() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        let mut d = diag("x");
        d["severity"] = json!(99);
        store.publish("file:///a.rs", Some(1), vec![d]);
        assert_eq!(store.diagnostics("file:///a.rs")[0].severity, None);
    }

    #[test]
    fn a_version_regression_is_refused() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 5);
        assert!(!store.change("file:///a.rs", 4));
        assert_eq!(store.version("file:///a.rs"), Some(5));
    }

    #[test]
    fn closing_stops_tracking_and_later_publishes_are_unknown() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 1);
        assert!(store.close("file:///a.rs"));
        assert!(!store.close("file:///a.rs"));
        assert_eq!(
            store.publish("file:///a.rs", Some(1), vec![diag("x")]),
            Publish::Unknown
        );
    }

    #[test]
    fn a_diagnostic_from_a_previous_incarnation_is_refused_even_at_a_matching_version() {
        // The case plain version comparison cannot see: an editor's version numbering restarts on
        // reopen, so (uri, version=1) is ambiguous between the file open now and the one closed a
        // moment ago. Without an incarnation token the stale publish looks perfectly current.
        let mut store = DocumentStore::new();
        let first = store.open("file:///a.rs", 1);
        store.close("file:///a.rs");
        let second = store.open("file:///a.rs", 1);
        assert_ne!(first, second, "each open is a distinct incarnation");

        let outcome = store.publish_for("file:///a.rs", first, Some(1), vec![diag("ghost")]);
        assert!(matches!(outcome, Publish::Stale { .. }), "{outcome:?}");
        assert!(store.diagnostics("file:///a.rs").is_empty());
        assert_eq!(store.stale_drops(), 1);

        // The current incarnation is accepted at the same version.
        assert_eq!(
            store.publish_for("file:///a.rs", second, Some(1), vec![diag("real")]),
            Publish::Accepted
        );
        assert_eq!(store.diagnostics("file:///a.rs").len(), 1);
    }

    #[test]
    fn an_incarnation_publish_for_an_unopened_document_is_unknown() {
        let mut store = DocumentStore::new();
        assert_eq!(
            store.publish_for("file:///gone.rs", 1, Some(1), vec![diag("x")]),
            Publish::Unknown
        );
    }

    #[test]
    fn reopening_discards_the_previous_incarnations_diagnostics() {
        let mut store = DocumentStore::new();
        store.open("file:///a.rs", 9);
        store.publish("file:///a.rs", Some(9), vec![diag("stale")]);
        store.open("file:///a.rs", 1);
        assert!(store.diagnostics("file:///a.rs").is_empty());
        assert_eq!(store.version("file:///a.rs"), Some(1));
    }
}
