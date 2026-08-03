//! Document versions and the staleness rule for diagnostics.
//!
//! Diagnostics are asynchronous: the agent edits a file, and the server publishes results computed
//! against whatever text it had when it started analysing. Those two orders are unrelated, so
//! without a version check the agent will read line/column positions that refer to text that no
//! longer exists and "fix" the wrong line. Every publish is therefore matched against the version
//! the document is currently at, and anything older is dropped and counted.

use std::collections::HashMap;

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
    diagnostics: Vec<serde_json::Value>,
}

/// Tracks open documents and the newest diagnostics that are not stale.
#[derive(Debug, Clone, Default)]
pub struct DocumentStore {
    docs: HashMap<String, Document>,
    next_incarnation: u64,
    stale_drops: u64,
    unknown_drops: u64,
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

    pub fn diagnostics(&self, uri: &str) -> &[serde_json::Value] {
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
        doc.diagnostics = diagnostics;
        Publish::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn diag(msg: &str) -> serde_json::Value {
        json!({ "message": msg })
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
