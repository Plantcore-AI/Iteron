//! Content-addressed memoization of PURE tool results (ADR-004: SOUND for pure tools keyed on
//! ALL determining inputs; a correctness bug for non-hermetic tools). The key is the honest
//! part: a `read_file` is keyed on (path, file-content-hash) so a stale cache can never serve an
//! edited file; a `grep` on (pattern, subtree-content-digest). If the determining inputs cannot
//! be captured, the tool is not memoized — silence over a wrong answer.
//!
//! This is the DB "spill/cache" transfer (ADR-003) done with the correctness precondition
//! (purity) stated, not assumed.

use core_protocol::ToolResult;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// A memo keyed by a caller-computed digest of all determining inputs. The caller is
/// responsible for including EVERY input that affects the result (that responsibility is the
/// whole correctness argument, so `key` takes the inputs explicitly, not a tool name alone).
pub struct Memo {
    map: Mutex<HashMap<String, ToolResult>>,
    hits: Mutex<u64>,
    misses: Mutex<u64>,
}

impl Memo {
    pub fn new() -> Self {
        Memo {
            map: Mutex::new(HashMap::new()),
            hits: Mutex::new(0),
            misses: Mutex::new(0),
        }
    }

    /// Compute a key from a tool name and its determining-input parts. Every part that affects
    /// the output MUST be included by the caller (e.g. for read_file: name, path, content-hash).
    pub fn key(tool: &str, determining_inputs: &[&str]) -> String {
        let mut h = Sha256::new();
        h.update(tool.as_bytes());
        for part in determining_inputs {
            h.update([0u8]); // separator so ("a","b") != ("ab","")
            h.update(part.as_bytes());
        }
        hex::encode(h.finalize())
    }

    pub fn get(&self, key: &str) -> Option<ToolResult> {
        let hit = self.map.lock().unwrap().get(key).cloned();
        if hit.is_some() {
            *self.hits.lock().unwrap() += 1;
        } else {
            *self.misses.lock().unwrap() += 1;
        }
        hit
    }

    /// Insert a PURE, non-error result. We never cache an error (a transient failure must not
    /// become a durable veto — the same discipline ADR-001 imposes on the merge gate).
    pub fn insert(&self, key: String, result: ToolResult) {
        if !result.is_error {
            self.map.lock().unwrap().insert(key, result);
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (*self.hits.lock().unwrap(), *self.misses.lock().unwrap())
    }
}

impl Default for Memo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::Trust;

    fn res(content: &str, err: bool) -> ToolResult {
        ToolResult {
            tool_use_id: "x".into(),
            content: content.into(),
            is_error: err,
            trust: Trust::Workspace,
            latency_ms: 0,
        }
    }

    #[test]
    fn key_includes_all_inputs_and_is_injective_on_separation() {
        // The separator prevents ("a","b") colliding with ("ab","") — a real hash-key footgun.
        assert_ne!(
            Memo::key("read", &["a", "b"]),
            Memo::key("read", &["ab", ""])
        );
    }

    #[test]
    fn hit_serves_the_cached_result() {
        let m = Memo::new();
        let k = Memo::key("read_file", &["src/main.rs", "confff00d"]);
        assert!(m.get(&k).is_none());
        m.insert(k.clone(), res("fn main(){}", false));
        assert_eq!(m.get(&k).unwrap().content, "fn main(){}");
        let (hits, misses) = m.stats();
        assert_eq!((hits, misses), (1, 1));
    }

    #[test]
    fn a_changed_content_hash_is_a_different_key_so_no_stale_serve() {
        let m = Memo::new();
        let before = Memo::key("read_file", &["a.rs", "hash_v1"]);
        let after = Memo::key("read_file", &["a.rs", "hash_v2"]); // file edited
        m.insert(before, res("old", false));
        assert!(
            m.get(&after).is_none(),
            "an edited file must miss the cache, never serve stale"
        );
    }

    #[test]
    fn errors_are_never_cached() {
        let m = Memo::new();
        let k = Memo::key("grep", &["pat", "digest"]);
        m.insert(k.clone(), res("transient failure", true));
        assert!(
            m.get(&k).is_none(),
            "a transient error must not become a durable cached veto"
        );
    }
}
