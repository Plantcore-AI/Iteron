//! Trust as a lattice (ADR-007 R11). Every context segment and tool result carries a tier.
//! The egress gate keys on the *low* tier of a turn's context join: an egress-capable tool
//! is unavailable in any turn whose join is below `Trusted`.
//!
//! This is a type, not a comment, precisely because R2 found the "checkable property" claim
//! was vacuous when repo content had no assigned tier.

use serde::{Deserialize, Serialize};

/// The trust lattice, ordered `Untrusted < Workspace < Trusted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Third-party fetched content: dependencies, web fetches, issue/PR text, MCP tool
    /// descriptions, tree-discovered instruction files. Trust-on-open is OFF for these.
    Untrusted = 0,
    /// First-party repo working-tree content the operator pointed us at.
    Workspace = 1,
    /// The operator's direct instruction and the harness's own prompt.
    Trusted = 2,
}

impl Trust {
    /// The join (least-upper-bound is `max`; the *governing* tier for an egress decision is
    /// the `min` — the most-restrictive input dominates). We expose both explicitly so a
    /// caller cannot accidentally use the wrong one.
    ///
    /// `governing` = the tier the egress gate keys on = the minimum over the segments.
    ///
    /// Empty input is intentionally explicit. Some callers are constructing an optional context
    /// segment, where “nothing was injected” has the mathematical identity `Trusted`; a security
    /// gate that unexpectedly lost all provenance must instead fail closed. Returning `Option`
    /// prevents this module from silently choosing on their behalf.
    pub fn governing(segments: impl IntoIterator<Item = Trust>) -> Option<Trust> {
        segments.into_iter().min()
    }

    /// May a turn whose governing trust is `self` invoke an egress-capable tool?
    /// Only if nothing untrusted is in scope (ADR-007 §1). The operator can escalate
    /// per-turn, but that is an explicit, recorded event handled above this type.
    pub fn egress_permitted(self) -> bool {
        self == Trust::Trusted
    }
}

#[cfg(test)]
mod tests {
    use super::Trust;

    #[test]
    fn empty_governing_evidence_requires_an_explicit_caller_policy() {
        assert_eq!(Trust::governing([]), None);
    }

    #[test]
    fn least_trusted_segment_governs() {
        assert_eq!(
            Trust::governing([Trust::Trusted, Trust::Workspace, Trust::Untrusted]),
            Some(Trust::Untrusted)
        );
    }
}
