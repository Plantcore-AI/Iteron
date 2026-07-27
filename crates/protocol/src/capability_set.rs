//! `CapabilitySet` — authority as a **set**, never as a point on an order.
//!
//! # Why this type exists
//!
//! `Capability` derives `Ord` so it can live in a `BTreeSet` (`crates/evolve` stores
//! `required_capabilities: BTreeSet<Capability>`). That derived order is a *declaration order*,
//! not an authority order, and nothing in the type system says so. An adversarial review of the
//! W1 ABI freeze found the consequence: if a ceiling is carried as a single `Capability` and
//! enforced with `<=`, then a ceiling that admits `IrreversibleExternal` **silently admits
//! `CodeExecuting` and `TrustMutating` as well**, because they sort below it. Authority is not a
//! chain — the five classes are five independent permissions.
//!
//! So every authority ceiling that crosses a seam carries a `CapabilitySet`. The type offers
//! [`CapabilitySet::intersect`] and [`CapabilitySet::contains`] and **deliberately offers no
//! union, no `max`, and no `Ord`**. Widening authority is not expressible; that is the point.
//! Admission can only ever narrow (ADR-007 intersection-only).
//!
//! `Capability` keeps its `Ord` because `BTreeSet` needs it. This type is what makes that
//! harmless: the ordering stays available for storage and is unavailable for decisions.

use crate::tool::Capability;
use serde::{Deserialize, Serialize};

/// Every capability class, in declaration order. The set representation is exactly this wide.
const ALL: [Capability; 5] = [
    Capability::ReadOnly,
    Capability::ReversibleLocal,
    Capability::CodeExecuting,
    Capability::TrustMutating,
    Capability::IrreversibleExternal,
];

fn bit(capability: Capability) -> u8 {
    match capability {
        Capability::ReadOnly => 1 << 0,
        Capability::ReversibleLocal => 1 << 1,
        Capability::CodeExecuting => 1 << 2,
        Capability::TrustMutating => 1 << 3,
        Capability::IrreversibleExternal => 1 << 4,
    }
}

/// A set of capability classes.
///
/// Serialises as a sorted, deduplicated JSON array of the `snake_case` capability names, so the
/// wire form is self-describing and stable regardless of how the set was built:
/// `["read_only","code_executing"]`.
///
/// There is no `Ord` and no union. To hold one of these is to hold an authority ceiling that can
/// only be narrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(u8);

impl CapabilitySet {
    /// The empty set: no authority at all. This is the deny-by-default starting point.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Exactly one class.
    pub fn only(capability: Capability) -> Self {
        Self(bit(capability))
    }

    /// Build from an iterator of classes.
    pub fn from_iter_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        let mut bits = 0u8;
        for capability in capabilities {
            bits |= bit(capability);
        }
        Self(bits)
    }

    /// Is this class in the set?
    pub fn contains(self, capability: Capability) -> bool {
        self.0 & bit(capability) != 0
    }

    /// The classes present in BOTH sets. This is the only combining operation, and it can only
    /// ever produce a set no wider than either input — the intersection-only admission rule of
    /// ADR-007 expressed in the type rather than in a comment.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Is every class in `self` also in `other`? Use this instead of `<=`.
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & other.0 == self.0
    }

    /// Nothing admitted.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterate the classes present, in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        ALL.into_iter().filter(move |c| self.contains(*c))
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let classes = Vec::<Capability>::deserialize(deserializer)?;
        Ok(Self::from_iter_capabilities(classes))
    }
}

#[cfg(test)]
mod tests {
    use super::CapabilitySet;
    use crate::tool::Capability;

    #[test]
    fn an_egress_ceiling_does_not_drag_in_the_classes_that_sort_below_it() {
        // The defect this type exists to prevent. Under `Capability`'s derived Ord,
        // `CodeExecuting <= IrreversibleExternal` is true, so a `<=` ceiling check would admit
        // code execution for a ceiling that only ever meant "may egress".
        assert!(Capability::CodeExecuting < Capability::IrreversibleExternal);

        let ceiling = CapabilitySet::only(Capability::IrreversibleExternal);
        assert!(ceiling.contains(Capability::IrreversibleExternal));
        assert!(!ceiling.contains(Capability::CodeExecuting));
        assert!(!ceiling.contains(Capability::TrustMutating));
    }

    #[test]
    fn intersection_can_only_narrow() {
        let broad = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
            Capability::IrreversibleExternal,
        ]);
        let policy = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]);

        let admitted = broad.intersect(policy);
        assert!(admitted.is_subset_of(broad));
        assert!(admitted.is_subset_of(policy));
        assert!(!admitted.contains(Capability::IrreversibleExternal));

        // Intersecting again with anything never re-widens.
        let narrower = admitted.intersect(CapabilitySet::only(Capability::ReadOnly));
        assert!(narrower.is_subset_of(admitted));
        assert_eq!(narrower.iter().count(), 1);
    }

    #[test]
    fn the_empty_set_admits_nothing_and_is_the_default() {
        let denied = CapabilitySet::default();
        assert!(denied.is_empty());
        assert_eq!(denied, CapabilitySet::none());
        for capability in [
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ] {
            assert!(!denied.contains(capability));
        }
    }

    #[test]
    fn the_wire_form_is_a_sorted_deduplicated_name_array_and_round_trips() {
        let set = CapabilitySet::from_iter_capabilities([
            Capability::IrreversibleExternal,
            Capability::ReadOnly,
            // duplicate, and out of declaration order on purpose
            Capability::ReadOnly,
        ]);
        let json = serde_json::to_string(&set).expect("CapabilitySet serialises");
        assert_eq!(json, r#"["read_only","irreversible_external"]"#);

        let back: CapabilitySet = serde_json::from_str(&json).expect("CapabilitySet round-trips");
        assert_eq!(back, set);
        assert_eq!(
            serde_json::to_string(&back).expect("re-serialises"),
            json,
            "the wire form is canonical: two sets that are equal serialise identically"
        );
    }
}
