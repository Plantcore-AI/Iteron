//! The read-only, boot-time view of the policy bundle in force, and the port that hands it over.
//!
//! # Why this lives in `core-protocol` and not in `core-evolve`
//!
//! The producing side of this seam is `core-evolve`, the offline promotion crate. The consuming
//! side is `crates/agents`, inside the runtime. The invariant that governs the whole arrangement is
//! that **the runtime never depends on the evolution crate** — evolution is deliberately outside the
//! trusted computing base, and a dependency edge pointing from `agents` or `kernel` into
//! `core-evolve` would drag an offline governance crate into the boot path of every run.
//!
//! A first cut declared this port in `core-evolve` over `core_evolve::PolicyBundle` and
//! `core_evolve::StrategySlot`. That reads as harmless until someone tries to implement it: naming
//! the trait, binding its return value, or even matching on it all require the consumer to name
//! external types, and Rust cannot name a type from a crate that is not in its dependency graph. So
//! the first real consumer's first line would have been the dependency the invariant forbids. The
//! acceptance grep that guards the invariant was green only because the port had no consumer — it
//! was measuring an absence, not preserving an invariant.
//!
//! Declaring the seam here fixes that by construction. `crates/evolve` already depends on
//! `core-protocol`; `crates/agents` already depends on `core-protocol`. Both sides can name every
//! type in every signature, and **neither side gains a dependency**. The evolve side supplies the
//! projection from its own `PolicyBundle` into [`ResolvedBundle`]; the agents side never learns that
//! `core-evolve` exists.
//!
//! # Why the view is not the bundle
//!
//! [`ResolvedBundle`] is deliberately narrower than the evolve-side bundle. It carries slot
//! identities and the digests that name each policy, and nothing else: no policy bodies, no
//! artifact locators, no lineage, no rollback pointer. The composition root needs to know *which
//! slots are governed and by what*, and giving it more than that would let a runtime path start
//! depending on promotion-side structure that the evolution crate must remain free to change.
//!
//! # Why there is no `governs` method on the port
//!
//! An earlier shape put `active_bundle()` and `governs(slot)` side by side on the trait. Both were
//! fallible and nothing tied them together, so an implementation could return a bundle containing
//! `core/router` and then answer `false` when asked whether it governs `core/router`. That
//! contradicts the one guarantee this seam exists to provide — the composition root asks once, at
//! startup, and gets an immutable answer. [`ResolvedBundle::governs`] is therefore a pure query on
//! the answer already given, and it is infallible because there is nothing left that can fail.

use crate::slot::SlotId;
use serde::{Deserialize, Serialize};

/// Upper bound on the number of governed slots in one resolved bundle.
pub const MAX_RESOLVED_BUNDLE_POLICIES: usize = 128;

/// Upper bound on each identity-bearing string carried in the view.
pub const MAX_RESOLVED_BUNDLE_FIELD_BYTES: usize = 256;

/// Length of the lowercase hex digests this view carries.
pub const RESOLVED_DIGEST_HEX_LEN: usize = 64;

/// One governed slot as the consuming side sees it: identity only, never a policy body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    /// Which slot this policy governs, in the kernel's own identity grammar.
    pub slot: SlotId,
    /// The policy's stable identifier within the bundle.
    pub policy_id: String,
    /// The policy's version string, opaque to this side.
    pub version: String,
    /// Content digest of the policy artifact: 64 lowercase hex characters.
    ///
    /// Opaque here. The runtime does not recompute it — it cannot, because it never sees the
    /// artifact. It carries the digest so a run record can name exactly what governed it, and so a
    /// third party can check that claim against the promotion journal afterwards.
    pub digest: String,
}

/// The read-only view of the bundle in force for this process.
///
/// Obtained once, at boot, through [`PolicyBundleResolver`]. "Read-only" describes what the seam
/// hands over — no policy bodies, no way to *set* the active bundle — and **not** the mutability of
/// this struct: every field is `pub`, so a holder can reassign them. An earlier version of this
/// comment called it "immutable" and said "nothing downstream can swap it", which were conventions
/// stated as properties. Whoever wires the composition root is the one who makes it immutable in
/// fact, by holding it behind a `OnceLock` or an `Arc` and never handing out a mutable borrow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBundle {
    pub bundle_id: String,
    /// Content digest of the bundle this view was projected from.
    pub digest: String,
    pub policies: Vec<ResolvedPolicy>,
}

impl ResolvedBundle {
    /// Whether the active bundle governs `slot`.
    ///
    /// A pure query on the answer already given, not a second call to the resolver, so this can
    /// never disagree with the bundle it was asked about.
    pub fn governs(&self, slot: &SlotId) -> bool {
        self.policies.iter().any(|policy| &policy.slot == slot)
    }

    /// The policy governing `slot`, if any.
    pub fn policy_for(&self, slot: &SlotId) -> Option<&ResolvedPolicy> {
        self.policies.iter().find(|policy| &policy.slot == slot)
    }

    /// Validate shape and bounds. States no opinion about whether the bundle is *good*, which is a
    /// promotion decision made offline and long before this view exists.
    ///
    /// Duplicate slots are refused rather than resolved by first-wins or last-wins. A bundle naming
    /// one slot twice is ambiguous about which policy governs it, and picking silently would make
    /// the run record unable to say what actually ran.
    pub fn validate(&self) -> Result<(), BundleResolutionError> {
        validate_field("resolved_bundle.bundle_id", &self.bundle_id)?;
        validate_digest("resolved_bundle.digest", &self.digest)?;
        if self.policies.len() > MAX_RESOLVED_BUNDLE_POLICIES {
            return Err(BundleResolutionError::Malformed(
                "resolved_bundle.policies exceeds the bound",
            ));
        }
        for policy in &self.policies {
            policy
                .slot
                .validate()
                .map_err(|_| BundleResolutionError::UnrepresentableSlot)?;
            validate_field("resolved_policy.policy_id", &policy.policy_id)?;
            validate_field("resolved_policy.version", &policy.version)?;
            validate_digest("resolved_policy.digest", &policy.digest)?;
        }
        for (index, policy) in self.policies.iter().enumerate() {
            if self.policies[..index]
                .iter()
                .any(|earlier| earlier.slot == policy.slot)
            {
                return Err(BundleResolutionError::DuplicateSlot);
            }
        }
        Ok(())
    }
}

fn validate_field(field: &'static str, value: &str) -> Result<(), BundleResolutionError> {
    if value.trim().is_empty() {
        return Err(BundleResolutionError::Malformed(field));
    }
    if value.len() > MAX_RESOLVED_BUNDLE_FIELD_BYTES {
        return Err(BundleResolutionError::Malformed(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), BundleResolutionError> {
    if value.len() != RESOLVED_DIGEST_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BundleResolutionError::Malformed(field));
    }
    Ok(())
}

/// Why a bundle could not be resolved into a usable view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleResolutionError {
    /// The resolver could not read its source at all.
    Unreadable(&'static str),
    /// A field is absent, empty, over bound, or not a well-formed digest.
    Malformed(&'static str),
    /// A bundle entry names a slot this side cannot express.
    ///
    /// The two slot grammars are related by a strict-subset rule with a direction (see
    /// [`crate::slot`]): every valid [`SlotId`] is a valid evolve-side slot, but not the reverse.
    /// Projecting therefore has a lossy direction, and a bundle carrying a slot the kernel cannot
    /// name is refused rather than silently dropped — a dropped entry would leave the slot running
    /// its built-in strategy while the promotion journal recorded it as governed.
    UnrepresentableSlot,
    /// One slot is named more than once, so which policy governs it is ambiguous.
    DuplicateSlot,
}

impl std::fmt::Display for BundleResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(source) => {
                write!(formatter, "policy bundle source is unreadable: {source}")
            }
            Self::Malformed(field) => {
                write!(formatter, "resolved bundle field is malformed: {field}")
            }
            Self::UnrepresentableSlot => write!(
                formatter,
                "policy bundle names a slot this side cannot express"
            ),
            Self::DuplicateSlot => write!(
                formatter,
                "policy bundle names the same slot more than once"
            ),
        }
    }
}

impl std::error::Error for BundleResolutionError {}

/// evolve -> agents: resolve the active policy bundle at boot, read only.
///
/// Declared in the crate **both** sides already depend on, so neither the implementor nor the
/// consumer gains a dependency by using it. See the module docs for why that is the whole point.
///
/// Deliberately absent: any way to *set* the active bundle. Promotion is human-gated and lives
/// entirely on the evolution side; this is the read half and only the read half.
pub trait PolicyBundleResolver: Send + Sync {
    /// The bundle in force for this process, if any.
    ///
    /// `Ok(None)` means no bundle is active and the built-in strategies apply — a normal state, not
    /// an error. A caller must not collapse `Err(..)` into this case: running the built-ins because
    /// the resolver failed, while the promotion journal records a bundle as active, is precisely the
    /// silent divergence this seam exists to prevent.
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError>;
}

#[cfg(test)]
mod tests {
    use super::{
        BundleResolutionError, MAX_RESOLVED_BUNDLE_FIELD_BYTES, PolicyBundleResolver,
        ResolvedBundle, ResolvedPolicy,
    };
    use crate::slot::SlotId;

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn policy(slot: &str) -> ResolvedPolicy {
        ResolvedPolicy {
            slot: SlotId(slot.to_owned()),
            policy_id: "acme.router".into(),
            version: "1.4.0".into(),
            digest: digest('a'),
        }
    }

    fn bundle(policies: Vec<ResolvedPolicy>) -> ResolvedBundle {
        ResolvedBundle {
            bundle_id: "acme-2026-07".into(),
            digest: digest('b'),
            policies,
        }
    }

    #[test]
    fn governs_answers_from_the_snapshot_and_cannot_disagree_with_it() {
        let resolved = bundle(vec![policy("core/router")]);
        assert!(resolved.governs(&SlotId("core/router".into())));
        assert!(!resolved.governs(&SlotId("core/verifier".into())));
        assert_eq!(
            resolved
                .policy_for(&SlotId("core/router".into()))
                .map(|p| p.policy_id.as_str()),
            Some("acme.router")
        );
        assert!(
            resolved
                .policy_for(&SlotId("core/verifier".into()))
                .is_none()
        );
    }

    #[test]
    fn an_empty_bundle_is_valid_and_governs_nothing() {
        // Distinct from "no bundle at all", which the resolver signals with `Ok(None)`.
        let resolved = bundle(Vec::new());
        assert!(resolved.validate().is_ok());
        assert!(!resolved.governs(&SlotId("core/router".into())));
    }

    #[test]
    fn a_slot_this_side_cannot_express_is_refused_rather_than_dropped() {
        // `db/query.planner` is a valid evolve-side slot and is NOT a valid SlotId: the subset
        // direction only runs one way. Dropping it would leave the slot on its built-in strategy
        // while the journal recorded it as governed.
        let resolved = bundle(vec![policy("db/query.planner")]);
        assert_eq!(
            resolved.validate(),
            Err(BundleResolutionError::UnrepresentableSlot)
        );
    }

    #[test]
    fn the_same_slot_twice_is_ambiguous_and_refused() {
        let resolved = bundle(vec![policy("core/router"), policy("core/router")]);
        assert_eq!(
            resolved.validate(),
            Err(BundleResolutionError::DuplicateSlot)
        );
    }

    #[test]
    fn a_digest_that_is_not_64_lowercase_hex_is_refused() {
        let mut resolved = bundle(vec![policy("core/router")]);
        resolved.digest = "z".repeat(64);
        assert!(matches!(
            resolved.validate(),
            Err(BundleResolutionError::Malformed(_))
        ));

        let mut short = bundle(vec![policy("core/router")]);
        short.policies[0].digest = "abc".into();
        assert!(matches!(
            short.validate(),
            Err(BundleResolutionError::Malformed(_))
        ));
    }

    #[test]
    fn identity_fields_are_bounded_and_non_empty() {
        let mut empty = bundle(vec![policy("core/router")]);
        empty.bundle_id = "   ".into();
        assert!(matches!(
            empty.validate(),
            Err(BundleResolutionError::Malformed(_))
        ));

        let mut over = bundle(vec![policy("core/router")]);
        over.policies[0].version = "9".repeat(MAX_RESOLVED_BUNDLE_FIELD_BYTES + 1);
        assert!(matches!(
            over.validate(),
            Err(BundleResolutionError::Malformed(_))
        ));
    }

    #[test]
    fn the_port_is_satisfiable_and_distinguishes_no_bundle_from_failure() {
        struct NoBundle;
        impl PolicyBundleResolver for NoBundle {
            fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
                Ok(None)
            }
        }
        struct Broken;
        impl PolicyBundleResolver for Broken {
            fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
                Err(BundleResolutionError::Unreadable("no journal on this host"))
            }
        }
        struct Governed;
        impl PolicyBundleResolver for Governed {
            fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
                Ok(Some(bundle(vec![policy("core/router")])))
            }
        }

        // The three answers must be mutually distinguishable by a caller. "No bundle is active" and
        // "the resolver is broken" mean opposite things for a boot path.
        assert!(matches!(NoBundle.active_bundle(), Ok(None)));
        assert!(Broken.active_bundle().is_err());
        let governed = Governed
            .active_bundle()
            .expect("resolver ok")
            .expect("a bundle");
        assert!(governed.governs(&SlotId("core/router".into())));
        assert!(governed.validate().is_ok());
    }

    #[test]
    fn the_view_round_trips_through_json_without_moving() {
        let resolved = bundle(vec![policy("core/router")]);
        let encoded = serde_json::to_string(&resolved).expect("serialize");
        let decoded: ResolvedBundle = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(resolved, decoded);
    }
}
