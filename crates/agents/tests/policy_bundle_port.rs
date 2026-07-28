//! `crates/agents` consumes the bundle-resolution port, and gains no dependency on the evolution
//! crate.
//!
//! # Why this test exists
//!
//! `#26` acceptance criterion 5 runs `grep -rniE 'core[-_]evolve'` over `crates/kernel` and
//! `crates/agents` and requires no hit, so that the bundle-resolution port cannot have added that
//! dependency to either. The invariant is real: evolution is deliberately outside the runtime
//! trusted computing base.
//!
//! A grep for an absence is green whenever nothing consumes the port at all, which is what it was:
//! the trait had no implementor and no caller anywhere in the workspace, so the criterion was
//! measuring "nobody uses this" rather than "the invariant holds". That is the worse of the two
//! failure modes, because it reads as a passing gate right up until the first consumer turns it red.
//!
//! This file is the consumer that makes it mean something. `crates/agents` names the port, holds it
//! as a trait object at a composition root, implements it, and reads a governed slot out of the
//! resolved view — all through `core-protocol`, which it already depends on. If the port is ever
//! moved back onto evolution-crate types, this file stops compiling, and the criterion goes from
//! vacuously green to honestly red.
//!
//! Read `crates/agents/Cargo.toml` alongside this: `core-ctx` and `core-protocol`, nothing else.
//!
//! # A warning about that grep, for whoever runs it next
//!
//! It is a plain text search and cannot tell an import from an English sentence. Writing the crate
//! name in a comment anywhere under these two directories turns the criterion red without any
//! dependency existing — this file tripped it three times while explaining it. The prose here is
//! therefore worded around the literal token deliberately. If the criterion ever does go red, read
//! the hits before believing them, and check `Cargo.toml` and `cargo tree` for the real answer.

use core_protocol::bundle::{
    BundleResolutionError, PolicyBundleResolver, ResolvedBundle, ResolvedPolicy,
};
use core_protocol::slot::SlotId;

fn digest(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn governed_bundle() -> ResolvedBundle {
    ResolvedBundle {
        bundle_id: "acme-2026-07".into(),
        digest: digest('b'),
        policies: vec![ResolvedPolicy {
            slot: SlotId("core/tool_policy".into()),
            policy_id: "acme.tool_policy".into(),
            version: "2.1.0".into(),
            digest: digest('a'),
        }],
    }
}

/// What a real boot path looks like on this side: one resolver, asked once, held immutably.
struct BootResolver {
    active: Option<ResolvedBundle>,
}

impl PolicyBundleResolver for BootResolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        Ok(self.active.clone())
    }
}

struct UnreadableResolver;

impl PolicyBundleResolver for UnreadableResolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        Err(BundleResolutionError::Unreadable(
            "no promotion journal on this host",
        ))
    }
}

/// The composition root: it holds the port as a trait object and never names an evolve type.
struct Boot<'a> {
    bundles: &'a dyn PolicyBundleResolver,
}

impl Boot<'_> {
    fn governed_slots(&self) -> Result<Vec<SlotId>, BundleResolutionError> {
        Ok(self
            .bundles
            .active_bundle()?
            .map(|bundle| bundle.policies.into_iter().map(|p| p.slot).collect())
            .unwrap_or_default())
    }
}

#[test]
fn agents_can_consume_the_port_without_naming_the_evolution_crate() {
    let resolver = BootResolver {
        active: Some(governed_bundle()),
    };
    let boot = Boot { bundles: &resolver };
    assert_eq!(
        boot.governed_slots().expect("resolver ok"),
        vec![SlotId("core/tool_policy".into())]
    );
}

#[test]
fn no_active_bundle_means_the_built_in_strategies_apply() {
    // `Ok(None)` is a normal state, not a degraded one: it is how the runtime is told that nothing
    // was promoted and the built-ins are correct.
    let boot = Boot {
        bundles: &BootResolver { active: None },
    };
    assert!(boot.governed_slots().expect("resolver ok").is_empty());
}

#[test]
fn a_broken_resolver_is_not_the_same_as_no_bundle() {
    // The distinction this side must never collapse. Falling back to the built-ins because the
    // resolver failed, while the promotion journal records a bundle as active, is a silent
    // divergence between what ran and what the record says ran.
    let boot = Boot {
        bundles: &UnreadableResolver,
    };
    assert!(matches!(
        boot.governed_slots(),
        Err(BundleResolutionError::Unreadable(_))
    ));
}

#[test]
fn the_resolved_view_answers_which_slots_are_governed_without_a_second_call() {
    // `governs` is a pure query on the answer already given, so it cannot disagree with the bundle
    // it was asked about. An earlier shape put a second fallible `governs` on the port itself, and
    // nothing tied the two answers together.
    let bundle = governed_bundle();
    assert!(bundle.governs(&SlotId("core/tool_policy".into())));
    assert!(!bundle.governs(&SlotId("core/router".into())));
    assert_eq!(
        bundle
            .policy_for(&SlotId("core/tool_policy".into()))
            .map(|p| p.version.as_str()),
        Some("2.1.0")
    );
}
