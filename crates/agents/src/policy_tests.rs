use super::*;
use core_protocol::bundle::ResolvedPolicy;

fn digest(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn bundle_with(policy_id: &str) -> ResolvedBundle {
    ResolvedBundle {
        bundle_id: "bundle-1".into(),
        digest: digest('a'),
        policies: vec![ResolvedPolicy {
            slot: tool_policy_slot(),
            policy_id: policy_id.into(),
            version: "1".into(),
            digest: digest('b'),
        }],
    }
}

struct Resolver(Result<Option<ResolvedBundle>, BundleResolutionError>);

impl PolicyBundleResolver for Resolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        self.0.clone()
    }
}

#[test]
fn absent_bundle_falls_back_to_baseline() {
    let boot = BootBundle::resolve(&Resolver(Ok(None))).expect("no bundle is not an error");
    assert_eq!(boot.tool_preference(), ToolPreference::Baseline);
    assert!(boot.active().is_none());
    assert!(
        boot.governance_receipt().is_none(),
        "nothing governed the run"
    );
    assert_eq!(
        narrow_under(&ToolFilter::All, boot.tool_preference()),
        ToolFilter::All.narrow(),
        "an ungoverned boot must behave exactly as the hand-written baseline"
    );
}

#[test]
fn promoted_bundle_shifts_tool_selection() {
    let baseline = narrow_under(&ToolFilter::All, ToolPreference::Baseline);
    let boot = BootBundle::resolve(&Resolver(Ok(Some(bundle_with("prefer-structural-search")))))
        .expect("a well-formed bundle resolves");
    assert_eq!(
        boot.tool_preference(),
        ToolPreference::PreferStructuralSearch
    );
    let governed = narrow_under(&ToolFilter::All, boot.tool_preference());

    assert_ne!(
        governed, baseline,
        "a promoted bundle must change something"
    );
    assert_eq!(
        governed.first().map(String::as_str),
        Some("glob"),
        "the promoted preference puts the structural searcher first"
    );
    // Narrowing is untouched: a promotion reorders, it never widens.
    assert_eq!(
        governed.iter().collect::<std::collections::BTreeSet<_>>(),
        baseline.iter().collect::<std::collections::BTreeSet<_>>(),
        "a promoted policy may reorder what an agent reaches for, never widen it"
    );
    // The run record can name exactly what governed it.
    let (bundle_digest, policy_digest) = boot.governance_receipt().expect("a governed run");
    assert_eq!(bundle_digest, digest('a'));
    assert_eq!(policy_digest, digest('b'));
}

#[test]
fn resolution_is_boot_time_and_immutable() {
    let boot = BootBundle::resolve(&Resolver(Ok(Some(bundle_with("prefer-structural-search")))))
        .expect("a well-formed bundle resolves");
    let first = boot.tool_preference();
    // Every accessor is a shared borrow; the type exposes no setter, no reload, and no interior
    // mutability, so the only way to observe a different answer is to build a different value.
    for _ in 0..8 {
        assert_eq!(boot.tool_preference(), first);
        assert_eq!(
            boot.active(),
            Some(&bundle_with("prefer-structural-search"))
        );
    }

    // The surface a live self-activation would need does not exist. This is the compile-fenced
    // half of that claim: `BootBundle` is constructible only by resolving or by asking for the
    // baseline, and neither takes a bundle from a caller after boot.
    let baseline = BootBundle::baseline();
    assert_eq!(baseline.tool_preference(), ToolPreference::Baseline);
}

#[test]
fn unknown_or_invalid_bundle_is_fail_safe_baseline() {
    // An identity this build has never heard of must not change behavior by being unrecognisable.
    let unknown = BootBundle::resolve(&Resolver(Ok(Some(bundle_with("some-future-policy")))))
        .expect("an unknown identity is still a well-formed bundle");
    assert_eq!(unknown.tool_preference(), ToolPreference::Baseline);

    // A resolver that cannot answer is baseline too: running ungoverned is the safe reading of
    // "I could not tell".
    let broken = ToolPreference::resolve_at_boot(&Resolver(Err(
        BundleResolutionError::Unreadable("fixture cannot read the active-bundle pointer"),
    )));
    assert_eq!(broken, ToolPreference::Baseline);

    // A malformed view is refused rather than improvised over.
    let mut malformed = bundle_with("prefer-structural-search");
    malformed.digest = "not-a-digest".into();
    assert!(BootBundle::resolve(&Resolver(Ok(Some(malformed.clone())))).is_err());
    assert_eq!(
        ToolPreference::from_bundle(Some(&malformed)),
        ToolPreference::Baseline
    );

    // A bundle that governs some other slot governs nothing here.
    let other = ResolvedBundle {
        bundle_id: "bundle-2".into(),
        digest: digest('c'),
        policies: vec![ResolvedPolicy {
            slot: core_protocol::slot::SlotId("core/context".into()),
            policy_id: "prefer-structural-search".into(),
            version: "1".into(),
            digest: digest('d'),
        }],
    };
    assert_eq!(
        ToolPreference::from_bundle(Some(&other)),
        ToolPreference::Baseline
    );
}

/// A typo in the preference order would be a silent no-op: the promoted bundle would look applied
/// and change nothing.
#[test]
fn every_preferred_tool_is_a_real_read_only_tool() {
    assert!(structural_search_order_is_grounded());
}

/// A promotion cannot smuggle a tool past the filter that refused it.
#[test]
fn a_promoted_policy_cannot_widen_a_narrowed_filter() {
    let deny = ToolFilter::Deny(vec!["glob".into(), "grep".into()]);
    let governed = narrow_under(&deny, ToolPreference::PreferStructuralSearch);
    assert!(!governed.iter().any(|tool| tool == "glob"));
    assert!(!governed.iter().any(|tool| tool == "grep"));
    // The order may still change — `repo_map` is preferred too and is not denied. What may never
    // change is the set: a promotion reorders what an agent reaches for and cannot add to it.
    assert_eq!(
        governed.iter().collect::<std::collections::BTreeSet<_>>(),
        deny.narrow()
            .iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "a promoted policy cannot hand back a tool the filter refused"
    );
}

/// The ungoverned promotion is the identity, so a host may apply it unconditionally.
///
/// This is what makes the boot wiring safe to land before any bundle exists: a host that always
/// promotes `promoted_leading()` reorders nothing at all until a bundle is actually promoted.
#[test]
fn the_baseline_promotes_nothing_and_a_governed_preference_promotes_real_tools() {
    assert!(ToolPreference::Baseline.promoted_leading().is_empty());
    let governed = ToolPreference::PreferStructuralSearch.promoted_leading();
    assert_eq!(governed, STRUCTURAL_SEARCH_ORDER);
    assert!(
        governed
            .iter()
            .all(|name| crate::def::READ_ONLY_TOOLS.contains(name)),
        "a promoted tool that is not a read-only tool would silently promote nothing"
    );
}
