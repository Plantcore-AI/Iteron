use super::*;
use iteron_agents::{BootBundle, ToolPreference, narrow_under, tool_policy_slot};
use iteron_evolve::{PolicyBundle, PolicyRef, StrategySlot};

fn digest(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn promoted(policy_id: &str) -> PolicyBundle {
    PolicyBundle {
        bundle_id: "promoted-1".into(),
        digest: digest('a'),
        policies: vec![PolicyRef {
            slot: StrategySlot::new("iteron/tool_policy").expect("a valid slot"),
            policy_id: policy_id.into(),
            version: "1".into(),
            digest: digest('b'),
        }],
        rollback_to: None,
    }
}

/// The two-boot behavioral diff, in one test: same binary, different active bundle, different
/// tool selection.
#[test]
fn a_promoted_bundle_shifts_tool_selection_across_two_boots() {
    let baseline_boot = BootBundle::resolve(&ActiveBundleResolver::from_active(None))
        .expect("an unconfigured authority boots ungoverned");
    let governed_boot = BootBundle::resolve(&ActiveBundleResolver::from_active(Some(promoted(
        "prefer-structural-search",
    ))))
    .expect("a promoted bundle projects and resolves");

    let filter = iteron_agents::ToolFilter::All;
    let selection_a = narrow_under(&filter, baseline_boot.tool_preference());
    let selection_b = narrow_under(&filter, governed_boot.tool_preference());

    // The demo, printed. Run it with:
    //   cargo test -p iteron-cli --bins bundle_adapter -- --nocapture
    println!("boot A (no active bundle)      tool order: {selection_a:?}");
    println!("boot B (promoted bundle)       tool order: {selection_b:?}");
    println!(
        "kernel TCB unchanged across both boots: PROTOCOL_VERSION={} (frozen at W1; \
         `conformance kernel` fails if it moves)",
        iteron_protocol::wire::PROTOCOL_VERSION
    );
    println!(
        "governed by: bundle {} policy {}",
        &digest('a')[..12],
        &digest('b')[..12]
    );

    assert_ne!(selection_a, selection_b, "promotion must be observable");
    assert_eq!(baseline_boot.tool_preference(), ToolPreference::Baseline);
    assert_eq!(
        governed_boot.tool_preference(),
        ToolPreference::PreferStructuralSearch
    );
    // The governed boot can name what governed it, and the ungoverned one cannot claim it was.
    assert_eq!(
        governed_boot.governance_receipt(),
        Some((digest('a'), digest('b')))
    );
    assert!(baseline_boot.governance_receipt().is_none());
}

#[test]
fn the_projection_carries_identity_and_never_a_policy_body() {
    let projected = project(&promoted("prefer-structural-search")).expect("projects");
    assert_eq!(projected.bundle_id, "promoted-1");
    assert_eq!(projected.digest, digest('a'));
    let policy = projected
        .policy_for(&tool_policy_slot())
        .expect("the tool-policy slot is governed");
    assert_eq!(policy.policy_id, "prefer-structural-search");
    assert_eq!(policy.digest, digest('b'));
    // `ResolvedPolicy` has four fields and none of them is a body: the runtime never sees the
    // artifact, which is why the digest is carried opaquely instead.
    assert_eq!(
        serde_json::to_value(policy)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        4
    );
}

/// A slot the agents-local grammar refuses is refused here, rather than assumed compatible.
#[test]
fn a_slot_the_agents_grammar_refuses_is_refused_by_the_projection() {
    let mut bundle = promoted("prefer-structural-search");
    bundle.policies[0].digest = "not-a-digest".into();
    assert!(project(&bundle).is_err());
}

/// An unknown promoted identity reaches the agents side and is refused there, not here: the
/// adapter's job is projection, and deciding what a build recognises is the consumer's.
#[test]
fn an_unknown_promoted_identity_projects_but_governs_nothing() {
    let boot = BootBundle::resolve(&ActiveBundleResolver::from_active(Some(promoted(
        "a-policy-this-build-has-never-heard-of",
    ))))
    .expect("an unknown identity is still a well-formed bundle");
    assert!(boot.active().is_some(), "the projection succeeded");
    assert_eq!(
        boot.tool_preference(),
        ToolPreference::Baseline,
        "but it governs nothing this build can act on"
    );
}
