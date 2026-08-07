//! Composition is asserted through the surface it produces, never through its internals: every
//! test here would still be meaningful if the merge were rewritten.

use super::*;
use crate::composition_model::{
    Contribution, MAX_CONTRIBUTIONS_PER_PLUGIN, MAX_DETAIL_BYTES, PluginScope, RuntimeScope,
};
use core_protocol::{Capability, capability_set::CapabilitySet};

fn skill(name: &str, description: &str) -> Contribution {
    Contribution::Skill {
        name: name.to_owned(),
        description: description.to_owned(),
    }
}

fn agent(name: &str) -> Contribution {
    Contribution::Agent {
        name: name.to_owned(),
        description: "an agent".to_owned(),
    }
}

fn hook(event: &str, action: &str) -> Contribution {
    Contribution::Hook {
        event: event.to_owned(),
        action: action.to_owned(),
    }
}

fn server(language: &str, command: &str) -> Contribution {
    Contribution::LanguageServer {
        language: language.to_owned(),
        command: command.to_owned(),
    }
}

fn mcp(name: &str, binding: &str) -> Contribution {
    Contribution::McpServer {
        name: name.to_owned(),
        binding: binding.to_owned(),
    }
}

/// Every ordering of `manifests`, so a property can be asserted over the set rather than a sequence.
fn permutations(manifests: &[Manifest]) -> Vec<Vec<Manifest>> {
    if manifests.is_empty() {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for (i, head) in manifests.iter().enumerate() {
        let mut rest = manifests.to_vec();
        rest.remove(i);
        for mut tail in permutations(&rest) {
            let mut one = vec![head.clone()];
            one.append(&mut tail);
            out.push(one);
        }
    }
    out
}

// -- the isolation property ------------------------------------------------------------------

#[test]
fn a_malformed_contribution_is_refused_while_its_neighbours_survive() {
    // The whole point: one plugin's indefensible manifest cannot reach the others.
    let good_a = Manifest::new("fmt", 10).with(skill("format", "reformat the file"));
    let good_b = Manifest::new("lint", 10)
        .with(agent("reviewer"))
        .with(hook("pre-tool-use", "deny-writes-outside-repo"));
    // `has space` is not addressable: nothing could ever ask for it by name.
    let malformed = Manifest::new("rogue", 10).with(skill("has space", "unreachable"));

    let composed = compose(&[good_a.clone(), malformed, good_b.clone()]);

    assert_eq!(
        composed.wiring,
        compose(&[good_a, good_b]).wiring,
        "the refusal must leave no trace at all in the runtime surface"
    );
    assert_eq!(composed.wiring.skill("format").unwrap().plugin, "fmt");
    assert_eq!(composed.wiring.agent("reviewer").unwrap().plugin, "lint");
    assert_eq!(composed.wiring.hooks("pre-tool-use").len(), 1);
    assert!(matches!(
        composed.report.refusal_for("rogue"),
        Some(Defect::InvalidSlotKey { .. })
    ));
}

#[test]
fn the_refusal_names_the_plugin_and_the_reason_rather_than_vanishing() {
    // A plugin that silently contributes nothing is indistinguishable from one never installed.
    let composed = compose(&[Manifest::new("rogue", 1).with(skill("ok", ""))]);
    let refusal = &composed.report.refusals()[0];
    let text = refusal.to_string();
    assert!(text.starts_with("rogue: "), "{text}");
    assert!(text.contains("empty"), "{text}");
}

#[test]
fn a_refused_plugin_forfeits_its_well_formed_contributions_too() {
    // Deliberate blast radius: loading half a manifest runs a configuration nobody authored.
    let malformed = Manifest::new("rogue", 10)
        .with(skill("perfectly-fine", "would have worked"))
        .with(hook("pre-tool-use", "\u{7}bell"));

    let composed = compose(&[malformed]);

    assert!(composed.wiring.is_empty());
    assert!(composed.wiring.skill("perfectly-fine").is_none());
    assert!(matches!(
        composed.report.refusal_for("rogue"),
        Some(Defect::UnusableDetail { .. })
    ));
}

#[test]
fn refusing_the_would_be_winner_promotes_the_neighbour_it_would_have_shadowed() {
    // Refusal is not "the slot is now empty"; it is "compose as if it were never installed".
    let strong_but_broken = Manifest::new("rogue", 99)
        .with(skill("review", "high precedence"))
        .with(skill("bad name!", "the defect"));
    let weak_but_valid = Manifest::new("careful", 1).with(skill("review", "low precedence"));

    let composed = compose(&[strong_but_broken, weak_but_valid]);

    let bound = composed.wiring.skill("review").unwrap();
    assert_eq!(bound.plugin, "careful");
    assert_eq!(bound.detail, "low precedence");
    assert!(
        composed.report.contests().is_empty(),
        "a refused plugin never contests anything"
    );
}

// -- determinism -----------------------------------------------------------------------------

#[test]
fn composition_is_a_function_of_the_set_and_not_of_the_order() {
    // Install order, discovery order and map iteration order appear nowhere in the merge.
    let manifests = vec![
        Manifest::new("alpha", 5)
            .with(skill("review", "alpha review"))
            .with(hook("pre-tool-use", "alpha-first"))
            .with(hook("pre-tool-use", "alpha-second")),
        Manifest::new("beta", 9)
            .with(skill("review", "beta review"))
            .with(server("rust", "beta-analyzer")),
        Manifest::new("gamma", 5).with(hook("pre-tool-use", "gamma")),
        Manifest::new("bad id", 1).with(skill("x", "d")),
    ];
    let expected = compose(&manifests);

    let orders = permutations(&manifests);
    assert_eq!(orders.len(), 24, "all permutations must be exercised");
    for order in orders {
        assert_eq!(
            compose(&order),
            expected,
            "composition differed for input order {:?}",
            order.iter().map(|m| &m.plugin).collect::<Vec<_>>()
        );
    }
}

#[test]
fn an_exclusive_slot_is_won_on_operator_precedence_and_the_loser_is_named() {
    let composed = compose(&[
        Manifest::new("zzz-preferred", 9).with(skill("review", "preferred")),
        Manifest::new("aaa-other", 1).with(skill("review", "other")),
    ]);

    let slot = Slot::new(Surface::Skill, "review");
    assert_eq!(composed.wiring.owner(&slot), Some("zzz-preferred"));
    let contest = composed.report.contest_for(&slot).unwrap();
    assert_eq!(contest.winner, "zzz-preferred");
    assert_eq!(contest.shadowed, vec!["aaa-other".to_owned()]);
    assert_eq!(contest.arbitration, Arbitration::Precedence);
    assert!(composed.report.unarbitrated().is_empty());
}

#[test]
fn an_equal_ranked_contest_is_settled_deterministically_but_declared_undecided() {
    // Deterministic and arbitrary are different things, and only one of them means the operator
    // has actually chosen. Collapsing them would hide a name hijack behind a stable outcome.
    let composed = compose(&[
        Manifest::new("bbb", 7).with(skill("review", "bbb")),
        Manifest::new("aaa", 7).with(skill("review", "aaa")),
    ]);

    let slot = Slot::new(Surface::Skill, "review");
    assert_eq!(composed.wiring.owner(&slot), Some("aaa"));
    let contest = composed.report.contest_for(&slot).unwrap();
    assert_eq!(contest.arbitration, Arbitration::TieBrokenByPluginId);
    assert!(!contest.arbitration.is_operator_intent());
    assert_eq!(composed.report.unarbitrated().len(), 1);
}

#[test]
fn a_single_claimant_is_not_reported_as_a_contest() {
    let composed = compose(&[Manifest::new("only", 1).with(skill("review", "sole"))]);
    assert!(composed.report.is_clean());
    assert_eq!(composed.wiring.skill("review").unwrap().plugin, "only");
}

#[test]
fn the_surface_is_part_of_the_address_so_a_skill_and_an_agent_may_share_a_name() {
    let composed = compose(&[
        Manifest::new("s", 1).with(skill("review", "the skill")),
        Manifest::new("a", 1).with(agent("review")),
    ]);

    assert_eq!(composed.wiring.skill("review").unwrap().plugin, "s");
    assert_eq!(composed.wiring.agent("review").unwrap().plugin, "a");
    assert!(
        composed.report.contests().is_empty(),
        "different surfaces never contest"
    );
    assert_eq!(
        composed.wiring.slots(),
        vec![
            &Slot::new(Surface::Skill, "review"),
            &Slot::new(Surface::Agent, "review"),
        ]
    );
}

#[test]
fn a_language_server_slot_is_exclusive_per_language() {
    let composed = compose(&[
        Manifest::new("a", 1).with(server("rust", "a-ls")),
        Manifest::new("b", 3).with(server("rust", "b-ls")),
        Manifest::new("c", 1).with(server("python", "c-ls")),
    ]);

    assert_eq!(composed.wiring.language_server("rust").unwrap().plugin, "b");
    assert_eq!(
        composed.wiring.language_server("python").unwrap().plugin,
        "c"
    );
    assert_eq!(composed.report.contests().len(), 1);
}

// -- hooks are a chain, not a slot -------------------------------------------------------------

#[test]
fn hooks_are_additive_and_run_in_one_total_order() {
    // Precedence decides who runs first (a hook that can veto must see the operator's preferred
    // plugin first); within a plugin, the author's declaration order is preserved.
    let composed = compose(&[
        Manifest::new("mid", 5)
            .with(hook("pre-tool-use", "mid-1"))
            .with(hook("pre-tool-use", "mid-2")),
        Manifest::new("high", 9).with(hook("pre-tool-use", "high-1")),
        Manifest::new("also-mid", 5).with(hook("pre-tool-use", "also-mid-1")),
    ]);

    let chain: Vec<&str> = composed
        .wiring
        .hooks("pre-tool-use")
        .iter()
        .map(|b| b.detail.as_str())
        .collect();
    assert_eq!(chain, vec!["high-1", "also-mid-1", "mid-1", "mid-2"]);
    assert!(
        composed.report.contests().is_empty(),
        "a chain has no losers, so nothing is shadowed"
    );
}

#[test]
fn an_unknown_event_has_an_empty_chain_rather_than_no_answer() {
    let composed = compose(&[Manifest::new("a", 1).with(hook("post-tool-use", "x"))]);
    assert!(composed.wiring.hooks("pre-tool-use").is_empty());
    assert_eq!(composed.wiring.events(), vec!["post-tool-use"]);
}

#[test]
fn one_plugins_admission_never_depends_on_how_many_hooks_its_neighbours_declared() {
    // The contribution bound is per plugin. A global per-event cap would make the last-evaluated
    // plugin lose its hook because of what the others declared -- the coupling this design removes.
    let manifests: Vec<Manifest> = (0..64)
        .map(|i| Manifest::new(format!("p{i:03}"), 1).with(hook("pre-tool-use", &format!("a{i}"))))
        .collect();

    let composed = compose(&manifests);

    assert_eq!(composed.wiring.hooks("pre-tool-use").len(), 64);
    assert!(composed.report.refusals().is_empty());
}

// -- what a manifest may not do ----------------------------------------------------------------

#[test]
fn a_plugin_that_claims_one_slot_twice_is_refused_because_the_intent_is_unknowable() {
    let composed = compose(&[
        Manifest::new("dup", 1)
            .with(skill("review", "first body"))
            .with(skill("review", "second body")),
        Manifest::new("ok", 1).with(skill("other", "fine")),
    ]);

    assert_eq!(
        composed.report.refusal_for("dup"),
        Some(&Defect::DuplicateClaim {
            index: 1,
            first: 0,
            slot: Slot::new(Surface::Skill, "review"),
        })
    );
    assert!(composed.wiring.skill("review").is_none());
    assert_eq!(composed.wiring.skill("other").unwrap().plugin, "ok");
}

#[test]
fn subscribing_twice_to_one_event_is_allowed_but_repeating_the_identical_action_is_not() {
    let distinct = compose(&[Manifest::new("a", 1)
        .with(hook("pre-tool-use", "one"))
        .with(hook("pre-tool-use", "two"))]);
    assert_eq!(distinct.wiring.hooks("pre-tool-use").len(), 2);

    // The same action twice would run the side effect twice, which no author intends.
    let repeated = compose(&[Manifest::new("a", 1)
        .with(hook("pre-tool-use", "one"))
        .with(hook("pre-tool-use", "one"))]);
    assert!(matches!(
        repeated.report.refusal_for("a"),
        Some(Defect::DuplicateClaim { .. })
    ));
}

#[test]
fn an_unusable_plugin_id_is_refused() {
    for bad in ["", "has space", "../escape", "a/b"] {
        let composed = compose(&[
            Manifest::new(bad, 1).with(skill("x", "d")),
            Manifest::new("good", 1).with(skill("y", "d")),
        ]);
        assert!(
            matches!(
                composed.report.refusal_for(bad),
                Some(Defect::InvalidPluginId { .. })
            ),
            "{bad:?} must be refused"
        );
        assert!(composed.wiring.skill("y").is_some(), "{bad:?}");
    }
}

#[test]
fn two_manifests_claiming_one_plugin_id_are_both_refused() {
    // Keeping either copy would answer the question the id exists to answer by guessing.
    let composed = compose(&[
        Manifest::new("twin", 1).with(skill("a", "first")),
        Manifest::new("twin", 9).with(skill("b", "second")),
        Manifest::new("bystander", 1).with(skill("c", "third")),
    ]);

    assert_eq!(composed.report.refusals().len(), 2);
    assert!(matches!(
        composed.report.refusal_for("twin"),
        Some(Defect::DuplicatePluginId { count: 2, .. })
    ));
    assert!(composed.wiring.skill("a").is_none());
    assert!(composed.wiring.skill("b").is_none());
    assert_eq!(composed.wiring.skill("c").unwrap().plugin, "bystander");
}

#[test]
fn a_manifest_larger_than_the_declared_bound_is_refused_at_the_bound() {
    let at_limit = (0..MAX_CONTRIBUTIONS_PER_PLUGIN).fold(Manifest::new("big", 1), |m, i| {
        m.with(skill(&format!("s{i}"), "d"))
    });
    assert!(
        compose(std::slice::from_ref(&at_limit))
            .report
            .refusals()
            .is_empty()
    );

    let over = at_limit.with(skill("one-too-many", "d"));
    assert_eq!(
        compose(&[over]).report.refusal_for("big"),
        Some(&Defect::TooManyContributions {
            count: MAX_CONTRIBUTIONS_PER_PLUGIN + 1
        })
    );
}

#[test]
fn a_detail_that_cannot_be_shown_to_the_operator_is_refused() {
    let cases: Vec<(&str, Contribution)> = vec![
        ("empty", skill("s", "   ")),
        ("carrying a control character", hook("e", "rm -rf /\nfake")),
        (
            "longer than the declared limit",
            server("rust", &"x".repeat(MAX_DETAIL_BYTES + 1)),
        ),
    ];
    for (problem, contribution) in cases {
        let composed = compose(&[Manifest::new("p", 1).with(contribution)]);
        match composed.report.refusal_for("p") {
            Some(Defect::UnusableDetail { problem: got, .. }) => assert_eq!(*got, problem),
            other => panic!("{problem} must be refused, got {other:?}"),
        }
        assert!(composed.wiring.is_empty());
    }
}

#[test]
fn an_empty_input_composes_to_an_empty_surface_rather_than_to_a_failure() {
    let composed = compose(&[]);
    assert!(composed.wiring.is_empty());
    assert!(composed.report.is_clean());
    assert!(composed.wiring.contributors().is_empty());
}

// -- the pure half of crash isolation ----------------------------------------------------------

#[test]
fn quarantine_equals_composing_without_the_quarantined_plugin() {
    // A supervisor that drops a faulted member must get the surface it would have had, not a
    // patched one -- otherwise the state after a crash is a state nothing was ever tested in.
    let a = Manifest::new("alpha", 5).with(skill("review", "alpha"));
    let b = Manifest::new("beta", 3)
        .with(agent("planner"))
        .with(hook("pre-tool-use", "beta-hook"));
    let mut host = Host::new(vec![a.clone(), b.clone()]);

    assert!(host.quarantine("alpha", "panicked twice in 60s"));
    assert_eq!(host.composition(), &compose(std::slice::from_ref(&b)));
    assert_eq!(host.quarantined(), vec![("alpha", "panicked twice in 60s")]);
    assert_eq!(
        host.in_service().into_iter().cloned().collect::<Vec<_>>(),
        vec![b]
    );

    // Idempotent: a second fault report for a plugin already out of service changes nothing.
    assert!(!host.quarantine("alpha", "panicked again"));
    assert_eq!(host.quarantined(), vec![("alpha", "panicked twice in 60s")]);
}

#[test]
fn quarantining_a_slot_owner_promotes_the_neighbour_it_was_shadowing() {
    let preferred = Manifest::new("preferred", 9).with(skill("review", "preferred body"));
    let fallback = Manifest::new("fallback", 1).with(skill("review", "fallback body"));
    let mut host = Host::new(vec![preferred, fallback]);
    assert_eq!(host.wiring().skill("review").unwrap().plugin, "preferred");

    host.quarantine("preferred", "hung past its deadline");

    let bound = host.wiring().skill("review").unwrap();
    assert_eq!(bound.plugin, "fallback");
    assert_eq!(bound.detail, "fallback body");
    assert!(
        host.report().contests().is_empty(),
        "with one claimant left there is nothing to contest"
    );
}

#[test]
fn releasing_a_quarantined_plugin_restores_exactly_the_original_surface() {
    let manifests = vec![
        Manifest::new("alpha", 9)
            .with(skill("review", "alpha"))
            .with(hook("pre-tool-use", "alpha-hook")),
        Manifest::new("beta", 1)
            .with(skill("review", "beta"))
            .with(hook("pre-tool-use", "beta-hook")),
    ];
    let original = compose(&manifests);
    let mut host = Host::new(manifests);

    host.quarantine("alpha", "crashed");
    assert_ne!(host.composition(), &original);
    assert_eq!(host.wiring().hooks("pre-tool-use").len(), 1);

    assert!(host.release("alpha"));
    assert_eq!(host.composition(), &original);
    assert!(host.quarantined().is_empty());
    assert!(!host.release("alpha"), "releasing twice reports no change");
}

#[test]
fn quarantining_a_plugin_that_is_not_installed_is_recorded_and_changes_nothing() {
    // A supervisor reporting a fault must never need a "could not quarantine" branch.
    let manifests = vec![Manifest::new("alpha", 1).with(skill("review", "alpha"))];
    let original = compose(&manifests);
    let mut host = Host::new(manifests);

    assert!(host.quarantine("ghost", "reported by a stale supervisor"));

    assert_eq!(host.composition(), &original);
    assert_eq!(
        host.quarantined(),
        vec![("ghost", "reported by a stale supervisor")]
    );
}

#[test]
fn a_refused_manifest_stays_refused_across_a_quarantine_of_someone_else() {
    let mut host = Host::new(vec![
        Manifest::new("rogue", 1).with(skill("bad name!", "d")),
        Manifest::new("alpha", 1).with(skill("review", "alpha")),
        Manifest::new("beta", 1).with(agent("planner")),
    ]);
    assert!(host.report().refusal_for("rogue").is_some());

    host.quarantine("alpha", "crashed");

    assert!(
        host.report().refusal_for("rogue").is_some(),
        "an unrelated quarantine must not change another plugin's admission"
    );
    assert!(host.wiring().skill("review").is_none());
    assert_eq!(host.wiring().contributors(), vec!["beta"]);
}

#[test]
fn a_bounded_json_manifest_carries_every_runtime_surface() {
    let manifest = Manifest::parse_json(
        br#"{
          "plugin":"plantcore-suite",
          "version":[1,2,3],
          "scope":"workspace",
          "precedence":7,
          "capabilities":["read_only","code_executing"],
          "contributions":[
            {"kind":"skill","name":"review","description":"review skill"},
            {"kind":"agent","name":"planner","description":"planning agent"},
            {"kind":"hook","event":"pre_tool","action":"bin/check"},
            {"kind":"mcp_server","name":"files","binding":"stdio:bin/files"},
            {"kind":"language_server","language":"rust","command":"rust-analyzer"}
          ]
        }"#,
    )
    .unwrap();
    let composition = compose(&[manifest]);
    assert!(composition.wiring.skill("review").is_some());
    assert!(composition.wiring.agent("planner").is_some());
    assert_eq!(composition.wiring.hooks("pre_tool").len(), 1);
    assert!(composition.wiring.mcp_server("files").is_some());
    assert!(composition.wiring.language_server("rust").is_some());
}

#[test]
fn scope_dependency_version_and_capability_ceiling_are_enforced_together() {
    let base = Manifest::new("base", 1)
        .at_version(crate::Version(2, 0, 0))
        .with(skill("base", "base"));
    let workspace = Manifest::new("workspace", 1)
        .at_version(crate::Version(1, 0, 0))
        .scoped(PluginScope::Workspace)
        .requiring("base", crate::Version(2, 0, 0))
        .with_capabilities(CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]))
        .with(mcp("repo", "stdio:repo-server"));
    let ceiling = CapabilitySet::only(Capability::ReadOnly);

    let user = compose_governed(
        &[base.clone(), workspace.clone()],
        RuntimeScope::User,
        ceiling,
    );
    assert!(user.wiring.mcp_server("repo").is_none());
    assert!(user.report.refusal_for("workspace").is_none());

    let workspace_composition = compose_governed(
        &[base.clone(), workspace.clone()],
        RuntimeScope::Workspace,
        ceiling,
    );
    let binding = workspace_composition.wiring.mcp_server("repo").unwrap();
    assert!(binding.capabilities.contains(Capability::ReadOnly));
    assert!(!binding.capabilities.contains(Capability::CodeExecuting));

    let old_base = base.at_version(crate::Version(1, 9, 9));
    let refused = compose_governed(&[old_base, workspace], RuntimeScope::Workspace, ceiling);
    assert!(matches!(
        refused.report.refusal_for("workspace"),
        Some(Defect::DependencyTooOld { .. })
    ));
    assert!(refused.wiring.mcp_server("repo").is_none());
}

#[test]
fn a_dependency_refusal_cascades_without_resurrecting_a_dead_manifest() {
    let broken = Manifest::new("broken", 1)
        .requiring("missing", crate::Version(1, 0, 0))
        .with(skill("broken", "broken"));
    let dependent = Manifest::new("dependent", 1)
        .requiring("broken", crate::Version::default())
        .with(agent("dependent"));
    let composition = compose(&[broken, dependent]);
    assert!(matches!(
        composition.report.refusal_for("broken"),
        Some(Defect::MissingDependency { .. })
    ));
    assert!(matches!(
        composition.report.refusal_for("dependent"),
        Some(Defect::MissingDependency { .. })
    ));
    assert!(composition.wiring.is_empty());
}
