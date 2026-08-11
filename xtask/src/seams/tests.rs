use super::source::{
    TRUSTED_CANONICAL_SEAM_SOURCE, find_trait_impl, include_targets, is_test_path,
    macro_bodies_mention, mentioned_identifiers, normalise, resolve_alias_closure,
};
use super::{SATISFIABILITY_TEST, SEAMS, validate_sources};
use std::collections::BTreeSet;

const TEST_SEAMS: &[&str] = &["TrajectoryProjection", "HeldOutEvidenceBridge"];
const CANONICAL_EVOLVE_ROOT: &str = "\
mod held_out;
mod seams;
mod trajectory_projection;
pub use seams::{HeldOutEvidenceBridge, TrajectoryProjection};
";

fn implements(source: &str) -> bool {
    let names = resolve_alias_closure(&[("x.rs".into(), source.to_owned(), BTreeSet::new())]);
    let file = syn::parse_file(source).expect("parses");
    find_trait_impl(&file, &names).is_some()
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn source(path: &str, source: impl Into<String>) -> (String, String, BTreeSet<String>) {
    (path.to_owned(), source.into(), [path.to_owned()].into())
}

fn held_out_sources(implementation: &str) -> Vec<(String, String, BTreeSet<String>)> {
    vec![
        source("crates/evolve/src/lib.rs", CANONICAL_EVOLVE_ROOT),
        source(
            "crates/evolve/src/held_out.rs",
            format!("use crate::{{HeldOutEvidenceBridge, Other}};\n{implementation}"),
        ),
    ]
}

fn validate_transition(
    remaining: &[&str],
    mut sources: Vec<(String, String, BTreeSet<String>)>,
) -> anyhow::Result<()> {
    if !sources
        .iter()
        .any(|(path, _, _)| path == "crates/evolve/src/lib.rs")
    {
        sources.push(source("crates/evolve/src/lib.rs", CANONICAL_EVOLVE_ROOT));
    }
    if !sources
        .iter()
        .any(|(path, _, _)| path == "crates/evolve/src/seams.rs")
    {
        sources.push(source(
            "crates/evolve/src/seams.rs",
            TRUSTED_CANONICAL_SEAM_SOURCE,
        ));
    }
    if !sources
        .iter()
        .any(|(path, _, _)| path == SATISFIABILITY_TEST)
    {
        sources.push(source(SATISFIABILITY_TEST, ""));
    }
    let transition =
        super::transition::Transition::from_sets(TEST_SEAMS, names(remaining)).expect("subset");
    validate_sources(&sources, &transition)
}

#[test]
fn removing_a_seam_requires_an_explicit_non_test_impl() {
    for decoy in [
        vec![],
        vec![source(
            SATISFIABILITY_TEST,
            "impl HeldOutEvidenceBridge for TestOnly {}",
        )],
        vec![source(
            "crates/evolve/examples/bridge.rs",
            "impl HeldOutEvidenceBridge for ExampleOnly {}",
        )],
        vec![source(
            "crates/evolve/build.rs",
            "impl HeldOutEvidenceBridge for BuildOnly {}",
        )],
        vec![source(
            "crates/evolve/src/bridge.rs",
            "macro_rules! bridge { () => { impl HeldOutEvidenceBridge for MacroOnly {} } }",
        )],
        vec![source(
            "crates/evolve/src/bridge.rs",
            "const CLAIM: &str = \"impl HeldOutEvidenceBridge for StringOnly\";",
        )],
        vec![source(
            "crates/evolve/src/bridge.rs",
            "// impl HeldOutEvidenceBridge for CommentOnly",
        )],
        vec![
            source(
                "crates/evolve/src/lib.rs",
                "mod seams;\n\
                 mod trajectory_projection;\n\
                 pub use seams::{HeldOutEvidenceBridge, TrajectoryProjection};",
            ),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for Unreferenced {}",
            ),
        ],
        held_out_sources("#[cfg(any())]\nimpl HeldOutEvidenceBridge for CfgDisabled {}"),
        vec![
            source("crates/evolve/src/lib.rs", "mod held_out;"),
            source(
                "crates/evolve/src/held_out.rs",
                "#![cfg(any())]\nuse crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for FileDisabled {}",
            ),
        ],
        vec![
            source("crates/evolve/src/lib.rs", "#![cfg(any())]\nmod held_out;"),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for LibraryDisabled {}",
            ),
        ],
        vec![
            source("crates/evolve/src/lib.rs", "#[cfg(any())]\nmod held_out;"),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for ModuleDisabled {}",
            ),
        ],
        vec![
            source(
                "crates/evolve/src/lib.rs",
                "#[path = \"held_out.rs\"]\nmod held_out;",
            ),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                     impl HeldOutEvidenceBridge for RedirectedModule {}",
            ),
        ],
        vec![
            source("crates/evolve/src/lib.rs", "mod held_out {}"),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for UnwiredFile {}",
            ),
        ],
        vec![
            source("crates/evolve/src/lib.rs", "mod held_out;"),
            source(
                "crates/evolve/src/held_out.rs",
                "trait HeldOutEvidenceBridge {}\n\
                 impl HeldOutEvidenceBridge for SameNamedLocalTrait {}",
            ),
        ],
        vec![
            source("crates/evolve/src/lib.rs", "mod held_out;"),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge as EvidencePort;\n\
                 impl EvidencePort for AliasedDecoy {}",
            ),
        ],
    ] {
        assert!(
            validate_transition(&["TrajectoryProjection"], decoy).is_err(),
            "a non-implementation satisfied a registry removal"
        );
    }
}

#[test]
fn a_real_impl_satisfies_only_the_seam_removed_from_the_registry() {
    validate_transition(
        &["TrajectoryProjection"],
        held_out_sources("impl HeldOutEvidenceBridge for EvidenceStore {}"),
    )
    .unwrap();

    assert!(
        validate_transition(
            &["TrajectoryProjection"],
            held_out_sources(
                "impl HeldOutEvidenceBridge for EvidenceStore {}\n\
                 impl TrajectoryProjection for EvidenceStore {}"
            ),
        )
        .is_err(),
        "an implementation of a still-declared seam escaped the gate"
    );
}

#[test]
fn a_removed_seam_needs_its_exact_crate_binding_not_an_alias_or_test_impl() {
    assert!(
        validate_transition(
            &["TrajectoryProjection"],
            held_out_sources("impl EvidencePort for Aliased {}"),
        )
        .is_err()
    );
    assert!(
        validate_transition(
            &["TrajectoryProjection"],
            vec![source(
                SATISFIABILITY_TEST,
                "use iteron_evolve::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for TestOnly {}",
            )],
        )
        .is_err()
    );
}

#[test]
fn a_crate_root_alias_and_same_named_decoy_do_not_implement_the_frozen_trait() {
    let decoy_root = "\
mod held_out;
mod seams;
mod trajectory_projection;
pub use seams::{
    HeldOutEvidenceBridge as FrozenHeldOutEvidenceBridge,
    TrajectoryProjection,
};
pub trait HeldOutEvidenceBridge {}
";
    assert!(
        validate_transition(
            &["TrajectoryProjection"],
            vec![
                source("crates/evolve/src/lib.rs", decoy_root),
                source(
                    "crates/evolve/src/held_out.rs",
                    "use crate::HeldOutEvidenceBridge;\n\
                     impl HeldOutEvidenceBridge for DecoyStore {}",
                ),
            ],
        )
        .is_err(),
        "a crate-root decoy satisfied retirement of the frozen trait"
    );
}

#[test]
fn changing_the_frozen_trait_source_cannot_satisfy_a_transition() {
    let redirected = TRUSTED_CANONICAL_SEAM_SOURCE.replacen(
        "pub trait HeldOutEvidenceBridge",
        "pub trait HeldOutEvidenceBridgeReplacement",
        1,
    );
    assert!(
        validate_transition(
            &["TrajectoryProjection"],
            vec![
                source("crates/evolve/src/lib.rs", CANONICAL_EVOLVE_ROOT),
                source("crates/evolve/src/seams.rs", redirected),
                source(
                    "crates/evolve/src/held_out.rs",
                    "use crate::HeldOutEvidenceBridge;\n\
                     impl HeldOutEvidenceBridge for DecoyStore {}",
                ),
            ],
        )
        .is_err(),
        "a rewritten frozen trait declaration satisfied retirement"
    );
}

#[test]
fn removing_every_seam_requires_every_real_impl_and_no_longer_needs_the_stub_proof() {
    let transition = super::transition::Transition::from_sets(TEST_SEAMS, BTreeSet::new()).unwrap();
    validate_sources(
        &[
            source("crates/evolve/src/lib.rs", CANONICAL_EVOLVE_ROOT),
            source("crates/evolve/src/seams.rs", TRUSTED_CANONICAL_SEAM_SOURCE),
            source(
                "crates/evolve/src/held_out.rs",
                "use crate::HeldOutEvidenceBridge;\n\
                 impl HeldOutEvidenceBridge for EvidenceStore {}",
            ),
            source(
                "crates/evolve/src/trajectory_projection.rs",
                "use crate::TrajectoryProjection;\n\
                 impl TrajectoryProjection for RunProjector {}",
            ),
        ],
        &transition,
    )
    .unwrap();
}

#[test]
fn the_shapes_that_defeated_the_byte_scanner_are_all_answered() {
    // Most of these walked past a hand-rolled scanner in one of four adversarial reviews; the
    // exceptions are labelled. A parser answers all of them without a single special case.
    //
    // The name used to say "thirteen", which was wrong twice over: the four alias shapes the
    // module docs count among the bypasses are asserted in the next test, not this one, and one
    // entry here never defeated anything. A number in a test name is a claim like any other.
    for source in [
        "impl<T> TrajectoryProjection for T {}",
        "impl  TrajectoryProjection  for  X {}",
        "impl\n  TrajectoryProjection\n  for X {}",
        "impl crate::seams::TrajectoryProjection for X {}",
        "impl<T: Fn() -> u32> TrajectoryProjection for T {}",
        "impl<T: M<{ 1 > 0 }>> TrajectoryProjection for T {}",
        "impl<T: M<{ 1 << 2 }>> TrajectoryProjection for T {}",
        // Not a historical bypass — it contains the literal substring the v1 scanner matched.
        // Kept as ordinary regression coverage, labelled honestly: a review pointed out that the
        // array was padded with shapes presented as defeats when they were not.
        "impl TrajectoryProjection for (A, B) {}",
        "impl<'a, T> TrajectoryProjection for &'a T {}",
        "impl\u{0b}TrajectoryProjection\u{0b}for X {}",
        "impl/*x*/TrajectoryProjection/*y*/for X {}",
        "impl r#TrajectoryProjection for X {}",
        "mod inner { impl TrajectoryProjection for X {} }",
        "const G: &str = \"/*\";\nimpl TrajectoryProjection for X {}",
    ] {
        assert!(implements(source), "not caught: {source}");
    }
}

#[test]
fn aliases_are_resolved_across_files_and_through_chains() {
    // Four separate bypasses of a one-hop, same-file, ASCII-only alias resolver.
    let cross_file = [
        (
            "a.rs".to_owned(),
            "pub(crate) use crate::seams::TrajectoryProjection as Proj;".to_owned(),
            BTreeSet::new(),
        ),
        (
            "b.rs".to_owned(),
            "use crate::a::Proj; impl Proj for Evil {}".to_owned(),
            BTreeSet::new(),
        ),
    ];
    let names = resolve_alias_closure(&cross_file);
    let file = syn::parse_file(&cross_file[1].1).expect("parses");
    assert!(find_trait_impl(&file, &names).is_some(), "cross-file alias");

    assert!(
        implements(
            "use crate::seams::TrajectoryProjection as A; use self::A as Bee; impl Bee for X {}"
        ),
        "chained alias"
    );
    assert!(
        implements("use crate::seams::TrajectoryProjection as 投影; impl 投影 for X {}"),
        "non-ASCII alias"
    );
    assert!(
        implements("use crate::seams::TrajectoryProjection as\n    Proj;\nimpl Proj for X {}"),
        "`as` followed by a newline"
    );
}

#[test]
fn the_things_that_are_not_a_trait_impl_are_not_reported() {
    for source in [
        "impl TrajectoryProjection { fn new() {} }",
        "impl OtherTrait for X {}",
        "fn f(x: &dyn TrajectoryProjection) {}",
        "fn f() -> impl TrajectoryProjection { todo!() }",
        "const M: &str = \"impl TrajectoryProjection for X\";",
        "// impl TrajectoryProjection for X\npub struct X;",
    ] {
        assert!(!implements(source), "false positive: {source}");
    }
}

#[test]
fn an_alias_declared_at_any_nesting_still_resolves() {
    // Found by auditing for the pattern rather than waiting for a seventh review to demonstrate
    // it: `collect_use_renames` was the last shallow walk left, so an alias declared inside a
    // `const _` block or a function body never entered the closure and the impl using it was not
    // recognised. Reproduced live against the real gate before this fix.
    for source in [
        "const _: () = { use crate::seams::TrajectoryProjection as P; impl P for E {} };",
        "fn f() { use crate::seams::TrajectoryProjection as P; impl P for E {} }",
        "mod m { fn g() { mod n { use crate::seams::TrajectoryProjection as P; impl P for E {} } } }",
    ] {
        assert!(implements(source), "not caught: {source}");
    }
}

#[test]
fn a_macro_and_an_include_are_found_at_any_nesting_too() {
    // `find_trait_impl` became a full visitor while its two SIBLING helpers stayed a shallow
    // `file.items` walk — the same defect, in the commit named after it. Three live bypasses
    // followed, all silent through the gate, clippy -D warnings and fmt.
    let seams: BTreeSet<String> = ["TrajectoryProjection".to_owned()].into();
    let in_const = syn::parse_file(
        "const _: () = { macro_rules! w { ($t:ty) => { impl TrajectoryProjection for $t {} }; } };",
    )
    .expect("parses");
    assert!(
        macro_bodies_mention(&in_const, &seams).is_some(),
        "a macro_rules! inside a const block spelling the seam"
    );
    let in_fn = syn::parse_file(
        "fn f() { macro_rules! w { ($t:ty) => { impl TrajectoryProjection for $t {} }; } }",
    )
    .expect("parses");
    assert!(macro_bodies_mention(&in_fn, &seams).is_some());

    // Alias-aware: the token search asks about the resolved closure, not the canonical name.
    // Searching SEAMS while the impl finder searched `names` was a live bypass.
    let aliased = syn::parse_file(
        "use crate::seams::TrajectoryProjection as Proj; macro_rules! w { ($t:ty) => { impl Proj for $t {} }; }",
    )
    .expect("parses");
    let closure = resolve_alias_closure(&[(
        "x.rs".into(),
        "use crate::seams::TrajectoryProjection as Proj;".to_owned(),
        BTreeSet::new(),
    )]);
    assert_eq!(
        macro_bodies_mention(&aliased, &closure).as_deref(),
        Some("Proj"),
        "a macro spelling a resolved alias was caught by nothing"
    );

    // `include!` below top level, and spelled with a path prefix.
    assert_eq!(
        include_targets("fn f() { mod m { include!(\"a.inc\"); } }"),
        vec!["a.inc".to_owned()],
        "an include! nested in a fn body removed the target from the scan entirely"
    );
    assert_eq!(
        include_targets("std::include!(\"b.inc\");"),
        vec!["b.inc".to_owned()]
    );
    assert_eq!(
        include_targets("iteron::include!(\"c.inc\");"),
        vec!["c.inc".to_owned()]
    );
    // The name is not what is matched any more: a review renamed the macro on import and the
    // target vanished from the scan. Anything whose whole body is one string literal counts.
    assert_eq!(
        include_targets("use std::include as pull; pull!(\"d.inc\");"),
        vec!["d.inc".to_owned()],
        "a renamed include import removed the target from the scan"
    );
}

#[test]
fn an_impl_nested_inside_any_item_is_still_an_impl() {
    // rustc registers a trait impl crate-globally however deeply it is nested. A walk over
    // `file.items` saw none of these; all three were live public runtime paths, silent through
    // the gate, fmt, clippy -D warnings and the whole test suite.
    for source in [
        "const _: () = { impl TrajectoryProjection for Evil {} };",
        "pub fn wire() { impl TrajectoryProjection for Evil {} }",
        "static _X: () = { impl TrajectoryProjection for Evil {} };",
        "impl Other { fn f() { impl TrajectoryProjection for Evil {} } }",
    ] {
        assert!(implements(source), "not caught: {source}");
    }
}

#[test]
fn a_tests_directory_inside_src_is_not_a_test_target() {
    // The exemption that let a non-`#[cfg(test)]` module compile a seam impl into the real
    // crate, silent through every gate in the repo.
    assert!(!is_test_path("crates/evolve/src/tests/projection.rs"));
    assert!(!is_test_path("crates/evolve/src/sub/tests/mod.rs"));
    assert!(!is_test_path("crates/evolve/src/benches/x.rs"));
    // And the real ones still are.
    assert!(is_test_path("crates/evolve/tests/seam_satisfiability.rs"));
    assert!(is_test_path("crates/evolve/benches/throughput.rs"));
    assert!(is_test_path("crates/evolve/tests/nested/deep.rs"));
}

#[test]
fn include_targets_are_normalised_to_repository_paths() {
    assert_eq!(
        normalise("crates/evolve/src/./zz.inc"),
        "crates/evolve/src/zz.inc"
    );
    assert_eq!(
        normalise("crates/evolve/src/../src/zz.inc"),
        "crates/evolve/src/zz.inc"
    );
}

#[test]
fn a_macro_that_spells_the_trait_literally_is_still_found() {
    let source = "macro_rules! wire { ($t:ty) => { impl TrajectoryProjection for $t {} }; }";
    let file = syn::parse_file(source).expect("parses");
    let seams: BTreeSet<String> = ["TrajectoryProjection".to_owned()].into();
    assert!(macro_bodies_mention(&file, &seams).is_some());
    // A macro taking the trait as a metavariable is the documented limit.
    let opaque = syn::parse_file("macro_rules! w { ($tr:path, $t:ty) => { impl $tr for $t {} }; }")
        .expect("parses");
    assert!(macro_bodies_mention(&opaque, &seams).is_none());
}

#[test]
fn identifiers_are_seen_but_strings_and_comments_are_not() {
    let named = syn::parse_file("type X = dyn TrajectoryProjection;").expect("parses");
    assert!(mentioned_identifiers(&named).contains("TrajectoryProjection"));
    let prose =
        syn::parse_file("/// TrajectoryProjection is forbidden\npub struct X;").expect("parses");
    assert!(!mentioned_identifiers(&prose).contains("TrajectoryProjection"));
    let string = syn::parse_file("const M: &str = \"TrajectoryProjection\";").expect("parses");
    assert!(!mentioned_identifiers(&string).contains("TrajectoryProjection"));
}

#[test]
fn the_candidate_registry_stays_within_the_initial_trusted_set() {
    let unique = SEAMS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), SEAMS.len());
    assert!(SEAMS.iter().all(|seam| TEST_SEAMS.contains(seam)));
}
