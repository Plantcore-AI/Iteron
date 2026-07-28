//! The declared-not-implemented gate for the W1 cross-owner seams.
//!
//! # Why this is a build gate and not a test
//!
//! "Declared but not implemented" is a property of **absence**. A test asserting that a stub returns
//! a not-implemented error proves only that someone wrote that error into that function; it says
//! nothing about whether a second, real implementation exists three files away. The property can
//! only be checked over the whole tree, so it is checked here.
//!
//! This also replaces what a shipped `Stub` would have been. A stub is a public, importable type
//! that satisfies the trait bound forever, and nothing forces its removal before release — it would
//! make the companion criterion, "referenced by no runtime path", permanently unenforceable.
//!
//! # Why this parses instead of scanning bytes
//!
//! The first four versions of this gate were a hand-rolled byte scanner, and four consecutive
//! adversarial reviews walked past it a combined **thirteen** times. Every fix was correct and every
//! fix was narrow — a two-byte special case for `->`, a one-hop same-file ASCII alias resolver, a
//! `for`-without-whitespace check, a wider whitespace predicate — and the next reviewer simply moved
//! one notch sideways: `impl<T: M<{ 1 > 0 }>> Seam for T` (a blanket impl, and fmt-clean),
//! `impl/*x*/Seam/*y*/for T`, a cross-file alias, a chained alias, a non-ASCII alias, `as` followed
//! by a newline.
//!
//! The fourth reviewer named the root cause, and it was not any of those thirteen: *a byte scanner
//! was being asked a question about Rust semantics, and each round patched the spelling the previous
//! reviewer happened to use. Patching these will produce a fourteenth.* So this now parses with
//! `syn`, which `core-xtask` already depends on and which `xtask/src/rust_source*.rs` already uses
//! for exactly this kind of work. Every one of the thirteen becomes a non-question: `syn` knows what
//! an `impl` header is, what a comment is, what a string is, and what balanced generics are.
//!
//! # What this gate does NOT catch
//!
//! Written down because a gate whose limits are unstated gets read as a guarantee it never made —
//! and because an earlier version of this section said "these three are real and remain", which was
//! itself a completeness claim in prose, and was then walked past nine more times.
//!
//! - **A macro that takes the trait as a metavariable.** `macro_rules! wire { ($tr:path, $ty:ty) =>
//!   { impl $tr for $ty {} } }` never names the trait at its definition, so no source-level analysis
//!   can see it; closing it means expanding macros, i.e. being the compiler.
//!
//!   A macro that spells the trait *literally* IS caught, at any nesting and in any crate. That
//!   sentence shipped FALSE in three consecutive rounds, each time for a different reason: first the
//!   search did not exist; then it ran only on non-owning crates, i.e. never where such a macro can
//!   legally live; then it walked only `file.items`, so a `macro_rules!` inside `const _ = { .. }`
//!   was invisible. It is true now because [`macro_bodies_name_seam`] is a `syn::visit` visitor, and
//!   there is a test per spelling. The history is attached deliberately — a claim this file has been
//!   wrong about three times should not read as settled.
//! - **Files git does not list.** The file list comes from `git ls-files --cached --others
//!   --exclude-standard`, so a `.gitignore`d source file that still compiles is invisible.
//! - **Anything rooted outside `crates/`.** [`collect_sources`] starts only from paths under
//!   `crates/`, so a workspace member elsewhere — `xtask/`, `release-tools/` — is never a starting
//!   point. It reaches OUT of `crates/` through `include!`, but never IN. Nothing outside `crates/`
//!   depends on `core-evolve` today; that is an assumption, recorded so it can be rechecked rather
//!   than assumed. This is NOT covered by the `#[path]` bullet below: those crates have owning
//!   boundaries, so `validate_path_coverage` is satisfied by them and never fires.
//!
//!   This limit was written down once, dropped in a rewrite, and then a commit message claimed to
//!   have restored it while the diff showed the module doc byte-identical to its parent — the edit
//!   lived in a script that aborted on an earlier assertion and nobody checked the result. It is
//!   here now.
//! - **Source pulled in from outside `crates/`** via `#[path]`. That is backstopped by a different
//!   rule — `boundaries check`'s file-coverage check refuses any repository file with no owning
//!   boundary — so a new file at the repo root fails there before reaching this gate. Recorded
//!   because relying on an adjacent gate is a real dependency, not an absence of risk.
//!
//! **This list is what is known to be uncovered. It is not a proof that nothing else is.**
//!
//! # For whoever lands the first real implementation
//!
//! Issue #27 (`HeldOutEvidenceBridge`) deletes its entry from [`SEAMS`] **in the same commit** that
//! lands the implementation, so the transition from promise to code is visible in the diff.
//!
//! Issue #28 has nothing to delete: bundle resolution is not policed here, because the port lives in
//! `core_protocol::bundle` where both sides of the seam already depend on it.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

/// The traits that must remain declared and unimplemented.
///
/// `PolicyBundleResolver` is deliberately absent: it lives in `core-protocol`, is declared over
/// `ResolvedBundle`, and both sides of its seam already depend on that crate, so naming it costs
/// nobody a dependency and there is nothing to police.
const SEAMS: &[&str] = &["TrajectoryProjection", "HeldOutEvidenceBridge"];

/// The one crate permitted to declare and name the seams above.
const OWNING_CRATE: &str = "crates/evolve/";

/// The integration test that proves the seams are implementable from outside.
const SATISFIABILITY_TEST: &str = "crates/evolve/tests/seam_satisfiability.rs";

/// Internal crates whose appearance in [`SATISFIABILITY_TEST`] would void the proof it exists to
/// make. An integration test inherits its crate's `[dependencies]`, so `core_protocol` compiles
/// there even though an outside implementor may hold only `core-evolve` — position alone proves
/// nothing, and this is what makes the single-dependency claim mechanical.
const INTERNAL_CRATE_PREFIX: &str = "core_";

pub(crate) fn validate(root: &Path, files: &[String]) -> Result<()> {
    let sources = collect_sources(root, files);

    // Aliases are resolved across the WHOLE tree, then to a fixpoint. A per-file, one-hop resolver
    // was walked past four ways: `use ..::Seam as Proj;` in one file with `impl Proj for X` in
    // another; `use ..::Seam as A; use self::A as Bee;`; a non-ASCII alias; and `as` followed by a
    // newline. An alias is a graph, so it is resolved as one.
    let names = resolve_alias_closure(&sources);

    let mut satisfiability_test_seen = false;
    for (relative, source, roots) in &sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("`{relative}` does not parse as Rust"))?;

        // A `macro_rules!` body is a template, not code, so no AST can tell whether it will be
        // invoked. It is treated as an implementation wherever it spells a seam, including inside
        // the owning crate. The previous version only searched macro bodies in NON-owning crates —
        // and the owning crate is the one place such a macro can legally live, so the check never ran
        // where it mattered. A review minted a live public runtime path that way, silent through
        // every gate in the repo, under a module doc claiming that exact case was covered.
        let via_macro = SEAMS
            .iter()
            .find(|seam| macro_bodies_name_seam(&file, seam))
            .map(|seam| (*seam).to_owned());
        if let Some(found) = find_trait_impl(&file, &names).or(via_macro)
            && !is_test_path(relative)
        {
            bail!(
                "`{relative}` implements the `{found}` seam outside a test target.\n\
                     These seams are declared, not implemented; the frozen contract says no \
                     runtime path references them.\n\
                     If this is the first real implementation, delete it from SEAMS in \
                  xtask/src/seams.rs in the same commit, so the change is visible in the diff."
            );
        }

        for seam in SEAMS {
            // Read from the parsed source, so a seam named in a doc comment or inside a string
            // literal is not a reference. Both directions of that were real bugs once.
            if !relative.starts_with(OWNING_CRATE) && identifiers_name_seam(&file, seam) {
                bail!(
                    "`{relative}` names the `{seam}` seam, but only `{OWNING_CRATE}` may.\n\
                     A crate that names it has begun consuming a seam that nothing implements."
                );
            }
        }

        // Applied to the proof AND to everything it includes: a review moved a `core_protocol`
        // import into a sibling `.inc` the test pulled in, and the check — keyed on the file's own
        // path — never saw it. Content a proof includes is part of the proof.
        if roots.contains(SATISFIABILITY_TEST) {
            if relative == SATISFIABILITY_TEST {
                satisfiability_test_seen = true;
            }
            validate_single_dependency(relative, &file)?;
        }
    }

    if !satisfiability_test_seen {
        bail!(
            "`{SATISFIABILITY_TEST}` is missing.\n\
             It is the only proof that the declared seams can be implemented by a crate that holds \
             `core-evolve` and nothing else. Without it the seams are unverified declarations."
        );
    }
    Ok(())
}

/// Every Rust source file under `crates/`, and everything reachable from one through `include!`.
///
/// # Why this runs to a fixpoint
///
/// The extension filter used to be `ends_with(".rs")` alone, and a review put a plain
/// `impl TrajectoryProjection for Evil` in `crates/evolve/src/zz.inc` and `include!`d it: inside
/// `crates/`, listed by git, covered by no documented limit, and never looked at. That was fixed by
/// collecting `include!` targets — but only from files that passed the same `.rs` filter, so the
/// next review chained one more hop (`a.rs -> b.inc -> c.inc`) and the leaf was invisible again.
///
/// A one-level fix to a reachability problem is not a fix, so this is a worklist with a visited set:
/// every collected source is itself searched for `include!`, to a fixpoint, and a cycle terminates
/// rather than looping.
///
/// Returned as `(path, source, roots)` where `roots` is the set of `.rs` files this source was
/// reached from, so [`validate_single_dependency`] can be applied to everything the satisfiability
/// proof pulls in, not only to the file that bears its name.
fn collect_sources(root: &Path, files: &[String]) -> Vec<(String, String, BTreeSet<String>)> {
    let mut collected: Vec<(String, String, BTreeSet<String>)> = Vec::new();
    let mut queue: Vec<(String, String)> = Vec::new();

    for relative in files {
        if !relative.starts_with("crates/") || !relative.ends_with(".rs") {
            continue;
        }
        if let Ok(source) = std::fs::read_to_string(root.join(relative)) {
            queue.push((relative.clone(), relative.clone()));
            collected.push((relative.clone(), source, [relative.clone()].into()));
        }
    }

    // Worklist: (path to expand, the `.rs` root it was reached from).
    let mut visited: BTreeSet<(String, String)> = queue.iter().cloned().collect();
    while let Some((relative, origin)) = queue.pop() {
        let Some((_, source, _)) = collected.iter().find(|(path, _, _)| *path == relative) else {
            continue;
        };
        let targets = include_targets(source);
        for target in targets {
            let Some(directory) = Path::new(&relative).parent() else {
                continue;
            };
            let Some(joined) = directory.join(&target).to_str().map(normalise) else {
                continue;
            };
            if !visited.insert((joined.clone(), origin.clone())) {
                continue;
            }
            if let Some((_, _, roots)) = collected.iter_mut().find(|(path, _, _)| *path == joined) {
                roots.insert(origin.clone());
            } else if let Ok(source) = std::fs::read_to_string(root.join(&joined)) {
                collected.push((joined.clone(), source, [origin.clone()].into()));
            } else {
                continue;
            }
            queue.push((joined, origin.clone()));
        }
    }
    collected
}

/// Collapse `a/./b` and `a/b/../c`, so an `include!("../x.inc")` matches the path git reports.
fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// String arguments of every `include!(..)` in this file, at any nesting and however it is spelled.
///
/// Two bypasses closed here, both found after `collect_sources` was correctly made a fixpoint over
/// the file graph — the per-file extraction feeding that fixpoint was still one level deep and one
/// spelling wide:
///
/// - `pub fn f() { mod hidden { include!("x.inc"); } }` — an `include!` below top level. The target
///   was never collected at all, so the plainest possible `impl Seam for Evil` inside it was
///   invisible.
/// - `std::include!("x.inc")` — matching the macro path with `is_ident("include")` is false for a
///   two-segment path, so one keyword prefix removed a file from the scan. The last segment is what
///   names the macro, so that is what is compared.
fn include_targets(source: &str) -> Vec<String> {
    let Ok(file) = syn::parse_file(source) else {
        return Vec::new();
    };
    struct Finder {
        targets: Vec<String>,
    }
    impl syn::visit::Visit<'_> for Finder {
        fn visit_macro(&mut self, mac: &syn::Macro) {
            if mac
                .path
                .segments
                .last()
                .is_some_and(|last| last.ident == "include")
                && let Ok(literal) = mac.parse_body::<syn::LitStr>()
            {
                self.targets.push(literal.value());
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut finder = Finder {
        targets: Vec::new(),
    };
    syn::visit::visit_file(&mut finder, &file);
    finder.targets
}

/// Every name that resolves to a seam anywhere in the tree, to a fixpoint.
fn resolve_alias_closure(sources: &[(String, String, BTreeSet<String>)]) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = SEAMS.iter().map(|seam| (*seam).to_owned()).collect();
    let mut edges: Vec<(String, String)> = Vec::new();
    for (_, source, _) in sources {
        let Ok(file) = syn::parse_file(source) else {
            continue;
        };
        collect_use_renames(&file.items, &mut edges);
    }
    loop {
        let before = names.len();
        for (alias, original) in &edges {
            if names.contains(original) {
                names.insert(alias.clone());
            }
        }
        if names.len() == before {
            return names;
        }
    }
}

fn collect_use_renames(items: &[syn::Item], edges: &mut Vec<(String, String)>) {
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, inner)) = &module.content {
                    collect_use_renames(inner, edges);
                }
            }
            syn::Item::Use(item) => walk_use_tree(&item.tree, edges),
            _ => {}
        }
    }
}

fn walk_use_tree(tree: &syn::UseTree, edges: &mut Vec<(String, String)>) {
    match tree {
        syn::UseTree::Path(path) => walk_use_tree(&path.tree, edges),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                walk_use_tree(item, edges);
            }
        }
        syn::UseTree::Rename(rename) => {
            edges.push((rename.rename.to_string(), rename.ident.to_string()));
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

/// The first trait impl anywhere in this file whose trait resolves to a seam.
///
/// # Why this is a full visitor and not a walk over `file.items`
///
/// The previous version recursed only into `syn::Item::Mod`, and a review put a seam implementation
/// in three places it therefore never looked:
///
/// - `const _: () = { impl Seam for Evil { .. } };` — the anonymous const block, which is the exact
///   idiom every derive macro emits, so it reads as ordinary code in review, and which rustc's
///   `non_local_definitions` lint deliberately exempts.
/// - a function body — caught only by that same lint, i.e. by an adjacent tool.
/// - a `static`, an associated function, anywhere else an item may be declared.
///
/// All three compiled, were reachable through a public function, and were silent through this gate,
/// `cargo fmt --check`, `cargo clippy -D warnings` AND the whole test suite. rustc registers a trait
/// impl crate-globally no matter how deeply it is nested, so anything less than a full traversal is
/// asking a shallower question than the contract does. `syn::visit` descends into expressions and
/// blocks, so this sees every `impl` present in the parsed AST — which is strictly more than a walk
/// over `file.items` saw, and strictly less than "every `impl` the compiler sees". Two things arrive
/// after parsing and are handled by separate mechanisms rather than by this one:
/// [`macro_bodies_name_seam`] for macro-generated impls and [`collect_sources`] for `include!`.
fn find_trait_impl(file: &syn::File, names: &BTreeSet<String>) -> Option<String> {
    struct Finder<'a> {
        names: &'a BTreeSet<String>,
        found: Option<String>,
    }
    impl syn::visit::Visit<'_> for Finder<'_> {
        fn visit_item_impl(&mut self, item: &syn::ItemImpl) {
            if let Some((_, path, _)) = &item.trait_
                && let Some(last) = path.segments.last()
            {
                let name = last.ident.to_string();
                if self.names.contains(&name) && self.found.is_none() {
                    self.found = Some(name);
                }
            }
            syn::visit::visit_item_impl(self, item);
        }
    }
    let mut finder = Finder { names, found: None };
    syn::visit::visit_file(&mut finder, file);
    finder.found
}

/// Does any identifier in the parsed file spell `seam`?
///
/// Walks the AST rather than the text, so a mention in a doc comment or inside a string literal is
/// not a reference — which was a real false positive once, on a constant whose entire content was a
/// warning not to implement the seam.
fn identifiers_name_seam(file: &syn::File, seam: &str) -> bool {
    struct Finder<'a> {
        seam: &'a str,
        found: bool,
    }
    impl syn::visit::Visit<'_> for Finder<'_> {
        fn visit_ident(&mut self, ident: &syn::Ident) {
            if ident == self.seam {
                self.found = true;
            }
        }
    }
    let mut finder = Finder { seam, found: false };
    syn::visit::visit_file(&mut finder, file);
    finder.found
}

/// Does any macro body anywhere in this file spell `seam`?
///
/// # Why this is a visitor and not a walk over `file.items`
///
/// `find_trait_impl` was converted to a full `syn::visit` visitor after a review found seam impls
/// hiding in `const _: () = { .. }` blocks and function bodies. Its two sibling helpers were left as
/// the same shallow `file.items` + `Item::Mod` walk with a `_ => {}` arm — so the very next review
/// put a `macro_rules!` spelling the trait *inside* a `const _` block, invoked it, and got a live
/// public runtime path that was silent through this gate, `cargo clippy -D warnings` and
/// `cargo fmt --check`. The const-block idiom is exempt from rustc's `non_local_definitions` lint,
/// so unlike the function-body case nothing in the repo saw it.
///
/// That was the third consecutive round of the same defect — a correct fix applied to the one
/// function the reviewer's example happened to touch. All three helpers are visitors now.
///
/// A `macro_rules!` body is a template, not code, so no AST can tell whether it will be invoked; a
/// body that names a seam is therefore treated as an implementation wherever it appears, including
/// inside the owning crate. That is deliberately conservative and it does constrain the owning
/// crate: an item-level macro invocation whose token stream merely *mentions* a seam — a
/// `thread_local!` holding a `Box<dyn Seam>`, say — is reported too. If that becomes a real
/// obstruction the answer is to narrow this to bodies containing an `impl ... for` shape, not to put
/// the owning crate back outside the check.
fn macro_bodies_name_seam(file: &syn::File, seam: &str) -> bool {
    struct Finder<'a> {
        seam: &'a str,
        found: bool,
    }
    impl syn::visit::Visit<'_> for Finder<'_> {
        fn visit_macro(&mut self, mac: &syn::Macro) {
            if mac
                .tokens
                .to_string()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == self.seam)
            {
                self.found = true;
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut finder = Finder { seam, found: false };
    syn::visit::visit_file(&mut finder, file);
    finder.found
}

/// A test target is `crates/<crate>/tests/**` or `crates/<crate>/benches/**` — nothing else.
///
/// This used to return true for a `tests` component ANYWHERE in the path, so
/// `crates/evolve/src/tests/projection.rs` was exempt. A module declared there without
/// `#[cfg(test)]` compiles into the real crate, and a review put a plain seam implementation in one:
/// silent through `boundaries check`, `cargo fmt --check`, `cargo clippy -D warnings` and the whole
/// test suite. The comment on the rule had named an in-`src` test module as "exactly where a real
/// implementation would be easiest to hide", and the check had left that very case open.
fn is_test_path(relative: &str) -> bool {
    let parts: Vec<&str> = relative.split('/').collect();
    matches!(parts.as_slice(), ["crates", _, kind, ..] if *kind == "tests" || *kind == "benches")
}

/// Refuse any internal crate other than `core_evolve` inside the satisfiability proof.
fn validate_single_dependency(relative: &str, file: &syn::File) -> Result<()> {
    // Identifiers only, walked over the AST. Rendering the file to a token string and word-splitting
    // it read the module doc comment — which explains at length why `core_protocol` must not be
    // imported here — as an import of `core_protocol`, and turned the gate red on its own
    // explanation. That is the third time in this file that reading text instead of structure
    // produced a false positive; it is why every check here now walks the tree.
    struct Foreign {
        found: Option<String>,
    }
    impl syn::visit::Visit<'_> for Foreign {
        fn visit_ident(&mut self, ident: &syn::Ident) {
            if self.found.is_some() {
                return;
            }
            let name = ident.to_string();
            if name.starts_with(INTERNAL_CRATE_PREFIX) && name != "core_evolve" {
                self.found = Some(name);
            }
        }
    }
    let mut foreign = Foreign { found: None };
    syn::visit::visit_file(&mut foreign, file);
    if let Some(word) = foreign.found {
        {
            bail!(
                "`{relative}` names the internal crate `{word}`.\n\
                 This test proves that a crate holding `core-evolve` ALONE can implement the seams, \
                 so every type must be reachable through `core_evolve::`.\n\
                 An integration test inherits its crate's dependencies, so `{word}` compiles here \
                 while an outside implementor may not have it — which is exactly the gap this \
                 check closes.\n\
                 If a type in a seam signature is not reachable through `core_evolve::`, re-export \
                 it from `core-evolve` rather than importing `{word}` here: the seam is wrong, not \
                 the test."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SEAMS, find_trait_impl, identifiers_name_seam, is_test_path, macro_bodies_name_seam,
        normalise, resolve_alias_closure,
    };
    use std::collections::BTreeSet;

    fn implements(source: &str) -> bool {
        let names = resolve_alias_closure(&[("x.rs".into(), source.to_owned(), BTreeSet::new())]);
        let file = syn::parse_file(source).expect("parses");
        find_trait_impl(&file, &names).is_some()
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
    fn a_macro_and_an_include_are_found_at_any_nesting_too() {
        // `find_trait_impl` became a full visitor while its two SIBLING helpers stayed a shallow
        // `file.items` walk — the same defect, in the commit named after it. Three live bypasses
        // followed, all silent through the gate, clippy -D warnings and fmt.
        let in_const = syn::parse_file(
            "const _: () = { macro_rules! w { ($t:ty) => { impl TrajectoryProjection for $t {} }; } };",
        )
        .expect("parses");
        assert!(
            macro_bodies_name_seam(&in_const, "TrajectoryProjection"),
            "a macro_rules! inside a const block spelling the seam"
        );
        let in_fn = syn::parse_file(
            "fn f() { macro_rules! w { ($t:ty) => { impl TrajectoryProjection for $t {} }; } }",
        )
        .expect("parses");
        assert!(macro_bodies_name_seam(&in_fn, "TrajectoryProjection"));

        // `include!` below top level, and spelled with a path prefix.
        assert_eq!(
            super::include_targets("fn f() { mod m { include!(\"a.inc\"); } }"),
            vec!["a.inc".to_owned()],
            "an include! nested in a fn body removed the target from the scan entirely"
        );
        assert_eq!(
            super::include_targets("std::include!(\"b.inc\");"),
            vec!["b.inc".to_owned()],
            "one keyword prefix defeated is_ident(\"include\") on a plain top-level include"
        );
        assert_eq!(
            super::include_targets("core::include!(\"c.inc\");"),
            vec!["c.inc".to_owned()]
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
        assert!(macro_bodies_name_seam(&file, "TrajectoryProjection"));
        // A macro taking the trait as a metavariable is the documented limit.
        let opaque =
            syn::parse_file("macro_rules! w { ($tr:path, $t:ty) => { impl $tr for $t {} }; }")
                .expect("parses");
        assert!(!macro_bodies_name_seam(&opaque, "TrajectoryProjection"));
    }

    #[test]
    fn identifiers_are_seen_but_strings_and_comments_are_not() {
        let named = syn::parse_file("type X = dyn TrajectoryProjection;").expect("parses");
        assert!(identifiers_name_seam(&named, "TrajectoryProjection"));
        let prose = syn::parse_file("/// TrajectoryProjection is forbidden\npub struct X;")
            .expect("parses");
        assert!(!identifiers_name_seam(&prose, "TrajectoryProjection"));
        let string = syn::parse_file("const M: &str = \"TrajectoryProjection\";").expect("parses");
        assert!(!identifiers_name_seam(&string, "TrajectoryProjection"));
    }

    #[test]
    fn the_seam_list_is_not_silently_empty() {
        // Every assertion above is vacuous if SEAMS is emptied, so pin it.
        assert_eq!(SEAMS.len(), 2);
        assert!(SEAMS.contains(&"TrajectoryProjection"));
        assert!(SEAMS.contains(&"HeldOutEvidenceBridge"));
    }
}
