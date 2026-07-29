use super::{IMPLEMENTATION_SITES, INTERNAL_CRATE_PREFIX};
use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;
use syn::ext::IdentExt;

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
pub(super) fn collect_sources(
    root: &Path,
    files: &[String],
) -> Vec<(String, String, BTreeSet<String>)> {
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
                // Only Rust. A string-literal macro argument may name a data file
                // (`include_str!("notes.md")`), and a data file cannot carry an implementation. This
                // is what makes it safe to stop guessing the macro's name in `include_targets`.
                if syn::parse_file(&source).is_err() {
                    continue;
                }
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
pub(super) fn normalise(path: &str) -> String {
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

/// Every string-literal macro argument in this file that names an existing repository file.
///
/// # Why this stops guessing the macro's name
///
/// This matched `is_ident("include")`, and a review defeated it with `std::include!` — a two-segment
/// path. The fix compared the LAST segment instead, and the next review defeated that with
/// `use std::include as pull; pull!("x.inc")`. Same defect class, one notch sideways, inside the
/// function that had just been fixed for it: the matcher was generalised over the path prefix and
/// not over the name.
///
/// So it no longer asks what the macro is called. Any macro whose entire body is one string literal
/// that resolves to a file on disk is treated as pulling that file in, because that is the only
/// property that matters — the file's bytes reach the compiler.
///
/// The honest cost: `include_str!("notes.md")` is picked up too. That is harmless, and deliberately
/// so — the caller only keeps targets that PARSE as Rust, and a data file does not. The residual
/// false positive is a `.rs` file included as a string for documentation, which would be scanned as
/// code; that is a louder failure than the silent one it replaces, and no such file exists in this
/// tree today.
pub(super) fn include_targets(source: &str) -> Vec<String> {
    let Ok(file) = syn::parse_file(source) else {
        return Vec::new();
    };
    struct Finder {
        targets: Vec<String>,
    }
    impl syn::visit::Visit<'_> for Finder {
        fn visit_macro(&mut self, mac: &syn::Macro) {
            if let Ok(literal) = mac.parse_body::<syn::LitStr>() {
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
#[cfg(test)]
pub(super) fn resolve_alias_closure(
    sources: &[(String, String, BTreeSet<String>)],
) -> BTreeSet<String> {
    resolve_alias_closure_from(["TrajectoryProjection", "HeldOutEvidenceBridge"], sources)
}

pub(super) fn resolve_alias_closure_from<'a>(
    initial: impl IntoIterator<Item = &'a str>,
    sources: &[(String, String, BTreeSet<String>)],
) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = initial.into_iter().map(str::to_owned).collect();
    let mut edges: Vec<(String, String)> = Vec::new();
    for (_, source, _) in sources {
        let Ok(file) = syn::parse_file(source) else {
            continue;
        };
        collect_use_renames(&file, &mut edges);
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

/// Collect every `use ... as Alias` edge in a file, at any nesting.
///
/// # The fourth sibling
///
/// This was the last function in this file still shaped like the one that has now bitten four times:
/// a walk over `file.items` that recursed into `Item::Mod` and dropped everything else into
/// `_ => {}`. `find_trait_impl`, `macro_bodies_name_seam` and `include_targets` were each converted
/// to visitors, one per review round, each time in response to the specific example the reviewer had
/// written — and each time the siblings doing the same kind of work were left alone.
///
/// So this one was found by asking the question instead of waiting for the seventh review:
/// `const _: () = { use crate::TrajectoryProjection as Proj; impl Proj for Evil { .. } };` compiled
/// and passed the gate. The alias was declared inside a const block, the collector never looked
/// there, so `Proj` never entered the closure and the impl was not recognised.
fn collect_use_renames(file: &syn::File, edges: &mut Vec<(String, String)>) {
    struct Collector<'a> {
        edges: &'a mut Vec<(String, String)>,
    }
    impl syn::visit::Visit<'_> for Collector<'_> {
        fn visit_item_use(&mut self, item: &syn::ItemUse) {
            walk_use_tree(&item.tree, self.edges);
            syn::visit::visit_item_use(self, item);
        }
    }
    let mut collector = Collector { edges };
    syn::visit::visit_file(&mut collector, file);
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
            edges.push((
                rename.rename.unraw().to_string(),
                rename.ident.unraw().to_string(),
            ));
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
pub(super) fn find_trait_impl(file: &syn::File, names: &BTreeSet<String>) -> Option<String> {
    struct Finder<'a> {
        names: &'a BTreeSet<String>,
        found: Option<String>,
    }
    impl syn::visit::Visit<'_> for Finder<'_> {
        fn visit_item_impl(&mut self, item: &syn::ItemImpl) {
            if let Some((_, path, _)) = &item.trait_
                && let Some(last) = path.segments.last()
            {
                let name = last.ident.unraw().to_string();
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

/// Whether the candidate contains the canonical production implementation for a retired seam.
///
/// The proof is intentionally narrower than the conservative prohibition above. A terminal trait
/// name anywhere in `src/` is not enough: an unreferenced file, cfg-disabled impl, example, macro
/// template, or same-named local trait does not put the frozen seam on a runtime path. Each frozen
/// seam therefore has one explicit implementation site. Its default-path module must be wired
/// directly from `core-evolve`'s managed library root, and the site must import the crate-root seam
/// without aliasing before implementing that exact binding in an active top-level item.
pub(super) fn has_canonical_production_impl(
    sources: &[(String, String, BTreeSet<String>)],
    seam: &str,
) -> Result<bool> {
    let Some(site) = IMPLEMENTATION_SITES.iter().find(|site| site.seam == seam) else {
        return Ok(false);
    };
    let Some((_, root_source, _)) = sources
        .iter()
        .find(|(path, _, _)| path == "crates/evolve/src/lib.rs")
    else {
        return Ok(false);
    };
    let root = syn::parse_file(root_source)
        .context("`crates/evolve/src/lib.rs` does not parse as Rust")?;
    if root
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        return Ok(false);
    }
    let mut modules = root.items.iter().filter_map(|item| match item {
        syn::Item::Mod(module) if module.ident.unraw() == site.module => Some(module),
        _ => None,
    });
    let Some(module) = modules.next() else {
        return Ok(false);
    };
    if modules.next().is_some()
        || !module.attrs.is_empty()
        || !matches!(module.vis, syn::Visibility::Inherited)
        || module.content.is_some()
    {
        return Ok(false);
    }

    let Some((_, implementation_source, _)) =
        sources.iter().find(|(path, _, _)| path == site.source)
    else {
        return Ok(false);
    };
    let implementation = syn::parse_file(implementation_source)
        .with_context(|| format!("`{}` does not parse as Rust", site.source))?;
    if implementation
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        return Ok(false);
    }
    let imports_seam = implementation.items.iter().any(|item| {
        let syn::Item::Use(item) = item else {
            return false;
        };
        item.attrs.is_empty()
            && matches!(item.vis, syn::Visibility::Inherited)
            && item.leading_colon.is_none()
            && use_tree_imports_crate_seam(&item.tree, &[], seam)
    });
    if !imports_seam {
        return Ok(false);
    }
    Ok(implementation.items.iter().any(|item| {
        let syn::Item::Impl(item) = item else {
            return false;
        };
        let Some((bang, path, _)) = &item.trait_ else {
            return false;
        };
        bang.is_none()
            && item.attrs.is_empty()
            && path.leading_colon.is_none()
            && path.segments.len() == 1
            && path.segments[0].ident.unraw() == seam
            && matches!(path.segments[0].arguments, syn::PathArguments::None)
    }))
}

fn use_tree_imports_crate_seam(tree: &syn::UseTree, prefix: &[String], seam: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            let mut nested = prefix.to_vec();
            nested.push(path.ident.unraw().to_string());
            use_tree_imports_crate_seam(&path.tree, &nested, seam)
        }
        syn::UseTree::Name(name) => prefix == ["crate"] && name.ident.unraw() == seam,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_imports_crate_seam(item, prefix, seam)),
        syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => false,
    }
}

/// Every identifier a file mentions, **including inside macro token streams**.
///
/// # Why there is one of these instead of three
///
/// Seven consecutive reviews found the same shape: a fix applied to the one function the reviewer's
/// example touched, with the siblings doing the same work left alone. The seventh found three at
/// once — `macro_bodies_name_seam` searched the canonical `SEAMS` while `find_trait_impl` searched
/// the resolved alias closure, so a macro spelling an alias was caught by neither;
/// `validate_single_dependency` had no macro-token vision at all, so the satisfiability proof could
/// silently take a second internal-crate dependency; and `identifiers_name_seam` shared that blind
/// spot.
///
/// Patching them one at a time would produce an eighth. The structural answer is to stop having
/// siblings: **one scan, used by every rule.** `syn`'s generated visitor descends into `mac.path`
/// but treats `mac.tokens` as an opaque `TokenStream`, so the token streams are walked here
/// explicitly and folded into the same set of names every rule then asks about.
pub(super) fn mentioned_identifiers(file: &syn::File) -> BTreeSet<String> {
    struct Scan {
        names: BTreeSet<String>,
    }
    impl Scan {
        fn absorb_tokens(&mut self, tokens: &str) {
            for word in tokens.split(|c: char| !c.is_alphanumeric() && c != '_') {
                if !word.is_empty() {
                    self.names.insert(word.to_owned());
                }
            }
        }
    }
    impl syn::visit::Visit<'_> for Scan {
        fn visit_ident(&mut self, ident: &syn::Ident) {
            self.names.insert(ident.unraw().to_string());
        }
        fn visit_macro(&mut self, mac: &syn::Macro) {
            // The one place `syn` stops: a macro body is unparsed tokens. Everything else in this
            // file goes through the AST.
            self.absorb_tokens(&mac.tokens.to_string());
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut scan = Scan {
        names: BTreeSet::new(),
    };
    syn::visit::visit_file(&mut scan, file);
    scan.names
}

/// The first name from the alias closure spelled inside any macro body in this file.
///
/// A `macro_rules!` body is a template, not code, so no AST can tell whether it will be invoked; a
/// body naming a seam is therefore treated as an implementation wherever it appears, including in
/// the owning crate — which is the only place such a macro can legally live, and where an earlier
/// version never looked.
///
/// It searches the resolved alias closure, not the canonical [`SEAMS`]. That difference was a live
/// bypass: `use ..::TrajectoryProjection as Proj;` at top level (so the alias WAS in the closure)
/// plus `macro_rules! wire { ($t:ty) => { impl Proj for $t {} } }` was caught by nothing —
/// `find_trait_impl` cannot see into unexpanded macro tokens, and the token search was only ever
/// looking for the canonical name.
pub(super) fn macro_bodies_mention(file: &syn::File, names: &BTreeSet<String>) -> Option<String> {
    struct Finder<'a> {
        names: &'a BTreeSet<String>,
        found: Option<String>,
    }
    impl syn::visit::Visit<'_> for Finder<'_> {
        fn visit_macro(&mut self, mac: &syn::Macro) {
            if self.found.is_none() {
                for word in mac
                    .tokens
                    .to_string()
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                {
                    if self.names.contains(word) {
                        self.found = Some(word.to_owned());
                        break;
                    }
                }
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let mut finder = Finder { names, found: None };
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
pub(super) fn is_test_path(relative: &str) -> bool {
    let parts: Vec<&str> = relative.split('/').collect();
    matches!(parts.as_slice(), ["crates", _, kind, ..] if *kind == "tests" || *kind == "benches")
}

/// Refuse any internal crate other than `core_evolve` inside the satisfiability proof.
///
/// Uses [`mentioned_identifiers`], so a dependency hidden inside a macro token stream is seen. A
/// review smuggled `core_protocol` past the previous `visit_ident` walk by wrapping it in a
/// pass-through `macro_rules!` — and this file is the ONLY mechanical evidence that the frozen seams
/// are implementable by a crate holding `core-evolve` alone, so a check it can be walked past is a
/// proof that proves nothing.
pub(super) fn validate_single_dependency(relative: &str, file: &syn::File) -> Result<()> {
    for word in mentioned_identifiers(file) {
        if word.starts_with(INTERNAL_CRATE_PREFIX) && word != "core_evolve" {
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
