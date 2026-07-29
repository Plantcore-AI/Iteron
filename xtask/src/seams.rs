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
//! [`SEAMS`] is both the compiled trusted-base registry and a literal registry in the candidate
//! source tree. A candidate may only subtract names from the trusted-base set, and every subtraction
//! must arrive with an explicit non-test `impl` of that exact seam. A test double, macro template,
//! string, comment, or removal of the gate wiring does not satisfy the transition.
//!
//! Issue #27 removes `HeldOutEvidenceBridge` from [`SEAMS`] **in the same commit** that lands its
//! implementation. Issue #29 does the same for `TrajectoryProjection`. The file, module wiring, and
//! validation call remain even after the list becomes empty; retiring the authority itself is a
//! separate governance change.
//!
//! Issue #28 has nothing to delete: bundle resolution is not policed here, because the port lives in
//! `core_protocol::bundle` where both sides of the seam already depend on it.

use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

mod source;
mod transition;

use source::{
    collect_sources, find_trait_impl, has_canonical_production_impl, is_test_path,
    macro_bodies_mention, mentioned_identifiers, resolve_alias_closure_from,
    validate_single_dependency,
};

/// The traits that must remain declared and unimplemented.
///
/// `PolicyBundleResolver` is deliberately absent: it lives in `core-protocol`, is declared over
/// `ResolvedBundle`, and both sides of its seam already depend on that crate, so naming it costs
/// nobody a dependency and there is nothing to police.
const SEAMS: &[&str] = &[];

/// The one crate permitted to declare and name the seams above.
const OWNING_CRATE: &str = "crates/evolve/";

/// The integration test that proves the seams are implementable from outside.
const SATISFIABILITY_TEST: &str = "crates/evolve/tests/seam_satisfiability.rs";

/// Internal crates whose appearance in [`SATISFIABILITY_TEST`] would void the proof it exists to
/// make. An integration test inherits its crate's `[dependencies]`, so `core_protocol` compiles
/// there even though an outside implementor may hold only `core-evolve` — position alone proves
/// nothing, and this is what makes the single-dependency claim mechanical.
const INTERNAL_CRATE_PREFIX: &str = "core_";

struct ImplementationSite {
    seam: &'static str,
    module: &'static str,
    source: &'static str,
}

const IMPLEMENTATION_SITES: &[ImplementationSite] = &[
    ImplementationSite {
        seam: "HeldOutEvidenceBridge",
        module: "held_out",
        source: "crates/evolve/src/held_out.rs",
    },
    ImplementationSite {
        seam: "TrajectoryProjection",
        module: "trajectory_projection",
        source: "crates/evolve/src/trajectory_projection.rs",
    },
];

pub(crate) fn validate(root: &Path, files: &[String]) -> Result<()> {
    let sources = collect_sources(root, files);
    let transition = transition::Transition::load(root, SEAMS)?;
    validate_sources(&sources, &transition)
}

fn validate_sources(
    sources: &[(String, String, BTreeSet<String>)],
    transition: &transition::Transition,
) -> Result<()> {
    let aliases = transition
        .base()
        .map(|seam| {
            (
                seam.clone(),
                resolve_alias_closure_from([seam.as_str()], sources),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut implemented = BTreeSet::new();
    for seam in transition.removed() {
        if has_canonical_production_impl(sources, seam)? {
            implemented.insert(seam.clone());
        }
    }
    let mut satisfiability_test_seen = false;
    for (relative, source, roots) in sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("`{relative}` does not parse as Rust"))?;

        // Every rule below asks the SAME question of the SAME scan, and asks it about the resolved
        // alias closure rather than the canonical names. The previous version searched macro bodies
        // for `SEAMS` while the impl finder searched `names`, so a macro spelling a resolved alias
        // was caught by neither.
        //
        // A `macro_rules!` body is a template, not code, so no AST can tell whether it will be
        // invoked; a body naming a seam is therefore treated as an implementation wherever it
        // appears, including in the owning crate — which is the only place such a macro can legally
        // live, and where an earlier version never looked.
        let mentioned = mentioned_identifiers(&file);
        for seam in transition.base() {
            let names = aliases
                .get(seam)
                .expect("every trusted seam has an alias closure");
            let explicit = find_trait_impl(&file, names);
            let via_macro = macro_bodies_mention(&file, names);
            if !is_test_path(relative)
                && transition.is_remaining(seam)
                && let Some(found) = explicit.or(via_macro)
            {
                bail!(
                    "`{relative}` implements the `{found}` seam outside a test target.\n\
                     This seam remains declared, not implemented, in the candidate registry."
                );
            }

            // Read from the parsed source, so a seam named in a doc comment or inside a string
            // literal is not a reference. Keep this check on the canonical name: aliases are
            // resolved tree-wide for impl detection, but treating every occurrence of a short
            // alias such as `P` as a seam reference would create unrelated false positives.
            if transition.is_remaining(seam)
                && !relative.starts_with(OWNING_CRATE)
                && mentioned.contains(seam)
            {
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

    transition.require_real_implementations(&implemented)?;
    if transition.has_remaining() && !satisfiability_test_seen {
        bail!(
            "`{SATISFIABILITY_TEST}` is missing.\n\
             It is the only proof that the declared seams can be implemented by a crate that holds \
             `core-evolve` and nothing else. Without it the seams are unverified declarations."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
