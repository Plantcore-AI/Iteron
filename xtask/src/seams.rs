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
//! make the companion criterion, "referenced by no runtime path", permanently unenforceable. An
//! absent implementation plus this gate gives the same guarantee and can actually be enforced.
//!
//! # For whoever lands the first real implementation
//!
//! Issues #27 (`HeldOutEvidenceBridge`) and #28 (bundle resolution) delete the relevant entry from
//! [`SEAMS`] **in the same commit** that lands the implementation. That deletion is the point at
//! which the seam stops being a promise and starts being code, and it should be visible in the diff
//! rather than discovered later.

use anyhow::{Result, bail};
use std::path::Path;

/// The traits that must remain declared and unimplemented, and the crate allowed to name them.
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
    let mut satisfiability_test_seen = false;

    for relative in files {
        if !relative.starts_with("crates/") || !relative.ends_with(".rs") {
            continue;
        }
        let raw = match std::fs::read_to_string(root.join(relative)) {
            Ok(source) => source,
            // A path git knows about but that is not readable is not this gate's business; the
            // file-coverage check upstream already reports it.
            Err(_) => continue,
        };
        // Every check below reads code, never prose. A doc comment that discusses a seam by name -
        // and the specs and design notes do - is documentation, not a reference.
        let source = strip_comments(&raw);

        for seam in SEAMS {
            // An implementation may exist only under `crates/*/tests/`. That is stricter than
            // "outside `#[cfg(test)]`" and needs no brace parsing to be correct: an in-`src` test
            // module is exactly where a real implementation would be easiest to hide, and the
            // satisfiability proof has no reason to live there anyway.
            if implements_seam(&source, seam) && !is_test_path(relative) {
                bail!(
                    "`{relative}` implements the `{seam}` seam outside a test target.\n\
                     These seams are declared, not implemented; the frozen contract says no runtime \
                     path references them.\n\
                     If this is the first real implementation, delete `{seam}` from SEAMS in \
                     xtask/src/seams.rs in the same commit, so the change is visible in the diff."
                );
            }
            if source.contains(seam) && !relative.starts_with(OWNING_CRATE) {
                bail!(
                    "`{relative}` names the `{seam}` seam, but only `{OWNING_CRATE}` may.\n\
                     A crate that names it has begun consuming a seam that nothing implements."
                );
            }
        }

        if relative == SATISFIABILITY_TEST {
            satisfiability_test_seen = true;
            validate_single_dependency(relative, &source)?;
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

/// Does this source implement `seam`, however the `impl` header is spelled?
///
/// A first version matched the literal `"impl {seam} for"`, and a self-review found the hole before
/// a reviewer did: `impl<T> TrajectoryProjection for T` — a blanket impl, the single most dangerous
/// shape here, since it implements the seam for *every* type at once — does not contain that
/// substring. Neither does `impl  Seam  for` with any extra whitespace. A gate that a blanket impl
/// walks through is worse than no gate, because it reports the property as held.
///
/// So this parses the header instead of pattern-matching it: find `impl` as a whole token, skip an
/// optional balanced generic parameter list, then require the seam name (bare or the last segment of
/// a path) followed by the `for` keyword.
fn implements_seam(source: &str, seam: &str) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find("impl") {
        let start = cursor + found;
        cursor = start + 4;
        // `impl` must be a whole token, not the tail of `noimpl` or the head of `implements`.
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = cursor >= bytes.len() || !is_ident_byte(bytes[cursor]);
        if !(before_ok && after_ok) {
            continue;
        }
        let mut index = skip_space(bytes, cursor);
        // An optional generic parameter list: `impl<T>`, `impl<'a, T: Bound<U>>`.
        if index < bytes.len() && bytes[index] == b'<' {
            let mut depth = 0usize;
            while index < bytes.len() {
                match bytes[index] {
                    b'<' => depth += 1,
                    b'>' => {
                        depth -= 1;
                        if depth == 0 {
                            index += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            index = skip_space(bytes, index);
        }
        // The trait path. Compare the last `::` segment, so `crate::seams::Foo` counts as `Foo`.
        let path_start = index;
        while index < bytes.len() && (is_ident_byte(bytes[index]) || bytes[index] == b':') {
            index += 1;
        }
        let path = &source[path_start..index];
        let named = path.rsplit("::").next().unwrap_or(path) == seam;
        // `impl Type { .. }` is an inherent impl, not a trait impl; only `for` makes it one.
        let rest = &source[skip_space(bytes, index)..];
        let is_trait_impl = rest.starts_with("for") && rest[3..].starts_with(char::is_whitespace);
        if named && is_trait_impl {
            return true;
        }
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn is_test_path(relative: &str) -> bool {
    relative
        .split('/')
        .any(|component| component == "tests" || component == "benches")
}

/// Strip `//` line comments and `/* */` block comments.
///
/// The gate below reads prose as code otherwise, and it did: the first run failed on the word
/// `core_protocol` inside the very doc comment explaining why `core_protocol` must not be imported.
/// A gate that fires on its own explanation is a gate someone disables, so it reads code only.
///
/// String literals are not excluded. A crate name inside a string is not an import and cannot make
/// anything compile, so treating one as a reference would be the same false positive in a new place.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            let mut depth = 1usize;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
        } else {
            // Push whole chars so a multi-byte character is never split.
            let ch = source[index..].chars().next().expect("in bounds");
            out.push(ch);
            index += ch.len_utf8();
        }
    }
    out
}

/// Refuse any internal crate other than `core_evolve` inside the satisfiability proof.
fn validate_single_dependency(relative: &str, source: &str) -> Result<()> {
    for (offset, _) in source.match_indices(INTERNAL_CRATE_PREFIX) {
        // Only treat it as a crate reference when the prefix starts an identifier, so `core_evolve`
        // inside a word or a longer identifier does not trip this.
        if offset > 0 {
            let previous = source.as_bytes()[offset - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                continue;
            }
        }
        let name: String = source[offset..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name != "core_evolve" {
            bail!(
                "`{relative}` names the internal crate `{name}`.\n\
                 This test proves that a crate holding `core-evolve` ALONE can implement the seams, \
                 so every type must be reachable through `core_evolve::`.\n\
                 An integration test inherits its crate's dependencies, so `{name}` compiles here \
                 while an outside implementor may not have it — which is exactly the gap this \
                 check closes.\n\
                 If a type in a seam signature is not reachable through `core_evolve::`, re-export \
                 it from `core-evolve` rather than importing `{name}` here: the seam is wrong, not \
                 the test."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{implements_seam, strip_comments};

    #[test]
    fn a_blanket_impl_does_not_walk_past_the_gate() {
        // The shape that motivated parsing the header rather than matching a literal: it implements
        // the seam for EVERY type at once, and the old `contains("impl Seam for")` missed it.
        assert!(implements_seam("impl<T> Seam for T {}", "Seam"));
        assert!(implements_seam(
            "impl<'a, T: Bound<U>> Seam for &'a T {}",
            "Seam"
        ));
    }

    #[test]
    fn whitespace_and_paths_do_not_hide_an_impl() {
        assert!(implements_seam("impl  Seam  for  X {}", "Seam"));
        assert!(implements_seam("impl\n    Seam\n    for X {}", "Seam"));
        assert!(implements_seam("impl crate::seams::Seam for X {}", "Seam"));
    }

    #[test]
    fn the_things_that_are_not_a_trait_impl_are_not_reported() {
        // An inherent impl on a type that happens to share the name.
        assert!(!implements_seam("impl Seam { fn new() {} }", "Seam"));
        // A different trait.
        assert!(!implements_seam("impl OtherSeam for X {}", "Seam"));
        // `impl` as part of a longer identifier, and the trait merely named.
        assert!(!implements_seam("fn f(x: &dyn Seam) {}", "Seam"));
        assert!(!implements_seam("let noimpl = Seam;", "Seam"));
        // `impl Trait` in return position names the trait without implementing it.
        assert!(!implements_seam("fn f() -> impl Seam { todo!() }", "Seam"));
    }

    #[test]
    fn a_comment_is_never_read_as_code() {
        assert_eq!(strip_comments("a // impl Seam for X\nb"), "a \nb");
        assert_eq!(strip_comments("a /* impl Seam for X */ b"), "a  b");
        assert!(!implements_seam(
            &strip_comments("// impl Seam for X"),
            "Seam"
        ));
    }

    #[test]
    fn a_string_literal_is_not_stripped_as_a_comment() {
        // The stripper does not track string literals. That is a deliberate, bounded imprecision:
        // it can only ever cause a `//` or `/*` INSIDE a string to eat the rest of a line, which
        // makes the gate blinder, never louder. Record the real behaviour rather than claim
        // otherwise - a stripper that is documented as exact and is not is the worse failure.
        let source = r#"let url = "https://example.invalid"; impl Seam for X {}"#;
        assert!(
            !implements_seam(&strip_comments(source), "Seam"),
            "the `//` in a URL swallows the rest of the line; this is the known blind spot"
        );
        // And the same code with the impl on its own line is caught, which is the shape that
        // matters: an `impl` header does not share a line with a URL in practice.
        let split = "let url = \"https://example.invalid\";\nimpl Seam for X {}";
        assert!(implements_seam(&strip_comments(split), "Seam"));
    }
}
