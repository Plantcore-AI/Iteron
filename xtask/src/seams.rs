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
//! # What this gate does NOT catch
//!
//! Stated here rather than discovered later, because a gate whose limits are unwritten gets read as
//! a guarantee it never made.
//!
//! A previous version of this section listed three limits and said "these three are real and
//! remain" — and a later review then walked through four more ways, all of which compiled as live
//! implementations in the very file this gate polices. So the sentence itself had become the defect
//! it was written to prevent: a completeness claim in prose. Those four (a renamed import, `->`
//! inside the impl generic list, `for` with no following whitespace, and non-ASCII Rust whitespace)
//! are now closed and unit-tested. **This list is what is known to be uncovered, not a proof that
//! nothing else is.**
//!
//! - **A macro that takes the trait as a metavariable.** `macro_rules! wire { ($tr:path, $ty:ty) =>
//!   { impl $tr for $ty { .. } } }` never spells the trait name next to `impl`, so nothing textual
//!   can see it. (A macro that spells the trait literally *is* caught.) Closing this means expanding
//!   macros, i.e. running the compiler, which is a different tool than a source scan. The honest
//!   mitigation is that it takes deliberate indirection: nobody writes that shape by accident, so
//!   this stops mistakes, not a determined author.
//! - **Anything outside `crates/`.** The scan skips every path that does not start with `crates/`
//!   (see [`validate`]), so a build script or a crate rooted elsewhere is unscanned. Nothing outside
//!   `crates/` depends on `core-evolve` today; that is an assumption, and it is written down here so
//!   it can be rechecked rather than assumed.
//! - **Files git does not list.** The file list comes from `git ls-files --cached --others
//!   --exclude-standard`, so a `.gitignore`d `.rs` that still compiles into a crate is invisible.
//!
//! An unterminated raw string or block comment also blinds the scanner from that point on — but such
//! a file does not compile, so it cannot hide a live implementation. That one is a non-issue and is
//! recorded only so the next reader does not spend an afternoon on it.
//!
//! # For whoever lands the first real implementation
//!
//! Issue #27 (`HeldOutEvidenceBridge`) deletes its entry from [`SEAMS`] **in the same commit** that
//! lands the implementation. That deletion is the point at which the seam stops being a promise and
//! starts being code, and it should be visible in the diff rather than discovered later.
//!
//! Issue #28 has nothing to delete: bundle resolution is not policed here at all, because the port
//! moved to `core_protocol::bundle` where both sides of the seam already depend on it. (This
//! paragraph used to name #28 alongside #27, which would have sent that implementor looking for an
//! entry that was deliberately never added.)

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
        let source = code_only(&raw);

        for seam in SEAMS {
            // An implementation may exist only under `crates/*/tests/`. That is stricter than
            // "outside `#[cfg(test)]`" and needs no brace parsing to be correct: an in-`src` test
            // module is exactly where a real implementation would be easiest to hide, and the
            // satisfiability proof has no reason to live there anyway.
            // A renamed import is the one shape with no backstop inside the owning crate: the
            // `contains(seam)` rule below is deliberately skipped there, so `use ...::Seam as P;
            // impl P for Evil {}` had nothing looking at it at all — in the very crate the gate
            // calls "the one that must never implement it".
            let names = seam_aliases(&source, seam);
            let implemented = names.iter().any(|name| implements_seam(&source, name));
            if implemented && !is_test_path(relative) {
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

/// Every local name that refers to `seam` in this file: the seam itself, plus any `use ... as X`
/// alias for it.
///
/// Rust lets an import be renamed, and the gate compared the literal trait name, so
/// `use crate::seams::TrajectoryProjection as Proj;` followed by `impl Proj for Evil {}` was
/// invisible. It compiled, it passed `cargo fmt --check`, and inside the owning crate no other rule
/// looks at it.
fn seam_aliases(source: &str, seam: &str) -> Vec<String> {
    let mut names = vec![seam.to_owned()];
    for (offset, _) in source.match_indices(seam) {
        // Only an occurrence that is a whole path segment, immediately followed by ` as `.
        let after = offset + seam.len();
        if after > 0 && source[after..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let rest = source[after..].trim_start();
        let Some(alias) = rest.strip_prefix("as ") else {
            continue;
        };
        let alias: String = alias
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !alias.is_empty() && !names.contains(&alias) {
            names.push(alias);
        }
    }
    names
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
                // `->` inside a bound is NOT a closing angle bracket. Treating it as one made
                // `impl<T: Fn() -> u32 + Marker> Seam for T {}` close the list early, read `u32>` as
                // the trait path, and walk through the gate — a blanket impl, in a shape someone
                // could reach for by accident, while the `where`-clause spelling of the same bound
                // was caught. A gate whose answer depends on where the author put a bound is worse
                // than one that is uniformly strict.
                if bytes[index..].starts_with(b"->") {
                    index += 2;
                    continue;
                }
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
        // `for` must be a whole keyword, but what follows it need not be whitespace:
        // `impl Seam for(A, B) {}` and `impl Seam for&T {}` are both valid Rust. Requiring
        // whitespace here let both through.
        let is_trait_impl =
            rest.starts_with("for") && rest[3..].chars().next().is_none_or(|c| !is_ident_char(c));
        if named && is_trait_impl {
            return true;
        }
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Skip whitespace as **Rust** defines it, not as ASCII defines it.
///
/// This used `is_ascii_whitespace`, which excludes U+000B and U+0085 that the Rust lexer accepts —
/// so a vertical tab between `impl` and the trait name walked through, while the very next check in
/// the same function already used the wider `char::is_whitespace`. An asymmetry inside one function
/// is the kind of thing nobody notices until someone is looking for a way past.
fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    let source = std::str::from_utf8(bytes).unwrap_or("");
    while index < bytes.len() {
        match source.get(index..).and_then(|rest| rest.chars().next()) {
            Some(ch) if ch.is_whitespace() => index += ch.len_utf8(),
            _ => break,
        }
    }
    index
}

fn is_test_path(relative: &str) -> bool {
    relative
        .split('/')
        .any(|component| component == "tests" || component == "benches")
}

/// Reduce a source file to the code a compiler would see: no comments, and no string contents.
///
/// # Two false results this exists to prevent, both of which happened
///
/// **A false positive.** The first version of this gate read prose as code, and its very first run
/// failed on the word `core_protocol` inside the doc comment explaining why `core_protocol` must not
/// be imported. A gate that fires on its own explanation is a gate someone disables.
///
/// **A false negative, and it was the dangerous one.** The second version stripped comments but not
/// string literals, on the reasoning that "a crate name inside a string is not an import and cannot
/// make anything compile". That reasoning is sound for what a string can *add* and completely misses
/// what a string can *hide*: an adversarial review put `const GLOB: &str = "/*";` at the top of a
/// file, the stripper saw the `/*`, searched for a closing `*/` that never came, and swallowed the
/// entire rest of the file. A textbook `impl TrajectoryProjection for Evil` underneath it was
/// invisible — in `crates/kernel`, a crate not even allowed to *name* the seam. The same trick blinded
/// the single-dependency check on the satisfiability proof. A `//` inside a string ate the rest of
/// its line the same way.
///
/// The asymmetry is the lesson: **including strings costs false positives, ignoring them costs false
/// negatives, and only one of those two failures is silent.** So strings are lexed and blanked rather
/// than left in, which fixes both directions at once — the `/*` can no longer start a comment, and a
/// seam name written inside a string is no longer mistaken for an implementation.
///
/// Quotes and delimiters are preserved so token structure survives; only the contents go.
fn code_only(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0usize;
    while index < bytes.len() {
        // `//` line comment
        if bytes[index..].starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        // `/* */` block comment, nested
        if bytes[index..].starts_with(b"/*") {
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
            continue;
        }
        // Raw string: r"..", r#".."#, r##".."##
        if bytes[index] == b'r' {
            let mut probe = index + 1;
            let mut hashes = 0usize;
            while probe < bytes.len() && bytes[probe] == b'#' {
                hashes += 1;
                probe += 1;
            }
            if probe < bytes.len() && bytes[probe] == b'"' {
                out.push('"');
                index = probe + 1;
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                while index < bytes.len() && !bytes[index..].starts_with(&close) {
                    index += 1;
                }
                index = (index + close.len()).min(bytes.len());
                out.push('"');
                continue;
            }
        }
        // Ordinary string, with escapes
        if bytes[index] == b'"' {
            out.push('"');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            out.push('"');
            continue;
        }
        // A `'` is a char literal only if it closes; otherwise it is a lifetime and must survive,
        // because `impl<'a, T> Seam for &'a T` has to stay parseable by `implements_seam`.
        if bytes[index] == b'\'' {
            let mut probe = index + 1;
            if probe < bytes.len() && bytes[probe] == b'\\' {
                probe += 2;
            } else if probe < bytes.len() {
                probe += source[probe..].chars().next().map_or(1, char::len_utf8);
            }
            if probe < bytes.len() && bytes[probe] == b'\'' {
                out.push_str("''");
                index = probe + 1;
                continue;
            }
        }
        let ch = source[index..].chars().next().expect("in bounds");
        out.push(ch);
        index += ch.len_utf8();
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
    use super::{code_only, implements_seam, seam_aliases};

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
    fn a_renamed_import_does_not_hide_an_impl() {
        // The only shape with no backstop inside the owning crate, where the `contains(seam)` rule
        // is deliberately skipped.
        let source = "use crate::seams::Seam as Proj;\nimpl Proj for Evil {}";
        assert!(implements_seam(source, &seam_aliases(source, "Seam")[1]));
        assert_eq!(seam_aliases(source, "Seam"), vec!["Seam", "Proj"]);
        // An unrelated `as` must not mint a bogus alias.
        assert_eq!(seam_aliases("let x = y as u32; Seam", "Seam"), vec!["Seam"]);
    }

    #[test]
    fn an_arrow_inside_the_generic_list_does_not_end_it_early() {
        // `->` is not a closing angle bracket. Treating it as one closed the list early, read `u32>`
        // as the trait path, and let a blanket impl through — in a shape someone could write by
        // accident, while the `where`-clause spelling of the same bound was caught.
        assert!(implements_seam(
            "impl<T: Fn() -> u32 + Marker> Seam for T {}",
            "Seam"
        ));
        assert!(implements_seam(
            "impl<F> Seam for F where F: Fn() -> u32 {}",
            "Seam"
        ));
    }

    #[test]
    fn for_need_not_be_followed_by_whitespace() {
        // Both are valid Rust and both were missed.
        assert!(implements_seam("impl Seam for(A, B) {}", "Seam"));
        assert!(implements_seam("impl Seam for&T {}", "Seam"));
        // But `format` must not be read as the `for` keyword.
        assert!(!implements_seam("impl Seam format {}", "Seam"));
    }

    #[test]
    fn rust_whitespace_is_not_only_ascii_whitespace() {
        // U+000B is whitespace to the Rust lexer and not to `is_ascii_whitespace`, which is what
        // the skipper used — while the check on the very next line already used the wider
        // `char::is_whitespace`.
        assert!(implements_seam("impl\u{0b}Seam\u{0b}for X {}", "Seam"));
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
        assert_eq!(code_only("a // impl Seam for X\nb"), "a \nb");
        assert_eq!(code_only("a /* impl Seam for X */ b"), "a  b");
        assert!(!implements_seam(&code_only("// impl Seam for X"), "Seam"));
    }

    #[test]
    fn a_string_containing_a_block_comment_opener_cannot_blind_the_scanner() {
        // The finding that mattered most from the adversarial review. The old stripper saw the `/*`
        // inside the string, hunted for a closing `*/` that never came, and ate the entire rest of
        // the file - so an impl underneath it was invisible, in ANY crate.
        let source = "const GLOB: &str = \"/*\";\nimpl Seam for Evil {}";
        assert!(
            implements_seam(&code_only(source), "Seam"),
            "a `/*` inside a string must not swallow the code after it"
        );
    }

    #[test]
    fn a_line_comment_marker_inside_a_string_cannot_hide_the_rest_of_its_line() {
        let source = r#"let u = "https://example.invalid"; impl Seam for Evil {}"#;
        assert!(
            implements_seam(&code_only(source), "Seam"),
            "the `//` in a URL must not eat the impl that follows it on the same line"
        );
    }

    #[test]
    fn a_seam_name_inside_a_string_is_not_an_implementation() {
        // The other direction of the same bug: a string constant that merely mentions the seam was
        // reported as implementing it, with a diagnostic that actively misdescribed the file.
        let source = r#"const MSG: &str = "impl Seam for X is forbidden";"#;
        assert!(!implements_seam(&code_only(source), "Seam"));
        assert!(!code_only(source).contains("Seam"));
    }

    #[test]
    fn raw_strings_and_escapes_are_handled_rather_than_guessed_at() {
        assert!(!code_only(r##"let a = r#"impl Seam for X"#;"##).contains("Seam"));
        assert!(!code_only(r#"let a = "impl Seam \" for X";"#).contains("Seam"));
        // An UNTERMINATED raw string does still swallow the rest of the file, and that is recorded
        // here as the real behaviour rather than asserted away. It is not exploitable: an
        // unterminated raw string is not valid Rust, so nothing after it compiles either, and code
        // the compiler never sees cannot be an implementation. The exploitable case was a
        // *terminated* string whose contents merely contained `/*`, which is perfectly valid Rust —
        // and that one is closed, above.
        assert!(
            !implements_seam(
                &code_only("let a = r#\"oops;\nimpl Seam for Evil {}"),
                "Seam"
            ),
            "documented limit: an unterminated raw string blinds the scanner, but such a file does \
             not compile, so it cannot hide a live implementation"
        );
    }

    #[test]
    fn a_lifetime_is_not_a_char_literal() {
        // `'a` must survive, or `impl<'a, T> Seam for &'a T` stops parsing and the blanket-impl
        // check silently goes blind again.
        assert!(implements_seam(
            &code_only("impl<'a, T> Seam for &'a T {}"),
            "Seam"
        ));
        // And a real char literal is still blanked.
        assert!(!code_only(r#"let c = '"'; let s = "Seam";"#).contains("Seam"));
    }
}
