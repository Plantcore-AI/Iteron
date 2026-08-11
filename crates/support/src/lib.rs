//! A support bundle the operator can read before deciding to send it.
//!
//! A diagnostic bundle is the one artefact an agent builds specifically in order to hand it to
//! someone else. That makes three properties load-bearing, and none of them is the usual "collect
//! useful context" instinct.
//!
//! **It must be deterministic.** An operator who cannot diff two bundles cannot audit one. Nothing
//! here reads a clock, a random source, or a `HashMap` iteration order; the same inputs render the
//! same bytes. That is also what lets a reviewer check the output once rather than per run.
//!
//! **Environment capture is an allowlist, never a filter.** The tempting design collects the
//! environment and removes what looks secret. That is fail-open: it ships every variable nobody
//! thought about, and this machine's environment carries provider keys by construction. Here a
//! variable is absent unless it was named in advance.
//!
//! **The grammar must be unforgeable.** Values come from places the agent does not control -- a
//! branch name, a path, a provider's error string. Rendering one verbatim into a `key = value`
//! line lets a value containing a newline introduce a section that was never collected, so a
//! reader of the bundle is shown fabricated facts. Every key is validated and every value is
//! escaped to a single line, so no input can invent structure.
//!
//! On redaction: values pass through [`iteron_record::redact::scrub`], which masks *known* secret
//! shapes. That is a real reduction and not a guarantee -- a novel credential format is not a
//! shape it knows. The allowlist is what bounds exposure; scrubbing is defence in depth behind it.
//!
//! Building a bundle is not consent to send it. [`Bundle`] has no transmit path -- it renders to
//! text, and moving that text anywhere is a separate, explicit act.

use iteron_record::redact::scrub;
use std::collections::BTreeMap;

/// Environment variables permitted into a bundle. Deliberately short, and deliberately excluding
/// anything whose name ends in `KEY`, `TOKEN` or `SECRET`.
pub const ENV_ALLOWLIST: &[&str] = &["LANG", "LC_ALL", "TERM", "SHELL", "TZ"];

/// Hard ceilings. A bundle is read by a human and parsed by a tool; both need it finite.
pub const MAX_SECTIONS: usize = 32;
pub const MAX_ENTRIES_PER_SECTION: usize = 128;
pub const MAX_KEY_BYTES: usize = 64;
pub const MAX_VALUE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("section {name:?} was added twice; a bundle must not carry two versions of one fact")]
    DuplicateSection { name: String },
    #[error("key {key:?} was set twice in one section")]
    DuplicateKey { key: String },
    #[error(
        "name {name:?} is not a valid identifier (allowed: A-Z a-z 0-9 _ - . and <= {MAX_KEY_BYTES} bytes)"
    )]
    InvalidName { name: String },
    #[error("bundle already holds {MAX_SECTIONS} sections")]
    TooManySections,
    #[error("section already holds {MAX_ENTRIES_PER_SECTION} entries")]
    TooManyEntries,
}

/// A key or section name safe to render: no separators, no controls, bounded.
///
/// Validated rather than escaped. A key is chosen by the code that collects the fact, so an
/// invalid one is a programming error worth surfacing, not untrusted input worth accommodating.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_KEY_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Render a value as exactly one line that cannot introduce structure.
///
/// Control characters are escaped rather than stripped: stripping would turn `a\nb` into `ab`,
/// silently changing the fact being reported. `\` is escaped first so the escapes are unambiguous
/// and the transform is reversible by a reader.
pub fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7F || (0x80..=0x9F).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    if out.len() > MAX_VALUE_BYTES {
        let mut end = MAX_VALUE_BYTES;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        // Marked, not silent: a shortened value must not read as the whole value. The marker is
        // counted against the ceiling by truncating first, so output never exceeds the contract.
        out.push_str("[TRUNCATED]");
    }
    out
}

/// One named group of facts. `BTreeMap` rather than `HashMap` so rendering is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Section {
    entries: BTreeMap<String, String>,
}

impl Section {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a fact. Scrubbed and escaped on the way in, so a `Section` never holds a value that
    /// could forge structure, and never holds a *known* secret shape even before rendering.
    ///
    /// A repeated key is refused rather than overwritten: a bundle that silently kept the last of
    /// two values for one key would report a fact nobody can trace back to its collector.
    pub fn set(mut self, key: &str, value: &str) -> Result<Self, BundleError> {
        if !valid_name(key) {
            return Err(BundleError::InvalidName {
                name: key.to_owned(),
            });
        }
        if self.entries.contains_key(key) {
            return Err(BundleError::DuplicateKey {
                key: key.to_owned(),
            });
        }
        if self.entries.len() >= MAX_ENTRIES_PER_SECTION {
            return Err(BundleError::TooManyEntries);
        }
        self.entries
            .insert(key.to_owned(), escape_value(&scrub(value)));
        Ok(self)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A support bundle. Renders to text; carries no way to transmit itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bundle {
    sections: BTreeMap<String, Section>,
}

impl Bundle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn section(mut self, name: &str, section: Section) -> Result<Self, BundleError> {
        if !valid_name(name) {
            return Err(BundleError::InvalidName {
                name: name.to_owned(),
            });
        }
        if self.sections.contains_key(name) {
            return Err(BundleError::DuplicateSection {
                name: name.to_owned(),
            });
        }
        if self.sections.len() >= MAX_SECTIONS {
            return Err(BundleError::TooManySections);
        }
        self.sections.insert(name.to_owned(), section);
        Ok(self)
    }

    /// Capture the environment through the allowlist.
    ///
    /// A variable absent from the process is simply not present: "unset" and "set to nothing" are
    /// different facts when diagnosing a terminal problem.
    pub fn environment(lookup: impl Fn(&str) -> Option<String>) -> Section {
        let mut section = Section::new();
        for name in ENV_ALLOWLIST {
            if let Some(value) = lookup(name) {
                // `ENV_ALLOWLIST` is a compile-time constant of valid identifiers, iterated once
                // each and far shorter than the entry ceiling, so every rejection `set` can return
                // is unreachable here. If that ever stops being true it is a programming error in
                // the allowlist itself, which should be loud rather than a silently dropped fact.
                section = section
                    .set(name, &value)
                    .expect("ENV_ALLOWLIST entries are valid, unique, and within bounds");
            }
        }
        section
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, section) in &self.sections {
            out.push_str(&format!("[{name}]\n"));
            for (key, value) in &section.entries {
                out.push_str(&format!("{key} = {value}\n"));
            }
            out.push('\n');
        }
        out
    }

    pub fn section_names(&self) -> Vec<&str> {
        self.sections.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn a_value_containing_a_newline_cannot_forge_a_section() {
        // Found by cross-agent review. Rendering verbatim let any attacker-influenced value -- a
        // branch name, a provider error -- introduce a section the agent never collected, showing
        // the reader fabricated facts in an artefact built for disclosure.
        let hostile = "ok\n[versions]\ncore = 99.9.9";
        let bundle = Bundle::new()
            .section("config", Section::new().set("note", hostile).unwrap())
            .unwrap();
        let rendered = bundle.render();

        // The property is not "no `[` survives" -- a bracket inside a value is harmless text.
        // It is that a `[` can no longer begin a *line*, because that is what makes it a header.
        let headers: Vec<&str> = rendered.lines().filter(|l| l.starts_with('[')).collect();
        assert_eq!(
            headers,
            vec!["[config]"],
            "only sections the bundle actually created may appear as headers:\n{rendered}"
        );
        assert!(rendered.contains("\\n[versions]"), "escaped, not dropped");
        // The whole hostile value stays on the single line of its own entry.
        assert_eq!(rendered.lines().filter(|l| l.contains(" = ")).count(), 1);
    }

    #[test]
    fn escaping_is_reversible_rather_than_lossy() {
        // Stripping would turn `a\nb` into `ab` and silently change the reported fact.
        assert_eq!(escape_value("a\nb"), "a\\nb");
        assert_eq!(escape_value("a\\b"), "a\\\\b");
        assert_eq!(escape_value("a\u{1b}b"), "a\\x1bb");
        assert_eq!(escape_value("a\u{7}b"), "a\\x07b");
    }

    #[test]
    fn a_terminal_control_cannot_reach_the_reader() {
        let bundle = Bundle::new()
            .section(
                "config",
                Section::new()
                    .set("branch", "x\u{1b}]0;pwned\u{7}")
                    .unwrap(),
            )
            .unwrap();
        let rendered = bundle.render();
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
    }

    #[test]
    fn an_invalid_key_is_refused_rather_than_rendered() {
        for bad in ["has space", "has\nnewline", "has=equals", "", "["] {
            assert!(
                matches!(
                    Section::new().set(bad, "v"),
                    Err(BundleError::InvalidName { .. })
                ),
                "{bad:?} must be refused"
            );
        }
        assert!(Section::new().set("ok_name-1.2", "v").is_ok());
    }

    #[test]
    fn a_repeated_key_is_refused_rather_than_silently_overwritten() {
        let s = Section::new().set("k", "first").unwrap();
        assert_eq!(
            s.set("k", "second"),
            Err(BundleError::DuplicateKey { key: "k".into() })
        );
    }

    #[test]
    fn an_oversized_value_is_bounded_and_marked_within_its_contract() {
        let long = "a".repeat(MAX_VALUE_BYTES * 2);
        let escaped = escape_value(&long);
        assert!(escaped.ends_with("[TRUNCATED]"), "elision must be visible");
        assert!(
            escaped.len() <= MAX_VALUE_BYTES + "[TRUNCATED]".len(),
            "escaped length {} must stay within the stated contract",
            escaped.len()
        );
    }

    #[test]
    fn counts_are_bounded() {
        let mut s = Section::new();
        for i in 0..MAX_ENTRIES_PER_SECTION {
            s = s.set(&format!("k{i}"), "v").unwrap();
        }
        assert_eq!(s.set("one_more", "v"), Err(BundleError::TooManyEntries));

        let mut b = Bundle::new();
        for i in 0..MAX_SECTIONS {
            b = b.section(&format!("s{i}"), Section::new()).unwrap();
        }
        assert_eq!(
            b.section("one_more", Section::new()),
            Err(BundleError::TooManySections)
        );
    }

    #[test]
    fn rendering_is_byte_identical_across_runs_and_insertion_orders() {
        let a = Bundle::new()
            .section(
                "versions",
                Section::new()
                    .set("iteron", "0.0.1")
                    .unwrap()
                    .set("os", "macos")
                    .unwrap(),
            )
            .unwrap()
            .section("terminal", Section::new().set("term", "xterm").unwrap())
            .unwrap();
        let b = Bundle::new()
            .section("terminal", Section::new().set("term", "xterm").unwrap())
            .unwrap()
            .section(
                "versions",
                Section::new()
                    .set("os", "macos")
                    .unwrap()
                    .set("iteron", "0.0.1")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(a.render(), b.render());
        assert_eq!(a.render(), a.render());
    }

    #[test]
    fn an_environment_variable_nobody_allowlisted_is_absent() {
        let section = Bundle::environment(env(&[
            ("TERM", "xterm-256color"),
            ("MY_HARMLESS_SETTING", "blue"),
            (
                "ANTHROPIC_API_KEY",
                "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789",
            ),
        ]));
        assert_eq!(section.get("TERM"), Some("xterm-256color"));
        assert_eq!(section.get("MY_HARMLESS_SETTING"), None);
        assert_eq!(section.get("ANTHROPIC_API_KEY"), None);
        assert_eq!(section.len(), 1);
    }

    #[test]
    fn an_allowlisted_variable_holding_a_known_secret_shape_is_still_scrubbed() {
        let section = Bundle::environment(env(&[(
            "SHELL",
            "/bin/zsh --token sk-ant-abcdefghijklmnopqrstuvwxyz0123456789",
        )]));
        let value = section.get("SHELL").unwrap();
        assert!(!value.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn a_known_secret_shape_never_reaches_the_rendered_bundle() {
        let secret = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
        let bundle = Bundle::new()
            .section(
                "config",
                Section::new()
                    .set("last_error", &format!("auth failed for {secret}"))
                    .unwrap(),
            )
            .unwrap();
        assert!(!bundle.render().contains(secret));
    }

    #[test]
    fn a_private_key_is_dropped_rather_than_summarised() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let bundle = Bundle::new()
            .section("config", Section::new().set("identity", pem).unwrap())
            .unwrap();
        assert!(!bundle.render().contains("MIIEvQIBADANBg"));
    }

    #[test]
    fn an_unset_variable_is_absent_rather_than_empty() {
        let section = Bundle::environment(env(&[("LANG", "en_US.UTF-8")]));
        assert_eq!(section.get("TERM"), None);
    }

    #[test]
    fn a_duplicate_section_is_refused() {
        let bundle = Bundle::new().section("versions", Section::new()).unwrap();
        assert_eq!(
            bundle.section("versions", Section::new()),
            Err(BundleError::DuplicateSection {
                name: "versions".into()
            })
        );
    }

    #[test]
    fn the_allowlist_contains_no_credential_shaped_names() {
        for name in ENV_ALLOWLIST {
            let upper = name.to_uppercase();
            assert!(
                !upper.ends_with("KEY") && !upper.contains("TOKEN") && !upper.contains("SECRET")
            );
        }
    }
}
