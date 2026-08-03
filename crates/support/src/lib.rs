//! A support bundle the operator can read before deciding to send it.
//!
//! A diagnostic bundle is the one artefact an agent builds specifically in order to hand it to
//! someone else. That makes two properties load-bearing, and neither is the usual "collect useful
//! context" instinct.
//!
//! **It must be deterministic.** An operator who cannot diff two bundles cannot audit one. Nothing
//! here reads a clock, a random source, or a `HashMap` iteration order; the same inputs render the
//! same bytes. That is also what lets a reviewer check the redaction *once* rather than per run.
//!
//! **Environment capture is an allowlist, never a filter.** The tempting design collects the
//! environment and removes what looks secret. That is fail-open: it ships every variable nobody
//! thought about, and this machine's environment carries provider keys by construction. Here a
//! variable is absent unless it was named in advance, so an unknown variable is excluded because
//! it is unknown -- not because its value looked dangerous.
//!
//! Redaction reuses [`core_record::redact::scrub`] rather than reimplementing it. A second
//! redactor is a second thing to keep correct, and the two would drift; the shapes that matter
//! are already handled there, idempotently.
//!
//! Building a bundle is not consent to send it. [`Bundle`] has no transmit path at all -- it
//! renders to text, and moving that text anywhere is a separate, explicit act by the caller.

use core_record::redact::scrub;
use std::collections::BTreeMap;

/// Environment variables permitted into a bundle. Deliberately short, and deliberately not
/// including anything whose name ends in `KEY`, `TOKEN` or `SECRET`.
pub const ENV_ALLOWLIST: &[&str] = &["LANG", "LC_ALL", "TERM", "SHELL", "TZ"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("section {name:?} was added twice; a bundle must not carry two versions of one fact")]
    DuplicateSection { name: String },
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

    /// Add a fact. The value is scrubbed on the way in, so a `Section` never holds an unredacted
    /// secret even in memory before rendering.
    pub fn set(mut self, key: &str, value: &str) -> Self {
        self.entries.insert(key.to_owned(), scrub(value));
        self
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

    /// Attach a section. Adding the same name twice is refused rather than overwriting: a bundle
    /// holding two versions of one fact cannot be reasoned about by whoever reads it.
    pub fn section(mut self, name: &str, section: Section) -> Result<Self, BundleError> {
        if self.sections.contains_key(name) {
            return Err(BundleError::DuplicateSection {
                name: name.to_owned(),
            });
        }
        self.sections.insert(name.to_owned(), section);
        Ok(self)
    }

    /// Capture the environment through the allowlist.
    ///
    /// `lookup` supplies values so this stays testable and free of ambient state. Variables absent
    /// from the process are simply not present; a missing `TERM` is not reported as empty, because
    /// "unset" and "set to nothing" are different facts when diagnosing a terminal problem.
    pub fn environment(lookup: impl Fn(&str) -> Option<String>) -> Section {
        let mut section = Section::new();
        for name in ENV_ALLOWLIST {
            if let Some(value) = lookup(name) {
                section = section.set(name, &value);
            }
        }
        section
    }

    /// Render to deterministic, redacted text.
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
    fn rendering_is_byte_identical_across_runs_and_insertion_orders() {
        // An operator who cannot diff two bundles cannot audit one.
        let a = Bundle::new()
            .section(
                "versions",
                Section::new().set("core", "0.0.1").set("os", "macos"),
            )
            .unwrap()
            .section("terminal", Section::new().set("term", "xterm"))
            .unwrap();
        let b = Bundle::new()
            .section("terminal", Section::new().set("term", "xterm"))
            .unwrap()
            .section(
                "versions",
                Section::new().set("os", "macos").set("core", "0.0.1"),
            )
            .unwrap();
        assert_eq!(a.render(), b.render());
        assert_eq!(a.render(), a.render());
    }

    #[test]
    fn an_environment_variable_nobody_allowlisted_is_absent_even_if_it_looks_harmless() {
        // Fail-closed: exclusion is by absence from the allowlist, not by the value looking risky.
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
    fn an_allowlisted_variable_holding_a_secret_shape_is_still_scrubbed() {
        // Defence in depth: the allowlist is the first gate, redaction the second. Neither is
        // trusted to be sufficient alone.
        let section = Bundle::environment(env(&[(
            "SHELL",
            "/bin/zsh --token sk-ant-abcdefghijklmnopqrstuvwxyz0123456789",
        )]));
        let value = section.get("SHELL").unwrap();
        assert!(
            !value.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
            "allowlisted values must still be scrubbed: {value}"
        );
    }

    #[test]
    fn a_secret_never_reaches_the_rendered_bundle() {
        let secret = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
        let bundle = Bundle::new()
            .section(
                "config",
                Section::new().set("last_error", &format!("auth failed for {secret}")),
            )
            .unwrap();
        let rendered = bundle.render();
        assert!(!rendered.contains(secret), "{rendered}");
    }

    #[test]
    fn a_private_key_is_dropped_rather_than_summarised() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
        let bundle = Bundle::new()
            .section("config", Section::new().set("identity", pem))
            .unwrap();
        let rendered = bundle.render();
        assert!(!rendered.contains("MIIEvQIBADANBg"), "{rendered}");
    }

    #[test]
    fn a_value_is_scrubbed_on_the_way_in_not_only_at_render() {
        // So a Section in memory is already safe if something else logs it.
        let secret = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
        let section = Section::new().set("k", secret);
        assert!(!section.get("k").unwrap().contains(secret));
    }

    #[test]
    fn an_unset_variable_is_absent_rather_than_empty() {
        // "unset" and "set to nothing" are different facts when diagnosing a terminal.
        let section = Bundle::environment(env(&[("LANG", "en_US.UTF-8")]));
        assert_eq!(section.get("TERM"), None);
        assert!(!section.render_contains_key("TERM"));
    }

    #[test]
    fn a_duplicate_section_is_refused_rather_than_overwriting() {
        let bundle = Bundle::new()
            .section("versions", Section::new().set("core", "0.0.1"))
            .unwrap();
        assert_eq!(
            bundle.section("versions", Section::new().set("core", "9.9.9")),
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
                !upper.ends_with("KEY") && !upper.contains("TOKEN") && !upper.contains("SECRET"),
                "{name} must not be allowlisted"
            );
        }
    }

    #[test]
    fn a_bundle_exposes_no_way_to_transmit_itself() {
        // Compile-time property, asserted here as documentation: the only output is a String the
        // caller must deliberately do something with. Building is not consent.
        let bundle = Bundle::new();
        let _: String = bundle.render();
        assert_eq!(bundle.section_names(), Vec::<&str>::new());
    }

    impl Section {
        fn render_contains_key(&self, key: &str) -> bool {
            self.entries.contains_key(key)
        }
    }
}
