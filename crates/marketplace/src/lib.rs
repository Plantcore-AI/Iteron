//! Installing a plugin: what must be true before code the operator did not write starts running.
//!
//! A marketplace install is the moment a coding agent gains capabilities from a third party. Four
//! properties decide whether that is safe, and each of them fails in a way that looks like success.
//!
//! **Signature verification fails closed.** An entry whose signature is missing, malformed or from
//! an unknown key is refused -- not warned about and installed. "Warn and continue" on a supply
//! chain is indistinguishable from no check at all, because the operator who sees the warning is
//! the one who already decided to install.
//!
//! **An update may not move backwards.** Serving an older, still-correctly-signed version is the
//! classic rollback attack: every signature verifies, and the target quietly loses a security fix.
//! Version must strictly increase, and a request to go backwards is refused with both versions
//! named.
//!
//! **Rollback is only offered when it can actually be performed.** A rollback that discovers
//! mid-way that the previous artifact was garbage-collected leaves the operator with nothing
//! installed, which is worse than the version they were trying to leave.
//!
//! **Offline is a state, not a silence.** A cached catalogue is still usable when the network is
//! gone -- refusing to work offline would be its own failure -- but it is reported as stale, with
//! its age, so "no updates available" cannot be confused with "could not ask".
//!
//! # After installation: composition
//!
//! Installation admits third-party code one plugin at a time. The moment two of them are installed,
//! a second question opens that no per-install check can answer: several people who never met have
//! each contributed a skill, an agent, a hook, a language server, and something must decide what the
//! runtime actually exposes. [`composition`] holds that decision -- slot-addressed merge,
//! order-independent conflict resolution, and refusal of a malformed manifest in isolation from its
//! neighbours -- and states what process-level crash isolation would still require.

use std::collections::BTreeMap;

pub mod composition;
pub mod composition_model;
pub mod implementation;
pub mod implementation_activation;
pub mod implementation_protocol;
pub mod implementation_runtime;
pub mod package;

#[cfg(test)]
mod implementation_activation_tests;
#[cfg(test)]
mod implementation_runtime_tests;

pub use composition::{
    Arbitration, Binding, Composition, Contest, Host, Report, Wiring, compose, compose_governed,
};
pub use composition_model::{
    Contribution, Defect, MAX_CONTRIBUTIONS_PER_PLUGIN, MAX_DETAIL_BYTES,
    MAX_PLUGIN_MANIFEST_BYTES, MAX_PLUGIN_REQUIREMENTS, MAX_SLOT_KEY_BYTES, Manifest, PluginScope,
    Refusal, Requirement, RuntimeScope, Slot, Surface,
};
pub use implementation::{
    AdmittedImplementation, EvidenceLimits, IMPLEMENTATION_CATALOG_SCHEMA_VERSION,
    IMPLEMENTATION_PROCESS_PROTOCOL_VERSION, ImplementationCatalog, ImplementationDependency,
    ImplementationError, ImplementationFailurePolicy, ImplementationManifest,
    ImplementationRegistry, MAX_IMPLEMENTATION_ARG_BYTES, MAX_IMPLEMENTATION_ARGV,
    MAX_IMPLEMENTATION_ARGV_BYTES, MAX_IMPLEMENTATION_CANCELLATION_MS,
    MAX_IMPLEMENTATION_CATALOG_BYTES, MAX_IMPLEMENTATION_DEPENDENCIES,
    MAX_IMPLEMENTATION_EVIDENCE_BYTES, MAX_IMPLEMENTATION_ID_BYTES,
    MAX_IMPLEMENTATION_OBSERVATIONS, MAX_IMPLEMENTATION_PATH_BYTES, MAX_IMPLEMENTATION_RUNTIME_MS,
    MAX_IMPLEMENTATIONS, ProcessLaunchPlan, VerifiedArtifactDigest,
};
pub use implementation_activation::{
    ActivationInput, ActivationMismatch, ActivationPathField, ActivationPathProblem,
    IMPLEMENTATION_ACTIVATION_SCHEMA_VERSION, ImplementationActivation,
    ImplementationActivationDocument, ImplementationActivationError,
    ImplementationActivationIdentity, ImplementationSource, MAX_IMPLEMENTATION_ACTIVATION_BYTES,
    MAX_IMPLEMENTATION_ACTIVATION_SOURCES,
};
pub use implementation_protocol::{
    IMPLEMENTATION_PROTOCOL, ImplementationObservationEnvelope, ImplementationProtocolError,
    ImplementationRequest, ImplementationRequestEnvelope, ImplementationResponse,
    ImplementationResponseEnvelope, MAX_IMPLEMENTATION_MESSAGE_BYTES,
    MAX_IMPLEMENTATION_PAYLOAD_BYTES, parse_implementation_observation,
    parse_implementation_request, parse_implementation_response, parse_implementation_response_for,
};
pub use implementation_runtime::{
    ImplementationRuntime, ImplementationRuntimeError, MAX_IMPLEMENTATION_STDIN_BYTES,
    RuntimeEvidence, RuntimeState,
};
pub use package::{
    ActivePlugin, ArtifactRef, InstalledPackage, PackageError, PluginStore, RuntimePackages,
};

/// Longest plugin identifier accepted. Names appear in paths and in the operator's UI.
pub const MAX_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    #[error("{name}: signature is {problem}; refusing to install unverified code")]
    Unverified { name: String, problem: &'static str },
    #[error("{name}: would move from {installed} to {candidate}; an update may not go backwards")]
    Downgrade {
        name: String,
        installed: Version,
        candidate: Version,
    },
    #[error("{name}: already at {version}")]
    AlreadyCurrent { name: String, version: Version },
    #[error("{name}: not installed")]
    NotInstalled { name: String },
    #[error("{name}: no retained previous artifact, so rollback cannot be performed")]
    NoRollbackTarget { name: String },
    #[error("plugin name {name:?} is not a valid identifier")]
    InvalidName { name: String },
    #[error("{name}: requires {dependency}, which is not installed")]
    MissingDependency { name: String, dependency: String },
}

/// A three-part version. Ordering is derived, so comparison is lexicographic over the tuple, which
/// is exactly semantic-version precedence for the numeric iteron.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Version(pub u32, pub u32, pub u32);

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The result of checking an entry's signature against the trusted key set.
///
/// Deliberately not a `bool`. A boolean invites `if !verified { warn() }`; naming *why* something
/// failed makes the refusal explainable to the operator and keeps "unsigned" distinct from
/// "signed by a key we do not trust", which are different problems with different remedies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    Verified,
    Missing,
    Malformed,
    UnknownKey,
}

impl Signature {
    fn problem(self) -> Option<&'static str> {
        match self {
            Signature::Verified => None,
            Signature::Missing => Some("missing"),
            Signature::Malformed => Some("malformed"),
            Signature::UnknownKey => Some("from an untrusted key"),
        }
    }
}

/// One catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub version: Version,
    pub signature: Signature,
    pub requires: Vec<String>,
}

/// What is installed, and what it can fall back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub version: Version,
    pub enabled: bool,
    /// The version rollback would return to, present only while its artifact is retained.
    pub previous: Option<Version>,
}

/// How a catalogue was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Fetched successfully.
    Live,
    /// Served from cache because the network was unavailable. Carries the age so a caller can say
    /// how old, rather than presenting stale data as current.
    Stale { age_secs: u64 },
}

impl Freshness {
    /// Whether "no update available" from this catalogue is a fact or merely an absence of news.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Freshness::Live)
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len()
            <= iteron_tunables::param_integer("marketplace.lib.max_name_bytes", MAX_NAME_BYTES)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The installed set.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    plugins: BTreeMap<String, Installed>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&Installed> {
        self.plugins.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.plugins.keys().map(String::as_str).collect()
    }

    /// Install or update to `entry`.
    ///
    /// Checks run in order of what they protect: identity, then authenticity, then dependency
    /// availability, then version direction. Reporting "downgrade" for an entry that is also
    /// unsigned would name the least important problem.
    pub fn install(&mut self, entry: &Entry) -> Result<Version, InstallError> {
        if !valid_name(&entry.name) {
            return Err(InstallError::InvalidName {
                name: entry.name.clone(),
            });
        }
        if let Some(problem) = entry.signature.problem() {
            return Err(InstallError::Unverified {
                name: entry.name.clone(),
                problem,
            });
        }
        for dep in &entry.requires {
            if !self.plugins.contains_key(dep) {
                return Err(InstallError::MissingDependency {
                    name: entry.name.clone(),
                    dependency: dep.clone(),
                });
            }
        }

        match self.plugins.get(&entry.name) {
            Some(current) if entry.version < current.version => Err(InstallError::Downgrade {
                name: entry.name.clone(),
                installed: current.version,
                candidate: entry.version,
            }),
            Some(current) if entry.version == current.version => {
                Err(InstallError::AlreadyCurrent {
                    name: entry.name.clone(),
                    version: current.version,
                })
            }
            Some(current) => {
                let previous = Some(current.version);
                self.plugins.insert(
                    entry.name.clone(),
                    Installed {
                        version: entry.version,
                        enabled: current.enabled,
                        previous,
                    },
                );
                Ok(entry.version)
            }
            None => {
                self.plugins.insert(
                    entry.name.clone(),
                    Installed {
                        version: entry.version,
                        enabled: true,
                        // A first install has nothing to roll back to, and saying so up front is
                        // better than discovering it during a rollback.
                        previous: None,
                    },
                );
                Ok(entry.version)
            }
        }
    }

    /// Return to the retained previous version.
    pub fn rollback(&mut self, name: &str) -> Result<Version, InstallError> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| InstallError::NotInstalled {
                name: name.to_owned(),
            })?;
        let target = entry
            .previous
            .ok_or_else(|| InstallError::NoRollbackTarget {
                name: name.to_owned(),
            })?;
        entry.version = target;
        // One step only. Retaining a chain would imply artifacts that are not retained, and an
        // offer to roll back further than the evidence supports is the failure this type exists to
        // prevent.
        entry.previous = None;
        Ok(target)
    }

    /// Disable without uninstalling. Rollback state survives, because disabling is not a decision
    /// about which version is installed.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), InstallError> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| InstallError::NotInstalled {
                name: name.to_owned(),
            })?;
        entry.enabled = enabled;
        Ok(())
    }

    pub fn uninstall(&mut self, name: &str) -> Result<(), InstallError> {
        self.plugins
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| InstallError::NotInstalled {
                name: name.to_owned(),
            })
    }

    /// Names that would break if `name` were removed.
    ///
    /// Checked against a catalogue rather than remembered at install time: a dependency added by a
    /// later version of some *other* plugin is still a dependency.
    pub fn dependents<'a>(&self, name: &str, catalogue: &'a [Entry]) -> Vec<&'a str> {
        catalogue
            .iter()
            .filter(|e| self.plugins.contains_key(&e.name))
            .filter(|e| e.requires.iter().any(|d| d == name))
            .map(|e| e.name.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, v: (u32, u32, u32)) -> Entry {
        Entry {
            name: name.to_owned(),
            version: Version(v.0, v.1, v.2),
            signature: Signature::Verified,
            requires: Vec::new(),
        }
    }

    #[test]
    fn an_unverified_entry_is_refused_rather_than_warned_about() {
        // "Warn and continue" on a supply chain is indistinguishable from no check: the operator
        // reading the warning is the one who already decided to install.
        for sig in [
            Signature::Missing,
            Signature::Malformed,
            Signature::UnknownKey,
        ] {
            let mut r = Registry::new();
            let mut e = entry("fmt", (1, 0, 0));
            e.signature = sig;
            assert!(
                matches!(r.install(&e), Err(InstallError::Unverified { .. })),
                "{sig:?} must be refused"
            );
            assert!(r.get("fmt").is_none(), "nothing may be installed");
        }
    }

    #[test]
    fn the_refusal_distinguishes_unsigned_from_untrusted() {
        // Different problems with different remedies; collapsing them into `false` loses that.
        let mut r = Registry::new();
        let mut unsigned = entry("a", (1, 0, 0));
        unsigned.signature = Signature::Missing;
        let mut untrusted = entry("b", (1, 0, 0));
        untrusted.signature = Signature::UnknownKey;

        assert!(
            r.install(&unsigned)
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
        assert!(
            r.install(&untrusted)
                .unwrap_err()
                .to_string()
                .contains("untrusted key")
        );
    }

    #[test]
    fn a_correctly_signed_downgrade_is_still_refused() {
        // The rollback attack: every signature verifies and the target quietly loses a fix.
        let mut r = Registry::new();
        r.install(&entry("fmt", (2, 1, 0))).unwrap();
        let err = r.install(&entry("fmt", (2, 0, 9))).unwrap_err();
        assert_eq!(
            err,
            InstallError::Downgrade {
                name: "fmt".into(),
                installed: Version(2, 1, 0),
                candidate: Version(2, 0, 9),
            }
        );
        assert_eq!(r.get("fmt").unwrap().version, Version(2, 1, 0));
    }

    #[test]
    fn an_unsigned_downgrade_reports_the_signature_not_the_version() {
        // Checks run in order of what they protect; naming "downgrade" here would name the least
        // important problem.
        let mut r = Registry::new();
        r.install(&entry("fmt", (2, 0, 0))).unwrap();
        let mut old = entry("fmt", (1, 0, 0));
        old.signature = Signature::Missing;
        assert!(matches!(
            r.install(&old),
            Err(InstallError::Unverified { .. })
        ));
    }

    #[test]
    fn a_first_install_offers_no_rollback_and_says_so_up_front() {
        // Better than discovering it half way through a rollback, with nothing installed.
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        assert_eq!(r.get("fmt").unwrap().previous, None);
        assert_eq!(
            r.rollback("fmt"),
            Err(InstallError::NoRollbackTarget { name: "fmt".into() })
        );
        assert_eq!(r.get("fmt").unwrap().version, Version(1, 0, 0));
    }

    #[test]
    fn an_update_can_be_rolled_back_exactly_once() {
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        r.install(&entry("fmt", (1, 1, 0))).unwrap();
        assert_eq!(r.rollback("fmt").unwrap(), Version(1, 0, 0));
        // Retaining a chain would imply artifacts that are not retained.
        assert_eq!(
            r.rollback("fmt"),
            Err(InstallError::NoRollbackTarget { name: "fmt".into() })
        );
    }

    #[test]
    fn reinstalling_the_same_version_is_refused_rather_than_silently_consuming_rollback() {
        // Otherwise `install` at the current version would set `previous` to itself and destroy
        // the only real rollback target.
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        r.install(&entry("fmt", (1, 1, 0))).unwrap();
        assert!(matches!(
            r.install(&entry("fmt", (1, 1, 0))),
            Err(InstallError::AlreadyCurrent { .. })
        ));
        assert_eq!(r.get("fmt").unwrap().previous, Some(Version(1, 0, 0)));
    }

    #[test]
    fn a_missing_dependency_blocks_installation() {
        let mut r = Registry::new();
        let mut e = entry("lint", (1, 0, 0));
        e.requires = vec!["fmt".into()];
        assert_eq!(
            r.install(&e),
            Err(InstallError::MissingDependency {
                name: "lint".into(),
                dependency: "fmt".into()
            })
        );
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        assert!(r.install(&e).is_ok());
    }

    #[test]
    fn dependents_are_computed_from_the_catalogue_not_from_install_time_memory() {
        // A dependency added by a later version of another plugin is still a dependency.
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        r.install(&entry("lint", (1, 0, 0))).unwrap();
        let mut lint_v2 = entry("lint", (2, 0, 0));
        lint_v2.requires = vec!["fmt".into()];
        assert_eq!(r.dependents("fmt", &[lint_v2]), vec!["lint"]);
    }

    #[test]
    fn disabling_does_not_disturb_the_rollback_target() {
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 0, 0))).unwrap();
        r.install(&entry("fmt", (1, 1, 0))).unwrap();
        r.set_enabled("fmt", false).unwrap();
        assert!(!r.get("fmt").unwrap().enabled);
        assert_eq!(r.get("fmt").unwrap().previous, Some(Version(1, 0, 0)));
    }

    #[test]
    fn a_stale_catalogue_cannot_claim_there_are_no_updates() {
        // "No updates available" and "could not ask" must not read the same.
        assert!(Freshness::Live.is_authoritative());
        assert!(!Freshness::Stale { age_secs: 3600 }.is_authoritative());
    }

    #[test]
    fn an_invalid_plugin_name_is_refused() {
        let mut r = Registry::new();
        for bad in ["", "has space", "../escape", "a/b"] {
            let mut e = entry("x", (1, 0, 0));
            e.name = bad.to_owned();
            assert!(
                matches!(r.install(&e), Err(InstallError::InvalidName { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn version_ordering_is_numeric_not_lexicographic_on_text() {
        // `1.10.0` is newer than `1.9.0`; a string comparison says otherwise.
        assert!(Version(1, 10, 0) > Version(1, 9, 0));
        let mut r = Registry::new();
        r.install(&entry("fmt", (1, 9, 0))).unwrap();
        assert!(r.install(&entry("fmt", (1, 10, 0))).is_ok());
    }
}

#[cfg(test)]
#[path = "implementation_tests.rs"]
mod implementation_tests;

#[cfg(test)]
#[path = "implementation_protocol_tests.rs"]
mod implementation_protocol_tests;
