//! Admission rules owned by the selected session-isolation profile.
//!
//! These checks run before continuation lookup or rollout creation. A hermetic benchmark attempt
//! therefore cannot accidentally read an earlier session merely because `--continue` or
//! `--resume` was present; durable and interactive profiles keep their explicit continuation
//! surfaces.

use iteron_tunables::RuntimeProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionIsolationPolicy {
    Hermetic,
    Durable,
    Interactive,
}

impl SessionIsolationPolicy {
    pub(crate) const fn from_runtime_profile(profile: RuntimeProfile) -> Self {
        match profile {
            RuntimeProfile::Benchmark => Self::Hermetic,
            RuntimeProfile::Research => Self::Durable,
            RuntimeProfile::Interactive => Self::Interactive,
        }
    }

    pub(crate) fn from_label(label: &str) -> Option<Self> {
        match label {
            "hermetic" => Some(Self::Hermetic),
            "durable" => Some(Self::Durable),
            "interactive" => Some(Self::Interactive),
            _ => None,
        }
    }

    pub(crate) fn admit_continuation(
        self,
        resume_requested: bool,
        continue_recent: bool,
    ) -> anyhow::Result<()> {
        if self == Self::Hermetic && (resume_requested || continue_recent) {
            anyhow::bail!(
                "hermetic sessions cannot use --resume or --continue; start a fresh isolated attempt"
            );
        }
        Ok(())
    }

    pub(crate) fn validate_profile(self, profile: RuntimeProfile) -> anyhow::Result<()> {
        if self != Self::from_runtime_profile(profile) {
            anyhow::bail!(
                "the immutable session-isolation profile does not match its runtime profile"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermetic_profile_rejects_both_continuation_surfaces() {
        let policy = SessionIsolationPolicy::from_runtime_profile(RuntimeProfile::Benchmark);
        assert!(policy.admit_continuation(true, false).is_err());
        assert!(policy.admit_continuation(false, true).is_err());
        assert!(policy.admit_continuation(false, false).is_ok());
    }

    #[test]
    fn non_hermetic_profiles_keep_explicit_continuation() {
        for profile in [RuntimeProfile::Interactive, RuntimeProfile::Research] {
            let policy = SessionIsolationPolicy::from_runtime_profile(profile);
            assert!(policy.admit_continuation(true, false).is_ok());
            assert!(policy.admit_continuation(false, true).is_ok());
            assert!(policy.validate_profile(profile).is_ok());
        }
    }

    #[test]
    fn checkpoint_profile_mismatch_is_rejected() {
        let policy = SessionIsolationPolicy::from_label("durable").unwrap();
        assert!(policy.validate_profile(RuntimeProfile::Research).is_ok());
        assert!(
            policy
                .validate_profile(RuntimeProfile::Interactive)
                .is_err()
        );
        assert!(SessionIsolationPolicy::from_label("unknown").is_none());
    }
}
