//! Admission rules owned by the selected session-isolation profile.
//!
//! These checks run before continuation lookup or rollout creation. A hermetic benchmark attempt
//! therefore cannot accidentally read an earlier session merely because `--continue` or
//! `--resume` was present; durable and interactive profiles keep their explicit continuation
//! surfaces.

use core_tunables::RuntimeProfile;

pub(crate) fn admit_continuation(
    profile: RuntimeProfile,
    resume_requested: bool,
    continue_recent: bool,
) -> anyhow::Result<()> {
    if profile == RuntimeProfile::Benchmark && (resume_requested || continue_recent) {
        anyhow::bail!(
            "benchmark sessions are hermetic and cannot use --resume or --continue; start a fresh benchmark attempt"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermetic_profile_rejects_both_continuation_surfaces() {
        assert!(admit_continuation(RuntimeProfile::Benchmark, true, false).is_err());
        assert!(admit_continuation(RuntimeProfile::Benchmark, false, true).is_err());
        assert!(admit_continuation(RuntimeProfile::Benchmark, false, false).is_ok());
    }

    #[test]
    fn non_hermetic_profiles_keep_explicit_continuation() {
        for profile in [RuntimeProfile::Interactive, RuntimeProfile::Research] {
            assert!(admit_continuation(profile, true, false).is_ok());
            assert!(admit_continuation(profile, false, true).is_ok());
        }
    }
}
