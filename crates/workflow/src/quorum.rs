//! Bounded early-stop policy for a `parallelQuorum(...)` fan.
//!
//! Ordinary `parallel(...)` remains a declaration-order, wait-all barrier. A caller must opt into
//! quorum semantics explicitly, which prevents an exploratory fan from silently losing coverage.

use serde::{Deserialize, Serialize};

/// Maximum accepted quorum count. This matches the workflow DSL's per-parallel-call ceiling.
pub const MAX_EARLY_STOP_QUORUM: usize = 4_096;

/// The production default represented by tunable family 142.
///
/// `strong_veto` is conservative: once any member settles without evidence, the group no longer
/// early-stops and waits for every remaining member. It never turns a failed child into evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarlyStopQuorumPolicy {
    minimum_evidence: usize,
    required_roles: usize,
    strong_veto: bool,
}

impl EarlyStopQuorumPolicy {
    pub fn new(
        minimum_evidence: usize,
        required_roles: usize,
        strong_veto: bool,
    ) -> Result<Self, &'static str> {
        if !(1..=iteron_tunables::param_usize(
            "workflow.quorum.max_early_stop_quorum",
            iteron_tunables::param_integer(
                "workflow.quorum.max_early_stop_quorum",
                MAX_EARLY_STOP_QUORUM,
            ),
        ))
            .contains(&minimum_evidence)
        {
            return Err("minimum evidence must be in 1..=4096");
        }
        if required_roles > 256 {
            return Err("required roles must be in 0..=256");
        }
        if required_roles > minimum_evidence {
            return Err("required roles cannot exceed minimum evidence");
        }
        Ok(Self {
            minimum_evidence,
            required_roles,
            strong_veto,
        })
    }

    pub const fn minimum_evidence(self) -> usize {
        self.minimum_evidence
    }

    pub const fn required_roles(self) -> usize {
        self.required_roles
    }

    pub const fn strong_veto(self) -> bool {
        self.strong_veto
    }
}

impl Default for EarlyStopQuorumPolicy {
    fn default() -> Self {
        Self::new(1, 0, true).expect("the built-in quorum policy is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_or_impossible_policies() {
        assert!(EarlyStopQuorumPolicy::new(0, 0, false).is_err());
        assert!(EarlyStopQuorumPolicy::new(MAX_EARLY_STOP_QUORUM + 1, 0, false).is_err());
        assert!(EarlyStopQuorumPolicy::new(1, 2, false).is_err());
        assert!(EarlyStopQuorumPolicy::new(256, 257, false).is_err());
    }
}
