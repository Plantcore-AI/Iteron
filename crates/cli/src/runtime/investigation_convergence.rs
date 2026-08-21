//! Bounded, provider-independent convergence policy for tool-only investigation loops.

/// Consecutive tool-only rounds without a candidate-changing action before the controller asks the
/// model to converge. This is a one-shot strategy hint, not a hard stop: difficult investigations
/// may continue when they can name a new falsifiable hypothesis.
pub(super) const INVESTIGATION_CONVERGENCE_ROUNDS: u32 = 6;
const INVESTIGATION_CONVERGENCE_INSTRUCTION: &str = "[Iteron strategy checkpoint] You have completed several consecutive investigation-only rounds without attempting a candidate change. Stop broadening the search and synthesize the evidence already collected. If the operator requested a code change and the evidence supports one, make the smallest coherent change now and verify it. If the task is read-only, answer now. If a specific blocker remains, state it precisely. Perform another read or search only when it can falsify a named unresolved hypothesis; do not reread the same evidence merely for confidence.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConvergenceRequest {
    pub(super) rounds: u32,
    pub(super) instruction: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvestigationConvergence {
    rounds: u32,
    threshold: u32,
    instruction_sent: bool,
}

impl Default for InvestigationConvergence {
    fn default() -> Self {
        Self {
            rounds: 0,
            threshold: iteron_tunables::param_integer(
                "cli.runtime.investigation_convergence.investigation_convergence_rounds",
                INVESTIGATION_CONVERGENCE_ROUNDS,
            )
            .clamp(2, 32),
            instruction_sent: false,
        }
    }
}

impl InvestigationConvergence {
    /// Observe one completed tool round. A candidate-changing attempt resets the streak. The first
    /// threshold crossing returns one request; later investigation remains allowed but quiet.
    pub(super) fn observe_round(
        &mut self,
        attempted_candidate_change: bool,
    ) -> Option<ConvergenceRequest> {
        if attempted_candidate_change {
            self.rounds = 0;
            return None;
        }
        self.rounds = self.rounds.saturating_add(1);
        if self.instruction_sent || self.rounds < self.threshold {
            return None;
        }
        self.instruction_sent = true;
        Some(ConvergenceRequest {
            rounds: self.rounds,
            instruction: iteron_tunables::param_str(
                "cli.runtime.investigation_convergence.investigation_convergence_instruction",
                INVESTIGATION_CONVERGENCE_INSTRUCTION,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_change_resets_the_streak_and_threshold_is_one_shot() {
        let mut policy = InvestigationConvergence {
            rounds: 0,
            threshold: 3,
            instruction_sent: false,
        };
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(true), None);
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(false), None);
        let request = policy.observe_round(false).expect("threshold crossing");
        assert_eq!(request.rounds, 3);
        assert!(request.instruction.contains("synthesize the evidence"));
        assert_eq!(policy.observe_round(false), None);
    }
}
