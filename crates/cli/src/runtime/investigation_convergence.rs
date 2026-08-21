//! Bounded, provider-independent convergence policy for tool-only investigation loops.

/// Consecutive tool-only rounds without a candidate-changing action before the controller asks the
/// model to converge.
pub(super) const INVESTIGATION_CONVERGENCE_ROUNDS: u32 = 6;
/// A second, wider ceiling enables a local execution gate that admits registered candidate-change
/// tools while keeping the provider-visible tool schemas stable. The model can still finish a
/// read-only task or name a blocker without a tool, but it cannot keep executing a broader coding
/// investigation indefinitely.
pub(super) const DEFAULT_IMPLEMENTATION_ROUNDS: u32 = 10;
const INVESTIGATION_CONVERGENCE_INSTRUCTION: &str = "[Iteron strategy checkpoint] You have completed several consecutive investigation-only rounds without attempting a candidate change. Stop broadening the search and synthesize the evidence already collected. If the operator requested a code change and the evidence supports one, make the smallest coherent change now and verify it. If the task is read-only, answer now. If a specific blocker remains, state it precisely. Perform another read or search only when it can falsify a named unresolved hypothesis; do not reread the same evidence merely for confidence.";
const DEFAULT_IMPLEMENTATION_INSTRUCTION: &str = "[Iteron action checkpoint] The bounded investigation phase is complete. On the next turn, either use a registered candidate-change tool to implement the smallest evidence-supported fix, finish the requested read-only answer, or state the exact blocker. The runtime will refuse further broad observation and orchestration calls until a candidate change occurs; do not substitute shell discovery for them.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InvestigationExecutionGate {
    Open,
    CandidateChangeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConvergenceStage {
    Synthesize,
    CandidateAction,
}

impl ConvergenceStage {
    pub(super) const fn reason_code(self) -> &'static str {
        match self {
            Self::Synthesize => "strategy_investigation_convergence",
            Self::CandidateAction => "strategy_candidate_action_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConvergenceRequest {
    pub(super) rounds: u32,
    pub(super) instruction: &'static str,
    pub(super) stage: ConvergenceStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvestigationConvergence {
    rounds: u32,
    synthesis_threshold: u32,
    action_threshold: u32,
    synthesis_sent: bool,
    action_required: bool,
}

impl Default for InvestigationConvergence {
    fn default() -> Self {
        let synthesis_threshold = iteron_tunables::param_integer(
            "cli.runtime.investigation_convergence.investigation_convergence_rounds",
            INVESTIGATION_CONVERGENCE_ROUNDS,
        )
        .clamp(2, 32);
        Self {
            rounds: 0,
            synthesis_threshold,
            action_threshold: iteron_tunables::param_integer(
                "cli.runtime.investigation_convergence.default_implementation_rounds",
                DEFAULT_IMPLEMENTATION_ROUNDS,
            )
            .clamp(synthesis_threshold.saturating_add(1), 64),
            synthesis_sent: false,
            action_required: false,
        }
    }
}

impl InvestigationConvergence {
    pub(super) const fn execution_gate(&self) -> InvestigationExecutionGate {
        if self.action_required {
            InvestigationExecutionGate::CandidateChangeOnly
        } else {
            InvestigationExecutionGate::Open
        }
    }

    /// Observe one completed tool round. A semantically registered candidate-change attempt opens
    /// a fresh bounded phase. The first threshold asks for synthesis; the second enables a local
    /// action gate instead of trusting a model to obey an unlimited soft hint. Tool schemas stay
    /// byte-stable across that transition so provider prompt caches remain reusable.
    pub(super) fn observe_round(
        &mut self,
        attempted_candidate_change: bool,
    ) -> Option<ConvergenceRequest> {
        if attempted_candidate_change {
            self.rounds = 0;
            self.synthesis_sent = false;
            self.action_required = false;
            return None;
        }
        self.rounds = self.rounds.saturating_add(1);
        if !self.synthesis_sent && self.rounds >= self.synthesis_threshold {
            self.synthesis_sent = true;
            return Some(ConvergenceRequest {
                rounds: self.rounds,
                instruction: iteron_tunables::param_str(
                    "cli.runtime.investigation_convergence.investigation_convergence_instruction",
                    INVESTIGATION_CONVERGENCE_INSTRUCTION,
                ),
                stage: ConvergenceStage::Synthesize,
            });
        }
        if !self.action_required && self.rounds >= self.action_threshold {
            self.action_required = true;
            return Some(ConvergenceRequest {
                rounds: self.rounds,
                instruction: iteron_tunables::param_str(
                    "cli.runtime.investigation_convergence.default_implementation_instruction",
                    DEFAULT_IMPLEMENTATION_INSTRUCTION,
                ),
                stage: ConvergenceStage::CandidateAction,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesis_then_action_only_is_bounded_and_candidate_change_resets_both() {
        let mut policy = InvestigationConvergence {
            rounds: 0,
            synthesis_threshold: 3,
            action_threshold: 5,
            synthesis_sent: false,
            action_required: false,
        };
        assert_eq!(policy.execution_gate(), InvestigationExecutionGate::Open);
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(false), None);
        let request = policy.observe_round(false).expect("threshold crossing");
        assert_eq!(request.rounds, 3);
        assert_eq!(request.stage, ConvergenceStage::Synthesize);
        assert!(request.instruction.contains("synthesize the evidence"));
        assert_eq!(policy.observe_round(false), None);
        let action = policy.observe_round(false).expect("action threshold");
        assert_eq!(action.rounds, 5);
        assert_eq!(action.stage, ConvergenceStage::CandidateAction);
        assert_eq!(
            policy.execution_gate(),
            InvestigationExecutionGate::CandidateChangeOnly
        );
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(true), None);
        assert_eq!(policy.execution_gate(), InvestigationExecutionGate::Open);
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(policy.observe_round(false), None);
        assert_eq!(
            policy.observe_round(false).unwrap().stage,
            ConvergenceStage::Synthesize
        );
    }
}
