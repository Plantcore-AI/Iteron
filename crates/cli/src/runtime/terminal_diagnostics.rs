//! Typed, content-free terminal evidence for one user-facing turn.

use super::*;
use iteron_protocol::PolicyHarnessErrorCode;
use iteron_protocol::product_contract::{TerminalEffectStateV1, TerminalEvidenceV1};

impl Agent {
    /// Arm the retained effect owner at the actual physical head before this product turn can
    /// admit work. Adoption clears it; legacy callers without this boundary retain verified replay.
    pub(crate) fn begin_terminal_diagnostic_scope(&mut self, first_sequence: Seq) {
        self.effect_journal
            .begin_terminal_scope(&self.rollout, first_sequence);
    }

    /// Classify the completed Product Turn without parsing a human-readable error. Admission
    /// captures this held physical rollout's next sequence before any run or follow-up work.
    /// A refusal can precede the kernel turn advance, so turn IDs cannot separate this scope.
    pub(crate) fn terminal_diagnostic_snapshot(
        &self,
        first_sequence: Seq,
        completion: &Result<Outcome, KernelError>,
    ) -> TerminalEvidenceV1 {
        let failure_code = match completion {
            Err(error) => Some(policy_evidence::policy_harness_error_code(error)),
            Ok(Outcome::Done) => None,
            Ok(Outcome::Drained) => Some(PolicyHarnessErrorCode::OperatorDrain),
            Ok(Outcome::Interrupted) => Some(PolicyHarnessErrorCode::OperatorInterrupted),
            Ok(Outcome::Stuck) => Some(PolicyHarnessErrorCode::ConsecutiveToolErrors),
            Ok(Outcome::BudgetExhausted(reason)) => {
                Some(policy_evidence::policy_budget_harness_error_code(reason))
            }
            Ok(Outcome::HarnessError) => Some(
                if self.plantcore_terminal() == Some(plantcore::PlantcoreTerminal::UsageUnavailable)
                {
                    PolicyHarnessErrorCode::UsageUnavailable
                } else {
                    PolicyHarnessErrorCode::HarnessFailure
                },
            ),
        };
        TerminalEvidenceV1 {
            failure_code,
            effect_state: self.terminal_effect_state(first_sequence),
        }
    }

    fn terminal_effect_state(&self, first_sequence: Seq) -> TerminalEffectStateV1 {
        // A failed append makes the physical record untrustworthy even if its readable prefix
        // happens to show settled effects. Never turn that prefix into an AllSettled claim.
        if self.record_failed {
            return TerminalEffectStateV1::Unavailable;
        }
        if let Some(state) = self
            .effect_journal
            .terminal_state(&self.rollout, first_sequence)
        {
            return state;
        }
        let Ok(events) = iteron_record::replay(self.rollout.path()) else {
            return TerminalEffectStateV1::Unavailable;
        };
        let scoped = events
            .into_iter()
            .filter(|event| event.seq.0 >= first_sequence.0)
            .collect::<Vec<_>>();
        let Ok(journal) = effects::EffectJournal::replay(&scoped) else {
            return TerminalEffectStateV1::Unavailable;
        };
        if !journal.pending().is_empty() || journal.unknown_count() > 0 {
            TerminalEffectStateV1::Unknown
        } else if journal.admitted().next().is_some() {
            TerminalEffectStateV1::AllSettled
        } else {
            TerminalEffectStateV1::NotDispatched
        }
    }
}
