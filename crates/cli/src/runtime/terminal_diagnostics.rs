//! Typed, content-free terminal evidence for one user-facing turn.

use super::*;
use iteron_protocol::PolicyHarnessErrorCode;
use iteron_protocol::product_contract::{TerminalEffectStateV1, TerminalEvidenceV1};

impl Agent {
    /// Classify the completed Product Turn without parsing a human-readable error. `first_turn`
    /// is the kernel turn captured by the App Server at admission; one Product Turn may contain
    /// several physical model turns, all of which belong to this evidence snapshot.
    pub(crate) fn terminal_diagnostic_snapshot(
        &self,
        first_turn: TurnId,
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
            effect_state: self.terminal_effect_state(first_turn),
        }
    }

    fn terminal_effect_state(&self, first_turn: TurnId) -> TerminalEffectStateV1 {
        // A failed append makes the physical record untrustworthy even if its readable prefix
        // happens to show settled effects. Never turn that prefix into an AllSettled claim.
        if self.record_failed {
            return TerminalEffectStateV1::Unavailable;
        }
        let Ok(events) = replay_logical_rollout(self.rollout.path()) else {
            return TerminalEffectStateV1::Unavailable;
        };
        let scoped = events
            .into_iter()
            .filter(|event| event.turn.0 >= first_turn.0)
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
