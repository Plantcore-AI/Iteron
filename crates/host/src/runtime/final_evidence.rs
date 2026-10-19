//! One bounded live-invocation evidence owner. Only confirmed writer receipts update facts;
//! answer claims are read for a host correction, never treated as verification or permission.
use iteron_protocol::final_evidence::{
    HostConfiguredCheckV1, HostFinalCorrectionV1, HostFinalCoverageV1, HostFinalEvidenceV1,
    HostFinalWorkStateV1,
};
use iteron_protocol::{
    RunId, Seq, TenantId, TurnId, VerificationConsensusEvidence, VerificationOutcomeEvidence,
};

#[derive(Default)]
pub(super) struct HostFinalEvidenceOwner {
    first_turn: Option<TurnId>,
    tools: u64,
    failures: u64,
    check: Option<(HostConfiguredCheckV1, Seq)>,
    write_admitted: bool,
    native_changes: u64,
    native_source: Option<Seq>,
    last_receipt: Option<Seq>,
    overflow: bool,
    published: Option<HostFinalEvidenceV1>,
}
impl HostFinalEvidenceOwner {
    pub(super) fn begin(&mut self, first_turn: TurnId) {
        *self = Self {
            first_turn: Some(first_turn),
            ..Default::default()
        };
    }
    pub(super) fn write_admitted(&mut self) {
        self.write_admitted = true;
    }
    pub(super) fn tool_terminal(&mut self, turn: TurnId, source: Seq, failed: bool) {
        if !self.in_scope(turn) || self.last_receipt.is_some_and(|old| source <= old) {
            return;
        }
        self.last_receipt = Some(source);
        if let Some(next) = self.tools.checked_add(1) {
            self.tools = next;
        } else {
            self.overflow = true;
        }
        if failed {
            if let Some(next) = self.failures.checked_add(1) {
                self.failures = next;
            } else {
                self.overflow = true;
            }
        }
    }
    pub(super) fn native_change(
        &mut self,
        terminal: &super::tool_execution_journal::ToolTerminalReceipt,
        observed: &super::native_change_evidence::NativeChangeObservation,
    ) {
        let source = terminal.sequence();
        if source.0 == 0
            || !self.in_scope(terminal.turn())
            || self.last_receipt != Some(source)
            || self.native_source.is_some_and(|old| source <= old)
        {
            return;
        }
        let Some(count) = observed.confirmed_by(terminal) else {
            return;
        };
        if let Some(next) = self.native_changes.checked_add(count) {
            self.native_changes = next;
            self.native_source = Some(source);
        } else {
            self.overflow = true;
        }
    }
    pub(super) fn configured_check(
        &mut self,
        turn: TurnId,
        source: Seq,
        physical_runs: u16,
        consensus: VerificationConsensusEvidence,
        outcome: VerificationOutcomeEvidence,
    ) {
        if !self.in_scope(turn)
            || physical_runs == 0
            || self.check.is_some_and(|(_, old)| source <= old)
        {
            return;
        }
        let check = match (consensus, outcome) {
            (VerificationConsensusEvidence::Accepted, VerificationOutcomeEvidence::Pass) => {
                HostConfiguredCheckV1::Passed
            }
            (_, VerificationOutcomeEvidence::TestFailure) => HostConfiguredCheckV1::Failed,
            _ => HostConfiguredCheckV1::Unknown,
        };
        self.check = Some((check, source));
    }
    fn in_scope(&self, turn: TurnId) -> bool {
        self.first_turn.is_some_and(|first| turn.0 >= first.0)
    }
    pub(super) fn correction(&self, answer: &str) -> Option<HostFinalCorrectionV1> {
        if !claims_test_success(answer) {
            return None;
        }
        Some(
            if self
                .check
                .is_some_and(|(check, _)| check == HostConfiguredCheckV1::Failed)
            {
                HostFinalCorrectionV1::ConfiguredCheckFailed
            } else {
                HostFinalCorrectionV1::TestSuccessUnverified
            },
        )
    }
    /// The caller supplies the actual successful RunFinalization Done receipt, not a predicted
    /// sequence or UiEvent. There is one immutable published snapshot, with no historical map.
    pub(super) fn publish(
        &mut self,
        tenant: &TenantId,
        run: &RunId,
        turn: TurnId,
        done_source: Seq,
        effects_known: bool,
        answer: &str,
    ) -> Option<HostFinalEvidenceV1> {
        let first = self.first_turn?;
        if turn.0 < first.0
            || self.last_receipt.is_some_and(|seq| seq >= done_source)
            || self.check.is_some_and(|(_, seq)| seq >= done_source)
            || self.native_source.is_some_and(|seq| seq >= done_source)
        {
            return None;
        }
        let known = effects_known && !self.overflow;
        let configured_check = if known {
            self.check
                .map_or(HostConfiguredCheckV1::NotObserved, |(check, _)| check)
        } else {
            HostConfiguredCheckV1::Unknown
        };
        let evidence = HostFinalEvidenceV1 {
            tenant: tenant.clone(),
            run_id: run.clone(),
            first_turn: first,
            final_turn: turn,
            source_seq: done_source,
            observed_tool_completions: self.tools,
            observed_tool_failures: self.failures,
            observed_native_file_changes: if self.overflow {
                0
            } else {
                self.native_changes
            },
            native_change_source_seq: if self.overflow {
                None
            } else {
                self.native_source
            },
            work_state: if !self.overflow && self.native_changes > 0 {
                HostFinalWorkStateV1::ChangedUnverified
            } else {
                HostFinalWorkStateV1::Unverified
            },
            configured_check,
            configured_check_source_seq: self.check.map(|(_, source)| source),
            effects_known: known,
            write_capable_effect_admitted: self.write_admitted,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: self.correction(answer),
        };
        self.published = Some(evidence.clone());
        Some(evidence)
    }
    pub(super) fn published(&self) -> Option<HostFinalEvidenceV1> {
        self.published.clone()
    }
}

fn claims_test_success(text: &str) -> bool {
    // Classification is bounded and only produces a caution. It cannot mint a PASS receipt or
    // change completion. No part of the model's claim is copied into a trusted host message.
    let limit = iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES;
    let mut head_end = text.len().min(limit);
    while !text.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = text.len().saturating_sub(limit);
    while !text.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    let claims = [
        "tests passed",
        "all tests pass",
        "test suite passed",
        "测试通过",
        "测试全部通过",
        "全部测试通过",
        "测试均通过",
        "测试已通过",
    ];
    [&text[..head_end], &text[tail_start..]]
        .into_iter()
        .any(|segment| {
            let segment = segment.to_lowercase();
            claims.into_iter().any(|claim| segment.contains(claim))
        })
}

#[cfg(test)]
#[path = "final_evidence_tests.rs"]
mod tests;
