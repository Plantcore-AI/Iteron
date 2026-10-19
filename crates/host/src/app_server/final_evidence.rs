//! Bounded presentation of one actual host receipt, with no writer, check or inference port.
use iteron_protocol::client_final_evidence::HostFinalEvidenceReadV1;
use iteron_protocol::final_evidence::HostFinalEvidenceV1;
use iteron_protocol::{RunId, SessionId, TenantId};
use serde_json::{Value, json};

#[derive(Default)]
pub(super) struct FinalEvidenceReader {
    scope: Option<(SessionId, TenantId, RunId)>,
    latest: Option<HostFinalEvidenceV1>,
}
impl FinalEvidenceReader {
    pub(super) fn bind(
        &mut self,
        thread: SessionId,
        tenant: TenantId,
        run: RunId,
        fact: Option<HostFinalEvidenceV1>,
    ) {
        self.scope = Some((thread, tenant, run));
        // None from a newly begun invocation clears the previous invocation's final receipt.
        self.latest = None;
        if let Some(fact) = fact {
            self.observe(&fact);
        }
    }
    pub(super) fn observe(&mut self, fact: &HostFinalEvidenceV1) -> bool {
        if self
            .scope
            .as_ref()
            .is_none_or(|(_, tenant, run)| *tenant != fact.tenant || *run != fact.run_id)
            || fact.source_seq.0 == 0
            || fact.first_turn.0 > fact.final_turn.0
            || fact.observed_tool_failures > fact.observed_tool_completions
            || !fact.native_change_evidence_valid()
            || fact
                .configured_check_source_seq
                .is_some_and(|seq| seq.0 == 0 || seq >= fact.source_seq)
            || matches!(
                fact.configured_check,
                iteron_protocol::final_evidence::HostConfiguredCheckV1::Passed
                    | iteron_protocol::final_evidence::HostConfiguredCheckV1::Failed
            ) && fact.configured_check_source_seq.is_none()
            || fact.configured_check
                == iteron_protocol::final_evidence::HostConfiguredCheckV1::NotObserved
                && fact.configured_check_source_seq.is_some()
            || fact.workspace_diff_inspected
            || fact.test_suite_identity_verified
        {
            return false;
        }
        if let Some(old) = self.latest.as_ref()
            && fact.source_seq <= old.source_seq
        {
            return old == fact;
        }
        self.latest = Some(fact.clone());
        true
    }
    pub(super) fn read(&self, command: HostFinalEvidenceReadV1) -> Value {
        if command.validate().is_err() {
            return refused("invalid_request");
        }
        let Some((thread, _, run)) = self.scope.as_ref() else {
            return refused("unavailable");
        };
        if *thread != command.thread_id || *run != command.run_id {
            return refused("scope_mismatch");
        }
        json!({"type":"host_final_evidence_v1","thread_id":thread,"run_id":run,"evidence":self.latest,
            "availability":if self.latest.is_some(){"available"}else{"no_live_invocation_receipt"},
            "source":"actual_host_receipt","historical_recovery":false})
    }
}
fn refused(code: &'static str) -> Value {
    json!({"type":"host_final_evidence_refused_v1","reason_code":code})
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::final_evidence::{HostConfiguredCheckV1, HostFinalCoverageV1};
    use iteron_protocol::{Seq, TurnId};
    fn fact() -> HostFinalEvidenceV1 {
        HostFinalEvidenceV1 {
            tenant: TenantId::default(),
            run_id: RunId("run".into()),
            first_turn: TurnId(0),
            final_turn: TurnId(0),
            source_seq: Seq(8),
            observed_tool_completions: 0,
            observed_tool_failures: 0,
            observed_native_file_changes: 0,
            native_change_source_seq: None,
            work_state: iteron_protocol::final_evidence::HostFinalWorkStateV1::Unverified,
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
            effects_known: true,
            write_capable_effect_admitted: false,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        }
    }
    #[test]
    fn additive_native_change_fields_keep_old_absent_bytes_and_reject_false_positive_shapes() {
        use iteron_protocol::final_evidence::HostFinalWorkStateV1;
        let original = fact();
        let wire = serde_json::to_value(&original).unwrap();
        for key in [
            "observed_native_file_changes",
            "native_change_source_seq",
            "work_state",
        ] {
            assert!(wire.get(key).is_none());
        }
        assert_eq!(
            serde_json::from_value::<HostFinalEvidenceV1>(wire).unwrap(),
            original
        );
        let mut owner = FinalEvidenceReader::default();
        owner.bind(
            SessionId("thread".into()),
            TenantId::default(),
            RunId("run".into()),
            None,
        );
        let mut native = original;
        native.observed_tool_completions = 1;
        native.write_capable_effect_admitted = true;
        native.observed_native_file_changes = 2;
        native.native_change_source_seq = Some(Seq(7));
        native.work_state = HostFinalWorkStateV1::ChangedUnverified;
        assert!(owner.observe(&native));
        for kind in [
            "zero",
            "no_source",
            "future_source",
            "state",
            "all_failed",
            "no_write",
        ] {
            let mut forged = native.clone();
            forged.source_seq = Seq(9);
            match kind {
                "zero" => forged.observed_native_file_changes = 0,
                "no_source" => forged.native_change_source_seq = None,
                "future_source" => forged.native_change_source_seq = Some(Seq(9)),
                "state" => forged.work_state = HostFinalWorkStateV1::Unverified,
                "all_failed" => forged.observed_tool_failures = 1,
                _ => forged.write_capable_effect_admitted = false,
            }
            assert!(!owner.observe(&forged), "{kind}");
        }
    }
    fn read(reader: &FinalEvidenceReader) -> Value {
        reader.read(HostFinalEvidenceReadV1 {
            thread_id: SessionId("thread".into()),
            run_id: RunId("run".into()),
        })
    }
    #[test]
    fn missing_receipt_remains_absent_and_read_cannot_claim_suite_pass() {
        let mut owner = FinalEvidenceReader::default();
        owner.bind(
            SessionId("thread".into()),
            TenantId::default(),
            RunId("run".into()),
            None,
        );
        assert_eq!(read(&owner)["availability"], "no_live_invocation_receipt");
        let actual = fact();
        assert!(owner.observe(&actual));
        assert!(owner.observe(&actual));
        assert_eq!(read(&owner)["evidence"]["configured_check"], "not_observed");
        assert_eq!(
            read(&owner)["evidence"]["test_suite_identity_verified"],
            false
        );
        let mut forged = actual.clone();
        forged.test_suite_identity_verified = true;
        assert!(!owner.observe(&forged));
        forged = actual;
        forged.configured_check = HostConfiguredCheckV1::Passed;
        assert!(!owner.observe(&forged));
        owner.bind(
            SessionId("thread".into()),
            TenantId::default(),
            RunId("run".into()),
            None,
        );
        assert!(
            read(&owner)["evidence"].is_null(),
            "beginning a new invocation clears the old receipt"
        );
    }
    #[test]
    fn tenant_run_and_terminal_source_are_checked_without_full_history_inference() {
        let mut owner = FinalEvidenceReader::default();
        owner.bind(
            SessionId("thread".into()),
            TenantId::default(),
            RunId("run".into()),
            None,
        );
        let actual = fact();
        let mut foreign = actual.clone();
        foreign.run_id = RunId("foreign".into());
        assert!(!owner.observe(&foreign));
        foreign = actual.clone();
        foreign.tenant = TenantId("foreign".into());
        assert!(!owner.observe(&foreign));
        foreign = actual.clone();
        foreign.source_seq = Seq::ZERO;
        assert!(!owner.observe(&foreign));
        assert!(owner.observe(&actual));
        owner.bind(
            SessionId("other".into()),
            TenantId::default(),
            RunId("other".into()),
            None,
        );
        assert_eq!(read(&owner)["reason_code"], "scope_mismatch");
        assert!(!owner.observe(&actual));
    }
}
