//! Completion observations never change the run owner, terminal outcome or input readiness.
use super::{App, Session, block, kv};
use iteron_protocol::client_final_evidence::HostFinalEvidenceReadV1;
use iteron_protocol::client_final_evidence::description;
use iteron_protocol::final_evidence::HostFinalEvidenceV1;
use iteron_protocol::{RunId, Seq};

#[derive(Default)]
pub(super) struct FinalEvidencePresentation {
    last: Option<(RunId, Seq)>,
}
impl FinalEvidencePresentation {
    fn admit(&mut self, fact: &HostFinalEvidenceV1) -> bool {
        if self
            .last
            .as_ref()
            .is_some_and(|(run, seq)| *run == fact.run_id && *seq >= fact.source_seq)
        {
            return false;
        }
        self.last = Some((fact.run_id.clone(), fact.source_seq));
        true
    }
}
pub(super) fn apply(app: &mut App, session: &Session, fact: HostFinalEvidenceV1) {
    let Some(scope) = session.client.thread_snapshot_v1() else {
        return;
    };
    if scope.run_id != fact.run_id {
        return;
    }
    let actual = session
        .client
        .host_final_evidence_v1(HostFinalEvidenceReadV1 {
            thread_id: scope.thread_id,
            run_id: scope.run_id,
        });
    let Some(observed) = actual
        .get("evidence")
        .and_then(|value| serde_json::from_value::<HostFinalEvidenceV1>(value.clone()).ok())
    else {
        return;
    };
    if observed != fact || !app.final_evidence.admit(&fact) {
        return;
    }
    app.panel(
        "◇",
        "Completion checks",
        vec![
            block::PanelRow::Note(description(&fact).into()),
            kv(
                "tool completions",
                &fact.observed_tool_completions.to_string(),
            ),
            kv("tool failures", &fact.observed_tool_failures.to_string()),
            kv(
                "effects",
                if fact.effects_known {
                    "known"
                } else {
                    "unconfirmed"
                },
            ),
            kv(
                "write-capable work",
                if fact.write_capable_effect_admitted {
                    "admitted; changes not independently inspected"
                } else {
                    "not observed"
                },
            ),
            kv("test-suite identity", "unverified"),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::final_evidence::{HostConfiguredCheckV1, HostFinalCoverageV1};
    use iteron_protocol::{TenantId, TurnId};
    #[test]
    fn configured_check_and_generic_completion_never_render_suite_success() {
        let mut fact = HostFinalEvidenceV1 {
            tenant: TenantId::default(),
            run_id: RunId("run".into()),
            first_turn: TurnId(0),
            final_turn: TurnId(0),
            source_seq: Seq(8),
            observed_tool_completions: 1,
            observed_tool_failures: 0,
            configured_check: HostConfiguredCheckV1::NotObserved,
            configured_check_source_seq: None,
            effects_known: true,
            write_capable_effect_admitted: true,
            coverage: HostFinalCoverageV1::LiveInvocation,
            workspace_diff_inspected: false,
            test_suite_identity_verified: false,
            correction: None,
        };
        assert!(description(&fact).contains("success is unverified"));
        fact.configured_check = HostConfiguredCheckV1::Passed;
        assert_eq!(
            description(&fact),
            "Configured check passed; test-suite identity remains unverified."
        );
        let mut owner = FinalEvidencePresentation::default();
        assert!(owner.admit(&fact));
        assert!(!owner.admit(&fact));
        fact.source_seq = Seq(9);
        assert!(owner.admit(&fact));
        fact.run_id = RunId("other".into());
        fact.source_seq = Seq(1);
        assert!(owner.admit(&fact));
    }
}
