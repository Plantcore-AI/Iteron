//! Read the actual host's current live-invocation evidence without submitting a check or claim.
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFinalEvidenceReadV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
}
impl HostFinalEvidenceReadV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 256
            || self.thread_id.0.chars().any(char::is_control)
        {
            return Err("invalid evidence thread identity");
        }
        crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
            run_id: self.run_id.clone(),
        }
        .validate()
    }
}
/// Pure display of a host observation. This function cannot establish check or suite success.
pub fn description(fact: &crate::final_evidence::HostFinalEvidenceV1) -> &'static str {
    use crate::final_evidence::HostConfiguredCheckV1;
    match fact.configured_check {
        HostConfiguredCheckV1::Passed => {
            "Configured check passed; test-suite identity remains unverified."
        }
        HostConfiguredCheckV1::Failed => "Configured check failed.",
        HostConfiguredCheckV1::Unknown => "Check outcome is unconfirmed.",
        HostConfiguredCheckV1::NotObserved => {
            "No configured check was observed; test-suite success is unverified."
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_read_cannot_mint_a_check_or_modify_the_observation() {
        let source = serde_json::json!({"thread_id":"session-run","run_id":"run"});
        assert!(
            serde_json::from_value::<HostFinalEvidenceReadV1>(source.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for key in [
            "passed",
            "configured_check",
            "source_seq",
            "actor",
            "workspace",
            "run_command",
        ] {
            let mut forged = source.clone();
            forged[key] = serde_json::json!(true);
            assert!(serde_json::from_value::<HostFinalEvidenceReadV1>(forged).is_err());
        }
    }
}
