//! Read live host provenance; client requests cannot submit a reason, source or decision.
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalsReadV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
}
impl RefusalsReadV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 256
            || self.thread_id.0.chars().any(char::is_control)
        {
            return Err("invalid refusal thread identity");
        }
        crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
            run_id: self.run_id.clone(),
        }
        .validate()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_cannot_mint_an_authority_or_writer_receipt() {
        let source = serde_json::json!({"thread_id":"session-run","run_id":"run"});
        assert!(
            serde_json::from_value::<RefusalsReadV1>(source.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for key in [
            "reason",
            "origin",
            "source",
            "sequence",
            "effects",
            "administrator",
        ] {
            let mut forged = source.clone();
            forged[key] = serde_json::json!(true);
            assert!(serde_json::from_value::<RefusalsReadV1>(forged).is_err());
        }
    }
}
