//! Historical wire vocabulary only. Standalone sessions hold no integration state or admission.
use crate::runtime::Agent;
use iteron_protocol::{Op, PlantcoreRunBootstrapV1};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlantcoreBootstrapAccepted {
    pub(crate) run_id: String,
    pub(crate) payload_digest_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlantcoreProtocolError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}
#[derive(Debug)]
pub(crate) struct PlantcoreAdmission;
impl PlantcoreAdmission {
    pub(crate) fn disabled() -> Self {
        Self
    }
    pub(crate) fn is_enabled(&self) -> bool {
        false
    }
    pub(crate) fn dispatch_gate(&self) -> Option<Arc<crate::runtime::DispatchGate>> {
        None
    }
    pub(crate) fn admit(
        &mut self,
        _payload: PlantcoreRunBootstrapV1,
        _agent: &mut Agent,
        _mcp: Option<&crate::mcp::McpRuntimeControl>,
    ) -> Result<PlantcoreBootstrapAccepted, PlantcoreProtocolError> {
        Err(PlantcoreProtocolError {
            code: "unsupported",
            message: "legacy integration is unavailable in standalone Iteron",
        })
    }
    pub(crate) fn admit_input(&mut self, _op: &Op) -> Result<(), PlantcoreProtocolError> {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::PlantcoreAdmission;
    #[test]
    fn default_admission_has_no_state_allocation_or_dispatch_authority() {
        assert_eq!(std::mem::size_of::<PlantcoreAdmission>(), 0);
        let admission = PlantcoreAdmission::disabled();
        assert!(!admission.is_enabled());
        assert!(admission.dispatch_gate().is_none());
    }
}
