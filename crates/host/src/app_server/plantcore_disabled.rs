//! Historical wire vocabulary only. Standalone sessions hold no integration state or admission.
use crate::runtime::Agent;
use iteron_protocol::{Op, PlantcoreRunBootstrapV1};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantcoreBootstrapAccepted;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantcoreProtocolError {
    pub code: &'static str,
    pub message: &'static str,
}
#[derive(Debug)]
pub struct PlantcoreAdmission;
impl PlantcoreAdmission {
    pub fn disabled() -> Self {
        Self
    }
    pub fn is_enabled(&self) -> bool {
        false
    }
    pub fn dispatch_gate(&self) -> Option<Arc<crate::runtime::DispatchGate>> {
        None
    }
    pub fn admit(
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
    pub fn admit_input(&mut self, _op: &Op) -> Result<(), PlantcoreProtocolError> {
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
