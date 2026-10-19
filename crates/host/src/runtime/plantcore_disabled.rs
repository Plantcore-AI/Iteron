//! Compatibility refusals for historical integration call sites. The standalone runtime owns
//! no integration state, paths, configuration, metering, product outputs or dispatch authority.
use super::{Agent, KernelError};
use iteron_protocol::{ProductResult, TurnId};
use std::sync::Arc;

const UNAVAILABLE: &str = "legacy integration is unavailable in standalone Iteron";

// These inaccessible sentinels preserve the typed historical transport contract. They cannot
// acquire a lease or admit a submission in a standalone build.
#[derive(Debug)]
pub struct DispatchGate;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeActivation;

impl DispatchGate {
    #[allow(
        dead_code,
        reason = "Frozen compatibility gate surface is unavailable in standalone; it cannot call the supplied effect or acquire state."
    )]
    pub async fn pause_after_safe_point(&self) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    pub(super) async fn await_recording_provider_usage_settled(&self) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    #[allow(
        dead_code,
        reason = "Frozen compatibility gate surface is unavailable in standalone; it cannot call the supplied effect or acquire state."
    )]
    pub fn prepare_resume(&self) -> Result<ResumeActivation, &'static str> {
        Err(UNAVAILABLE)
    }
    pub fn activate_resume(&self, _activation: ResumeActivation) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    #[allow(
        dead_code,
        reason = "Frozen compatibility gate surface is unavailable in standalone; it cannot call the supplied effect or acquire state."
    )]
    pub fn terminal(&self) {}
    #[allow(
        dead_code,
        reason = "Frozen compatibility gate surface is unavailable in standalone; it cannot call the supplied effect or acquire state."
    )]
    pub fn terminalize_if_accepted<T, E>(
        &self,
        _submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        Err(UNAVAILABLE)
    }
    pub fn submit_if_admitted<T, E>(
        &self,
        _submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        Err(UNAVAILABLE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Retained historical outcome vocabulary; standalone never constructs one.
pub(super) enum PlantcoreTerminal {
    Budget(&'static str),
    UsageUnavailable,
}

impl Agent {
    pub fn arm_recording_harness_error(&mut self) {}
    pub fn install_plantcore_dispatch_gate(&mut self, _gate: Arc<DispatchGate>) {}
    pub(super) fn plantcore_dispatch_gate(&self) -> Option<Arc<DispatchGate>> {
        None
    }
    pub(super) async fn cross_plantcore_logical_turn_gate(&self) -> Result<(), ()> {
        Ok(())
    }
    pub fn terminalize_plantcore_dispatch_gate(&self) {}
    pub fn plantcore_runtime_enabled(&self) -> bool {
        false
    }
    pub fn take_product_result(&mut self) -> Option<ProductResult> {
        None
    }
    pub(super) fn complete_plantcore_product(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    pub(super) fn plantcore_terminal(&self) -> Option<PlantcoreTerminal> {
        None
    }
    pub fn plantcore_usage_unavailable(&self) -> bool {
        false
    }
    pub(super) fn emit_plantcore_turn_usage(&mut self, _turn: TurnId) -> Result<(), KernelError> {
        Ok(())
    }
}
