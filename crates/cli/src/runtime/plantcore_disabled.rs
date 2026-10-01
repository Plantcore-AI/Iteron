//! Compatibility refusals for historical integration call sites. The standalone runtime owns
//! no integration state, paths, configuration, metering, product outputs or dispatch authority.
use super::{Agent, KernelError};
use iteron_protocol::{ArtifactDeclaration, ProductResult, ProviderRouteAttemptAccounting, TurnId};
use std::sync::Arc;

const UNAVAILABLE: &str = "legacy integration is unavailable in standalone Iteron";

#[derive(Debug, Default)]
pub(super) struct PlantcoreRuntime {
    _private: (),
}

impl PlantcoreRuntime {
    pub(super) fn terminal(&self) -> Option<PlantcoreTerminal> {
        None
    }
    pub(super) async fn enter_external_dispatch(&self) -> Result<Option<DispatchPermit>, ()> {
        Ok(None)
    }
    pub(super) fn observe_provider_attempt(
        &mut self,
        _turn: TurnId,
        _accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        Ok(())
    }
}

// These inaccessible sentinels preserve the typed historical transport contract. They cannot
// acquire a lease or admit a submission in a standalone build.
#[derive(Debug)]
pub(crate) struct DispatchGate;
#[derive(Debug)]
pub(super) struct DispatchPermit;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResumeActivation;

impl DispatchGate {
    pub(crate) async fn pause_after_safe_point(&self) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    pub(super) async fn await_recording_provider_usage_settled(&self) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    pub(crate) fn prepare_resume(&self) -> Result<ResumeActivation, &'static str> {
        Err(UNAVAILABLE)
    }
    pub(crate) fn activate_resume(
        &self,
        _activation: ResumeActivation,
    ) -> Result<(), &'static str> {
        Err(UNAVAILABLE)
    }
    pub(crate) fn terminal(&self) {}
    pub(crate) fn terminalize_if_accepted<T, E>(
        &self,
        _submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        Err(UNAVAILABLE)
    }
    pub(crate) fn submit_if_admitted<T, E>(
        &self,
        _submit: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, &'static str> {
        Err(UNAVAILABLE)
    }
    pub(super) async fn enter(self: &Arc<Self>) -> Option<DispatchPermit> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Retained historical outcome vocabulary; standalone never constructs one.
pub(super) enum PlantcoreTerminal {
    Budget(&'static str),
    UsageUnavailable,
}

impl Agent {
    pub(crate) fn arm_recording_harness_error(&mut self) {}
    pub(crate) fn install_plantcore_dispatch_gate(&mut self, _gate: Arc<DispatchGate>) {}
    pub(super) fn plantcore_dispatch_gate(&self) -> Option<Arc<DispatchGate>> {
        None
    }
    pub(super) fn is_plantcore_mcp_dispatch(&self, name: &str) -> bool {
        self.registry.is_mcp_effect(name)
    }
    pub(super) async fn enter_plantcore_external_dispatch(
        &self,
    ) -> Result<Option<DispatchPermit>, ()> {
        Ok(None)
    }
    pub(super) async fn cross_plantcore_logical_turn_gate(&self) -> Result<(), ()> {
        Ok(())
    }
    pub(crate) fn terminalize_plantcore_dispatch_gate(&self) {}
    pub(crate) fn plantcore_runtime_enabled(&self) -> bool {
        false
    }
    pub(crate) fn take_product_result(&mut self) -> Option<ProductResult> {
        None
    }
    pub(super) fn complete_plantcore_product(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    pub(super) fn observe_plantcore_provider_attempt(
        &mut self,
        _turn: TurnId,
        _accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    pub(super) fn plantcore_terminal(&self) -> Option<PlantcoreTerminal> {
        None
    }
    pub(crate) fn plantcore_usage_unavailable(&self) -> bool {
        false
    }
    pub(super) fn emit_plantcore_turn_usage(&mut self, _turn: TurnId) -> Result<(), KernelError> {
        Ok(())
    }
    pub(super) fn request_plantcore_input_from_value(
        &mut self,
        _tool_use_id: &str,
        _input: serde_json::Value,
    ) -> Result<(), String> {
        Err(UNAVAILABLE.into())
    }
    pub(super) async fn snapshot_plantcore_artifact(
        &mut self,
        _input: serde_json::Value,
    ) -> Result<ArtifactDeclaration, String> {
        Err(UNAVAILABLE.into())
    }
}

pub(super) fn artifact_result_content(_artifact: &ArtifactDeclaration) -> String {
    UNAVAILABLE.into()
}
