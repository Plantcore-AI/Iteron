//! Capture one actual current provider execution seed. Actual admission already owns its real
//! governor/USD obligations; the executable driver receives the trusted immutable tool scope.
use super::pricing::ProviderAttemptGuard;
use super::provider_execution_scope::ProviderExecutionConfiguration;
use super::provider_route::ProviderDispatchAdmission;
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_turn::ProviderRouteTurn;
use super::provider_turn_driver::ProviderTurnStart;
use super::{Agent, INTERRUPTED_STREAM_MAX_BYTES, KernelError};
use iteron_protocol::{Trust, TurnId};
use iteron_provider::TurnRequest;
use std::time::{Duration, Instant};

pub(super) struct ProviderTurnRequest {
    pub(super) turn: TurnId,
    pub(super) request: TurnRequest,
    pub(super) requested_output: u32,
    pub(super) argument_trust: Trust,
    pub(super) early_effects: bool,
}
impl Agent {
    pub(super) fn provider_turn_start(
        &mut self,
        input: ProviderTurnRequest,
        admission: ProviderDispatchAdmission,
    ) -> Result<(ProviderTurnStart, ProviderAttemptGuard), KernelError> {
        let extension_enabled = self.provider_extension_enabled();
        let deadline = self.run_deadline.current();
        let financial = self.provider_financial_source();
        let manifests = self.request_manifest_factory();
        let start = ProviderTurnStart {
            route: ProviderRouteTurn::new(
                input.request,
                input.requested_output,
                self.provider.clone(),
                self.governed_route_id(),
                &self.fallback_provider_routes,
                self.retry_policy,
                iteron_provider::MAX_INTERACTIVE_RETRY_AFTER,
            ),
            route_permit: admission.primary_route_permit,
            refusal: self.provider_dispatch_refusal(),
            hedged: admission.use_hedge,
            execution: ProviderExecutionConfiguration {
                turn: input.turn,
                strategy: self.compiled_policy_bundle.slots().tool_policy.clone(),
                trust: input.argument_trust,
                overlap: self.pure_overlap_enabled,
                early_effects: input.early_effects && !extension_enabled,
                hooks: self.hooks.clone(),
                hook_journal: self.hook_effect_journal.clone(),
                concurrency: self.scheduled_tool_concurrency()?,
                run_deadline: deadline,
                provider_deadline: deadline.unwrap_or_else(|| {
                    Instant::now()
                        .checked_add(Duration::from_secs(self.budget.max_wall_secs))
                        .unwrap_or_else(Instant::now)
                }),
                interrupt: self.control.interrupt().cloned(),
                force_cancel: self.control.force_cancel().clone(),
                drain: self.control.drain().clone(),
                allow_in_flight_past_deadline: extension_enabled,
                events: self.tool_events(input.turn),
            },
            events: ProviderRouteEvents {
                turn: input.turn,
                lifecycle: self.lifecycle_emitter.clone(),
                hooks: self.lifecycle_hooks.clone(),
                correlation: self.lifecycle_correlation(Some(input.turn)),
                activity: self.activity.clone(),
            },
            manifests,
            financial,
            prefix_limit: iteron_tunables::param_integer(
                "cli.runtime.interrupted_stream_max_bytes",
                INTERRUPTED_STREAM_MAX_BYTES,
            )
            .min(INTERRUPTED_STREAM_MAX_BYTES),
        };
        Ok((start, admission.attempt_guard))
    }
}
