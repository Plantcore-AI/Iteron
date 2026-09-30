//! Actual undispatched request and bounded emergency-compaction candidate owner. Summary IO,
//! durable compaction commit, hooks and control safe points use the existing host ports.
use super::KernelError;
use super::compaction::CompactionCommitReceipt;
use super::context_runtime::{ContextBudgetInspection, ContextBudgetRecoveryGuard};
use super::request_accounting::{AccountedRequest, RequestAccounting};
use iteron_ctx::{
    CompactionPlan, CompactionPolicy, ContextBudgetViolation, ContextEstimate, RequestEstimator,
};
use iteron_protocol::{ImageContent, ReasoningEffort};
use iteron_protocol::{LifecyclePayload, Message};
use iteron_provider::{PreparedToolSchemas, ProviderRequestControls, TurnRequest};
use sha2::{Digest, Sha256};

#[cfg(all(test, unix))]
#[path = "request_preparation_tests.rs"]
mod tests;

pub(super) struct RequestContent<'a> {
    pub(super) system: String,
    pub(super) messages: &'a mut Vec<Message>,
    pub(super) input_images: Vec<ImageContent>,
    pub(super) tools: PreparedToolSchemas,
    pub(super) max_tokens: u32,
}
pub(super) struct RequestConfiguration {
    pub(super) model: String,
    pub(super) cache_system: bool,
    pub(super) thinking_budget: u32,
    pub(super) reasoning_effort: ReasoningEffort,
    pub(super) controls: ProviderRequestControls,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparationPhase {
    Projected,
    RecoveryRequested,
    Recovering,
    Assessed,
    RecoverySettled,
    Validated,
}
struct Recovery {
    window_overflow: bool,
    initial_violation: Option<ContextBudgetViolation>,
    component: Option<ContextBudgetViolation>,
    before: Option<usize>,
    after: Option<usize>,
    plan: Option<CompactionPlan>,
}
struct Candidate {
    messages: Vec<Message>,
    accounting: AccountedRequest,
    submitted_summary_sha256: [u8; 32],
    summarized: usize,
}
pub(super) struct RequestPreparation<'a> {
    request: RequestContent<'a>,
    requested_output: u32,
    window: Option<u64>,
    accounting: RequestAccounting,
    projection: AccountedRequest,
    phase: PreparationPhase,
    recovery: Option<Recovery>,
    candidate: Option<Candidate>,
}

impl<'a> RequestPreparation<'a> {
    pub(super) fn new(
        request: RequestContent<'a>,
        requested_output: u32,
        window: Option<u64>,
        accounting: RequestAccounting,
        estimator: &mut RequestEstimator,
    ) -> Self {
        let raw = estimator.estimate_with_tool_tokens(
            &request.system,
            &request.messages,
            request.tools.len(),
            request.tools.estimated_tokens(),
            request.tools.cache_identity(),
        );
        let projection = accounting.project(estimator, &request.messages, raw);
        Self {
            request,
            requested_output,
            window,
            accounting,
            projection,
            phase: PreparationPhase::Projected,
            recovery: None,
            candidate: None,
        }
    }
    pub(super) fn request(&self) -> &RequestContent<'a> {
        &self.request
    }
    pub(super) fn estimate(&self) -> ContextEstimate {
        self.projection.estimate
    }
    pub(super) fn baseline(&self) -> usize {
        self.projection.baseline
    }
    pub(super) fn inspection(&self) -> ContextBudgetInspection {
        self.projection.inspection
    }

    /// Auxiliary physical work can durably select another resident route. The host supplies
    /// its real current context-window and physical-output proof before assessing a candidate
    /// or final admission. The original requested policy remains separate and unchanged.
    pub(super) fn bind_route_budget(
        &mut self,
        window: Option<u64>,
        physical_output: u32,
    ) -> Result<(), KernelError> {
        if self.phase == PreparationPhase::Validated {
            return Err(KernelError::ContextResolution(
                "validated request route cannot be rebound".into(),
            ));
        }
        if physical_output == 0 {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "rebound route needs a nonzero physical output ceiling",
            });
        }
        self.window = window;
        self.request.max_tokens = physical_output;
        Ok(())
    }

    /// Claim only the existing once-per-growth component bridge. A default ordinary turn that
    /// fits its actual cap/window does not create a plan or admit an auxiliary provider call.
    pub(super) fn recovery_request(
        &mut self,
        compaction: &CompactionPolicy,
        compacted_in_run: bool,
        guard: &mut ContextBudgetRecoveryGuard,
    ) -> Option<LifecyclePayload> {
        if self.phase != PreparationPhase::Projected {
            return None;
        }
        let estimate = self.estimate();
        let window_overflow = self.window.map_or_else(
            || {
                estimate.total_tokens
                    > compaction.effective_trigger_tokens(None, self.request.max_tokens)
            },
            |window| {
                u64::try_from(estimate.total_tokens)
                    .unwrap_or(u64::MAX)
                    .saturating_add(u64::from(self.request.max_tokens))
                    > window
            },
        );
        let compactable = compaction.enabled
            && self.request.messages.len() > compaction.keep_recent.saturating_add(2);
        let initial_violation = self.inspection().violation();
        let component = if compactable {
            initial_violation.filter(|violation| guard.claim(violation))
        } else {
            None
        };
        let before = component.map(|v| self.inspection().component_tokens(v.class));
        self.recovery = Some(Recovery {
            window_overflow,
            initial_violation,
            component,
            before,
            after: None,
            plan: None,
        });
        if !(compactable && !compacted_in_run && window_overflow) && component.is_none() {
            return None;
        }
        self.phase = PreparationPhase::RecoveryRequested;
        Some(self.recovery_payload(None))
    }
    pub(super) fn authorize_recovery(&mut self, compaction: &CompactionPolicy, allowed: bool) {
        if self.phase != PreparationPhase::RecoveryRequested {
            return;
        }
        self.phase = PreparationPhase::Recovering;
        if allowed {
            self.recovery
                .as_mut()
                .expect("owned recovery decision")
                .plan = compaction.force_plan(&self.request.messages);
        }
    }
    pub(super) fn plan(&self) -> Option<&CompactionPlan> {
        self.recovery
            .as_ref()
            .and_then(|recovery| recovery.plan.as_ref())
    }
    pub(super) fn recovery_payload(&self, count: Option<usize>) -> LifecyclePayload {
        let recovery = self.recovery.as_ref().expect("owned recovery projection");
        if let Some(violation) = recovery.component {
            LifecyclePayload {
                reason_code: Some(violation.reason_code().into()),
                count: Some(u64::try_from(violation.ceiling).unwrap_or(u64::MAX)),
                magnitude: Some(
                    u64::try_from(recovery.before.unwrap_or(violation.used)).unwrap_or(u64::MAX),
                ),
                ..LifecyclePayload::default()
            }
        } else {
            LifecyclePayload {
                count: count.map(|count| u64::try_from(count).unwrap_or(u64::MAX)),
                magnitude: count
                    .is_none()
                    .then(|| u64::try_from(self.estimate().total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            }
        }
    }
    pub(super) fn recovery_reason(&self) -> &'static str {
        if self
            .recovery
            .as_ref()
            .is_some_and(|r| r.component.is_some())
        {
            "component_budget_recovery"
        } else {
            "overflow_emergency"
        }
    }
    /// Assess only an actual completed summary. A rejected candidate cannot overwrite the real
    /// transcript, and a second assessment cannot install a different summary after approval.
    pub(super) fn assess_summary(
        &mut self,
        summary: &str,
        covered: bool,
        compaction: &CompactionPolicy,
        estimator: &RequestEstimator,
        accounting: RequestAccounting,
    ) -> Result<Option<&'static str>, KernelError> {
        if self.phase != PreparationPhase::Recovering || self.plan().is_none() {
            return Err(KernelError::ContextResolution(
                "summary lacks its owned recovery plan".into(),
            ));
        }
        self.phase = PreparationPhase::Assessed;
        let rebuilt =
            CompactionPolicy::rebuild(self.plan().expect("owned plan"), summary.to_owned());
        let raw = estimator.estimate_uncached(
            &self.request.system,
            &rebuilt,
            self.request.tools.as_ref(),
        );
        let projection = accounting.project(estimator, &rebuilt, raw);
        let recovery = self.recovery.as_mut().expect("owned recovery projection");
        if let Some(violation) = recovery.component {
            recovery.after = Some(projection.inspection.component_tokens(violation.class));
        }
        let exit = compaction.hysteresis.exit_threshold(
            compaction.effective_trigger_tokens(self.window, self.request.max_tokens),
        );
        let reason = if !covered {
            Some("summary_coverage_missing")
        } else if projection.inspection.violation().is_some() {
            Some("component_budget_not_recovered")
        } else if recovery.window_overflow && projection.estimate.total_tokens > exit {
            Some("hysteresis_exit_not_reached")
        } else {
            None
        };
        if reason.is_none() {
            self.accounting = accounting;
            self.candidate = Some(Candidate {
                messages: rebuilt,
                accounting: projection,
                submitted_summary_sha256: Sha256::digest(summary.as_bytes()).into(),
                summarized: self.plan().expect("assessed plan").to_summarize.len(),
            });
        }
        Ok(reason)
    }
    pub(super) fn fatal_recovery_refusal(&self, covered: bool) -> Option<KernelError> {
        self.recovery
            .as_ref()
            .filter(|r| r.initial_violation.is_none())
            .map(|_| {
                KernelError::ContextResolution(if covered {
                    "emergency compaction did not cross the resolved hysteresis exit".into()
                } else {
                    "emergency compaction summary failed the resolved coverage check".into()
                })
            })
    }
    /// Caller must have committed the actual compaction record first. This only moves the
    /// accepted candidate and invalidates the genuine incremental estimator after the rewrite.
    pub(super) fn commit_candidate(
        &mut self,
        receipt: CompactionCommitReceipt,
        estimator: &mut RequestEstimator,
    ) -> Result<Option<(ContextBudgetViolation, usize)>, KernelError> {
        if self.phase != PreparationPhase::Assessed {
            return Err(KernelError::ContextResolution(
                "compaction candidate is unassessed".into(),
            ));
        }
        let candidate = self.candidate.as_ref().ok_or_else(|| {
            KernelError::ContextResolution("compaction candidate was refused or consumed".into())
        })?;
        if !receipt.matches(candidate.summarized, &candidate.submitted_summary_sha256) {
            return Err(KernelError::ContextResolution(
                "compaction commit proof differs from the candidate".into(),
            ));
        }
        let candidate = self.candidate.take().ok_or_else(|| {
            KernelError::ContextResolution("compaction candidate was refused or consumed".into())
        })?;
        *self.request.messages = candidate.messages;
        self.projection = candidate.accounting;
        self.accounting.clear_file();
        estimator.invalidate_transcript();
        Ok(self
            .recovery
            .as_ref()
            .and_then(|r| r.component.map(|v| (v, r.after.unwrap_or(v.used)))))
    }
    pub(super) fn settle_recovery(
        &mut self,
        guard: &mut ContextBudgetRecoveryGuard,
    ) -> Option<(ContextBudgetViolation, usize)> {
        if matches!(
            self.phase,
            PreparationPhase::Projected | PreparationPhase::RecoveryRequested
        ) || self.candidate.is_some()
        {
            return None;
        }
        self.phase = PreparationPhase::RecoverySettled;
        let recovery = self.recovery.as_ref()?;
        let violation = recovery.component?;
        let recovered = self.inspection().violation().is_none();
        guard.settle(recovered);
        (!recovered).then_some((
            violation,
            recovery.after.or(recovery.before).unwrap_or(violation.used),
        ))
    }
    pub(super) fn window_refusal(&self) -> Option<KernelError> {
        let window = self.window?;
        let input = u64::try_from(self.estimate().total_tokens).unwrap_or(u64::MAX);
        (input.saturating_add(u64::from(self.request.max_tokens)) > window).then_some(
            KernelError::ContextWindowExceeded {
                estimated_input_tokens: input,
                reserved_output_tokens: self.request.max_tokens,
                context_window_tokens: window,
            },
        )
    }
    pub(super) fn validate(&mut self) -> Result<(), KernelError> {
        if !matches!(
            self.phase,
            PreparationPhase::Projected | PreparationPhase::RecoverySettled
        ) || self.candidate.is_some()
        {
            return Err(KernelError::ContextResolution(
                "request recovery is unsettled".into(),
            ));
        }
        if let Some(error) = self.window_refusal() {
            return Err(error);
        }
        if let Some(violation) = self.inspection().violation() {
            return Err(KernelError::ContextBudget(violation.to_string()));
        }
        self.phase = PreparationPhase::Validated;
        Ok(())
    }
    pub(super) fn into_request(
        self,
        config: RequestConfiguration,
    ) -> Result<(TurnRequest, u32), KernelError> {
        if self.phase != PreparationPhase::Validated {
            return Err(KernelError::ContextResolution(
                "request preparation is unadmitted".into(),
            ));
        }
        Ok((
            TurnRequest {
                model: config.model,
                system: self.request.system,
                messages: self.request.messages.clone(),
                input_images: self.request.input_images,
                tools: self.request.tools,
                max_tokens: self.request.max_tokens,
                cache_system: config.cache_system,
                thinking_budget: config.thinking_budget,
                reasoning_effort: config.reasoning_effort,
                controls: config.controls,
            },
            self.requested_output,
        ))
    }
}
