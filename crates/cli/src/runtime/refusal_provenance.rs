//! Content-free provenance from actual authority branches. This adapter does not inspect model
//! output, foreign error strings or command stderr, and never changes permission or settlement.
use super::KernelError;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolTerminalReceipt;
use super::tool_presentation::strict_utf8_head;
use iteron_protocol::refusal::{
    HostRefusalV1, RefusalEffectStateV1, RefusalReasonV1, RefusalSourceV1,
};
use iteron_provider::ProviderError;

pub(super) fn publish_tool_refusal(
    events: &StreamToolEvents,
    receipt: &ToolTerminalReceipt,
    reason: RefusalReasonV1,
    effects: RefusalEffectStateV1,
) {
    let observation = HostRefusalV1 {
        reason,
        source: Some(RefusalSourceV1 {
            tenant: receipt.tenant().clone(),
            run_id: receipt.run().clone(),
            turn: receipt.turn(),
            sequence: receipt.sequence(),
        }),
        tool: Some(strict_utf8_head(
            &iteron_record::redact::scrub(receipt.tool()),
            2048,
        )),
        tool_use_id: Some(strict_utf8_head(
            &iteron_record::redact::scrub(receipt.tool_use_id()),
            2048,
        )),
        effects,
    };
    events.refusal(observation);
}
/// A live gate can refuse before a failed writer can append. This has no durable receipt and
/// must remain distinguishable from a confirmed ToolDone; it says nothing about other run effects.
pub(super) fn publish_unrecorded_tool_refusal(
    events: &StreamToolEvents,
    call: &iteron_protocol::ToolUse,
    reason: RefusalReasonV1,
) {
    events.refusal(HostRefusalV1 {
        reason,
        source: None,
        tool: Some(strict_utf8_head(
            &iteron_record::redact::scrub(&call.name),
            2048,
        )),
        tool_use_id: Some(strict_utf8_head(
            &iteron_record::redact::scrub(&call.id),
            2048,
        )),
        effects: RefusalEffectStateV1::NotDispatched,
    });
}
impl KernelError {
    /// An opaque policy/configuration string cannot prove who refused. These mappings use only
    /// existing closed error variants whose producer has already established the category.
    pub(crate) fn refusal_reason(&self) -> RefusalReasonV1 {
        use RefusalReasonV1 as Reason;
        match self {
            Self::OrdinaryExtension(_) => Reason::ExtensionUnavailable,
            Self::AgentControl(error) => match error {
                iteron_agents::ControllerError::Capacity => Reason::ObservationLimit,
                iteron_agents::ControllerError::Budget => Reason::BudgetLimit,
                iteron_agents::ControllerError::Permission => Reason::PermissionDenied,
                iteron_agents::ControllerError::Store(_)
                | iteron_agents::ControllerError::Poisoned => Reason::DurableRecordUnavailable,
                _ => Reason::Unknown,
            },
            Self::ProviderControl(_) | Self::ProviderRequestControl(_) => Reason::ModelUnavailable,
            Self::ProviderAdmission(reason) => match reason {
                iteron_provider::AdmissionReason::UnknownRoute => Reason::InvalidRequest,
                iteron_provider::AdmissionReason::Ceiling
                | iteron_provider::AdmissionReason::QuotaExhausted => Reason::BudgetLimit,
                iteron_provider::AdmissionReason::QuotaUnknown
                | iteron_provider::AdmissionReason::CircuitOpen
                | iteron_provider::AdmissionReason::CircuitHalfOpen => Reason::ResourceUnavailable,
            },
            Self::Provider(error) => match error {
                ProviderError::Refusal => Reason::ProviderRefusal,
                ProviderError::KnownModelUnavailable { .. } => Reason::ModelUnavailable,
                ProviderError::KnownAccountUnavailable { .. }
                | ProviderError::NoKey
                | ProviderError::MissingCredential { .. } => Reason::ResourceUnavailable,
                ProviderError::RequestDeadlineBeforeDispatch | ProviderError::DeadlineExceeded => {
                    Reason::DeadlineLimit
                }
                ProviderError::Interrupted => Reason::OperatorInterrupted,
                _ => Reason::Unknown,
            },
            Self::Record(_) | Self::EffectJournal(_) => Reason::DurableRecordUnavailable,
            Self::InferenceBudgetExhausted(_) => Reason::BudgetLimit,
            Self::ContextBudget(_)
            | Self::ContextWindowExceeded { .. }
            | Self::InstructionContextTooLarge { .. }
            | Self::EnvironmentContextTooLarge { .. } => Reason::BudgetLimit,
            Self::UnpricedUsdCeiling | Self::Pricing(_) | Self::PricingLedger(_) => {
                Reason::PricingUnavailable
            }
            Self::ProviderRunNoticeLimit | Self::IdentityExhausted(_) => Reason::ObservationLimit,
            Self::InvalidPermissionPolicy(_) => Reason::InvalidPermissionPolicy,
            Self::SensitiveModelContext => Reason::PermissionDenied,
            Self::ModelContextProjectionLimit => Reason::ObservationLimit,
            _ => Reason::Unknown,
        }
    }
    pub(crate) fn refusal_observation(&self) -> HostRefusalV1 {
        HostRefusalV1::unscoped(self.refusal_reason())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::refusal::RefusalOriginV1;
    #[test]
    fn foreign_error_text_cannot_invent_administrator_sandbox_or_user_authority() {
        for text in [
            "administrator denied",
            "OS sandbox refused",
            "operator denied secret=credential",
        ] {
            for error in [
                KernelError::ExecutionPolicy(text.into()),
                KernelError::ToolingPolicy(text.into()),
                KernelError::Provider(ProviderError::Configuration(text.into())),
            ] {
                let observation = error.refusal_observation();
                assert_eq!(observation.origin(), RefusalOriginV1::Unknown);
                assert_eq!(observation.effects, RefusalEffectStateV1::Unavailable);
                assert!(observation.source.is_none());
                assert!(!serde_json::to_string(&observation).unwrap().contains(text));
            }
        }
        assert_eq!(
            KernelError::InferenceBudgetExhausted("max_turns").refusal_reason(),
            RefusalReasonV1::BudgetLimit
        );
        assert_eq!(
            KernelError::Provider(ProviderError::Refusal).refusal_reason(),
            RefusalReasonV1::ProviderRefusal
        );
    }
}

#[cfg(test)]
mod actual_control_cause_tests {
    use super::*;
    use iteron_protocol::refusal::RefusalOriginV1;
    #[test]
    fn typed_model_controls_and_governor_causes_keep_existing_harness_class_without_generic_text() {
        use super::super::policy_evidence::policy_harness_error_code;
        use iteron_protocol::PolicyHarnessErrorCode;
        let control = iteron_provider::ControlError::IdempotencyNotAttested;
        for (error, expected_class) in [
            (
                KernelError::ProviderControl(control),
                PolicyHarnessErrorCode::RouteError,
            ),
            (
                KernelError::ProviderRequestControl(control),
                PolicyHarnessErrorCode::ProviderError,
            ),
        ] {
            assert_eq!(
                error.refusal_reason().origin(),
                RefusalOriginV1::ModelCapability
            );
            assert_eq!(policy_harness_error_code(&error), expected_class);
            assert!(error.refusal_observation().source.is_none());
        }
        for (cause, expected) in [
            (
                iteron_provider::AdmissionReason::UnknownRoute,
                RefusalReasonV1::InvalidRequest,
            ),
            (
                iteron_provider::AdmissionReason::QuotaExhausted,
                RefusalReasonV1::BudgetLimit,
            ),
            (
                iteron_provider::AdmissionReason::QuotaUnknown,
                RefusalReasonV1::ResourceUnavailable,
            ),
        ] {
            let error = KernelError::ProviderAdmission(cause);
            assert_eq!(error.refusal_reason(), expected);
            assert_eq!(
                policy_harness_error_code(&error),
                PolicyHarnessErrorCode::ProviderError
            );
            assert!(error.refusal_observation().source.is_none());
        }
    }
}
