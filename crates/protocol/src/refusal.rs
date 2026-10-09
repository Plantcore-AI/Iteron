//! Read-only refusal provenance. A reason names the authority that actually refused; neither an
//! error message nor an unsuccessful command establishes a sandbox, administrator or user denial.
//! This observation does not grant authority or change physical effect certainty.
use crate::{RunId, Seq, TenantId, TurnId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalOriginV1 {
    Unknown,
    OsSandbox,
    UserApproval,
    HostPolicy,
    AdministratorPolicy,
    ExtensionPolicy,
    ResourceLimit,
    ModelCapability,
    Provider,
    DurableRecord,
    OperatorControl,
}

/// Each closed reason has one source category. Consumers never classify `summary` or tool output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReasonV1 {
    Unknown,
    SandboxUnavailable,
    SandboxProfileRefused,
    OperatorDenied,
    ApprovalUnavailable,
    ApprovalCancelled,
    PermissionDenied,
    CapabilityCeiling,
    UntrustedExternalEffect,
    ApprovalProjectionIncomplete,
    InvalidPermissionPolicy,
    AdministratorDenied,
    ExtensionDenied,
    ExtensionUnavailable,
    BudgetLimit,
    DeadlineLimit,
    ObservationLimit,
    ResourceUnavailable,
    PricingUnavailable,
    ModelUnavailable,
    ModelContextLimit,
    ProviderRefusal,
    DurableRecordUnavailable,
    OperatorInterrupted,
    DuplicateFailedAction,
    InvalidRequest,
}
impl RefusalReasonV1 {
    pub const fn origin(self) -> RefusalOriginV1 {
        use RefusalOriginV1 as Origin;
        match self {
            Self::Unknown | Self::InvalidRequest => Origin::Unknown,
            Self::SandboxUnavailable | Self::SandboxProfileRefused => Origin::OsSandbox,
            Self::OperatorDenied | Self::ApprovalUnavailable | Self::ApprovalCancelled => {
                Origin::UserApproval
            }
            Self::PermissionDenied
            | Self::CapabilityCeiling
            | Self::UntrustedExternalEffect
            | Self::ApprovalProjectionIncomplete
            | Self::InvalidPermissionPolicy
            | Self::DuplicateFailedAction => Origin::HostPolicy,
            Self::AdministratorDenied => Origin::AdministratorPolicy,
            Self::ExtensionDenied | Self::ExtensionUnavailable => Origin::ExtensionPolicy,
            Self::BudgetLimit
            | Self::DeadlineLimit
            | Self::ObservationLimit
            | Self::ResourceUnavailable
            | Self::PricingUnavailable => Origin::ResourceLimit,
            Self::ModelUnavailable | Self::ModelContextLimit => Origin::ModelCapability,
            Self::ProviderRefusal => Origin::Provider,
            Self::DurableRecordUnavailable => Origin::DurableRecord,
            Self::OperatorInterrupted => Origin::OperatorControl,
        }
    }
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Unknown => "The refusal source is unavailable.",
            Self::SandboxUnavailable => "The requested operating-system sandbox is unavailable.",
            Self::SandboxProfileRefused => {
                "The operating-system sandbox profile could not be applied."
            }
            Self::OperatorDenied => "The operator denied the approval request.",
            Self::ApprovalUnavailable => "The required operator approval could not be obtained.",
            Self::ApprovalCancelled => "The approval transaction was cancelled.",
            Self::PermissionDenied => "The current host permission policy refuses this operation.",
            Self::CapabilityCeiling => "The operation exceeds its inherited capability ceiling.",
            Self::UntrustedExternalEffect => {
                "The governing context does not authorize this external effect."
            }
            Self::ApprovalProjectionIncomplete => {
                "The complete operation cannot fit the approval surface."
            }
            Self::InvalidPermissionPolicy => "The requested permission policy is invalid.",
            Self::AdministratorDenied => {
                "An identified administrator policy refuses this operation."
            }
            Self::ExtensionDenied => "An installed extension policy refuses this operation.",
            Self::ExtensionUnavailable => "The requested extension capability is unavailable.",
            Self::BudgetLimit => "The operation exceeds an admitted budget ceiling.",
            Self::DeadlineLimit => "The admitted wall deadline has elapsed.",
            Self::ObservationLimit => "The bounded observation or identity capacity is exhausted.",
            Self::ResourceUnavailable => "A required execution resource is unavailable.",
            Self::PricingUnavailable => "The required pricing evidence is unavailable or invalid.",
            Self::ModelUnavailable => "The selected model capability is unavailable.",
            Self::ModelContextLimit => "The request exceeds the selected context allowance.",
            Self::ProviderRefusal => "The provider reported a model refusal.",
            Self::DurableRecordUnavailable => "The durable record cannot confirm this operation.",
            Self::OperatorInterrupted => "An operator control stopped this operation.",
            Self::DuplicateFailedAction => {
                "The host did not repeat this previously failed exact action."
            }
            Self::InvalidRequest => "The operation request is invalid.",
        }
    }
}

/// The actual supporting writer receipt. It confirms the recorded decision/terminal, not that
/// this live provenance was itself replayed from that record. On historical generic errors the
/// origin remains Unknown; consumers may not recover it by parsing record text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalSourceV1 {
    pub tenant: TenantId,
    pub run_id: RunId,
    pub turn: TurnId,
    pub sequence: Seq,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalEffectStateV1 {
    NotDispatched,
    Settled,
    Unknown,
    Unavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRefusalV1 {
    pub reason: RefusalReasonV1,
    pub source: Option<RefusalSourceV1>,
    /// Bounded registry subject, never an authority identifier or an executable command.
    pub tool: Option<String>,
    pub tool_use_id: Option<String>,
    pub effects: RefusalEffectStateV1,
}
impl HostRefusalV1 {
    pub const fn unscoped(reason: RefusalReasonV1) -> Self {
        Self {
            reason,
            source: None,
            tool: None,
            tool_use_id: None,
            effects: RefusalEffectStateV1::Unavailable,
        }
    }
    pub const fn origin(&self) -> RefusalOriginV1 {
        self.reason.origin()
    }
    pub const fn summary(&self) -> &'static str {
        self.reason.summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sources_do_not_confuse_operator_policy_with_administrator_or_sandbox() {
        assert_eq!(
            RefusalReasonV1::PermissionDenied.origin(),
            RefusalOriginV1::HostPolicy
        );
        assert_eq!(
            RefusalReasonV1::OperatorDenied.origin(),
            RefusalOriginV1::UserApproval
        );
        assert_eq!(
            RefusalReasonV1::SandboxProfileRefused.origin(),
            RefusalOriginV1::OsSandbox
        );
        assert_eq!(
            RefusalReasonV1::AdministratorDenied.origin(),
            RefusalOriginV1::AdministratorPolicy
        );
        let unknown = HostRefusalV1::unscoped(RefusalReasonV1::Unknown);
        assert_eq!(unknown.origin(), RefusalOriginV1::Unknown);
        assert!(unknown.source.is_none());
        assert_eq!(unknown.effects, RefusalEffectStateV1::Unavailable);
        assert_eq!(
            serde_json::from_str::<HostRefusalV1>(&serde_json::to_string(&unknown).unwrap())
                .unwrap(),
            unknown
        );
    }
}
