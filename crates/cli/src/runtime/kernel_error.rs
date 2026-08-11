use super::effects;

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("provider: {0}")]
    Provider(#[from] iteron_provider::ProviderError),
    #[error("record: {0}")]
    Record(#[from] iteron_record::RecordError),
    #[error("invalid route metadata in {field}: {reason}")]
    InvalidRouteMetadata {
        field: &'static str,
        reason: &'static str,
    },
    #[error("provider request does not match the durable selected route: {0}")]
    InvalidRoute(&'static str),
    #[error("provider run-notice evidence exceeded its per-run bound")]
    ProviderRunNoticeLimit,
    #[error("invalid execution budget: {0}")]
    InvalidBudget(&'static str),
    /// A queued submission failed the protocol's own admission bounds. Nothing is wrong with the
    /// run and no prefix of the submission is admitted.
    #[error("submission refused: {0}")]
    InvalidSubmission(&'static str),
    #[error("cannot enforce a USD ceiling for a route without a verified rate card")]
    UnpricedUsdCeiling,
    #[error("invalid pricing evidence: {0}")]
    Pricing(#[from] iteron_obs::PricingError),
    #[error("pricing ledger invariant failed: {0}")]
    PricingLedger(&'static str),
    #[error("invalid permission policy: {0}")]
    InvalidPermissionPolicy(&'static str),
    #[error("initial runtime policy can only be configured before the first durable event")]
    RuntimePolicyAlreadyRecorded,
    #[error("{count} external effect(s) have an unknown outcome and require reconciliation")]
    UnknownEffects { count: usize },
    #[error("effect journal invariant failed: {0}")]
    EffectJournal(#[from] effects::EffectJournalError),
    #[error("effect boundary refused the dispatch: {0}")]
    EffectBoundary(String),
    #[error("{0} identity space is exhausted; refusing to reuse a durable correlation id")]
    IdentityExhausted(&'static str),
    #[error("provider request budget is exhausted: {0}")]
    InferenceBudgetExhausted(&'static str),
    #[error(
        "provider hides multiple transport attempts behind one turn; refusing unjournaled retry"
    )]
    OpaqueProviderRetries,
    #[error(
        "request context admission failed: estimated input {estimated_input_tokens} + reserved output {reserved_output_tokens} exceeds model window {context_window_tokens}"
    )]
    ContextWindowExceeded {
        estimated_input_tokens: u64,
        reserved_output_tokens: u32,
        context_window_tokens: u64,
    },
    #[error("request context component admission failed: {0}")]
    ContextBudget(String),
    #[error("instruction context is {bytes} bytes, exceeding the {max}-byte admission limit")]
    InstructionContextTooLarge { bytes: usize, max: usize },
    #[error("instruction context is already resolved for this run")]
    InstructionContextAlreadyResolved,
    #[error("environment context is {bytes} bytes, exceeding the {max}-byte admission limit")]
    EnvironmentContextTooLarge { bytes: usize, max: usize },
    #[error("environment context is already resolved for this run")]
    EnvironmentContextAlreadyResolved,
    #[error("context resolution failed: {0}")]
    ContextResolution(String),
    #[error("context strategy inputs are already resolved for this run")]
    ContextAlreadyResolved,
    #[error("agent catalog is already pinned for this run")]
    AgentCatalogAlreadyResolved,
    #[error("runtime tunables are already pinned for this run")]
    TunablesAlreadyResolved,
    #[error("runtime tunables must be pinned before this operation")]
    TunablesNotResolved,
    #[error("resolved tooling policy could not be installed: {0}")]
    ToolingPolicy(String),
    #[error("ordinary tool-output spill lifecycle invariant failed: {0}")]
    ToolOutputSpill(&'static str),
    #[error("MCP lifecycle invariant failed: {0}")]
    McpLifecycle(&'static str),
    #[error("policy evidence invariant failed: {0}")]
    PolicyEvidence(String),
    #[error("delegation depth limit reached; child agents cannot delegate")]
    DelegationDepthExceeded,
    #[cfg(test)]
    #[allow(dead_code)]
    #[error("built-in workflow engine failed: {0}")]
    WorkflowEngine(String),
}

impl KernelError {
    /// Secret-safe operator text. Provider transport/parser diagnostics may contain URLs, echoed
    /// payload fragments, or implementation details and therefore never cross a frontend seam.
    pub fn public_summary(&self) -> String {
        match self {
            Self::Provider(error) => format!("provider: {}", error.public_summary()),
            Self::Record(_) => "session record operation failed".into(),
            Self::InvalidRouteMetadata { field, reason } => {
                format!("invalid route metadata in {field}: {reason}")
            }
            Self::InvalidRoute(reason) => {
                format!("provider request does not match the durable selected route: {reason}")
            }
            Self::ProviderRunNoticeLimit => {
                "provider run-notice evidence exceeded its per-run safety bound".into()
            }
            Self::InvalidBudget(reason) => format!("invalid execution budget: {reason}"),
            Self::InvalidSubmission(reason) => format!("submission refused: {reason}"),
            Self::UnpricedUsdCeiling => {
                "cannot enforce the requested USD ceiling: this route has no verified rate card"
                    .into()
            }
            Self::Pricing(_) | Self::PricingLedger(_) => {
                "route pricing evidence failed validation; Core will not invent a dollar amount"
                    .into()
            }
            Self::InvalidPermissionPolicy(reason) => {
                format!("invalid permission policy: {reason}")
            }
            Self::RuntimePolicyAlreadyRecorded => {
                "initial runtime policy was changed after the session record began".into()
            }
            Self::UnknownEffects { count } => format!(
                "{count} external effect(s) have an unknown outcome; Core will not retry them"
            ),
            Self::EffectJournal(_) => {
                "the durable effect journal is inconsistent; Core will not execute".into()
            }
            Self::EffectBoundary(reason) => {
                format!("effect boundary refused the dispatch: {reason}")
            }
            Self::IdentityExhausted(kind) => {
                format!("{kind} identity space is exhausted; Core will not reuse an id")
            }
            Self::InferenceBudgetExhausted(reason) => {
                format!("provider request budget is exhausted: {reason}")
            }
            Self::OpaqueProviderRetries => {
                "provider retry policy cannot be durably attributed; Core will not dispatch".into()
            }
            Self::ContextWindowExceeded {
                estimated_input_tokens,
                reserved_output_tokens,
                context_window_tokens,
            } => format!(
                "request is too large for the selected model: {estimated_input_tokens} estimated input + {reserved_output_tokens} reserved output > {context_window_tokens} context window"
            ),
            Self::ContextBudget(_) => {
                "one request context component exceeded its immutable run ceiling".into()
            }
            Self::InstructionContextTooLarge { bytes, max } => {
                format!("instruction context is {bytes} bytes, exceeding the {max}-byte limit")
            }
            Self::InstructionContextAlreadyResolved => {
                "instruction context is already fixed for this run".into()
            }
            Self::EnvironmentContextTooLarge { bytes, max } => {
                format!("environment context is {bytes} bytes, exceeding the {max}-byte limit")
            }
            Self::EnvironmentContextAlreadyResolved => {
                "environment context is already fixed for this run".into()
            }
            Self::ContextResolution(_) => {
                "context selection or materialization failed closed".into()
            }
            Self::ContextAlreadyResolved => {
                "context strategy inputs are already fixed for this run".into()
            }
            Self::AgentCatalogAlreadyResolved => {
                "agent catalog is already fixed for this run".into()
            }
            Self::TunablesAlreadyResolved => {
                "runtime tunables are already fixed for this run".into()
            }
            Self::TunablesNotResolved => {
                "runtime tunables were not resolved before execution began".into()
            }
            Self::ToolingPolicy(_) => {
                "resolved process/LSP policy could not be installed before execution".into()
            }
            Self::ToolOutputSpill(_) => {
                "private tool-output spill storage could not be confirmed; Core stopped the run"
                    .into()
            }
            Self::McpLifecycle(_) => {
                "private MCP result cleanup could not be confirmed; Core stopped the run".into()
            }
            Self::PolicyEvidence(_) => {
                "policy evidence could not be joined to the immutable run identity".into()
            }
            Self::DelegationDepthExceeded => {
                "delegation depth limit reached; child agents cannot delegate".into()
            }
            #[cfg(test)]
            Self::WorkflowEngine(_) => {
                "built-in workflow engine failed before the writer could continue".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KernelError;

    #[test]
    fn public_provider_error_never_exposes_transport_diagnostics() {
        let error = KernelError::Provider(iteron_provider::ProviderError::Http(
            "request to https://secret.example/sk-test-secret failed".into(),
        ));
        let public = error.public_summary();
        assert_eq!(public, "provider: provider transport failed");
        assert!(!public.contains("secret.example"));
        assert!(!public.contains("sk-test-secret"));
    }
}
