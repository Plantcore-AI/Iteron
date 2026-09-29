use super::effects;

/// Closed, content-free record failure classes. A record error can carry paths, tenant names,
/// hashes, JSON diagnostics, or private-content details; none of those fields may reach a client.
#[derive(Clone, Copy)]
enum PublicRecordFailure {
    StorageFull,
    StorageAccess,
    StorageIo,
    WriterBusy,
    WriterLock,
    WriterPoisoned,
    Limit,
    InvalidSchema,
    Integrity,
    Checkpoint,
    PrivateContent,
}

impl PublicRecordFailure {
    fn all() -> [Self; 11] {
        [
            Self::StorageFull,
            Self::StorageAccess,
            Self::StorageIo,
            Self::WriterBusy,
            Self::WriterLock,
            Self::WriterPoisoned,
            Self::Limit,
            Self::InvalidSchema,
            Self::Integrity,
            Self::Checkpoint,
            Self::PrivateContent,
        ]
    }

    fn from_error(error: &iteron_record::RecordError) -> Self {
        use iteron_record::RecordError;
        match error {
            RecordError::Io(source) => match source.kind() {
                std::io::ErrorKind::StorageFull => Self::StorageFull,
                std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::ReadOnlyFilesystem
                | std::io::ErrorKind::NotFound => Self::StorageAccess,
                _ => Self::StorageIo,
            },
            RecordError::WriterBusy { .. } => Self::WriterBusy,
            RecordError::WriterLock { .. } => Self::WriterLock,
            RecordError::WriterPoisoned => Self::WriterPoisoned,
            RecordError::RecordLineTooLarge { .. }
            | RecordError::EnvironmentContextTooLarge { .. }
            | RecordError::RolloutTooLarge { .. }
            | RecordError::TooManyEvents { .. }
            | RecordError::TooManyRecordLines { .. } => Self::Limit,
            RecordError::InvalidRunId { .. }
            | RecordError::InvalidEventSchema { .. }
            | RecordError::InvalidAppendBatch { .. }
            | RecordError::Json(_) => Self::InvalidSchema,
            RecordError::SequenceBroken { .. }
            | RecordError::TenantMismatch { .. }
            | RecordError::ChainBroken { .. }
            | RecordError::ForkParentMismatch { .. } => Self::Integrity,
            RecordError::Pricing(_)
            | RecordError::TunablesSnapshot(_)
            | RecordError::PolicyBundleCheckpoint(_) => Self::Checkpoint,
            RecordError::PrivateContent(_) => Self::PrivateContent,
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::StorageFull => {
                "session record [storage_full]: storage is full; recover space before reopening this run"
            }
            Self::StorageAccess => {
                "session record [storage_access]: record storage is unavailable or not writable; check its mount and permissions before reopening"
            }
            Self::StorageIo => {
                "session record [storage_io]: durable I/O failed; inspect storage and recover before reopening this run"
            }
            Self::WriterBusy => {
                "session record [writer_busy]: another writer owns this run; close that writer before reopening"
            }
            Self::WriterLock => {
                "session record [writer_lock]: exclusive writer lock failed; inspect storage before reopening"
            }
            Self::WriterPoisoned => {
                "session record [writer_poisoned]: append durability is uncertain; close and recover this run before reopening"
            }
            Self::Limit => {
                "session record [limit]: a durable record limit was reached; this run cannot append more"
            }
            Self::InvalidSchema => {
                "session record [invalid_schema]: record input or encoding failed validation; do not continue this run"
            }
            Self::Integrity => {
                "session record [integrity]: durable sequence or identity evidence is inconsistent; do not continue this run"
            }
            Self::Checkpoint => {
                "session record [checkpoint]: durable policy or pricing checkpoint failed validation; do not continue this run"
            }
            Self::PrivateContent => {
                "session record [private_content]: private-content storage or validation failed; do not continue this run"
            }
        }
    }
}

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
    #[error("resolved execution policy could not be installed: {0}")]
    ExecutionPolicy(String),
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
            Self::Record(error) => PublicRecordFailure::from_error(error).summary().into(),
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
                "route pricing evidence failed validation; Iteron will not invent a dollar amount"
                    .into()
            }
            Self::InvalidPermissionPolicy(reason) => {
                format!("invalid permission policy: {reason}")
            }
            Self::ExecutionPolicy(_) => {
                "resolved execution policy failed validation; no child work was admitted".into()
            }
            Self::RuntimePolicyAlreadyRecorded => {
                "initial runtime policy was changed after the session record began".into()
            }
            Self::UnknownEffects { count } => format!(
                "{count} external effect(s) have an unknown outcome; Iteron will not retry them"
            ),
            Self::EffectJournal(_) => {
                "the durable effect journal is inconsistent; Iteron will not execute".into()
            }
            Self::EffectBoundary(reason) => {
                format!("effect boundary refused the dispatch: {reason}")
            }
            Self::IdentityExhausted(kind) => {
                format!("{kind} identity space is exhausted; Iteron will not reuse an id")
            }
            Self::InferenceBudgetExhausted(reason) => {
                format!("provider request budget is exhausted: {reason}")
            }
            Self::OpaqueProviderRetries => {
                "provider retry policy cannot be durably attributed; Iteron will not dispatch"
                    .into()
            }
            Self::ContextWindowExceeded {
                estimated_input_tokens,
                reserved_output_tokens,
                context_window_tokens,
            } => format!(
                "request is too large for the selected model: {estimated_input_tokens} estimated input + {reserved_output_tokens} reserved output > {context_window_tokens} context window"
            ),
            // The violation already knows which component overflowed, by how much, and against
            // what ceiling, and it implements Display to say so. Discarding it left an operator
            // with a sentence that names no component, no number and no next step -- attaching a
            // 327 KB screenshot produced exactly this, with nothing to indicate the attachment
            // was the cause or what size would have fit.
            Self::ContextBudget(violation) => {
                let mut text = format!(
                    "one request context component exceeded its immutable run ceiling: {violation}"
                );
                // `ContextBudgetViolation` already rendered which class overflowed. Capability
                // admission runs before image inspection and budgeting, so a Multimodal
                // violation here is from a route with verified image support. That real budget
                // ceiling is profile-addressable and is the only class worth naming a next step
                // for. Matching rendered text rather than the class remains the narrow change:
                // the typed value is discarded at the two call sites that build this error.
                if violation.starts_with("Multimodal ") {
                    text.push_str(
                        "; raise it with `--set multimodal_token_budget=<tokens>`, or attach a \
                         smaller image",
                    );
                }
                text
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
            Self::ContextResolution(reason)
                if reason == "context task exceeds its local observation bound" =>
            {
                let limit = iteron_tunables::param_integer(
                    "ctx.context_strategy.max_context_task_bytes",
                    64 * 1024,
                );
                format!(
                    "context relevance query exceeds the {limit}-byte selection limit; split or shorten the submission"
                )
            }
            Self::ContextResolution(reason)
                if matches!(
                    reason.as_str(),
                    "requested context bytes exceed the protocol ceiling"
                        | "granted context bytes exceed the protocol ceiling"
                ) =>
            {
                let limit = iteron_tunables::param_integer(
                    "protocol.context.max_context_grant_bytes",
                    iteron_protocol::context::MAX_CONTEXT_GRANT_BYTES,
                );
                format!(
                    "context materialization exceeds the {limit}-byte protocol grant limit; reduce the configured context grant size"
                )
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
                "private tool-output spill storage could not be confirmed; Iteron stopped the run"
                    .into()
            }
            Self::McpLifecycle(_) => {
                "private MCP result cleanup could not be confirmed; Iteron stopped the run".into()
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

    /// The TUI receives only a projected terminal summary, not the original typed error. Match
    /// exact strings from the closed classifier rather than parsing an arbitrary error or exposing
    /// a raw record diagnostic just to decide whether Ctrl+R is safe to offer.
    pub(crate) fn is_public_record_failure(summary: &str) -> bool {
        PublicRecordFailure::all()
            .iter()
            .any(|class| summary == class.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::KernelError;
    use iteron_record::RecordError;

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

    #[test]
    fn public_record_errors_classify_without_paths_raw_io_or_record_material() {
        const SECRET: &str = "private/client/sk-test-secret";
        let cases = [
            (
                RecordError::Io(std::io::Error::new(std::io::ErrorKind::StorageFull, SECRET)),
                "[storage_full]",
            ),
            (
                RecordError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    SECRET,
                )),
                "[storage_access]",
            ),
            (
                RecordError::Io(std::io::Error::other(SECRET)),
                "[storage_io]",
            ),
            (
                RecordError::WriterBusy {
                    path: SECRET.into(),
                },
                "[writer_busy]",
            ),
            (
                RecordError::WriterLock {
                    path: SECRET.into(),
                    source: std::io::Error::other(SECRET),
                },
                "[writer_lock]",
            ),
            (RecordError::WriterPoisoned, "[writer_poisoned]"),
            (
                RecordError::RolloutTooLarge {
                    bytes: 101,
                    max: 100,
                },
                "[limit]",
            ),
            (
                RecordError::InvalidEventSchema { reason: SECRET },
                "[invalid_schema]",
            ),
            (
                RecordError::ChainBroken {
                    seq: 1,
                    stored: SECRET.into(),
                    computed: SECRET.into(),
                },
                "[integrity]",
            ),
        ];
        for (record_error, expected_class) in cases {
            let public = KernelError::Record(record_error).public_summary();
            assert!(public.contains(expected_class), "{public}");
            assert!(!public.contains(SECRET), "{public}");
            assert!(KernelError::is_public_record_failure(&public));
        }
        assert!(!KernelError::is_public_record_failure(
            "session record [storage_full]: private/client/sk-test-secret"
        ));
        assert!(!KernelError::is_public_record_failure(
            "provider: provider transport failed"
        ));
    }
}

#[cfg(test)]
mod context_budget_message_tests {
    use super::*;
    use iteron_ctx::ContextBudgetClass;
    use iteron_ctx::ContextBudgetViolation;

    /// The rendered violation is what the operator reads, so the message must carry it.
    ///
    /// Before this, every context-budget refusal rendered one sentence naming no component, no
    /// number and no ceiling. Attaching a single large screenshot produced exactly that, with
    /// nothing to indicate the attachment was the cause.
    #[test]
    fn the_message_names_the_component_that_overflowed() {
        let violation = ContextBudgetViolation {
            class: ContextBudgetClass::Transcript,
            used: 41_000,
            ceiling: 40_000,
        };
        let rendered = KernelError::ContextBudget(violation.to_string()).public_summary();
        assert!(
            rendered.contains("Transcript")
                && rendered.contains("41000")
                && rendered.contains("40000"),
            "the component, its usage and its ceiling must all survive: {rendered}"
        );
    }

    /// A supported route that reaches its multimodal ceiling names the setting that can raise it.
    #[test]
    fn a_supported_route_multimodal_overflow_names_the_setting_that_raises_it() {
        let violation = ContextBudgetViolation {
            class: ContextBudgetClass::Multimodal,
            used: 20_000,
            ceiling: 12_000,
        };
        let rendered = KernelError::ContextBudget(violation.to_string()).public_summary();
        assert!(
            rendered.contains("multimodal_token_budget"),
            "a raisable ceiling must name its own escape hatch: {rendered}"
        );
    }

    /// And no other class claims a hatch it does not have.
    #[test]
    fn a_fixed_ceiling_does_not_advertise_a_setting() {
        let violation = ContextBudgetViolation {
            class: ContextBudgetClass::ToolSchemas,
            used: 9_000,
            ceiling: 8_000,
        };
        let rendered = KernelError::ContextBudget(violation.to_string()).public_summary();
        assert!(
            !rendered.contains("multimodal_token_budget"),
            "only the multimodal ceiling is profile-addressable: {rendered}"
        );
    }

    /// Unsupported image input is capability refusal, never a multimodal-budget escape hatch.
    #[test]
    fn an_unsupported_route_refusal_does_not_advertise_a_multimodal_budget() {
        let rendered =
            KernelError::InvalidSubmission("image input is unsupported").public_summary();
        assert!(
            !rendered.contains("multimodal_token_budget"),
            "unsupported routes cannot be repaired by widening a component budget: {rendered}"
        );
    }
}

#[cfg(test)]
mod context_resolution_message_tests {
    use super::*;

    #[test]
    fn bounded_context_refusals_name_the_limit_without_exposing_arbitrary_reasons() {
        let query = KernelError::ContextResolution(
            "context task exceeds its local observation bound".into(),
        )
        .public_summary();
        assert!(query.contains("65536-byte selection limit"), "{query}");

        let grant = KernelError::ContextResolution(
            "requested context bytes exceed the protocol ceiling".into(),
        )
        .public_summary();
        assert!(
            grant.contains("131072-byte protocol grant limit"),
            "{grant}"
        );

        let opaque =
            KernelError::ContextResolution("private/path/secret-token".into()).public_summary();
        assert_eq!(opaque, "context selection or materialization failed closed");
    }
}
