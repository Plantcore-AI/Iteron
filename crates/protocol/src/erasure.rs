//! Content-free protocol for durable record-erasure operations and receipts.
//!
//! The receipt is audit evidence, not another copy of the data being erased. Its identifiers use
//! a deliberately narrow grammar and every collection-free field has an explicit byte or numeric
//! bound. Content revocation is represented even before the blob/reference graph exists so an
//! implementation can fail closed with a typed terminal receipt instead of silently degrading to
//! whole-session deletion.

use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) mod ids;

use crate::erasure::ids::valid_session_target;
pub use crate::erasure::ids::{
    ErasureAuthorityId, ErasureContentDigest, ErasureOperationId, ErasureScopeId, ErasureTargetId,
    MAX_ERASURE_AUTHORITY_ID_BYTES, MAX_ERASURE_OPERATION_ID_BYTES, MAX_ERASURE_SCOPE_ID_BYTES,
    MAX_ERASURE_TARGET_ID_BYTES,
};

pub const ERASURE_RECEIPT_SCHEMA_VERSION: u16 = 1;
pub const MAX_ERASURE_RECEIPT_BYTES: usize = 32 * 1024;
pub const MAX_RETENTION_KEEP_LAST: u32 = 1_000_000;
pub const MAX_RETENTION_AGE_SECS: u64 = 100 * 366 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureValidationError {
    OperationId,
    AuthorityId,
    ScopeId,
    TargetId,
    ContentDigest,
    RetentionPolicy,
    Receipt,
    TerminalReceipt,
    Transition,
}

impl fmt::Display for ErasureValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OperationId => "invalid bounded erasure operation id",
            Self::AuthorityId => "invalid bounded erasure authority id",
            Self::ScopeId => "invalid bounded erasure scope id",
            Self::TargetId => "invalid bounded erasure target id",
            Self::ContentDigest => "content target must be a lowercase sha256 digest",
            Self::RetentionPolicy => "retention erasure requires one bounded selection rule",
            Self::Receipt => "invalid erasure receipt",
            Self::TerminalReceipt => "terminal erasure receipts are immutable",
            Self::Transition => "invalid erasure state transition",
        })
    }
}

impl std::error::Error for ErasureValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureOperationKind {
    ExactSession,
    RetentionPrune,
    ContentRevocation,
}

/// The three destructive operations are intentionally not interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErasureTarget {
    ExactSession {
        scope_id: ErasureScopeId,
        run_id: ErasureTargetId,
    },
    RetentionPrune {
        scope_id: ErasureScopeId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_age_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keep_last: Option<u32>,
    },
    ContentRevocation {
        scope_id: ErasureScopeId,
        content_digest: ErasureContentDigest,
    },
}

impl ErasureTarget {
    pub fn kind(&self) -> ErasureOperationKind {
        match self {
            Self::ExactSession { .. } => ErasureOperationKind::ExactSession,
            Self::RetentionPrune { .. } => ErasureOperationKind::RetentionPrune,
            Self::ContentRevocation { .. } => ErasureOperationKind::ContentRevocation,
        }
    }

    pub fn validate(&self) -> Result<(), ErasureValidationError> {
        if let Self::ExactSession { run_id, .. } = self
            && !valid_session_target(run_id.as_str())
        {
            return Err(ErasureValidationError::TargetId);
        }
        if let Self::RetentionPrune {
            max_age_secs,
            keep_last,
            ..
        } = self
        {
            if max_age_secs.is_none() && keep_last.is_none() {
                return Err(ErasureValidationError::RetentionPolicy);
            }
            if max_age_secs.is_some_and(|value| {
                value
                    > iteron_tunables::param_integer(
                        "protocol.erasure.max_retention_age_secs",
                        MAX_RETENTION_AGE_SECS,
                    )
            }) || keep_last.is_some_and(|value| {
                value
                    > iteron_tunables::param_integer(
                        "protocol.erasure.max_retention_keep_last",
                        MAX_RETENTION_KEEP_LAST,
                    )
            }) {
                return Err(ErasureValidationError::RetentionPolicy);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureRequest {
    pub operation_id: ErasureOperationId,
    pub authority_id: ErasureAuthorityId,
    pub requested_at_unix_ms: u64,
    pub target: ErasureTarget,
}

impl ErasureRequest {
    pub fn validate(&self) -> Result<(), ErasureValidationError> {
        self.target.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureState {
    Requested,
    Quiescing,
    Tombstoned,
    Shredded,
    Propagating,
    Verified,
    Failed,
}

impl ErasureState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Failed)
    }

    fn permits(self, operation: ErasureOperationKind, next: Self) -> bool {
        if next == Self::Failed {
            return !self.is_terminal();
        }
        match operation {
            // Exact deletion and retention unlink journals but never claim that a content key was
            // shredded or that a derivative graph was propagated. Keeping their graphs separate
            // makes such a receipt impossible to mint even through direct protocol API use.
            ErasureOperationKind::ExactSession | ErasureOperationKind::RetentionPrune => matches!(
                (self, next),
                (Self::Requested, Self::Quiescing)
                    | (Self::Quiescing, Self::Tombstoned)
                    | (Self::Tombstoned, Self::Verified)
            ),
            // Content revocation must cross every destructive durability boundary in order.
            ErasureOperationKind::ContentRevocation => matches!(
                (self, next),
                (Self::Requested, Self::Quiescing)
                    | (Self::Quiescing, Self::Tombstoned)
                    | (Self::Tombstoned, Self::Shredded)
                    | (Self::Shredded, Self::Propagating)
                    | (Self::Propagating, Self::Verified)
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureFailureCode {
    /// Retained for decoding receipts produced before content-reference propagation shipped.
    UnsupportedContentRevocation,
    TargetNotFound,
    ActiveWriter,
    RetainedByDescendants,
    RetainedByDerivatives,
    ReferenceGraphBoundExceeded,
    StorageFailure,
    VerificationFailure,
    ReceiptBoundExceeded,
}

/// Content-free coverage receipt for the fixed derivative namespaces guarded by one revocation.
///
/// A `true` value means that namespace consults the same durable revocation generation before it
/// can serve or materialize content. It does not claim that an object existed in that namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasurePropagationCoverage {
    pub session_projections: bool,
    pub indexes: bool,
    pub prompt_history: bool,
    pub attachments: bool,
    pub tool_artifacts: bool,
    pub checkpoints: bool,
    pub memory_context: bool,
    pub exports: bool,
    pub telemetry_debug: bool,
    pub trajectories: bool,
    pub datasets: bool,
    pub evaluator_inputs: bool,
    pub candidate_stores: bool,
}

impl ErasurePropagationCoverage {
    pub fn is_complete(&self) -> bool {
        self.session_projections
            && self.indexes
            && self.prompt_history
            && self.attachments
            && self.tool_artifacts
            && self.checkpoints
            && self.memory_context
            && self.exports
            && self.telemetry_debug
            && self.trajectories
            && self.datasets
            && self.evaluator_inputs
            && self.candidate_stores
    }
}

/// Bounded, content-free proof attached only to a verified receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErasureVerification {
    ExactSessionAbsent,
    RetentionApplied {
        retained_sessions: u32,
        active_sessions: u32,
        ancestor_sessions: u32,
    },
    ContentRevoked {
        reference_count: u32,
        affected_sessions: u32,
        revocation_generation: u64,
        coverage: ErasurePropagationCoverage,
    },
}

/// The durable state of one operation. Terminal receipts never transition again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureReceipt {
    schema_version: u16,
    request: ErasureRequest,
    state: ErasureState,
    transition_count: u8,
    accepted_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<ErasureVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<ErasureFailureCode>,
}

impl ErasureReceipt {
    pub fn requested(
        request: ErasureRequest,
        accepted_at_unix_ms: u64,
    ) -> Result<Self, ErasureValidationError> {
        request.validate()?;
        Ok(Self {
            schema_version: ERASURE_RECEIPT_SCHEMA_VERSION,
            request,
            state: ErasureState::Requested,
            transition_count: 0,
            accepted_at_unix_ms,
            updated_at_unix_ms: accepted_at_unix_ms,
            verification: None,
            failure: None,
        })
    }

    pub fn request(&self) -> &ErasureRequest {
        &self.request
    }

    pub fn state(&self) -> ErasureState {
        self.state
    }

    pub fn transition_count(&self) -> u8 {
        self.transition_count
    }

    pub fn accepted_at_unix_ms(&self) -> u64 {
        self.accepted_at_unix_ms
    }

    pub fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }

    pub fn verification(&self) -> Option<&ErasureVerification> {
        self.verification.as_ref()
    }

    pub fn failure(&self) -> Option<ErasureFailureCode> {
        self.failure
    }

    pub fn advance(
        &mut self,
        next: ErasureState,
        updated_at_unix_ms: u64,
    ) -> Result<(), ErasureValidationError> {
        if self.state.is_terminal() {
            return Err(ErasureValidationError::TerminalReceipt);
        }
        if !self.state.permits(self.request.target.kind(), next)
            || matches!(next, ErasureState::Verified | ErasureState::Failed)
        {
            return Err(ErasureValidationError::Transition);
        }
        self.set_state(next, updated_at_unix_ms);
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        verification: ErasureVerification,
        updated_at_unix_ms: u64,
    ) -> Result<(), ErasureValidationError> {
        if self.state.is_terminal() {
            return Err(ErasureValidationError::TerminalReceipt);
        }
        if !self
            .state
            .permits(self.request.target.kind(), ErasureState::Verified)
        {
            return Err(ErasureValidationError::Transition);
        }
        self.verification = Some(verification);
        self.set_state(ErasureState::Verified, updated_at_unix_ms);
        Ok(())
    }

    pub fn mark_failed(
        &mut self,
        failure: ErasureFailureCode,
        updated_at_unix_ms: u64,
    ) -> Result<(), ErasureValidationError> {
        if self.state.is_terminal() {
            return Err(ErasureValidationError::TerminalReceipt);
        }
        if !self
            .state
            .permits(self.request.target.kind(), ErasureState::Failed)
        {
            return Err(ErasureValidationError::Transition);
        }
        self.failure = Some(failure);
        self.set_state(ErasureState::Failed, updated_at_unix_ms);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ErasureValidationError> {
        self.request.validate()?;
        if self.schema_version != ERASURE_RECEIPT_SCHEMA_VERSION
            || self.updated_at_unix_ms < self.accepted_at_unix_ms
            || self.transition_count > 6
        {
            return Err(ErasureValidationError::Receipt);
        }
        let terminal_shape = match self.state {
            ErasureState::Verified => {
                self.failure.is_none()
                    && match (self.request.target.kind(), self.verification.as_ref()) {
                        (
                            ErasureOperationKind::ExactSession,
                            Some(ErasureVerification::ExactSessionAbsent),
                        ) => true,
                        (
                            ErasureOperationKind::RetentionPrune,
                            Some(ErasureVerification::RetentionApplied { .. }),
                        ) => true,
                        (
                            ErasureOperationKind::ContentRevocation,
                            Some(ErasureVerification::ContentRevoked { coverage, .. }),
                        ) => coverage.is_complete(),
                        _ => false,
                    }
            }
            ErasureState::Failed => self.verification.is_none() && self.failure.is_some(),
            _ => self.verification.is_none() && self.failure.is_none(),
        };
        let operation_shape = match self.request.target.kind() {
            ErasureOperationKind::ExactSession | ErasureOperationKind::RetentionPrune => !matches!(
                self.state,
                ErasureState::Shredded | ErasureState::Propagating
            ),
            ErasureOperationKind::ContentRevocation => {
                !matches!(self.state, ErasureState::Verified)
                    || matches!(
                        self.verification,
                        Some(ErasureVerification::ContentRevoked { .. })
                    )
            }
        };
        let failure_shape = !matches!(
            self.failure,
            Some(ErasureFailureCode::UnsupportedContentRevocation)
        ) || self.request.target.kind()
            == ErasureOperationKind::ContentRevocation;
        let count_shape = match self.state {
            ErasureState::Requested => self.transition_count == 0,
            ErasureState::Quiescing => self.transition_count == 1,
            ErasureState::Tombstoned => self.transition_count == 2,
            ErasureState::Shredded => self.transition_count == 3,
            ErasureState::Propagating => (3..=4).contains(&self.transition_count),
            ErasureState::Verified | ErasureState::Failed => self.transition_count >= 1,
        };
        if !terminal_shape || !operation_shape || !failure_shape || !count_shape {
            return Err(ErasureValidationError::Receipt);
        }
        Ok(())
    }

    fn set_state(&mut self, state: ErasureState, updated_at_unix_ms: u64) {
        self.state = state;
        self.transition_count = self.transition_count.saturating_add(1);
        self.updated_at_unix_ms = self.updated_at_unix_ms.max(updated_at_unix_ms);
    }
}

#[cfg(test)]
mod tests {
    include!("erasure/tests.rs");
}
