//! Closed content-free high assurance barrier. Approvals never authorize physical effects until
//! their exact scope/operation/policy and independent signer commitments are durably recorded.
use super::types::HighAssuranceScope;
use crate::runtime::KernelError;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::high_assurance::{
    HighAssuranceAuditV1, HighAssuranceAuthorizationV1, HighAssuranceProfileEvidenceV1,
};
use iteron_protocol::{Event, EventKind, Seq, TurnId};
use iteron_record::Rollout;
use std::time::Instant;

pub(crate) struct HighAssuranceJournal<'a> {
    pub(crate) workspace: &'a std::path::Path,
    pub(crate) rollout: &'a mut Rollout,
    pub(crate) ledger: &'a mut Ledger,
    pub(crate) record_failed: &'a mut bool,
    pub(crate) diagnostics: &'a DiagnosticEmitter,
}
impl HighAssuranceJournal<'_> {
    pub(super) fn in_scope(&self, scope: &HighAssuranceScope) -> bool {
        HighAssuranceScope::from_host(
            self.rollout.tenant().clone(),
            self.rollout.run_id().clone(),
            self.workspace,
        )
        .as_ref()
            == Ok(scope)
    }
    pub(crate) fn configured(
        &mut self,
        turn: TurnId,
        evidence: HighAssuranceProfileEvidenceV1,
    ) -> Result<Seq, KernelError> {
        let scope = HighAssuranceScope::from_host(
            self.rollout.tenant().clone(),
            self.rollout.run_id().clone(),
            self.workspace,
        )
        .map_err(|_| KernelError::InvalidRoute("high assurance workspace scope refused"))?;
        if scope.commitment() != evidence.scope_sha256 {
            return Err(KernelError::InvalidRoute(
                "high assurance profile scope refused",
            ));
        }
        self.append(turn, HighAssuranceAuditV1::Configured { evidence })
    }
    pub(super) fn authorized(
        &mut self,
        turn: TurnId,
        evidence: HighAssuranceAuthorizationV1,
    ) -> Result<Seq, KernelError> {
        let scope = HighAssuranceScope::from_host(
            self.rollout.tenant().clone(),
            self.rollout.run_id().clone(),
            self.workspace,
        )
        .map_err(|_| KernelError::InvalidRoute("high assurance workspace scope refused"))?;
        if scope.commitment() != evidence.challenge.scope_sha256 {
            return Err(KernelError::InvalidRoute(
                "high assurance authorization scope refused",
            ));
        }
        self.append(turn, HighAssuranceAuditV1::Authorized { evidence })
    }
    fn append(&mut self, turn: TurnId, audit: HighAssuranceAuditV1) -> Result<Seq, KernelError> {
        if *self.record_failed {
            return Err(KernelError::InvalidRoute(
                "high assurance record already refused",
            ));
        }
        audit
            .validate()
            .map_err(|_| KernelError::InvalidRoute("high assurance audit proof refused"))?;
        let started = Instant::now();
        let result = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::HighAssuranceAuditV1 { audit },
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result.map_err(|error| {
            *self.record_failed = true;
            self.diagnostics
                .emit(KernelDiagnostic::RecordAppendFailed {});
            KernelError::Record(error)
        })
    }
}
