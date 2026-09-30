//! Closed content-free high assurance barrier. Approvals never authorize physical effects until
//! their exact scope/operation/policy and independent signer commitments are durably recorded.
use crate::runtime::KernelError;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, Seq, TurnId};
use iteron_record::Rollout;
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
pub(super) struct AuthorizationAudit<'a> {
    pub schema: &'static str,
    pub policy_sha256: &'a str,
    pub scope_sha256: &'a str,
    pub challenge_id: &'a str,
    pub operation_sha256: &'a str,
    pub signer_commitments_sha256: &'a [String],
    pub signature_verification_us: u64,
}
pub(crate) struct HighAssuranceJournal<'a> {
    pub(crate) rollout: &'a mut Rollout,
    pub(crate) ledger: &'a mut Ledger,
    pub(crate) record_failed: &'a mut bool,
    pub(crate) diagnostics: &'a DiagnosticEmitter,
}
impl HighAssuranceJournal<'_> {
    pub(super) fn authorized(
        &mut self,
        turn: TurnId,
        audit: AuthorizationAudit<'_>,
    ) -> Result<Seq, KernelError> {
        if *self.record_failed {
            return Err(KernelError::InvalidRoute(
                "high assurance record already refused",
            ));
        }
        let text = serde_json::to_string(&audit)
            .map_err(|_| KernelError::InvalidRoute("high assurance audit encoding refused"))?;
        let started = Instant::now();
        let result = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Notice { text },
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
