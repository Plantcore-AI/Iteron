//! Closed, content-free refusal diagnostics. Release stderr and admission semantics are unchanged.
use crate::artifacts::ArtifactStoreError;
use iteron_provider::request_capture::RequestCaptureError;

#[derive(Clone, Copy)]
pub(super) enum Stage {
    StoreCapture,
    TicketScope,
    StateLock,
    StateTransition,
    MailboxPreparation,
    PreparedPublication,
    MailboxConfirmation,
    DispatchPublication,
    UnsupportedPublication,
    UnsupportedMailbox,
}

#[derive(Clone, Copy)]
pub(super) enum Cause {
    Artifact(ArtifactStoreError),
    Request(RequestCaptureError),
    MailboxConfirmationRefused,
}

pub(super) fn refused(
    stage: Stage,
    cause: Cause,
    mapped: RequestCaptureError,
) -> RequestCaptureError {
    let (stage, code) = labels(stage, cause);
    #[cfg(debug_assertions)]
    eprintln!("request observation refused: stage={stage} code={code}");
    #[cfg(not(debug_assertions))]
    let _ = (stage, code);
    mapped
}

fn labels(stage: Stage, cause: Cause) -> (&'static str, &'static str) {
    let stage = match stage {
        Stage::StoreCapture => "store_capture",
        Stage::TicketScope => "ticket_scope",
        Stage::StateLock => "state_lock",
        Stage::StateTransition => "state_transition",
        Stage::MailboxPreparation => "mailbox_preparation",
        Stage::PreparedPublication => "prepared_publication",
        Stage::MailboxConfirmation => "mailbox_confirmation",
        Stage::DispatchPublication => "dispatch_publication",
        Stage::UnsupportedPublication => "unsupported_publication",
        Stage::UnsupportedMailbox => "unsupported_mailbox",
    };
    let code = match cause {
        Cause::Artifact(ArtifactStoreError::Scope) => "artifact_scope",
        Cause::Artifact(ArtifactStoreError::Unavailable) => "artifact_unavailable",
        Cause::Artifact(ArtifactStoreError::PublicationUnknown) => "artifact_publication_unknown",
        Cause::Artifact(ArtifactStoreError::Corrupt) => "artifact_corrupt",
        Cause::Artifact(ArtifactStoreError::Capacity) => "artifact_capacity",
        Cause::Artifact(ArtifactStoreError::InvalidRequest) => "artifact_invalid_request",
        Cause::Request(RequestCaptureError::Unavailable) => "observation_unavailable",
        Cause::Request(RequestCaptureError::Bounds) => "observation_bounds",
        Cause::Request(RequestCaptureError::ReconciliationNeeded) => "observation_reconciliation",
        Cause::MailboxConfirmationRefused => "mailbox_confirmation_refused",
    };
    (stage, code)
}

#[cfg(test)]
fn line(stage: Stage, cause: Cause) -> String {
    let (stage, code) = labels(stage, cause);
    format!("request observation refused: stage={stage} code={code}")
}

#[cfg(test)]
mod tests {
    use super::{Cause, Stage, line};
    use crate::artifacts::ArtifactStoreError;
    use iteron_provider::request_capture::RequestCaptureError;

    #[test]
    fn diagnostics_are_bounded_closed_codes_without_foreign_error_content() {
        let stages = [
            Stage::StoreCapture,
            Stage::TicketScope,
            Stage::StateLock,
            Stage::StateTransition,
            Stage::MailboxPreparation,
            Stage::PreparedPublication,
            Stage::MailboxConfirmation,
            Stage::DispatchPublication,
            Stage::UnsupportedPublication,
            Stage::UnsupportedMailbox,
        ];
        let causes = [
            Cause::Artifact(ArtifactStoreError::Scope),
            Cause::Artifact(ArtifactStoreError::Unavailable),
            Cause::Artifact(ArtifactStoreError::PublicationUnknown),
            Cause::Artifact(ArtifactStoreError::Corrupt),
            Cause::Artifact(ArtifactStoreError::Capacity),
            Cause::Artifact(ArtifactStoreError::InvalidRequest),
            Cause::Request(RequestCaptureError::Unavailable),
            Cause::Request(RequestCaptureError::Bounds),
            Cause::Request(RequestCaptureError::ReconciliationNeeded),
            Cause::MailboxConfirmationRefused,
        ];
        for stage in stages {
            for cause in causes {
                let value = line(stage, cause);
                assert!(value.len() < 128);
                assert!(
                    value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b" _=:".contains(&byte))
                );
                assert!(value.starts_with("request observation refused: stage="));
                assert!(value.contains(" code="));
            }
        }
        assert_eq!(
            line(
                Stage::PreparedPublication,
                Cause::Artifact(ArtifactStoreError::Unavailable)
            ),
            "request observation refused: stage=prepared_publication code=artifact_unavailable"
        );
        assert_eq!(
            line(
                Stage::DispatchPublication,
                Cause::Artifact(ArtifactStoreError::PublicationUnknown)
            ),
            "request observation refused: stage=dispatch_publication code=artifact_publication_unknown"
        );
    }
}
