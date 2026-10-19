//! Closed, content-free refusal diagnostics. Terminal rendering belongs to the client; the
//! returned refusal remains authoritative even when debug diagnostics are redirected to a log.
use crate::artifacts::ArtifactStoreError;
use iteron_provider::request_capture::RequestCaptureError;

#[derive(Clone, Copy)]
pub(super) enum Stage {
    TicketScope,
    WireAdmission,
    StateLock,
    StateTransition,
    MailboxPreparation,
    MailboxConfirmation,
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
    {
        use std::io::IsTerminal as _;
        // A raw stderr write can overwrite the active TUI composer. The returned error already
        // follows the ordinary client error path; keep extra diagnostics only in redirected logs.
        if !std::io::stderr().is_terminal() {
            eprintln!("request observation refused: stage={stage} code={code}");
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = (stage, code);
    mapped
}

fn labels(stage: Stage, cause: Cause) -> (&'static str, &'static str) {
    let stage = match stage {
        Stage::TicketScope => "ticket_scope",
        Stage::WireAdmission => "wire_admission",
        Stage::StateLock => "state_lock",
        Stage::StateTransition => "state_transition",
        Stage::MailboxPreparation => "mailbox_preparation",
        Stage::MailboxConfirmation => "mailbox_confirmation",
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
            Stage::TicketScope,
            Stage::WireAdmission,
            Stage::StateLock,
            Stage::StateTransition,
            Stage::MailboxPreparation,
            Stage::MailboxConfirmation,
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
                Stage::WireAdmission,
                Cause::Artifact(ArtifactStoreError::Unavailable)
            ),
            "request observation refused: stage=wire_admission code=artifact_unavailable"
        );
        assert_eq!(
            line(
                Stage::WireAdmission,
                Cause::Artifact(ArtifactStoreError::PublicationUnknown)
            ),
            "request observation refused: stage=wire_admission code=artifact_publication_unknown"
        );
    }
}
