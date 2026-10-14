//! Bounded, content-free snapshots of a failed record operation.
//!
//! A runtime that must stop after an observational append cannot retain only a boolean: later
//! admission and finalization would replace the cause with a generic I/O error. These snapshots
//! retain the original class and numeric evidence without copying paths, JSON, or private text.

use crate::{ContentStoreError, RecordError, Rollout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFailureKind {
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
    ContentBusy,
}

/// No open text fields. This is process-local evidence, not a new durable/wire schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("previous record failure: {kind:?}")]
pub struct RecordFailure {
    pub kind: RecordFailureKind,
    pub io_kind: Option<std::io::ErrorKind>,
    pub os_code: Option<i32>,
    pub bytes: Option<u64>,
    pub limit: Option<u64>,
}

impl RecordFailure {
    pub fn from_error(error: &RecordError) -> Self {
        use RecordFailureKind as Kind;
        let kind = match error {
            RecordError::PreviousFailure(failure) => return *failure,
            RecordError::Io(source) => match source.kind() {
                std::io::ErrorKind::StorageFull => Kind::StorageFull,
                std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::ReadOnlyFilesystem
                | std::io::ErrorKind::NotFound => Kind::StorageAccess,
                _ => Kind::StorageIo,
            },
            RecordError::WriterBusy { .. } => Kind::WriterBusy,
            RecordError::WriterLock { .. } => Kind::WriterLock,
            RecordError::WriterPoisoned => Kind::WriterPoisoned,
            RecordError::RecordLineTooLarge { .. }
            | RecordError::EnvironmentContextTooLarge { .. }
            | RecordError::RolloutTooLarge { .. }
            | RecordError::TooManyEvents { .. }
            | RecordError::TooManyRecordLines { .. } => Kind::Limit,
            RecordError::InvalidRunId { .. }
            | RecordError::InvalidEventSchema { .. }
            | RecordError::InvalidAppendBatch { .. }
            | RecordError::Json(_) => Kind::InvalidSchema,
            RecordError::SequenceBroken { .. }
            | RecordError::TenantMismatch { .. }
            | RecordError::ChainBroken { .. }
            | RecordError::ForkParentMismatch { .. } => Kind::Integrity,
            RecordError::Pricing(_)
            | RecordError::TunablesSnapshot(_)
            | RecordError::PolicyBundleCheckpoint(_) => Kind::Checkpoint,
            RecordError::PrivateContent(ContentStoreError::Busy) => Kind::ContentBusy,
            RecordError::PrivateContent(_) => Kind::PrivateContent,
        };
        let source = match error {
            RecordError::Io(source) | RecordError::WriterLock { source, .. } => Some(source),
            _ => None,
        };
        let (bytes, limit) = match error {
            RecordError::RecordLineTooLarge { bytes, max }
            | RecordError::EnvironmentContextTooLarge { bytes, max } => {
                (Some(*bytes as u64), Some(*max as u64))
            }
            RecordError::RolloutTooLarge { bytes, max } => (Some(*bytes), Some(*max)),
            RecordError::TooManyEvents { max } | RecordError::TooManyRecordLines { max } => {
                (None, Some(*max as u64))
            }
            _ => (None, None),
        };
        Self {
            kind,
            io_kind: source.map(std::io::Error::kind),
            os_code: source.and_then(std::io::Error::raw_os_error),
            bytes,
            limit,
        }
    }

    /// Recreate an append-worker receipt for each waiting caller without copying raw error text.
    /// Physical append errors keep their I/O kind and OS code; poison remains a typed refusal.
    pub(crate) fn into_append_error(self) -> RecordError {
        match self.kind {
            RecordFailureKind::StorageFull
            | RecordFailureKind::StorageAccess
            | RecordFailureKind::StorageIo => match self.io_kind {
                Some(kind) => RecordError::Io(self.os_code.map_or_else(
                    || std::io::Error::from(kind),
                    std::io::Error::from_raw_os_error,
                )),
                None => RecordError::PreviousFailure(self),
            },
            RecordFailureKind::WriterPoisoned => RecordError::WriterPoisoned,
            _ => RecordError::PreviousFailure(self),
        }
    }
}

impl Rollout {
    /// Capture the first cause when a caller stops its run after a record error. Subsequent
    /// poison/terminal errors cannot replace it. This method never changes writer authority.
    pub fn retain_failure(&mut self, error: &RecordError) {
        if self.retained_failure.is_none() {
            self.retained_failure = Some(RecordFailure::from_error(error));
        }
    }

    pub fn retained_failure(&self) -> Option<RecordFailure> {
        self.retained_failure
    }

    /// A caller has already latched a record failure. Preserve its diagnosed cause if available;
    /// legacy callers and test faults without one keep the conservative generic I/O refusal.
    pub fn unavailable_error(&self) -> RecordError {
        self.retained_failure.map_or_else(
            || RecordError::Io(std::io::Error::other("durable record is unavailable")),
            RecordError::PreviousFailure,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_retain_only_closed_classification_and_numeric_evidence() {
        let io = RecordFailure::from_error(&RecordError::Io(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "private/path/secret-session-fragment",
        )));
        assert_eq!(io.kind, RecordFailureKind::StorageFull);
        assert_eq!(io.io_kind, Some(std::io::ErrorKind::StorageFull));
        assert!(!format!("{io:?} {io}").contains("private"));
        let receipt = io.into_append_error();
        assert!(matches!(receipt, RecordError::Io(_)));
        assert_eq!(RecordFailure::from_error(&receipt), io);
        assert!(!format!("{receipt:?} {receipt}").contains("private"));
        assert!(matches!(
            RecordFailure::from_error(&RecordError::WriterPoisoned).into_append_error(),
            RecordError::WriterPoisoned
        ));
        let limit = RecordFailure::from_error(&RecordError::RecordLineTooLarge {
            bytes: 129,
            max: 128,
        });
        assert_eq!(limit.bytes, Some(129));
        assert_eq!(limit.limit, Some(128));
        assert_eq!(
            RecordFailure::from_error(&RecordError::PreviousFailure(limit)),
            limit
        );
    }
}
