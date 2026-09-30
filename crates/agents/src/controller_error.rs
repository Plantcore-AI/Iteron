//! Shared failure vocabulary for the independent controller and mailbox state owners.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerStoreError {
    Unavailable,
    OutcomeUnknown,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerError {
    Invalid(&'static str),
    UnknownAgent,
    UnknownMessage,
    Permission,
    StaleEpoch,
    Closed,
    RecoveryRequired,
    Capacity,
    Budget,
    RequestConflict,
    Store(ControllerStoreError),
    Poisoned,
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid agent control: {reason}"),
            other => write!(f, "agent control refused: {other:?}"),
        }
    }
}

impl std::error::Error for ControllerError {}
