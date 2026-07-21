//! Versioned SQ/EQ transport envelopes.
//!
//! `Op` and `Event` remain the inner vocabulary used by the in-process kernel and durable record.
//! Anything crossing the submission/event wire is wrapped here and must pass an exact version
//! check before the payload is interpreted.

use crate::{Event, Op};
use serde::{Deserialize, Serialize};

/// Current SQ/EQ wire version. Changes to the `protocol-compat` boundary must bump this value;
/// `core-xtask boundaries check-pr` compares it with the trusted base revision.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersionError {
    pub expected: u32,
    pub actual: u32,
}

impl std::fmt::Display for ProtocolVersionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unsupported SQ/EQ protocol version {}; expected {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for ProtocolVersionError {}

fn require_current(actual: u32) -> Result<(), ProtocolVersionError> {
    if actual == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolVersionError {
            expected: PROTOCOL_VERSION,
            actual,
        })
    }
}

/// One item on the submission queue (SQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqEnvelope {
    pub protocol_version: u32,
    pub op: Op,
}

impl SqEnvelope {
    pub fn current(op: Op) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            op,
        }
    }

    pub fn with_version(protocol_version: u32, op: Op) -> Self {
        Self {
            protocol_version,
            op,
        }
    }

    pub fn into_current(self) -> Result<Op, ProtocolVersionError> {
        require_current(self.protocol_version)?;
        Ok(self.op)
    }
}

impl From<Op> for SqEnvelope {
    fn from(op: Op) -> Self {
        Self::current(op)
    }
}

/// One item on the event queue (EQ).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqEnvelope {
    pub protocol_version: u32,
    pub event: Event,
}

impl EqEnvelope {
    pub fn current(event: Event) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            event,
        }
    }

    pub fn with_version(protocol_version: u32, event: Event) -> Self {
        Self {
            protocol_version,
            event,
        }
    }

    pub fn into_current(self) -> Result<Event, ProtocolVersionError> {
        require_current(self.protocol_version)?;
        Ok(self.event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, Seq, TurnId};

    #[test]
    fn d1_02_sq_and_eq_are_stamped_and_reject_version_skew() {
        let sq = SqEnvelope::current(Op::Interrupt);
        let encoded = serde_json::to_value(&sq).unwrap();
        assert_eq!(encoded["protocol_version"], PROTOCOL_VERSION);
        assert!(matches!(
            serde_json::from_value::<SqEnvelope>(encoded)
                .unwrap()
                .into_current(),
            Ok(Op::Interrupt)
        ));
        assert_eq!(
            SqEnvelope::with_version(PROTOCOL_VERSION + 1, Op::Drain)
                .into_current()
                .unwrap_err(),
            ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: PROTOCOL_VERSION + 1,
            }
        );

        let event = Event {
            seq: Seq(7),
            turn: TurnId(2),
            kind: EventKind::TurnStart,
        };
        let eq = EqEnvelope::current(event);
        assert_eq!(
            serde_json::to_value(&eq).unwrap()["protocol_version"],
            PROTOCOL_VERSION
        );
        assert_eq!(
            EqEnvelope::with_version(PROTOCOL_VERSION + 1, eq.event)
                .into_current()
                .unwrap_err()
                .actual,
            PROTOCOL_VERSION + 1
        );
    }
}
