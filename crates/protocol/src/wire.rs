//! Versioned SQ/EQ transport envelopes.
//!
//! `Op` and `Event` remain the inner vocabulary used by the in-process kernel and durable record.
//! Anything crossing the submission/event wire is wrapped here and must pass an exact version
//! check before the payload is interpreted.
//!
//! # The version gate is not the `#[serde(other)] Unknown` discipline, and must not become it
//!
//! `docs/spec/abi.md` §4.3(b) states two rules that pull in opposite directions here. Unknown
//! *tags* degrade: a newer writer's `Op` variant decodes to `Op::Unknown` with its payload
//! dropped, so one unrecognised submission does not kill a replay. Version *skew* is hard-refused:
//! a run accepts messages of exactly one `PROTOCOL_VERSION`.
//!
//! The first rule is deliberately scoped to the payload vocabulary and stops at
//! `protocol_version`. A v2 envelope decodes cleanly today — its unknown op tag degrades exactly
//! as designed — so a reader that trusted decoding alone would receive a well-formed
//! `Op::Unknown` and have no way left to tell it apart from a genuine v1 submission of an
//! unrecognised kind. The two are not the same: the second is a message this build understands
//! the frame of, the first is a message whose whole frame is defined by a spec this build has
//! never read.
//!
//! That is why the refusal is a typed `Err` on a value that decoded successfully, rather than a
//! decode failure. `crates/kernel/src/lib.rs` binds `let Ok(op) = envelope.into_current() else`;
//! the `Err` arm is the only thing standing between a foreign-version submission and the loop.
//!
//! # Why the freeze adds contracts and still leaves this at 1
//!
//! §4.3(a) obliges a bump when a *published shape* moves, not when this crate is touched. The W1
//! freeze adds `TaskEnvelope`, `EffectProposal`, `SlotId` and the rest here and holds the constant
//! at 1 because every one of them is a brand-new surface: no existing field, tag or fixture moved,
//! so no byte on either queue moved and no live run's pinned version changed. From here on the
//! five contracts are published too, and reshaping any of them does oblige a bump, exactly as
//! §4.3(c) requires.

use crate::{Event, Op};
use serde::{Deserialize, Serialize};

/// Current SQ/EQ wire version. Changes to the `protocol-compat` boundary must bump this value;
/// `core-xtask boundaries check-pr` compares it with the trusted base revision.
pub const PROTOCOL_VERSION: u32 = 2;

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

    /// A v2 submission in the form it would actually arrive in: bytes from another build, not a
    /// constructor call this build made against itself. The op tag is one no version of this
    /// crate has ever defined, because a real v2 producer is free to send exactly that.
    const V2_SUBMISSION_JSON: &str =
        r#"{"protocol_version":2,"op":{"op":"reprioritize","lane":"background"}}"#;

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

        // The W1 freeze pins the stamp. Written as a literal rather than as `PROTOCOL_VERSION + 1`
        // so that a future bump has to come here and decide what the skew case now means, instead
        // of silently re-aiming this test at v3 and leaving v2 untested.
        assert_eq!(PROTOCOL_VERSION, 1);
        let v2: SqEnvelope = serde_json::from_str(V2_SUBMISSION_JSON)
            .expect("a v2 envelope decodes; it is the version gate that refuses it, not serde");
        let refused = v2
            .into_current()
            .expect_err("a v2 submission must not yield an Op to interpret");
        assert_eq!(
            refused,
            ProtocolVersionError {
                expected: 1,
                actual: 2,
            }
        );

        // Typed and returned, not raised: the kernel's `let Ok(op) = ... else` arm needs a value
        // it can branch on, and the operator-facing message has to name both versions or the
        // report is "something was rejected".
        let propagated: &dyn std::error::Error = &refused;
        let rendered = propagated.to_string();
        assert!(
            rendered.contains("version 2") && rendered.contains("expected 1"),
            "the refusal must say which version arrived and which one this build speaks: {rendered}"
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

    #[test]
    fn an_unknown_op_degrades_but_an_unknown_version_never_does() {
        // Same unknown tag under both stamps. Under v1 it is a submission this build understands
        // the frame of and simply cannot name, so degrading it is right. Under v2 the frame
        // itself is unread, and degrading it would present the caller with an `Op::Unknown`
        // indistinguishable from the v1 one - a skewed message accepted as an ordinary no-op.
        let v1: SqEnvelope =
            serde_json::from_str(r#"{"protocol_version":1,"op":{"op":"reprioritize"}}"#)
                .expect("an unknown tag decodes");
        assert!(matches!(v1.into_current(), Ok(Op::Unknown)));

        let v2: SqEnvelope = serde_json::from_str(V2_SUBMISSION_JSON).expect("v2 decodes");
        assert!(matches!(v2.op, Op::Unknown));
        assert!(
            !serde_json::to_string(&v2.op)
                .expect("Op re-serialises")
                .contains("background"),
            "the degraded arm must carry no foreign payload onward into logs or the record"
        );
        assert!(
            v2.into_current().is_err(),
            "a degraded payload is not consent to the envelope; the stamp is checked either way"
        );
    }
}
