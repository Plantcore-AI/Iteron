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
//! `protocol_version`. An envelope one version ahead decodes cleanly today — its unknown op tag
//! degrades exactly as designed — so a reader that trusted decoding alone would receive a
//! well-formed `Op::Unknown` and have no way left to tell it apart from a genuine current-version
//! submission of an unrecognised kind. The two are not the same: the second is a message this
//! build understands the frame of, the first is a message whose whole frame is defined by a spec
//! this build has never read.
//!
//! That is why the refusal is a typed `Err` on a value that decoded successfully, rather than a
//! decode failure. `crates/kernel/src/lib.rs` binds `let Ok(op) = envelope.into_current() else`;
//! the `Err` arm is the only thing standing between a foreign-version submission and the loop.
//!
//! # Why the freeze left this at 1, and what moved it to 2
//!
//! §4.3(a) obliges a bump when a *published shape* moves, not when this crate is touched. The W1
//! freeze added `TaskEnvelope`, `EffectProposal`, `SlotId` and the rest here and held the constant
//! at 1 because every one of them was a brand-new surface: no existing field, tag or fixture
//! moved, so no byte on either queue moved and no live run's pinned version changed. From there on
//! the five contracts were published too, and reshaping any of them does oblige a bump, exactly as
//! §4.3(c) requires.
//!
//! That is what version 2 is. `record.rollout` moved 7 → 8 and `record.event-envelope` moved 3 → 4
//! to carry the `tunables_snapshot` event, which reshapes a published surface that travels on EQ.
//! A peer built against version 1 would accept such an envelope by its stamp and then read its
//! contents against a shape it does not have; the bump is what turns that into a typed refusal.

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

    /// A v3 submission in the form it would actually arrive in: bytes from another build, not a
    /// constructor call this build made against itself. The op tag is one no version of this
    /// crate has ever defined, because a real v3 producer is free to send exactly that.
    ///
    /// This was the v2 fixture while `PROTOCOL_VERSION` was 1. The bump to 2 made v2 the version
    /// this build speaks, so the skew case moved up with it rather than staying pointed at a
    /// version that is now current -- which is what the literal assertion below exists to force.
    const SKEWED_SUBMISSION_JSON: &str =
        r#"{"protocol_version":3,"op":{"op":"reprioritize","lane":"background"}}"#;

    /// The same unknown op tag under the version this build does speak.
    const CURRENT_UNKNOWN_OP_JSON: &str = r#"{"protocol_version":2,"op":{"op":"reprioritize"}}"#;

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

        // Written as a literal rather than as `PROTOCOL_VERSION + 1` so that a future bump has to
        // come here and decide what the skew case now means, instead of silently re-aiming this
        // test one version higher and leaving the version it used to guard untested. The bump from
        // 1 to 2 did exactly that: the fixture moved to v3, and v2 -- now current -- is covered by
        // the decode-and-accept case above.
        assert_eq!(PROTOCOL_VERSION, 2);
        let skewed: SqEnvelope = serde_json::from_str(SKEWED_SUBMISSION_JSON)
            .expect("a v3 envelope decodes; it is the version gate that refuses it, not serde");
        let refused = skewed
            .into_current()
            .expect_err("a v3 submission must not yield an Op to interpret");
        assert_eq!(
            refused,
            ProtocolVersionError {
                expected: 2,
                actual: 3,
            }
        );

        // Typed and returned, not raised: the kernel's `let Ok(op) = ... else` arm needs a value
        // it can branch on, and the operator-facing message has to name both versions or the
        // report is "something was rejected".
        let propagated: &dyn std::error::Error = &refused;
        let rendered = propagated.to_string();
        assert!(
            rendered.contains("version 3") && rendered.contains("expected 2"),
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
        // Same unknown tag under both stamps. Under the current version it is a submission this
        // build understands the frame of and simply cannot name, so degrading it is right. Under a
        // future version the frame itself is unread, and degrading it would present the caller
        // with an `Op::Unknown` indistinguishable from the current one - a skewed message accepted
        // as an ordinary no-op.
        let current: SqEnvelope =
            serde_json::from_str(CURRENT_UNKNOWN_OP_JSON).expect("an unknown tag decodes");
        assert!(matches!(current.into_current(), Ok(Op::Unknown)));

        let skewed: SqEnvelope =
            serde_json::from_str(SKEWED_SUBMISSION_JSON).expect("a v3 envelope decodes");
        assert!(matches!(skewed.op, Op::Unknown));
        assert!(
            !serde_json::to_string(&skewed.op)
                .expect("Op re-serialises")
                .contains("background"),
            "the degraded arm must carry no foreign payload onward into logs or the record"
        );
        assert!(
            skewed.into_current().is_err(),
            "a degraded payload is not consent to the envelope; the stamp is checked either way"
        );
    }
}
