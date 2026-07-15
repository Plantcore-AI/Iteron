//! Identifiers. `Seq` is the total order within a run's record chain (ADR-008: per-run,
//! not global, so the WORM append is not a global-lock bottleneck).

use serde::{Deserialize, Serialize};
use std::fmt;

/// A run of the agent against a task. The record chain is keyed per-run (ADR-008).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

/// Tenant principal (ADR-009). Core from day one; the vertical slice sets it to the default.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl Default for TenantId {
    fn default() -> Self {
        TenantId("default".into())
    }
}

/// A turn = one model call plus the tool executions it drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TurnId(pub u32);

/// Harness-minted identity for one admitted external effect. Provider/model tool-call ids remain
/// untrusted correlation metadata and must never be used as the durable effect identity.
///
/// The transparent string representation keeps the first experimental `EffectIntent` records
/// readable; the kernel distinguishes those legacy records by the absence of `tool_use_id`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectId(pub String);

/// A submission's id, correlating an `Op` with the `Event`s it produces (the SQ/EQ `id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubmissionId(pub u64);

/// Monotonic sequence number within a run's record chain. Total order per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Seq(pub u64);

impl Seq {
    pub const ZERO: Seq = Seq(0);
    pub fn next(self) -> Seq {
        Seq(self.0 + 1)
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for EffectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
