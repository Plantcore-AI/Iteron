use iteron_protocol::Usage;
use serde::{Deserialize, Serialize};

/// Counters whose value is derived exclusively from durable runtime events.
///
/// This type deliberately contains no wall-clock values. Serializing it is therefore safe for
/// live-versus-replay equality checks: a consumer cannot accidentally compare process-local
/// timing with record-derived accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibleCounters {
    pub provider_attempts: u32,
    pub completed_turns: u32,
    pub usage: Usage,
    pub tool_calls: u64,
    pub tool_errors: u64,
}

/// Process-local wall-clock observations. These numbers are never inferred from absent events.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralTimings {
    pub tool_wall_ms: u64,
    pub tool_overlapped_ms: u64,
    pub phase_context_ms: u64,
    pub phase_model_ms: u64,
    pub phase_tools_ms: u64,
    pub phase_verify_ms: u64,
}

impl EphemeralTimings {
    pub(crate) fn merge(&mut self, child: Self) {
        self.tool_wall_ms = self.tool_wall_ms.saturating_add(child.tool_wall_ms);
        self.tool_overlapped_ms = self
            .tool_overlapped_ms
            .saturating_add(child.tool_overlapped_ms);
        self.phase_context_ms = self.phase_context_ms.saturating_add(child.phase_context_ms);
        self.phase_model_ms = self.phase_model_ms.saturating_add(child.phase_model_ms);
        self.phase_tools_ms = self.phase_tools_ms.saturating_add(child.phase_tools_ms);
        self.phase_verify_ms = self.phase_verify_ms.saturating_add(child.phase_verify_ms);
    }

    pub(crate) fn attributed_phase_ms(self) -> u64 {
        self.phase_context_ms
            .saturating_add(self.phase_model_ms)
            .saturating_add(self.phase_tools_ms)
            .saturating_add(self.phase_verify_ms)
    }
}

/// Whether a timing snapshot covers the whole logical run.
///
/// Resume reconstructs counters from the append-only record, but older durable events do not
/// contain every phase duration. In that case the API exposes `UnknownAfterReplay` instead of a
/// plausible-looking zero. `observed_partial` may contain later process-local measurements; it is
/// never presented as a complete historical total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingSnapshot {
    Complete(EphemeralTimings),
    UnknownAfterReplay { observed_partial: EphemeralTimings },
}

impl TimingSnapshot {
    pub fn complete(self) -> Option<EphemeralTimings> {
        match self {
            Self::Complete(timings) => Some(timings),
            Self::UnknownAfterReplay { .. } => None,
        }
    }
}
