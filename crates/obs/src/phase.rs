use crate::Ledger;
use core_protocol::Phase;
use std::time::{Duration, Instant};

/// A phase span: name a phase and measure its wall-clock duration.
///
/// Durations are reported in whole milliseconds, rounded up so a real sub-millisecond phase is
/// observable rather than indistinguishable from a phase that never ran. Conversion saturates at
/// `u64::MAX`; observational accounting can never wrap and reopen a bound.
pub struct PhaseSpan {
    pub phase: Phase,
    started: Instant,
}

impl PhaseSpan {
    pub fn enter(phase: Phase) -> Self {
        Self {
            phase,
            started: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        duration_ms_ceil(self.started.elapsed())
    }
}

impl Ledger {
    /// Record bounded context-assembly wall time. This is a pure additive projection: the caller
    /// supplies the measurement and the Ledger gains no clock, filesystem, process, or network
    /// authority.
    pub fn phase_context(&mut self, ms: u64) {
        self.timings.phase_context_ms = self.timings.phase_context_ms.saturating_add(ms);
    }

    pub fn phase_tools(&mut self, ms: u64) {
        self.timings.phase_tools_ms = self.timings.phase_tools_ms.saturating_add(ms);
    }

    /// Record independent verification wall time, kept distinct from tool execution.
    pub fn phase_verify(&mut self, ms: u64) {
        self.timings.phase_verify_ms = self.timings.phase_verify_ms.saturating_add(ms);
    }

    /// Saturating total of the four active run phases represented by this ledger. Idle is an
    /// operator wait state and intentionally remains outside run-work attribution.
    pub fn attributed_phase_ms(&self) -> Option<u64> {
        (!self.timing_history_unknown).then(|| self.timings.attributed_phase_ms())
    }
}

fn duration_ms_ceil(duration: Duration) -> u64 {
    let nanos = duration.as_nanos();
    let millis = nanos.saturating_add(999_999) / 1_000_000;
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_sub_millisecond_spans_remain_observable() {
        let span = PhaseSpan::enter(Phase::Context);
        assert_eq!(span.phase, Phase::Context);
        assert!(span.elapsed_ms() >= 1);
    }

    #[test]
    fn duration_conversion_rounds_up_without_wrapping() {
        assert_eq!(duration_ms_ceil(Duration::from_nanos(1)), 1);
        assert_eq!(duration_ms_ceil(Duration::from_millis(1)), 1);
        assert_eq!(duration_ms_ceil(Duration::from_nanos(1_000_001)), 2);
        assert_eq!(duration_ms_ceil(Duration::MAX), u64::MAX);
    }

    #[test]
    fn context_and_verify_phase_counters_are_saturating_and_additive() {
        let mut parent = Ledger::new();
        parent.phase_context(2);
        parent.phase_tools(3);
        parent.phase_verify(5);
        let mut child = Ledger::new();
        child.phase_context(7);
        child.phase_verify(11);
        parent.merge(&child);

        let timings = parent
            .timings()
            .complete()
            .expect("live timing is complete");
        assert_eq!(timings.phase_context_ms, 9);
        assert_eq!(timings.phase_tools_ms, 3);
        assert_eq!(timings.phase_verify_ms, 16);
        assert_eq!(parent.attributed_phase_ms(), Some(28));
        assert!(parent.summary().contains("context=9"));
        assert!(parent.summary().contains("verify=16"));

        parent.timings.phase_context_ms = u64::MAX;
        parent.timings.phase_verify_ms = u64::MAX;
        parent.phase_context(1);
        parent.phase_verify(1);
        let timings = parent
            .timings()
            .complete()
            .expect("live timing is complete");
        assert_eq!(timings.phase_context_ms, u64::MAX);
        assert_eq!(timings.phase_verify_ms, u64::MAX);
        assert_eq!(parent.attributed_phase_ms(), Some(u64::MAX));
    }
}
