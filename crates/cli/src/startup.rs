//! Startup latency instrumentation for the composition root.
//!
//! Every `PhaseSpan` in this binary lives inside the turn loop, so nothing measured the work that
//! happens BEFORE the first frame: config load, tool-server registration, provider discovery and
//! terminal probing. A startup regression was therefore invisible — the only symptom was an
//! operator saying it "felt slow".
//!
//! The instrument is off unless the operator asks for it. When it is off no clock is read, no
//! allocation is made and nothing is written: `StartupTiming::disabled` carries no origin, so
//! `mark` cannot observe a phase and `flush` has nothing to print. Measurement must never become a
//! reason startup got slower.

use std::ffi::OsStr;
use std::time::Instant;

/// Set to any value other than empty or `0` to print the startup breakdown on stderr.
pub(crate) const STARTUP_TIMING_ENV: &str = "ITERON_STARTUP_TIMING";

/// The four startup phases that stand between the process starting and the first painted frame.
/// The list is closed: a fifth phase is a deliberate contract change, not an ad-hoc `eprintln!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupPhase {
    /// Argument parsing plus repo/user/project config resolution.
    Config,
    /// Connecting configured tool servers and registering their tools.
    ToolServer,
    /// Resolving provider instances and their model catalogs.
    ProviderDiscover,
    /// Interactive terminal capability queries (keyboard enhancement, OSC 11).
    TerminalProbe,
}

impl StartupPhase {
    /// Stable label. Operators grep these, so they are part of the contract.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::ToolServer => "tool_server",
            Self::ProviderDiscover => "provider_discover",
            Self::TerminalProbe => "terminal_probe",
        }
    }
}

/// One `Instant` taken at the top of `run_cli`, plus the bounded list of phases closed since.
#[derive(Debug)]
pub(crate) struct StartupTiming {
    /// `None` is the whole off-switch: no clock, no spans, no output.
    origin: Option<Instant>,
    /// Wall-clock at the end of the previous phase, so each span is a duration, not a prefix sum.
    previous: Option<Instant>,
    spans: Vec<(StartupPhase, u64)>,
}

impl StartupTiming {
    /// Arm from the environment exactly once, at the top of `run_cli`.
    pub(crate) fn from_env() -> Self {
        Self::armed(enabled(std::env::var_os(STARTUP_TIMING_ENV).as_deref()))
    }

    pub(crate) fn armed(enabled: bool) -> Self {
        let origin = enabled.then(Instant::now);
        Self {
            origin,
            previous: origin,
            spans: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self::armed(false)
    }

    /// Close `phase` at the current instant. A phase is recorded at most once: re-marking would
    /// silently attribute another phase's time to it.
    pub(crate) fn mark(&mut self, phase: StartupPhase) {
        let Some(previous) = self.previous else {
            return;
        };
        if self.spans.iter().any(|(recorded, _)| *recorded == phase) {
            return;
        }
        let now = Instant::now();
        self.spans.push((
            phase,
            iteron_obs::duration_ms_ceil(now.duration_since(previous)),
        ));
        self.previous = Some(now);
    }

    /// Render the one line this instrument emits, or `None` when it is off or nothing was marked.
    pub(crate) fn report(&self) -> Option<String> {
        let origin = self.origin?;
        if self.spans.is_empty() {
            return None;
        }
        let mut line = String::from("startup:");
        for (phase, ms) in &self.spans {
            line.push_str(&format!(" {}={ms}ms", phase.label()));
        }
        line.push_str(&format!(
            " total={}ms",
            iteron_obs::duration_ms_ceil(origin.elapsed())
        ));
        Some(line)
    }

    /// Emit the breakdown and disarm, so a second call (one-shot and TUI share this type) cannot
    /// print a second, misleading line.
    pub(crate) fn flush(&mut self) {
        if let Some(line) = self.report() {
            eprintln!("{line}");
        }
        self.origin = None;
        self.previous = None;
        self.spans.clear();
    }
}

/// Absent, empty, whitespace, and `0` all mean off; anything else arms the instrument.
fn enabled(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| {
        let value = value.to_string_lossy();
        let value = value.trim();
        !value.is_empty() && value != "0"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_instrument_reads_no_clock_and_prints_nothing() {
        let mut timing = StartupTiming::disabled();
        timing.mark(StartupPhase::Config);
        timing.mark(StartupPhase::ToolServer);
        timing.mark(StartupPhase::ProviderDiscover);
        timing.mark(StartupPhase::TerminalProbe);
        assert!(timing.origin.is_none(), "no startup clock is ever read");
        assert!(timing.spans.is_empty(), "no span is ever allocated");
        assert_eq!(timing.report(), None);
        timing.flush();
        assert_eq!(timing.report(), None);
    }

    #[test]
    fn an_armed_instrument_reports_every_startup_phase_exactly_once() {
        let mut timing = StartupTiming::armed(true);
        timing.mark(StartupPhase::Config);
        timing.mark(StartupPhase::ToolServer);
        timing.mark(StartupPhase::ProviderDiscover);
        timing.mark(StartupPhase::TerminalProbe);
        // A re-mark is the regression this guards: it would move another phase's wall time into an
        // already-closed one and make the breakdown add up to more than the total.
        timing.mark(StartupPhase::Config);

        let report = timing.report().expect("an armed instrument reports");
        for phase in [
            StartupPhase::Config,
            StartupPhase::ToolServer,
            StartupPhase::ProviderDiscover,
            StartupPhase::TerminalProbe,
        ] {
            assert_eq!(
                report.matches(&format!("{}=", phase.label())).count(),
                1,
                "{} appears exactly once in {report}",
                phase.label()
            );
        }
        assert!(report.starts_with("startup:"));
        assert!(report.contains("total="));

        timing.flush();
        assert_eq!(
            timing.report(),
            None,
            "flushing disarms; a second drain cannot print a second line"
        );
    }

    #[test]
    fn the_environment_switch_treats_only_a_real_value_as_on() {
        assert!(!enabled(None));
        assert!(!enabled(Some(OsStr::new(""))));
        assert!(!enabled(Some(OsStr::new("  "))));
        assert!(!enabled(Some(OsStr::new("0"))));
        assert!(enabled(Some(OsStr::new("1"))));
        assert!(enabled(Some(OsStr::new("yes"))));
    }
}
