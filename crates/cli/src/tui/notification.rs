//! Fixed, out-of-band terminal notifications for semantic TUI boundaries.
//!
//! Provider, tool, and repository text can never become terminal control data. A notification is
//! one BEL byte, so an interrupted or short write cannot leave an unterminated OSC sequence that
//! consumes a later ratatui frame. The caller supplies the live terminal backend as the writer,
//! keeping the byte outside retained transcript state.

use core_kernel::UiEvent;
use core_protocol::SubmissionId;
use std::io::Write;

const TERMINAL_BELL: &[u8; 1] = b"\x07";

/// The live out-of-band terminal writer. Unix stdout is switched to nonblocking mode for exactly
/// one one-byte syscall and restored before returning, so terminal backpressure cannot stall the
/// event loop. Tests inject ordinary `Write` implementations into `TerminalNotifier` instead.
pub(super) struct LiveTerminalWriter;

impl Write for LiveTerminalWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer != TERMINAL_BELL {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "terminal notifier accepts exactly one BEL byte",
            ));
        }
        write_live_bell()?;
        Ok(1)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
fn write_live_bell() -> std::io::Result<()> {
    let descriptor = libc::STDOUT_FILENO;
    // SAFETY: fcntl reads flags from the valid process-owned stdout descriptor.
    let original_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if original_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: O_NONBLOCK is installed only for this single-byte notification write.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: TERMINAL_BELL is live and has the exact one-byte length supplied to write.
    let written = unsafe { libc::write(descriptor, TERMINAL_BELL.as_ptr().cast(), 1) };
    let write_error = (written < 0).then(std::io::Error::last_os_error);
    // SAFETY: restore the exact flags observed above before ordinary ratatui output resumes.
    let restored = unsafe { libc::fcntl(descriptor, libc::F_SETFL, original_flags) };
    if restored < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if let Some(error) = write_error {
        return Err(error);
    }
    if written != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "terminal bell write produced no byte",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_live_bell() -> std::io::Result<()> {
    match std::io::stdout().write(TERMINAL_BELL)? {
        1 => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "terminal bell write produced no byte",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    TurnComplete,
    ApprovalRequired(SubmissionId),
}

/// Session-local notification transport. A failed terminal write disables later attempts so a
/// broken output path cannot create an error/retry loop. Repeated delivery of the same approval id
/// is suppressed; approval ids are monotonic within a session.
#[derive(Debug)]
pub(super) struct TerminalNotifier {
    enabled: bool,
    transport_failed: bool,
    last_approval: Option<SubmissionId>,
    current_turn_notified: bool,
}

impl TerminalNotifier {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            transport_failed: false,
            last_approval: None,
            current_turn_notified: false,
        }
    }

    /// Derive notification intent from typed lifecycle events. `Phase::Model` opens a provider
    /// turn. A normal `TurnEnd` closes it; if usage is missing, the kernel truthfully omits
    /// `TurnEnd`, so `Done` supplies exactly one completion fallback. Stream deltas never create a
    /// trigger and cannot become terminal bytes.
    pub(super) fn trigger_for_event(&mut self, event: &UiEvent) -> Option<Trigger> {
        match event {
            UiEvent::Phase(core_protocol::Phase::Model) => {
                self.current_turn_notified = false;
                None
            }
            UiEvent::TurnEnd { .. } => {
                self.current_turn_notified = true;
                Some(Trigger::TurnComplete)
            }
            UiEvent::Done(_) if !self.current_turn_notified => {
                self.current_turn_notified = true;
                Some(Trigger::TurnComplete)
            }
            UiEvent::Done(_) => None,
            UiEvent::ApprovalRequest { id, .. } => Some(Trigger::ApprovalRequired(*id)),
            _ => None,
        }
    }

    /// Queue one BEL directly through the terminal backend. There is one one-byte write attempt,
    /// with no `write_all` loop, flush, or retry. The imminent ordinary TUI draw owns flushing. A
    /// zero-byte or failed write disables future attempts without disturbing the semantic event.
    pub(super) fn emit<W: Write>(&mut self, writer: &mut W, trigger: Trigger) {
        if !self.enabled || self.transport_failed {
            return;
        }
        if let Trigger::ApprovalRequired(id) = trigger {
            if self.last_approval == Some(id) {
                return;
            }
            self.last_approval = Some(id);
        }
        if !matches!(writer.write(TERMINAL_BELL), Ok(1)) {
            self.transport_failed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_is_byte_silent_for_every_notification_boundary() {
        let mut output = Vec::new();
        let mut notifier = TerminalNotifier::new(false);
        notifier.emit(&mut output, Trigger::TurnComplete);
        notifier.emit(&mut output, Trigger::ApprovalRequired(SubmissionId(1)));
        assert!(output.is_empty());
    }

    #[test]
    fn enabled_emits_one_byte_and_deduplicates_approval_ids() {
        let mut output = Vec::new();
        let mut notifier = TerminalNotifier::new(true);
        notifier.emit(&mut output, Trigger::TurnComplete);
        notifier.emit(&mut output, Trigger::ApprovalRequired(SubmissionId(7)));
        notifier.emit(&mut output, Trigger::ApprovalRequired(SubmissionId(7)));
        notifier.emit(&mut output, Trigger::ApprovalRequired(SubmissionId(8)));
        assert_eq!(output, TERMINAL_BELL.repeat(3));
    }

    #[test]
    fn streamed_or_hostile_content_cannot_create_terminal_output() {
        let mut notifier = TerminalNotifier::new(true);
        for event in [
            UiEvent::Text("delta\x1b]9;injected\x07".into()),
            UiEvent::Thinking("reasoning".into()),
            UiEvent::Notice("turn complete".into()),
        ] {
            assert_eq!(notifier.trigger_for_event(&event), None);
        }
    }

    #[test]
    fn zero_byte_write_disables_later_attempts_without_a_partial_sequence() {
        struct ZeroWriter {
            writes: usize,
        }

        impl Write for ZeroWriter {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                assert_eq!(buffer, TERMINAL_BELL);
                Ok(0)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                panic!("notification transport must not flush independently")
            }
        }

        let mut writer = ZeroWriter { writes: 0 };
        let mut notifier = TerminalNotifier::new(true);
        notifier.emit(&mut writer, Trigger::TurnComplete);
        notifier.emit(&mut writer, Trigger::TurnComplete);
        assert_eq!(writer.writes, 1);
    }
}
