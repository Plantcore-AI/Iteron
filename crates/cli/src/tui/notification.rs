//! Fixed, out-of-band terminal notifications for semantic TUI boundaries.
//!
//! Provider, tool, and repository text can never become terminal control data. OSC 9 and OSC 777
//! are admitted only to the terminal writer already owned by ratatui; an ordinary `Write` receives
//! one BEL byte instead. The sole writer appends each fixed notification after a complete retained
//! frame. If a notification write is interrupted after accepting a prefix, it completes or repairs
//! that prefix before poisoning the writer, so later frame bytes cannot be consumed as OSC text.

use crate::runtime::UiEvent;
use iteron_protocol::SubmissionId;
use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

const TERMINAL_BELL: &[u8; 1] = b"\x07";
const LONG_IDLE_AFTER: Duration = Duration::from_secs(30);
const MAX_NOTIFICATION_BYTES: usize = 64;
const NOTIFICATION_QUEUE_CAPACITY: usize = 4;
const MAX_ENV_VALUE_BYTES: usize = 128;
const CANCEL_SEQUENCE: &[u8; 1] = b"\x18";

const OSC9_RUN_COMPLETE: &[u8] = b"\x1b]9;Iteron: run complete\x07";
const OSC9_APPROVAL_REQUIRED: &[u8] = b"\x1b]9;Iteron: approval required\x07";
const OSC9_LONG_IDLE: &[u8] = b"\x1b]9;Iteron: run is waiting\x07";
const OSC777_RUN_COMPLETE: &[u8] = b"\x1b]777;notify;Iteron;Run complete\x07";
const OSC777_APPROVAL_REQUIRED: &[u8] = b"\x1b]777;notify;Iteron;Approval required\x07";
const OSC777_LONG_IDLE: &[u8] = b"\x1b]777;notify;Iteron;Run is waiting\x07";

const _: () = assert!(OSC9_RUN_COMPLETE.len() <= MAX_NOTIFICATION_BYTES);
const _: () = assert!(OSC9_APPROVAL_REQUIRED.len() <= MAX_NOTIFICATION_BYTES);
const _: () = assert!(OSC9_LONG_IDLE.len() <= MAX_NOTIFICATION_BYTES);
const _: () = assert!(OSC777_RUN_COMPLETE.len() <= MAX_NOTIFICATION_BYTES);
const _: () = assert!(OSC777_APPROVAL_REQUIRED.len() <= MAX_NOTIFICATION_BYTES);
const _: () = assert!(OSC777_LONG_IDLE.len() <= MAX_NOTIFICATION_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Bell,
    Osc9,
    Osc777,
}

impl Protocol {
    fn detect() -> Self {
        Self::detect_with(|name| {
            let value = std::env::var(name).ok()?;
            (value.len()
                <= iteron_tunables::param_integer(
                    "cli.tui.notification.max_env_value_bytes",
                    MAX_ENV_VALUE_BYTES,
                ))
            .then_some(value)
        })
    }

    fn detect_with(mut value: impl FnMut(&str) -> Option<String>) -> Self {
        let term = value("TERM").unwrap_or_default();
        if term == "dumb" || value("TMUX").is_some() || value("STY").is_some() {
            return Self::Bell;
        }

        let term_program = value("TERM_PROGRAM")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let osc9_program = matches!(term_program.as_str(), "iterm.app" | "wezterm" | "vscode");
        let osc9_runtime = ["WT_SESSION", "WEZTERM_PANE"]
            .into_iter()
            .any(|name| value(name).is_some_and(|signal| !signal.is_empty()));
        if osc9_program || osc9_runtime {
            Self::Osc9
        } else if value("VTE_VERSION")
            .and_then(|version| version.parse::<u32>().ok())
            .is_some_and(|version| version >= 5_000)
            || value("KONSOLE_VERSION")
                .and_then(|version| version.parse::<u32>().ok())
                .is_some_and(|version| version >= 180_400)
        {
            Self::Osc777
        } else {
            Self::Bell
        }
    }
}

/// Result of offering one fixed sequence to a notification transport.
///
/// `Accepted(Ok(()))` means the transport owns the complete sequence; it deliberately does not
/// claim that a terminal displayed it. A backend that cannot preserve prefix integrity returns
/// `Unsupported` without touching the output, and the notifier safely falls back to BEL.
pub(super) enum NotificationAdmission {
    Unsupported,
    Accepted(io::Result<()>),
}

/// Out-of-band intent kept separate from ratatui's retained frame buffer.
pub(super) trait NotificationTransport {
    fn write_bell(&mut self) -> io::Result<()>;

    fn admit_notification(&mut self, sequence: &[u8]) -> NotificationAdmission {
        if sequence == TERMINAL_BELL {
            NotificationAdmission::Accepted(self.write_bell())
        } else {
            NotificationAdmission::Unsupported
        }
    }
}

#[derive(Clone, Copy)]
struct FixedNotification {
    bytes: [u8; MAX_NOTIFICATION_BYTES],
    len: u8,
}

impl FixedNotification {
    fn new(sequence: &[u8]) -> Option<Self> {
        if sequence.is_empty()
            || sequence.len()
                > iteron_tunables::param_integer(
                    "cli.tui.notification.max_notification_bytes",
                    MAX_NOTIFICATION_BYTES,
                )
            || (sequence != TERMINAL_BELL
                && ![
                    OSC9_RUN_COMPLETE,
                    OSC9_APPROVAL_REQUIRED,
                    OSC9_LONG_IDLE,
                    OSC777_RUN_COMPLETE,
                    OSC777_APPROVAL_REQUIRED,
                    OSC777_LONG_IDLE,
                ]
                .contains(&sequence))
        {
            return None;
        }
        let mut bytes = [0; MAX_NOTIFICATION_BYTES];
        bytes[..sequence.len()].copy_from_slice(sequence);
        Some(Self {
            bytes,
            len: sequence.len() as u8,
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The only live terminal writer. Ratatui writes retained-frame bytes through `Write`, then calls
/// `flush`; that boundary flushes the frame first and appends every admitted notification. No
/// worker thread or second stdout handle can interleave inside a retained frame.
pub(super) struct LiveTerminalWriter<W: Write> {
    inner: W,
    shared: Arc<Mutex<LiveNotificationQueue>>,
    poisoned: bool,
}

struct LiveNotificationQueue {
    notifications: VecDeque<FixedNotification>,
    desktop_sequences_supported: bool,
    poisoned: bool,
}

pub(super) struct LiveNotificationTransport {
    shared: Arc<Mutex<LiveNotificationQueue>>,
}

impl LiveTerminalWriter<std::io::Stdout> {
    pub(super) fn stdout() -> (Self, LiveNotificationTransport) {
        Self::with_desktop_sequences(std::io::stdout(), live_stdout_supports_desktop_sequences())
    }
}

impl<W: Write> LiveTerminalWriter<W> {
    fn with_desktop_sequences(
        inner: W,
        desktop_sequences_supported: bool,
    ) -> (Self, LiveNotificationTransport) {
        let shared = Arc::new(Mutex::new(LiveNotificationQueue {
            notifications: VecDeque::with_capacity(iteron_tunables::param_integer(
                "cli.tui.notification.notification_queue_capacity",
                NOTIFICATION_QUEUE_CAPACITY,
            )),
            desktop_sequences_supported,
            poisoned: false,
        }));
        (
            Self {
                inner,
                shared: Arc::clone(&shared),
                poisoned: false,
            },
            LiveNotificationTransport { shared },
        )
    }

    fn write_notification(&mut self, frame: FixedNotification) -> io::Result<()> {
        let sequence = frame.as_slice();
        let mut accepted = 0;
        let mut interrupted = 0;
        while accepted < sequence.len() {
            match self.inner.write(&sequence[accepted..]) {
                Ok(0) => {
                    return self.fail_notification(
                        sequence,
                        accepted,
                        io::Error::new(
                            io::ErrorKind::WriteZero,
                            "terminal notification write produced no byte",
                        ),
                    );
                }
                Ok(written) => {
                    accepted += written;
                    interrupted = 0;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 3 => {
                    interrupted += 1;
                }
                Err(error) => return self.fail_notification(sequence, accepted, error),
            }
        }
        self.inner.flush()
    }

    fn fail_notification(
        &mut self,
        sequence: &[u8],
        accepted: usize,
        error: io::Error,
    ) -> io::Result<()> {
        if sequence.starts_with(b"\x1b]") && accepted > 0 && accepted < sequence.len() {
            let repair = if accepted == 1 {
                CANCEL_SEQUENCE
            } else {
                TERMINAL_BELL
            };
            let _ = write_one_byte(&mut self.inner, repair);
            let _ = self.inner.flush();
        }
        self.poisoned = true;
        if let Ok(mut queue) = self.shared.lock() {
            queue.poisoned = true;
            queue.notifications.clear();
        }
        Err(error)
    }

    #[cfg(test)]
    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for LiveTerminalWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the terminal notification writer is poisoned",
            ));
        }
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the terminal notification writer is poisoned",
            ));
        }
        // Finish the retained frame before beginning any out-of-band control sequence.
        self.inner.flush()?;
        let mut notifications = {
            let mut queue = self.shared.lock().map_err(|_| {
                io::Error::other("the terminal notification queue lock is poisoned")
            })?;
            std::mem::take(&mut queue.notifications)
        };
        while let Some(frame) = notifications.pop_front() {
            self.write_notification(frame)?;
        }
        Ok(())
    }
}

impl LiveNotificationTransport {
    fn with_queue(
        &mut self,
        operation: impl FnOnce(&mut LiveNotificationQueue) -> io::Result<()>,
    ) -> io::Result<()> {
        match self.shared.try_lock() {
            Ok(mut queue) => operation(&mut queue),
            Err(TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the terminal notification queue is busy",
            )),
            Err(TryLockError::Poisoned(_)) => Err(io::Error::other(
                "the terminal notification queue lock is poisoned",
            )),
        }
    }

    fn admit_fixed(&mut self, frame: FixedNotification) -> io::Result<()> {
        self.with_queue(|queue| {
            if queue.poisoned {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the terminal notification writer is poisoned",
                ));
            }
            if queue.notifications.len()
                == iteron_tunables::param_integer(
                    "cli.tui.notification.notification_queue_capacity",
                    NOTIFICATION_QUEUE_CAPACITY,
                )
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the bounded terminal notification queue is full",
                ));
            }
            queue.notifications.push_back(frame);
            Ok(())
        })
    }
}

impl NotificationTransport for LiveNotificationTransport {
    fn write_bell(&mut self) -> io::Result<()> {
        let frame = FixedNotification::new(TERMINAL_BELL)
            .expect("the fixed terminal bell fits the notification frame");
        self.admit_fixed(frame)
    }

    fn admit_notification(&mut self, sequence: &[u8]) -> NotificationAdmission {
        let desktop_sequences_supported = match self.shared.try_lock() {
            Ok(queue) => queue.desktop_sequences_supported,
            Err(TryLockError::WouldBlock) => {
                return NotificationAdmission::Accepted(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "the terminal notification queue is busy",
                )));
            }
            Err(TryLockError::Poisoned(_)) => {
                return NotificationAdmission::Accepted(Err(io::Error::other(
                    "the terminal notification queue lock is poisoned",
                )));
            }
        };
        if sequence != TERMINAL_BELL && !desktop_sequences_supported {
            return NotificationAdmission::Unsupported;
        }
        let Some(frame) = FixedNotification::new(sequence) else {
            return NotificationAdmission::Unsupported;
        };
        NotificationAdmission::Accepted(self.admit_fixed(frame))
    }
}

fn write_one_byte(writer: &mut impl Write, byte: &[u8; 1]) -> io::Result<()> {
    for _ in 0..=3 {
        match writer.write(byte) {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "terminal repair write produced no byte",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "terminal repair write was repeatedly interrupted",
    ))
}

fn live_stdout_supports_desktop_sequences() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    #[cfg(unix)]
    {
        // A nonblocking shared stdout can refuse a repair byte after accepting an OSC prefix.
        // Refuse desktop sequences up front; BEL remains a safe one-byte fallback.
        // SAFETY: fcntl only reads the flags of the process-owned stdout descriptor.
        let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
        flags >= 0 && flags & libc::O_NONBLOCK == 0
    }
    #[cfg(not(unix))]
    true
}

/// Adapts an ordinary writer without pretending it can preserve a multi-byte control sequence.
/// Exactly one one-byte write is ever offered to the underlying writer.
#[cfg(test)]
pub(super) struct OrdinaryWriter<'a, W: Write + ?Sized>(&'a mut W);

#[cfg(test)]
impl<'a, W: Write + ?Sized> OrdinaryWriter<'a, W> {
    pub(super) fn new(writer: &'a mut W) -> Self {
        Self(writer)
    }
}

#[cfg(test)]
impl<W: Write + ?Sized> NotificationTransport for OrdinaryWriter<'_, W> {
    fn write_bell(&mut self) -> io::Result<()> {
        match self.0.write(TERMINAL_BELL) {
            Ok(1) => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "terminal bell write produced no byte",
            )),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
impl NotificationTransport for Vec<u8> {
    fn write_bell(&mut self) -> io::Result<()> {
        self.extend_from_slice(TERMINAL_BELL);
        Ok(())
    }

    fn admit_notification(&mut self, sequence: &[u8]) -> NotificationAdmission {
        self.extend_from_slice(sequence);
        NotificationAdmission::Accepted(Ok(()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    RunComplete,
    ApprovalRequired(SubmissionId),
    LongIdle,
}

/// Session-local notification transport. A failed terminal write disables later attempts so a
/// broken output path cannot create an error/retry loop. Repeated delivery of the same approval id
/// is suppressed. A run-complete trigger exists only between one accepted submission and the first
/// authoritative App Server terminal event. Long-idle is emitted once per quiet period and rearms
/// only after new semantic activity.
#[derive(Debug)]
pub(super) struct TerminalNotifier {
    enabled: bool,
    protocol: Protocol,
    transport_failed: bool,
    last_approval: Option<SubmissionId>,
    run_active: bool,
    idle_after: Duration,
    idle_tracking: bool,
    last_activity: Instant,
    idle_notified: bool,
}

impl TerminalNotifier {
    pub(super) fn new(enabled: bool) -> Self {
        Self::with_settings(
            enabled,
            Protocol::detect(),
            iteron_tunables::param_duration(
                "cli.tui.notification.long_idle_after",
                LONG_IDLE_AFTER,
            ),
            Instant::now(),
        )
    }

    fn with_settings(
        enabled: bool,
        protocol: Protocol,
        idle_after: Duration,
        now: Instant,
    ) -> Self {
        Self {
            enabled,
            protocol,
            transport_failed: false,
            last_approval: None,
            run_active: false,
            idle_after,
            idle_tracking: false,
            last_activity: now,
            idle_notified: false,
        }
    }

    /// Start one notification lifecycle only after the App Server accepts a submission.
    pub(super) fn begin_run(&mut self) {
        self.begin_run_at(Instant::now());
    }

    fn begin_run_at(&mut self, now: Instant) {
        self.run_active = true;
        self.idle_tracking = true;
        self.last_activity = now;
        self.idle_notified = false;
    }

    /// Consume the accepted run at its authoritative App Server terminal boundary. `UiEvent::Done`
    /// is presentation-only legacy text and provider `TurnEnd` can occur many times in one tool
    /// loop, so neither is allowed to create this trigger.
    pub(super) fn run_completed(&mut self) -> Option<Trigger> {
        let completed = self.run_active;
        self.run_active = false;
        self.idle_tracking = false;
        self.idle_notified = false;
        completed.then_some(Trigger::RunComplete)
    }

    /// Derive attention intent from typed live events. Every event refreshes the idle clock for an
    /// accepted run; only a new approval request creates an immediate notification.
    pub(super) fn trigger_for_event(&mut self, event: &UiEvent) -> Option<Trigger> {
        self.trigger_for_event_at(event, Instant::now())
    }

    fn trigger_for_event_at(&mut self, event: &UiEvent, now: Instant) -> Option<Trigger> {
        if self.run_active {
            self.idle_tracking = true;
            self.last_activity = now;
            self.idle_notified = false;
        }
        match event {
            UiEvent::ApprovalRequest { id, .. } => Some(Trigger::ApprovalRequired(*id)),
            _ => None,
        }
    }

    /// Poll the bounded long-idle timer started by `begin_run`. An event rearms it, and one quiet
    /// period can create at most one trigger.
    pub(super) fn poll_idle(&mut self, running: bool) -> Option<Trigger> {
        self.poll_idle_at(running, Instant::now())
    }

    fn poll_idle_at(&mut self, running: bool, now: Instant) -> Option<Trigger> {
        if !running {
            self.run_active = false;
            self.idle_tracking = false;
            self.idle_notified = false;
            return None;
        }
        if !self.enabled || !self.run_active || !self.idle_tracking {
            return None;
        }
        if !self.idle_notified
            && now.saturating_duration_since(self.last_activity) >= self.idle_after
        {
            self.idle_notified = true;
            return Some(Trigger::LongIdle);
        }
        None
    }

    /// Offer the selected fixed sequence to a prefix-safe transport. Unsupported transports fall
    /// back to one BEL. Admission failure disables later attempts; acceptance deliberately does
    /// not claim that the desktop displayed the notification.
    pub(super) fn emit_transport<T: NotificationTransport + ?Sized>(
        &mut self,
        transport: &mut T,
        trigger: Trigger,
    ) {
        if !self.admit(trigger) {
            return;
        }
        let result = match self.protocol {
            Protocol::Bell => transport.write_bell(),
            protocol => {
                let sequence = notification_sequence(protocol, trigger);
                debug_assert!(
                    sequence.len()
                        <= iteron_tunables::param_integer(
                            "cli.tui.notification.max_notification_bytes",
                            MAX_NOTIFICATION_BYTES
                        )
                );
                debug_assert!(sequence.ends_with(TERMINAL_BELL));
                match transport.admit_notification(sequence) {
                    NotificationAdmission::Unsupported => transport.write_bell(),
                    NotificationAdmission::Accepted(result) => result,
                }
            }
        };
        if result.is_err() {
            self.transport_failed = true;
        }
    }

    /// Safely adapt an ordinary writer. There is one one-byte write attempt, with no `write_all`
    /// loop, flush, or retry.
    #[cfg(test)]
    pub(super) fn emit<W: Write>(&mut self, writer: &mut W, trigger: Trigger) {
        let mut transport = OrdinaryWriter::new(writer);
        self.emit_transport(&mut transport, trigger);
    }

    fn admit(&mut self, trigger: Trigger) -> bool {
        if !self.enabled || self.transport_failed {
            return false;
        }
        if let Trigger::ApprovalRequired(id) = trigger {
            if self.last_approval == Some(id) {
                return false;
            }
            self.last_approval = Some(id);
        }
        true
    }
}

fn notification_sequence(protocol: Protocol, trigger: Trigger) -> &'static [u8] {
    match (protocol, trigger) {
        (Protocol::Bell, _) => TERMINAL_BELL,
        (Protocol::Osc9, Trigger::RunComplete) => OSC9_RUN_COMPLETE,
        (Protocol::Osc9, Trigger::ApprovalRequired(_)) => OSC9_APPROVAL_REQUIRED,
        (Protocol::Osc9, Trigger::LongIdle) => OSC9_LONG_IDLE,
        (Protocol::Osc777, Trigger::RunComplete) => OSC777_RUN_COMPLETE,
        (Protocol::Osc777, Trigger::ApprovalRequired(_)) => OSC777_APPROVAL_REQUIRED,
        (Protocol::Osc777, Trigger::LongIdle) => OSC777_LONG_IDLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_is_byte_silent_for_every_notification_boundary() {
        let mut output = Vec::new();
        let mut notifier = TerminalNotifier::new(false);
        notifier.begin_run();
        let completion = notifier
            .run_completed()
            .expect("accepted run owns a terminal boundary");
        notifier.emit(&mut output, completion);
        notifier.emit(&mut output, Trigger::ApprovalRequired(SubmissionId(1)));
        notifier.emit(&mut output, Trigger::LongIdle);
        assert!(output.is_empty());
    }

    #[test]
    fn enabled_emits_one_byte_and_deduplicates_approval_ids() {
        let mut output = Vec::new();
        let mut notifier = TerminalNotifier::new(true);
        notifier.begin_run();
        let completion = notifier
            .run_completed()
            .expect("accepted run owns a terminal boundary");
        notifier.emit(&mut output, completion);
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
        notifier.begin_run();
        let completion = notifier
            .run_completed()
            .expect("accepted run owns a terminal boundary");
        notifier.emit(&mut writer, completion);
        notifier.emit(&mut writer, completion);
        assert_eq!(writer.writes, 1);
    }

    #[test]
    fn protocol_detection_is_conservative_and_capability_selected() {
        let detect = |pairs: &[(&str, &str)]| {
            Protocol::detect_with(|name| {
                pairs
                    .iter()
                    .find_map(|(key, value)| (*key == name).then(|| (*value).to_owned()))
            })
        };

        assert_eq!(detect(&[]), Protocol::Bell);
        assert_eq!(detect(&[("WT_SESSION", "1")]), Protocol::Osc9);
        assert_eq!(detect(&[("TERM_PROGRAM", "WezTerm")]), Protocol::Osc9);
        assert_eq!(
            detect(&[("TERM_PROGRAM", "unknown"), ("VTE_VERSION", "7600")]),
            Protocol::Osc777
        );
        assert_eq!(detect(&[("KONSOLE_VERSION", "240800")]), Protocol::Osc777);
        assert_eq!(
            detect(&[("WT_SESSION", "1"), ("TERM", "dumb")]),
            Protocol::Bell
        );
        assert_eq!(
            detect(&[("VTE_VERSION", "7600"), ("TMUX", "session")]),
            Protocol::Bell
        );
        assert_eq!(
            detect(&[("VTE_VERSION", "4999")]),
            Protocol::Bell,
            "an old VTE version is not positive OSC 777 evidence"
        );
    }

    #[test]
    fn live_notification_queue_is_bounded_and_flushes_only_after_the_retained_frame() {
        #[derive(Default)]
        struct FlushCapture {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for FlushCapture {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }

        let (mut output, mut transport) =
            LiveTerminalWriter::with_desktop_sequences(FlushCapture::default(), true);
        output.write_all(b"retained-frame").unwrap();
        assert!(matches!(
            transport.admit_notification(OSC9_RUN_COMPLETE),
            NotificationAdmission::Accepted(Ok(()))
        ));
        for _ in 1..NOTIFICATION_QUEUE_CAPACITY {
            transport.write_bell().unwrap();
        }
        assert_eq!(
            transport
                .write_bell()
                .expect_err("a full notification queue must refuse without waiting")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        output.flush().expect("flush one frame boundary");
        let output = output.into_inner();
        assert_eq!(
            output.bytes,
            [
                b"retained-frame".as_slice(),
                OSC9_RUN_COMPLETE,
                &TERMINAL_BELL.repeat(NOTIFICATION_QUEUE_CAPACITY - 1),
            ]
            .concat()
        );
        assert_eq!(output.flushes, NOTIFICATION_QUEUE_CAPACITY + 1);
    }

    #[test]
    fn incapable_live_output_receives_only_one_bell() {
        let (mut output, mut transport) =
            LiveTerminalWriter::with_desktop_sequences(Vec::new(), false);
        let mut notifier =
            TerminalNotifier::with_settings(true, Protocol::Osc9, LONG_IDLE_AFTER, Instant::now());
        notifier.emit_transport(&mut transport, Trigger::RunComplete);
        output.flush().unwrap();
        assert_eq!(output.into_inner(), TERMINAL_BELL);
    }

    #[test]
    fn every_partial_osc_prefix_is_repaired_before_the_writer_is_poisoned() {
        enum Step {
            Accept(usize),
            Error,
        }

        struct ScriptedWriter {
            steps: VecDeque<Step>,
            bytes: Vec<u8>,
            write_calls: usize,
        }

        impl Write for ScriptedWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.write_calls += 1;
                match self.steps.pop_front().expect("scripted write step") {
                    Step::Accept(limit) => {
                        let accepted = buffer.len().min(limit);
                        self.bytes.extend_from_slice(&buffer[..accepted]);
                        Ok(accepted)
                    }
                    Step::Error => Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "injected notification failure",
                    )),
                }
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        for accepted in 1..OSC9_RUN_COMPLETE.len() {
            let inner = ScriptedWriter {
                steps: VecDeque::from([Step::Accept(accepted), Step::Error, Step::Accept(1)]),
                bytes: Vec::new(),
                write_calls: 0,
            };
            let (mut output, mut transport) =
                LiveTerminalWriter::with_desktop_sequences(inner, true);
            assert!(matches!(
                transport.admit_notification(OSC9_RUN_COMPLETE),
                NotificationAdmission::Accepted(Ok(()))
            ));
            assert_eq!(
                output.flush().expect_err("script must fail").kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                output
                    .write(b"later retained frame")
                    .expect_err("a poisoned writer must reject later frame bytes")
                    .kind(),
                io::ErrorKind::BrokenPipe
            );

            let inner = output.into_inner();
            let repair = if accepted == 1 {
                CANCEL_SEQUENCE
            } else {
                TERMINAL_BELL
            };
            let mut expected = OSC9_RUN_COMPLETE[..accepted].to_vec();
            expected.extend_from_slice(repair);
            assert_eq!(inner.bytes, expected);
            assert_eq!(
                inner.write_calls, 3,
                "the rejected later frame never reaches the terminal"
            );
        }
    }

    #[test]
    fn every_fixed_desktop_sequence_is_bounded_and_terminated() {
        for protocol in [Protocol::Osc9, Protocol::Osc777] {
            for trigger in [
                Trigger::RunComplete,
                Trigger::ApprovalRequired(SubmissionId(u64::MAX)),
                Trigger::LongIdle,
            ] {
                let sequence = notification_sequence(protocol, trigger);
                assert!(sequence.len() <= MAX_NOTIFICATION_BYTES);
                assert!(sequence.starts_with(b"\x1b]"));
                assert!(sequence.ends_with(TERMINAL_BELL));
                assert_eq!(
                    sequence[..sequence.len() - 1]
                        .iter()
                        .filter(|byte| **byte == TERMINAL_BELL[0])
                        .count(),
                    0,
                    "the only OSC terminator is the final byte"
                );
            }
        }
    }

    #[derive(Default)]
    struct AdmissionCapture {
        bytes: Vec<u8>,
        admission_calls: usize,
        bell_calls: usize,
    }

    impl NotificationTransport for AdmissionCapture {
        fn write_bell(&mut self) -> io::Result<()> {
            self.bell_calls += 1;
            self.bytes.extend_from_slice(TERMINAL_BELL);
            Ok(())
        }

        fn admit_notification(&mut self, sequence: &[u8]) -> NotificationAdmission {
            self.admission_calls += 1;
            self.bytes.extend_from_slice(sequence);
            NotificationAdmission::Accepted(Ok(()))
        }
    }

    #[test]
    fn capable_transport_receives_one_fixed_sequence_per_boundary() {
        for protocol in [Protocol::Osc9, Protocol::Osc777] {
            let now = Instant::now();
            let mut notifier =
                TerminalNotifier::with_settings(true, protocol, LONG_IDLE_AFTER, now);
            let mut output = AdmissionCapture::default();

            notifier.emit_transport(&mut output, Trigger::RunComplete);
            notifier.emit_transport(&mut output, Trigger::ApprovalRequired(SubmissionId(9)));
            notifier.emit_transport(&mut output, Trigger::ApprovalRequired(SubmissionId(9)));
            notifier.emit_transport(&mut output, Trigger::LongIdle);

            let mut expected = Vec::new();
            expected.extend_from_slice(notification_sequence(protocol, Trigger::RunComplete));
            expected.extend_from_slice(notification_sequence(
                protocol,
                Trigger::ApprovalRequired(SubmissionId(9)),
            ));
            expected.extend_from_slice(notification_sequence(protocol, Trigger::LongIdle));
            assert_eq!(output.bytes, expected);
            assert_eq!(output.admission_calls, 3);
            assert_eq!(output.bell_calls, 0);
        }
    }

    #[test]
    fn every_refused_admission_disables_retries() {
        struct BoundaryAdmission {
            fail_before: usize,
            bytes: Vec<u8>,
            calls: usize,
        }

        impl NotificationTransport for BoundaryAdmission {
            fn write_bell(&mut self) -> io::Result<()> {
                panic!("a failed admission must not be retried as BEL")
            }

            fn admit_notification(&mut self, sequence: &[u8]) -> NotificationAdmission {
                self.calls += 1;
                if self.fail_before < sequence.len() {
                    NotificationAdmission::Accepted(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "injected admission refusal",
                    )))
                } else {
                    self.bytes.extend_from_slice(sequence);
                    NotificationAdmission::Accepted(Ok(()))
                }
            }
        }

        let sequence = OSC777_APPROVAL_REQUIRED;
        for fail_before in 0..=sequence.len() {
            let mut transport = BoundaryAdmission {
                fail_before,
                bytes: Vec::new(),
                calls: 0,
            };
            let mut notifier = TerminalNotifier::with_settings(
                true,
                Protocol::Osc777,
                LONG_IDLE_AFTER,
                Instant::now(),
            );
            notifier.emit_transport(&mut transport, Trigger::ApprovalRequired(SubmissionId(1)));
            notifier.emit_transport(&mut transport, Trigger::ApprovalRequired(SubmissionId(1)));

            if fail_before < sequence.len() {
                assert!(transport.bytes.is_empty());
                assert_eq!(transport.calls, 1, "a refusal disables later attempts");
            } else {
                assert_eq!(transport.bytes, sequence);
                assert_eq!(
                    transport.calls, 1,
                    "the duplicate approval id is suppressed after success"
                );
            }
        }
    }

    #[test]
    fn ordinary_short_or_closed_writers_are_never_offered_an_osc_prefix() {
        struct BoundaryWriter {
            capacity: usize,
            offered: Vec<Vec<u8>>,
            bytes: Vec<u8>,
            closed: bool,
        }

        impl Write for BoundaryWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.offered.push(buffer.to_vec());
                if self.closed {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
                }
                let accepted = buffer.len().min(self.capacity);
                self.bytes.extend_from_slice(&buffer[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("notification transport must not flush independently")
            }
        }

        for boundary in 0..=OSC777_APPROVAL_REQUIRED.len() {
            let mut writer = BoundaryWriter {
                capacity: boundary,
                offered: Vec::new(),
                bytes: Vec::new(),
                closed: false,
            };
            let mut notifier = TerminalNotifier::with_settings(
                true,
                Protocol::Osc777,
                LONG_IDLE_AFTER,
                Instant::now(),
            );
            notifier.emit(&mut writer, Trigger::ApprovalRequired(SubmissionId(1)));
            assert_eq!(writer.offered, vec![TERMINAL_BELL.to_vec()]);
            assert!(writer.bytes.is_empty() || writer.bytes == TERMINAL_BELL);
            assert!(!writer.bytes.starts_with(b"\x1b]"));
        }

        let mut closed = BoundaryWriter {
            capacity: usize::MAX,
            offered: Vec::new(),
            bytes: Vec::new(),
            closed: true,
        };
        let mut notifier =
            TerminalNotifier::with_settings(true, Protocol::Osc9, LONG_IDLE_AFTER, Instant::now());
        notifier.emit(&mut closed, Trigger::RunComplete);
        notifier.emit(&mut closed, Trigger::LongIdle);
        assert_eq!(closed.offered, vec![TERMINAL_BELL.to_vec()]);
        assert!(closed.bytes.is_empty());
    }

    #[test]
    fn provider_turns_and_done_are_silent_until_one_authoritative_run_boundary() {
        let now = Instant::now();
        let mut notifier =
            TerminalNotifier::with_settings(true, Protocol::Bell, LONG_IDLE_AFTER, now);
        notifier.begin_run_at(now);
        let end = UiEvent::TurnEnd {
            cost: iteron_obs::CostState::default(),
            usage: iteron_protocol::Usage::default(),
            context: iteron_ctx::ContextEstimate {
                system_tokens: 0,
                tool_tokens: 0,
                conversation_tokens: 0,
                tool_result_tokens: 0,
                lsp_result_tokens: 0,
                transcript_tokens: 0,
                framing_tokens: 0,
                total_tokens: 0,
                provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
            },
            model_context_window: None,
            reserved_output_tokens: 0,
            compaction_trigger_tokens: 0,
            effort: iteron_provider::EffortApplication::Unsupported {
                requested: iteron_protocol::ReasoningEffort::Medium,
            },
        };

        assert_eq!(notifier.trigger_for_event_at(&end, now), None);
        assert_eq!(notifier.trigger_for_event_at(&end, now), None);
        assert_eq!(
            notifier.trigger_for_event_at(&UiEvent::Phase(iteron_protocol::Phase::Model), now,),
            None
        );
        assert_eq!(
            notifier.trigger_for_event_at(&UiEvent::Done("legacy presentation".into()), now),
            None
        );
        assert_eq!(notifier.run_completed(), Some(Trigger::RunComplete));
        assert_eq!(
            notifier.run_completed(),
            None,
            "a duplicate App Server terminal event cannot notify twice"
        );

        notifier.begin_run_at(now);
        assert_eq!(
            notifier.run_completed(),
            Some(Trigger::RunComplete),
            "an accepted follow-up owns a fresh run-complete boundary"
        );
    }

    #[test]
    fn long_idle_notifies_once_then_rearms_only_after_activity() {
        let start = Instant::now();
        let idle_after = Duration::from_secs(5);
        let mut notifier = TerminalNotifier::with_settings(true, Protocol::Bell, idle_after, start);
        notifier.begin_run_at(start);

        assert_eq!(notifier.poll_idle_at(true, start), None);
        assert_eq!(
            notifier.poll_idle_at(true, start + idle_after),
            Some(Trigger::LongIdle)
        );
        assert_eq!(
            notifier.poll_idle_at(true, start + idle_after + Duration::from_secs(60)),
            None
        );

        let activity = start + idle_after + Duration::from_secs(61);
        assert_eq!(
            notifier.trigger_for_event_at(&UiEvent::Text("fixed activity".into()), activity),
            None
        );
        assert_eq!(
            notifier.poll_idle_at(true, activity + idle_after),
            Some(Trigger::LongIdle)
        );
        assert_eq!(notifier.poll_idle_at(false, activity + idle_after), None);
        let next_run = activity + idle_after + Duration::from_secs(1);
        notifier.begin_run_at(next_run);
        assert_eq!(
            notifier.poll_idle_at(true, next_run),
            None,
            "a new run starts a fresh timer instead of inheriting old silence"
        );
    }
}
