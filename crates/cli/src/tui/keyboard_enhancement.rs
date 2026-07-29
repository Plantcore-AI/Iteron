use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// One Kitty keyboard-protocol stack frame owned by the TUI.
///
/// The state mutex is also the terminal-I/O gate: no signal or unwind path can observe `Active`
/// before the complete Push write+flush succeeds, or emit Pop while Push is still in flight.
#[derive(Clone, Debug, Default)]
pub(crate) struct Restorer {
    shared: Arc<Shared>,
}

#[derive(Debug, Default)]
pub(crate) struct Controller {
    restorer: Restorer,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    #[default]
    Inactive,
    /// A teardown path won the gate before negotiation. No later Push may cross that boundary.
    Closed,
    Pushing,
    Active,
    Popping,
    /// A write, flush, or panic made terminal ownership unknowable. Never issue another Pop: the
    /// prior attempt may already have completed and a retry could pop an outer application's frame.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreOutcome {
    AlreadyInactive,
    Restored,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PanicRestoreOutcome {
    Completed,
    /// The current thread may itself be panicking inside Push/Pop. Blocking on the gate here would
    /// self-deadlock before unwinding can release it, so normal Drop performs conservative cleanup.
    /// Core's release profile retains Rust's default `panic = "unwind"`; downstream abort builds
    /// cannot provide post-hook Drop cleanup for an in-flight, indeterminate terminal write.
    Deferred,
}

impl Controller {
    pub(crate) fn restorer(&self) -> Restorer {
        self.restorer.clone()
    }

    /// Ask the terminal whether it implements progressive keyboard enhancement and, only when it
    /// answers positively, push the smallest flag set that disambiguates modified keys.
    ///
    /// A missing/unsupported query is a normal fallback, not a TUI startup failure. Once support is
    /// known, however, a failed push is returned and permanently becomes indeterminate: issuing a
    /// Pop without proof that Push completed could corrupt an outer application's stack frame.
    pub(crate) fn negotiate(&self, supported: bool) -> io::Result<bool> {
        let mut stdout = io::stdout();
        self.negotiate_with(&mut stdout, supported)
    }

    pub(super) fn negotiate_with(
        &self,
        writer: &mut impl Write,
        supported: bool,
    ) -> io::Result<bool> {
        let mut state = self.restorer.lock_state();
        match *state {
            State::Active => return Ok(true),
            State::Inactive if !supported => return Ok(false),
            State::Inactive => {}
            State::Closed => return Err(io::Error::other("terminal teardown already started")),
            State::Pushing | State::Popping | State::Unknown => {
                *state = State::Unknown;
                return Err(indeterminate_state_error());
            }
        }

        *state = State::Pushing;
        let result = execute!(
            writer,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
        );
        match result {
            Ok(()) => {
                *state = State::Active;
                Ok(true)
            }
            Err(error) => {
                *state = State::Unknown;
                Err(error)
            }
        }
    }
}

impl Restorer {
    /// Pop exactly the stack frame Core verifiably pushed.
    ///
    /// Any Pop error becomes `Unknown` and is never retried. The error cannot reveal whether the
    /// terminal accepted the complete sequence, so retrying could pop somebody else's frame.
    pub(crate) fn restore(&self, writer: &mut impl Write) -> io::Result<RestoreOutcome> {
        let mut state = self.lock_state();
        restore_locked(&mut state, writer)
    }

    /// Panic hooks run before stack unwinding. Never block when Push/Pop owns the gate: on a
    /// same-thread writer panic that would deadlock forever. Drop retries only the state decision
    /// after unwinding; an in-flight/poisoned transition becomes `Unknown` and emits no blind Pop.
    pub(crate) fn restore_after_panic(
        &self,
        writer: &mut impl Write,
    ) -> io::Result<PanicRestoreOutcome> {
        let mut state = match self.shared.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return Ok(PanicRestoreOutcome::Deferred),
        };
        restore_locked(&mut state, writer).map(|_| PanicRestoreOutcome::Completed)
    }

    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn state(&self) -> State {
        *self.lock_state()
    }
}

fn restore_locked(state: &mut State, writer: &mut impl Write) -> io::Result<RestoreOutcome> {
    match *state {
        State::Inactive => {
            *state = State::Closed;
            return Ok(RestoreOutcome::AlreadyInactive);
        }
        State::Closed => return Ok(RestoreOutcome::AlreadyInactive),
        State::Unknown | State::Pushing | State::Popping => {
            *state = State::Unknown;
            return Ok(RestoreOutcome::Indeterminate);
        }
        State::Active => {}
    }

    *state = State::Popping;
    match execute!(writer, PopKeyboardEnhancementFlags) {
        Ok(()) => {
            *state = State::Closed;
            Ok(RestoreOutcome::Restored)
        }
        Err(error) => {
            *state = State::Unknown;
            Err(error)
        }
    }
}

fn indeterminate_state_error() -> io::Error {
    io::Error::other("keyboard enhancement terminal state is indeterminate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    const PUSH: &[u8] = b"\x1b[>1u";
    const POP: &[u8] = b"\x1b[<1u";

    #[derive(Debug, Default)]
    struct FaultWriter {
        bytes: Vec<u8>,
        fail_after: Option<usize>,
        fail_flush: bool,
    }

    impl FaultWriter {
        fn fail_after_more(&mut self, bytes: usize) {
            self.fail_after = Some(self.bytes.len() + bytes);
        }

        fn recover(&mut self) {
            self.fail_after = None;
            self.fail_flush = false;
        }
    }

    impl Write for FaultWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(limit) = self.fail_after {
                if self.bytes.len() >= limit {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected write"));
                }
                let writable = (limit - self.bytes.len()).min(bytes.len());
                self.bytes.extend_from_slice(&bytes[..writable]);
                return Ok(writable);
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected flush"))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BarrierWriter {
        output: SharedWriter,
        entered: Option<mpsc::Sender<()>>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Write for BarrierWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                let (released, wake) = &*self.release;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
            }
            self.output.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.output.flush()
        }
    }

    #[test]
    fn unsupported_terminal_emits_no_stack_commands() {
        let controller = Controller::default();
        let mut output = Vec::new();

        assert!(!controller.negotiate_with(&mut output, false).unwrap());
        assert_eq!(
            controller.restorer().restore(&mut output).unwrap(),
            RestoreOutcome::AlreadyInactive
        );
        assert!(output.is_empty());
    }

    #[test]
    fn supported_terminal_pushes_and_restores_exactly_once() {
        let controller = Controller::default();
        let mut output = Vec::new();

        assert!(controller.negotiate_with(&mut output, true).unwrap());
        assert!(controller.negotiate_with(&mut output, true).unwrap());
        assert_eq!(output, PUSH);
        assert_eq!(
            controller.restorer().restore(&mut output).unwrap(),
            RestoreOutcome::Restored
        );
        assert_eq!(
            controller.restorer().restore(&mut output).unwrap(),
            RestoreOutcome::AlreadyInactive
        );
        assert_eq!(output, [PUSH, POP].concat());
    }

    #[test]
    fn zero_byte_partial_and_flush_failed_push_never_blind_pop() {
        for written in 0..PUSH.len() {
            let controller = Controller::default();
            let mut writer = FaultWriter::default();
            writer.fail_after_more(written);

            assert!(controller.negotiate_with(&mut writer, true).is_err());
            assert_eq!(controller.restorer().state(), State::Unknown);
            let before_restore = writer.bytes.clone();
            writer.recover();
            assert_eq!(
                controller.restorer().restore(&mut writer).unwrap(),
                RestoreOutcome::Indeterminate
            );
            assert_eq!(
                writer.bytes, before_restore,
                "blind Pop after {written} bytes"
            );
        }

        let controller = Controller::default();
        let mut writer = FaultWriter {
            fail_flush: true,
            ..FaultWriter::default()
        };
        assert!(controller.negotiate_with(&mut writer, true).is_err());
        assert_eq!(
            writer.bytes, PUSH,
            "flush failure happens after queueing Push"
        );
        writer.recover();
        assert_eq!(
            controller.restorer().restore(&mut writer).unwrap(),
            RestoreOutcome::Indeterminate
        );
        assert_eq!(
            writer.bytes, PUSH,
            "flush failure must not trigger blind Pop"
        );
    }

    #[test]
    fn failed_pop_becomes_unknown_and_is_never_retried() {
        for written in 0..POP.len() {
            let controller = Controller::default();
            let mut writer = FaultWriter::default();
            controller.negotiate_with(&mut writer, true).unwrap();
            writer.fail_after_more(written);

            assert!(controller.restorer().restore(&mut writer).is_err());
            assert_eq!(controller.restorer().state(), State::Unknown);
            let after_first_attempt = writer.bytes.clone();
            writer.recover();
            assert_eq!(
                controller.restorer().restore(&mut writer).unwrap(),
                RestoreOutcome::Indeterminate
            );
            assert_eq!(
                writer.bytes, after_first_attempt,
                "Pop retry after {written} bytes could remove an outer frame"
            );
        }

        let controller = Controller::default();
        let mut writer = FaultWriter::default();
        controller.negotiate_with(&mut writer, true).unwrap();
        writer.fail_flush = true;
        assert!(controller.restorer().restore(&mut writer).is_err());
        assert_eq!(writer.bytes, [PUSH, POP].concat());
        writer.recover();
        assert_eq!(
            controller.restorer().restore(&mut writer).unwrap(),
            RestoreOutcome::Indeterminate
        );
        assert_eq!(
            writer.bytes,
            [PUSH, POP].concat(),
            "flush-unknown Pop must not be emitted twice"
        );
    }

    #[test]
    fn signal_style_restore_waits_until_push_terminalizes() {
        let controller = Arc::new(Controller::default());
        let restorer = controller.restorer();
        let output = SharedWriter::default();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (push_entered_tx, push_entered_rx) = mpsc::channel();
        let mut push_writer = BarrierWriter {
            output: output.clone(),
            entered: Some(push_entered_tx),
            release: Arc::clone(&release),
        };
        let push_controller = Arc::clone(&controller);
        let push = thread::spawn(move || push_controller.negotiate_with(&mut push_writer, true));
        push_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Push reached the deterministic write barrier");

        let (restore_started_tx, restore_started_rx) = mpsc::channel();
        let (restore_done_tx, restore_done_rx) = mpsc::channel();
        let mut restore_writer = output.clone();
        let restore = thread::spawn(move || {
            restore_started_tx.send(()).unwrap();
            let result = restorer.restore(&mut restore_writer);
            restore_done_tx.send(result).unwrap();
        });
        restore_started_rx.recv().unwrap();
        let early_restore = restore_done_rx.recv_timeout(Duration::from_millis(100));
        let restore_waited_for_push = matches!(&early_restore, Err(RecvTimeoutError::Timeout));

        let (released, wake) = &*release;
        *released.lock().unwrap() = true;
        wake.notify_all();
        assert!(push.join().unwrap().unwrap());
        let restore_result = match early_restore {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => restore_done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("restore completes after Push"),
            Err(RecvTimeoutError::Disconnected) => panic!("restore result channel disconnected"),
        };
        restore.join().unwrap();

        assert!(
            restore_waited_for_push,
            "restore completed while Push still held the shared I/O gate"
        );
        assert_eq!(restore_result.unwrap(), RestoreOutcome::Restored);
        assert_eq!(*output.0.lock().unwrap(), [PUSH, POP].concat());
    }

    #[test]
    fn teardown_that_wins_the_gate_permanently_prevents_late_push() {
        let controller = Controller::default();
        let mut output = Vec::new();
        assert_eq!(
            controller.restorer().restore(&mut output).unwrap(),
            RestoreOutcome::AlreadyInactive
        );
        assert!(controller.negotiate_with(&mut output, true).is_err());
        assert!(
            output.is_empty(),
            "Push crossed the terminal teardown boundary"
        );
    }

    #[test]
    fn panic_probe_does_not_self_lock_inside_pushing_writer() {
        struct PanicWriter {
            restorer: Restorer,
            observed: Arc<Mutex<Option<PanicRestoreOutcome>>>,
        }
        impl Write for PanicWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                let mut panic_output = Vec::new();
                let outcome = self
                    .restorer
                    .restore_after_panic(&mut panic_output)
                    .unwrap();
                assert!(panic_output.is_empty());
                *self.observed.lock().unwrap() = Some(outcome);
                panic!("injected writer panic while Pushing");
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let controller = Controller::default();
        let observed = Arc::new(Mutex::new(None));
        let mut writer = PanicWriter {
            restorer: controller.restorer(),
            observed: Arc::clone(&observed),
        };
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _ = controller.negotiate_with(&mut writer, true);
        }));
        assert!(unwind.is_err());
        assert_eq!(
            *observed.lock().unwrap(),
            Some(PanicRestoreOutcome::Deferred)
        );

        let mut cleanup = Vec::new();
        assert_eq!(
            controller.restorer().restore(&mut cleanup).unwrap(),
            RestoreOutcome::Indeterminate
        );
        assert!(
            cleanup.is_empty(),
            "poisoned Pushing state must not blind Pop"
        );
    }
}
