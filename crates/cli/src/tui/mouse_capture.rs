use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use std::io::{self, Write};

/// Whether terminal mouse events belong to Core or to the terminal's native selection UI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    Captured,
    Released,
}

impl State {
    pub(super) fn is_captured(self) -> bool {
        self == Self::Captured
    }

    pub(super) fn status_label(self) -> &'static str {
        match self {
            Self::Captured => "mouse:on",
            Self::Released => "selection:on",
        }
    }

    pub(super) fn hint(self) -> &'static str {
        match self {
            Self::Captured => "ctrl+t select",
            Self::Released => "ctrl+t mouse",
        }
    }

    fn toggled(self) -> Self {
        match self {
            Self::Captured => Self::Released,
            Self::Released => Self::Captured,
        }
    }

    fn write_to(self, writer: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Captured => execute!(writer, EnableMouseCapture),
            Self::Released => execute!(writer, DisableMouseCapture),
        }
    }
}

pub(super) fn release(writer: &mut impl Write) -> io::Result<()> {
    State::Released.write_to(writer)
}

/// Owns the live terminal mouse mode. State changes commit only after their escape sequence was
/// written successfully, and unwind always attempts to release capture.
pub(super) struct Controller<W: Write> {
    writer: W,
    state: State,
}

impl<W: Write> Controller<W> {
    pub(super) fn capture(mut writer: W) -> io::Result<Self> {
        State::Captured.write_to(&mut writer)?;
        Ok(Self {
            writer,
            state: State::Captured,
        })
    }

    pub(super) fn toggle(&mut self) -> io::Result<State> {
        let next = self.state.toggled();
        next.write_to(&mut self.writer)?;
        self.state = next;
        Ok(next)
    }

    pub(super) fn state(&self) -> State {
        self.state
    }

    pub(super) fn set(&mut self, state: State) -> io::Result<State> {
        state.write_to(&mut self.writer)?;
        self.state = state;
        Ok(state)
    }

    /// Emit disable even when the tracked state is already released. Teardown must repair a
    /// terminal whose mode drifted independently of our in-memory projection.
    pub(super) fn release(&mut self) -> io::Result<()> {
        release(&mut self.writer)?;
        self.state = State::Released;
        Ok(())
    }
}

impl<W: Write> Drop for Controller<W> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
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

    #[test]
    fn toggle_commits_protocol_mode_and_exposes_truthful_labels() {
        let sink = SharedWriter::default();
        let bytes = sink.0.clone();
        let mut controller = Controller::capture(sink).unwrap();

        assert_eq!(controller.toggle().unwrap(), State::Released);
        assert_eq!(State::Released.status_label(), "selection:on");
        assert_eq!(controller.toggle().unwrap(), State::Captured);
        assert_eq!(State::Captured.hint(), "ctrl+t select");

        drop(controller);
        let output = bytes.lock().unwrap().clone();
        let mut disable = Vec::new();
        State::Released.write_to(&mut disable).unwrap();
        assert!(
            output.ends_with(&disable),
            "drop must release mouse capture"
        );
    }

    #[test]
    fn panic_unwind_releases_mouse_capture() {
        for release_before_panic in [false, true] {
            let sink = SharedWriter::default();
            let bytes = sink.0.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut controller = Controller::capture(sink).unwrap();
                if release_before_panic {
                    assert_eq!(controller.toggle().unwrap(), State::Released);
                }
                let _controller = controller;
                panic!("exercise mouse-capture unwind");
            }));

            assert!(result.is_err());
            let output = bytes.lock().unwrap().clone();
            let mut disable = Vec::new();
            State::Released.write_to(&mut disable).unwrap();
            assert!(
                output.ends_with(&disable),
                "panic unwind must leave native selection enabled"
            );
        }
    }
}
