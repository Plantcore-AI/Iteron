//! Explicit ownership of mouse input inside the full-screen TUI.
//!
//! Core captures the mouse by default so wheel/trackpad events scroll the current session's
//! transcript instead of the terminal emulator's older scrollback. Ctrl-T releases capture for
//! native drag selection and toggles it back without leaving the alternate screen.

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use std::io::{self, Write};

/// Whether mouse events belong to Core or to the terminal's native selection UI.
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
            Self::Captured => "mouse:on · wheel:transcript",
            Self::Released => "selection:on",
        }
    }

    pub(super) fn hint(self) -> &'static str {
        match self {
            Self::Captured => "ctrl+t selection",
            Self::Released => "ctrl+t app mouse",
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

pub(super) struct Controller<W: Write> {
    writer: W,
    state: State,
}

impl<W: Write> Controller<W> {
    pub(super) fn capture_to_terminal(mut writer: W) -> io::Result<Self> {
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

    /// Emit disable even when no in-memory transition occurred. Teardown must repair a terminal
    /// whose mode drifted independently of Core.
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
    fn controller_captures_by_default_toggles_and_releases_on_drop() {
        let sink = SharedWriter::default();
        let bytes = sink.0.clone();
        let mut controller = Controller::capture_to_terminal(sink).unwrap();
        assert_eq!(controller.state(), State::Captured);
        let mut enable = Vec::new();
        State::Captured.write_to(&mut enable).unwrap();
        assert!(bytes.lock().unwrap().ends_with(&enable));

        let mut disable = Vec::new();
        release(&mut disable).unwrap();
        assert_eq!(controller.toggle().unwrap(), State::Released);
        assert!(bytes.lock().unwrap().ends_with(&disable));
        assert_eq!(controller.toggle().unwrap(), State::Captured);
        assert_eq!(State::Captured.hint(), "ctrl+t selection");

        drop(controller);
        assert!(bytes.lock().unwrap().ends_with(&disable));
    }

    #[test]
    fn panic_unwind_leaves_native_selection_enabled() {
        let sink = SharedWriter::default();
        let bytes = sink.0.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _controller = Controller::capture_to_terminal(sink).unwrap();
            panic!("exercise mouse-capture unwind");
        }));

        assert!(result.is_err());
        let mut disable = Vec::new();
        release(&mut disable).unwrap();
        assert!(bytes.lock().unwrap().ends_with(&disable));
    }
}
