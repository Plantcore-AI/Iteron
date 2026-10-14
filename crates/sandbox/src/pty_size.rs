//! The common finite window geometry admitted before either Unix PTY or Windows ConPTY.
use std::io;

/// The largest window dimension this crate will program into the kernel.
///
/// `struct winsize` is 16-bit, so the kernel itself would accept up to 65535 rows and columns. The
/// bound is a good deal smaller because a window is attacker-influenced input: a terminal size is
/// typically echoed back into a screen buffer whose cost is `rows * cols` cells, and 65535 squared
/// is a 4-gigacell allocation request. Refusing early keeps that product bounded.
pub const MAX_WINDOW_DIMENSION: u16 = 4096;

/// A validated terminal window size.
///
/// There is no `Default`: every pty in this crate is opened with a size the caller chose, because a
/// silently zero-sized window is the classic way a full-screen program renders nothing and reports
/// no error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowSize {
    rows: u16,
    cols: u16,
}

impl WindowSize {
    /// Validate a window size.
    ///
    /// Both dimensions must be non-zero and within [`MAX_WINDOW_DIMENSION`].
    pub fn new(rows: u16, cols: u16) -> io::Result<Self> {
        if rows == 0 || cols == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal window must have a non-zero row and column count",
            ));
        }
        if rows
            > iteron_tunables::param_integer(
                "sandbox.pty.max_window_dimension",
                MAX_WINDOW_DIMENSION,
            )
            || cols
                > iteron_tunables::param_integer(
                    "sandbox.pty.max_window_dimension",
                    MAX_WINDOW_DIMENSION,
                )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("terminal window exceeds the fixed {MAX_WINDOW_DIMENSION}-cell bound"),
            ));
        }
        Ok(Self { rows, cols })
    }

    pub fn rows(self) -> u16 {
        self.rows
    }

    pub fn cols(self) -> u16 {
        self.cols
    }

    #[cfg(unix)]
    pub(crate) fn to_winsize(self) -> libc::winsize {
        libc::winsize {
            ws_row: self.rows,
            ws_col: self.cols,
            // Pixel geometry is reported to the child as "unknown" rather than invented. Programs
            // that care (sixel, kitty graphics) query the terminal directly.
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}
