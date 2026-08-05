//! Pseudoterminal seam — shared vocabulary plus the Windows ConPTY backend.
//!
//! # Status of the two halves
//!
//! This module currently contains **only** the Windows half. There is no `#[cfg(unix)]`
//! pseudoterminal in this crate: no file in `crates/*/src/` calls `openpty`, `posix_openpt`,
//! `TIOCSWINSZ`, or `TIOCGWINSZ`. The only pseudoterminal code that exists anywhere in the
//! repository is test scaffolding under `crates/cli/tests/` (`tui_pty.rs`,
//! `workflow_interrupt_pty.rs`, `windows_conpty.rs`), which drives a pty through the
//! `portable-pty` **dev-dependency** in order to observe the production TUI from outside. That
//! is an oracle, not a backend.
//!
//! So the types below were written to be a good home for a future Unix backend, but they are
//! deliberately *not* an abstraction over one. Introducing a `Pty` trait with a single
//! implementation would be inventing a seam whose second side nobody has seen; the shape of the
//! Unix side (does it own the child? does it return a single master fd or a pair?) is exactly
//! what would determine that trait, and guessing it here would be the expensive kind of wrong.
//! What is shared is what genuinely does not depend on the platform: the size type, its
//! validation, the error taxonomy, argv quoting, and the teardown order.
//!
//! # Why ConPTY is not a port of a Unix pty
//!
//! | concern | Unix pty | Windows ConPTY |
//! |---|---|---|
//! | endpoints | one master fd, bidirectional | two *unidirectional anonymous pipes*, four handles |
//! | child attachment | `dup2` the slave fd onto 0/1/2 | `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` on an attribute list |
//! | hiding the master from the child | `FD_CLOEXEC` / `O_CLOEXEC` | handles are created **non-inheritable** and nothing is inherited at all |
//! | resize | `ioctl(TIOCSWINSZ)` | `ResizePseudoConsole(HPCON, COORD)` |
//! | dimension type | `winsize` fields are `unsigned short` (0..=65535) | `COORD` fields are `SHORT` (i16), and 0 is rejected |
//! | failing to drain | loses output | **deadlocks `ClosePseudoConsole`** |
//!
//! The last row is the one that actually changes the code. On Unix, "drain before you reap"
//! protects output. On Windows it protects liveness: `ClosePseudoConsole` blocks until the
//! pseudoconsole has flushed everything it still owes to the output pipe, and an anonymous pipe
//! whose read end nobody is servicing fills up and stays full. If teardown closes the
//! pseudoconsole while no reader is running, the closing thread parks forever. That is why
//! [`TEARDOWN_ORDER`] starts the drain first and why [`ConPty::close`] iterates that constant
//! rather than open-coding the sequence.

use std::fmt;

// ---------------------------------------------------------------------------
// Platform-independent core. Everything in this section is exercised by the
// unit tests at the bottom of this file on every host, including this one.
// ---------------------------------------------------------------------------

/// Smallest dimension a pseudoterminal window may have.
///
/// ConPTY rejects a zero dimension outright, so zero can never be a legal size here even though
/// a Unix `winsize` will happily hold it (where it conventionally means "unknown").
pub const PTY_MIN_DIMENSION: u16 = 1;

/// Largest dimension a pseudoterminal window may have.
///
/// `COORD` is a pair of `SHORT`, so the Windows ceiling is `i16::MAX`. Unix `winsize` would
/// allow up to `u16::MAX`. The shared type takes the **intersection** rather than the union: a
/// `PtySize` that validates here is representable on either platform, so a resize cannot succeed
/// on one host and silently overflow into a negative `COORD` on another.
pub const PTY_MAX_DIMENSION: u16 = i16::MAX as u16;

/// A pseudoterminal window size, in character cells.
///
/// Construct with [`PtySize::new`], which is the only way to get one; there are no public
/// fields, so an unvalidated size cannot reach a platform call.
///
/// **Argument order is `(cols, rows)`** — width first, matching `COORD`'s `(X, Y)`. Unix's
/// `struct winsize` declares `ws_row` before `ws_col`, so the two conventions disagree and a
/// transposed pair is the classic pseudoterminal bug: it is not a crash, just a terminal that
/// wraps in the wrong place. [`PtySize::to_coord_parts`] pins the mapping and
/// `cols_map_to_coord_x_and_rows_map_to_coord_y` is the regression test for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PtySize {
    cols: u16,
    rows: u16,
}

impl PtySize {
    /// Validate and build a size. `cols` is the width, `rows` is the height.
    pub fn new(cols: u16, rows: u16) -> Result<Self, PtyError> {
        check_dimension("cols", cols)?;
        check_dimension("rows", rows)?;
        Ok(Self { cols, rows })
    }

    /// Width in character cells.
    pub fn cols(self) -> u16 {
        self.cols
    }

    /// Height in character cells.
    pub fn rows(self) -> u16 {
        self.rows
    }

    /// The `(COORD.X, COORD.Y)` pair for this size: **X is columns, Y is rows**.
    ///
    /// Infallible by construction — [`PTY_MAX_DIMENSION`] is `i16::MAX`, so neither cast can
    /// wrap. The `debug_assert`s state that dependency rather than trusting it silently.
    pub fn to_coord_parts(self) -> (i16, i16) {
        debug_assert!(self.cols <= PTY_MAX_DIMENSION);
        debug_assert!(self.rows <= PTY_MAX_DIMENSION);
        (self.cols as i16, self.rows as i16)
    }
}

impl fmt::Display for PtySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{} (cols x rows)", self.cols, self.rows)
    }
}

fn check_dimension(field: &'static str, value: u16) -> Result<(), PtyError> {
    if (PTY_MIN_DIMENSION..=PTY_MAX_DIMENSION).contains(&value) {
        Ok(())
    } else {
        Err(PtyError::InvalidSize {
            field,
            value,
            min: PTY_MIN_DIMENSION,
            max: PTY_MAX_DIMENSION,
        })
    }
}

/// What can go wrong on the pseudoterminal seam.
///
/// The two operating-system variants are kept apart on purpose. `CreatePseudoConsole` and
/// `ResizePseudoConsole` return an `HRESULT` and do **not** set the thread's last-error value,
/// while `CreatePipe` / `CreateProcessW` / the attribute-list calls return `BOOL` and report
/// through `GetLastError`. Folding both into one integer would produce error text that cannot be
/// looked up, because the reader would not know which numbering they are holding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PtyError {
    #[error("pseudoterminal {field} must be within {min}..={max}; got {value}")]
    InvalidSize {
        field: &'static str,
        value: u16,
        min: u16,
        max: u16,
    },

    #[error(
        "no pseudoterminal backend is built for this target. Windows uses ConPTY \
         (`CreatePseudoConsole`, Windows 10 1809+); the Unix backend is not implemented in \
         core-sandbox. See docs/reference/platforms.md."
    )]
    Unsupported,

    /// A ConPTY entry point failed. `hr` is an `HRESULT`, printed the way the SDK prints it.
    #[error("{call} failed: HRESULT 0x{hr:08X}")]
    Hresult { call: &'static str, hr: i32 },

    /// A Win32 `BOOL`-returning call failed. `code` is a `GetLastError` value.
    #[error("{call} failed: Windows error {code}")]
    Os { call: &'static str, code: u32 },

    /// A command line could not be built because an argument was not representable.
    #[error("cannot build a command line: {0}")]
    Argv(String),

    /// The pseudoterminal was already torn down.
    #[error("pseudoterminal is closed")]
    Closed,
}

/// One step of ConPTY teardown.
///
/// Ordering here is a liveness property, not tidiness. See [`TEARDOWN_ORDER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TeardownStep {
    /// Begin servicing the output pipe on another thread.
    ///
    /// Must be first. Everything after this point can block on the pseudoconsole making
    /// progress, and the pseudoconsole cannot make progress once the output pipe is full.
    StartOutputDrain,
    /// Drop our write end of the input pipe, so the child reads EOF on stdin.
    CloseInputWrite,
    /// Wait (with a ceiling) for the child to exit.
    WaitForChild,
    /// `ClosePseudoConsole`. Blocks until the pseudoconsole has flushed its output.
    ClosePseudoConsole,
    /// Join the drain thread, which sees EOF once the pseudoconsole is gone.
    JoinOutputDrain,
    /// Drop our read end of the output pipe.
    CloseOutputRead,
}

/// The only correct ConPTY teardown order.
///
/// Two constraints make this order forced rather than stylistic:
///
/// 1. `StartOutputDrain` precedes `ClosePseudoConsole`. `ClosePseudoConsole` blocks until the
///    pseudoconsole has written out everything it owes. An anonymous pipe holds a bounded amount
///    (64 KiB by default) and then blocks its writer. With no reader running, the pseudoconsole
///    cannot finish, so the thread inside `ClosePseudoConsole` never returns. This is the
///    Windows form of the Unix drain-before-reap rule, promoted from "you lose the tail of the
///    output" to "you hang".
/// 2. `CloseInputWrite` precedes `WaitForChild`. A child blocked reading stdin will not exit
///    until it sees EOF, and it cannot see EOF while we still hold the write end.
///
/// `JoinOutputDrain` must follow `ClosePseudoConsole` for the symmetric reason: the drain reads
/// until EOF, and EOF on that pipe is produced by the pseudoconsole going away.
///
/// [`ConPty::close`] iterates this array instead of writing the calls out in sequence, so the
/// order that the unit tests below assert is the order that actually executes.
pub const TEARDOWN_ORDER: [TeardownStep; 6] = [
    TeardownStep::StartOutputDrain,
    TeardownStep::CloseInputWrite,
    TeardownStep::WaitForChild,
    TeardownStep::ClosePseudoConsole,
    TeardownStep::JoinOutputDrain,
    TeardownStep::CloseOutputRead,
];

/// Render an argument vector into a single command-line string using the parsing rules that
/// `CommandLineToArgvW` (and therefore the C runtime that most Windows programs start from)
/// applies in reverse.
///
/// `CreateProcessW` takes one flat string, not an argv, so the quoting has to happen on this
/// side. The algorithm is the standard one: a backslash is only an escape character when it
/// precedes a quote, so a run of backslashes is doubled if a quote follows it (either a quote in
/// the argument or the closing quote) and left alone otherwise.
///
/// This is pure string handling with no platform calls in it, which is the point — it is the
/// part of process spawning most likely to be subtly wrong, and it is fully testable on a Mac.
pub fn command_line_from_argv<S: AsRef<str>>(argv: &[S]) -> Result<String, PtyError> {
    if argv.is_empty() {
        return Err(PtyError::Argv("argv must not be empty".into()));
    }
    let mut line = String::new();
    for (index, argument) in argv.iter().enumerate() {
        let argument = argument.as_ref();
        if argument.contains('\0') {
            return Err(PtyError::Argv(format!(
                "argument {index} contains an interior NUL, which cannot cross the Win32 boundary"
            )));
        }
        if index > 0 {
            line.push(' ');
        }
        append_quoted_argument(&mut line, argument);
    }
    Ok(line)
}

fn append_quoted_argument(line: &mut String, argument: &str) {
    let needs_quoting = argument.is_empty()
        || argument
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '"'));
    if !needs_quoting {
        line.push_str(argument);
        return;
    }
    line.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                // A run of N backslashes before a quote becomes 2N backslashes (each escaping
                // itself) plus one more that escapes the quote: 2N + 1 in total. Emitting N + 1
                // here is the classic off-by-one — it round-trips for N = 0 and corrupts every
                // longer run.
                for _ in 0..(backslashes * 2 + 1) {
                    line.push('\\');
                }
                backslashes = 0;
                line.push('"');
            }
            _ => {
                for _ in 0..backslashes {
                    line.push('\\');
                }
                backslashes = 0;
                line.push(character);
            }
        }
    }
    // Backslashes immediately before the closing quote would otherwise escape it.
    for _ in 0..backslashes * 2 {
        line.push('\\');
    }
    line.push('"');
}

// ---------------------------------------------------------------------------
// Windows ConPTY backend.
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use windows_backend::{ConPty, PtyChild, PtyExit};

#[cfg(windows)]
mod windows_backend {
    use super::{PtyError, PtySize, TEARDOWN_ORDER, TeardownStep};
    use crate::BoundedCapture;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::time::{Duration, Instant};

    // -- Minimal Win32 surface -------------------------------------------------
    //
    // These are declared here rather than pulled from `windows-sys` on purpose. `core-sandbox`
    // has no Windows dependency today (`crates/sandbox/Cargo.toml` lists only a `cfg(unix)`
    // libc), and adding one would mean editing `Cargo.lock` for a graph that cannot be built or
    // checked on the machine this was written on. Hand-declaring twelve documented, stable C
    // signatures keeps the change to a single file and removes a whole class of "the crate moved
    // that symbol between minor versions" failure that would only surface on a Windows runner.
    // The bindings mirror the SDK headers exactly; `#[repr(C)]` gives the struct layout.

    // These mirror SDK layouts and are handed to foreign code wholesale. Several fields are
    // only ever written (or only read by Windows itself), so `dead_code` is suppressed on the
    // group rather than field by field.

    type Handle = *mut c_void;
    type Hpcon = *mut c_void;
    type Bool32 = i32;

    const FALSE: Bool32 = 0;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_FAILED: u32 = u32::MAX;

    /// `ProcThreadAttributeValue(ProcThreadAttributePseudoConsole=22, thread=FALSE, input=TRUE,
    /// additive=FALSE)` — the SDK computes this with a macro, so it is derived here the same way:
    /// `(22 & 0xFFFF) | PROC_THREAD_ATTRIBUTE_INPUT (0x0002_0000)`.
    const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 22 | 0x0002_0000;

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: Bool32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: Handle,
        h_std_output: Handle,
        h_std_error: Handle,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        lp_attribute_list: *mut c_void,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct ProcessInformation {
        h_process: Handle,
        h_thread: Handle,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePseudoConsole(
            size: Coord,
            h_input: Handle,
            h_output: Handle,
            dw_flags: u32,
            phpc: *mut Hpcon,
        ) -> i32;
        fn ResizePseudoConsole(hpc: Hpcon, size: Coord) -> i32;
        fn ClosePseudoConsole(hpc: Hpcon);
        fn CreatePipe(
            h_read: *mut Handle,
            h_write: *mut Handle,
            attributes: *const SecurityAttributes,
            size: u32,
        ) -> Bool32;
        fn GetLastError() -> u32;
        fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: u32,
            flags: u32,
            size: *mut usize,
        ) -> Bool32;
        fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *mut c_void,
            size: usize,
            previous: *mut c_void,
            return_size: *mut usize,
        ) -> Bool32;
        fn DeleteProcThreadAttributeList(list: *mut c_void);
        fn CreateProcessW(
            application_name: *const u16,
            command_line: *mut u16,
            process_attributes: *const SecurityAttributes,
            thread_attributes: *const SecurityAttributes,
            inherit_handles: Bool32,
            creation_flags: u32,
            environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *mut StartupInfoW,
            process_information: *mut ProcessInformation,
        ) -> Bool32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> Bool32;
        fn TerminateProcess(process: Handle, exit_code: u32) -> Bool32;
    }

    fn last_error(call: &'static str) -> PtyError {
        // SAFETY: `GetLastError` reads thread-local state and has no preconditions.
        PtyError::Os {
            call,
            code: unsafe { GetLastError() },
        }
    }

    fn hresult(call: &'static str, hr: i32) -> Result<(), PtyError> {
        if hr < 0 {
            Err(PtyError::Hresult { call, hr })
        } else {
            Ok(())
        }
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Build the `CREATE_UNICODE_ENVIRONMENT` block: `KEY=VALUE\0` repeated, then a final `\0`.
    ///
    /// A deliberately empty environment is `\0\0`, not `\0`: the block is a sequence of
    /// NUL-terminated strings terminated by an empty string, so it always ends in two NULs. With
    /// a single NUL, `CreateProcessW` reads past the end of the allocation looking for the
    /// terminator. Callers that want to *inherit* the environment pass `None` instead and get a
    /// null pointer, which is a different thing entirely.
    fn environment_block(pairs: &[(String, String)]) -> Vec<u16> {
        if pairs.is_empty() {
            return vec![0, 0];
        }
        let mut block = Vec::new();
        for (key, value) in pairs {
            block.extend(format!("{key}={value}").encode_utf16());
            block.push(0);
        }
        block.push(0);
        block
    }

    /// An anonymous pipe pair. Both ends are created **non-inheritable**, which is the ConPTY
    /// analogue of `O_CLOEXEC`: the child never receives these handles by inheritance, because
    /// the pseudoconsole attribute is what conveys the console to it. `CreateProcessW` is
    /// therefore called with `bInheritHandles = FALSE`, so no unrelated handle in this process
    /// can leak into the child either.
    fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), PtyError> {
        let attributes = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: std::ptr::null_mut(),
            b_inherit_handle: FALSE,
        };
        let mut read: Handle = std::ptr::null_mut();
        let mut write: Handle = std::ptr::null_mut();
        // SAFETY: both out-pointers address live locals and `attributes` outlives the call.
        let ok = unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) };
        if ok == FALSE {
            return Err(last_error("CreatePipe"));
        }
        // SAFETY: `CreatePipe` succeeded, so both handles are valid, owned, and unaliased.
        unsafe {
            Ok((
                OwnedHandle::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            ))
        }
    }

    /// How a child under a pseudoconsole finished.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PtyExit {
        pub code: u32,
        /// True when the wait ceiling elapsed and the child had to be terminated.
        pub timed_out: bool,
    }

    /// A process attached to a pseudoconsole.
    pub struct PtyChild {
        process: OwnedHandle,
        _thread: OwnedHandle,
        pub pid: u32,
    }

    impl PtyChild {
        /// Wait up to `timeout` for exit; terminate and reap if the ceiling elapses.
        ///
        /// Bounded on purpose, for the same reason `terminate_with_grace` in this crate's root
        /// is bounded: a hostile or wedged child must not be able to hold teardown open forever.
        pub fn wait_bounded(&mut self, timeout: Duration) -> Result<PtyExit, PtyError> {
            let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: `self.process` is a live process handle owned by this struct.
            let status = unsafe { WaitForSingleObject(self.process.as_raw_handle(), millis) };
            match status {
                WAIT_OBJECT_0 => Ok(PtyExit {
                    code: self.exit_code()?,
                    timed_out: false,
                }),
                WAIT_TIMEOUT => {
                    self.kill()?;
                    // Reap so the handle is not left signalling a running process.
                    // SAFETY: same live handle; a bounded second wait after TerminateProcess.
                    let _ = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 5_000) };
                    Ok(PtyExit {
                        code: self.exit_code().unwrap_or(1),
                        timed_out: true,
                    })
                }
                WAIT_FAILED => Err(last_error("WaitForSingleObject")),
                other => Err(PtyError::Os {
                    call: "WaitForSingleObject",
                    code: other,
                }),
            }
        }

        /// Force-terminate the child. Idempotent enough for teardown: terminating an already
        /// dead process fails, and that failure is not interesting here.
        pub fn kill(&mut self) -> Result<(), PtyError> {
            // SAFETY: `self.process` is a live handle for the duration of `self`.
            let ok = unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
            if ok == FALSE {
                return Err(last_error("TerminateProcess"));
            }
            Ok(())
        }

        fn exit_code(&self) -> Result<u32, PtyError> {
            let mut code = 0u32;
            // SAFETY: live handle; `code` is a live local.
            let ok = unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) };
            if ok == FALSE {
                return Err(last_error("GetExitCodeProcess"));
            }
            // 259 (`STILL_ACTIVE`) is also a legitimate exit code a process may return, so it is
            // only ambiguous while the process is actually running. Every caller reaches this
            // after a successful wait, so the value is reported as-is rather than guessed at.
            Ok(code)
        }
    }

    /// A Windows pseudoconsole and the two pipe ends this process keeps.
    ///
    /// `CreatePseudoConsole` receives the *read* end of the input pipe and the *write* end of the
    /// output pipe; it duplicates both, so this side drops its copies immediately after the call
    /// and keeps only the ends it will actually use. Leaving the handed-over copies open here is
    /// a common ConPTY bug: the child's stdin would never reach EOF, because this process would
    /// still be holding a writer alive.
    pub struct ConPty {
        hpc: Hpcon,
        input_write: Option<File>,
        output_read: Option<File>,
        size: PtySize,
    }

    // SAFETY: `Hpcon` is an opaque process-wide kernel handle, not a thread-affine resource.
    // `ConPty` owns it exclusively (no `Clone`, and `close`/`Drop` consume or run once), so
    // moving the value between threads cannot produce a second user of the same handle.
    unsafe impl Send for ConPty {}

    impl ConPty {
        /// Create a pseudoconsole of `size`.
        ///
        /// Requires Windows 10 1809 (build 17763) or newer; on older systems the loader fails to
        /// resolve `CreatePseudoConsole` from `kernel32`.
        pub fn open(size: PtySize) -> Result<Self, PtyError> {
            let (input_read, input_write) = anonymous_pipe()?;
            let (output_read, output_write) = anonymous_pipe()?;

            let (x, y) = size.to_coord_parts();
            let mut hpc: Hpcon = std::ptr::null_mut();
            // SAFETY: both handles are live for the call, and `hpc` is a live local out-pointer.
            let hr = unsafe {
                CreatePseudoConsole(
                    Coord { x, y },
                    input_read.as_raw_handle(),
                    output_write.as_raw_handle(),
                    0,
                    &mut hpc,
                )
            };
            hresult("CreatePseudoConsole", hr)?;

            // The pseudoconsole duplicated what it needed. Dropping these now is what lets the
            // child observe stdin EOF later and what lets the output pipe report EOF at all.
            drop(input_read);
            drop(output_write);

            Ok(Self {
                hpc,
                input_write: Some(File::from(input_write)),
                output_read: Some(File::from(output_read)),
                size,
            })
        }

        /// The size this pseudoconsole was last successfully set to.
        pub fn size(&self) -> PtySize {
            self.size
        }

        /// Resize the pseudoconsole.
        ///
        /// The cached size is updated only after the call succeeds, so a failed resize leaves
        /// [`ConPty::size`] reporting the size the console is actually still using.
        pub fn resize(&mut self, size: PtySize) -> Result<(), PtyError> {
            if self.hpc.is_null() {
                return Err(PtyError::Closed);
            }
            let (x, y) = size.to_coord_parts();
            // SAFETY: `self.hpc` is non-null and owned by `self`.
            let hr = unsafe { ResizePseudoConsole(self.hpc, Coord { x, y }) };
            hresult("ResizePseudoConsole", hr)?;
            self.size = size;
            Ok(())
        }

        /// The write end of the child's stdin.
        pub fn writer(&mut self) -> Result<&mut File, PtyError> {
            self.input_write.as_mut().ok_or(PtyError::Closed)
        }

        /// The read end of the child's stdout/stderr, as the pseudoconsole renders them.
        pub fn reader(&mut self) -> Result<&mut File, PtyError> {
            self.output_read.as_mut().ok_or(PtyError::Closed)
        }

        /// Launch `argv` attached to this pseudoconsole.
        ///
        /// The attachment is the `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` entry on an extended
        /// startup info block. Two rules are easy to get wrong and are both load-bearing here:
        ///
        /// * `STARTF_USESTDHANDLES` must **not** be set. The pseudoconsole supplies the child's
        ///   standard handles; setting the flag makes `CreateProcessW` prefer the (unset) fields
        ///   in `StartupInfoW` and the child ends up with no console at all.
        /// * The attribute list must stay alive and at a fixed address until `CreateProcessW`
        ///   returns, which is why it is a local `Vec` that is only dropped afterwards.
        pub fn spawn(
            &self,
            argv: &[String],
            cwd: Option<&str>,
            env: Option<&[(String, String)]>,
        ) -> Result<PtyChild, PtyError> {
            if self.hpc.is_null() {
                return Err(PtyError::Closed);
            }
            let mut command_line = wide_nul(&super::command_line_from_argv(argv)?);
            let cwd_wide = cwd.map(wide_nul);
            let mut env_block = env.map(environment_block);

            // Size the attribute list, then allocate it `usize`-aligned. A `Vec<u8>` would only
            // guarantee byte alignment, and the list holds pointers.
            //
            // The sizing call is *expected* to return FALSE with ERROR_INSUFFICIENT_BUFFER — that
            // is how the API reports the size — so its return value is deliberately ignored and
            // the out-parameter is what gets checked.
            let mut bytes = 0usize;
            // SAFETY: passing a null list is the documented way to ask for the required size;
            // `bytes` is a live local.
            unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes) };
            if bytes == 0 {
                return Err(last_error("InitializeProcThreadAttributeList"));
            }
            let words = bytes.div_ceil(std::mem::size_of::<usize>());
            let mut storage = vec![0usize; words];
            let list = storage.as_mut_ptr().cast::<c_void>();

            // SAFETY: `list` points at `words * size_of::<usize>() >= bytes` writable bytes.
            let ok = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) };
            if ok == FALSE {
                return Err(last_error("InitializeProcThreadAttributeList"));
            }

            // The attribute stores the HPCON *by value*; `cbSize` is the size of the handle, not
            // of anything it points at.
            // SAFETY: `list` is initialised above; `self.hpc` outlives this call.
            let ok = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    self.hpc,
                    std::mem::size_of::<Hpcon>(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ok == FALSE {
                let error = last_error("UpdateProcThreadAttribute");
                // SAFETY: the list was successfully initialised, so it must be deleted.
                unsafe { DeleteProcThreadAttributeList(list) };
                return Err(error);
            }

            let mut startup: StartupInfoExW = unsafe { std::mem::zeroed() };
            startup.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
            startup.lp_attribute_list = list;

            let mut info: ProcessInformation = unsafe { std::mem::zeroed() };
            // SAFETY: every pointer below addresses a live local that outlives the call.
            // `inherit_handles = FALSE` because the pseudoconsole attribute, not inheritance,
            // is what gives the child its console.
            let ok = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    FALSE,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    env_block
                        .as_mut()
                        .map(|block| block.as_mut_ptr().cast::<c_void>())
                        .unwrap_or(std::ptr::null_mut()),
                    cwd_wide
                        .as_ref()
                        .map(|path| path.as_ptr())
                        .unwrap_or(std::ptr::null()),
                    &mut startup.startup_info,
                    &mut info,
                )
            };
            let spawn_error = (ok == FALSE).then(|| last_error("CreateProcessW"));
            // SAFETY: initialised above and no longer referenced by anything live.
            unsafe { DeleteProcThreadAttributeList(list) };
            drop(storage);
            if let Some(error) = spawn_error {
                return Err(error);
            }

            // SAFETY: `CreateProcessW` succeeded, so both handles are valid and owned here.
            unsafe {
                Ok(PtyChild {
                    process: OwnedHandle::from_raw_handle(info.h_process),
                    _thread: OwnedHandle::from_raw_handle(info.h_thread),
                    pid: info.dw_process_id,
                })
            }
        }

        /// Tear the pseudoconsole down in [`TEARDOWN_ORDER`] and return what the child printed.
        ///
        /// The returned bytes are bounded by `limit` using the same `BoundedCapture` the sandbox
        /// uses for ordinary child output, so hitting the ceiling truncates the *retained* copy
        /// but never stops the drain — which here is a liveness requirement, not just a courtesy.
        /// The boolean is `true` when output was truncated.
        pub fn close(
            mut self,
            child: Option<&mut PtyChild>,
            wait: Duration,
            limit: usize,
        ) -> Result<(Vec<u8>, bool), PtyError> {
            let mut drain: Option<std::thread::JoinHandle<(Vec<u8>, bool)>> = None;
            let mut collected = (Vec::new(), false);
            let mut child = child;
            let deadline = Instant::now() + wait;

            for step in TEARDOWN_ORDER {
                match step {
                    TeardownStep::StartOutputDrain => {
                        if let Some(mut reader) = self.output_read.take() {
                            drain = Some(std::thread::spawn(move || {
                                let mut capture = BoundedCapture::with_limit(limit);
                                let mut chunk = [0u8; 8 * 1024];
                                loop {
                                    match reader.read(&mut chunk) {
                                        Ok(0) | Err(_) => break,
                                        Ok(read) => capture.push(&chunk[..read], limit),
                                    }
                                }
                                (capture.bytes, capture.truncated)
                            }));
                        }
                    }
                    TeardownStep::CloseInputWrite => {
                        drop(self.input_write.take());
                    }
                    TeardownStep::WaitForChild => {
                        if let Some(child) = child.as_deref_mut() {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            let _ = child.wait_bounded(remaining)?;
                        }
                    }
                    TeardownStep::ClosePseudoConsole => {
                        if !self.hpc.is_null() {
                            // SAFETY: non-null and owned; the drain thread started at the top of
                            // this loop is servicing the output pipe, which is what allows this
                            // call to return rather than block forever.
                            unsafe { ClosePseudoConsole(self.hpc) };
                            self.hpc = std::ptr::null_mut();
                        }
                    }
                    TeardownStep::JoinOutputDrain => {
                        if let Some(handle) = drain.take() {
                            collected = handle.join().unwrap_or((Vec::new(), false));
                        }
                    }
                    TeardownStep::CloseOutputRead => {
                        // The drain thread owned and dropped the reader; this is the explicit
                        // no-op that keeps the executed sequence aligned with TEARDOWN_ORDER.
                        debug_assert!(self.output_read.is_none());
                    }
                }
            }
            Ok(collected)
        }
    }

    impl Drop for ConPty {
        /// Best-effort teardown for the path where `close` was never called.
        ///
        /// This drops the read end *before* `ClosePseudoConsole`, which is the opposite of
        /// [`TEARDOWN_ORDER`] and deliberately so: with no drain thread available from a `Drop`
        /// that must not block, breaking the pipe is what stops `ClosePseudoConsole` from
        /// hanging. `ERROR_BROKEN_PIPE` unblocks the pseudoconsole's writer at the cost of any
        /// output still in flight. Callers that want the output must use
        /// [`ConPty::close`]; this exists so a leaked `ConPty` cannot wedge the process.
        fn drop(&mut self) {
            drop(self.input_write.take());
            drop(self.output_read.take());
            if !self.hpc.is_null() {
                // SAFETY: non-null and owned; both pipe ends are already closed above.
                unsafe { ClosePseudoConsole(self.hpc) };
                self.hpc = std::ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
#[path = "pty_tests.rs"]
mod pty_tests;
