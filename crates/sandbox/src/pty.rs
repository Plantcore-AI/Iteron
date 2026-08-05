//! Kernel pseudo-terminal allocation for confined child processes.
//!
//! [`crate::spawn_confined_process`] deliberately wires a persistent child to bounded pipes
//! (`persistent.rs`), which is why the process tools advertise `TERM=dumb` and refuse resize. This
//! module owns the missing half: a real kernel pty pair, its window size, and the exact child-side
//! step that turns the slave into a *controlling* terminal.
//!
//! It is deliberately transport-only. Allocating a pty grants no confinement by itself, so nothing
//! here spawns a process or relaxes a sandbox decision; a caller still has to obtain a child
//! through a backend that confines it. Keeping the two separable is what lets the pty half be
//! tested on every unix while the confinement half stays platform-gated.
//!
//! Two invariants are load-bearing and are enforced here rather than left to callers:
//!
//! * **Both descriptors are close-on-exec.** A pty master leaked into a confined child would hand
//!   that child a writable handle to its own terminal, letting it forge output that the controller
//!   attributes to the program it launched. The slave reaches the child only through the explicit
//!   `dup2` that [`make_controlling_terminal`] performs after fork, never by inheritance.
//! * **The parent must drop its slave copy** once the child holds one. That is necessary but not
//!   sufficient for end-of-input, which is not portable at all: see [`PtyPair::into_master`] for
//!   what Linux and macOS actually do and why a supervisor must key off child exit instead.
//!   [`PtyPair::into_master`] is the closing move that makes dropping the slave hard to forget.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

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
        if rows > MAX_WINDOW_DIMENSION || cols > MAX_WINDOW_DIMENSION {
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

    fn to_winsize(self) -> libc::winsize {
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

/// An open pty master together with the slave the parent has not yet handed to a child.
///
/// Dropping the pair closes both ends.
pub struct PtyPair {
    master: File,
    slave: File,
    slave_name: PathBuf,
}

impl PtyPair {
    /// Allocate a pty pair and program its window size.
    ///
    /// The sequence is the POSIX one: `posix_openpt`, `grantpt`, `unlockpt`, resolve the slave
    /// name, then open the slave. `O_NOCTTY` is set on both ends so that merely allocating a pty
    /// never makes it *this* process's controlling terminal — acquiring it is an explicit,
    /// child-side act performed by [`make_controlling_terminal`].
    pub fn open(size: WindowSize) -> io::Result<Self> {
        // SAFETY: `posix_openpt` only opens a new descriptor; the result is checked below and is
        // adopted by an `OwnedFd` before any fallible step can leak it.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `master` is a fresh, exclusively owned descriptor returned by `posix_openpt`.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        // `posix_openpt` has no portable `O_CLOEXEC`, so the flag is set immediately afterwards.
        // The window between the two calls is safe because a descriptor can only be inherited by a
        // `fork` this thread has not performed yet.
        set_close_on_exec(master.as_raw_fd())?;

        // SAFETY: `master` is an open pty master. `grantpt` fixes the slave's ownership and mode
        // and `unlockpt` clears the lock that makes opening the slave fail; neither touches memory
        // owned by this process.
        if unsafe { libc::grantpt(master.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: see above; `master` is still open and exclusively owned here.
        if unsafe { libc::unlockpt(master.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let slave_name = slave_name_of(master.as_raw_fd())?;
        let slave = open_slave(&slave_name)?;

        let pair = Self {
            master: File::from(master),
            slave,
            slave_name,
        };
        pair.resize(size)?;
        Ok(pair)
    }

    /// The master end. Reads observe everything the child writes to the terminal; writes are
    /// delivered to the child as terminal input.
    pub fn master(&self) -> &File {
        &self.master
    }

    /// The parent's copy of the slave end.
    pub fn slave(&self) -> &File {
        &self.slave
    }

    /// The `/dev` path of the slave, for diagnostics and for a child that reopens it by name.
    pub fn slave_name(&self) -> &Path {
        &self.slave_name
    }

    /// Duplicate the slave so it can be installed as a child's stdin, stdout, and stderr.
    ///
    /// The duplicate is close-on-exec like its original: a child receives it only through the
    /// deliberate `dup2` in [`make_controlling_terminal`], never by silent inheritance.
    pub fn try_clone_slave(&self) -> io::Result<File> {
        let clone = self.slave.try_clone()?;
        set_close_on_exec(clone.as_raw_fd())?;
        Ok(clone)
    }

    /// Read the window size back out of the kernel through the **slave**.
    ///
    /// Deliberately not a cached copy of what [`Self::resize`] was told, and deliberately read from
    /// the end the child will use: this is the size a program running on the pty actually observes.
    pub fn window_size(&self) -> io::Result<WindowSize> {
        // SAFETY: `TIOCGWINSZ` writes one `winsize` through the pointer. The descriptor is an open
        // terminal owned by `self` and the destination is a live, correctly typed local.
        let size = unsafe {
            let mut raw: libc::winsize = std::mem::zeroed();
            if libc::ioctl(self.slave.as_raw_fd(), libc::TIOCGWINSZ as _, &mut raw) < 0 {
                return Err(io::Error::last_os_error());
            }
            raw
        };
        WindowSize::new(size.ws_row, size.ws_col)
    }

    /// Program a new window size and let the kernel raise `SIGWINCH` on the foreground group.
    ///
    /// This is the operation the pipe backend cannot offer at all, which is why a persistent job on
    /// pipes has to advertise resize as unavailable.
    pub fn resize(&self, size: WindowSize) -> io::Result<()> {
        let raw = size.to_winsize();
        // SAFETY: `TIOCSWINSZ` reads one `winsize` through the pointer. The descriptor is an open
        // terminal owned by `self` and `raw` is a live, correctly typed local.
        if unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &raw) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Give up the parent's slave copy and keep the master.
    ///
    /// Call this once a child owns its own slave: until every parent-side copy is closed, the pty
    /// still has a writer, so the master cannot even in principle report that output has ended.
    ///
    /// Closing them is necessary but **not** sufficient, and the difference is a portability trap
    /// worth stating plainly. Once the last slave closes, Linux fails subsequent master reads with
    /// `EIO`, which is a usable end-of-input signal. macOS does not: a master read simply blocks,
    /// and it was measured blocking indefinitely here after the child had exited and every slave
    /// descriptor was closed. A supervisor therefore must not treat "the master went quiet" as
    /// termination on any platform — child exit status is the authority, exactly as
    /// `persistent.rs` already treats it for pipes, and reads must carry their own deadline.
    pub fn into_master(self) -> File {
        self.master
    }
}

/// Make `slave` the calling process's controlling terminal.
///
/// The three steps are inseparable and ordered. `setsid` starts a new session, because a process
/// that is already a session member cannot acquire a different controlling terminal — and it must
/// not already be a process-group leader, which is exactly why this has to run in a fresh child.
/// `TIOCSCTTY` then attaches the terminal to that new session, which is what makes `/dev/tty`
/// resolve and job control work. Only then is the slave installed as the standard streams, so a
/// failure cannot leave a child running with a terminal it does not own.
///
/// The slave duplicates onto descriptors 0, 1, and 2 lose close-on-exec, which is the point: those
/// three are what the executed program inherits. The original `slave` descriptor keeps the flag and
/// disappears at `exec`.
///
/// Calling this is sufficient everywhere but it is not *necessary* everywhere, and a caller
/// reasoning about confinement should know the difference. On Linux, `TIOCSCTTY` is the only way to
/// get a controlling terminal, so a child that never calls this never has one. macOS follows the
/// older BSD rule instead: a session leader that execs with a terminal already on its descriptors
/// acquires it regardless. That was measured here on darwin 25.3 — `setsid` plus `dup2` plus exec,
/// with no `TIOCSCTTY` anywhere, still produced a working `/dev/tty`. So "the child was not given a
/// controlling terminal" is not a portable property, and anything that depends on a child *lacking*
/// job control must enforce it some other way than by declining to call this function.
///
/// # Safety
///
/// This must run in a freshly forked child, before `exec`, and nowhere else — as the body of a
/// `pre_exec` closure. It calls only async-signal-safe functions, and it changes the caller's
/// session, so running it on a live thread of a multi-threaded process would detach that process
/// from its own terminal.
pub unsafe fn make_controlling_terminal(slave: RawFd) -> io::Result<()> {
    // SAFETY: the contract above restricts this to a post-fork, pre-exec child, where the caller is
    // single-threaded and is not yet a process-group leader.
    unsafe {
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        // The third argument is the "steal from another session" flag; 0 refuses to steal, so this
        // can only ever claim a terminal that no other session controls.
        if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            if libc::dup2(slave, target) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn set_close_on_exec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor owned by the caller. `F_SETFD` only replaces the
    // descriptor flags and reads no memory through a pointer.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn open_slave(name: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt as _;

    let c_name = std::ffi::CString::new(name.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pty slave name contains NUL"))?;
    // SAFETY: `c_name` is a live NUL-terminated C string for the duration of the call, and the
    // returned descriptor is checked and adopted by an `OwnedFd` before anything else can fail.
    let fd = unsafe {
        libc::open(
            c_name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, exclusively owned descriptor just returned by `open`.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Resolve the slave device name for an unlocked master.
///
/// `ptsname` is used rather than the per-platform ioctls (`TIOCGPTN` on Linux, `TIOCPTYGNAME` on
/// macOS) so that one code path is compiled and tested everywhere this crate builds, instead of a
/// platform split whose branches are only ever exercised on one host. The cost is that `ptsname`
/// returns a pointer into per-process static storage, so the call and the copy out of that storage
/// are serialized below.
fn slave_name_of(master: RawFd) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;
    use std::sync::{Mutex, PoisonError};

    static PTSNAME: Mutex<()> = Mutex::new(());

    let _serialized = PTSNAME.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: `master` is an open, unlocked pty master. The returned pointer aliases static storage
    // that a concurrent `ptsname` could overwrite, so the guard above is held across both the call
    // and the copy, and the bytes are owned by the returned `PathBuf` before it is released.
    let bytes = unsafe {
        let name = libc::ptsname(master);
        if name.is_null() {
            return Err(io::Error::last_os_error());
        }
        std::ffi::CStr::from_ptr(name).to_bytes().to_vec()
    };
    if bytes.is_empty() {
        return Err(io::Error::other("pty slave name resolved empty"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{MAX_WINDOW_DIMENSION, PtyPair, WindowSize, make_controlling_terminal};
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    fn pair() -> PtyPair {
        PtyPair::open(WindowSize::new(24, 80).unwrap()).expect("allocate a pty pair")
    }

    /// Read from the master until `needle` appears, output ends, or a deadline expires.
    ///
    /// The deadline is not defensive padding, it is required for correctness of the suite: a pty
    /// master has no portable end-of-input. Linux fails the read with `EIO` once the last slave
    /// closes, while macOS blocks forever in the same situation. A plain blocking read here would
    /// therefore hang the test binary on macOS instead of failing it, so every read is gated on
    /// `poll` and a timeout returns whatever was collected for the caller to assert against.
    fn read_until(master: &mut std::fs::File, needle: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut seen = String::new();
        let mut buf = [0_u8; 256];
        loop {
            if seen.contains(needle) {
                return seen;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let millis = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            if millis == 0 {
                return seen;
            }
            let mut waiting = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `waiting` is one live, correctly typed `pollfd` and the count matches it.
            // The descriptor is the open master owned by the caller.
            if unsafe { libc::poll(&mut waiting, 1, millis) } <= 0 {
                return seen;
            }
            match master.read(&mut buf) {
                Ok(0) => return seen,
                Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => return seen,
                Err(error) => panic!("read pty master: {error}"),
            }
        }
    }

    fn is_close_on_exec(fd: std::os::fd::RawFd) -> bool {
        // SAFETY: `fd` is an open descriptor owned by the caller; `F_GETFD` only reads flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed");
        flags & libc::FD_CLOEXEC != 0
    }

    #[test]
    fn open_allocates_a_real_character_device_slave() {
        let pty = pair();
        let name = pty.slave_name().to_path_buf();
        assert!(
            name.starts_with("/dev/"),
            "slave name is not a device path: {}",
            name.display()
        );
        let metadata = std::fs::metadata(&name).expect("stat the pty slave");
        assert!(
            std::os::unix::fs::FileTypeExt::is_char_device(&metadata.file_type()),
            "pty slave {} is not a character device",
            name.display()
        );
    }

    #[test]
    fn bytes_written_to_the_slave_are_readable_on_the_master() {
        let pty = pair();
        let mut slave = pty.try_clone_slave().unwrap();
        slave.write_all(b"from-the-child\n").unwrap();
        slave.flush().unwrap();
        drop(slave);
        let mut master = pty.master().try_clone().unwrap();
        assert!(read_until(&mut master, "from-the-child").contains("from-the-child"));
    }

    #[test]
    fn bytes_written_to_the_master_are_readable_on_the_slave() {
        let pty = pair();
        let mut master = pty.master().try_clone().unwrap();
        // The line discipline is canonical by default, so a slave read only completes on a newline.
        master.write_all(b"typed-input\n").unwrap();
        master.flush().unwrap();

        let mut slave = pty.try_clone_slave().unwrap();
        let mut buf = [0_u8; 64];
        let n = slave.read(&mut buf).expect("read the terminal input");
        assert_eq!(&buf[..n], b"typed-input\n");
    }

    #[test]
    fn resize_is_observable_through_the_kernel_on_the_child_side() {
        let pty = pair();
        assert_eq!(pty.window_size().unwrap(), WindowSize::new(24, 80).unwrap());

        pty.resize(WindowSize::new(60, 200).unwrap()).unwrap();
        let observed = pty.window_size().unwrap();
        assert_eq!(observed.rows(), 60);
        assert_eq!(observed.cols(), 200);
    }

    #[test]
    fn both_ends_are_close_on_exec_so_neither_leaks_into_an_unrelated_child() {
        let pty = pair();
        assert!(is_close_on_exec(pty.master().as_raw_fd()), "master leaks");
        assert!(is_close_on_exec(pty.slave().as_raw_fd()), "slave leaks");
        assert!(
            is_close_on_exec(pty.try_clone_slave().unwrap().as_raw_fd()),
            "a slave duplicate leaks"
        );
    }

    #[test]
    fn a_master_descriptor_does_not_survive_exec_into_a_child() {
        let pty = pair();
        let raw = pty.master().as_raw_fd();
        // `sh` is not given the descriptor deliberately: if close-on-exec were not set, the fd
        // number would still be open in the child and the test below would observe it.
        let probe = Command::new("/bin/sh")
            .arg("-c")
            // Descriptor 1 is the control. It is unavoidably open in the child, so if the probe
            // cannot see *it* then /dev/fd is not usable on this host and a "closed" verdict for
            // the master would be vacuous rather than evidence.
            .arg(format!(
                "test -e /dev/fd/1 && echo control-visible; \
                 test -e /dev/fd/{raw} && echo leaked || echo closed"
            ))
            .stdin(Stdio::null())
            .output()
            .expect("run the descriptor probe");
        let seen = String::from_utf8_lossy(&probe.stdout);
        assert!(
            seen.contains("control-visible"),
            "/dev/fd is not usable here, so this test proves nothing: {seen:?}"
        );
        assert!(
            seen.contains("closed") && !seen.contains("leaked"),
            "the pty master survived exec into an unrelated child: {seen:?}"
        );
    }

    #[test]
    fn degenerate_and_oversized_windows_are_refused() {
        for (rows, cols) in [(0, 80), (24, 0), (0, 0)] {
            assert_eq!(
                WindowSize::new(rows, cols).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        let over = MAX_WINDOW_DIMENSION + 1;
        assert!(WindowSize::new(over, 80).is_err());
        assert!(WindowSize::new(24, over).is_err());
        assert!(WindowSize::new(MAX_WINDOW_DIMENSION, MAX_WINDOW_DIMENSION).is_ok());
    }

    #[test]
    fn a_child_on_the_slave_sees_a_tty_and_owns_it_as_its_controlling_terminal() {
        let pty = pair();
        let slave = pty.try_clone_slave().unwrap();
        let raw = slave.as_raw_fd();
        let mut child = {
            let mut command = Command::new("/bin/sh");
            command
                // `test -t 1` proves stdout is a terminal at all. Writing to /dev/tty proves the
                // stronger property: the kernel resolved a *controlling* terminal for this session,
                // which only TIOCSCTTY can establish.
                .arg("-c")
                .arg("test -t 1 && echo isatty > /dev/tty && echo ctty-acquired > /dev/tty");
            // SAFETY: the closure runs in the forked child before exec. It calls only
            // async-signal-safe functions and the child is single-threaded at that point.
            unsafe {
                command.pre_exec(move || make_controlling_terminal(raw));
            }
            command.spawn().expect("spawn the pty child")
        };
        // The parent's copies must go before reading, or the master never sees the output end.
        drop(slave);
        let mut master = pty.into_master();

        let output = read_until(&mut master, "ctty-acquired");
        child.wait().expect("reap the pty child");
        assert!(
            output.contains("isatty"),
            "child stdout was not a tty: {output:?}"
        );
        assert!(
            output.contains("ctty-acquired"),
            "child could not write to its controlling terminal: {output:?}"
        );
    }

    #[test]
    fn acquiring_a_controlling_terminal_fails_loudly_when_the_target_is_not_a_terminal() {
        // The negative control. It deliberately does not assert "setsid alone leaves no
        // controlling terminal": that is true on Linux but false on macOS, where a session leader
        // acquires a terminal already on its descriptors as it execs, with no TIOCSCTTY involved.
        // Measured directly on darwin 25.3, that arrangement reports HAS-CTTY. So the portable
        // property worth pinning is the one this module actually owns — TIOCSCTTY is really issued
        // and its failure is propagated instead of leaving a child half-configured.
        let (reader, _writer) = std::io::pipe().expect("create a non-terminal descriptor");
        let raw = reader.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("echo should-never-run")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the closure runs post-fork, pre-exec, and calls only async-signal-safe functions.
        unsafe {
            command.pre_exec(move || make_controlling_terminal(raw));
        }
        let error = command
            .spawn()
            .expect_err("a pipe must not be accepted as a controlling terminal");
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ENOTTY),
            "expected ENOTTY from TIOCSCTTY on a pipe, got {error:?}"
        );
    }

    #[test]
    fn a_pty_child_must_be_drained_before_it_is_reaped() {
        // This ordering is the test. Reaping first and reading afterwards deadlocks: written that
        // way, this case hung in `wait4` indefinitely on darwin 25.3 for a child whose entire
        // output was one short line. A pty is not a pipe with a big kernel buffer that a dead
        // child leaves behind — the reader has to be running for the writer to finish.
        //
        // `persistent.rs` already states the equivalent rule for its pipe backend ("the caller
        // must additionally impose a wall-clock deadline and drain both output pipes"). Wiring a
        // pty into that supervisor does not relax the rule, it makes violating it deadlock rather
        // than merely truncate, which is why it is pinned here.
        let pty = pair();
        let slave = pty.try_clone_slave().unwrap();
        let raw = slave.as_raw_fd();
        let mut child = {
            let mut command = Command::new("/bin/sh");
            command.arg("-c").arg("echo done");
            // SAFETY: as above — post-fork, pre-exec, async-signal-safe calls only.
            unsafe {
                command.pre_exec(move || make_controlling_terminal(raw));
            }
            command.spawn().expect("spawn the short-lived pty child")
        };
        drop(slave);
        let mut master = pty.into_master();

        // Note what is NOT asserted: that the master reports end-of-input. It does on Linux and it
        // does not on macOS (see `into_master`), so the portable guarantee is only that the output
        // is retrievable, and only by a reader that runs before the reap.
        let trailing = read_until(&mut master, "done");
        child.wait().expect("reap the short-lived pty child");
        assert!(
            trailing.contains("done"),
            "the child's output was lost: {trailing:?}"
        );
    }
}
