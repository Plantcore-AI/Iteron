use crate::pty::{PtyPair, WindowSize};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct AsyncPty {
    pub(crate) input: PtyInput,
    pub(crate) output: PtyOutput,
    pub(crate) resize: PtyResize,
}

impl AsyncPty {
    pub(crate) fn from_pair(pair: PtyPair) -> io::Result<Self> {
        let writer = pair.try_clone_master()?;
        let resize = pair.try_clone_master()?;
        let reader = pair.into_master();
        set_nonblocking(&reader)?;
        Ok(Self {
            input: PtyInput {
                writer: AsyncFd::new(writer)?,
                eof_sent: false,
            },
            output: PtyOutput {
                reader: AsyncFd::new(reader)?,
            },
            resize: PtyResize(Arc::new(resize)),
        })
    }
}

pub(crate) struct PtyInput {
    writer: AsyncFd<File>,
    eof_sent: bool,
}

impl PtyInput {
    /// Deliver terminal EOF through the line discipline. Closing only the write duplicate would
    /// not close the shared pty master while the output reader is alive. Two VEOF bytes cover both
    /// canonical states: when a partial line is buffered the first releases that line and the
    /// second makes the following read return zero; when no line is buffered both are harmless
    /// terminal EOF indications. Raw-mode applications interpret VEOF as ordinary input, which is
    /// an intrinsic PTY limitation rather than a half-close this transport can manufacture.
    pub(crate) async fn send_eof(&mut self) -> io::Result<()> {
        if self.eof_sent {
            return Ok(());
        }
        tokio::io::AsyncWriteExt::write_all(self, &[0x04, 0x04]).await?;
        tokio::io::AsyncWriteExt::flush(self).await?;
        self.eof_sent = true;
        Ok(())
    }
}

impl AsyncWrite for PtyInput {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut ready = ready!(this.writer.poll_write_ready(context))?;
            match ready.try_io(|inner| inner.get_ref().write(buffer)) {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct PtyOutput {
    reader: AsyncFd<File>,
}

impl AsyncRead for PtyOutput {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut ready = ready!(this.reader.poll_read_ready(context))?;
            let result = ready.try_io(|inner| {
                let target = buffer.initialize_unfilled();
                inner.get_ref().read(target)
            });
            match result {
                Ok(Ok(read)) => {
                    buffer.advance(read);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => {
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct PtyResize(Arc<File>);

impl PtyResize {
    pub(crate) fn resize(&self, size: WindowSize) -> io::Result<()> {
        let raw = libc::winsize {
            ws_row: size.rows(),
            ws_col: size.cols(),
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(self.0.as_raw_fd(), libc::TIOCSWINSZ as _, &raw) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    let descriptor = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
