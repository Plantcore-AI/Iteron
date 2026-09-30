//! Bounded terminal assistant-text spill owner and exact cleanup.

use super::{AtomicU64, Ordering};
use std::io::{Read as _, Seek as _, Write as _};

static NEXT_EQ_TERMINAL_TEXT_SPILL: AtomicU64 = AtomicU64::new(0);

pub(super) fn max_eq_terminal_text_spill_bytes() -> usize {
    128 * 1024 * 1024
}

#[derive(Debug)]
pub(super) struct AssistantTextSpill {
    pub(super) file: std::fs::File,
    /// `None` after Unix unlinks the name immediately while retaining the private descriptor.
    pub(super) path: Option<std::path::PathBuf>,
    pub(super) bytes: usize,
    pub(super) run_id: String,
}

impl AssistantTextSpill {
    /// Return the owned text with every ordinary I/O refusal so the caller can restore the
    /// `RunEnded` payload instead of turning a spool failure into silent final-answer loss.
    pub(super) fn create(run_id: String, text: String) -> Result<Self, (std::io::Error, String)> {
        if text.len() > max_eq_terminal_text_spill_bytes() {
            return Err((
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "terminal text exceeds the bounded EQ spool ceiling",
                ),
                text,
            ));
        }
        let root = std::env::temp_dir();
        for _ in 0..16 {
            let ordinal = NEXT_EQ_TERMINAL_TEXT_SPILL.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "iteron-eq-terminal-{}-{ordinal}.tmp",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
                options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            match options.open(&path) {
                Ok(file) => {
                    let mut spill = Self {
                        file,
                        path: Some(path),
                        bytes: text.len(),
                        run_id,
                    };
                    let prepared = (|| -> std::io::Result<()> {
                        spill.file.write_all(text.as_bytes())?;
                        spill.file.seek(std::io::SeekFrom::Start(0))?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt as _;
                            let metadata = spill.file.metadata()?;
                            if !metadata.is_file() || metadata.mode() & 0o777 != 0o600 {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    "bounded EQ terminal spool was not a private regular file",
                                ));
                            }
                            // Keep only the already-open descriptor. A crash cannot strand terminal
                            // content in the shared temporary directory, and no later path lookup can
                            // substitute a different file before the consumer reads it.
                            let Some(path) = spill.path.as_ref() else {
                                return Err(std::io::Error::other(
                                    "new terminal spool lost its cleanup identity",
                                ));
                            };
                            std::fs::remove_file(path)?;
                            spill.path = None;
                        }
                        Ok(())
                    })();
                    if let Err(error) = prepared {
                        return Err((error, text));
                    }
                    return Ok(spill);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err((error, text)),
            }
        }
        Err((
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate a unique bounded EQ terminal spool",
            ),
            text,
        ))
    }

    pub(super) fn read_to_string(mut self, expected_run_id: &str) -> std::io::Result<String> {
        if self.run_id != expected_run_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded EQ terminal spool correlation did not match RunEnded",
            ));
        }
        let mut bytes = Vec::with_capacity(self.bytes);
        std::io::Read::by_ref(&mut self.file)
            .take(
                u64::try_from(self.bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)?;
        if bytes.len() != self.bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "bounded EQ terminal spool length changed",
            ));
        }
        String::from_utf8(bytes).map_err(std::io::Error::other)
    }
}

impl Drop for AssistantTextSpill {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}
