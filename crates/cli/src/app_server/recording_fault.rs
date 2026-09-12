//! Closed, release-recording-only App Server fault admission.

use anyhow::{Context as _, bail};
use clap::ValueEnum;
use std::io::Read as _;
use std::path::Path;

const CONTROL_BRIDGE_ENV: &str = "CONTROL_BRIDGE";
const MAX_MARKER_BYTES: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum RecordingAppServerFault {
    RawV7AtLimit,
    RawV7OverLimit,
    FrameChunkMissing,
    FrameChunkOutOfOrder,
    FrameChunkConflict,
}

impl RecordingAppServerFault {
    pub(crate) fn marker_path(self) -> &'static Path {
        Path::new(match self {
            Self::RawV7AtLimit => {
                "/run/plantcore/bridge/iteron.app-server-fault.raw-v7-at-limit.enabled"
            }
            Self::RawV7OverLimit => {
                "/run/plantcore/bridge/iteron.app-server-fault.raw-v7-over-limit.enabled"
            }
            Self::FrameChunkMissing => {
                "/run/plantcore/bridge/iteron.app-server-fault.frame-chunk-missing.enabled"
            }
            Self::FrameChunkOutOfOrder => {
                "/run/plantcore/bridge/iteron.app-server-fault.frame-chunk-out-of-order.enabled"
            }
            Self::FrameChunkConflict => {
                "/run/plantcore/bridge/iteron.app-server-fault.frame-chunk-conflict.enabled"
            }
        })
    }

    /// Consume the exact one-shot marker before any listener is bound.
    #[cfg(unix)]
    pub(crate) fn consume_marker(self) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;

        if std::env::var_os(CONTROL_BRIDGE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            bail!("recording_app_server_fault_requires_control_bridge");
        }
        let path = self.marker_path();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .context("recording_app_server_fault_marker_open_failed")?;
        let metadata = file
            .metadata()
            .context("recording_app_server_fault_marker_metadata_failed")?;
        if !metadata.file_type().is_file() || metadata.len() != MAX_MARKER_BYTES {
            bail!("recording_app_server_fault_marker_invalid");
        }
        let mut bytes = Vec::with_capacity(MAX_MARKER_BYTES as usize);
        file.take(MAX_MARKER_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("recording_app_server_fault_marker_read_failed")?;
        if bytes != b"enabled\n" {
            bail!("recording_app_server_fault_marker_invalid");
        }
        std::fs::remove_file(path).context("recording_app_server_fault_marker_consume_failed")?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn consume_marker(self) -> anyhow::Result<()> {
        let _ = self;
        bail!("recording_app_server_fault_unsupported_platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_paths_are_fixed_and_match_the_cli_values() {
        for (fault, value) in [
            (RecordingAppServerFault::RawV7AtLimit, "raw-v7-at-limit"),
            (RecordingAppServerFault::RawV7OverLimit, "raw-v7-over-limit"),
            (
                RecordingAppServerFault::FrameChunkMissing,
                "frame-chunk-missing",
            ),
            (
                RecordingAppServerFault::FrameChunkOutOfOrder,
                "frame-chunk-out-of-order",
            ),
            (
                RecordingAppServerFault::FrameChunkConflict,
                "frame-chunk-conflict",
            ),
        ] {
            assert_eq!(fault.to_possible_value().unwrap().get_name(), value);
            assert_eq!(
                fault.marker_path(),
                Path::new(&format!(
                    "/run/plantcore/bridge/iteron.app-server-fault.{value}.enabled"
                ))
            );
        }
    }
}
