//! Readable historical fault vocabulary. Standalone never opens or consumes a marker.
use clap::ValueEnum;
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
    pub(crate) fn consume_marker(self) -> anyhow::Result<()> {
        let _ = self;
        anyhow::bail!("legacy recording faults are unavailable in standalone Iteron")
    }
}
#[cfg(test)]
mod tests {
    use super::RecordingAppServerFault;
    #[test]
    fn every_historical_fault_refuses_without_a_marker_locator() {
        for fault in [
            RecordingAppServerFault::RawV7AtLimit,
            RecordingAppServerFault::RawV7OverLimit,
            RecordingAppServerFault::FrameChunkMissing,
            RecordingAppServerFault::FrameChunkOutOfOrder,
            RecordingAppServerFault::FrameChunkConflict,
        ] {
            assert!(fault.consume_marker().is_err());
        }
    }
}
