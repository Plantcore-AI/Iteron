//! Closed local diagnostics for existing adoption refusals; no foreign error content is logged.
use super::KernelError;

#[derive(Clone, Copy)]
pub(super) enum Stage {
    GenesisEnvironment,
    RecordedEnvironment,
    ResidentContent,
    ProcessFamilies,
    QueueOwner,
    FallbackTopology,
    NativeCeilings,
    SpawnQuota,
}

impl Stage {
    fn code(self) -> &'static str {
        match self {
            Self::GenesisEnvironment => "genesis_environment",
            Self::RecordedEnvironment => "recorded_environment",
            Self::ResidentContent => "resident_content",
            Self::ProcessFamilies => "process_families",
            Self::QueueOwner => "queue_owner",
            Self::FallbackTopology => "fallback_topology",
            Self::NativeCeilings => "native_ceilings",
            Self::SpawnQuota => "spawn_quota",
        }
    }
}

pub(super) fn refused(stage: Stage, error: KernelError) -> KernelError {
    if matches!(&error, KernelError::ExecutionPolicy(_)) {
        let code = stage.code();
        #[cfg(debug_assertions)]
        eprintln!("session adoption refused: stage={code}");
        #[cfg(not(debug_assertions))]
        let _ = code;
    }
    error
}

#[cfg(test)]
mod tests {
    use super::{Stage, refused};
    use crate::runtime::KernelError;

    #[test]
    fn closed_stage_diagnostic_preserves_the_exact_refusal() {
        for stage in [
            Stage::GenesisEnvironment,
            Stage::RecordedEnvironment,
            Stage::ResidentContent,
            Stage::ProcessFamilies,
            Stage::QueueOwner,
            Stage::FallbackTopology,
            Stage::NativeCeilings,
            Stage::SpawnQuota,
        ] {
            let code = stage.code();
            assert!(code.len() < 32);
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
            let error = refused(stage, KernelError::ExecutionPolicy("private cause".into()));
            assert!(
                matches!(error, KernelError::ExecutionPolicy(reason) if reason == "private cause")
            );
            assert_eq!(
                refused(stage, KernelError::UnpricedUsdCeiling).public_summary(),
                KernelError::UnpricedUsdCeiling.public_summary()
            );
        }
    }
}
