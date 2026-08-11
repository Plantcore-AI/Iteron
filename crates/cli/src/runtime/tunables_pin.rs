//! Immutable, version-neutral tunables identity shared by one execution lineage.

use super::KernelError;
use iteron_protocol::{
    Event, EventKind, RunGenesisTunablesInheritance, RunGenesisTunablesVersion,
    RunGenesisTunablesVersionV2, RunId, Seq,
};
use iteron_record::{Rollout, TunablesCheckpoint, TunablesSnapshotError};
use std::sync::Arc;

/// One validated physical-sequence-one checkpoint shared by a root and every child.
///
/// The `Arc` is intentional: cloning a child configuration clones this handle, never a resolver
/// input and never a source of ambient defaults. Historical V1 checkpoints remain V1; a resume is
/// not silently upgraded to whatever the current resolver would produce.
#[derive(Debug, Clone)]
pub(crate) struct TunablesPin {
    checkpoint: Arc<TunablesCheckpoint>,
}

impl TunablesPin {
    /// Project a fresh atomic resolver result exactly once into the current V2 record identity.
    pub(crate) fn from_resolved(
        resolved: &iteron_tunables::ResolvedTunableSet,
    ) -> Result<Self, KernelError> {
        let snapshot = iteron_record::snapshot_v2_from_resolved(resolved)
            .map_err(iteron_record::RecordError::from)?;
        Ok(Self {
            checkpoint: Arc::new(TunablesCheckpoint::V2(snapshot)),
        })
    }

    /// Admit the exact checkpoint recovered from a held rollout. No resolver is consulted.
    pub(crate) fn from_checkpoint(checkpoint: TunablesCheckpoint) -> Result<Self, KernelError> {
        validate(&checkpoint).map_err(iteron_record::RecordError::from)?;
        Ok(Self {
            checkpoint: Arc::new(checkpoint),
        })
    }

    pub(crate) fn checkpoint(&self) -> &TunablesCheckpoint {
        self.checkpoint.as_ref()
    }

    pub(crate) fn resolution_digest_sha256(&self) -> &str {
        match self.checkpoint() {
            TunablesCheckpoint::V1(snapshot) => &snapshot.resolution_digest_sha256,
            TunablesCheckpoint::V2(snapshot) => &snapshot.resolution_digest_sha256,
        }
    }

    /// Append an independent root transcript plus this exact checkpoint. `parent_run` binds a
    /// spawned child to its parent without turning the child's transcript into a logical fork.
    pub(crate) fn append_genesis(
        &self,
        rollout: &mut Rollout,
        run_start: &Event,
        parent_run: Option<&RunId>,
    ) -> Result<(Seq, Seq), iteron_record::RecordError> {
        if !rollout.is_empty() {
            return Err(snapshot_error("genesis append requires an empty rollout"));
        }

        let inherited_from = parent_run.map(|parent| RunGenesisTunablesInheritance {
            parent_run: parent.0.clone(),
            parent_snapshot_digest_sha256: self.checkpoint().snapshot_digest_sha256().to_owned(),
        });
        let kind = match self.checkpoint() {
            TunablesCheckpoint::V1(snapshot) => EventKind::TunablesSnapshot {
                version: RunGenesisTunablesVersion::V1,
                snapshot: snapshot.clone(),
                inherited_from,
            },
            TunablesCheckpoint::V2(snapshot) => EventKind::TunablesSnapshotV2 {
                version: RunGenesisTunablesVersionV2::V2,
                snapshot: snapshot.clone(),
                inherited_from,
            },
        };
        let snapshot_event = Event {
            seq: Seq::ZERO,
            turn: run_start.turn,
            kind,
        };

        // Validate the complete pair before the first write. A failure between the two fsyncs may
        // still leave an unpinned prefix, which every checked resume rejects; an invalid pair can
        // never create that prefix in the first place.
        let mut validation_start = run_start.clone();
        validation_start.seq = Seq::ZERO;
        let mut validation_snapshot = snapshot_event.clone();
        validation_snapshot.seq = Seq(1);
        let projected = iteron_record::tunables_checkpoint_from_events(&[
            validation_start,
            validation_snapshot,
        ])
        .map_err(iteron_record::RecordError::from)?;
        if projected.as_ref() != Some(self.checkpoint()) {
            return Err(snapshot_error(
                "validated genesis did not preserve the pinned checkpoint",
            ));
        }

        let start_seq = rollout.append(run_start)?;
        let checkpoint_seq = rollout.append(&snapshot_event)?;
        Ok((start_seq, checkpoint_seq))
    }
}

fn validate(checkpoint: &TunablesCheckpoint) -> Result<(), TunablesSnapshotError> {
    match checkpoint {
        TunablesCheckpoint::V1(snapshot) => iteron_record::validate_tunables_snapshot(snapshot),
        TunablesCheckpoint::V2(snapshot) => iteron_record::validate_tunables_snapshot_v2(snapshot),
    }
}

fn snapshot_error(reason: &'static str) -> iteron_record::RecordError {
    TunablesSnapshotError::GenesisOrder { reason }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{RunGenesisTunablesSnapshot, RunGenesisTunablesVersion};

    fn invalid_v1() -> TunablesCheckpoint {
        TunablesCheckpoint::V1(RunGenesisTunablesSnapshot {
            version: RunGenesisTunablesVersion::V1,
            canonicalization: "invalid".into(),
            resolution_schema_version: 1,
            registry_id: "fixture".into(),
            registry_schema_version: 1,
            family_schema_version: 1,
            registry_revision: 1,
            registry_digest_sha256: "a".repeat(64),
            input_digest_sha256: "b".repeat(64),
            effective_digest_sha256: "c".repeat(64),
            resolution_digest_sha256: "d".repeat(64),
            profile_digest_sha256: None,
            entries: Vec::new(),
            snapshot_digest_sha256: "e".repeat(64),
        })
    }

    #[test]
    fn resume_constructor_rejects_an_invalid_checkpoint() {
        assert!(TunablesPin::from_checkpoint(invalid_v1()).is_err());
    }

    #[test]
    fn lineage_clones_share_one_checkpoint_allocation() {
        let pin = TunablesPin {
            checkpoint: Arc::new(invalid_v1()),
        };
        let child = pin.clone();
        assert!(Arc::ptr_eq(&pin.checkpoint, &child.checkpoint));
        assert_eq!(pin.resolution_digest_sha256(), "d".repeat(64));
    }
}
