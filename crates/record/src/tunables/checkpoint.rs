//! Version-neutral tunables checkpoint admission, inheritance, and compatibility.

use super::{
    LegacyTunablesPolicy, TunablesCompatibility, TunablesSnapshotError, is_sha256,
    snapshot_from_resolved, snapshot_v2_from_resolved, validate_tunables_snapshot,
    validate_tunables_snapshot_v2,
};
use core_protocol::{
    EventKind, RunGenesisTunablesInheritance, RunGenesisTunablesSnapshot,
    RunGenesisTunablesSnapshotV2, RunGenesisTunablesVersion,
};

/// One immutable checkpoint read from physical sequence one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunablesCheckpoint {
    V1(RunGenesisTunablesSnapshot),
    V2(RunGenesisTunablesSnapshotV2),
}

impl TunablesCheckpoint {
    pub fn version(&self) -> RunGenesisTunablesVersion {
        match self {
            Self::V1(_) => RunGenesisTunablesVersion::V1,
            Self::V2(_) => RunGenesisTunablesVersion::V2,
        }
    }

    pub fn snapshot_digest_sha256(&self) -> &str {
        match self {
            Self::V1(snapshot) => &snapshot.snapshot_digest_sha256,
            Self::V2(snapshot) => &snapshot.snapshot_digest_sha256,
        }
    }

    pub fn effective_digest_sha256(&self) -> &str {
        match self {
            Self::V1(snapshot) => &snapshot.effective_digest_sha256,
            Self::V2(snapshot) => &snapshot.effective_digest_sha256,
        }
    }

    pub fn as_v2(&self) -> Option<&RunGenesisTunablesSnapshotV2> {
        match self {
            Self::V2(snapshot) => Some(snapshot),
            Self::V1(_) => None,
        }
    }

    fn validate(&self) -> Result<(), TunablesSnapshotError> {
        match self {
            Self::V1(snapshot) => validate_tunables_snapshot(snapshot),
            Self::V2(snapshot) => validate_tunables_snapshot_v2(snapshot),
        }
    }
}

fn mismatch(expected: &TunablesCheckpoint, recorded: &TunablesCheckpoint) -> TunablesSnapshotError {
    TunablesSnapshotError::Mismatch {
        expected: expected.snapshot_digest_sha256().to_owned(),
        recorded: recorded.snapshot_digest_sha256().to_owned(),
    }
}

fn check_missing(
    legacy: LegacyTunablesPolicy,
) -> Result<TunablesCompatibility, TunablesSnapshotError> {
    match legacy {
        LegacyTunablesPolicy::AllowUnpinned => Ok(TunablesCompatibility::LegacyUnpinned),
        LegacyTunablesPolicy::RejectUnpinned => Err(TunablesSnapshotError::LegacyUnpinned),
    }
}

/// Compare a record with one exact versioned checkpoint.
pub(crate) fn check_checkpoint_compatibility(
    recorded: Option<&TunablesCheckpoint>,
    expected: &TunablesCheckpoint,
    legacy: LegacyTunablesPolicy,
) -> Result<TunablesCompatibility, TunablesSnapshotError> {
    expected.validate()?;
    let Some(recorded) = recorded else {
        return check_missing(legacy);
    };
    recorded.validate()?;
    if recorded == expected {
        Ok(TunablesCompatibility::Exact)
    } else {
        Err(mismatch(expected, recorded))
    }
}

/// Compare against a current atomic resolver result while admitting an exact historical V1
/// identity without pretending that the old journal contains reconstructable values.
pub(crate) fn check_resolved_compatibility(
    recorded: Option<&TunablesCheckpoint>,
    resolved: &core_tunables::ResolvedTunableSet,
    legacy: LegacyTunablesPolicy,
) -> Result<TunablesCompatibility, TunablesSnapshotError> {
    let Some(recorded) = recorded else {
        return check_missing(legacy);
    };
    recorded.validate()?;
    match recorded {
        TunablesCheckpoint::V2(recorded) => {
            let expected = snapshot_v2_from_resolved(resolved)?;
            if *recorded == expected {
                Ok(TunablesCompatibility::Exact)
            } else {
                Err(mismatch(
                    &TunablesCheckpoint::V2(expected),
                    &TunablesCheckpoint::V2(recorded.clone()),
                ))
            }
        }
        TunablesCheckpoint::V1(recorded) => {
            let expected = snapshot_from_resolved(resolved)?;
            if *recorded == expected {
                Ok(TunablesCompatibility::LegacyV1Exact)
            } else {
                Err(mismatch(
                    &TunablesCheckpoint::V1(expected),
                    &TunablesCheckpoint::V1(recorded.clone()),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GenesisTunablesState {
    root_parent: Option<Option<String>>,
    checkpoint: Option<TunablesCheckpoint>,
}

impl GenesisTunablesState {
    pub(crate) fn checkpoint(&self) -> Option<&TunablesCheckpoint> {
        self.checkpoint.as_ref()
    }

    pub(crate) fn observe(
        &mut self,
        seq: u64,
        kind: &EventKind,
    ) -> Result<(), TunablesSnapshotError> {
        if seq == 0 {
            self.root_parent = root_parent(kind);
        }
        let Some((checkpoint, inherited_from)) = checkpoint_event(kind)? else {
            return Ok(());
        };
        if seq != 1 || self.checkpoint.is_some() {
            return Err(TunablesSnapshotError::GenesisOrder {
                reason: "snapshot is late or duplicated",
            });
        }
        let Some(parent) = &self.root_parent else {
            return Err(TunablesSnapshotError::GenesisOrder {
                reason: "physical seq 0 is not run_start",
            });
        };
        checkpoint.validate()?;
        validate_inheritance(parent.as_deref(), inherited_from, &checkpoint)?;
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<Option<&TunablesCheckpoint>, TunablesSnapshotError> {
        if self.root_parent.is_none() {
            return Err(TunablesSnapshotError::GenesisOrder {
                reason: "physical seq 0 is not a structurally valid run_start",
            });
        }
        Ok(self.checkpoint())
    }
}

fn root_parent(kind: &EventKind) -> Option<Option<String>> {
    match kind {
        EventKind::RunStart {
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } => match (parent_run, forked_at, parent_hash_at_seq) {
            (None, None, None) => Some(None),
            (Some(parent_run), Some(_), Some(parent_hash))
                if crate::validate_run_id(&core_protocol::RunId(parent_run.clone())).is_ok()
                    && is_sha256(parent_hash) =>
            {
                Some(Some(parent_run.clone()))
            }
            _ => None,
        },
        _ => None,
    }
}

fn checkpoint_event(
    kind: &EventKind,
) -> Result<
    Option<(TunablesCheckpoint, Option<&RunGenesisTunablesInheritance>)>,
    TunablesSnapshotError,
> {
    match kind {
        EventKind::TunablesSnapshot {
            version,
            snapshot,
            inherited_from,
        } => {
            if *version != RunGenesisTunablesVersion::V1 || *version != snapshot.version {
                return Err(TunablesSnapshotError::Invalid {
                    reason: "V1 event and snapshot versions disagree",
                });
            }
            Ok(Some((
                TunablesCheckpoint::V1(snapshot.clone()),
                inherited_from.as_ref(),
            )))
        }
        EventKind::TunablesSnapshotV2 {
            version,
            snapshot,
            inherited_from,
        } => {
            if *version != RunGenesisTunablesVersion::V2 || *version != snapshot.version {
                return Err(TunablesSnapshotError::Invalid {
                    reason: "V2 event and snapshot versions disagree",
                });
            }
            Ok(Some((
                TunablesCheckpoint::V2(snapshot.clone()),
                inherited_from.as_ref(),
            )))
        }
        _ => Ok(None),
    }
}

fn validate_inheritance(
    parent: Option<&str>,
    inherited: Option<&RunGenesisTunablesInheritance>,
    checkpoint: &TunablesCheckpoint,
) -> Result<(), TunablesSnapshotError> {
    match (parent, inherited) {
        (None, None) => Ok(()),
        (None, Some(inherited))
            if crate::validate_run_id(&core_protocol::RunId(inherited.parent_run.clone()))
                .is_ok()
                && inherited.parent_snapshot_digest_sha256
                    == checkpoint.snapshot_digest_sha256() =>
        {
            // A spawned agent owns an independent transcript/journal, not the parent's logical
            // prefix. Its companion snapshot still binds the exact parent run and checkpoint.
            Ok(())
        }
        (Some(parent), Some(inherited))
            if inherited.parent_run == parent
                && inherited.parent_snapshot_digest_sha256
                    == checkpoint.snapshot_digest_sha256() =>
        {
            Ok(())
        }
        (None, Some(_)) => Err(TunablesSnapshotError::GenesisOrder {
            reason: "spawned child snapshot parent or digest binding is invalid",
        }),
        (Some(_), None) => Err(TunablesSnapshotError::GenesisOrder {
            reason: "fork snapshot omits parent snapshot binding",
        }),
        (Some(_), Some(_)) => Err(TunablesSnapshotError::GenesisOrder {
            reason: "fork snapshot parent or digest binding mismatches run_start",
        }),
    }
}

pub(crate) fn checkpoint_from_events(
    events: &[core_protocol::Event],
) -> Result<Option<TunablesCheckpoint>, TunablesSnapshotError> {
    let mut state = GenesisTunablesState::default();
    for event in events {
        state.observe(event.seq.0, &event.kind)?;
    }
    Ok(state.finish()?.cloned())
}

pub(crate) fn inherited_from(
    parent_run: &str,
    checkpoint: &TunablesCheckpoint,
) -> RunGenesisTunablesInheritance {
    RunGenesisTunablesInheritance {
        parent_run: parent_run.to_owned(),
        parent_snapshot_digest_sha256: checkpoint.snapshot_digest_sha256().to_owned(),
    }
}
