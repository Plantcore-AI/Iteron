//! Immutable run-genesis tunables evidence and exact-compatibility checks.

use iteron_protocol::{
    MAX_RUN_GENESIS_TUNABLE_ENTRIES, MAX_RUN_GENESIS_TUNABLE_ID_BYTES,
    RUN_GENESIS_TUNABLES_CANONICALIZATION, RunGenesisTunableEntry, RunGenesisTunableState,
    RunGenesisTunablesSnapshot, RunGenesisTunablesVersion,
};
use iteron_tunables::{EntryState, ResolvedTunableSet};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

#[path = "tunables/snapshot_v2.rs"]
mod snapshot_v2;
pub use snapshot_v2::validate_tunables_snapshot_v2;
#[path = "tunables/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::TunablesCheckpoint;
pub(crate) use checkpoint::{
    GenesisTunablesState, check_checkpoint_compatibility, check_resolved_compatibility,
    checkpoint_from_events, inherited_from,
};

/// A checked legacy decision must be explicit at every resume/replay/fork call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyTunablesPolicy {
    /// Refuse a record that predates immutable tunables evidence.
    RejectUnpinned,
    /// Admit the historical record without claiming that its effective tunables are known.
    AllowUnpinned,
}

/// What a checked operation actually established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunablesCompatibility {
    Exact,
    /// A historical identity-only V1 checkpoint exactly matches the current resolver commitments.
    /// Effective values cannot be reconstructed from that old journal.
    LegacyV1Exact,
    LegacyUnpinned,
}

/// The registry identity written before the product was renamed to Iteron.
///
/// Records are immutable, so a run recorded by an older build legitimately carries the old
/// identity. Decoding accepts it; nothing writes it. Producing a snapshot always uses
/// [`iteron_tunables::REGISTRY_ID`].
const LEGACY_REGISTRY_ID: &str = "core-tunables";

fn is_known_registry_id(registry_id: &str) -> bool {
    registry_id == iteron_tunables::REGISTRY_ID || registry_id == LEGACY_REGISTRY_ID
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TunablesSnapshotError {
    #[error("invalid tunables genesis snapshot: {reason}")]
    Invalid { reason: &'static str },
    #[error("tunables snapshot must be the unique event at physical seq 1: {reason}")]
    GenesisOrder { reason: &'static str },
    #[error("legacy rollout has no immutable tunables snapshot")]
    LegacyUnpinned,
    #[error(
        "resolved tunables mismatch: expected snapshot {expected}, recorded snapshot {recorded}"
    )]
    Mismatch { expected: String, recorded: String },
}

#[derive(Serialize)]
struct SnapshotPayload<'a> {
    version: RunGenesisTunablesVersion,
    canonicalization: &'a str,
    resolution_schema_version: u16,
    registry_id: &'a str,
    registry_schema_version: u16,
    family_schema_version: u16,
    registry_revision: u16,
    registry_digest_sha256: &'a str,
    input_digest_sha256: &'a str,
    effective_digest_sha256: &'a str,
    resolution_digest_sha256: &'a str,
    profile_digest_sha256: &'a Option<String>,
    entries: &'a [RunGenesisTunableEntry],
}

fn payload(snapshot: &RunGenesisTunablesSnapshot) -> SnapshotPayload<'_> {
    SnapshotPayload {
        version: snapshot.version,
        canonicalization: &snapshot.canonicalization,
        resolution_schema_version: snapshot.resolution_schema_version,
        registry_id: &snapshot.registry_id,
        registry_schema_version: snapshot.registry_schema_version,
        family_schema_version: snapshot.family_schema_version,
        registry_revision: snapshot.registry_revision,
        registry_digest_sha256: &snapshot.registry_digest_sha256,
        input_digest_sha256: &snapshot.input_digest_sha256,
        effective_digest_sha256: &snapshot.effective_digest_sha256,
        resolution_digest_sha256: &snapshot.resolution_digest_sha256,
        profile_digest_sha256: &snapshot.profile_digest_sha256,
        entries: &snapshot.entries,
    }
}

pub(super) fn digest_json(value: &impl Serialize) -> Result<String, TunablesSnapshotError> {
    serde_json::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| TunablesSnapshotError::Invalid {
            reason: "canonical snapshot encoding failed",
        })
}

pub(super) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len()
            <= iteron_tunables::param_integer(
                "protocol.tunables_snapshot.max_run_genesis_tunable_id_bytes",
                MAX_RUN_GENESIS_TUNABLE_ID_BYTES,
            )
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        && crate::redact::scrub_route_identifier(value) == value
}

/// Recompute and validate every bounded identity field. The stored self-digest is never trusted.
pub fn validate_tunables_snapshot(
    snapshot: &RunGenesisTunablesSnapshot,
) -> Result<(), TunablesSnapshotError> {
    if snapshot.version != RunGenesisTunablesVersion::V1
        || snapshot.canonicalization != RUN_GENESIS_TUNABLES_CANONICALIZATION
    {
        return Err(TunablesSnapshotError::Invalid {
            reason: "unsupported snapshot version or canonicalization",
        });
    }
    if snapshot.resolution_schema_version == 0
        || snapshot.registry_schema_version == 0
        || snapshot.family_schema_version == 0
        || snapshot.registry_revision == 0
        || !is_known_registry_id(&snapshot.registry_id)
    {
        return Err(TunablesSnapshotError::Invalid {
            reason: "registry identity or schema version is invalid",
        });
    }
    for digest in [
        &snapshot.registry_digest_sha256,
        &snapshot.input_digest_sha256,
        &snapshot.effective_digest_sha256,
        &snapshot.resolution_digest_sha256,
        &snapshot.snapshot_digest_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(TunablesSnapshotError::Invalid {
                reason: "a required digest is not lowercase SHA-256",
            });
        }
    }
    if snapshot
        .profile_digest_sha256
        .as_deref()
        .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(TunablesSnapshotError::Invalid {
            reason: "profile digest is not lowercase SHA-256",
        });
    }
    if snapshot.entries.len() != MAX_RUN_GENESIS_TUNABLE_ENTRIES {
        return Err(TunablesSnapshotError::Invalid {
            reason: "snapshot does not contain exactly the v1 family cardinality",
        });
    }
    let mut families = BTreeSet::new();
    let mut semantic_keys = BTreeSet::new();
    for (index, entry) in snapshot.entries.iter().enumerate() {
        let expected_ordinal =
            u16::try_from(index + 1).map_err(|_| TunablesSnapshotError::Invalid {
                reason: "snapshot ordinal overflow",
            })?;
        if entry.ordinal != expected_ordinal
            || !safe_id(&entry.family_id)
            || !safe_id(&entry.semantic_key)
            || !families.insert(&entry.family_id)
            || !semantic_keys.insert(&entry.semantic_key)
        {
            return Err(TunablesSnapshotError::Invalid {
                reason: "entry identity, order, or uniqueness is invalid",
            });
        }
    }
    if digest_json(&payload(snapshot))? != snapshot.snapshot_digest_sha256 {
        return Err(TunablesSnapshotError::Invalid {
            reason: "snapshot self-digest mismatch",
        });
    }
    Ok(())
}

/// Project the accepted pure resolver result into a bounded protocol-native durable identity.
pub fn snapshot_from_resolved(
    resolved: &ResolvedTunableSet,
) -> Result<RunGenesisTunablesSnapshot, TunablesSnapshotError> {
    snapshot_from_report(resolved.report())
}

/// Project an accepted resolver result into the reconstructable V2 durable checkpoint.
pub fn snapshot_v2_from_resolved(
    resolved: &ResolvedTunableSet,
) -> Result<iteron_protocol::RunGenesisTunablesSnapshotV2, TunablesSnapshotError> {
    snapshot_v2::snapshot_v2_from_report(resolved.report())
}

fn snapshot_from_report(
    report: &iteron_tunables::ResolutionReport,
) -> Result<RunGenesisTunablesSnapshot, TunablesSnapshotError> {
    let entries = report
        .entries
        .iter()
        .map(|entry| {
            let state = match entry.outcome.state() {
                EntryState::Effective => RunGenesisTunableState::Effective,
                EntryState::Inactive => RunGenesisTunableState::Inactive,
                EntryState::Unavailable => RunGenesisTunableState::Unavailable,
                EntryState::Unresolved | EntryState::Rejected => {
                    return Err(TunablesSnapshotError::Invalid {
                        reason: "atomic resolver success contains a failed active family",
                    });
                }
            };
            Ok(RunGenesisTunableEntry {
                ordinal: entry.ordinal,
                family_id: entry.family_id.to_owned(),
                semantic_key: entry.semantic_key.to_owned(),
                state,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut snapshot = RunGenesisTunablesSnapshot {
        version: RunGenesisTunablesVersion::V1,
        canonicalization: RUN_GENESIS_TUNABLES_CANONICALIZATION.to_owned(),
        resolution_schema_version: report.schema_version,
        registry_id: report.registry_id.to_owned(),
        registry_schema_version: iteron_tunables::REGISTRY_SCHEMA_VERSION,
        family_schema_version: iteron_tunables::FAMILY_SCHEMA_VERSION,
        registry_revision: report.registry_revision,
        registry_digest_sha256: report.registry_digest.to_owned(),
        input_digest_sha256: report.input_digest_sha256.clone(),
        effective_digest_sha256: report.effective_digest_sha256.clone(),
        resolution_digest_sha256: report.resolution_digest_sha256.clone(),
        profile_digest_sha256: report.profile_digest_sha256.clone(),
        entries,
        snapshot_digest_sha256: String::new(),
    };
    snapshot.snapshot_digest_sha256 = digest_json(&payload(&snapshot))?;
    validate_tunables_snapshot(&snapshot)?;
    Ok(snapshot)
}

#[cfg(test)]
pub(crate) fn check_compatibility(
    recorded: Option<&RunGenesisTunablesSnapshot>,
    expected: &RunGenesisTunablesSnapshot,
    legacy: LegacyTunablesPolicy,
) -> Result<TunablesCompatibility, TunablesSnapshotError> {
    validate_tunables_snapshot(expected)?;
    match recorded {
        Some(recorded) => {
            validate_tunables_snapshot(recorded)?;
            if recorded == expected {
                Ok(TunablesCompatibility::Exact)
            } else {
                Err(TunablesSnapshotError::Mismatch {
                    expected: expected.snapshot_digest_sha256.clone(),
                    recorded: recorded.snapshot_digest_sha256.clone(),
                })
            }
        }
        None if legacy == LegacyTunablesPolicy::AllowUnpinned => {
            Ok(TunablesCompatibility::LegacyUnpinned)
        }
        None => Err(TunablesSnapshotError::LegacyUnpinned),
    }
}

#[cfg(test)]
pub(crate) fn fixture_snapshot() -> RunGenesisTunablesSnapshot {
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let entries = (1..=MAX_RUN_GENESIS_TUNABLE_ENTRIES)
        .map(|ordinal| RunGenesisTunableEntry {
            ordinal: u16::try_from(ordinal).unwrap(),
            family_id: format!("family_{ordinal}"),
            semantic_key: format!("iteron.tunables.family_{ordinal}"),
            state: RunGenesisTunableState::Effective,
        })
        .collect();
    let mut snapshot = RunGenesisTunablesSnapshot {
        version: RunGenesisTunablesVersion::V1,
        canonicalization: RUN_GENESIS_TUNABLES_CANONICALIZATION.to_owned(),
        resolution_schema_version: 1,
        registry_id: iteron_tunables::REGISTRY_ID.to_owned(),
        registry_schema_version: iteron_tunables::REGISTRY_SCHEMA_VERSION,
        family_schema_version: iteron_tunables::FAMILY_SCHEMA_VERSION,
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest_sha256: iteron_tunables::REGISTRY_DIGEST_SHA256.to_owned(),
        input_digest_sha256: digest.to_owned(),
        effective_digest_sha256: digest.to_owned(),
        resolution_digest_sha256: digest.to_owned(),
        profile_digest_sha256: None,
        entries,
        snapshot_digest_sha256: String::new(),
    };
    snapshot.snapshot_digest_sha256 = digest_json(&payload(&snapshot)).unwrap();
    snapshot
}

#[cfg(test)]
pub(crate) fn fixture_snapshot_variant(marker: char) -> RunGenesisTunablesSnapshot {
    assert!(marker.is_ascii_hexdigit() && marker.is_ascii_lowercase());
    let mut snapshot = fixture_snapshot();
    snapshot.input_digest_sha256 = marker.to_string().repeat(64);
    snapshot.snapshot_digest_sha256 = digest_json(&payload(&snapshot)).unwrap();
    snapshot
}

/// A registry-driven `ResolvedTunableSet`, exposed under a feature so other crates' tests can pin
/// real tunables instead of inventing a snapshot. It resolves the compiled registry, so it fails
/// the moment the registry and its golden digest drift apart, which is exactly what a fake would
/// hide. Never compiled into a release build.
#[cfg(any(test, feature = "test-fixtures"))]
#[path = "resolved_fixture.rs"]
pub mod resolved_fixture;

#[cfg(test)]
#[path = "tunables_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tunables/v2_tests.rs"]
mod v2_tests;
