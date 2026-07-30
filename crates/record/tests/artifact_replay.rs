//! A declared artifact survives the record: replay yields the same set it was given.
//!
//! The point of `EventKind::ArtifactProduced` is that a product built on top of a run can be
//! stored, listed and reopened later. That only holds if the handle comes back intact, so this
//! writes a run, replays it from disk, and compares the artifact set rather than trusting that
//! serialization round-trips.

use core_protocol::artifact::{ArtifactRef, ArtifactSchema, Producer, Provenance};
use core_protocol::capability_set::CapabilitySet;
use core_protocol::{Capability, Event, EventKind, RunId, Seq, TenantId, TurnId};

struct Runs(std::path::PathBuf);

impl Drop for Runs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn runs_dir(label: &str) -> Runs {
    let path = std::env::temp_dir().join(format!(
        "core-artifact-replay-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    Runs(path)
}

fn artifact(index: u8, locator: &str) -> ArtifactRef {
    ArtifactRef {
        hash: format!("{index:064x}"),
        schema: ArtifactSchema::FileDiff,
        producer: Producer::Tool {
            tool: "edit".into(),
        },
        provenance: Provenance {
            run_id: RunId("artifact-run".into()),
            parent_hashes: Vec::new(),
            effect_id: None,
        },
        permissions: CapabilitySet::only(Capability::ReadOnly),
        locator: locator.into(),
    }
}

fn artifacts(events: &[Event]) -> Vec<ArtifactRef> {
    events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::ArtifactProduced { artifact } => Some(artifact.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_declared_artifact_survives_replay() {
    let runs = runs_dir("survives");
    let run = RunId("artifact-run".into());
    let declared = [
        artifact(1, "reports/summary.md"),
        artifact(2, "reports/table.csv"),
    ];

    {
        let mut rollout = core_record::Rollout::open(&runs.0, &run, TenantId::default()).unwrap();
        for (index, artifact) in declared.iter().enumerate() {
            rollout
                .append(&Event {
                    seq: Seq(index as u64 + 1),
                    turn: TurnId(1),
                    kind: EventKind::ArtifactProduced {
                        artifact: artifact.clone(),
                    },
                })
                .unwrap();
        }
    }

    let replayed = artifacts(&core_record::load_forked(&runs.0, &run).unwrap());
    assert_eq!(
        replayed.len(),
        declared.len(),
        "replay must yield the same artifact set"
    );
    for (before, after) in declared.iter().zip(replayed.iter()) {
        assert_eq!(before.hash, after.hash, "the content address must survive");
        assert_eq!(before.schema, after.schema);
        assert_eq!(before.producer, after.producer);
        assert_eq!(before.locator, after.locator);
    }
}

/// The handle stays resolvable: masking the content address would make the product unfindable,
/// which is the same correlation break a scrubbed `tool_use_id` caused.
#[test]
fn the_content_address_is_not_masked_by_the_record_path() {
    let declared = artifact(9, "reports/summary.md");
    let redacted = core_record::redact::redact_event(&Event {
        seq: Seq(1),
        turn: TurnId(1),
        kind: EventKind::ArtifactProduced {
            artifact: declared.clone(),
        },
    });
    let EventKind::ArtifactProduced { artifact } = &redacted.kind else {
        panic!("the kind changed");
    };
    assert_eq!(artifact.hash, declared.hash);
    assert_eq!(artifact.locator, declared.locator);
}
