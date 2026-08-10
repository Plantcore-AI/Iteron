use iteron_evolve::{
    EvidenceRecorder, RecordedRunFixture, RecordedRunProjector, RetentionTrainingUse,
    TrainingAdmissionPolicy, TrajectoryProjection, TrajectoryRegistry,
};
use std::collections::{BTreeMap, BTreeSet};

const FIXTURE: &[u8] = include_bytes!("fixtures/recorded-run-clean-v1.json");
const ROLLOUT_DIGEST: &str = "0722b7c0b2b2f35b340557421165459ab748e6bfa1355d30e398ebc9270439f9";

#[test]
fn committed_record_fixture_projects_and_ingests_through_the_frozen_seam() {
    let fixture = RecordedRunFixture::from_json(FIXTURE).unwrap();
    let policy = TrainingAdmissionPolicy::new(
        BTreeSet::from(["apache-2.0".to_owned()]),
        BTreeMap::from([("training-v1".to_owned(), RetentionTrainingUse::Allowed)]),
    )
    .unwrap();
    let projector = RecordedRunProjector::new(vec![fixture], policy).unwrap();
    let envelope = projector.project(ROLLOUT_DIGEST).unwrap().unwrap();
    EvidenceRecorder::new()
        .verify_trajectory(&envelope)
        .unwrap();

    let root = std::env::temp_dir().join(format!(
        "iteron-evolve-projection-integration-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    registry.ingest(&envelope).unwrap();
    assert_eq!(registry.len().unwrap(), 1);
    std::fs::remove_dir_all(root).unwrap();
}
