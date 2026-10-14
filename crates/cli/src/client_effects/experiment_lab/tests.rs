use super::*;
pub(crate) const KEY: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
pub(crate) fn fixture() -> (std::path::PathBuf, crate::runtime::Agent) {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "iteron-native-lab-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let agent = crate::app_server::navigation_agent(&root);
    (root, agent)
}
pub(crate) fn family() -> &'static str {
    iteron_tunables::families()
        .iter()
        .find(|family| {
            family.implementation_status == iteron_tunables::ImplementationStatus::Full
                && family.optimization.class != iteron_tunables::OptimizationClass::Pin
        })
        .unwrap()
        .id
}
pub(crate) fn install_evidence(root: &std::path::Path) {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../eval/fixtures/evidence-bundle-v1");
    let target = root.join(".iteron/experiments/evidence/evidence-bundle-v1");
    std::fs::create_dir_all(&target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
    }
}
pub(crate) fn request(agent: &crate::runtime::Agent) -> NativeExperimentLab {
    NativeExperimentLab::capture(
        agent,
        LabActionV1::Request {
            family: family().into(),
            value: "true".into(),
        },
    )
    .unwrap()
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn request_is_content_addressed_train_only_and_has_no_activation_surface() {
    let (root, agent) = fixture();
    let LabFactsV1::Request { receipt: first } = request(&agent).execute().facts.unwrap() else {
        panic!("native request expected")
    };
    assert_eq!(first.status, RequestStatusV1::Created);
    let before = std::fs::read(root.join(&first.relative_path)).unwrap();
    let LabFactsV1::Request { receipt: second } = request(&agent).execute().facts.unwrap() else {
        panic!("native reused request expected")
    };
    assert_eq!(first.request_id, second.request_id);
    assert_eq!(second.status, RequestStatusV1::Existing);
    assert_eq!(
        std::fs::read(root.join(&first.relative_path)).unwrap(),
        before
    );
    let mut document: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(document["allowed_partition"], "train");
    assert_eq!(document["evaluation_purpose"], "tune");
    assert_eq!(document["promotion"]["runtime_activation"], false);
    assert_eq!(document["promotion"]["self_promotion"], false);
    document["promotion"]["runtime_activation"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ExperimentRequest>(document).is_err());
    std::fs::write(
        root.join(&first.relative_path),
        b"operator's existing different bytes",
    )
    .unwrap();
    assert!(request(&agent).execute().facts.is_err());
    assert_eq!(
        std::fs::read(root.join(&first.relative_path)).unwrap(),
        b"operator's existing different bytes"
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn exact_signed_fixture_compares_actual_held_sources_and_refuses_changed_file_or_key() {
    let (root, agent) = fixture();
    install_evidence(&root);
    let command = |key: &str| LabActionV1::Compare {
        bundle_id: "evidence-bundle-v1".into(),
        trusted_public_key: key.into(),
    };
    let LabFactsV1::Comparison { view } = NativeExperimentLab::capture(&agent, command(KEY))
        .unwrap()
        .execute()
        .facts
        .unwrap()
    else {
        panic!("verified comparison expected")
    };
    assert!(view.synthetic);
    assert_eq!(view.success, 2);
    assert_eq!(view.task_failure, 1);
    assert_eq!(view.infrastructure_failure, 1);
    assert_eq!(view.held_out, 1);
    assert!(
        NativeExperimentLab::capture(&agent, command(&"0".repeat(64)))
            .unwrap()
            .execute()
            .facts
            .is_err()
    );
    let directory = root.join(".iteron/experiments/evidence/evidence-bundle-v1");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("bundle.index.json")).unwrap())
            .unwrap();
    let name = index["files"][0]["file_name"].as_str().unwrap();
    std::fs::write(directory.join(name), b"changed actual bytes").unwrap();
    assert!(
        NativeExperimentLab::capture(&agent, command(KEY))
            .unwrap()
            .execute()
            .facts
            .is_err()
    );
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn pin_and_symlinked_lab_root_are_refused() {
    let (root, mut agent) = fixture();
    let pin = iteron_tunables::families()
        .iter()
        .find(|family| family.optimization.class == iteron_tunables::OptimizationClass::Pin)
        .unwrap();
    assert!(
        NativeExperimentLab::capture(
            &agent,
            LabActionV1::Request {
                family: pin.id.into(),
                value: "true".into()
            }
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".iteron/experiments")).unwrap();
        assert!(request(&agent).execute().facts.is_err());
        assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
    }
    agent.narrow_authority_ceiling(iteron_protocol::capability_set::CapabilitySet::none());
    assert!(NativeExperimentLab::capture(&agent, LabActionV1::List).is_err());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn bounded_inventory_reports_large_scan_and_does_not_advertise_forged_status() {
    let (root, agent) = fixture();
    let LabFactsV1::Request { receipt } = request(&agent).execute().facts.unwrap() else {
        panic!("native request expected")
    };
    let mut bytes: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(&receipt.relative_path)).unwrap()).unwrap();
    bytes["status"] = serde_json::json!("activated");
    std::fs::write(
        root.join(&receipt.relative_path),
        serde_json::to_vec(&bytes).unwrap(),
    )
    .unwrap();
    let dir = root.join(".iteron/experiments/requests");
    for n in 0..MAX_SCAN + 1 {
        std::fs::write(dir.join(format!("junk-{n}.json")), b"{}").unwrap();
    }
    let LabFactsV1::Inventory {
        requests,
        incomplete,
        ..
    } = NativeExperimentLab::capture(&agent, LabActionV1::List)
        .unwrap()
        .execute()
        .facts
        .unwrap()
    else {
        panic!("native inventory expected")
    };
    assert!(incomplete);
    assert!(requests.is_empty());
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
