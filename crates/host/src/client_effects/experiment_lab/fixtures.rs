use super::*;
pub const KEY: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
pub fn fixture() -> (std::path::PathBuf, crate::runtime::Agent) {
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
pub fn family() -> &'static str {
    iteron_tunables::families()
        .iter()
        .find(|family| {
            family.implementation_status == iteron_tunables::ImplementationStatus::Full
                && family.optimization.class != iteron_tunables::OptimizationClass::Pin
        })
        .unwrap()
        .id
}
pub fn install_evidence(root: &std::path::Path) {
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
pub fn request(agent: &crate::runtime::Agent) -> NativeExperimentLab {
    NativeExperimentLab::capture(
        agent,
        LabActionV1::Request {
            family: family().into(),
            value: "true".into(),
        },
    )
    .unwrap()
}
