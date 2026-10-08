use super::*;
use crate::client_effects::experiment_lab::{
    NativeExperimentLab,
    tests::{KEY, fixture, install_evidence, request},
};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn request_is_content_addressed_train_only_and_has_no_activation_surface() {
    let (root, agent) = fixture();
    let facts = request(&agent).execute().facts.unwrap();
    let mut app = App::new();
    render_facts(&mut app, facts);
    let text = app.history.blocks().last().unwrap().to_text();
    assert!(text.contains("train partition only"));
    assert!(text.contains("runtime activation"));
    let screen = crate::tui::tests::render_text(&mut app, 120, 30);
    assert!(screen.contains("experiment request"));
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn exact_frozen_fixture_renders_with_unmistakable_non_result_provenance() {
    let (root, agent) = fixture();
    install_evidence(&root);
    let facts = NativeExperimentLab::capture(
        &agent,
        LabActionV1::Compare {
            bundle_id: "evidence-bundle-v1".into(),
            trusted_public_key: KEY.into(),
        },
    )
    .unwrap()
    .execute()
    .facts
    .unwrap();
    let mut app = App::new();
    render_facts(&mut app, facts);
    let text = app.history.blocks().last().unwrap().to_text();
    assert!(text.contains("not a result"));
    assert!(text.contains("2 success"));
    assert!(text.contains("1 held out"));
    let screen = crate::tui::tests::render_text(&mut app, 120, 35);
    assert!(screen.contains("synthetic fixture"), "{screen}");
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn command_parser_keeps_existing_scope_and_rejects_traversal_and_extra_authority() {
    assert!(matches!(parse("list"), Ok(LabActionV1::List)));
    assert!(parse(&format!("compare ../outside {}", KEY)).is_err());
    assert!(parse("request").is_err());
    assert!(parse(&format!("request family {}", "x".repeat(33 * 1024))).is_err());
    assert!(parse(&format!("compare evidence {} more", KEY)).is_err());
}
