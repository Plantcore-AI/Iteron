use iteron_tunables::{
    PromptArtifactInstallError, install_prompt_artifact_overrides, installed_prompt_artifact_count,
    prompt_artifact,
};

#[test]
fn a_prompt_artifact_replaces_model_text_and_installs_once() {
    assert_eq!(prompt_artifact("prompt/planner@v1", "compiled"), "compiled");
    assert!(matches!(
        install_prompt_artifact_overrides([("prompt/planner@v1".to_owned(), "  ".to_owned(),)]),
        Err(PromptArtifactInstallError::EmptyArtifact(_))
    ));
    assert_eq!(
        install_prompt_artifact_overrides([(
            "prompt/planner@v1".to_owned(),
            "replacement".to_owned(),
        )])
        .expect("published artifact installs"),
        1
    );
    assert_eq!(installed_prompt_artifact_count(), 1);
    assert_eq!(
        prompt_artifact("prompt/planner@v1", "compiled"),
        "replacement"
    );
    assert!(
        install_prompt_artifact_overrides([("prompt/planner@v1".to_owned(), "second".to_owned(),)])
            .is_err(),
        "mid-run prompt replacement would destroy reproducibility"
    );
}
