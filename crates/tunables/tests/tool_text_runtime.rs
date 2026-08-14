use iteron_tunables::{
    ArtifactOverride, MAX_ARTIFACT_TEXT_BYTES, ModuleId, PROFILE_DOCUMENT_SCHEMA_VERSION,
    ProfileDocument, ProfileLoadError, PromptArtifactInstallError, REGISTRY_DIGEST_SHA256,
    REGISTRY_REVISION, TOOL_TEXT_ARTIFACTS, TOOL_TEXT_REGISTRY_ID,
    install_prompt_artifact_overrides, surface, tool_description, tool_text_registry_digest_sha256,
    validate_profile,
};

fn document(artifacts: Vec<ArtifactOverride>) -> ProfileDocument {
    ProfileDocument {
        schema_version: PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: "tool-text-test".to_owned(),
        registry_revision: REGISTRY_REVISION,
        registry_digest: REGISTRY_DIGEST_SHA256.to_owned(),
        param_registry_digest: None,
        module_scope: None,
        values: Vec::new(),
        params: Vec::new(),
        artifacts,
    }
}

#[test]
fn published_tool_rows_are_stable_unique_and_exported_with_an_exact_digest() {
    let ids: std::collections::BTreeSet<_> = TOOL_TEXT_ARTIFACTS.iter().map(|row| row.id).collect();
    let names: std::collections::BTreeSet<_> =
        TOOL_TEXT_ARTIFACTS.iter().map(|row| row.tool).collect();
    assert_eq!(ids.len(), TOOL_TEXT_ARTIFACTS.len());
    assert_eq!(names.len(), TOOL_TEXT_ARTIFACTS.len());
    assert!(TOOL_TEXT_ARTIFACTS.iter().all(|row| {
        row.id == format!("tool/{}/description@v1", row.tool)
            && row.module == ModuleId::PromptToolDescription
            && row.overridable
            && !row.decl.is_empty()
            && !row.effect.is_empty()
    }));

    let export = surface();
    assert_eq!(export.tool_text_registry_id, TOOL_TEXT_REGISTRY_ID);
    assert_eq!(
        export.tool_text_registry_digest,
        tool_text_registry_digest_sha256()
    );
    assert_eq!(export.tool_descriptions, TOOL_TEXT_ARTIFACTS);
    assert_eq!(
        export.counts.tool_descriptions,
        export.tool_descriptions.len()
    );
    assert_eq!(
        export.counts.tool_descriptions_overridable,
        export
            .tool_descriptions
            .iter()
            .filter(|row| row.overridable)
            .count()
    );
}

#[test]
fn profile_accepts_exact_builtins_and_rejects_unknown_duplicate_blank_and_oversized_text() {
    let known = TOOL_TEXT_ARTIFACTS[0].id;
    assert!(
        validate_profile(&document(vec![ArtifactOverride {
            artifact: known.to_owned(),
            text: "replacement".to_owned(),
        }]))
        .is_ok()
    );

    for unknown in [
        "tool/not_a_builtin/description@v1",
        "tool/mcp__remote/description@v1",
        "tool/server__runtime/description@v1",
    ] {
        assert!(matches!(
            validate_profile(&document(vec![ArtifactOverride {
                artifact: unknown.to_owned(),
                text: "external text".to_owned(),
            }])),
            Err(ProfileLoadError::UnknownArtifact(id)) if id == unknown
        ));
    }

    assert!(matches!(
        validate_profile(&document(vec![
            ArtifactOverride {
                artifact: known.to_owned(),
                text: "first".to_owned(),
            },
            ArtifactOverride {
                artifact: known.to_owned(),
                text: "second".to_owned(),
            },
        ])),
        Err(ProfileLoadError::DuplicateArtifact(_))
    ));
    assert!(matches!(
        validate_profile(&document(vec![ArtifactOverride {
            artifact: known.to_owned(),
            text: " \n\t".to_owned(),
        }])),
        Err(ProfileLoadError::EmptyArtifact(_))
    ));
    assert!(matches!(
        validate_profile(&document(vec![ArtifactOverride {
            artifact: known.to_owned(),
            text: "x".repeat(MAX_ARTIFACT_TEXT_BYTES + 1),
        }])),
        Err(ProfileLoadError::ArtifactTooLarge { .. })
    ));
}

#[test]
fn per_tool_override_wins_aggregate_and_installation_is_single_shot() {
    let exact = "tool/read_file/description@v1";
    assert!(matches!(
        install_prompt_artifact_overrides([
            (exact.to_owned(), "first".to_owned()),
            (exact.to_owned(), "duplicate".to_owned()),
        ]),
        Err(PromptArtifactInstallError::DuplicateArtifact(_))
    ));
    assert!(matches!(
        install_prompt_artifact_overrides([(
            "tool/mcp__runtime/description@v1".to_owned(),
            "external".to_owned(),
        )]),
        Err(PromptArtifactInstallError::UnknownArtifact(_))
    ));

    assert_eq!(
        install_prompt_artifact_overrides([
            (
                "prompt/tool_description@v1".to_owned(),
                "aggregate".to_owned(),
            ),
            (exact.to_owned(), "read-specific".to_owned()),
        ])
        .unwrap(),
        2
    );
    assert_eq!(
        tool_description("read_file", "compiled read"),
        "read-specific"
    );
    assert_eq!(tool_description("list_dir", "compiled list"), "aggregate");
    assert_eq!(
        tool_description("mcp__runtime", "untrusted external description"),
        "untrusted external description"
    );
    assert!(matches!(
        install_prompt_artifact_overrides([(exact.to_owned(), "later".to_owned())]),
        Err(PromptArtifactInstallError::AlreadyInstalled)
    ));
}
