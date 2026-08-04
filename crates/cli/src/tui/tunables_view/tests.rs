use super::*;

fn minimal_request() -> String {
    format!(
        r#"{{"schema_version":1,"registry_id":"core-tunables","registry_revision":{},"registry_digest":"{}","declared_values":[],"default_evidence":[],"activation_evidence":[],"constraint_evidence":[],"runtime":{{}}}}"#,
        core_tunables::REGISTRY_REVISION,
        core_tunables::REGISTRY_DIGEST_SHA256,
    )
}

#[test]
fn catalog_exposes_all_families_and_all_truthful_detail_fields() {
    let catalog = registry_catalog();
    assert_eq!(catalog.entries.len(), core_tunables::EXPECTED_FAMILY_COUNT);
    assert!(catalog.title.contains("simulation only"));
    for (index, entry) in catalog.entries.iter().enumerate() {
        assert_eq!(entry.family_id, core_tunables::families()[index].id);
        let labels: Vec<_> = entry.rows.iter().map(|row| row.0.as_str()).collect();
        for required in [
            "surface",
            "resolution",
            "requested",
            "effective",
            "adjustments",
            "default",
            "declared sources",
            "constraints",
            "benchmarks",
        ] {
            assert!(
                labels.contains(&required),
                "{} omitted {required}",
                entry.family_id
            );
        }
        assert!(
            entry
                .rows
                .iter()
                .all(|row| row.1.chars().count() <= MAX_FIELD_CHARS)
        );
    }
}

#[test]
fn frozen_request_failure_still_yields_a_redacted_atomic_report() {
    let request = minimal_request();
    let catalog = catalog_from_bytes(request.as_bytes()).expect("valid frozen request");
    assert!(catalog.title.contains("active resolution failed"));
    assert_eq!(catalog.entries.len(), core_tunables::EXPECTED_FAMILY_COUNT);
    assert!(
        catalog
            .entries
            .iter()
            .flat_map(|entry| &entry.rows)
            .any(|row| row.0 == "requested" && row.1.contains("<redacted>"))
    );
    assert!(
        catalog
            .entries
            .iter()
            .flat_map(|entry| &entry.rows)
            .filter(|row| { matches!(row.0.as_str(), "requested" | "effective" | "adjustments") })
            .all(|row| !row.1.contains("glm"))
    );
    let provider = catalog
        .entries
        .iter()
        .find(|entry| entry.family_id == "provider")
        .expect("provider entry");
    assert!(
        provider
            .notes
            .iter()
            .any(|note| note.contains("not the current process state"))
    );
}

#[test]
fn invalid_request_fails_closed_without_a_partial_catalog() {
    let error = catalog_from_bytes(b"{}").expect_err("invalid identity must fail");
    assert_eq!(
        error.to_string(),
        "request validation failed closed; no simulation report was produced"
    );
}

#[test]
fn workspace_loader_is_confined_and_enforces_the_resolver_input_cap() {
    let root = std::env::temp_dir().join(format!(
        "core-tunables-view-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    std::fs::write(root.join("request.json"), minimal_request()).expect("write valid request");

    let catalog = load_workspace_request(&root, "request.json").expect("load confined request");
    assert!(catalog.title.contains("active resolution failed"));
    assert_eq!(
        load_workspace_request(&root, "../request.json")
            .expect_err("parent traversal must fail")
            .to_string(),
        "request path must stay inside the workspace"
    );
    assert_eq!(
        load_workspace_request(&root, &root.join("request.json").display().to_string())
            .expect_err("absolute path must fail")
            .to_string(),
        "request path must stay inside the workspace"
    );

    std::fs::write(
        root.join("oversized.json"),
        vec![b' '; RESOLUTION_INPUT_MAX_BYTES + 1],
    )
    .expect("write oversized request");
    assert_eq!(
        load_workspace_request(&root, "oversized.json")
            .expect_err("oversized request must fail")
            .to_string(),
        "request exceeds the resolver's 1 MiB input cap"
    );
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}
