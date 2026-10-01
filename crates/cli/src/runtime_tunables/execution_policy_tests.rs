use super::{RoleSpecificModelMapIdentity, admitted_role_model_routes_with_routes};
use iteron_agents::AgentCatalog;

#[test]
fn configured_role_models_require_exact_unambiguous_native_identity() {
    let root = std::env::temp_dir().join(format!(
        "iteron-role-native-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let home = root.join("home");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(home.join(".iteron/agents")).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    for (role, model) in [
        ("reviewer", "model-other"),
        ("unbound", "missing-model"),
        ("primary", "model-primary"),
    ] {
        std::fs::write(home.join(".iteron/agents").join(format!("{role}.md")),
            format!("---\nname: {role}\ndescription: Bounded investigation\nmodel: {model}\ntools: [read_file]\n---\nInspect one file.\n")).unwrap();
    }
    let catalog = AgentCatalog::discover(&home, &workspace);
    let held = [("other-provider", "model-other")];
    let admitted = admitted_role_model_routes_with_routes(
        &catalog,
        "primary-provider",
        "model-primary",
        &held,
    )
    .unwrap();
    assert_eq!(
        admitted.get("reviewer").map(String::as_str),
        Some("other-provider:model-other")
    );
    assert_eq!(
        admitted.get("primary").map(String::as_str),
        Some("primary-provider:model-primary")
    );
    assert!(!admitted.contains_key("unbound"));
    let identity = RoleSpecificModelMapIdentity::from_routes(&admitted).unwrap();
    assert_eq!(
        identity
            .validate_owner_with_routes(&catalog, "primary-provider", "model-primary", &held)
            .unwrap(),
        admitted
    );
    assert!(
        identity
            .validate_owner_with_routes(&catalog, "primary-provider", "model-primary", &[])
            .is_err()
    );
    assert!(
        identity
            .validate_owner_with_routes(
                &catalog,
                "primary-provider",
                "model-primary",
                &[("wrong-provider", "model-other")]
            )
            .is_err()
    );
    let ambiguous = [
        ("other-provider", "model-other"),
        ("third-provider", "model-other"),
    ];
    assert!(
        !admitted_role_model_routes_with_routes(
            &catalog,
            "primary-provider",
            "model-primary",
            &ambiguous
        )
        .unwrap()
        .contains_key("reviewer")
    );
    assert!(
        identity
            .validate_owner_with_routes(&catalog, "primary-provider", "model-primary", &ambiguous)
            .is_err()
    );
    let duplicate_primary = [("fallback-provider", "model-primary")];
    assert_eq!(
        admitted_role_model_routes_with_routes(
            &catalog,
            "primary-provider",
            "model-primary",
            &duplicate_primary
        )
        .unwrap()
        .get("primary")
        .map(String::as_str),
        Some("primary-provider:model-primary")
    );
    let over =
        vec![("other-provider", "model-other"); iteron_provider::catalog::MAX_RESOLVED_ROUTES];
    assert!(
        admitted_role_model_routes_with_routes(
            &catalog,
            "primary-provider",
            "model-primary",
            &over
        )
        .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}
