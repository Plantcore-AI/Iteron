use super::*;

#[test]
fn workspace_members_and_internal_relative_paths_are_exact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let workspace = read_toml(root, "Cargo.toml").unwrap();
    validate_workspace(&workspace).unwrap();
    let mut missing = workspace.clone();
    missing["workspace"]["members"]
        .as_array_mut()
        .unwrap()
        .retain(|member| member.as_str() != Some("crates/protocol"));
    assert!(validate_workspace(&missing).is_err());
    let mut duplicated = workspace.clone();
    duplicated["workspace"]["members"]
        .as_array_mut()
        .unwrap()
        .push(toml::Value::String("crates/protocol".into()));
    assert!(validate_workspace(&duplicated).is_err());
    assert_eq!(
        relative_member_path("crates/cli", "crates/protocol").unwrap(),
        "../protocol"
    );
    assert_eq!(
        relative_member_path("xtask", "crates/agents").unwrap(),
        "../crates/agents"
    );
}

#[test]
fn managed_module_declarations_reject_cfg_path_inline_and_decoys() {
    validate_module_source("mod output;", "main.rs", "output", false).unwrap();
    assert!(
        validate_module_source(
            "#[path = \"evil.rs\"] mod output;",
            "main.rs",
            "output",
            false,
        )
        .is_err()
    );
    assert!(
        validate_module_source("#[cfg(any())] mod output;", "main.rs", "output", false,).is_err()
    );
    assert!(validate_module_source("mod output {}", "main.rs", "output", false).is_err());
    assert!(
        validate_module_source("mod output; mod output_decoy;", "main.rs", "output", false,)
            .is_ok()
    );
    assert!(validate_module_source("mod output; mod output;", "main.rs", "output", false).is_err());
}

#[test]
fn managed_package_metadata_rejects_build_autobin_and_target_redirects() {
    let base: toml::Value = toml::from_str(
        r#"[package]
name = "core-protocol"
"#,
    )
    .unwrap();
    validate_package_metadata(&base, "Cargo.toml", "core-protocol").unwrap();
    for addition in [
        "build = \"evil.rs\"",
        "autobins = false",
        "autolib = false",
        "default-run = \"evil\"",
        "workspace = \"../evil\"",
    ] {
        let source = format!("[package]\nname = \"core-protocol\"\n{addition}\n");
        let value: toml::Value = toml::from_str(&source).unwrap();
        assert!(validate_package_metadata(&value, "Cargo.toml", "core-protocol").is_err());
    }
    let redirected: toml::Value = toml::from_str(
        r#"[package]
name = "core-protocol"
[lib]
path = "evil.rs"
"#,
    )
    .unwrap();
    assert!(validate_package_metadata(&redirected, "Cargo.toml", "core-protocol").is_err());
}
