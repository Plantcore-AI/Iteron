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

/// The rule this pins is directional, and the direction is the whole point.
///
/// It replaced an exact-equality check that made the crate graph unable to grow at all: this
/// validator is built from the merge base, so comparing the candidate's member set for equality
/// rejected every crate-adding pull request no matter what it contained, and no ordering of
/// policy-first or code-first commits could pass both this check and the candidate's own. Every
/// member present before that fix entered in the initial commit; none had ever passed through this
/// gate. Loosening it was therefore correct, but only in one direction, and nothing was pinning
/// which one -- so a later reader could restore equality, or widen additions, and no test would go
/// red. That is what this is for.
#[test]
fn the_trusted_crate_graph_may_grow_but_never_shrink_and_only_into_canonical_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let workspace = read_toml(root, "Cargo.toml").unwrap();

    let with_member = |member: &str| {
        let mut candidate = workspace.clone();
        candidate["workspace"]["members"]
            .as_array_mut()
            .unwrap()
            .push(toml::Value::String(member.into()));
        candidate
    };

    // Growth is allowed, which is the half that was impossible before.
    validate_workspace(&with_member("crates/newly-added")).unwrap();
    validate_workspace(&with_member("crates/a1")).unwrap();

    // A path is not merely "starts with crates/": it is one canonical slug directly beneath it.
    // A nested path would let an added member sit inside another crate's tree, and `..` would let
    // it leave the repository altogether -- both were reachable when the only check was a
    // `starts_with` plus a literal `..` scan.
    for rejected in [
        "vendor/evil",
        "crates",
        "crates/",
        "crates/nested/deeper",
        "crates/../../evil",
        "crates/..",
        "crates/Capitalised",
        "crates/1leading-digit",
        "crates/trailing-",
        "crates/double--hyphen",
        "crates/under_score",
        "crates/.hidden",
    ] {
        assert!(
            validate_workspace(&with_member(rejected)).is_err(),
            "accepted non-canonical added member `{rejected}`"
        );
    }

    // Shrinking stays refused in both of its forms. A dropped crate takes its boundary, its owners
    // and its checks with it, and a rename is a drop plus an add.
    let mut removed = workspace.clone();
    removed["workspace"]["members"]
        .as_array_mut()
        .unwrap()
        .retain(|member| member.as_str() != Some("crates/kernel"));
    assert!(validate_workspace(&removed).is_err());

    let mut renamed = workspace.clone();
    for member in renamed["workspace"]["members"].as_array_mut().unwrap() {
        if member.as_str() == Some("crates/kernel") {
            *member = toml::Value::String("crates/kernel-renamed".into());
        }
    }
    assert!(
        validate_workspace(&renamed).is_err(),
        "a rename is a removal wearing an addition's clothes"
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
name = "iteron-protocol"
"#,
    )
    .unwrap();
    validate_package_metadata(&base, "Cargo.toml", "iteron-protocol").unwrap();
    for addition in [
        "build = \"evil.rs\"",
        "autobins = false",
        "autolib = false",
        "default-run = \"evil\"",
        "workspace = \"../evil\"",
    ] {
        let source = format!("[package]\nname = \"iteron-protocol\"\n{addition}\n");
        let value: toml::Value = toml::from_str(&source).unwrap();
        assert!(validate_package_metadata(&value, "Cargo.toml", "iteron-protocol").is_err());
    }
    let redirected: toml::Value = toml::from_str(
        r#"[package]
name = "iteron-protocol"
[lib]
path = "evil.rs"
"#,
    )
    .unwrap();
    assert!(validate_package_metadata(&redirected, "Cargo.toml", "iteron-protocol").is_err());
}

#[test]
fn optional_evolve_binary_has_one_exact_canonical_declaration() {
    let exact: toml::Value = toml::from_str(
        r#"[[bin]]
name = "evolve-transcript"
path = "src/main.rs"
"#,
    )
    .unwrap();
    validate_bin_declaration(
        &exact,
        "crates/evolve/Cargo.toml",
        "evolve-transcript",
        "src/main.rs",
    )
    .unwrap();

    for invalid in [
        r#"[[bin]]
name = "alternate"
path = "src/main.rs"
"#,
        r#"[[bin]]
name = "evolve-transcript"
path = "src/bin/transcript.rs"
"#,
        r#"[[bin]]
name = "evolve-transcript"
path = "src/main.rs"

[[bin]]
name = "alternate"
path = "src/alternate.rs"
"#,
        r#"[[bin]]
name = "evolve-transcript"
path = "src/main.rs"
required-features = ["alternate"]
"#,
    ] {
        let value: toml::Value = toml::from_str(invalid).unwrap();
        assert!(
            validate_bin_declaration(
                &value,
                "crates/evolve/Cargo.toml",
                "evolve-transcript",
                "src/main.rs",
            )
            .is_err(),
            "accepted non-canonical declaration:\n{invalid}"
        );
    }
}

#[test]
fn repository_cargo_config_admits_only_windows_stack_size_rustflags() {
    let valid: toml::Value = toml::from_str(
        r#"[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/STACK:8388608"]

[target.aarch64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/STACK:8388608"]
"#,
    )
    .unwrap();
    validate_cargo_config_contents(&valid).unwrap();

    for invalid in [
        r#"[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/STACK:4194304"]
"#,
        r#"[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=/STACK:8388608"]
"#,
        r#"[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "link-arg=/STACK:8388608"]
build = "custom.rs"
"#,
        r#"[target.x86_64-pc-windows-msvc]
linker = "lld"
"#,
    ] {
        let value: toml::Value = toml::from_str(invalid).unwrap();
        assert!(
            validate_cargo_config_contents(&value).is_err(),
            "accepted non-canonical Cargo config:\n{invalid}"
        );
    }
}
