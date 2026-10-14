use super::*;

static NEXT_CARGO_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct CargoIdentityFixture(std::path::PathBuf);

impl CargoIdentityFixture {
    fn current() -> Self {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = Self(std::env::temp_dir().join(format!(
            "iteron-cargo-authority-{}-{nonce}-{}",
            std::process::id(),
            NEXT_CARGO_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )));
        std::fs::create_dir(&fixture.0).unwrap();
        std::fs::copy(source.join("Cargo.toml"), fixture.0.join("Cargo.toml")).unwrap();
        // These are the real current manifests, not a synthetic graph that drops target/dev edges.
        for (member, _) in MEMBERS {
            std::fs::create_dir_all(fixture.0.join(member)).unwrap();
            std::fs::copy(
                source.join(member).join("Cargo.toml"),
                fixture.0.join(member).join("Cargo.toml"),
            )
            .unwrap();
        }
        fixture
    }

    fn member(&self, member: &str) -> toml::Value {
        read_toml(&self.0, &format!("{member}/Cargo.toml")).unwrap()
    }

    fn write_member(&self, member: &str, manifest: &toml::Value) {
        std::fs::write(
            self.0.join(member).join("Cargo.toml"),
            toml::to_string(manifest).unwrap(),
        )
        .unwrap();
    }
}

impl Drop for CargoIdentityFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_sdk_identity_and_existing_internal_fixture_edges_are_admitted_exactly() {
    let fixture = CargoIdentityFixture::current();
    let identities = workspace_member_identities(&fixture.0).unwrap();
    assert!(identities.contains(&("crates/extension-sdk".into(), "iteron-extension-sdk".into(),)));
    validate_member_identities_and_paths(&fixture.0).unwrap();

    let mut sdk = fixture.member("crates/extension-sdk");
    sdk["package"]["name"] = "iteron-sdk-replacement".into();
    fixture.write_member("crates/extension-sdk", &sdk);
    assert!(validate_member_identities_and_paths(&fixture.0).is_err());

    let mut missing = read_toml(&fixture.0, "Cargo.toml").unwrap();
    missing["workspace"]["members"]
        .as_array_mut()
        .unwrap()
        .retain(|member| member.as_str() != Some("crates/extension-sdk"));
    assert!(validate_workspace(&missing).is_err());
}

#[test]
fn canonical_added_packages_use_the_actual_iteron_namespace() {
    validate_added_package_name("crates/newly-added", "iteron-newly-added").unwrap();
    for rejected in [
        "core-newly-added",
        "foreign-newly-added",
        "iteron-",
        "iteron-Capitalised",
        "iteron-double--hyphen",
        "iteron-under_score",
        "iteron-trailing-",
    ] {
        assert!(validate_added_package_name("crates/newly-added", rejected).is_err());
    }
}

#[test]
fn real_internal_dependency_aliases_and_redirects_are_refused_in_every_cargo_scope() {
    let fixture = CargoIdentityFixture::current();
    let original = fixture.member("crates/cli");
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        for target_specific in [false, true] {
            let header = if target_specific {
                format!("[target.'cfg(windows)'.{kind}]")
            } else {
                format!("[{kind}]")
            };
            for dependency in [
                "iteron-protocol = { path = \"../record\" }",
                "iteron-protocol = { path = \"../protocol/../record\" }",
                "iteron-protocol = { path = \"../../outside\" }",
                "iteron-protocol = \"1\"",
                "iteron-protocol = { path = \"../protocol\", version = \"1\" }",
                "iteron-protocol = { path = \"../protocol\", git = \"https://example.invalid/replacement\" }",
                "iteron-protocol = { path = \"../protocol\", optional = true }",
                "iteron-protocol = { path = \"../protocol\", default-features = false }",
                "iteron-protocol = { path = \"../protocol\", package = \"iteron-protocol\" }",
                "unrelated = { path = \"../protocol\", package = \"iteron-protocol\" }",
                "iteron_protocol = { path = \"../protocol\" }",
                "iteron_protocol = \"1\"",
                "unrelated = { version = \"1\", package = \"iteron_protocol\" }",
                "replacement = { path = \"../../outside\" }",
                "iteron-unknown = { path = \"../protocol\" }",
            ] {
                let modified: toml::Value =
                    toml::from_str(&format!("{header}\n{dependency}\n")).unwrap();
                let mut manifest = original.clone();
                let section = if target_specific { "target" } else { kind };
                manifest
                    .as_table_mut()
                    .unwrap()
                    .insert(section.into(), modified[section].clone());
                fixture.write_member("crates/cli", &manifest);
                assert!(
                    validate_member_identities_and_paths(&fixture.0).is_err(),
                    "accepted redirected/aliased actual graph: {header} {dependency}",
                );
            }
        }
    }
}

#[test]
fn existing_fixture_features_cannot_move_into_runtime_build_or_target_dependencies() {
    let fixture = CargoIdentityFixture::current();
    for (member, dependency, feature) in [
        ("crates/extension-sdk", "iteron-tools", "test-helper"),
        ("crates/cli", "iteron-tools", "test-helper"),
        ("crates/cli", "iteron-record", "test-fixtures"),
        ("crates/record", "iteron-tunables", "test-fixtures"),
    ] {
        let original = fixture.member(member);
        let admitted = original["dev-dependencies"][dependency].clone();
        assert_eq!(admitted["features"][0].as_str(), Some(feature));
        for header in [
            "[dependencies]",
            "[build-dependencies]",
            "[target.'cfg(windows)'.dev-dependencies]",
        ] {
            let mut modified: toml::Value = toml::from_str(&format!(
                "{header}\n{dependency} = {{ path = \"../tools\" }}\n"
            ))
            .unwrap();
            let section = if header.contains("target") {
                modified["target"]["cfg(windows)"]["dev-dependencies"][dependency] =
                    admitted.clone();
                "target"
            } else if header.contains("build") {
                modified["build-dependencies"][dependency] = admitted.clone();
                "build-dependencies"
            } else {
                modified["dependencies"][dependency] = admitted.clone();
                "dependencies"
            };
            let mut manifest = original.clone();
            manifest
                .as_table_mut()
                .unwrap()
                .insert(section.into(), modified[section].clone());
            fixture.write_member(member, &manifest);
            assert!(validate_member_identities_and_paths(&fixture.0).is_err());
        }
        for invalid in [
            toml::Value::String(feature.into()),
            toml::Value::Array(Vec::new()),
            toml::Value::Array(vec!["unapproved-fixture".into()]),
            toml::Value::Array(vec![feature.into(), feature.into()]),
        ] {
            let mut manifest = original.clone();
            manifest["dev-dependencies"][dependency]["features"] = invalid;
            fixture.write_member(member, &manifest);
            assert!(validate_member_identities_and_paths(&fixture.0).is_err());
        }
        fixture.write_member(member, &original);
        validate_member_identities_and_paths(&fixture.0).unwrap();
    }
}

#[test]
fn malformed_dependency_scopes_cannot_skip_internal_authority_validation() {
    for source in [
        "dependencies = []",
        "target = []",
        "[target]\ninvalid = []",
        "[target.'cfg(windows)']\ndev-dependencies = []",
    ] {
        let manifest: toml::Value = toml::from_str(source).unwrap();
        assert!(dependency_tables(&manifest).is_err(), "{source}");
    }
}

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
