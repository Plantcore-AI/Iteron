use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const MEMBERS: &[(&str, &str)] = &[
    ("crates/agents", "core-agents"),
    ("crates/cli", "core-cli"),
    ("crates/ctx", "core-ctx"),
    ("crates/eval", "core-eval"),
    ("crates/evolve", "core-evolve"),
    ("crates/kernel", "core-kernel"),
    ("crates/mcp", "core-mcp"),
    ("crates/obs", "core-obs"),
    ("crates/protocol", "core-protocol"),
    ("crates/provider", "core-provider"),
    ("crates/record", "core-record"),
    ("crates/sandbox", "core-sandbox"),
    ("crates/sched", "core-sched"),
    ("crates/tools", "core-tools"),
    ("crates/verify", "core-verify"),
    ("crates/workflow", "core-workflow"),
    ("xtask", "core-xtask"),
];

pub(super) fn validate(root: &Path) -> Result<()> {
    reject_repository_cargo_config(root)?;
    let workspace = read_toml(root, "Cargo.toml")?;
    validate_workspace(&workspace)?;
    validate_dependency_authority(root, &workspace)?;
    validate_member_identities_and_paths(root)?;
    validate_targets_and_internal_paths(root)?;
    validate_managed_modules(root)
}

fn reject_repository_cargo_config(root: &Path) -> Result<()> {
    for relative in [".cargo/config", ".cargo/config.toml"] {
        match std::fs::symlink_metadata(root.join(relative)) {
            Ok(_) => bail!(
                "schema dependency authority does not admit repository-local Cargo config '{relative}'"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect repository Cargo config '{relative}'")
                });
            }
        }
    }
    Ok(())
}

fn validate_workspace(workspace: &toml::Value) -> Result<()> {
    let workspace = workspace
        .get("workspace")
        .and_then(toml::Value::as_table)
        .context("root Cargo.toml lacks [workspace]")?;
    if workspace.get("resolver").and_then(toml::Value::as_str) != Some("3")
        || workspace.get("exclude").is_some()
    {
        bail!("schema workspace must retain resolver 3 without excluded package redirects");
    }
    let member_values = workspace
        .get("members")
        .and_then(toml::Value::as_array)
        .context("schema workspace lacks explicit members")?;
    let members = member_values
        .iter()
        .map(|member| {
            member
                .as_str()
                .map(str::to_owned)
                .context("workspace member is not a string")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = MEMBERS
        .iter()
        .map(|(member, _)| (*member).to_owned())
        .collect::<BTreeSet<_>>();
    if member_values.len() != expected.len() || members != expected {
        bail!("schema workspace membership differs from its trusted crate graph");
    }
    Ok(())
}

fn validate_member_identities_and_paths(root: &Path) -> Result<()> {
    let names = MEMBERS
        .iter()
        .map(|(member, package)| ((*package).to_owned(), (*member).to_owned()))
        .collect::<BTreeMap<_, _>>();
    for (member, package_name) in MEMBERS {
        let manifest = format!("{member}/Cargo.toml");
        let value = read_toml(root, &manifest)?;
        let package = value
            .get("package")
            .and_then(toml::Value::as_table)
            .with_context(|| format!("workspace member '{manifest}' lacks [package]"))?;
        if package.get("name").and_then(toml::Value::as_str) != Some(*package_name) {
            bail!("workspace member '{member}' changed its canonical package identity");
        }
        for dependencies in dependency_tables(&value) {
            for (dependency_name, dependency) in dependencies {
                let claimed_package = dependency
                    .as_table()
                    .and_then(|table| table.get("package"))
                    .and_then(toml::Value::as_str);
                if claimed_package.is_some_and(|name| name.starts_with("core-")) {
                    bail!(
                        "workspace member '{member}' aliases internal package '{claimed_package:?}'"
                    );
                }
                if !dependency_name.starts_with("core-") {
                    continue;
                }
                let target = names.get(dependency_name).with_context(|| {
                    format!(
                        "workspace member '{member}' names unknown internal dependency '{dependency_name}'"
                    )
                })?;
                let table = dependency.as_table().with_context(|| {
                    format!(
                        "workspace member '{member}' internal dependency '{dependency_name}' is not a path table"
                    )
                })?;
                let expected_path = relative_member_path(member, target)?;
                if table.len() != 1
                    || table.get("path").and_then(toml::Value::as_str)
                        != Some(expected_path.as_str())
                {
                    bail!(
                        "workspace member '{member}' redirects internal dependency '{dependency_name}'"
                    );
                }
            }
        }
    }
    Ok(())
}

fn dependency_tables(manifest: &toml::Value) -> Vec<&toml::value::Table> {
    let mut tables = ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|kind| manifest.get(*kind).and_then(toml::Value::as_table))
        .collect::<Vec<_>>();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            tables.extend(
                ["dependencies", "dev-dependencies", "build-dependencies"]
                    .iter()
                    .filter_map(|kind| target.get(*kind).and_then(toml::Value::as_table)),
            );
        }
    }
    tables
}

fn relative_member_path(from: &str, to: &str) -> Result<String> {
    let from = Path::new(from)
        .components()
        .map(component_name)
        .collect::<Result<Vec<_>>>()?;
    let to = Path::new(to)
        .components()
        .map(component_name)
        .collect::<Result<Vec<_>>>()?;
    let shared = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut components = vec!["..".to_owned(); from.len().saturating_sub(shared)];
    components.extend(to[shared..].iter().cloned());
    Ok(components.join("/"))
}

fn component_name(component: Component<'_>) -> Result<String> {
    match component {
        Component::Normal(name) => name
            .to_str()
            .map(str::to_owned)
            .context("workspace member path is not UTF-8"),
        _ => bail!("workspace member path is not a normalized relative path"),
    }
}

fn validate_dependency_authority(root: &Path, workspace: &toml::Value) -> Result<()> {
    let dependencies = workspace
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .context("workspace Cargo.toml lacks [workspace.dependencies]")?;
    let serde = dependencies
        .get("serde")
        .and_then(toml::Value::as_table)
        .context("workspace serde dependency is not an explicit table")?;
    if serde.len() != 2
        || serde.get("version").and_then(toml::Value::as_str) != Some("1")
        || serde
            .get("features")
            .and_then(toml::Value::as_array)
            .is_none_or(|features| features.len() != 1 || features[0].as_str() != Some("derive"))
    {
        bail!("workspace serde authority must be exact crates.io serde v1 with derive only");
    }
    if dependencies.get("serde_json").and_then(toml::Value::as_str) != Some("1") {
        bail!("workspace serde_json authority must be exact crates.io serde_json v1");
    }
    if workspace.get("patch").is_some() || workspace.get("replace").is_some() {
        bail!("schema dependency authority does not admit Cargo patch/replace tables");
    }
    for (manifest, names) in [
        ("crates/protocol/Cargo.toml", &["serde", "serde_json"][..]),
        ("crates/record/Cargo.toml", &["serde", "serde_json"][..]),
        ("crates/kernel/Cargo.toml", &["serde", "serde_json"][..]),
        ("crates/eval/Cargo.toml", &["serde", "serde_json"][..]),
        ("crates/cli/Cargo.toml", &["serde", "serde_json"][..]),
    ] {
        let package = read_toml(root, manifest)?;
        let dependencies = package
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .with_context(|| format!("schema crate manifest '{manifest}' lacks dependencies"))?;
        for name in names {
            let dependency = dependencies
                .get(*name)
                .and_then(toml::Value::as_table)
                .with_context(|| {
                    format!("schema crate manifest '{manifest}' lacks table dependency '{name}'")
                })?;
            if dependency.len() != 1
                || dependency.get("workspace").and_then(toml::Value::as_bool) != Some(true)
                || target_dependency_mentions(&package, name)
            {
                bail!(
                    "schema crate manifest '{manifest}' must inherit exact workspace dependency '{name}'"
                );
            }
        }
    }
    Ok(())
}

fn validate_targets_and_internal_paths(root: &Path) -> Result<()> {
    for (member, package_name) in MEMBERS {
        let manifest = format!("{member}/Cargo.toml");
        let value = read_toml(root, &manifest)?;
        validate_package_metadata(&value, &manifest, package_name)?;
        reject_implicit_targets(root, member, package_name, &value)?;
    }
    validate_bin_target(root, "crates/cli/Cargo.toml", "core", "src/main.rs")?;
    validate_bin_target(root, "crates/eval/Cargo.toml", "core-eval", "src/main.rs")?;
    Ok(())
}

fn validate_package_metadata(
    value: &toml::Value,
    manifest: &str,
    package_name: &str,
) -> Result<()> {
    let package = value
        .get("package")
        .and_then(toml::Value::as_table)
        .with_context(|| format!("managed manifest '{manifest}' lacks [package]"))?;
    if package.get("name").and_then(toml::Value::as_str) != Some(package_name)
        || package.get("build").is_some()
        || package.get("autolib").is_some()
        || package.get("autobins").is_some()
        || package.get("default-run").is_some()
        || package.get("workspace").is_some()
    {
        bail!("managed manifest '{manifest}' redirects its package/build/lib authority");
    }
    if value.get("lib").is_some() {
        bail!("managed manifest '{manifest}' redirects its library source");
    }
    Ok(())
}

fn reject_implicit_targets(
    root: &Path,
    member: &str,
    package_name: &str,
    manifest: &toml::Value,
) -> Result<()> {
    let has_lib = !matches!(package_name, "core-cli" | "core-xtask");
    let has_bin = matches!(package_name, "core-cli" | "core-eval" | "core-xtask");
    if has_lib {
        let source = format!("{member}/src/lib.rs");
        let _ = read_bounded(root, &source, MAX_SOURCE_BYTES)?;
    } else if std::fs::symlink_metadata(root.join(member).join("src/lib.rs")).is_ok() {
        bail!("managed binary package '{manifest}' gains an implicit library target");
    }
    if has_bin {
        let source = format!("{member}/src/main.rs");
        let _ = read_bounded(root, &source, MAX_SOURCE_BYTES)?;
    } else if std::fs::symlink_metadata(root.join(member).join("src/main.rs")).is_ok() {
        bail!("managed library package '{member}' gains an implicit binary target");
    }
    for relative in ["build.rs", "src/bin"] {
        if std::fs::symlink_metadata(root.join(member).join(relative)).is_ok() {
            bail!("managed package '{member}' gains implicit Cargo target '{relative}'");
        }
    }
    let explicit_bin = manifest.get("bin");
    if matches!(package_name, "core-cli" | "core-eval") {
        if explicit_bin.is_none() {
            bail!("managed package '{member}' loses its explicit canonical binary target");
        }
    } else if explicit_bin.is_some() {
        bail!("managed package '{member}' gains an alternate binary target");
    }
    Ok(())
}

fn validate_bin_target(root: &Path, manifest: &str, name: &str, path: &str) -> Result<()> {
    let value = read_toml(root, manifest)?;
    let bins = value
        .get("bin")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("managed manifest '{manifest}' lacks its explicit binary"))?;
    let [bin] = bins.as_slice() else {
        bail!("managed manifest '{manifest}' must declare exactly one binary");
    };
    let bin = bin
        .as_table()
        .context("managed binary target is not a table")?;
    if bin.len() != 2
        || bin.get("name").and_then(toml::Value::as_str) != Some(name)
        || bin.get("path").and_then(toml::Value::as_str) != Some(path)
    {
        bail!("managed manifest '{manifest}' redirects its binary source");
    }
    Ok(())
}

fn validate_managed_modules(root: &Path) -> Result<()> {
    for (source, module, public) in [
        ("crates/kernel/src/lib.rs", "diagnostics", true),
        ("crates/eval/src/lib.rs", "contract", true),
        ("crates/eval/src/lib.rs", "runner", true),
        ("crates/eval/src/lib.rs", "strict_json", false),
        ("crates/cli/src/main.rs", "output", false),
    ] {
        let bytes = read_bounded(root, source, MAX_SOURCE_BYTES)?;
        let source_text = std::str::from_utf8(&bytes)
            .with_context(|| format!("managed crate root '{source}' is not UTF-8"))?;
        validate_module_source(source_text, source, module, public)?;
    }
    Ok(())
}

fn validate_module_source(
    source_text: &str,
    source: &str,
    module: &str,
    public: bool,
) -> Result<()> {
    let file = syn::parse_file(source_text)
        .with_context(|| format!("managed crate root '{source}' does not parse"))?;
    if file
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("managed crate root '{source}' has an active crate attribute");
    }
    let mut modules = file.items.iter().filter_map(|item| match item {
        syn::Item::Mod(item) if item.ident == module => Some(item),
        _ => None,
    });
    let declaration = modules
        .next()
        .with_context(|| format!("managed crate root '{source}' lacks module '{module}'"))?;
    if modules.next().is_some()
        || declaration.content.is_some()
        || !declaration.attrs.is_empty()
        || matches!(declaration.vis, syn::Visibility::Public(_)) != public
    {
        bail!(
            "managed module '{module}' in '{source}' must use one unmodified default-path declaration"
        );
    }
    Ok(())
}

fn target_dependency_mentions(manifest: &toml::Value, name: &str) -> bool {
    manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| {
            targets.values().any(|target| {
                ["dependencies", "dev-dependencies", "build-dependencies"]
                    .iter()
                    .any(|kind| {
                        target
                            .get(kind)
                            .and_then(toml::Value::as_table)
                            .is_some_and(|dependencies| dependencies.contains_key(name))
                    })
            })
        })
}

fn read_toml(root: &Path, relative: &str) -> Result<toml::Value> {
    let bytes = read_bounded(root, relative, MAX_SOURCE_BYTES)?;
    let source = std::str::from_utf8(&bytes)
        .with_context(|| format!("schema dependency manifest '{relative}' is not UTF-8"))?;
    toml::from_str(source)
        .with_context(|| format!("schema dependency manifest '{relative}' is invalid TOML"))
}

#[cfg(test)]
#[path = "schema_compat_rust_authority_tests.rs"]
mod tests;
