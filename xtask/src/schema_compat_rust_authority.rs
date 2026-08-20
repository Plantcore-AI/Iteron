use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

const MEMBERS: &[(&str, &str)] = &[
    ("crates/agents", "iteron-agents"),
    ("crates/changeset", "iteron-changeset"),
    ("crates/cli", "iteron-cli"),
    ("crates/ctx", "iteron-ctx"),
    ("crates/eval", "iteron-eval"),
    ("crates/evolve", "iteron-evolve"),
    ("crates/kernel", "iteron-kernel"),
    ("crates/lsp", "iteron-lsp"),
    ("crates/marketplace", "iteron-marketplace"),
    ("crates/mcp", "iteron-mcp"),
    ("crates/obs", "iteron-obs"),
    ("crates/protocol", "iteron-protocol"),
    ("crates/provider", "iteron-provider"),
    ("crates/record", "iteron-record"),
    ("crates/sandbox", "iteron-sandbox"),
    ("crates/sched", "iteron-sched"),
    ("crates/statusline", "iteron-statusline"),
    ("crates/support", "iteron-support"),
    ("crates/tools", "iteron-tools"),
    ("crates/tunables", "iteron-tunables"),
    ("crates/verify", "iteron-verify"),
    ("crates/workflow", "iteron-workflow"),
    ("xtask", "iteron-xtask"),
];

pub(super) fn validate(root: &Path) -> Result<()> {
    validate_repository_cargo_config(root)?;
    let workspace = read_toml(root, "Cargo.toml")?;
    validate_workspace(&workspace)?;
    validate_dependency_authority(root, &workspace)?;
    validate_member_identities_and_paths(root)?;
    validate_targets_and_internal_paths(root)?;
    validate_managed_modules(root)
}

fn validate_repository_cargo_config(root: &Path) -> Result<()> {
    if std::fs::symlink_metadata(root.join(".cargo/config")).is_ok() {
        bail!(
            "schema dependency authority does not admit repository-local Cargo config '.cargo/config'"
        );
    }
    let path = root.join(".cargo/config.toml");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded(root, ".cargo/config.toml", MAX_SOURCE_BYTES)?;
            let source = std::str::from_utf8(&bytes)
                .context("repository Cargo config '.cargo/config.toml' is not UTF-8")?;
            let value: toml::Value = toml::from_str(source)
                .context("repository Cargo config '.cargo/config.toml' is invalid TOML")?;
            validate_cargo_config_contents(&value)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| "cannot inspect repository Cargo config '.cargo/config.toml'");
        }
    }
    Ok(())
}

fn validate_cargo_config_contents(value: &toml::Value) -> Result<()> {
    let table = value
        .as_table()
        .context("repository Cargo config must be a TOML table")?;
    if !table.contains_key("target") || table.len() != 1 {
        bail!("repository Cargo config must contain exactly one top-level [target] table");
    }
    let target = value
        .get("target")
        .and_then(toml::Value::as_table)
        .context("repository Cargo config [target] must be a table")?;
    for (triple, settings) in target {
        if triple != "x86_64-pc-windows-msvc" && triple != "aarch64-pc-windows-msvc" {
            bail!("repository Cargo config admits only Windows MSVC targets, found '{triple}'");
        }
        let settings = settings.as_table().with_context(|| {
            format!("repository Cargo config target '{triple}' must be a table")
        })?;
        if settings.len() != 1 || !settings.contains_key("rustflags") {
            bail!("repository Cargo config target '{triple}' must contain only rustflags");
        }
        let rustflags = settings["rustflags"].as_array().with_context(|| {
            format!("repository Cargo config target '{triple}' rustflags must be an array")
        })?;
        if rustflags.len() != 2
            || rustflags[0].as_str() != Some("-C")
            || rustflags[1].as_str() != Some("link-arg=/STACK:8388608")
        {
            bail!(
                "repository Cargo config target '{triple}' rustflags are not the admitted Windows stack-size fix"
            );
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
    if member_values.len() != members.len() {
        bail!("schema workspace lists a member twice");
    }
    // Removals and renames stay forbidden: every member this binary was built to trust must still
    // be present, under the same path. That is the property worth pinning -- a crate silently
    // dropped from the graph takes its boundary, its owners, and its checks with it.
    if let Some(missing) = expected.difference(&members).next() {
        bail!("schema workspace no longer contains trusted member '{missing}'");
    }
    // Additions are permitted, because forbidding them made the graph unable to grow: this binary
    // is built from the merge base, so a compiled-in equality check rejects every crate-adding pull
    // request no matter what it contains, and there is no ordering of policy-first or code-first
    // commits that passes both this check and the candidate's own. An added member must still
    // declare itself in the cargo policy, which is owner-reviewed, and it is validated in full by
    // the candidate's own binary in the Rust lane.
    for added in members.difference(&expected) {
        validate_added_member_path(added)?;
    }
    Ok(())
}

fn validate_added_member_path(member: &str) -> Result<()> {
    let Some(crate_name) = member.strip_prefix("crates/") else {
        bail!("added workspace member '{member}' is not under crates/");
    };
    if !is_canonical_slug(crate_name) {
        bail!("added workspace member '{member}' is not a canonical direct crates/ path");
    }
    Ok(())
}

fn is_canonical_slug(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase())
        && !value.ends_with('-')
        && !value.contains("--")
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

/// Complete workspace identity table, including members this binary was not built to know about.
///
/// Added manifests are parsed by the trusted binary before any candidate binary is compiled. This
/// keeps package identity and target authority enforceable on both sides of the bootstrap boundary.
fn workspace_member_identities(root: &Path) -> Result<Vec<(String, String)>> {
    let workspace = read_toml(root, "Cargo.toml")?;
    validate_workspace(&workspace)?;
    let trusted = MEMBERS
        .iter()
        .map(|(member, _)| *member)
        .collect::<BTreeSet<_>>();
    let mut identities = MEMBERS
        .iter()
        .map(|(member, package)| ((*member).to_owned(), (*package).to_owned()))
        .collect::<Vec<_>>();
    let mut names = MEMBERS
        .iter()
        .map(|(member, package)| ((*package).to_owned(), (*member).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let members = workspace
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get("members"))
        .and_then(toml::Value::as_array)
        .context("schema workspace lacks explicit members")?;
    for member in members.iter().filter_map(toml::Value::as_str) {
        if trusted.contains(member) {
            continue;
        }
        validate_added_member_path(member)?;
        let manifest = format!("{member}/Cargo.toml");
        let value = read_toml(root, &manifest)?;
        let package_name = value
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .with_context(|| format!("added member '{manifest}' lacks a package name"))?;
        let Some(suffix) = package_name.strip_prefix("core-") else {
            bail!("added workspace member '{member}' is not an internal `core-` package");
        };
        if !is_canonical_slug(suffix) {
            bail!("added workspace member '{member}' has a non-canonical package name");
        }
        if names
            .insert(package_name.to_owned(), member.to_owned())
            .is_some()
        {
            bail!("added workspace member '{member}' collides with a trusted package name");
        }
        identities.push((member.to_owned(), package_name.to_owned()));
    }
    identities.sort();
    Ok(identities)
}

fn validate_member_identities_and_paths(root: &Path) -> Result<()> {
    let identities = workspace_member_identities(root)?;
    let names = identities
        .iter()
        .map(|(member, package)| (package.to_owned(), member.to_owned()))
        .collect::<BTreeMap<_, _>>();
    for (member, package_name) in identities {
        let manifest = format!("{member}/Cargo.toml");
        let value = read_toml(root, &manifest)?;
        let package = value
            .get("package")
            .and_then(toml::Value::as_table)
            .with_context(|| format!("workspace member '{manifest}' lacks [package]"))?;
        if package.get("name").and_then(toml::Value::as_str) != Some(package_name.as_str()) {
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
                let expected_path = relative_member_path(&member, target)?;
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
    for (member, package_name) in workspace_member_identities(root)? {
        validate_member_target(root, &member, &package_name)?;
    }
    validate_bin_targets(root, "crates/cli/Cargo.toml", &[("iteron", "src/main.rs")])?;
    validate_bin_targets(
        root,
        "crates/eval/Cargo.toml",
        &[
            ("iteron-eval", "src/main.rs"),
            ("iteron-harness", "src/iteron_harness_main.rs"),
        ],
    )?;
    validate_optional_bin_target(
        root,
        "crates/evolve/Cargo.toml",
        "evolve-transcript",
        "src/main.rs",
    )?;
    Ok(())
}

fn validate_member_target(root: &Path, member: &str, package_name: &str) -> Result<()> {
    let manifest = format!("{member}/Cargo.toml");
    let value = read_toml(root, &manifest)?;
    validate_package_metadata(&value, &manifest, package_name)?;
    reject_implicit_targets(root, member, package_name, &value)
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
    let has_lib = !matches!(package_name, "iteron-cli" | "iteron-xtask");
    let explicit_bin = manifest.get("bin");
    let has_bin = matches!(package_name, "iteron-cli" | "iteron-eval" | "iteron-xtask")
        || (package_name == "iteron-evolve" && explicit_bin.is_some());
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
    if matches!(package_name, "iteron-cli" | "iteron-eval") {
        if explicit_bin.is_none() {
            bail!("managed package '{member}' loses its explicit canonical binary target");
        }
    } else if package_name != "iteron-evolve" && explicit_bin.is_some() {
        bail!("managed package '{member}' gains an alternate binary target");
    }
    Ok(())
}

fn validate_bin_targets(root: &Path, manifest: &str, expected: &[(&str, &str)]) -> Result<()> {
    let value = read_toml(root, manifest)?;
    validate_bin_declarations(&value, manifest, expected)
}

/// Admit the transcript driver only if it is declared as the one canonical `iteron-evolve` binary.
///
/// Absence remains valid so this governance prerequisite can land before the implementation. Once
/// a candidate adds any `[[bin]]` entry, the exact target name and source path become mandatory.
fn validate_optional_bin_target(root: &Path, manifest: &str, name: &str, path: &str) -> Result<()> {
    let value = read_toml(root, manifest)?;
    if value.get("bin").is_none() {
        return Ok(());
    }
    validate_bin_declarations(&value, manifest, &[(name, path)])
}

fn validate_bin_declarations(
    value: &toml::Value,
    manifest: &str,
    expected: &[(&str, &str)],
) -> Result<()> {
    let bins = value
        .get("bin")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("managed manifest '{manifest}' lacks its explicit binary"))?;
    if bins.len() != expected.len() {
        bail!(
            "managed manifest '{manifest}' must declare exactly {} governed binary target(s)",
            expected.len()
        );
    }
    for (bin, (name, path)) in bins.iter().zip(expected) {
        let bin = bin
            .as_table()
            .context("managed binary target is not a table")?;
        if bin.len() != 2
            || bin.get("name").and_then(toml::Value::as_str) != Some(*name)
            || bin.get("path").and_then(toml::Value::as_str) != Some(*path)
        {
            bail!("managed manifest '{manifest}' redirects its binary source");
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_bin_declaration(
    value: &toml::Value,
    manifest: &str,
    name: &str,
    path: &str,
) -> Result<()> {
    validate_bin_declarations(value, manifest, &[(name, path)])
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
