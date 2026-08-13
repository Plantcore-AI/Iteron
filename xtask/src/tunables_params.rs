//! Harvest the tier-2 parameter catalog from the source declarations.
//!
//! One scanner, two entry points: `generate` writes `governance/tunables-params.json`, `check`
//! re-scans and fails when the committed catalog and the source disagree. They share the scan so
//! the two cannot drift apart the way two independent implementations would.
//!
//! What counts as a parameter: every `const` and `static` declared in a shipped crate, outside
//! test code. `xtask` is excluded on purpose — it is build tooling, not agent behaviour, and
//! exposing its constants would put the build system inside the optimization surface.

use anyhow::{Context, Result, bail};
use iteron_tunables::{ModuleId, ParamClass, ParamType};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Crates whose constants are *not* agent behaviour and are therefore out of the surface.
const EXCLUDED_CRATES: &[&str] = &["xtask"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ParamRow {
    pub id: String,
    pub module: ModuleId,
    pub class: ParamClass,
    #[serde(rename = "type")]
    pub ty: ParamType,
    pub default: String,
    #[serde(skip_serializing_if = "DomainRow::is_empty")]
    #[serde(default)]
    pub domain: DomainRow,
    pub krate: String,
    pub decl: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub(crate) struct DomainRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i128>,
}

impl DomainRow {
    fn is_empty(&self) -> bool {
        self.min.is_none() && self.max.is_none()
    }
}

#[derive(Debug, Serialize)]
struct Catalog {
    schema_version: u16,
    registry_id: String,
    revision: u16,
    params: Vec<ParamRow>,
}

pub(crate) fn generate(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let catalog = Catalog {
        schema_version: iteron_tunables::PARAM_SCHEMA_VERSION,
        registry_id: iteron_tunables::PARAM_REGISTRY_ID.to_owned(),
        revision: 1,
        params: rows,
    };
    let mut json = serde_json::to_string_pretty(&catalog)?;
    json.push('\n');
    let path = root.join("governance/tunables-params.json");
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    println!(
        "wrote {} parameters to governance/tunables-params.json",
        catalog.params.len()
    );
    Ok(())
}

pub(crate) fn check(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let path = root.join("governance/tunables-params.json");
    let committed =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let committed: serde_json::Value = serde_json::from_str(&committed)?;
    let committed_rows = committed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if committed_rows != rows.len() {
        bail!(
            "tier-2 parameter catalog is stale: source declares {} parameters, \
             governance/tunables-params.json has {}. Run `cargo run -p iteron-xtask -- tunables \
             generate-params`.",
            rows.len(),
            committed_rows
        );
    }
    let regenerated = serde_json::to_value(&Catalog {
        schema_version: iteron_tunables::PARAM_SCHEMA_VERSION,
        registry_id: iteron_tunables::PARAM_REGISTRY_ID.to_owned(),
        revision: 1,
        params: rows,
    })?;
    if regenerated != committed {
        bail!(
            "tier-2 parameter catalog disagrees with the source declarations. Run \
             `cargo run -p iteron-xtask -- tunables generate-params`."
        );
    }
    println!("tier-2 parameter catalog matches source ({committed_rows} parameters)");
    Ok(())
}

/// Per-crate census, printed by `tunables constants-audit`.
pub(crate) fn census(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let mut by_crate: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
    for row in &rows {
        let slot = by_crate.entry(row.krate.as_str()).or_default();
        match row.class {
            ParamClass::Searchable => slot[0] += 1,
            ParamClass::Bounded => slot[1] += 1,
            ParamClass::Structural => slot[2] += 1,
        }
    }
    println!(
        "{:<14} {:>10} {:>9} {:>11} {:>7}",
        "crate", "searchable", "bounded", "structural", "total"
    );
    let (mut s, mut b, mut t) = (0, 0, 0);
    for (krate, [searchable, bounded, structural]) in &by_crate {
        println!(
            "{krate:<14} {searchable:>10} {bounded:>9} {structural:>11} {:>7}",
            searchable + bounded + structural
        );
        s += searchable;
        b += bounded;
        t += structural;
    }
    println!("{:<14} {s:>10} {b:>9} {t:>11} {:>7}", "TOTAL", s + b + t);
    let mut modules: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &rows {
        *modules.entry(row.module.as_str()).or_default() += 1;
    }
    println!("\nmodules covered by tier-2: {}/28", modules.len());
    Ok(())
}

fn scan(root: &Path) -> Result<Vec<ParamRow>> {
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    files.sort();
    let mut rows = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&relative) {
            continue;
        }
        let Some(krate) = crate_of(&relative) else {
            continue;
        };
        if EXCLUDED_CRATES.contains(&krate) {
            continue;
        }
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let body = strip_test_modules(&source);
        for (name, ty_text, value) in declarations(&body) {
            rows.push(row_for(krate, &relative, &name, &ty_text, &value));
        }
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    rows.dedup_by(|left, right| left.id == right.id);
    Ok(rows)
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn is_test_path(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.ends_with("_tests.rs")
        || relative.ends_with("/tests.rs")
        || relative.contains("/benches/")
}

fn crate_of(relative: &str) -> Option<&str> {
    relative
        .strip_prefix("crates/")
        .and_then(|rest| rest.split('/').next())
}

/// Remove `#[cfg(test)] mod … { … }` bodies by brace matching, so test-only constants never enter
/// the surface. A regex cannot do this correctly; nested braces are common in these modules.
fn strip_test_modules(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < source.len() {
        let Some(found) = source[index..].find("#[cfg(test)]") else {
            out.push_str(&source[index..]);
            break;
        };
        let start = index + found;
        out.push_str(&source[index..start]);
        let Some(brace_offset) = source[start..].find('{') else {
            break;
        };
        let mut depth = 0i32;
        let mut cursor = start + brace_offset;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        cursor += 1;
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        index = cursor;
    }
    out
}

/// Extract `const NAME: TYPE = VALUE;` and `static NAME: TYPE = VALUE;` at any indentation.
fn declarations(body: &str) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        let rest = trimmed
            .strip_prefix("pub const ")
            .or_else(|| trimmed.strip_prefix("const "))
            .or_else(|| trimmed.strip_prefix("pub static "))
            .or_else(|| trimmed.strip_prefix("static "))
            .or_else(|| {
                trimmed
                    .strip_prefix("pub(crate) const ")
                    .or_else(|| trimmed.strip_prefix("pub(super) const "))
                    .or_else(|| trimmed.strip_prefix("pub(crate) static "))
                    .or_else(|| trimmed.strip_prefix("pub(super) static "))
            });
        let Some(rest) = rest else { continue };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        let Some((ty_text, value)) = tail.split_once('=') else {
            continue;
        };
        found.push((
            name.to_owned(),
            ty_text.trim().to_owned(),
            value.trim().trim_end_matches(';').trim().to_owned(),
        ));
    }
    found
}

fn row_for(krate: &str, relative: &str, name: &str, ty_text: &str, value: &str) -> ParamRow {
    let ty = param_type(ty_text);
    let class = classify(name, ty);
    let domain = match class {
        // A safety bound is exposed so it can be *tightened*. The ceiling is the value the build
        // shipped with: loosening past it would make the running system less bounded than the
        // audited one, which is exactly what the invariant forbids. Raising a specific ceiling
        // stays a deliberate source change, reviewed on its own merits.
        ParamClass::Bounded => DomainRow {
            min: Some(0),
            max: numeric_literal(value),
        },
        ParamClass::Searchable | ParamClass::Structural => DomainRow::default(),
    };
    ParamRow {
        id: format!("{krate}.{}.{}", module_path(relative), name.to_lowercase()),
        module: module_for(krate, relative),
        class,
        ty,
        default: value.to_owned(),
        domain,
        krate: krate.to_owned(),
        decl: relative.to_owned(),
    }
}

fn module_path(relative: &str) -> String {
    relative
        .rsplit_once("/src/")
        .map(|(_, tail)| tail)
        .unwrap_or(relative)
        .trim_end_matches(".rs")
        .replace('/', ".")
}

fn param_type(ty_text: &str) -> ParamType {
    let ty = ty_text.trim();
    if ty.starts_with('[') || ty.starts_with("&[") {
        return ParamType::Array;
    }
    if ty.contains("Duration") {
        return ParamType::Duration;
    }
    if ty.contains("bool") {
        return ParamType::Boolean;
    }
    if ty.contains("f32") || ty.contains("f64") {
        return ParamType::Float;
    }
    if ty.contains("usize")
        || ty.contains("u8")
        || ty.contains("u16")
        || ty.contains("u32")
        || ty.contains("u64")
        || ty.contains("u128")
        || ty.contains("i8")
        || ty.contains("i16")
        || ty.contains("i32")
        || ty.contains("i64")
        || ty.contains("i128")
        || ty.contains("NonZero")
    {
        return ParamType::Integer;
    }
    ParamType::Text
}

const STRUCTURAL_MARKERS: &[&str] = &[
    "VERSION",
    "SCHEMA",
    "DIGEST",
    "SHA256",
    "NAME",
    "KIND",
    "MIME",
    "HEADER",
    "PREFIX",
    "SUFFIX",
    "PATH",
    "DIR",
    "FILE",
    "EXT",
    "ENV",
    "SCHEME",
    "URL",
    "URI",
    "NAMESPACE",
    "MAGIC",
    "SENTINEL",
    "MARKER",
    "TAG",
    "LABEL",
    "SEPARATOR",
    "DELIM",
    "DOMAIN",
    "ALGORITHM",
    "ID",
];

const BOUND_PREFIXES: &[&str] = &[
    "MAX_", "CAP_", "CEILING_", "RESERVE_", "LIMIT_", "HARD_", "ABS_",
];

fn classify(name: &str, ty: ParamType) -> ParamClass {
    let structural_name = STRUCTURAL_MARKERS
        .iter()
        .any(|marker| name.contains(marker));
    // A numeric MAX_* is a bound even when its name also contains a structural word
    // (`MAX_SCHEMA_BYTES` bounds a size, it does not name a schema), so bounds are tested first.
    if matches!(ty, ParamType::Integer | ParamType::Duration)
        && (BOUND_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) || name.ends_with("_CAP"))
    {
        return ParamClass::Bounded;
    }
    if structural_name && !matches!(ty, ParamType::Integer | ParamType::Float) {
        return ParamClass::Structural;
    }
    if matches!(ty, ParamType::Text | ParamType::Array) && structural_name {
        return ParamClass::Structural;
    }
    if matches!(ty, ParamType::Text) && name.ends_with("_VERSION") {
        return ParamClass::Structural;
    }
    ParamClass::Searchable
}

fn numeric_literal(value: &str) -> Option<i128> {
    let cleaned: String = value
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    if cleaned.is_empty() {
        // `1024 * 1024` and `Duration::from_secs(30)` are common; take the first integer found.
        let mut digits = String::new();
        for ch in value.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if !digits.is_empty() {
                break;
            }
        }
        return digits.parse().ok();
    }
    cleaned.parse().ok()
}

/// Map a declaration site to its optimization module.
fn module_for(krate: &str, relative: &str) -> ModuleId {
    let file = relative
        .rsplit_once("/src/")
        .map(|(_, t)| t)
        .unwrap_or(relative);
    match krate {
        "ctx" => {
            if file.contains("memory") {
                ModuleId::MemoryRecall
            } else if file.contains("compact") || file.contains("summary") {
                ModuleId::ContextCompaction
            } else if file.contains("skill") {
                ModuleId::PromptSkill
            } else {
                ModuleId::ContextAssembly
            }
        }
        "tools" => {
            if file.contains("grep")
                || file.contains("glob")
                || file.contains("outline")
                || file.contains("repo")
            {
                ModuleId::ToolSearchStrategy
            } else if file.contains("edit") || file.contains("patch") || file.contains("fs_tools") {
                ModuleId::ToolEditStrategy
            } else {
                ModuleId::ToolArguments
            }
        }
        "provider" => {
            if file.contains("retry") || file.contains("backoff") || file.contains("failover") {
                ModuleId::ProviderRetry
            } else if file.contains("cache") {
                ModuleId::ProviderPromptCache
            } else if file.contains("catalog") || file.contains("route") || file.contains("router")
            {
                ModuleId::ProviderRouting
            } else {
                ModuleId::ProviderSampling
            }
        }
        "sched" | "sandbox" | "kernel" => ModuleId::SchedulerParallelism,
        "workflow" | "agents" => ModuleId::PlannerFanout,
        "verify" | "eval" => ModuleId::VerificationQuorum,
        "mcp" | "lsp" | "marketplace" => ModuleId::ToolExposure,
        "record" | "obs" | "evolve" | "changeset" | "support" => ModuleId::SessionCheckpoint,
        "protocol" | "tunables" => ModuleId::BudgetAllocation,
        "statusline" => ModuleId::SessionStop,
        "cli" => {
            if file.starts_with("tui") {
                ModuleId::SessionStop
            } else if file.contains("runtime_tunables") || file.contains("context") {
                ModuleId::ContextAssembly
            } else if file.contains("provider") {
                ModuleId::ProviderRouting
            } else if file.contains("config") {
                ModuleId::BudgetAllocation
            } else if file.contains("workflow") || file.contains("agent") {
                ModuleId::PlannerFanout
            } else if file.contains("session") || file.contains("resume") {
                ModuleId::SessionFork
            } else {
                ModuleId::SchedulerParallelism
            }
        }
        _ => ModuleId::SchedulerParallelism,
    }
}

/// Print the whole optimization surface and assert the counts the PRD fixed. This is the gate that
/// keeps the export honest: a surface that claims more than the loader accepts fails here.
pub(crate) fn surface(root: &Path, write: bool) -> Result<()> {
    let surface = iteron_tunables::surface();
    let counts = &surface.counts;
    println!("families                    {}", counts.families);
    println!("  Full                      {}", counts.families_full);
    println!(
        "  FixedHidden               {}",
        counts.families_fixed_hidden
    );
    println!(
        "  profile-addressable       {}",
        counts.families_profile_addressable
    );
    println!("params (tier 2)             {}", counts.params);
    println!("  searchable                {}", counts.params_searchable);
    println!("  bounded                   {}", counts.params_bounded);
    println!("  structural (read-only)    {}", counts.params_structural);
    println!("modules                     {}", counts.modules);
    println!("prompt artifacts            {}", counts.prompt_artifacts);

    if counts.families != iteron_tunables::EXPECTED_FAMILY_COUNT {
        bail!("family count drifted");
    }
    if counts.modules != 28 {
        bail!("module axis must have exactly 28 modules");
    }
    // Totality: every family and every parameter belongs to a module, and no module is empty of
    // all three kinds of member. An axis with an empty module cannot be ablated over.
    let empty: Vec<&str> = surface
        .modules
        .iter()
        .filter(|entry| entry.families == 0 && entry.params == 0 && entry.artifacts == 0)
        .map(|entry| entry.id)
        .collect();
    if !empty.is_empty() {
        bail!("modules with no members: {empty:?}");
    }
    let assigned: usize = surface.modules.iter().map(|entry| entry.families).sum();
    if assigned != counts.families {
        bail!(
            "family module assignment is not total: {assigned} of {}",
            counts.families
        );
    }
    let assigned_params: usize = surface.modules.iter().map(|entry| entry.params).sum();
    if assigned_params != counts.params {
        bail!("parameter module assignment is not total");
    }
    let path = root.join("governance/tunables-surface.json");
    let rendered = iteron_tunables::surface_json()?;
    if write {
        std::fs::write(&path, &rendered)?;
        println!("\nwrote governance/tunables-surface.json");
        return Ok(());
    }
    let committed =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if committed != rendered {
        bail!(
            "governance/tunables-surface.json is stale. Run `cargo run -p iteron-xtask -- \
             tunables generate-surface`."
        );
    }
    println!("\ngovernance/tunables-surface.json matches the compiled surface");
    Ok(())
}

/// Per-crate exposure baseline.
///
/// The property worth enforcing is directional, not absolute: the exposed surface may grow, and
/// the read-only `structural` share may not grow silently. A constant quietly reclassified as
/// structural is a control leaving the surface, which is exactly the regression this whole change
/// exists to prevent — and it would otherwise look like nothing at all in a diff.
pub(crate) fn census_check(root: &Path, write: bool) -> Result<()> {
    let rows = scan(root)?;
    let mut by_crate: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    for row in &rows {
        let slot = by_crate.entry(row.krate.clone()).or_default();
        match row.class {
            ParamClass::Searchable => slot[0] += 1,
            ParamClass::Bounded => slot[1] += 1,
            ParamClass::Structural => slot[2] += 1,
        }
    }
    let settable: usize = by_crate.values().map(|slot| slot[0] + slot[1]).sum();
    let structural: usize = by_crate.values().map(|slot| slot[2]).sum();
    let document = serde_json::json!({
        "schema_version": 1,
        "total": rows.len(),
        "settable": settable,
        "structural": structural,
        "by_crate": by_crate
            .iter()
            .map(|(krate, [searchable, bounded, structural])| {
                (
                    krate.clone(),
                    serde_json::json!({
                        "searchable": searchable,
                        "bounded": bounded,
                        "structural": structural,
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>(),
    });
    let mut rendered = serde_json::to_string_pretty(&document)?;
    rendered.push('\n');
    let path = root.join("governance/constants-census.json");
    if write {
        std::fs::write(&path, &rendered)?;
        println!(
            "wrote governance/constants-census.json ({settable} settable, {structural} structural)"
        );
        return Ok(());
    }
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    let baseline_settable = committed["settable"].as_u64().unwrap_or(0) as usize;
    let baseline_structural = committed["structural"]
        .as_u64()
        .unwrap_or(usize::MAX as u64) as usize;
    if settable < baseline_settable {
        bail!(
            "the exposed surface shrank: {settable} settable parameters against a baseline of \
             {baseline_settable}. Exposure is not supposed to go backwards; if this is deliberate, \
             update the baseline with `tunables generate-census` in the same change."
        );
    }
    if structural > baseline_structural {
        bail!(
            "read-only parameters grew from {baseline_structural} to {structural}: something left \
             the addressable surface. If that is deliberate, say so by updating the baseline."
        );
    }
    println!(
        "constants census within baseline: {settable} settable (>= {baseline_settable}), \
         {structural} structural (<= {baseline_structural})"
    );
    Ok(())
}
