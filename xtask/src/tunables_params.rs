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
use iteron_tunables::{ModuleId, ParamClass, ParamType, ParamUnit};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

/// Crates whose constants are *not* agent behaviour and are therefore out of the surface.
const EXCLUDED_CRATES: &[&str] = &["xtask"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ParamRow {
    pub id: String,
    pub module: ModuleId,
    pub class: ParamClass,
    #[serde(rename = "type")]
    pub ty: ParamType,
    pub rust_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<ParamUnit>,
    pub default: String,
    #[serde(skip_serializing_if = "DomainRow::is_empty")]
    #[serde(default)]
    pub domain: DomainRow,
    pub krate: String,
    pub decl: String,
    pub applied: bool,
    pub candidate_kind: CandidateKind,
    pub disposition: Disposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invariant_reason: Option<InvariantReason>,
    pub owner: OwnerRow,
    pub use_sites: Vec<UseSiteRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior_oracle: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CandidateKind {
    Const,
    Static,
    AssociatedConst,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Disposition {
    RuntimeSettable,
    InvariantReadOnly,
}

/// Closed vocabulary for values which must remain outside the learned/runtime-settable plane.
/// There is deliberately no `structural` or `other` escape hatch.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InvariantReason {
    Identity,
    WireCompatibility,
    CapabilityAuthority,
    Security,
    DurabilityReplay,
    HardBudgetEffectLedger,
    RuntimeStateNotAValue,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct OwnerRow {
    pub krate: String,
    pub path: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct UseSiteRow {
    pub path: String,
    pub line: usize,
    pub evidence: String,
}

#[derive(Debug, Clone)]
struct Declaration {
    name: String,
    ty: String,
    value: String,
    kind: CandidateKind,
    owner_symbol: String,
    line: usize,
    cfg_key: Option<String>,
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
    validate_rows(&rows)?;
    let catalog = Catalog {
        schema_version: iteron_tunables::PARAM_SCHEMA_VERSION,
        registry_id: iteron_tunables::PARAM_REGISTRY_ID.to_owned(),
        revision: 3,
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
    validate_rows(&rows)?;
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
        revision: 3,
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

pub(crate) fn validate_rows(rows: &[ParamRow]) -> Result<()> {
    let inert = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::RuntimeSettable) && !row.applied)
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    if !inert.is_empty() {
        bail!(
            "{} advertised runtime_settable parameters are not runtime applied:\n  {}",
            inert.len(),
            inert.join("\n  ")
        );
    }
    let mut ids = BTreeSet::new();
    for row in rows {
        if !ids.insert(&row.id) {
            bail!(
                "optimization census contains duplicate stable id `{}`",
                row.id
            );
        }
        match row.disposition {
            Disposition::RuntimeSettable => {
                if matches!(row.class, ParamClass::Structural) {
                    bail!(
                        "{} is runtime_settable but has legacy structural class",
                        row.id
                    );
                }
                if row.use_sites.is_empty() {
                    bail!(
                        "{} is runtime_settable without a production use site",
                        row.id
                    );
                }
                if row.behavior_oracle.as_deref().is_none_or(str::is_empty) {
                    bail!("{} is runtime_settable without a behavior oracle", row.id);
                }
                if row.invariant_reason.is_some() {
                    bail!(
                        "{} is runtime_settable but carries an invariant reason",
                        row.id
                    );
                }
            }
            Disposition::InvariantReadOnly => {
                if !matches!(row.class, ParamClass::Structural) {
                    bail!(
                        "{} is invariant_read_only without legacy structural class",
                        row.id
                    );
                }
                if row.invariant_reason.is_none() {
                    bail!("{} is invariant_read_only without a closed reason", row.id);
                }
                if row.applied {
                    bail!(
                        "{} is invariant_read_only but is resolved by a runtime helper",
                        row.id
                    );
                }
            }
        }
    }
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

/// Production calls which actually resolve an id through the installed override table. Parsed
/// from the AST so comments, strings, and test-only code cannot make an inert setting look applied.
fn applied_evidence(root: &Path) -> Result<BTreeMap<String, Vec<UseSiteRow>>> {
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    let mut evidence: BTreeMap<String, Vec<UseSiteRow>> = BTreeMap::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&relative) {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parsing {relative} for runtime parameter use sites"))?;
        AppliedEvidenceCollector {
            relative: &relative,
            found: &mut evidence,
        }
        .visit_file(&syntax);
    }
    for sites in evidence.values_mut() {
        sites.sort_by(|left, right| {
            (&left.path, left.line, &left.evidence).cmp(&(&right.path, right.line, &right.evidence))
        });
        sites.dedup();
    }
    Ok(evidence)
}

const PARAM_HELPERS: &[&str] = &[
    "param_i128",
    "param_integer",
    "param_usize",
    "param_u64",
    "param_bool",
    "param_f32",
    "param_f64",
    "param_duration",
    "param_str",
    "param_str_list",
    "param_bytes",
    "param_value",
    "param_char",
    "param_enum",
    "param_list",
    "param_map",
    "param_object",
];

struct AppliedEvidenceCollector<'a> {
    relative: &'a str,
    found: &'a mut BTreeMap<String, Vec<UseSiteRow>>,
}

impl AppliedEvidenceCollector<'_> {
    fn collect_macro_tokens(&mut self, stream: proc_macro2::TokenStream) {
        let tokens = stream.into_iter().collect::<Vec<_>>();
        for (index, token) in tokens.iter().enumerate() {
            if let proc_macro2::TokenTree::Group(group) = token {
                self.collect_macro_tokens(group.stream());
            }
            let proc_macro2::TokenTree::Ident(helper) = token else {
                continue;
            };
            if !PARAM_HELPERS.contains(&helper.to_string().as_str()) {
                continue;
            }
            let Some(proc_macro2::TokenTree::Group(arguments)) = tokens.get(index + 1) else {
                continue;
            };
            let Some(proc_macro2::TokenTree::Literal(id)) = arguments.stream().into_iter().next()
            else {
                continue;
            };
            let Ok(id) = syn::parse_str::<syn::LitStr>(&id.to_string()) else {
                continue;
            };
            self.found.entry(id.value()).or_default().push(UseSiteRow {
                path: self.relative.to_owned(),
                line: helper.span().start().line,
                evidence: format!("{} runtime resolution in macro", helper),
            });
        }
    }
}

impl<'ast> Visit<'ast> for AppliedEvidenceCollector<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_impl(self, item);
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_const(self, item);
        }
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_static(self, item);
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let syn::Expr::Path(function) = node.func.as_ref() else {
            visit::visit_expr_call(self, node);
            return;
        };
        let Some(helper) = function
            .path
            .segments
            .last()
            .map(|part| part.ident.to_string())
        else {
            return;
        };
        if !PARAM_HELPERS.contains(&helper.as_str()) {
            visit::visit_expr_call(self, node);
            return;
        }
        let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(id),
            ..
        })) = node.args.first()
        else {
            visit::visit_expr_call(self, node);
            return;
        };
        self.found.entry(id.value()).or_default().push(UseSiteRow {
            path: self.relative.to_owned(),
            line: node.span().start().line,
            evidence: format!("{helper} runtime resolution"),
        });
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        self.collect_macro_tokens(invocation.tokens.clone());
    }
}

/// Mechanically wrap same-file runtime reads of every currently inert primitive integer.
///
/// This intentionally skips const/static initializers and array lengths: those require a semantic
/// rewrite because runtime values are not legal in a const context. It also skips test-only
/// modules so an `applied` marker can never be earned by a test that production does not execute.
pub(crate) fn wire_integers(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let mut by_file: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        !row.applied
            && !matches!(row.class, ParamClass::Structural)
            && matches!(row.ty, ParamType::Integer)
    }) {
        let name = row
            .id
            .rsplit('.')
            .next()
            .expect("parameter ids have a final segment")
            .to_ascii_uppercase();
        if name == "_" {
            continue;
        }
        by_file
            .entry(row.decl.clone())
            .or_default()
            .insert(name, row.id.clone());
    }

    let mut changed_files = 0usize;
    let mut replacements = 0usize;
    let mut wired_ids = BTreeSet::new();
    for (relative, targets) in by_file {
        let path = root.join(&relative);
        let mut source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parsing {} for integer wiring", path.display()))?;
        let mut collector = IntegerUseCollector {
            source: &source,
            targets: &targets,
            replacements: Vec::new(),
        };
        collector.visit_file(&syntax);
        collector
            .replacements
            .sort_by_key(|replacement| replacement.start);
        collector
            .replacements
            .dedup_by_key(|replacement| (replacement.start, replacement.end));
        if collector.replacements.is_empty() {
            continue;
        }
        for replacement in collector.replacements.into_iter().rev() {
            wired_ids.insert(replacement.id.clone());
            let runtime = if replacement.id.starts_with("tunables.") {
                "crate::param_integer"
            } else {
                "iteron_tunables::param_integer"
            };
            source.replace_range(
                replacement.start..replacement.end,
                &format!(
                    "{runtime}(\"{}\", {})",
                    replacement.id, replacement.original,
                ),
            );
            replacements += 1;
        }
        std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
        changed_files += 1;
    }
    println!(
        "wired {replacements} runtime integer read(s) for {} parameter(s) across {changed_files} file(s); const/pattern/cross-file blockers remain explicit",
        wired_ids.len()
    );
    Ok(())
}

/// Wrap same-file production reads of all primitive non-integer scalar parameters.
pub(crate) fn wire_scalars(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let mut by_file: BTreeMap<String, BTreeMap<String, ScalarTarget>> = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        !row.applied
            && !matches!(row.class, ParamClass::Structural)
            && matches!(
                row.ty,
                ParamType::Boolean | ParamType::Duration | ParamType::Float | ParamType::Text
            )
    }) {
        let helper = match (row.ty, row.rust_type.trim()) {
            (ParamType::Boolean, "bool") => "param_bool",
            (ParamType::Duration, _) => "param_duration",
            (ParamType::Float, "f32") => "param_f32",
            (ParamType::Float, "f64") => "param_f64",
            (ParamType::Text, "char") => "param_char",
            (ParamType::Text, "&str" | "&'static str") => "param_str",
            _ => continue,
        };
        let name = row
            .id
            .rsplit('.')
            .next()
            .expect("parameter ids have a final segment")
            .to_ascii_uppercase();
        by_file.entry(row.decl.clone()).or_default().insert(
            name,
            ScalarTarget {
                id: row.id.clone(),
                helper,
            },
        );
    }

    let mut changed_files = 0usize;
    let mut replacements = 0usize;
    let mut wired_ids = BTreeSet::new();
    for (relative, targets) in by_file {
        let path = root.join(&relative);
        let mut source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parsing {} for scalar wiring", path.display()))?;
        let mut collector = ScalarUseCollector {
            source: &source,
            targets: &targets,
            replacements: Vec::new(),
        };
        collector.visit_file(&syntax);
        collector
            .replacements
            .sort_by_key(|replacement| replacement.start);
        collector
            .replacements
            .dedup_by_key(|replacement| (replacement.start, replacement.end));
        if collector.replacements.is_empty() {
            continue;
        }
        for replacement in collector.replacements.into_iter().rev() {
            wired_ids.insert(replacement.id.clone());
            let runtime = if replacement.id.starts_with("tunables.") {
                format!("crate::{}", replacement.helper)
            } else {
                format!("iteron_tunables::{}", replacement.helper)
            };
            source.replace_range(
                replacement.start..replacement.end,
                &format!(
                    "{runtime}(\"{}\", {})",
                    replacement.id, replacement.original
                ),
            );
            replacements += 1;
        }
        std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
        changed_files += 1;
    }
    println!(
        "wired {replacements} runtime scalar read(s) for {} parameter(s) across {changed_files} file(s)",
        wired_ids.len()
    );
    Ok(())
}

/// Wire remaining primitive scalar constants used from sibling modules. A name is eligible only
/// when it identifies exactly one settable parameter in its crate, avoiding any guess about an
/// unqualified import that could refer to two declaration sites.
pub(crate) fn wire_cross_file(root: &Path) -> Result<()> {
    let rows = scan(root)?;
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in &rows {
        let name = row
            .id
            .rsplit('.')
            .next()
            .expect("parameter ids have a final segment")
            .to_ascii_uppercase();
        *counts.entry((row.krate.clone(), name)).or_default() += 1;
    }
    let mut by_crate: BTreeMap<String, BTreeMap<String, ScalarTarget>> = BTreeMap::new();
    for row in rows.iter().filter(|row| {
        !row.applied
            && !matches!(row.class, ParamClass::Structural)
            && matches!(
                row.ty,
                ParamType::Integer
                    | ParamType::Boolean
                    | ParamType::Duration
                    | ParamType::Float
                    | ParamType::Text
            )
    }) {
        let name = row
            .id
            .rsplit('.')
            .next()
            .expect("parameter ids have a final segment")
            .to_ascii_uppercase();
        if counts.get(&(row.krate.clone(), name.clone())) != Some(&1) {
            continue;
        }
        let helper = match (row.ty, row.rust_type.trim()) {
            (ParamType::Integer, _) => "param_integer",
            (ParamType::Boolean, "bool") => "param_bool",
            (ParamType::Duration, _) => "param_duration",
            (ParamType::Float, "f32") => "param_f32",
            (ParamType::Float, "f64") => "param_f64",
            (ParamType::Text, "char") => "param_char",
            (ParamType::Text, "&str" | "&'static str") => "param_str",
            _ => continue,
        };
        by_crate.entry(row.krate.clone()).or_default().insert(
            name,
            ScalarTarget {
                id: row.id.clone(),
                helper,
            },
        );
    }

    let mut replacements = 0usize;
    let mut changed_files = 0usize;
    let mut wired_ids = BTreeSet::new();
    for (krate, targets) in by_crate {
        let mut files = Vec::new();
        collect_rust_files(&root.join("crates").join(&krate).join("src"), &mut files)?;
        for path in files {
            let mut source = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let syntax = syn::parse_file(&source)
                .with_context(|| format!("parsing {} for cross-file wiring", path.display()))?;
            let mut collector = ScalarUseCollector {
                source: &source,
                targets: &targets,
                replacements: Vec::new(),
            };
            collector.visit_file(&syntax);
            collector
                .replacements
                .sort_by_key(|replacement| replacement.start);
            collector
                .replacements
                .dedup_by_key(|replacement| (replacement.start, replacement.end));
            if collector.replacements.is_empty() {
                continue;
            }
            for replacement in collector.replacements.into_iter().rev() {
                wired_ids.insert(replacement.id.clone());
                let runtime = if replacement.id.starts_with("tunables.") {
                    format!("crate::{}", replacement.helper)
                } else {
                    format!("iteron_tunables::{}", replacement.helper)
                };
                source.replace_range(
                    replacement.start..replacement.end,
                    &format!(
                        "{runtime}(\"{}\", {})",
                        replacement.id, replacement.original
                    ),
                );
                replacements += 1;
            }
            std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
            changed_files += 1;
        }
    }
    println!(
        "wired {replacements} cross-file scalar read(s) for {} parameter(s) across {changed_files} file(s)",
        wired_ids.len()
    );
    Ok(())
}

#[derive(Clone)]
struct ScalarTarget {
    id: String,
    helper: &'static str,
}

struct ScalarReplacement {
    start: usize,
    end: usize,
    original: String,
    id: String,
    helper: &'static str,
}

struct ScalarUseCollector<'a> {
    source: &'a str,
    targets: &'a BTreeMap<String, ScalarTarget>,
    replacements: Vec<ScalarReplacement>,
}

impl ScalarUseCollector<'_> {
    fn push_span(&mut self, span: proc_macro2::Span, target: &ScalarTarget) {
        let start = source_offset(self.source, span.start());
        let end = source_offset(self.source, span.end());
        if start >= end || end > self.source.len() {
            return;
        }
        self.replacements.push(ScalarReplacement {
            start,
            end,
            original: self.source[start..end].to_owned(),
            id: target.id.clone(),
            helper: target.helper,
        });
    }

    fn collect_token_stream(&mut self, stream: proc_macro2::TokenStream) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                proc_macro2::TokenTree::Group(group) => self.collect_token_stream(group.stream()),
                proc_macro2::TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let qualified = index > 0
                        && matches!(tokens[index - 1], proc_macro2::TokenTree::Punct(ref punct) if punct.as_char() == ':');
                    if !qualified && let Some(target) = self.targets.get(&name) {
                        self.push_span(ident.span(), target);
                    }
                }
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for ScalarUseCollector<'_> {
    fn visit_item_const(&mut self, _node: &'ast syn::ItemConst) {}
    fn visit_item_static(&mut self, _node: &'ast syn::ItemStatic) {}
    fn visit_pat(&mut self, _node: &'ast syn::Pat) {}

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !has_cfg_test(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let Some(last) = node.path.segments.last() else {
            return;
        };
        let eligible_path = node.path.segments.len() == 1
            || (node.path.segments.len() == 2
                && node
                    .path
                    .segments
                    .first()
                    .is_some_and(|segment| segment.ident == "Self"))
            || node.path.segments.first().is_some_and(|segment| {
                matches!(segment.ident.to_string().as_str(), "crate" | "super")
            });
        if eligible_path && let Some(target) = self.targets.get(&last.ident.to_string()) {
            self.push_span(node.span(), target);
            return;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.collect_token_stream(node.tokens.clone());
    }
}

/// Remove runtime wrappers from parameters whose corrected catalog class is structural.
/// Structural values remain visible for research and compatibility inspection but are never
/// admitted from an optimization profile.
pub(crate) fn unwire_structural(root: &Path) -> Result<()> {
    let structural: BTreeSet<String> = scan(root)?
        .into_iter()
        .filter(|row| matches!(row.class, ParamClass::Structural))
        .map(|row| row.id)
        .collect();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    let mut changed_files = 0usize;
    let mut removed = 0usize;
    for path in files {
        if is_test_path(&path.to_string_lossy()) {
            continue;
        }
        let mut source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parsing {} for structural unwiring", path.display()))?;
        let mut collector = StructuralCallCollector {
            source: &source,
            structural: &structural,
            replacements: Vec::new(),
        };
        collector.visit_file(&syntax);
        if collector.replacements.is_empty() {
            continue;
        }
        collector
            .replacements
            .sort_by_key(|replacement| replacement.start);
        collector
            .replacements
            .dedup_by_key(|replacement| (replacement.start, replacement.end));
        for replacement in collector.replacements.into_iter().rev() {
            source.replace_range(replacement.start..replacement.end, &replacement.original);
            removed += 1;
        }
        std::fs::write(&path, source).with_context(|| format!("writing {}", path.display()))?;
        changed_files += 1;
    }
    println!("removed {removed} structural runtime wrapper(s) across {changed_files} file(s)");
    Ok(())
}

struct StructuralCallCollector<'a> {
    source: &'a str,
    structural: &'a BTreeSet<String>,
    replacements: Vec<SourceReplacement>,
}

impl<'ast> Visit<'ast> for StructuralCallCollector<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let syn::Expr::Path(function) = node.func.as_ref() else {
            visit::visit_expr_call(self, node);
            return;
        };
        let Some(helper) = function
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        if !matches!(
            helper.as_str(),
            "param_i128"
                | "param_integer"
                | "param_usize"
                | "param_u64"
                | "param_bool"
                | "param_f32"
                | "param_f64"
                | "param_duration"
                | "param_str"
                | "param_char"
        ) || node.args.len() != 2
        {
            visit::visit_expr_call(self, node);
            return;
        }
        let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(id),
            ..
        })) = node.args.first()
        else {
            visit::visit_expr_call(self, node);
            return;
        };
        if !self.structural.contains(&id.value()) {
            visit::visit_expr_call(self, node);
            return;
        }
        let Some(default) = node.args.iter().nth(1) else {
            return;
        };
        let call_start = source_offset(self.source, node.span().start());
        let call_end = source_offset(self.source, node.span().end());
        let default_start = source_offset(self.source, default.span().start());
        let default_end = source_offset(self.source, default.span().end());
        if call_start >= call_end || default_start >= default_end || default_end > self.source.len()
        {
            return;
        }
        self.replacements.push(SourceReplacement {
            start: call_start,
            end: call_end,
            original: self.source[default_start..default_end].to_owned(),
            id: id.value(),
        });
    }
}

struct SourceReplacement {
    start: usize,
    end: usize,
    original: String,
    id: String,
}

struct IntegerUseCollector<'a> {
    source: &'a str,
    targets: &'a BTreeMap<String, String>,
    replacements: Vec<SourceReplacement>,
}

impl IntegerUseCollector<'_> {
    fn push_span(&mut self, span: proc_macro2::Span, id: &str) {
        let start = source_offset(self.source, span.start());
        let end = source_offset(self.source, span.end());
        if start >= end || end > self.source.len() {
            return;
        }
        self.replacements.push(SourceReplacement {
            start,
            end,
            original: self.source[start..end].to_owned(),
            id: id.to_owned(),
        });
    }

    fn collect_token_stream(&mut self, stream: proc_macro2::TokenStream) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                proc_macro2::TokenTree::Group(group) => self.collect_token_stream(group.stream()),
                proc_macro2::TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let qualified = index > 0
                        && matches!(tokens[index - 1], proc_macro2::TokenTree::Punct(ref punct) if punct.as_char() == ':');
                    if !qualified && let Some(id) = self.targets.get(&name) {
                        self.push_span(ident.span(), id);
                    }
                }
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for IntegerUseCollector<'_> {
    fn visit_item_const(&mut self, _node: &'ast syn::ItemConst) {}

    fn visit_item_static(&mut self, _node: &'ast syn::ItemStatic) {}
    fn visit_pat(&mut self, _node: &'ast syn::Pat) {}

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_type_array(&mut self, node: &'ast syn::TypeArray) {
        self.visit_type(&node.elem);
    }

    fn visit_expr_repeat(&mut self, node: &'ast syn::ExprRepeat) {
        self.visit_expr(&node.expr);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let Some(last) = node.path.segments.last() else {
            return;
        };
        let eligible_path = node.path.segments.len() == 1
            || (node.path.segments.len() == 2
                && node
                    .path
                    .segments
                    .first()
                    .is_some_and(|segment| segment.ident == "Self"));
        if eligible_path && let Some(id) = self.targets.get(&last.ident.to_string()) {
            self.push_span(node.span(), id);
            return;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.collect_token_stream(node.tokens.clone());
    }
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    use quote::ToTokens as _;
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.meta.to_token_stream().to_string().contains("test")
    })
}

fn source_offset(source: &str, location: proc_macro2::LineColumn) -> usize {
    let line_start = source
        .split_inclusive('\n')
        .take(location.line.saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let line = source[line_start..]
        .split_once('\n')
        .map_or(&source[line_start..], |(line, _)| line);
    let byte_column = line
        .char_indices()
        .nth(location.column)
        .map_or(line.len(), |(index, _)| index);
    line_start + byte_column
}

pub(crate) fn scan(root: &Path) -> Result<Vec<ParamRow>> {
    let applied = applied_evidence(root)?;
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    files.sort();
    let mut sources = Vec::new();
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
        let declarations = declarations(&source)?;
        sources.push((krate.to_owned(), relative, source, declarations));
    }

    // The Stage-1 address stays unchanged whenever it is unambiguous. Repeated associated/local
    // names (for example one `VERSION` per port implementation) receive an owner-qualified id so
    // the AST-complete inventory never silently deduplicates declarations.
    let mut base_id_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut qualified_id_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (krate, relative, _, declarations) in &sources {
        for declaration in declarations {
            *base_id_counts
                .entry(base_param_id(krate, relative, &declaration.name))
                .or_default() += 1;
            *qualified_id_counts
                .entry(qualified_param_id(
                    krate,
                    relative,
                    &declaration.owner_symbol,
                    &declaration.name,
                ))
                .or_default() += 1;
        }
    }

    // Resolve literal constants globally first, then same-file aliases to a fixed point. Rust
    // bounds are commonly written as `MAX_CHILD = MAX_PARENT * 2`; dropping the ceiling merely
    // because the source chose a readable alias would accidentally turn a tighten-only safety
    // control into an unbounded one.
    let mut candidates: BTreeMap<String, Option<i128>> = BTreeMap::new();
    for (_, _, _, declarations) in &sources {
        for declaration in declarations {
            let Some(value) = numeric_literal(&declaration.value, &BTreeMap::new())
                .or_else(|| literal_length(&declaration.value, &BTreeMap::new()))
            else {
                continue;
            };
            candidates
                .entry(declaration.name.clone())
                .and_modify(|existing| {
                    if existing.is_some_and(|existing| existing != value) {
                        *existing = None;
                    }
                })
                .or_insert(Some(value));
        }
    }
    let global_symbols: BTreeMap<String, i128> = candidates
        .into_iter()
        .filter_map(|(name, value)| value.map(|value| (name, value)))
        .collect();

    let mut names_by_crate: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (krate, _, _, declarations) in &sources {
        names_by_crate.entry(krate.clone()).or_default().extend(
            declarations
                .iter()
                .map(|declaration| declaration.name.clone()),
        );
    }
    let mut declaration_uses: BTreeMap<(String, String), Vec<UseSiteRow>> = BTreeMap::new();
    for (krate, relative, source, _) in &sources {
        let targets = names_by_crate
            .get(krate)
            .expect("each scanned crate has a declaration name set");
        for (name, sites) in source_use_sites(source, relative, targets)? {
            declaration_uses
                .entry((krate.clone(), name))
                .or_default()
                .extend(sites);
        }
    }
    for sites in declaration_uses.values_mut() {
        sites.sort_by(|left, right| (&left.path, left.line).cmp(&(&right.path, right.line)));
        sites.dedup();
    }

    let mut rows = Vec::new();
    for (krate, relative, _, declarations) in sources {
        let mut symbols = global_symbols.clone();
        loop {
            let before = symbols.len();
            for declaration in &declarations {
                if let Some(value) = numeric_literal(&declaration.value, &symbols)
                    .or_else(|| literal_length(&declaration.value, &symbols))
                {
                    symbols.insert(declaration.name.clone(), value);
                }
            }
            if symbols.len() == before {
                break;
            }
        }
        for declaration in declarations {
            let ceiling = numeric_literal(&declaration.value, &symbols);
            let mut row = row_for(
                &krate,
                &relative,
                &declaration.name,
                &declaration.ty,
                &declaration.value,
                ceiling,
                declaration.kind,
                &declaration.owner_symbol,
                declaration.line,
            );
            if base_id_counts.get(&row.id).copied().unwrap_or_default() > 1 {
                row.id = qualified_param_id(
                    &krate,
                    &relative,
                    &declaration.owner_symbol,
                    &declaration.name,
                );
                if qualified_id_counts
                    .get(&row.id)
                    .copied()
                    .unwrap_or_default()
                    > 1
                {
                    let cfg = declaration.cfg_key.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "duplicate declaration {} has no cfg discriminator",
                            declaration.owner_symbol
                        )
                    })?;
                    row.id.push('.');
                    row.id.push_str(&cfg_discriminator(cfg));
                }
            }
            if matches!(row.disposition, Disposition::InvariantReadOnly)
                && let Some(sites) =
                    declaration_uses.get(&(krate.clone(), declaration.name.clone()))
                && !sites.is_empty()
            {
                row.use_sites = sites.clone();
            }
            if let Some(sites) = applied.get(&row.id) {
                row.use_sites = sites.clone();
                row.applied = true;
            }
            if row.applied {
                row.behavior_oracle = Some(format!(
                    "installed profile id {} is resolved at every listed production helper call",
                    row.id
                ));
            }
            rows.push(row);
        }
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
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

/// Canonical const/static inventory. There is intentionally no line-oriented candidate prefilter:
/// `syn` owns discovery, including multiline declarations, associated constants, and nested inline
/// modules. Test-attributed items are pruned while walking the tree.
fn declarations(source: &str) -> Result<Vec<Declaration>> {
    let syntax =
        syn::parse_file(source).context("parsing Rust declarations for the tunables catalog")?;
    let mut collector = DeclarationCollector {
        source,
        found: Vec::new(),
        modules: Vec::new(),
        owners: Vec::new(),
    };
    collector.visit_file(&syntax);
    Ok(collector.found)
}

struct DeclarationCollector<'a> {
    source: &'a str,
    found: Vec<Declaration>,
    modules: Vec<String>,
    owners: Vec<String>,
}

impl DeclarationCollector<'_> {
    fn push(
        &mut self,
        attrs: &[syn::Attribute],
        name: &syn::Ident,
        ty: &syn::Type,
        value: &syn::Expr,
        kind: CandidateKind,
    ) {
        let name = name.to_string();
        if name == "_" {
            return;
        }
        let Some(ty_text) = span_text(self.source, ty.span()) else {
            return;
        };
        let Some(value_text) = span_text(self.source, value.span()) else {
            return;
        };
        let mut owner = self.modules.join("::");
        for item_owner in &self.owners {
            if !owner.is_empty() {
                owner.push_str("::");
            }
            owner.push_str(item_owner);
        }
        if !owner.is_empty() {
            owner.push_str("::");
        }
        owner.push_str(&name);
        self.found.push(Declaration {
            name,
            ty: ty_text.to_owned(),
            value: value_text.to_owned(),
            kind,
            owner_symbol: owner,
            line: value.span().start().line,
            cfg_key: attrs
                .iter()
                .filter(|attr| attr.path().is_ident("cfg"))
                .map(|attr| quote::ToTokens::to_token_stream(&attr.meta).to_string())
                .reduce(|left, right| format!("{left}_{right}")),
        });
    }
}

impl<'ast> Visit<'ast> for DeclarationCollector<'_> {
    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if !has_cfg_test(&node.attrs) {
            self.push(
                &node.attrs,
                &node.ident,
                &node.ty,
                &node.expr,
                CandidateKind::Const,
            );
        }
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        if !has_cfg_test(&node.attrs) {
            self.push(
                &node.attrs,
                &node.ident,
                &node.ty,
                &node.expr,
                CandidateKind::Static,
            );
        }
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.modules.push(node.ident.to_string());
        if let Some((_, items)) = &node.content {
            for item in items {
                self.visit_item(item);
            }
        }
        self.modules.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens as _;
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.owners
            .push(node.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit::visit_item_impl(self, node);
        self.owners.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.owners.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.owners.pop();
    }

    fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
        if !has_cfg_test(&node.attrs) {
            self.push(
                &node.attrs,
                &node.ident,
                &node.ty,
                &node.expr,
                CandidateKind::AssociatedConst,
            );
        }
    }

    fn visit_trait_item_const(&mut self, node: &'ast syn::TraitItemConst) {
        if !has_cfg_test(&node.attrs)
            && let Some((_, value)) = &node.default
        {
            self.push(
                &node.attrs,
                &node.ident,
                &node.ty,
                value,
                CandidateKind::AssociatedConst,
            );
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.owners.push(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.owners.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.owners.push(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.owners.pop();
    }
}

fn source_use_sites(
    source: &str,
    relative: &str,
    targets: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<UseSiteRow>>> {
    let syntax = syn::parse_file(source)
        .with_context(|| format!("parsing {relative} for const/static use-site evidence"))?;
    let mut collector = DeclarationUseCollector {
        relative,
        targets,
        found: BTreeMap::new(),
    };
    collector.visit_file(&syntax);
    Ok(collector.found)
}

struct DeclarationUseCollector<'a> {
    relative: &'a str,
    targets: &'a BTreeSet<String>,
    found: BTreeMap<String, Vec<UseSiteRow>>,
}

impl DeclarationUseCollector<'_> {
    fn push(&mut self, name: &str, span: proc_macro2::Span, evidence: &str) {
        if self.targets.contains(name) {
            self.found
                .entry(name.to_owned())
                .or_default()
                .push(UseSiteRow {
                    path: self.relative.to_owned(),
                    line: span.start().line,
                    evidence: evidence.to_owned(),
                });
        }
    }

    fn visit_tokens(&mut self, stream: proc_macro2::TokenStream) {
        for token in stream {
            match token {
                proc_macro2::TokenTree::Group(group) => self.visit_tokens(group.stream()),
                proc_macro2::TokenTree::Ident(ident) => {
                    self.push(&ident.to_string(), ident.span(), "macro token reference")
                }
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for DeclarationUseCollector<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_item_impl(self, item);
        }
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        if let Some(name) = expression.path.segments.last() {
            self.push(
                &name.ident.to_string(),
                expression.span(),
                "Rust path reference",
            );
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        self.visit_tokens(invocation.tokens.clone());
    }
}

fn span_text(source: &str, span: proc_macro2::Span) -> Option<&str> {
    let start = source_offset(source, span.start());
    let end = source_offset(source, span.end());
    (start < end && end <= source.len()).then(|| &source[start..end])
}

#[allow(clippy::too_many_arguments)]
fn row_for(
    krate: &str,
    relative: &str,
    name: &str,
    ty_text: &str,
    value: &str,
    numeric_ceiling: Option<i128>,
    candidate_kind: CandidateKind,
    owner_symbol: &str,
    declaration_line: usize,
) -> ParamRow {
    let ty = param_type(ty_text, value);
    let cryptographic_shape = (krate == "record"
        && relative.ends_with("/content_store/crypto.rs")
        && matches!(name, "KEY_BYTES" | "NONCE_BYTES"))
        || (krate == "evolve"
            && relative.ends_with("/verifier_crypto.rs")
            && name == "HMAC_BLOCK_BYTES")
        || (krate == "protocol"
            && relative.ends_with("/bundle.rs")
            && name == "RESOLVED_DIGEST_HEX_LEN")
        || (krate == "cli"
            && relative.ends_with("/providers.rs")
            && name == "CATALOG_CACHE_SCOPE_KEY_BYTES")
        || (krate == "cli"
            && relative.ends_with("/tui/headless/auth.rs")
            && matches!(
                name,
                "BEARER_TOKEN_BYTES" | "BEARER_TOKEN_HEX_BYTES" | "MAX_BEARER_TOKEN_INPUT_BYTES"
            ));
    let runtime_state = ["OnceLock", "LazyLock", "Atomic", "Mutex", "RwLock"]
        .iter()
        .any(|marker| ty_text.contains(marker));
    let custom_object = matches!(ty, ParamType::Object)
        && !matches!(ty_text.trim(), "LangSpec" | "Limits" | "libc::c_int");
    let custom_array = matches!(ty, ParamType::Array)
        && array_has_custom_type(ty_text)
        && !ty_text.contains("Color")
        && !ty_text.contains("ToolPreference");
    let invariant_array_crate = matches!(
        krate,
        "tunables"
            | "protocol"
            | "sandbox"
            | "kernel"
            | "record"
            | "obs"
            | "verify"
            | "evolve"
            | "eval"
    ) && matches!(ty, ParamType::Array);
    let evidence_only_duplicate = matches!(
        (krate, relative, name),
        (
            "cli",
            "crates/cli/src/runtime_tunables/core_facts.rs",
            "RATIO_EIGHT_TENTHS"
        )
    );
    let exact_schema_cardinality = matches!(
        (krate, relative, name),
        (
            "protocol",
            "crates/protocol/src/tunables_snapshot.rs",
            "MAX_RUN_GENESIS_TUNABLE_ENTRIES"
        )
    );
    let wire_compatibility_invariant = matches!(
        (krate, relative, name),
        (
            "protocol",
            "crates/protocol/src/input.rs",
            "MAX_INPUT_SEGMENTS" | "MAX_INPUT_IMAGES" | "MAX_TOTAL_IMAGE_BASE64_BYTES"
        ) | (
            "protocol",
            "crates/protocol/src/message.rs",
            "MAX_STOP_REASON_CODE_BYTES"
        ) | (
            "cli",
            "crates/cli/src/output.rs",
            "MAX_PENDING_STREAM_TOKEN_BYTES"
        ) | (
            "protocol",
            "crates/protocol/src/message.rs",
            "ANTHROPIC_MESSAGES_CONTENT_BLOCKS_V1"
                | "OPENAI_CHAT_REASONING_CONTENT_V1"
                | "OPENAI_RESPONSES_OUTPUT_ITEMS_V1"
        )
    ) || (krate == "cli"
        && relative == "crates/cli/src/config.rs"
        && name == "MAX_SERVER_BYTES"
        && owner_symbol.contains("Mcp")
        && owner_symbol.contains("BindingId"));
    let derived_object = ty_text.trim() == "Limits";
    let platform_identity_invariant = name == "NULL_DEVICE"
        || matches!(
            (krate, relative, name),
            (
                "marketplace",
                "crates/marketplace/src/implementation_runtime/process.rs",
                "SIGKILL"
            ) | (
                "marketplace",
                "crates/marketplace/src/hotswap.rs",
                "GENESIS_HASH"
            ) | (
                "marketplace",
                "crates/marketplace/src/implementation.rs",
                "IMPLEMENTATION_PROCESS_PROTOCOL_V1"
            ) | (
                "eval",
                "crates/eval/src/research_execution/process.rs",
                "PROC_PGRP_ONLY"
            )
        );
    let hard_budget_invariant = name.starts_with("MAX_")
        && matches!(
            (krate, relative),
            ("cli", "crates/cli/src/plugin_runtime/candidate.rs")
                | ("eval", "crates/eval/src/adapter_registry.rs")
                | ("eval", "crates/eval/src/lib.rs")
                | (
                    "eval",
                    "crates/eval/src/research_execution/implementation.rs"
                )
                | ("eval", "crates/eval/src/research_execution/process.rs")
                | (
                    "eval",
                    "crates/eval/src/research_execution/response_validation.rs"
                )
                | ("eval", "crates/eval/src/research_protocol.rs")
                | ("eval", "crates/eval/src/terminal_bench.rs")
                | ("eval", "crates/eval/src/trainer_bridge.rs")
                | ("eval", "crates/eval/src/runner/hermetic.rs")
                | ("eval", "crates/eval/src/tuner/candidate_graph.rs")
                | ("marketplace", "crates/marketplace/src/hotswap.rs")
                | ("marketplace", "crates/marketplace/src/implementation.rs")
                | (
                    "marketplace",
                    "crates/marketplace/src/implementation_activation.rs"
                )
                | (
                    "marketplace",
                    "crates/marketplace/src/implementation_runtime.rs"
                )
                | (
                    "marketplace",
                    "crates/marketplace/src/implementation_protocol.rs"
                )
                | ("tunables", "crates/tunables/src/capability_graph.rs")
                | ("tunables", "crates/tunables/src/service_graph.rs")
        )
        || matches!(
            (krate, relative, name),
            (
                "eval",
                "crates/eval/src/tuner.rs",
                "MAX_UNIVERSAL_CANDIDATE_DIMENSIONS"
            )
        );
    let deliberate_runtime_control = match (krate, relative, name) {
        (
            "agents",
            "crates/agents/src/decompose.rs",
            "CODE_EXTS"
            | "FRAME_MARKERS"
            | "RUN_MARKERS"
            | "RUN_INTENT_MARKERS"
            | "INTERNATIONAL_RUN_MARKERS"
            | "MULTI_MARKERS"
            | "INTERNATIONAL_MULTI_MARKERS",
        )
        | ("cli", "crates/cli/src/block/links.rs", "PATH_ARG_KEYS" | "URL_ARG_KEYS") => {
            Some(ParamClass::Searchable)
        }
        ("tools", "crates/tools/src/tool_search.rs", "DEFAULT_DEFERRED_TOOL_EAGER_LIMIT")
        | ("tools", "crates/tools/src/web.rs", "DEFAULT_SEARCH_RESULT_COUNT") => {
            Some(ParamClass::Bounded)
        }
        ("tools", "crates/tools/src/lsp/session.rs", "PROCESS_EXIT_TIMEOUT") => {
            Some(ParamClass::Bounded)
        }
        (
            "evolve",
            "crates/evolve/src/transcript.rs",
            "DEFAULT_PRIMARY_PRODUCER" | "DEFAULT_SECONDARY_PRODUCER",
        )
        | ("tools", "crates/tools/src/process/policy.rs", "DEFAULT_PERSISTENT_BACKEND")
        | ("workflow", "crates/workflow/src/execution_policy.rs", "DEFAULT_TASK_FAILURE_ACTION")
        | (
            "verify",
            "crates/verify/src/runtime_policy.rs",
            "DEFAULT_VERIFICATION_SELECTION"
            | "DEFAULT_VERIFICATION_CHECKPOINT_TURN_BOUNDARY"
            | "DEFAULT_VERIFICATION_CHECKPOINT_BEFORE_VERIFICATION"
            | "DEFAULT_FLAKY_REPEAT_COUNT",
        ) => Some(ParamClass::Searchable),
        ("workflow", "crates/workflow/src/schema_retry.rs", "DEFAULT_SCHEMA_RETRY_BASE_MS") => {
            Some(ParamClass::Searchable)
        }
        ("workflow", "crates/workflow/src/schema_retry.rs", "DEFAULT_SCHEMA_RETRY_CAP_MS") => {
            Some(ParamClass::Bounded)
        }
        ("tools", "crates/tools/src/shell.rs", "MAX_PER_STREAM_BYTES") => Some(ParamClass::Bounded),
        ("tools", "crates/tools/src/git_observe.rs", "DEFAULT_LOG_COUNT")
        | ("cli", "crates/cli/src/tui/status_line.rs", "SEPARATOR") => Some(ParamClass::Searchable),
        _ => None,
    };
    let class = if let Some(class) = deliberate_runtime_control {
        class
    } else if cryptographic_shape
        || runtime_state
        || custom_object
        || matches!(ty, ParamType::Enum)
        || custom_array
        || invariant_array_crate
        || direct_alias(value)
        || evidence_only_duplicate
        || exact_schema_cardinality
        || wire_compatibility_invariant
        || derived_object
        || platform_identity_invariant
        || hard_budget_invariant
    {
        // Cryptographic widths, capability-token framing, redaction buffering, and bounds embedded
        // in frozen manual serde support are invariants, not search parameters. Exposing them would
        // put security, authentication, or byte-compatibility inside the learned plane.
        ParamClass::Structural
    } else {
        classify(name, ty)
    };
    let domain = match class {
        // A safety bound is exposed so it can be *tightened*. The ceiling is the value the build
        // shipped with: loosening past it would make the running system less bounded than the
        // audited one, which is exactly what the invariant forbids. Raising a specific ceiling
        // stays a deliberate source change, reviewed on its own merits.
        ParamClass::Bounded => DomainRow {
            min: Some(0),
            max: numeric_ceiling,
        },
        ParamClass::Searchable | ParamClass::Structural => DomainRow::default(),
    };
    let (disposition, invariant_reason) = if matches!(class, ParamClass::Structural) {
        (
            Disposition::InvariantReadOnly,
            Some(invariant_reason_for(
                krate,
                relative,
                name,
                ty_text,
                cryptographic_shape,
                runtime_state,
                wire_compatibility_invariant || exact_schema_cardinality,
                hard_budget_invariant,
            )),
        )
    } else {
        (Disposition::RuntimeSettable, None)
    };
    ParamRow {
        id: format!("{krate}.{}.{}", module_path(relative), name.to_lowercase()),
        module: module_for(krate, relative),
        class,
        ty,
        rust_type: ty_text.to_owned(),
        unit: duration_unit(ty, value),
        default: value.to_owned(),
        domain,
        krate: krate.to_owned(),
        decl: relative.to_owned(),
        applied: false,
        candidate_kind,
        disposition,
        invariant_reason,
        owner: OwnerRow {
            krate: krate.to_owned(),
            path: relative.to_owned(),
            symbol: owner_symbol.to_owned(),
        },
        use_sites: vec![UseSiteRow {
            path: relative.to_owned(),
            line: declaration_line,
            evidence: "production declaration".to_owned(),
        }],
        behavior_oracle: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn invariant_reason_for(
    krate: &str,
    relative: &str,
    name: &str,
    ty_text: &str,
    cryptographic_shape: bool,
    runtime_state: bool,
    wire_compatibility: bool,
    hard_budget: bool,
) -> InvariantReason {
    if cryptographic_shape
        || name.contains("SIGNATURE")
        || name.contains("HMAC")
        || name.contains("BEARER_TOKEN")
        || name.contains("SECRET")
        || relative.contains("/crypto")
        || relative.contains("/auth")
    {
        return InvariantReason::Security;
    }
    if wire_compatibility
        || krate == "protocol"
        || name.contains("WIRE")
        || name.contains("ENCODING")
        || name.contains("FORMAT")
    {
        return InvariantReason::WireCompatibility;
    }
    if krate == "sandbox" || name.contains("CAPABILITY") || name.contains("PERMISSION") {
        return InvariantReason::CapabilityAuthority;
    }
    if matches!(krate, "record" | "obs")
        || name.contains("REPLAY")
        || name.contains("JOURNAL")
        || name.contains("CHECKPOINT")
    {
        return InvariantReason::DurabilityReplay;
    }
    if hard_budget
        || krate == "kernel"
        || name.contains("EFFECT")
        || name.contains("LEDGER")
        || name.contains("HARD_BUDGET")
    {
        return InvariantReason::HardBudgetEffectLedger;
    }
    if runtime_state
        || ["OnceLock", "LazyLock", "Atomic", "Mutex", "RwLock"]
            .iter()
            .any(|marker| ty_text.contains(marker))
    {
        return InvariantReason::RuntimeStateNotAValue;
    }
    if name == "NULL_DEVICE"
        || name.contains("VERSION")
        || name.contains("SCHEMA")
        || name.contains("DIGEST")
        || name.contains("MAGIC")
        || name.contains("ID")
        || name.contains("NAME")
        || name.contains("KIND")
        || name.contains("MIME")
        || name.contains("PATH")
        || name.contains("PREFIX")
        || name.contains("SUFFIX")
        || name.contains("TAG")
        || name.contains("MARKER")
        || name.contains("SENTINEL")
    {
        return InvariantReason::Identity;
    }
    // Structural objects, aliases, and compile-time tables are values describing runtime state or
    // type shape rather than independently optimizable policy values. This is a closed, explicit
    // disposition, not a catch-all reason emitted by the census schema.
    InvariantReason::RuntimeStateNotAValue
}

fn module_path(relative: &str) -> String {
    relative
        .rsplit_once("/src/")
        .map(|(_, tail)| tail)
        .unwrap_or(relative)
        .trim_end_matches(".rs")
        .replace('/', ".")
}

fn base_param_id(krate: &str, relative: &str, name: &str) -> String {
    format!("{krate}.{}.{}", module_path(relative), name.to_lowercase())
}

fn qualified_param_id(krate: &str, relative: &str, owner: &str, name: &str) -> String {
    let owner = owner
        .strip_suffix(name)
        .unwrap_or(owner)
        .trim_end_matches("::")
        .replace("::", ".")
        .replace(
            |character: char| !character.is_ascii_alphanumeric() && character != '.',
            "_",
        )
        .to_ascii_lowercase();
    if owner.is_empty() {
        base_param_id(krate, relative, name)
    } else {
        format!(
            "{krate}.{}.{owner}.{}",
            module_path(relative),
            name.to_lowercase()
        )
    }
}

fn cfg_discriminator(cfg: &str) -> String {
    let mut rendered = String::from("cfg_");
    let mut separator = false;
    for character in cfg.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if separator && !rendered.ends_with('_') {
                rendered.push('_');
            }
            rendered.push(character);
            separator = false;
        } else {
            separator = true;
        }
    }
    rendered.trim_end_matches('_').to_owned()
}

fn param_type(ty_text: &str, value: &str) -> ParamType {
    let ty = ty_text.trim();
    let compact: String = ty
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if ty.starts_with('[') || ty.starts_with("&[") {
        return ParamType::Array;
    }
    if compact.contains("BTreeMap<")
        || compact.contains("HashMap<")
        || compact.starts_with("IndexMap<")
        || compact.contains("::IndexMap<")
    {
        return ParamType::Map;
    }
    if compact.ends_with("Duration") {
        return ParamType::Duration;
    }
    if compact == "bool" {
        return ParamType::Boolean;
    }
    if matches!(compact.as_str(), "f32" | "f64") || compact.ends_with("DecimalValue") {
        return ParamType::Float;
    }
    if compact == "libc::c_int"
        || matches!(
            compact.as_str(),
            "usize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "isize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
        )
    {
        return ParamType::Integer;
    }
    if matches!(
        compact.as_str(),
        "&str" | "&'staticstr" | "str" | "String" | "char"
    ) {
        return ParamType::Text;
    }
    if value.contains("::") && !value.contains(['{', '(', '[']) {
        return ParamType::Enum;
    }
    ParamType::Object
}

fn duration_unit(ty: ParamType, value: &str) -> Option<ParamUnit> {
    if !matches!(ty, ParamType::Duration) {
        return None;
    }
    if value.contains("from_nanos") {
        Some(ParamUnit::Nanoseconds)
    } else if value.contains("from_micros") {
        Some(ParamUnit::Microseconds)
    } else if value.contains("from_millis") {
        Some(ParamUnit::Milliseconds)
    } else if value.contains("from_secs") {
        Some(ParamUnit::Seconds)
    } else {
        None
    }
}

fn array_has_custom_type(ty_text: &str) -> bool {
    ty_text
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .any(|token| {
            token
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
        })
}

fn direct_alias(value: &str) -> bool {
    let Ok(expression) = syn::parse_str::<syn::Expr>(value) else {
        return false;
    };
    match expression {
        syn::Expr::Path(_) => true,
        syn::Expr::Cast(value) => matches!(*value.expr, syn::Expr::Path(_)),
        _ => false,
    }
}

const STRUCTURAL_MARKERS: &[&str] = &[
    "VERSION",
    "SCHEMA",
    "DIGEST",
    "SHA256",
    "NAME",
    "KIND",
    "MIME",
    "MEDIA",
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
    "ACTION",
    "BOM",
    "CANONICAL",
    "CANONICALIZATION",
    "CAPABILITY",
    "CATALOG",
    "ARTIFACT",
    "CODE",
    "ENCODING",
    "EVENT",
    "FIXED",
    "FORMAT",
    "GOVERNED",
    "HEX",
    "KEY",
    "MODEL",
    "POLICY",
    "PROTOCOL",
    "REGISTRY",
    "SEQUENCE",
    "SIGNATURE",
    "SUPPORTED",
    "UNAVAILABLE",
    "BELL",
    "CANDIDATES",
    "DISPATCH",
    "FIELD",
    "FOOTER",
    "OSC",
    "PNG",
    "POLICIES",
    "REFUSED",
    "ROOT",
    "SLOT",
    "SOURCE",
    "TOOLS",
];

const BOUND_PREFIXES: &[&str] = &[
    "MAX_", "CAP_", "CEILING_", "RESERVE_", "LIMIT_", "HARD_", "ABS_",
];

fn classify(name: &str, ty: ParamType) -> ParamClass {
    let parts: Vec<_> = name.split('_').collect();
    let structural_name = STRUCTURAL_MARKERS.iter().any(|marker| {
        parts.iter().any(|part| {
            *part == *marker
                || part.strip_suffix('S') == Some(*marker)
                || (*marker == "OSC" && part.starts_with("OSC"))
        })
    });
    let numeric = matches!(
        ty,
        ParamType::Integer | ParamType::Duration | ParamType::Float
    );
    let bounded_name = BOUND_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.ends_with("_CAP")
        || parts
            .iter()
            .any(|part| matches!(*part, "MAX" | "CAP" | "CEILING" | "LIMIT" | "HARD"));
    // A numeric MAX_* is a bound even when its name also contains a structural word
    // (`MAX_SCHEMA_BYTES` bounds a size, it does not name a schema), so bounds are tested first.
    if numeric && bounded_name {
        return ParamClass::Bounded;
    }
    // These are presentation truncation controls, not digest identity or cryptographic widths.
    if numeric && name.ends_with("_PREFIX_CHARS") {
        return ParamClass::Searchable;
    }
    let numeric_structural = parts.iter().any(|part| {
        matches!(
            *part,
            "VERSION"
                | "SCHEMA"
                | "ID"
                | "SHA256"
                | "HASH"
                | "HEX"
                | "DIGEST"
                | "MAGIC"
                | "DOMAIN"
                | "COUNT"
                | "REVISION"
                | "ORDINAL"
                | "EXIT"
                | "ATTRIBUTE"
                | "FLAG"
                | "WEXITED"
                | "WNOHANG"
                | "WNOWAIT"
                | "PID"
                | "ACE"
                | "SEQUENCE"
        )
    });
    if (numeric && numeric_structural) || (!numeric && structural_name) {
        return ParamClass::Structural;
    }
    ParamClass::Searchable
}

fn numeric_literal(value: &str, symbols: &BTreeMap<String, i128>) -> Option<i128> {
    syn::parse_str::<syn::Expr>(value)
        .ok()
        .as_ref()
        .and_then(|expression| eval_integer_expr(expression, symbols))
}

fn literal_length(value: &str, symbols: &BTreeMap<String, i128>) -> Option<i128> {
    fn expression_length(expression: &syn::Expr, symbols: &BTreeMap<String, i128>) -> Option<i128> {
        match expression {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::ByteStr(value),
                ..
            }) => i128::try_from(value.value().len()).ok(),
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => i128::try_from(value.value().len()).ok(),
            syn::Expr::Array(value) => i128::try_from(value.elems.len()).ok(),
            syn::Expr::Repeat(value) => eval_integer_expr(&value.len, symbols),
            syn::Expr::Reference(value) => expression_length(&value.expr, symbols),
            syn::Expr::Paren(value) => expression_length(&value.expr, symbols),
            syn::Expr::Group(value) => expression_length(&value.expr, symbols),
            _ => None,
        }
    }

    syn::parse_str::<syn::Expr>(value)
        .ok()
        .as_ref()
        .and_then(|expression| expression_length(expression, symbols))
}

fn eval_integer_expr(expression: &syn::Expr, symbols: &BTreeMap<String, i128>) -> Option<i128> {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) => parse_integer_literal(value),
        syn::Expr::Path(value) => symbols
            .get(&value.path.segments.last()?.ident.to_string())
            .copied(),
        syn::Expr::Paren(value) => eval_integer_expr(&value.expr, symbols),
        syn::Expr::Group(value) => eval_integer_expr(&value.expr, symbols),
        syn::Expr::Cast(value) => eval_integer_expr(&value.expr, symbols),
        syn::Expr::Unary(value) => {
            let operand = eval_integer_expr(&value.expr, symbols)?;
            match value.op {
                syn::UnOp::Neg(_) => operand.checked_neg(),
                syn::UnOp::Not(_) => Some(!operand),
                _ => None,
            }
        }
        syn::Expr::Binary(value) => {
            let left = eval_integer_expr(&value.left, symbols)?;
            let right = eval_integer_expr(&value.right, symbols)?;
            match value.op {
                syn::BinOp::Add(_) => left.checked_add(right),
                syn::BinOp::Sub(_) => left.checked_sub(right),
                syn::BinOp::Mul(_) => left.checked_mul(right),
                syn::BinOp::Div(_) => left.checked_div(right),
                syn::BinOp::Rem(_) => left.checked_rem(right),
                syn::BinOp::Shl(_) => left.checked_shl(u32::try_from(right).ok()?),
                syn::BinOp::Shr(_) => left.checked_shr(u32::try_from(right).ok()?),
                syn::BinOp::BitAnd(_) => Some(left & right),
                syn::BinOp::BitOr(_) => Some(left | right),
                syn::BinOp::BitXor(_) => Some(left ^ right),
                _ => None,
            }
        }
        syn::Expr::Call(value) => {
            let syn::Expr::Path(function) = value.func.as_ref() else {
                return None;
            };
            let constructor = function.path.segments.last()?.ident.to_string();
            if !matches!(
                constructor.as_str(),
                "from_secs" | "from_millis" | "from_micros" | "from_nanos"
            ) || value.args.len() != 1
            {
                return None;
            }
            eval_integer_expr(value.args.first()?, symbols)
        }
        syn::Expr::MethodCall(value) if value.method == "div_ceil" && value.args.len() == 1 => {
            let left = eval_integer_expr(&value.receiver, symbols)?;
            let right = eval_integer_expr(value.args.first()?, symbols)?;
            if right == 0 {
                None
            } else {
                left.checked_add(right.checked_sub(1)?)?.checked_div(right)
            }
        }
        syn::Expr::MethodCall(value) if value.method == "len" && value.args.is_empty() => {
            let syn::Expr::Path(receiver) = value.receiver.as_ref() else {
                return None;
            };
            symbols
                .get(&receiver.path.segments.last()?.ident.to_string())
                .copied()
        }
        _ => None,
    }
}

fn parse_integer_literal(value: &syn::LitInt) -> Option<i128> {
    let rendered = value.to_string();
    let without_suffix = rendered.strip_suffix(value.suffix()).unwrap_or(&rendered);
    let compact = without_suffix.replace('_', "");
    if let Some(hex) = compact.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = compact.strip_prefix("0o") {
        i128::from_str_radix(octal, 8).ok()
    } else if let Some(binary) = compact.strip_prefix("0b") {
        i128::from_str_radix(binary, 2).ok()
    } else {
        compact.parse().ok()
    }
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
    println!("  applied                   {}", counts.params_applied);
    println!("modules                     {}", counts.modules);
    println!("prompt artifacts            {}", counts.prompt_artifacts);
    println!(
        "  overridable               {}",
        counts.prompt_artifacts_overridable
    );

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

/// Every artifact marked `overridable` must have a real resolution site, and every artifact with a
/// resolution site must be marked.
///
/// The flag is hand-maintained and the code is not, so they drift the moment someone wires a
/// prompt without updating the table — or, as happened here, marks one that was never wired. A
/// grep is a crude oracle but it is the same one a reader would use, and it fails loudly rather
/// than letting the export quietly overstate itself again.
pub(crate) fn artifacts_check(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    let mut wired = std::collections::BTreeSet::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap_or_default();
        let compact = source
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        for artifact in iteron_tunables::PROMPT_ARTIFACTS {
            if compact.contains(&format!("artifact_override(document,\"{}\"", artifact.id))
                || compact.contains(&format!("prompt_artifact(\"{}\"", artifact.id))
                || compact.contains(&format!("installed_artifact(\"{}\"", artifact.id))
            {
                wired.insert(artifact.id);
            }
        }
    }
    let mut wrong = Vec::new();
    for artifact in iteron_tunables::PROMPT_ARTIFACTS {
        let has_site = wired.contains(artifact.id);
        if has_site != artifact.overridable {
            wrong.push(format!(
                "{} is marked overridable={} but has {} resolution site(s)",
                artifact.id,
                artifact.overridable,
                usize::from(has_site)
            ));
        }
    }
    if !wrong.is_empty() {
        bail!(
            "prompt artifact overridable flags disagree with the code:\n  {}",
            wrong.join("\n  ")
        );
    }
    println!(
        "prompt artifacts: {}/{} overridable, each confirmed by a resolution site",
        wired.len(),
        iteron_tunables::PROMPT_ARTIFACTS.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_inventory_finds_multiline_nested_and_associated_declarations() {
        let source = r#"
            pub const MULTILINE:
                usize =
                7;
            mod nested {
                pub static FLAG:
                    bool = true;
            }
            struct Limits;
            impl Limits {
                const CAPACITY:
                    usize = 8;
            }
            trait Versioned {
                const VERSION:
                    u32 = 1;
            }
            #[cfg(test)]
            const TEST_ONLY: usize = 9;
            #[cfg(test)]
            mod tests { const ALSO_TEST_ONLY: usize = 10; }
        "#;
        let rows = declarations(source).unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().any(|row| row.name == "MULTILINE"));
        assert!(rows.iter().any(|row| {
            row.name == "FLAG"
                && row.owner_symbol == "nested::FLAG"
                && matches!(row.kind, CandidateKind::Static)
        }));
        assert!(rows.iter().any(|row| {
            row.name == "VERSION"
                && row.owner_symbol == "Versioned::VERSION"
                && matches!(row.kind, CandidateKind::AssociatedConst)
        }));
        assert!(rows.iter().any(|row| {
            row.name == "CAPACITY"
                && row.owner_symbol == "Limits::CAPACITY"
                && matches!(row.kind, CandidateKind::AssociatedConst)
        }));
        assert!(!rows.iter().any(|row| row.name.contains("TEST_ONLY")));
    }

    #[test]
    fn map_types_are_not_collapsed_into_objects() {
        assert!(matches!(
            param_type("BTreeMap<String, usize>", "BTreeMap::new()"),
            ParamType::Map
        ));
        assert!(matches!(
            param_type("std::collections::HashMap<String, bool>", "HashMap::new()"),
            ParamType::Map
        ));
    }

    #[test]
    fn applied_evidence_finds_a_real_multiline_helper_call() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask lives below the repository root");
        let evidence = applied_evidence(root).unwrap();
        let nearby = evidence
            .keys()
            .filter(|key| key.contains("brand_icon") || key.starts_with("cli.block"))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            evidence.contains_key("cli.block.brand_icon_width"),
            "AST helper census dropped a production multiline call; total={} nearby={nearby:?}",
            evidence.len()
        );
    }
}
