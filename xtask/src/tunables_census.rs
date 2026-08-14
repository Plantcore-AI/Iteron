//! Covered-class production optimization census and honesty gate.
//!
//! The Tier-2 catalog remains the compatibility surface for const/static parameters. This module
//! adds syntax-aware discovery of defaults expressed through serde/clap and named runtime policy
//! constructors, then emits one exact generated artifact covering those inventories. It does not
//! claim that these syntax classes exhaust every optimization input in the repository.

use crate::tunables_params::{
    CandidateKind, Disposition, InvariantReason, OwnerRow, ParamRow, UseSiteRow,
};
use anyhow::{Context, Result, bail};
use quote::ToTokens as _;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

const EXCLUDED_CRATES: &[&str] = &["xtask"];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CensusCandidateKind {
    Const,
    Static,
    AssociatedConst,
    SerdeDefault,
    ClapDefault,
    PolicyDefaultConstructor,
    PolicyFallbackCall,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExternalAddressability {
    UnifiedProfile,
    DirectConfig,
    CallerInjected,
    InvariantReadOnly,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CensusRow {
    id: String,
    candidate_kind: CensusCandidateKind,
    rust_type: String,
    value: String,
    owner: OwnerRow,
    use_sites: Vec<UseSiteRow>,
    disposition: Disposition,
    external_addressability: ExternalAddressability,
    #[serde(skip_serializing_if = "Option::is_none")]
    invariant_reason: Option<InvariantReason>,
    applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    behavior_oracle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier2_id: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CensusDocument {
    schema_version: u16,
    total: usize,
    runtime_settable: usize,
    invariant_read_only: usize,
    profile_addressable: usize,
    direct_config: usize,
    caller_injected: usize,
    runtime_applied: usize,
    candidates: Vec<CensusRow>,
}

pub(crate) fn run(root: &Path, write: bool) -> Result<()> {
    let document = scan(root)?;
    validate(&document.candidates)?;
    let mut rendered = serde_json::to_string_pretty(&document)?;
    rendered.push('\n');
    let path = root.join("governance/optimization-census.json");
    if write {
        std::fs::write(&path, rendered).with_context(|| format!("writing {}", path.display()))?;
        println!(
            "wrote governance/optimization-census.json ({} profile, {} direct config, {} caller-injected, {} invariant)",
            document.profile_addressable,
            document.direct_config,
            document.caller_injected,
            document.invariant_read_only
        );
        return Ok(());
    }
    let committed =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if committed != rendered {
        bail!(
            "governance/optimization-census.json is stale; run `cargo run --locked -p \
             iteron-xtask -- tunables generate-optimization-census`"
        );
    }
    println!(
        "optimization census matches covered source classes: {} candidates, {} runtime-settable/applied ({} unified-profile)",
        document.total, document.runtime_applied, document.profile_addressable
    );
    Ok(())
}

fn scan(root: &Path) -> Result<CensusDocument> {
    let params = crate::tunables_params::scan(root)?;
    crate::tunables_params::validate_rows(&params)?;
    let mut rows: Vec<CensusRow> = params.iter().map(CensusRow::from_param).collect();

    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    files.sort();
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
        rows.extend(discover_source(krate, &relative, &source)?);
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let runtime_settable = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::RuntimeSettable))
        .count();
    let invariant_read_only = rows.len() - runtime_settable;
    let runtime_applied = rows
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::RuntimeSettable) && row.applied)
        .count();
    let profile_addressable = addressability_count(&rows, ExternalAddressability::UnifiedProfile);
    let direct_config = addressability_count(&rows, ExternalAddressability::DirectConfig);
    let caller_injected = addressability_count(&rows, ExternalAddressability::CallerInjected);
    Ok(CensusDocument {
        schema_version: 2,
        total: rows.len(),
        runtime_settable,
        invariant_read_only,
        profile_addressable,
        direct_config,
        caller_injected,
        runtime_applied,
        candidates: rows,
    })
}

fn addressability_count(rows: &[CensusRow], expected: ExternalAddressability) -> usize {
    rows.iter()
        .filter(|row| row.external_addressability == expected)
        .count()
}

impl CensusRow {
    fn from_param(param: &ParamRow) -> Self {
        let candidate_kind = match param.candidate_kind {
            CandidateKind::Const => CensusCandidateKind::Const,
            CandidateKind::Static => CensusCandidateKind::Static,
            CandidateKind::AssociatedConst => CensusCandidateKind::AssociatedConst,
        };
        Self {
            id: param.id.clone(),
            candidate_kind,
            rust_type: param.rust_type.clone(),
            value: param.default.clone(),
            owner: param.owner.clone(),
            use_sites: param.use_sites.clone(),
            disposition: param.disposition,
            external_addressability: if matches!(param.disposition, Disposition::RuntimeSettable) {
                ExternalAddressability::UnifiedProfile
            } else {
                ExternalAddressability::InvariantReadOnly
            },
            invariant_reason: param.invariant_reason,
            applied: param.applied,
            behavior_oracle: param.behavior_oracle.clone(),
            tier2_id: Some(param.id.clone()),
        }
    }
}

fn discover_source(krate: &str, relative: &str, source: &str) -> Result<Vec<CensusRow>> {
    let syntax = syn::parse_file(source)
        .with_context(|| format!("parsing {relative} for optimization candidates"))?;
    let mut visitor = CensusVisitor {
        krate,
        relative,
        modules: Vec::new(),
        owner: Vec::new(),
        ordinals: BTreeMap::new(),
        found: Vec::new(),
    };
    visitor.visit_file(&syntax);
    Ok(visitor.found)
}

struct CensusVisitor<'a> {
    krate: &'a str,
    relative: &'a str,
    modules: Vec<String>,
    owner: Vec<String>,
    ordinals: BTreeMap<String, usize>,
    found: Vec<CensusRow>,
}

impl CensusVisitor<'_> {
    fn current_owner(&self) -> String {
        self.modules
            .iter()
            .chain(self.owner.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("::")
    }

    fn field_default(
        &mut self,
        field: &syn::Field,
        field_index: usize,
        kind: CensusCandidateKind,
        value: String,
        attribute: &str,
    ) {
        let field_name = field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("unnamed_{field_index}"));
        let owner = self.current_owner();
        let flavor = match kind {
            CensusCandidateKind::SerdeDefault => "serde_default",
            CensusCandidateKind::ClapDefault => "clap_default",
            _ => unreachable!("field defaults use serde or clap"),
        };
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{field_name}.{flavor}"),
            ),
            candidate_kind: kind,
            rust_type: field.ty.to_token_stream().to_string(),
            value,
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: format!("{owner}::{field_name}"),
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: field.span().start().line,
                evidence: format!("{attribute} production parser/deserializer default"),
            }],
            disposition: Disposition::RuntimeSettable,
            external_addressability: ExternalAddressability::DirectConfig,
            invariant_reason: None,
            applied: true,
            behavior_oracle: Some(format!(
                "explicit input for {owner}::{field_name} replaces the declared {attribute} default"
            )),
            tier2_id: None,
        });
    }

    fn inspect_fields<'a>(&mut self, fields: impl Iterator<Item = &'a syn::Field>) {
        for (field_index, field) in fields.enumerate() {
            if has_cfg_test(&field.attrs) {
                continue;
            }
            for attr in &field.attrs {
                let path = attr.path();
                let rendered = attr.meta.to_token_stream().to_string();
                if path.is_ident("serde") && attribute_option(&rendered, "default") {
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::SerdeDefault,
                        attribute_value(&rendered, "default")
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "serde(default)",
                    );
                }
                if (path.is_ident("arg") || path.is_ident("clap"))
                    && (attribute_option(&rendered, "default_value")
                        || attribute_option(&rendered, "default_value_t"))
                {
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::ClapDefault,
                        attribute_value(&rendered, "default_value_t")
                            .or_else(|| attribute_value(&rendered, "default_value"))
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "clap(default_value)",
                    );
                }
            }
        }
    }

    fn inspect_container_default(
        &mut self,
        ident: &syn::Ident,
        attrs: &[syn::Attribute],
        span: proc_macro2::Span,
    ) {
        for attr in attrs {
            let rendered = attr.meta.to_token_stream().to_string();
            if !attr.path().is_ident("serde") || !attribute_option(&rendered, "default") {
                continue;
            }
            let owner = self.current_owner();
            self.found.push(CensusRow {
                id: stable_id(self.krate, self.relative, &format!("{owner}.serde_default")),
                candidate_kind: CensusCandidateKind::SerdeDefault,
                rust_type: ident.to_string(),
                value: attribute_value(&rendered, "default")
                    .unwrap_or_else(|| "Default::default()".to_owned()),
                owner: OwnerRow {
                    krate: self.krate.to_owned(),
                    path: self.relative.to_owned(),
                    symbol: owner.clone(),
                },
                use_sites: vec![UseSiteRow {
                    path: self.relative.to_owned(),
                    line: span.start().line,
                    evidence: "serde(default) production container deserializer".to_owned(),
                }],
                disposition: Disposition::RuntimeSettable,
                external_addressability: ExternalAddressability::DirectConfig,
                invariant_reason: None,
                applied: true,
                behavior_oracle: Some(format!(
                    "explicit input fields for {owner} replace its serde container defaults"
                )),
                tier2_id: None,
            });
        }
    }

    fn policy_call(&mut self, node: &syn::ExprCall, callee: &syn::Path) {
        let rendered = callee.to_token_stream().to_string().replace(' ', "");
        let leaf = callee
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let context = format!("{}::{rendered}", self.current_owner()).to_ascii_lowercase();
        let named_default = leaf == "default" || leaf.starts_with("default_");
        let named_fallback = leaf.contains("fallback");
        if !(named_default || named_fallback) || !is_policy_context(&context) {
            return;
        }
        let key = format!("{}::{rendered}", self.current_owner());
        let ordinal = {
            let entry = self.ordinals.entry(key).or_default();
            *entry += 1;
            *entry
        };
        let kind = if named_fallback {
            CensusCandidateKind::PolicyFallbackCall
        } else {
            CensusCandidateKind::PolicyDefaultConstructor
        };
        let owner = self.current_owner();
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{rendered}.{ordinal}"),
            ),
            candidate_kind: kind,
            rust_type: "_ (inferred by rustc)".to_owned(),
            value: node.to_token_stream().to_string(),
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: owner,
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: node.span().start().line,
                evidence: "production policy constructor call".to_owned(),
            }],
            disposition: Disposition::RuntimeSettable,
            external_addressability: ExternalAddressability::CallerInjected,
            invariant_reason: None,
            applied: true,
            behavior_oracle: Some(
                "caller-provided policy/configuration replaces this constructor fallback"
                    .to_owned(),
            ),
            tier2_id: None,
        });
    }
}

impl<'ast> Visit<'ast> for CensusVisitor<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.modules.push(item.ident.to_string());
        if let Some((_, items)) = &item.content {
            for item in items {
                self.visit_item(item);
            }
        }
        self.modules.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        self.inspect_fields(item.fields.iter());
        self.owner.pop();
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        for variant in &item.variants {
            if has_cfg_test(&variant.attrs) {
                continue;
            }
            self.owner.push(variant.ident.to_string());
            self.inspect_fields(variant.fields.iter());
            self.owner.pop();
        }
        self.owner.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner
            .push(item.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit::visit_item_impl(self, item);
        self.owner.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        visit::visit_item_trait(self, item);
        self.owner.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_trait_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = node.func.as_ref() {
            self.policy_call(node, &function.path);
        }
        visit::visit_expr_call(self, node);
    }
}

fn validate(rows: &[CensusRow]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for row in rows {
        if row.id.is_empty() || !ids.insert(&row.id) {
            bail!(
                "optimization candidate id is empty or duplicated: `{}`",
                row.id
            );
        }
        if row.rust_type.trim().is_empty() || row.value.trim().is_empty() {
            bail!("{} has no Rust type/value evidence", row.id);
        }
        if row.owner.krate.is_empty() || row.owner.path.is_empty() || row.owner.symbol.is_empty() {
            bail!("{} has incomplete ownership", row.id);
        }
        match row.disposition {
            Disposition::RuntimeSettable => {
                if matches!(
                    row.external_addressability,
                    ExternalAddressability::InvariantReadOnly
                ) {
                    bail!("{} is settable but marked invariant-addressable", row.id);
                }
                if !row.applied {
                    bail!("{} is advertised runtime_settable but not applied", row.id);
                }
                if row.use_sites.is_empty() {
                    bail!(
                        "{} is runtime_settable without production use-site evidence",
                        row.id
                    );
                }
                if row.behavior_oracle.as_deref().is_none_or(str::is_empty) {
                    bail!("{} is runtime_settable without a behavior oracle", row.id);
                }
                if row.invariant_reason.is_some() {
                    bail!("{} is settable but carries an invariant reason", row.id);
                }
            }
            Disposition::InvariantReadOnly => {
                if !matches!(
                    row.external_addressability,
                    ExternalAddressability::InvariantReadOnly
                ) {
                    bail!("{} is invariant but carries a settable address", row.id);
                }
                if row.invariant_reason.is_none() {
                    bail!("{} is read-only without a closed invariant reason", row.id);
                }
                if row.applied {
                    bail!("{} is invariant_read_only but marked applied", row.id);
                }
            }
        }
    }
    Ok(())
}

fn stable_id(krate: &str, relative: &str, symbol: &str) -> String {
    let module = relative
        .rsplit_once("/src/")
        .map(|(_, tail)| tail)
        .unwrap_or(relative)
        .trim_end_matches(".rs");
    format!("{krate}.{module}.{symbol}")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn is_policy_context(context: &str) -> bool {
    [
        "policy",
        "config",
        "options",
        "limits",
        "budget",
        "retry",
        "timeout",
        "cache",
        "routing",
        "router",
        "model",
        "provider",
        "workflow",
        "verifier",
        "context",
        "memory",
        "compact",
        "prompt",
        "tool",
        "sandbox",
        "admission",
        "sampling",
        "reasoning",
        "queue",
        "concurrency",
        "turnstate",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn attribute_option(rendered: &str, name: &str) -> bool {
    rendered
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == name)
}

fn attribute_value(rendered: &str, name: &str) -> Option<String> {
    let (_, tail) = rendered.split_once(name)?;
    let value = tail.trim_start().strip_prefix('=')?.trim_start();
    Some(
        value
            .split(',')
            .next()
            .unwrap_or(value)
            .trim()
            .trim_end_matches(')')
            .trim()
            .to_owned(),
    )
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.meta.to_token_stream().to_string().contains("test")
    })
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_serde_clap_and_policy_defaults_but_excludes_tests() {
        let source = r#"
            struct RuntimePolicy {
                #[serde(default = "default_timeout")]
                timeout: u64,
                #[arg(default_value_t = 4)]
                workers: usize,
            }
            fn build_policy() { let _ = RuntimePolicy::default(); }
            #[cfg(test)]
            mod tests {
                struct Hidden { #[serde(default)] field: bool }
                fn policy_test() { let _ = RuntimePolicy::default(); }
            }
        "#;
        let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
        assert!(
            rows.iter()
                .any(|row| matches!(row.candidate_kind, CensusCandidateKind::SerdeDefault))
        );
        assert!(
            rows.iter()
                .any(|row| matches!(row.candidate_kind, CensusCandidateKind::ClapDefault))
        );
        assert!(rows.iter().any(|row| matches!(
            row.candidate_kind,
            CensusCandidateKind::PolicyDefaultConstructor
        )));
        assert_eq!(
            rows.iter()
                .filter(|row| row.owner.symbol.contains("Hidden"))
                .count(),
            0
        );
    }

    #[test]
    fn honesty_gate_rejects_settable_without_evidence() {
        let mut rows = discover_source(
            "demo",
            "crates/demo/src/lib.rs",
            "struct Config { #[serde(default)] value: usize }",
        )
        .unwrap();
        rows[0].use_sites.clear();
        assert!(
            validate(&rows)
                .unwrap_err()
                .to_string()
                .contains("without production use-site")
        );
        rows[0].use_sites.push(UseSiteRow {
            path: "crates/demo/src/lib.rs".to_owned(),
            line: 1,
            evidence: "serde".to_owned(),
        });
        rows[0].behavior_oracle = None;
        assert!(
            validate(&rows)
                .unwrap_err()
                .to_string()
                .contains("without a behavior oracle")
        );
    }

    #[test]
    fn addressability_distinguishes_profile_config_and_injection() {
        let source = r#"
            struct RuntimePolicy {
                #[serde(default)]
                enabled: bool,
                #[arg(default_value_t = 4)]
                workers: usize,
            }
            fn build_policy() { let _ = RuntimePolicy::default(); }
        "#;
        let rows = discover_source("demo", "crates/demo/src/lib.rs", source).unwrap();
        assert_eq!(
            addressability_count(&rows, ExternalAddressability::DirectConfig),
            2
        );
        assert_eq!(
            addressability_count(&rows, ExternalAddressability::CallerInjected),
            1
        );
        assert_eq!(
            addressability_count(&rows, ExternalAddressability::UnifiedProfile),
            0
        );
    }

    #[test]
    fn invariant_reason_vocabulary_has_no_generic_fallback() {
        let reasons = [
            InvariantReason::Identity,
            InvariantReason::WireCompatibility,
            InvariantReason::CapabilityAuthority,
            InvariantReason::Security,
            InvariantReason::DurabilityReplay,
            InvariantReason::HardBudgetEffectLedger,
            InvariantReason::RuntimeStateNotAValue,
        ];
        let json = serde_json::to_string(&reasons).unwrap();
        assert!(!json.contains("structural"));
        assert!(!json.contains("other"));
    }
}
