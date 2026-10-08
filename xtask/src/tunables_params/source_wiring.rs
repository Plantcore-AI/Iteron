//! Explicit maintainer source rewrites; owns finite AST spans and replacements, never the catalog.
use super::{collect_rust_files, has_cfg_test, is_test_path, scan, source_offset};
use anyhow::{Context, Result};
use iteron_tunables::{ParamClass, ParamType};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

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
