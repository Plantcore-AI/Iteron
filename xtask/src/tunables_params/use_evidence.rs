//! Read-only AST evidence of real runtime parameter helper calls, including macro tokens.
use super::{UseSiteRow, collect_rust_files, has_cfg_test, is_test_path};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

pub(super) fn applied_evidence(root: &Path) -> Result<BTreeMap<String, Vec<UseSiteRow>>> {
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
