//! Rebuildable physical production/test and responsibility inventory for refactoring decisions.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::Visit;

const MAX_SOURCE_BYTES: u64 = 2 * 1_024 * 1_024;
const PRODUCTION_TARGET: usize = 1_200;

struct Surface {
    path: &'static str,
    boundary: &'static str,
    responsibilities: &'static [&'static str],
    next_seams: &'static [&'static str],
}

mod host_catalog;
mod runtime_catalog;

#[derive(Serialize)]
struct Inventory {
    version: u32,
    production_line_target: usize,
    interpretation: &'static str,
    modules: Vec<ModuleInventory>,
}

#[derive(Serialize)]
struct ModuleInventory {
    path: &'static str,
    boundary_id: &'static str,
    source_sha256: String,
    physical_lines: usize,
    production_lines: usize,
    test_lines: usize,
    exceeds_production_target: bool,
    responsibilities: &'static [&'static str],
    remaining_seams: &'static [&'static str],
}

pub(crate) fn print(root: &Path) -> Result<()> {
    let modules = runtime_catalog::SURFACES
        .iter()
        .chain(host_catalog::SURFACES.iter())
        .filter(|surface| root.join(surface.path).is_file())
        .map(|surface| measure(root, surface))
        .collect::<Result<Vec<_>>>()?;
    let inventory = Inventory {
        version: 1,
        production_line_target: PRODUCTION_TARGET,
        interpretation: "Physical source lines; syntactically test-only items excluded via Rust AST spans. Comments and blanks are counted. This is a refactoring inventory, not architecture or release acceptance.",
        modules,
    };
    println!("{}", serde_json::to_string_pretty(&inventory)?);
    Ok(())
}

fn measure(root: &Path, surface: &Surface) -> Result<ModuleInventory> {
    let mut source = String::new();
    std::fs::File::open(root.join(surface.path))?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_string(&mut source)?;
    if source.len() as u64 > MAX_SOURCE_BYTES {
        bail!("architecture inventory source exceeded byte ceiling");
    }
    let parsed = syn::parse_file(&source).with_context(|| format!("parse {}", surface.path))?;
    let physical_lines = source.lines().count();
    let mut visitor = TestLines {
        lines: BTreeSet::new(),
        physical_lines,
    };
    visitor.visit_file(&parsed);
    let test_lines = visitor.lines.len();
    let production_lines = physical_lines - test_lines;
    Ok(ModuleInventory {
        path: surface.path,
        boundary_id: surface.boundary,
        source_sha256: hex_digest(source.as_bytes()),
        physical_lines,
        production_lines,
        test_lines,
        exceeds_production_target: production_lines > PRODUCTION_TARGET,
        responsibilities: surface.responsibilities,
        remaining_seams: surface.next_seams,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The same syntax-aware count feeds the inventory and the production owner gate. Tests may
/// use private owner fixtures; optional product code remains part of the enforced owner budget.
pub(crate) fn production_lines(source: &str) -> Result<usize> {
    let parsed = syn::parse_file(source)?;
    let physical_lines = source.lines().count();
    let mut visitor = TestLines {
        lines: BTreeSet::new(),
        physical_lines,
    };
    visitor.visit_file(&parsed);
    Ok(physical_lines - visitor.lines.len())
}

pub(crate) fn test_only_item(item: &syn::Item) -> bool {
    let attributes = match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => return false,
    };
    test_only(attributes)
}

struct TestLines {
    lines: BTreeSet<usize>,
    physical_lines: usize,
}

impl<'ast> Visit<'ast> for TestLines {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if test_only_item(item) {
            self.include(item.span());
        } else {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attributes = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => return syn::visit::visit_impl_item(self, item),
        };
        if test_only(attributes) {
            self.include(item.span());
        } else {
            syn::visit::visit_impl_item(self, item);
        }
    }
}

impl TestLines {
    fn include(&mut self, span: proc_macro2::Span) {
        let start = span.start().line.max(1);
        let end = span.end().line.min(self.physical_lines);
        self.lines.extend(start..=end);
    }
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .filter_map(|attribute| attribute.parse_args::<syn::Meta>().ok())
        .any(|meta| requires_test(&meta))
}

fn requires_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser;
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") => {
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .is_ok_and(|items| items.iter().any(requires_test))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_excludes_only_test_items_and_retains_conditional_product_code() {
        let source = "struct Owner {}\n#[cfg(test)]\nmod tests {\n fn one() {}\n}\n#[cfg(any(test, feature = \"optional\"))]\nfn product() {}\nimpl Owner {\n #[cfg(all(test, unix))]\n fn helper() {}\n}\n";
        let parsed = syn::parse_file(source).unwrap();
        let mut visitor = TestLines {
            lines: BTreeSet::new(),
            physical_lines: source.lines().count(),
        };
        visitor.visit_file(&parsed);
        assert!(visitor.lines.contains(&2) && visitor.lines.contains(&5));
        assert!(visitor.lines.contains(&9) && visitor.lines.contains(&10));
        assert!(!visitor.lines.contains(&6) && !visitor.lines.contains(&7));
    }
}
