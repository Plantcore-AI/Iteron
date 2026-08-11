use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit as _;

const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct CoverageReport {
    pub(crate) registered: usize,
    pub(crate) active: usize,
    pub(crate) reserved: usize,
}

pub(crate) fn check(root: &Path) -> Result<CoverageReport> {
    let registry_path = root.join("crates/protocol/src/lifecycle/registry.rs");
    let registry = parse_rust(&registry_path)?;
    let registered = string_array(&registry, "EVENTS")?;
    let reserved = string_array(&registry, "RESERVED_EVENTS")?;
    if registered.len() != registered.iter().collect::<BTreeSet<_>>().len() {
        bail!("lifecycle EVENTS contains duplicate identifiers");
    }
    if reserved.len() != reserved.iter().collect::<BTreeSet<_>>().len() {
        bail!("lifecycle RESERVED_EVENTS contains duplicate identifiers");
    }
    let unknown_reserved = reserved
        .iter()
        .filter(|event| !registered.contains(event))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_reserved.is_empty() {
        bail!("reserved lifecycle identifiers are not registered: {unknown_reserved:?}");
    }

    let mut literals = BTreeSet::new();
    let mut emitted_literals = BTreeSet::new();
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    for path in files {
        if excluded_source(root, &path) {
            continue;
        }
        let source = read_source(&path)?;
        let syntax =
            syn::parse_file(&source).with_context(|| format!("cannot parse {}", path.display()))?;
        let mut visitor = LifecycleCallVisitor {
            emitted: &mut emitted_literals,
        };
        visitor.visit_file(&syntax);
        for event in &registered {
            if source.contains(&format!("\"{event}\"")) {
                literals.insert(event.clone());
            }
        }
    }

    let unknown_emitted = emitted_literals
        .difference(&registered.iter().cloned().collect())
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_emitted.is_empty() {
        bail!("production lifecycle calls use unregistered identifiers: {unknown_emitted:?}");
    }

    let active = registered
        .iter()
        .filter(|event| !reserved.contains(event))
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing = active
        .iter()
        .filter(|event| !literals.contains(event.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("active lifecycle events without a production owner literal: {missing:?}");
    }
    let produced_reserved = reserved
        .iter()
        .filter(|event| literals.contains(event.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !produced_reserved.is_empty() {
        bail!(
            "reserved lifecycle events now have a production path; activate and classify them: {produced_reserved:?}"
        );
    }

    Ok(CoverageReport {
        registered: registered.len(),
        active: active.len(),
        reserved: reserved.len(),
    })
}

struct LifecycleCallVisitor<'a> {
    emitted: &'a mut BTreeSet<String>,
}

impl<'ast> syn::visit::Visit<'ast> for LifecycleCallVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "lifecycle_event"
                | "lifecycle_event_with_correlation"
                | "child_lifecycle_event"
                | "tool_lifecycle_event"
                | "record_lifecycle"
                | "emit"
        ) && let Some(syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(event),
            ..
        })) = node.args.first()
            && looks_like_lifecycle_id(&event.value())
        {
            self.emitted.insert(event.value());
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn looks_like_lifecycle_id(value: &str) -> bool {
    const DOMAINS: [&str; 15] = [
        "context.",
        "memory.",
        "submission.",
        "queue.",
        "steer.",
        "cancel.",
        "drain.",
        "control.",
        "tool.",
        "process.",
        "background.",
        "model.",
        "workflow.",
        "session.",
        "verification.",
    ];
    DOMAINS.iter().any(|domain| value.starts_with(domain))
        || value.starts_with("checkpoint.")
        || value.starts_with("replay.")
        || value.starts_with("hook.")
        || value.starts_with("exporter.")
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "cannot inspect lifecycle source directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_rust_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn excluded_source(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let rendered = relative.to_string_lossy();
    rendered == "crates/protocol/src/lifecycle/registry.rs"
        || rendered.starts_with("crates/obs/src/otel/")
        || rendered.contains("/tests/")
        || rendered.ends_with("/tests.rs")
        || rendered.ends_with("_tests.rs")
}

fn parse_rust(path: &Path) -> Result<syn::File> {
    let source = read_source(path)?;
    syn::parse_file(&source).with_context(|| format!("cannot parse {}", path.display()))
}

fn read_source(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() > MAX_SOURCE_BYTES {
        bail!("lifecycle source {} exceeds 2 MiB", path.display());
    }
    String::from_utf8(bytes)
        .with_context(|| format!("lifecycle source {} is not UTF-8", path.display()))
}

fn string_array(file: &syn::File, name: &str) -> Result<Vec<String>> {
    let item = file.items.iter().find_map(|item| match item {
        syn::Item::Const(item) if item.ident == name => Some(item),
        _ => None,
    });
    let Some(item) = item else {
        bail!("lifecycle registry does not declare {name}");
    };
    let syn::Expr::Array(array) = item.expr.as_ref() else {
        bail!("lifecycle registry {name} is not a literal array");
    };
    array
        .elems
        .iter()
        .map(|expression| match expression {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Ok(value.value()),
            _ => bail!("lifecycle registry {name} contains a non-string expression"),
        })
        .collect()
}
