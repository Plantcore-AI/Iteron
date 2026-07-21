use anyhow::{Context, Result, bail};
use quote::ToTokens;
use syn::visit::Visit;

pub(super) fn validate(source: &str) -> Result<()> {
    let file = syn::parse_file(source).context("CLI main source does not parse as Rust")?;
    if file
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("CLI main source has an active crate attribute");
    }
    validate_top_level_authority(&file)?;
    validate_entrypoint(&file)?;
    validate_run_cli(&file)
}

fn validate_top_level_authority(file: &syn::File) -> Result<()> {
    let mut emitter_origins = Vec::new();
    let mut format_origins = Vec::new();
    for item in &file.items {
        match item {
            syn::Item::Use(item) => {
                if item
                    .attrs
                    .iter()
                    .any(|attribute| !attribute.path().is_ident("doc"))
                {
                    bail!("CLI main import has an active or conditional attribute");
                }
                let mut bindings = Vec::new();
                flatten_use(&item.tree, &mut Vec::new(), &mut bindings)?;
                for (binding, origin, renamed) in bindings {
                    if renamed && matches!(binding.as_str(), "output" | "Emitter" | "OutputFormat")
                    {
                        bail!("CLI main renames a machine-output authority binding");
                    }
                    if binding == "Emitter" {
                        emitter_origins.push(origin);
                    } else if binding == "OutputFormat" {
                        format_origins.push(origin);
                    } else if binding == "output" {
                        bail!("CLI main shadows its canonical output module");
                    }
                }
            }
            syn::Item::ExternCrate(_) | syn::Item::Macro(_) => {
                bail!("CLI main has an extern-crate or item-macro authority bypass")
            }
            _ => {}
        }
    }
    let expected = vec!["output".to_owned(), "Emitter".to_owned()];
    if emitter_origins != [expected] {
        bail!("CLI main does not import Emitter exactly from its output module");
    }
    let expected = vec!["output".to_owned(), "OutputFormat".to_owned()];
    if format_origins != [expected] {
        bail!("CLI main does not import OutputFormat exactly from its output module");
    }
    Ok(())
}

fn validate_entrypoint(file: &syn::File) -> Result<()> {
    let actual = unique_function(file, "main")?;
    let expected: syn::ItemFn = syn::parse_quote! {
        #[tokio::main]
        async fn main() -> std::process::ExitCode {
            match run_cli().await {
                Ok(code) => std::process::ExitCode::from(code),
                Err(error) => {
                    let error = core_record::redact::scrub(&format!("{error:#}"));
                    eprintln!("error: {error}");
                    std::process::ExitCode::from(output::EXIT_HARNESS)
                }
            }
        }
    };
    if actual.to_token_stream().to_string() != expected.to_token_stream().to_string() {
        bail!("CLI entrypoint no longer dispatches exactly through run_cli");
    }
    Ok(())
}

fn validate_run_cli(file: &syn::File) -> Result<()> {
    let function = unique_function(file, "run_cli")?;
    if !function.attrs.is_empty()
        || !matches!(function.vis, syn::Visibility::Inherited)
        || function.sig.asyncness.is_none()
        || function.sig.constness.is_some()
        || function.sig.unsafety.is_some()
        || function.sig.abi.is_some()
        || !function.sig.inputs.is_empty()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
    {
        bail!("CLI run_cli function has conditional or redirected authority");
    }
    let mut probe = RunCliProbe::default();
    probe.visit_block(&function.block);
    if probe.block_items != 0 || probe.authority_shadows != 0 {
        bail!(
            "CLI run_cli contains a block-local item/use or authority shadow (items={}, shadows={})",
            probe.block_items,
            probe.authority_shadows
        );
    }
    if probe.emitter_events != 2 || probe.emitter_results != 1 {
        bail!(
            "CLI run_cli must retain exactly two Emitter event drains and one result sink (events={}, results={})",
            probe.emitter_events,
            probe.emitter_results
        );
    }
    let emitter_index = function
        .block
        .stmts
        .iter()
        .position(is_emitter_binding)
        .context("CLI run_cli lacks its exact Emitter construction")?;
    let mut stdout = StdoutProbe::default();
    for statement in function.block.stmts.iter().skip(emitter_index + 1) {
        stdout.visit_stmt(statement);
    }
    if stdout.found {
        bail!("CLI machine run path bypasses Emitter with a direct stdout write");
    }
    Ok(())
}

fn unique_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .with_context(|| format!("CLI main lacks function '{name}'"))?;
    if functions.next().is_some() {
        bail!("CLI main repeats function '{name}'");
    }
    Ok(function)
}

#[derive(Default)]
struct RunCliProbe {
    block_items: usize,
    authority_shadows: usize,
    emitter_events: usize,
    emitter_results: usize,
}

impl<'ast> Visit<'ast> for RunCliProbe {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "select")
        {
            let rendered = mac.tokens.to_string();
            if rendered.matches("emitter . event (event)").count() == 1 {
                self.emitter_events = self.emitter_events.saturating_add(1);
            }
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if let syn::Stmt::Item(item) = statement {
            let trusted_terminal_import = matches!(item, syn::Item::Use(import)
                if import.attrs.is_empty() && exact_use_path(&import.tree, &["std", "io", "IsTerminal"]));
            if !trusted_terminal_import {
                self.block_items = self.block_items.saturating_add(1);
            }
        }
        syn::visit::visit_stmt(self, statement);
    }

    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        if matches!(
            pattern.ident.to_string().as_str(),
            "output" | "Emitter" | "OutputFormat"
        ) {
            self.authority_shadows = self.authority_shadows.saturating_add(1);
        }
        syn::visit::visit_pat_ident(self, pattern);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if path_is(&call.receiver, &["emitter"]) {
            if call.method == "event" && call.args.len() == 1 {
                self.emitter_events = self.emitter_events.saturating_add(1);
            } else if call.method == "result" && call.args.len() == 1 {
                self.emitter_results = self.emitter_results.saturating_add(1);
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn exact_use_path(tree: &syn::UseTree, expected: &[&str]) -> bool {
    let mut actual = Vec::new();
    let mut tree = tree;
    loop {
        match tree {
            syn::UseTree::Path(path) => {
                actual.push(path.ident.to_string());
                tree = &path.tree;
            }
            syn::UseTree::Name(name) => {
                actual.push(name.ident.to_string());
                break;
            }
            _ => return false,
        }
    }
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

#[derive(Default)]
struct StdoutProbe {
    found: bool,
}

impl<'ast> Visit<'ast> for StdoutProbe {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| {
            matches!(segment.ident.to_string().as_str(), "print" | "println")
        }) {
            self.found = true;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_is(&call.func, &["stdout"]) || path_is(&call.func, &["std", "io", "stdout"]) {
            self.found = true;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn is_emitter_binding(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Local(local) = statement else {
        return false;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return false;
    };
    let Some(initializer) = &local.init else {
        return false;
    };
    let syn::Expr::Call(call) = initializer.expr.as_ref() else {
        return false;
    };
    binding.ident == "emitter"
        && binding.mutability.is_some()
        && path_is(&call.func, &["Emitter", "new"])
        && call.args.len() == 1
}

fn path_is(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.ident == expected)
}

fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<(String, Vec<String>, bool)>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, bindings)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut origin = prefix.clone();
            origin.push(name.ident.to_string());
            bindings.push((name.ident.to_string(), origin, false));
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            origin.push(rename.ident.to_string());
            bindings.push((rename.rename.to_string(), origin, true));
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(tree, prefix, bindings)?;
            }
        }
        syn::UseTree::Glob(_) => bail!("CLI main imports cannot use glob bindings"),
    }
    Ok(())
}

#[cfg(test)]
#[path = "schema_compat_rust_cli_main_tests.rs"]
mod tests;
