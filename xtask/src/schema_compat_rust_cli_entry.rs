//! Resolve the actual CLI presentation owner and prove its directional admission ports.
use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use super::cli_main::{flatten_use, path_is, unique_function};
use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::path::Path;
use syn::visit::Visit;

pub(super) struct MachineOwner {
    pub(super) source: String,
    pub(super) function: &'static str,
}

pub(super) fn validate(root: &Path, main: &str) -> Result<MachineOwner> {
    let file = parse(main)?;
    if file
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Mod(m) if m.ident == "cli_entry"))
    {
        require_module(&file, "cli_entry")?;
        let entry = load(root, "crates/cli/src/cli_entry/mod.rs")?;
        for module in ["frontend", "options", "preflight", "run_options"] {
            require_module(&entry, module)?;
        }
        let frontend_source = read(root, "crates/cli/src/cli_entry/frontend.rs")?;
        validate_extracted(
            main,
            &frontend_source,
            &read(root, "crates/cli/src/cli_entry/options.rs")?,
            &read(root, "crates/cli/src/cli_entry/preflight.rs")?,
            &read(root, "crates/cli/src/cli_entry/run_options.rs")?,
        )?;
        Ok(MachineOwner {
            source: frontend_source,
            function: "drive",
        })
    } else {
        super::cli_main::validate(main)?;
        Ok(MachineOwner {
            source: main.to_owned(),
            function: "run_cli",
        })
    }
}

fn read(root: &Path, path: &str) -> Result<String> {
    String::from_utf8(read_bounded(root, path, MAX_SOURCE_BYTES)?)
        .with_context(|| format!("CLI authority source '{path}' is not UTF-8"))
}

fn load(root: &Path, path: &str) -> Result<syn::File> {
    parse(&read(root, path)?)
}

fn parse(source: &str) -> Result<syn::File> {
    let file = syn::parse_file(source).context("CLI authority source does not parse as Rust")?;
    if file.attrs.iter().any(|attr| !attr.path().is_ident("doc")) {
        bail!("CLI authority source has an active crate attribute");
    }
    Ok(file)
}

fn require_module(file: &syn::File, name: &str) -> Result<()> {
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == name => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1
        || modules[0].content.is_some()
        || modules[0]
            .attrs
            .iter()
            .any(|attr| !attr.path().is_ident("doc"))
    {
        bail!("CLI authority module '{name}' is missing, conditional or redirected");
    }
    Ok(())
}

fn authority_import(file: &syn::File, name: &str, expected: &[&str]) -> Result<()> {
    let mut origins = Vec::new();
    for item in &file.items {
        if let syn::Item::Use(item) = item {
            if item.attrs.iter().any(|attr| !attr.path().is_ident("doc")) {
                bail!("CLI authority import is conditional");
            }
            let mut bindings = Vec::new();
            flatten_use(&item.tree, &mut Vec::new(), &mut bindings)?;
            for (binding, origin, renamed) in bindings {
                if binding == name {
                    if renamed {
                        bail!("CLI output authority '{name}' is renamed");
                    }
                    origins.push(origin);
                }
            }
        }
        if matches!(item, syn::Item::ExternCrate(_) | syn::Item::Macro(_)) {
            bail!("CLI authority has an item-macro or extern-crate bypass");
        }
    }
    let expected = expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    if origins != [expected] {
        bail!("CLI output authority '{name}' has a redirected import");
    }
    Ok(())
}

fn validate_extracted(
    main: &str,
    frontend: &str,
    options: &str,
    preflight: &str,
    run_options: &str,
) -> Result<()> {
    let main = parse(main)?;
    super::cli_main::validate_entrypoint(&main)?;
    let run = unique_function(&main, "run_cli")?;
    if !run.attrs.is_empty()
        || !matches!(run.vis, syn::Visibility::Inherited)
        || run.sig.asyncness.is_none()
        || !run.sig.inputs.is_empty()
        || run.sig.unsafety.is_some()
        || !run.sig.generics.params.is_empty()
    {
        bail!("CLI launch coordinator has redirected authority");
    }
    // Presentation is the awaited tail: no second frontend and no output transform after it.
    let Some(syn::Stmt::Expr(syn::Expr::Await(tail), None)) = run.block.stmts.last() else {
        bail!("CLI launch does not return its awaited presentation port");
    };
    let syn::Expr::Call(call) = tail.base.as_ref() else {
        bail!("CLI presentation tail is not a direct call");
    };
    if !path_is(&call.func, &["cli_entry", "frontend", "drive"]) || call.args.len() != 1 {
        bail!("CLI presentation port is redirected");
    }
    let syn::Expr::Struct(launch) = &call.args[0] else {
        bail!("CLI presentation port lacks a typed launch envelope");
    };
    if launch.path.to_token_stream().to_string() != "cli_entry :: frontend :: FrontendLaunch"
        || launch.rest.is_some()
    {
        bail!("CLI presentation launch envelope is redirected or inherits fields");
    }
    for name in ["output_format", "machine_schema_version"] {
        let fields = launch
            .fields
            .iter()
            .filter(|field| {
                field.member
                    == syn::Member::Named(syn::Ident::new(name, proc_macro2::Span::call_site()))
            })
            .collect::<Vec<_>>();
        if fields.len() != 1 || !path_is(&fields[0].expr, &[name]) {
            bail!("CLI presentation launch transforms '{name}'");
        }
    }
    validate_immutable_projection(run, &["output_format", "machine_schema_version"])?;
    let mut probe = CoordinatorProbe::default();
    probe.visit_block(&run.block);
    if probe.frontend_calls != 1 || probe.preflight_calls != 1 || probe.stdout {
        bail!("CLI launch must validate once and dispatch once without a stdout bypass");
    }
    let body = run.block.to_token_stream().to_string();
    if !body
        .contains("cli_entry :: preflight :: PreflightOutcome :: Exit (code) => return Ok (code)")
        || !body.contains("cli_entry :: preflight :: PreflightOutcome :: Run (launch) => launch")
    {
        bail!("CLI launch does not honor preflight exit/admission");
    }
    let frontend = parse(frontend)?;
    authority_import(&frontend, "Emitter", &["crate", "output", "Emitter"])?;
    authority_import(
        &frontend,
        "OutputFormat",
        &["crate", "output", "OutputFormat"],
    )?;
    authority_import(&frontend, "output", &["crate", "output"])?;
    let drive = unique_function(&frontend, "drive")?;
    let expected: syn::Signature =
        syn::parse_quote!(async fn drive(launch: FrontendLaunch) -> anyhow::Result<u8>);
    if drive.sig.to_token_stream().to_string() != expected.to_token_stream().to_string()
        || !matches!(drive.vis, syn::Visibility::Restricted(_))
    {
        bail!("CLI presentation owner has a redirected signature");
    }
    validate_immutable_projection(drive, &["output_format", "machine_schema_version"])?;
    super::cli_main::validate_machine_driver(drive, true)?;
    authority_import(
        &parse(options)?,
        "OutputFormat",
        &["crate", "output", "OutputFormat"],
    )?;
    validate_admission(&parse(preflight)?, &parse(run_options)?)
}

fn validate_admission(preflight: &syn::File, run_options: &syn::File) -> Result<()> {
    let validation = unique_function(preflight, "validate")?;
    authority_import(preflight, "output", &["crate", "output"])?;
    validate_immutable_projection(validation, &["machine_schema_version"])?;
    let body = validation.block.to_token_stream().to_string();
    let expected: syn::Stmt = syn::parse_quote! {
        let machine_schema_version = cli.output_schema_version.unwrap_or(output::DEFAULT_SCHEMA_VERSION);
    };
    if !validation.attrs.is_empty() || !body.contains(&expected.to_token_stream().to_string()) {
        bail!("CLI preflight does not derive the selected schema from the canonical default");
    }
    let guard: syn::Expr =
        syn::parse_quote!(!output::SUPPORTED_SCHEMA_VERSIONS.contains(&machine_schema_version));
    let mut supported_refusal = false;
    for stmt in &validation.block.stmts {
        if let syn::Stmt::Expr(syn::Expr::If(branch), _) = stmt
            && branch.cond.to_token_stream().to_string() == guard.to_token_stream().to_string()
            && branch.else_branch.is_none()
            && branch.then_branch.stmts.len() == 1
            && matches!(&branch.then_branch.stmts[0], syn::Stmt::Macro(mac) if mac.mac.path.to_token_stream().to_string() == "anyhow :: bail")
        {
            supported_refusal = true;
        }
    }
    if !supported_refusal {
        bail!("CLI preflight does not refuse unsupported machine schemas");
    }
    let resolve = unique_function(run_options, "resolve")?;
    validate_immutable_projection(resolve, &["output_format"])?;
    validate_envelope_projection(validation, "ValidatedLaunch", "machine_schema_version")?;
    validate_envelope_projection(resolve, "ResolvedLaunchOptions", "output_format")?;
    let expected: syn::Stmt = syn::parse_quote!(let output_format = cli.output_format;);
    if !resolve
        .block
        .stmts
        .iter()
        .any(|stmt| stmt.to_token_stream().to_string() == expected.to_token_stream().to_string())
    {
        bail!("CLI launch options transform the selected output format");
    }
    Ok(())
}

fn validate_envelope_projection(function: &syn::ItemFn, ty: &str, field: &str) -> Result<()> {
    let mut probe = EnvelopeProbe {
        ty,
        field,
        count: 0,
        invalid: false,
    };
    probe.visit_block(&function.block);
    if probe.count != 1 || probe.invalid {
        bail!("CLI admission envelope '{ty}' transforms '{field}'");
    }
    Ok(())
}
struct EnvelopeProbe<'a> {
    ty: &'a str,
    field: &'a str,
    count: usize,
    invalid: bool,
}
impl<'ast> Visit<'ast> for EnvelopeProbe<'_> {
    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        if expr
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == self.ty)
        {
            self.count += 1;
            let fields = expr
                .fields
                .iter()
                .filter(|f| matches!(&f.member, syn::Member::Named(n) if n == self.field))
                .collect::<Vec<_>>();
            self.invalid |= expr.rest.is_some()
                || fields.len() != 1
                || !path_is(&fields[0].expr, &[self.field]);
        }
        syn::visit::visit_expr_struct(self, expr);
    }
}

fn validate_immutable_projection(function: &syn::ItemFn, names: &[&str]) -> Result<()> {
    for name in names {
        let mut probe = ProjectionProbe {
            name,
            bindings: 0,
            invalid: false,
        };
        probe.visit_block(&function.block);
        if probe.bindings != 1 || probe.invalid {
            bail!("CLI selected output '{name}' is shadowed or mutable");
        }
    }
    Ok(())
}
struct ProjectionProbe<'a> {
    name: &'a str,
    bindings: usize,
    invalid: bool,
}
impl<'ast> Visit<'ast> for ProjectionProbe<'_> {
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        if pat.ident == self.name {
            self.bindings += 1;
            self.invalid |=
                pat.mutability.is_some() || pat.by_ref.is_some() || pat.subpat.is_some();
        }
        syn::visit::visit_pat_ident(self, pat);
    }
    fn visit_expr_assign(&mut self, expr: &'ast syn::ExprAssign) {
        self.invalid |= path_is(&expr.left, &[self.name]);
        syn::visit::visit_expr_assign(self, expr);
    }
}

#[derive(Default)]
struct CoordinatorProbe {
    frontend_calls: usize,
    preflight_calls: usize,
    stdout: bool,
}
impl<'ast> Visit<'ast> for CoordinatorProbe {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_is(&call.func, &["cli_entry", "frontend", "drive"]) {
            self.frontend_calls += 1;
        }
        if path_is(&call.func, &["cli_entry", "preflight", "validate"]) {
            self.preflight_calls += 1;
        }
        if path_is(&call.func, &["stdout"]) || path_is(&call.func, &["std", "io", "stdout"]) {
            self.stdout = true;
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.segments.last().is_some_and(|s| {
            matches!(
                s.ident.to_string().as_str(),
                "print" | "println" | "write" | "writeln"
            )
        }) {
            self.stdout = true;
        }
        syn::visit::visit_macro(self, mac);
    }
}

#[cfg(test)]
#[path = "schema_compat_rust_cli_entry_tests.rs"]
mod tests;
