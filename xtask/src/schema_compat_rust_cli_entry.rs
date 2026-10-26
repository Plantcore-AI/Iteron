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
        if root.join("crates/host/src/lib.rs").is_file() {
            return validate_host(root, main);
        }
        require_module(&file, "output")?;
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

/// Resolve a real, unconditional named import and reject a duplicate declaration.
pub(super) fn require_binding(file: &syn::File, name: &str, expected: &[&str]) -> Result<()> {
    let mut origins = Vec::new();
    for item in &file.items {
        if let syn::Item::Use(import) = item {
            let mut bindings = Vec::new();
            flatten_use(&import.tree, &mut Vec::new(), &mut bindings)?;
            for (binding, origin, renamed) in bindings {
                if binding == name {
                    if renamed || import.attrs.iter().any(|a| !a.path().is_ident("doc")) {
                        bail!("shared host binding '{name}' is conditional or renamed");
                    }
                    origins.push(origin);
                }
            }
        }
        let declared = match item {
            syn::Item::Mod(v) => Some(&v.ident),
            syn::Item::Fn(v) => Some(&v.sig.ident),
            syn::Item::Struct(v) => Some(&v.ident),
            syn::Item::Enum(v) => Some(&v.ident),
            syn::Item::Type(v) => Some(&v.ident),
            syn::Item::Const(v) => Some(&v.ident),
            syn::Item::Static(v) => Some(&v.ident),
            syn::Item::ExternCrate(v) => Some(&v.ident),
            _ => None,
        };
        if declared.is_some_and(|ident| ident == name) {
            bail!("shared host binding '{name}' is shadowed");
        }
    }
    let expected = expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    if origins != [expected] {
        bail!("shared host binding '{name}' has redirected authority");
    }
    Ok(())
}

fn validate_host(root: &Path, main: &str) -> Result<MachineOwner> {
    let file = parse(main)?;
    for module in ["output", "machine_projection", "runtime"] {
        require_binding(&file, module, &["iteron_host", module])?;
    }
    let host = load(root, "crates/host/src/lib.rs")?;
    for module in [
        "output",
        "machine_projection",
        "runtime",
        "launch",
        "cli_entry",
        "server",
        "transport",
    ] {
        require_module(&host, module)?;
    }
    let adapter = read(root, "crates/cli/src/cli_entry/mod.rs")?;
    let expected: syn::File = syn::parse_quote! {
        pub(crate) use iteron_host::cli_entry::*;
        pub(crate) mod frontend;
        pub(crate) mod local_commands;
        mod workflow_command;
        pub(crate) use workflow_command::run_workflow_command;
    };
    let mut parsed = parse(&adapter)?;
    parsed.attrs.clear();
    if parsed.to_token_stream().to_string() != expected.to_token_stream().to_string() {
        bail!("CLI entry adapter redirects the shared host admission exports");
    }
    let entry = load(root, "crates/host/src/cli_entry/mod.rs")?;
    for module in ["options", "preflight", "run_options"] {
        require_module(&entry, module)?;
    }
    validate_server_ports(
        &read(root, "crates/host/src/server.rs")?,
        &read(root, "crates/app-server/src/main.rs")?,
    )?;
    let frontend = read(root, "crates/cli/src/cli_entry/frontend.rs")?;
    validate_host_extracted(
        main,
        &frontend,
        &read(root, "crates/host/src/launch.rs")?,
        &read(root, "crates/host/src/cli_entry/options.rs")?,
        &read(root, "crates/host/src/cli_entry/preflight.rs")?,
        &read(root, "crates/host/src/cli_entry/run_options.rs")?,
    )?;
    Ok(MachineOwner {
        source: frontend,
        function: "drive",
    })
}

fn validate_host_extracted(
    main: &str,
    frontend: &str,
    assembly: &str,
    options: &str,
    preflight: &str,
    run_options: &str,
) -> Result<()> {
    let main = parse(main)?;
    for module in ["output", "machine_projection", "runtime"] {
        require_binding(&main, module, &["iteron_host", module])?;
    }
    super::cli_main::validate_entrypoint(&main)?;
    let wrapper = validate_startup_wrapper(&main)?;
    let mut entry_probe = CoordinatorProbe {
        startup_wrapper: wrapper,
        ..Default::default()
    };
    entry_probe.visit_block(&unique_function(&main, "main")?.block);
    if entry_probe.invalid || entry_probe.stdout {
        bail!("CLI entry has a startup shadow or stdout bypass");
    }
    let run = unique_function(&main, "run_cli")?;
    let signature: syn::Signature = syn::parse_quote!(async fn run_cli() -> anyhow::Result<u8>);
    if run.sig.to_token_stream().to_string() != signature.to_token_stream().to_string()
        || !run.attrs.is_empty()
        || !matches!(run.vis, syn::Visibility::Inherited)
    {
        bail!("CLI launch coordinator has redirected authority");
    }
    let expected_tail: syn::Stmt = syn::parse_quote! {
        match startup_future!(iteron_host::launch::assemble(cli, startup, validated)).await? {
            iteron_host::launch::AssemblyOutcome::Exit(code) => Ok(code),
            iteron_host::launch::AssemblyOutcome::Ready(launch) => {
                startup_future!(cli_entry::frontend::drive(*launch)).await
            }
        }
    };
    if run
        .block
        .stmts
        .last()
        .map(|s| s.to_token_stream().to_string())
        != Some(expected_tail.to_token_stream().to_string())
    {
        bail!("CLI launch must forward the admitted host envelope directly to one frontend");
    }
    validate_projection(run, &["validated", "cli", "startup"], wrapper)?;
    for name in ["output_format", "machine_schema_version"] {
        let mut probe = ProjectionProbe {
            name,
            bindings: 0,
            invalid: false,
            startup_wrapper: wrapper,
        };
        probe.visit_block(&run.block);
        if probe.bindings != 0 || probe.invalid {
            bail!("CLI coordinator shadows shared output authority");
        }
    }
    let mut probe = CoordinatorProbe {
        startup_wrapper: wrapper,
        ..Default::default()
    };
    probe.visit_block(&run.block);
    if probe.frontend_calls != 1
        || probe.preflight_calls != 1
        || probe.assembly_calls != 1
        || probe.stdout
        || probe.invalid
    {
        bail!("CLI launch must admit, assemble and dispatch exactly once without stdout bypasses");
    }
    let admission: syn::Stmt = syn::parse_quote! {
        let validated = match cli_entry::preflight::validate(&cli)? {
            cli_entry::preflight::PreflightOutcome::Exit(code) => return Ok(code),
            cli_entry::preflight::PreflightOutcome::Run(launch) => launch,
        };
    };
    if !run
        .block
        .stmts
        .iter()
        .any(|s| s.to_token_stream().to_string() == admission.to_token_stream().to_string())
    {
        bail!("CLI coordinator does not preserve the preflight admission result");
    }
    let assembly = parse(assembly)?;
    require_binding(&assembly, "cli_entry", &["crate", "cli_entry"])?;
    require_binding(
        &assembly,
        "OutputFormat",
        &["crate", "output", "OutputFormat"],
    )?;
    let assembly_wrapper = validate_startup_wrapper_for(&assembly, true)?;
    let assemble = unique_function(&assembly, "assemble")?;
    let mut assembly_probe = CoordinatorProbe {
        startup_wrapper: assembly_wrapper,
        ..Default::default()
    };
    assembly_probe.visit_block(&assemble.block);
    if assembly_probe.invalid
        || assembly_probe.stdout
        || assembly_probe.frontend_calls != 0
        || assembly_probe.preflight_calls != 0
        || assembly_probe.assembly_calls != 0
    {
        bail!("shared host assembly contains an output bypass or repeated admission/dispatch");
    }
    let signature: syn::Signature = syn::parse_quote!(async fn assemble(cli: cli_entry::Cli,
        mut startup: startup::StartupTiming, validated: cli_entry::preflight::ValidatedLaunch,) -> anyhow::Result<AssemblyOutcome>);
    if assemble.sig.to_token_stream().to_string() != signature.to_token_stream().to_string()
        || !matches!(assemble.vis, syn::Visibility::Public(_))
        || !assemble.attrs.is_empty()
    {
        bail!("shared host assembly redirects its admission signature");
    }
    validate_projection(
        assemble,
        &["output_format", "machine_schema_version"],
        assembly_wrapper,
    )?;
    let schema: syn::Stmt = syn::parse_quote! {
        let cli_entry::preflight::ValidatedLaunch { machine_schema_version, tunables_profile_document, } = validated;
    };
    if !assemble
        .block
        .stmts
        .iter()
        .any(|s| s.to_token_stream().to_string() == schema.to_token_stream().to_string())
    {
        bail!("shared host transforms the admitted machine schema");
    }
    let format: syn::Stmt = syn::parse_quote! {
        let cli_entry::run_options::ResolvedLaunchOptions {
            max_turns, max_turns_origin, max_usd, max_usd_origin, max_tokens,
            max_tokens_origin, max_wall_secs, max_wall_secs_origin, allow_code,
            allow_code_origin, effort_runtime_override, resolved_effort, effort_origin,
            headless_serve, one_shot, output_format, mode_runtime_override, mode,
            mode_origin, one_shot_images, runtime_profile,
        } = cli_entry::run_options::resolve(&cli, &file, &user_file)?;
    };
    if !assemble
        .block
        .stmts
        .iter()
        .any(|s| s.to_token_stream().to_string() == format.to_token_stream().to_string())
    {
        bail!("shared host transforms the resolved output format");
    }
    for field in ["output_format", "machine_schema_version"] {
        validate_envelope_projection(assemble, "FrontendLaunch", field)?;
    }
    let frontend = parse(frontend)?;
    authority_import(&frontend, "Emitter", &["crate", "output", "Emitter"])?;
    authority_import(&frontend, "output", &["crate", "output"])?;
    require_binding(
        &frontend,
        "FrontendLaunch",
        &["iteron_host", "launch", "FrontendLaunch"],
    )?;
    let drive = unique_function(&frontend, "drive")?;
    let signature: syn::Signature =
        syn::parse_quote!(async fn drive(launch: FrontendLaunch) -> anyhow::Result<u8>);
    if drive.sig.to_token_stream().to_string() != signature.to_token_stream().to_string()
        || !matches!(drive.vis, syn::Visibility::Restricted(_))
    {
        bail!("CLI presentation owner signature is redirected");
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

fn validate_server_ports(server: &str, entry: &str) -> Result<()> {
    let server = parse(server)?;
    let entry = parse(entry)?;
    let expected_host: syn::ItemFn = syn::parse_quote! {
    pub async fn run(options: Cli) -> anyhow::Result<u8> {
        if !matches!(options.command, Some(LocalCommand::Serve { .. })) {
            anyhow::bail!("the AppServer host requires server launch options");
        }
        let startup = crate::startup::StartupTiming::from_env();
        let validated = match crate::cli_entry::preflight::validate(&options)? {
            crate::cli_entry::preflight::PreflightOutcome::Exit(code) => return Ok(code),
            crate::cli_entry::preflight::PreflightOutcome::Run(launch) => launch,
        };
        #[cfg(windows)]
        let assembled =
            boxed_startup_future(|| crate::launch::assemble(options, startup, validated)).await?;
        #[cfg(not(windows))]
        let assembled = crate::launch::assemble(options, startup, validated).await?;
        match assembled {
            AssemblyOutcome::Exit(code) => Ok(code),
            AssemblyOutcome::Ready(launch) => {
                #[cfg(windows)]
                {
                    boxed_startup_future(|| serve(*launch)).await
                }
                #[cfg(not(windows))]
                {
                    serve(*launch).await
                }
            }
        }
    }
        };
    let expected_entry: syn::ItemFn = syn::parse_quote! {
    fn run(args: ServerArgs) -> anyhow::Result<u8> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        #[cfg(windows)]
        let launch = boxed_startup_future(|| iteron_host::server::run(args.into_launch()));
        #[cfg(not(windows))]
        let launch = iteron_host::server::run(args.into_launch());
        runtime.block_on(launch)
    }
        };
    let expected_factory: syn::ItemFn = syn::parse_quote! {
    #[cfg(windows)]
    #[inline(never)]
    fn boxed_startup_future<F: std::future::Future>(construct: impl FnOnce() -> F,) -> std::pin::Pin<Box<F>> {
        Box::pin(construct())
    }
        };
    for (file, expected) in [(&server, &expected_host), (&entry, &expected_entry)] {
        let mut function = unique_function(file, "run")?.clone();
        function.attrs.retain(|attr| !attr.path().is_ident("doc"));
        if function.to_token_stream().to_string() != expected.to_token_stream().to_string() {
            bail!("AppServer must forward one admitted launch through the canonical shared host");
        }
        let factory = unique_function(file, "boxed_startup_future")?;
        if factory.to_token_stream().to_string() != expected_factory.to_token_stream().to_string() {
            bail!("AppServer Windows startup factory redirects the shared launch");
        }
        for item in &file.items {
            if matches!(item, syn::Item::Macro(_) | syn::Item::ExternCrate(_)) {
                bail!("AppServer forwarding scope has an unproved macro or extern crate");
            }
        }
    }
    require_binding(&server, "Cli", &["crate", "cli_entry", "Cli"])?;
    require_binding(
        &server,
        "LocalCommand",
        &["crate", "cli_entry", "LocalCommand"],
    )?;
    require_binding(
        &server,
        "AssemblyOutcome",
        &["crate", "launch", "AssemblyOutcome"],
    )?;
    require_binding(
        &server,
        "FrontendLaunch",
        &["crate", "launch", "FrontendLaunch"],
    )?;
    Ok(())
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

// This is a platform allocation seam, not a second presentation authority. Match both
// definitions exactly before treating its one expression as transparent to the probes.
fn validate_startup_wrapper(file: &syn::File) -> Result<bool> {
    validate_startup_wrapper_for(file, false)
}

fn validate_startup_wrapper_for(file: &syn::File, host: bool) -> Result<bool> {
    let expected_macro: syn::ItemMacro = syn::parse_quote! {
        macro_rules! startup_future {
            ($future:expr) => {{
                #[cfg(windows)]
                {
                    boxed_startup_future(|| $future)
                }
                #[cfg(not(windows))]
                {
                    $future
                }
            }};
        }
    };
    let expected_factory: syn::ItemFn = syn::parse_quote! {
        #[cfg(windows)]
        #[inline(never)]
        fn boxed_startup_future<F: std::future::Future>(
            construct: impl FnOnce() -> F,
        ) -> std::pin::Pin<Box<F>> {
            Box::pin(construct())
        }
    };
    let mut macros = 0;
    let mut factories = 0;
    for item in &file.items {
        match item {
            syn::Item::Macro(item) => {
                if item.to_token_stream().to_string()
                    != expected_macro.to_token_stream().to_string()
                {
                    bail!("CLI startup has an unproved item macro");
                }
                macros += 1;
            }
            syn::Item::Fn(item) if item.sig.ident == "boxed_startup_future" => {
                if item.to_token_stream().to_string()
                    != expected_factory.to_token_stream().to_string()
                {
                    bail!("CLI startup future factory is not the lazy Windows allocation seam");
                }
                factories += 1;
            }
            syn::Item::Use(item) => {
                let mut bindings = Vec::new();
                flatten_use(&item.tree, &mut Vec::new(), &mut bindings)?;
                if bindings.iter().any(|(name, origin, renamed)| {
                    startup_binding(name)
                        || (name == "cli_entry"
                            && !(host
                                && !renamed
                                && origin == &["crate".to_owned(), "cli_entry".to_owned()]))
                }) {
                    bail!("CLI startup authority is shadowed by an import");
                }
            }
            syn::Item::ExternCrate(_) => bail!("CLI startup has an extern-crate bypass"),
            _ => {
                let name = match item {
                    syn::Item::Const(item) => Some(&item.ident),
                    syn::Item::Enum(item) => Some(&item.ident),
                    syn::Item::Fn(item) => Some(&item.sig.ident),
                    syn::Item::Mod(item) => Some(&item.ident),
                    syn::Item::Static(item) => Some(&item.ident),
                    syn::Item::Struct(item) => Some(&item.ident),
                    syn::Item::Trait(item) => Some(&item.ident),
                    syn::Item::TraitAlias(item) => Some(&item.ident),
                    syn::Item::Type(item) => Some(&item.ident),
                    syn::Item::Union(item) => Some(&item.ident),
                    _ => None,
                };
                if name.is_some_and(|name| startup_binding(&name.to_string())) {
                    bail!("CLI startup authority has a shadowing declaration");
                }
            }
        }
    }
    match (macros, factories) {
        (0, 0) => Ok(false), // Retain the original direct-call entry form.
        (1, 1) => Ok(true),
        _ => bail!("CLI startup wrapper and factory must have one matching definition"),
    }
}

fn startup_binding(name: &str) -> bool {
    matches!(
        name,
        "startup_future" | "boxed_startup_future" | "Box" | "FnOnce" | "std" | "iteron_host"
    )
}

fn is_startup_wrapper(mac: &syn::Macro) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "startup_future")
}

fn startup_expression(mac: &syn::Macro, validated: bool) -> Result<syn::Expr> {
    if !validated
        || !mac.path.is_ident("startup_future")
        || !matches!(mac.delimiter, syn::MacroDelimiter::Paren(_))
    {
        bail!("CLI startup invocation is redirected or has no validated definition");
    }
    syn::parse2(mac.tokens.clone()).context("CLI startup wrapper requires exactly one expression")
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
    let startup_wrapper = validate_startup_wrapper(&main)?;
    let mut entry_probe = CoordinatorProbe {
        startup_wrapper,
        ..Default::default()
    };
    entry_probe.visit_block(&unique_function(&main, "main")?.block);
    if entry_probe.invalid || entry_probe.stdout {
        bail!("CLI entry has a startup shadow or stdout bypass");
    }
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
    let expanded;
    let presentation = if let syn::Expr::Macro(wrapper) = tail.base.as_ref() {
        if !wrapper.attrs.is_empty() {
            bail!("CLI startup presentation invocation is conditional");
        }
        expanded = startup_expression(&wrapper.mac, startup_wrapper)?;
        &expanded
    } else {
        tail.base.as_ref()
    };
    let syn::Expr::Call(call) = presentation else {
        bail!("CLI presentation tail is not a direct call");
    };
    if !tail.attrs.is_empty()
        || !call.attrs.is_empty()
        || !path_is(&call.func, &["cli_entry", "frontend", "drive"])
        || call.args.len() != 1
    {
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
    validate_projection(
        run,
        &["output_format", "machine_schema_version"],
        startup_wrapper,
    )?;
    let mut probe = CoordinatorProbe {
        startup_wrapper,
        ..Default::default()
    };
    probe.visit_block(&run.block);
    if probe.frontend_calls != 1 || probe.preflight_calls != 1 || probe.stdout || probe.invalid {
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
    let entry_resolve = unique_function(run_options, "resolve")?;
    // Terminal detection is injected into the same resolver for deterministic launch tests.
    // Accept only this exact forwarding wrapper; the selected output still has one immutable
    // binding and one envelope field in the actual resolver below.
    let terminal_wrapper: syn::Block = syn::parse_quote!({
        use std::io::IsTerminal;
        resolve_with_terminal(
            cli,
            file,
            user_file,
            std::io::stdout().is_terminal() && std::io::stdin().is_terminal(),
        )
    });
    let resolve = if entry_resolve.block.to_token_stream().to_string()
        == terminal_wrapper.to_token_stream().to_string()
    {
        unique_function(run_options, "resolve_with_terminal")?
    } else {
        entry_resolve
    };
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
    validate_projection(function, names, false)
}

fn validate_projection(
    function: &syn::ItemFn,
    names: &[&str],
    startup_wrapper: bool,
) -> Result<()> {
    for name in names {
        let mut probe = ProjectionProbe {
            name,
            bindings: 0,
            invalid: false,
            startup_wrapper,
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
    startup_wrapper: bool,
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
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if is_startup_wrapper(mac) {
            match startup_expression(mac, self.startup_wrapper) {
                Ok(expr) => {
                    let mut nested = ProjectionProbe {
                        name: self.name,
                        bindings: 0,
                        invalid: false,
                        startup_wrapper: self.startup_wrapper,
                    };
                    nested.visit_expr(&expr);
                    self.bindings += nested.bindings;
                    self.invalid |= nested.invalid;
                }
                Err(_) => self.invalid = true,
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

#[derive(Default)]
struct CoordinatorProbe {
    frontend_calls: usize,
    preflight_calls: usize,
    assembly_calls: usize,
    stdout: bool,
    startup_wrapper: bool,
    inside_startup: bool,
    invalid: bool,
}
impl<'ast> Visit<'ast> for CoordinatorProbe {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        self.invalid |= self.inside_startup && !attr.path().is_ident("doc");
        syn::visit::visit_attribute(self, attr);
    }
    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        // A block-local declaration can replace a validated path or macro at its use site.
        self.invalid |= matches!(stmt, syn::Stmt::Item(_));
        if let syn::Stmt::Macro(item) = stmt {
            self.invalid |= is_startup_wrapper(&item.mac) && !item.attrs.is_empty();
        }
        syn::visit::visit_stmt(self, stmt);
    }
    fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
        self.invalid |= startup_binding(&pat.ident.to_string()) || pat.ident == "cli_entry";
        syn::visit::visit_pat_ident(self, pat);
    }
    fn visit_expr_macro(&mut self, expr: &'ast syn::ExprMacro) {
        self.invalid |= is_startup_wrapper(&expr.mac) && !expr.attrs.is_empty();
        syn::visit::visit_expr_macro(self, expr);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_is(&call.func, &["cli_entry", "frontend", "drive"]) {
            self.frontend_calls += 1;
        }
        if path_is(&call.func, &["cli_entry", "preflight", "validate"]) {
            self.preflight_calls += 1;
        }
        if path_is(&call.func, &["iteron_host", "launch", "assemble"]) {
            self.assembly_calls += 1;
        }
        if path_is(&call.func, &["stdout"]) || path_is(&call.func, &["std", "io", "stdout"]) {
            self.stdout = true;
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if is_startup_wrapper(mac) {
            match startup_expression(mac, self.startup_wrapper) {
                Ok(expr) => {
                    let mut nested = CoordinatorProbe {
                        startup_wrapper: self.startup_wrapper,
                        inside_startup: true,
                        ..Default::default()
                    };
                    nested.visit_expr(&expr);
                    self.frontend_calls += nested.frontend_calls;
                    self.preflight_calls += nested.preflight_calls;
                    self.assembly_calls += nested.assembly_calls;
                    self.stdout |= nested.stdout;
                    self.invalid |= nested.invalid;
                }
                Err(_) => self.invalid = true,
            }
        } else if self.inside_startup {
            // Unknown macro payloads are opaque. Do not create a new bypass by accepting
            // them inside the one wrapper whose expression we claim to have inspected.
            self.invalid = true;
        }
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
