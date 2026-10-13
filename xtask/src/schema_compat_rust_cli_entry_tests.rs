use super::validate_extracted;

struct Sources {
    main: String,
    frontend: String,
    options: String,
    preflight: String,
    run_options: String,
}

impl Sources {
    fn load() -> Self {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let read = |path| std::fs::read_to_string(root.join(path)).unwrap();
        Self {
            main: read("crates/cli/src/main.rs"),
            frontend: read("crates/cli/src/cli_entry/frontend.rs"),
            options: read("crates/cli/src/cli_entry/options.rs"),
            preflight: read("crates/cli/src/cli_entry/preflight.rs"),
            run_options: read("crates/cli/src/cli_entry/run_options.rs"),
        }
    }
    fn validate(&self) -> anyhow::Result<()> {
        validate_extracted(
            &self.main,
            &self.frontend,
            &self.options,
            &self.preflight,
            &self.run_options,
        )
    }

    fn replace_main(&mut self, before: &str, after: &str) {
        let updated = self.main.replacen(before, after, 1);
        assert_ne!(
            updated, self.main,
            "test mutation must change main: {before}"
        );
        self.main = updated;
    }
}

#[test]
fn actual_entry_owner_retains_output_authority() {
    let source = Sources::load();
    source.validate().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let owner = super::validate(root, &source.main).unwrap();
    assert_eq!(owner.function, "drive");
    assert_eq!(owner.source, source.frontend);
}

#[test]
fn actual_entry_owner_rejects_redirection_and_stdout() {
    let mut source = Sources::load();
    source.frontend = source.frontend.replacen(
        "use crate::output::{Emitter, OutputFormat};",
        "use crate::evil::{Emitter, OutputFormat};",
        1,
    );
    assert!(source.validate().is_err());
    let mut source = Sources::load();
    source.main = source
        .main
        .replacen("cli_entry::frontend::drive(", "evil::drive(", 1);
    assert!(source.validate().is_err());
    let mut source = Sources::load();
    source.frontend = source
        .frontend
        .replacen("emitter.event(event)", "evil(event)", 1);
    assert!(source.validate().is_err());
    let mut source = Sources::load();
    source.frontend = source.frontend.replacen(
        "if let Some(error) = output_error {",
        "println!(\"evil\"); if let Some(error) = output_error {",
        1,
    );
    assert!(source.validate().is_err());
}

#[test]
fn actual_entry_owner_rejects_schema_and_format_transforms() {
    let mut source = Sources::load();
    source.preflight = source.preflight.replacen(
        "output::SUPPORTED_SCHEMA_VERSIONS.contains(&machine_schema_version)",
        "evil(&machine_schema_version)",
        1,
    );
    assert!(source.validate().is_err());
    let mut source = Sources::load();
    source.run_options = source.run_options.replacen(
        "let output_format = cli.output_format;",
        "let output_format = evil(cli.output_format);",
        1,
    );
    assert!(source.validate().is_err());
    let mut source = Sources::load();
    source.frontend = source.frontend.replacen("let mut emitter = Emitter::new(output_format, machine_schema_version);", "let machine_schema_version = 1; let mut emitter = Emitter::new(output_format, machine_schema_version);", 1);
    assert!(source.validate().is_err());
}

#[test]
fn terminal_injection_keeps_the_exact_production_forwarding_boundary() {
    let source = Sources::load();
    source.validate().unwrap();
    let mut redirected = Sources::load();
    redirected.run_options = redirected.run_options.replacen(
        "    resolve_with_terminal(\n",
        "    redirected_resolver(\n",
        1,
    );
    assert_ne!(redirected.run_options, source.run_options);
    assert!(redirected.validate().is_err());
}

#[test]
fn startup_wrapper_requires_the_exact_lazy_factory_and_platform_branches() {
    for (before, after) in [
        ("Box::pin(construct())", "Box::pin(evil(construct()))"),
        (
            "Box::pin(construct())",
            "{ construct(); Box::pin(construct()) }",
        ),
        ("construct: impl FnOnce() -> F", "construct: F"),
        ("#[inline(never)]", "#[inline(always)]"),
        ("#[cfg(windows)]\n#[inline(never)]", "#[inline(never)]"),
        ("boxed_startup_future(|| $future)", "Box::pin($future)"),
        (
            "boxed_startup_future(|| $future)",
            "boxed_startup_future(|| evil($future))",
        ),
        ("#[cfg(not(windows))]", "#[cfg(windows)]"),
        ("            $future\n", "            evil($future)\n"),
        (
            "            $future\n",
            "            { $future; $future }\n",
        ),
        ("($future:expr) =>", "($future:tt) =>"),
    ] {
        let mut source = Sources::load();
        source.replace_main(before, after);
        assert!(
            source.validate().is_err(),
            "accepted changed wrapper: {after}"
        );
    }
    let mut source = Sources::load();
    let file = syn::parse_file(&source.main).unwrap();
    for item in &file.items {
        if matches!(item, syn::Item::Macro(mac) if mac.ident.as_ref().is_some_and(|name| name == "startup_future"))
        {
            use quote::ToTokens;
            source.main.push_str(&item.to_token_stream().to_string());
        }
    }
    assert!(
        source.validate().is_err(),
        "accepted a second wrapper definition"
    );
}

#[test]
fn startup_payload_keeps_recursive_output_and_dispatch_checks() {
    const ORIGINAL: &str = "startup_future!(cli_entry::local_commands::machine(&cli))";
    for replacement in [
        "startup_future!({ println!(\"bypass\"); cli_entry::local_commands::machine(&cli) })",
        "startup_future!(startup_future!({ std::io::stdout(); cli_entry::local_commands::machine(&cli) }))",
        "startup_future!({ let machine_schema_version = 1; cli_entry::local_commands::machine(&cli) })",
        "startup_future!({ let output_format = evil(); cli_entry::local_commands::machine(&cli) })",
        "startup_future!({ machine_schema_version = 1; cli_entry::local_commands::machine(&cli) })",
        "startup_future!({ cli_entry::frontend::drive(evil()); cli_entry::local_commands::machine(&cli) })",
        "startup_future!({ cli_entry::preflight::validate(&cli); cli_entry::local_commands::machine(&cli) })",
        "startup_future!({ opaque!(); cli_entry::local_commands::machine(&cli) })",
        "evil::startup_future!(cli_entry::local_commands::machine(&cli))",
        "startup_future!(cli_entry::local_commands::machine(&cli), evil())",
        "startup_future!(#[cfg(windows)] cli_entry::local_commands::machine(&cli))",
    ] {
        let mut source = Sources::load();
        source.replace_main(ORIGINAL, replacement);
        assert!(
            source.validate().is_err(),
            "accepted payload bypass: {replacement}"
        );
    }
    let mut source = Sources::load();
    source.replace_main("cli_entry::frontend::drive(", "evil::drive(");
    assert!(
        source.validate().is_err(),
        "accepted redirected wrapped frontend"
    );
}

#[test]
fn startup_wrapper_rejects_shadowing_at_definition_and_invocation_scopes() {
    for declaration in [
        "use evil::Box;",
        "use evil::FnOnce;",
        "use evil::std;",
        "use evil::boxed_startup_future;",
        "use evil::startup_future;",
        "use evil::cli_entry;",
        "type Box<T> = evil::Box<T>;",
        "mod std {}",
        "evil!();",
    ] {
        let mut source = Sources::load();
        source.main.push_str(declaration);
        assert!(
            source.validate().is_err(),
            "accepted top-level shadow: {declaration}"
        );
    }
    for entry in [
        "async fn run_cli() -> anyhow::Result<u8> {",
        "fn main() -> std::process::ExitCode {",
    ] {
        for declaration in [
            "use evil::boxed_startup_future;",
            "fn boxed_startup_future<T>(value: T) -> T { value }",
            "macro_rules! startup_future { ($value:expr) => { evil($value) }; }",
            "let boxed_startup_future = evil;",
        ] {
            let mut source = Sources::load();
            source.replace_main(entry, &format!("{entry} {declaration}"));
            assert!(
                source.validate().is_err(),
                "accepted local shadow: {declaration}"
            );
        }
    }
    let mut source = Sources::load();
    source.replace_main(
        "startup_future!(cli_entry::local_commands::machine(&cli))",
        "startup_future!({ use evil::boxed_startup_future; cli_entry::local_commands::machine(&cli) })",
    );
    assert!(
        source.validate().is_err(),
        "accepted a shadow inside wrapper payload"
    );
}

#[test]
fn entry_owner_rejects_conditional_module_redirects() {
    let file: syn::File = syn::parse_quote!(
        #[path = "evil.rs"]
        mod frontend;
    );
    assert!(super::require_module(&file, "frontend").is_err());
    let file: syn::File = syn::parse_quote!(
        #[cfg(any())]
        mod frontend;
    );
    assert!(super::require_module(&file, "frontend").is_err());
}
