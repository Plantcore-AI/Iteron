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
