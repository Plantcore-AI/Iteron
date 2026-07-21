use super::*;

fn source() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    std::fs::read_to_string(root.join("crates/cli/src/main.rs")).unwrap()
}

#[test]
fn main_entry_and_output_type_authority_reject_redirects() {
    let source = source();
    validate(&source).unwrap();
    let entry = source.replacen("match run_cli().await", "match evil().await", 1);
    assert!(validate(&entry).is_err());
    let import = source.replacen(
        "use output::{Emitter, OutputFormat};",
        "use evil::{Emitter, OutputFormat};",
        1,
    );
    assert!(validate(&import).is_err());
    let conditional = source.replacen(
        "async fn run_cli() -> anyhow::Result<u8>",
        "#[cfg(any())] async fn run_cli() -> anyhow::Result<u8>",
        1,
    );
    assert!(validate(&conditional).is_err());
}

#[test]
fn run_cli_retains_both_event_drains_and_exclusive_stdout() {
    let source = source();
    let dropped = source.replacen("emitter.event(event)", "evil(event)", 1);
    assert!(validate(&dropped).is_err());
    let stdout = source.replacen(
        "if let Some(error) = output_error {",
        "println!(\"evil\");\n    if let Some(error) = output_error {",
        1,
    );
    assert!(validate(&stdout).is_err());
    let shadow = source.replacen(
        "let mut emitter = Emitter::new(output_format);",
        "use crate::evil::{self as output, Emitter};\n    let mut emitter = Emitter::new(output_format);",
        1,
    );
    assert!(validate(&shadow).is_err());
}
