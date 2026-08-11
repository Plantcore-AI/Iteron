use super::*;

fn source(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::fs::read_to_string(root.join(path)).unwrap()
}

#[test]
fn eval_admission_and_typed_decode_cannot_be_bypassed() {
    let contract = source("crates/eval/src/contract.rs");
    validate_contract(&syn::parse_file(&contract).unwrap()).unwrap();
    let unconditional = contract.replacen(
        "if !SUPPORTED_ITERON_CLI_SCHEMA_VERSIONS.contains(&actual) {",
        "if false {",
        1,
    );
    assert!(validate_contract(&syn::parse_file(&unconditional).unwrap()).is_err());
    let untyped = contract.replacen(
        "let event: CliStreamEvent = serde_json::from_value(value)",
        "let event: CliStreamEvent = evil(value)",
        1,
    );
    assert!(validate_contract(&syn::parse_file(&untyped).unwrap()).is_err());

    let type_shadow = format!("{contract}\nstruct serde_json;");
    assert!(validate_contract(&syn::parse_file(&type_shadow).unwrap()).is_err());
    let grouped_shadow = format!(
        "{contract}\nmod evil {{ pub mod serde_json {{}} }}\nuse evil::serde_json::{{self}};"
    );
    assert!(validate_contract(&syn::parse_file(&grouped_shadow).unwrap()).is_err());
}

#[test]
fn eval_duplicate_parser_and_runner_reachability_are_bound() {
    let strict = source("crates/eval/src/strict_json.rs");
    validate_strict_file(&syn::parse_file(&strict).unwrap()).unwrap();
    let duplicate = strict.replacen("if !keys.insert(key.clone()) {", "if false {", 1);
    assert!(validate_strict_file(&syn::parse_file(&duplicate).unwrap()).is_err());

    let runner = source("crates/eval/src/runner.rs");
    validate_runner_file(&syn::parse_file(&runner).unwrap()).unwrap();
    let bypass = runner.replacen(
        "match parse_final_result(&output.stdout, output.exit_code)",
        "match evil(&output.stdout, output.exit_code)",
        1,
    );
    assert!(validate_runner_file(&syn::parse_file(&bypass).unwrap()).is_err());
}
