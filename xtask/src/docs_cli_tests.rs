use super::*;

fn repository_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// This is the gate the item asks for: a new flag with no doc entry fails the build. It runs in
/// `cargo test -p core-xtask`, and `core-xtask docs check` is the same comparison from CI.
#[test]
fn the_published_reference_matches_the_argument_parser() {
    check(&repository_root()).expect(
        "docs/reference/cli.md drifted from crates/cli/src/main.rs; run \
         `cargo run --locked -p core-xtask -- docs generate`",
    );
}

#[test]
fn every_shipped_flag_and_subcommand_appears() {
    // The exact omissions the audit found in the 63-line hand-written page. `--max-tokens` and the
    // permission bypass were shipped and undocumented; `reindex` and `workflow` did not exist on
    // the page at all.
    let rendered = render(&repository_root()).unwrap();
    for shipped in [
        "--max-tokens",
        "--dangerously-bypass-permissions",
        "core reindex",
        "core workflow",
        "core workflow run",
        "core workflow list",
        "core workflow resume",
        "core workflow watch",
        "core tunables resolve",
        "core tunables explain",
        "--allow-code",
        "--image",
        "--timeline",
        "--transcript",
        "--output-format",
    ] {
        assert!(
            rendered.contains(shipped),
            "the generated reference omits `{shipped}`"
        );
    }
}

#[test]
fn a_new_flag_without_a_doc_entry_is_a_rendering_difference() {
    let root = repository_root();
    let source = std::fs::read_to_string(root.join(CLI_SOURCE)).unwrap();
    let tunables = std::fs::read_to_string(root.join("crates/cli/src/tunables.rs")).unwrap();
    let modules = [("tunables", tunables.as_str())];
    let published = render_sources(&source, &modules).unwrap();
    let with_new_flag = source.replacen(
        "    /// The repository to work in (defaults to the current directory).",
        "    /// Undocumented escalation nobody wrote a doc entry for.\n    #[arg(long)]\n    \
         secret_escape_hatch: bool,\n\n    /// The repository to work in (defaults to the current directory).",
        1,
    );
    assert_ne!(with_new_flag, source, "the anchor must still exist");
    let regenerated = render_sources(&with_new_flag, &modules).unwrap();
    assert_ne!(
        regenerated, published,
        "a new flag must change the generated reference, so `docs check` fails until it is regenerated"
    );
    assert!(regenerated.contains("--secret-escape-hatch"));
}

#[test]
fn a_parser_that_stopped_matching_fails_instead_of_rendering_an_empty_table() {
    // Anti-vacuity: a generator that silently matches nothing certifies an empty page as correct.
    let stripped =
        "#[derive(Parser)]\nstruct Cli {\n    /// One task.\n    task: Option<String>,\n}\n";
    let error = render_source(stripped).unwrap_err().to_string();
    assert!(error.contains("stopped matching"), "{error}");
}

#[test]
fn table_cells_escape_the_pipes_the_doc_comments_contain() {
    assert_eq!(
        escape_cell("text | json | stream-json"),
        "text \\| json \\| stream-json"
    );
    assert_eq!(kebab("Reindex"), "reindex");
    assert_eq!(kebab("UserPromptSubmit"), "user-prompt-submit");
}
