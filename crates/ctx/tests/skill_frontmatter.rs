use iteron_ctx::skills::SkillCatalog;
use std::path::{Path, PathBuf};

fn temporary_repo(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-ctx-skill-frontmatter-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn write_skill(repo: &Path, directory: &str, source: &str) {
    let path = repo.join(".iteron/skills").join(directory);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("SKILL.md"), source).unwrap();
}

#[test]
fn d8_07_g1_path_arguments_and_manual_invocation_are_distinct() {
    let repo = temporary_repo("activation");
    write_skill(
        &repo,
        "rust-review",
        "---\nname: rust-review\ndescription: Review Rust changes\nargument-hint: <path>\n\
         when_to_use: editing Rust implementation files\npaths: [tests/**, src/**]\n---\nReview ownership and safety.\n",
    );
    write_skill(
        &repo,
        "manual-release",
        "---\nname: manual-release\ndescription: Operator-only release procedure\n\
         disable-model-invocation: true\n---\nRun only when explicitly requested.\n",
    );
    write_skill(
        &repo,
        "ticket",
        "---\nname: ticket\ndescription: Work on a ticket\narguments: <ticket-id>\n---\nLoad ticket context.\n",
    );

    let catalog = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
    let docs_listing = catalog.listing_for_paths(4_000, &[PathBuf::from("docs/architecture.md")]);
    assert!(!docs_listing.contains("rust-review"));
    assert!(!docs_listing.contains("manual-release"));
    assert!(docs_listing.contains("ticket <ticket-id>"));

    let rust_listing = catalog.listing_for_paths(4_000, &[PathBuf::from("src/lib.rs")]);
    assert!(rust_listing.contains("rust-review <path>"));
    assert!(rust_listing.contains("use when: editing Rust implementation files"));
    assert!(!rust_listing.contains("manual-release"));

    let manual = catalog
        .get("manual-release")
        .expect("model-hidden skills remain explicitly user-invocable by name");
    assert!(manual.metadata.disable_model_invocation);
    assert!(
        manual
            .framed()
            .contains("Run only when explicitly requested")
    );
    std::fs::remove_dir_all(repo).ok();
}

#[test]
fn d8_07_g2_unknown_keys_load_but_malformed_known_fields_are_surfaced() {
    let repo = temporary_repo("compat");
    write_skill(
        &repo,
        "future",
        "---\nname: future\ndescription: Future-compatible skill\nfuture-vendor-key: opaque\n---\nbody\n",
    );
    write_skill(
        &repo,
        "malformed",
        "---\nname: malformed\ndescription: Must be rejected\ndisable-model-invocation: sometimes\n---\nbody\n",
    );

    let catalog = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
    assert!(catalog.get("future").is_some());
    assert!(catalog.get("malformed").is_none());
    assert!(catalog.errors().iter().any(|error| {
        error.source.contains("malformed") && error.reason.contains("must be exactly true or false")
    }));
    std::fs::remove_dir_all(repo).ok();
}

#[test]
fn d8_07_g3_listing_is_byte_deterministic_for_a_stable_prefix() {
    let repo = temporary_repo("deterministic");
    for name in ["zeta", "alpha", "middle"] {
        write_skill(
            &repo,
            name,
            &format!(
                "---\nname: {name}\ndescription: Skill {name}\npaths: [src/**, tests/**]\n\
                 argument-hint: <target>\n---\nbody\n"
            ),
        );
    }
    let active = [PathBuf::from("src/stable.rs")];
    let first =
        SkillCatalog::discover(Path::new("/nonexistent"), &repo).listing_for_paths(4_000, &active);
    let second =
        SkillCatalog::discover(Path::new("/nonexistent"), &repo).listing_for_paths(4_000, &active);
    assert_eq!(first.as_bytes(), second.as_bytes());
    assert!(first.find("alpha").unwrap() < first.find("middle").unwrap());
    assert!(first.find("middle").unwrap() < first.find("zeta").unwrap());
    std::fs::remove_dir_all(repo).ok();
}
