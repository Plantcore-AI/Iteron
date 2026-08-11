use super::*;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_REPO: AtomicU64 = AtomicU64::new(0);

struct GitRepo {
    root: PathBuf,
}

impl GitRepo {
    fn new() -> Self {
        let id = NEXT_REPO.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-schema-compat-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repo = Self { root };
        repo.git(&["init", "--initial-branch=main"]);
        repo.git(&["config", "user.name", "Core Schema Test"]);
        repo.git(&["config", "user.email", "schema-test@example.invalid"]);
        repo
    }

    fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn write_contract(&self, value: &Value) {
        self.write(
            CONTRACT_PATH,
            serde_json::to_vec_pretty(value).expect("fixture contract serializes"),
        );
    }

    fn commit_base(&self) -> String {
        self.commit_paths("schema base", &[CONTRACT_PATH, V1])
    }

    fn commit_paths(&self, message: &str, paths: &[&str]) -> String {
        let mut add = vec!["add", "--"];
        add.extend_from_slice(paths);
        self.git(&add);
        self.git(&["commit", "--no-gpg-sign", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(args)
            .current_dir(&self.root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

impl Drop for GitRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn d13_14_fixture_paths_are_ascii_normalized_and_git_byte_exact() {
    for hostile in [
        "governance/schema-compat/fixtures/bad\nname.json",
        "governance/schema-compat/fixtures/中文.json",
        "governance/schema-compat/fixtures/double//slash.json",
        "governance/schema-compat/fixtures/./alias.json",
        "governance/schema-compat/fixtures/../escape.json",
    ] {
        assert!(
            manifest::validate_repo_path(hostile).is_err(),
            "hostile path must be rejected before first-generation admission: {hostile:?}"
        );
    }

    let repo = GitRepo::new();
    repo.write(V1, b"{\"version\":1}\n");
    let base = repo.commit_paths("byte-exact fixture", &[V1]);
    assert_eq!(
        git::git_object(&repo.root, &base, V1, 1024).unwrap(),
        Some(b"{\"version\":1}\n".to_vec())
    );
}

fn field(name: &str, deprecated: Option<u32>) -> Value {
    let mut value = json!({
        "name": name,
        "introduced_release": 1
    });
    if let Some(release) = deprecated {
        value["deprecated_release"] = json!(release);
    }
    value
}

fn contract(
    release: u32,
    current_version: u32,
    fields: Vec<Value>,
    fixtures: Vec<Value>,
    shims: Vec<Value>,
) -> Value {
    json!({
        "schema_version": 1,
        "release_ordinal": release,
        "minimum_deprecation_releases": 1,
        "surfaces": [{
            "id": "protocol.test",
            "current_version": current_version,
            "version_field": "version",
            "fixtures": fixtures,
            "fields": fields,
            "compatibility_shims": shims
        }]
    })
}

fn fixture(path: &str, version: u32) -> Value {
    json!({ "path": path, "format": "json", "schema_version": version })
}

#[test]
fn d13_14_schema_surface_inventory_remains_bounded_at_160() {
    let template = contract(
        1,
        1,
        vec![field("version", None)],
        vec![fixture(V1, 1)],
        Vec::new(),
    )["surfaces"][0]
        .clone();
    let surfaces = (0..=160)
        .map(|index| {
            let mut surface = template.clone();
            surface["id"] = json!(format!("protocol.bound-{index}"));
            surface
        })
        .collect::<Vec<_>>();
    let value = json!({
        "schema_version": 1,
        "release_ordinal": 1,
        "minimum_deprecation_releases": 1,
        "surfaces": surfaces,
    });
    let encoded = serde_json::to_vec(&value).unwrap();
    let parsed = manifest::parse_contract(&encoded, "surface-bound fixture").unwrap();
    let error = manifest::validate_contract_shape(&parsed).unwrap_err();
    assert!(error.to_string().contains("1..=160 surfaces"));
}

const V1: &str = "governance/schema-compat/fixtures/test/v1.json";
const V1_ALT: &str = "governance/schema-compat/fixtures/test/v1-alt.json";
const V2: &str = "governance/schema-compat/fixtures/test/v2.json";
const V3: &str = "governance/schema-compat/fixtures/test/v3.json";
const MIXED_V1: &str = "governance/schema-compat/fixtures/test/mixed-v1.jsonl";
const MIXED_V2: &str = "governance/schema-compat/fixtures/test/mixed-v2.jsonl";

fn v5_input_attachment_surface() -> Surface {
    serde_json::from_value(json!({
        "id": CLI_INPUT_ATTACHMENT_SURFACE,
        "current_version": 5,
        "version_field": "schema_version",
        "selector": {"field": "type", "value": "input_attachment"},
        "fixtures": [{
            "path": CLI_INPUT_ATTACHMENT_FIXTURE,
            "format": "jsonl",
            "schema_version": 5
        }],
        "fields": [
            {"name": "encoded_bytes", "introduced_release": 1},
            {"name": "media_type", "introduced_release": 1},
            {"name": "ordinal", "introduced_release": 1},
            {"name": "schema_version", "introduced_release": 1},
            {"name": "type", "introduced_release": 1}
        ],
        "compatibility_shims": []
    }))
    .unwrap()
}

#[test]
fn d13_14_only_input_attachment_has_the_same_version_cli_stream_exception() {
    let admitted = v5_input_attachment_surface();
    assert!(is_v5_input_attachment_addition(&admitted, Some(5)));

    let mut mutations = Vec::new();
    let mut wrong_id = admitted.clone();
    wrong_id.id = "cli.machine-stream.other".into();
    mutations.push(wrong_id);
    let mut wrong_version = admitted.clone();
    wrong_version.current_version = 6;
    mutations.push(wrong_version);
    let mut wrong_selector = admitted.clone();
    wrong_selector.selector.as_mut().unwrap().value = "other".into();
    mutations.push(wrong_selector);
    let mut wrong_fixture = admitted.clone();
    wrong_fixture.fixtures[0].path = "crates/cli/tests/golden/other_stream_v5.jsonl".into();
    mutations.push(wrong_fixture);
    let mut extra_field = admitted.clone();
    extra_field.fields.push(
        serde_json::from_value(json!({
            "name": "path",
            "introduced_release": 1
        }))
        .unwrap(),
    );
    mutations.push(extra_field);
    let mut optional_field = admitted.clone();
    optional_field.fields[0].optional = true;
    mutations.push(optional_field);
    let mut rewritten_history = admitted.clone();
    rewritten_history.fields[0].introduced_release = 2;
    mutations.push(rewritten_history);

    for mutation in mutations {
        assert!(
            !is_v5_input_attachment_addition(&mutation, Some(5)),
            "the allowlist must fail closed for {mutation:?}"
        );
    }
    assert!(!is_v5_input_attachment_addition(&admitted, Some(4)));
}

#[test]
fn d13_14_candidate_contract_rejects_duplicate_keys_at_nested_schema_levels() {
    let repo = GitRepo::new();
    let candidate = contract(
        2,
        2,
        vec![
            field("version", None),
            json!({"name": "replacement", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 1,
            "target_version": 2,
            "target_fields": ["replacement", "version"],
            "fixtures": [V1],
            "migrator": "d13-14-test-rename-v1-v2"
        })],
    );
    let encoded = serde_json::to_string(&candidate).unwrap();
    for (key, needle, duplicate) in [
        (
            "id",
            r#""id":"protocol.test""#,
            r#""id":"protocol.test","id":"protocol.test""#,
        ),
        (
            "current_version",
            r#""current_version":2"#,
            r#""current_version":2,"current_version":2"#,
        ),
        (
            "old_field",
            r#""old_field":"old""#,
            r#""old_field":"old","old_field":"old""#,
        ),
    ] {
        let hostile = encoded.replacen(needle, duplicate, 1);
        assert_ne!(hostile, encoded, "test fixture must inject `{key}`");
        repo.write(CONTRACT_PATH, hostile);
        let error = format!(
            "{:#}",
            manifest::load_candidate(&repo.root)
                .expect_err("candidate contract duplicate keys must fail closed")
        );
        assert!(
            error.contains(&format!("duplicate JSON object key '{key}'")),
            "{error}"
        );
    }
}

#[test]
fn d13_14_immediate_and_published_base_contracts_reject_duplicate_keys() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    let base_contract = serde_json::to_string(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ))
    .unwrap();
    let hostile_base = base_contract.replacen(
        r#""current_version":1"#,
        r#""current_version":1,"current_version":1"#,
        1,
    );
    assert_ne!(hostile_base, base_contract);
    repo.write(CONTRACT_PATH, hostile_base);
    let base = repo.commit_base();

    repo.write_contract(&contract(
        2,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    for error in [
        validate_against_base(&repo.root, &base)
            .expect_err("the immediate base must reject duplicate contract keys"),
        validate_release_against_base(&repo.root, &base)
            .expect_err("the published base must reject duplicate contract keys"),
    ] {
        let error = format!("{error:#}");
        assert!(
            error.contains("duplicate JSON object key 'current_version'"),
            "{error}"
        );
    }
}

#[test]
fn d13_14_additive_change_passes_only_with_new_version_and_frozen_fixture() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let base = repo.commit_base();

    repo.write(V2, br#"{"version":1,"old":"v1","added":"v1"}"#);
    repo.write_contract(&contract(
        2,
        1,
        vec![
            field("version", None),
            field("old", None),
            json!({"name": "added", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 1)],
        vec![],
    ));
    assert!(validate_against_base(&repo.root, &base).is_err());

    repo.write(V2, br#"{"version":2,"old":"v1","added":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            field("old", None),
            json!({"name": "added", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    ));
    validate_against_base(&repo.root, &base).unwrap();

    repo.write(V1, br#"{"version":1,"old":"rewritten"}"#);
    assert!(validate_against_base(&repo.root, &base).is_err());
}

#[test]
fn d13_14_rename_requires_prior_deprecation_live_shim_and_migrator() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", Some(1))],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let base = repo.commit_base();
    repo.write(V2, br#"{"version":2,"replacement":"v2"}"#);

    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            json!({
                "name": "replacement",
                "introduced_release": 2
            }),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    ));
    assert!(validate_against_base(&repo.root, &base).is_err());

    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            json!({
                "name": "replacement",
                "introduced_release": 2
            }),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 1,
            "target_version": 2,
            "target_fields": ["replacement", "version"],
            "fixtures": [V1],
            "migrator": "d13-14-test-rename-v1-v2"
        })],
    ));
    validate_against_base(&repo.root, &base).unwrap();
    validate_release_against_base(&repo.root, &base)
        .expect("a deprecation in the published base permits removal one release later");
}

#[test]
fn d13_14_shim_covers_every_affected_fixture_and_source_version() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write(V2, br#"{"version":2,"old":"v2"}"#);
    repo.write(V3, br#"{"version":3,"replacement":"v3"}"#);
    let shim = |fixtures: Vec<&str>| {
        json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 1,
            "target_version": 3,
            "target_fields": ["replacement", "version"],
            "fixtures": fixtures,
            "migrator": "d13-14-test-rename-v1-or-v2-v3"
        })
    };
    let candidate = |shim: Value| {
        contract(
            3,
            3,
            vec![
                field("version", None),
                json!({"name": "replacement", "introduced_release": 3}),
            ],
            vec![fixture(V1, 1), fixture(V2, 2), fixture(V3, 3)],
            vec![shim],
        )
    };

    repo.write_contract(&candidate(shim(vec![V1])));
    let error = validate_current(&repo.root)
        .expect_err("omitting an affected source version must fail")
        .to_string();
    assert!(error.contains("coverage is not exhaustive"), "{error}");

    repo.write_contract(&candidate(shim(vec![V1, V2])));
    validate_current(&repo.root)
        .expect("one permanent shim must execute against every affected fixture/source version");

    repo.write(
        V1,
        br#"{"version":1,"old":"v1","replacement":"must-not-be-overwritten"}"#,
    );
    repo.write_contract(&candidate(shim(vec![V1, V2])));
    let error = validate_current(&repo.root)
        .expect_err("a rename must not overwrite a pre-existing replacement value")
        .to_string();
    assert!(error.contains("would overwrite"), "{error}");
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);

    repo.write_contract(&candidate(shim(vec![V1, V2, V3])));
    assert!(
        validate_current(&repo.root).is_err(),
        "an unaffected current fixture cannot be claimed as shim coverage"
    );
}

#[test]
fn d13_14_same_release_deprecation_and_removal_is_rejected() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let base = repo.commit_base();
    repo.write(V2, br#"{"version":2,"replacement":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            json!({
                "name": "replacement",
                "introduced_release": 2
            }),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 2,
            "target_version": 2,
            "target_fields": ["replacement", "version"],
            "fixtures": [V1],
            "migrator": "d13-14-test-rename-v1-v2"
        })],
    ));
    assert!(validate_against_base(&repo.root, &base).is_err());
}

#[test]
fn d13_14_permanent_shim_targets_do_not_freeze_later_additive_versions() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", Some(1))],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let release_one = repo.commit_base();

    let shim = json!({
        "old_field": "old",
        "replacement": "replacement",
        "deprecated_release": 1,
        "target_version": 2,
        "target_fields": ["replacement", "version"],
        "fixtures": [V1],
        "migrator": "d13-14-test-rename-v1-v2"
    });
    repo.write(V2, br#"{"version":2,"replacement":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            json!({"name": "replacement", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![shim.clone()],
    ));
    validate_release_against_base(&repo.root, &release_one).unwrap();
    let release_two = repo.commit_paths("published removal", &[CONTRACT_PATH, V2]);

    repo.write(V1_ALT, br#"{"version":1,"old":"legacy-v1"}"#);
    repo.write(V3, br#"{"version":3,"replacement":"v3","added":"v3"}"#);
    let mut expanded_shim = shim;
    expanded_shim["fixtures"] = json!([V1, V1_ALT]);
    repo.write_contract(&contract(
        3,
        3,
        vec![
            field("version", None),
            json!({"name": "replacement", "introduced_release": 2}),
            json!({"name": "added", "introduced_release": 3}),
        ],
        vec![
            fixture(V1, 1),
            fixture(V1_ALT, 1),
            fixture(V2, 2),
            fixture(V3, 3),
        ],
        vec![expanded_shim],
    ));
    validate_release_against_base(&repo.root, &release_two)
        .expect("a permanent shim may add exhaustive legacy fixture coverage without changing its frozen target");
}

#[test]
fn d13_14_new_surface_cannot_claim_phantom_compatibility_history() {
    let repo = GitRepo::new();
    repo.write(V3, br#"{"version":1,"old":"published"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V3, 1)],
        vec![],
    ));
    let base = repo.commit_paths("published schema", &[CONTRACT_PATH, V3]);

    repo.write(
        MIXED_V1,
        b"{\"version\":1,\"type\":\"phase\",\"old\":\"legacy\"}\n",
    );
    repo.write(
        MIXED_V2,
        b"{\"version\":2,\"type\":\"phase\",\"replacement\":\"current\"}\n",
    );
    let mut candidate = contract(
        2,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V3, 1)],
        vec![],
    );
    candidate["surfaces"].as_array_mut().unwrap().push(json!({
        "id": "test.phase",
        "current_version": 2,
        "version_field": "version",
        "selector": {"field": "type", "value": "phase"},
        "fixtures": [
            {"path": MIXED_V1, "format": "jsonl", "schema_version": 1},
            {"path": MIXED_V2, "format": "jsonl", "schema_version": 2}
        ],
        "fields": [
            {"name": "version", "introduced_release": 2},
            {"name": "type", "introduced_release": 2},
            {"name": "replacement", "introduced_release": 2}
        ],
        "compatibility_shims": [{
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 1,
            "target_version": 2,
            "target_fields": ["replacement", "type", "version"],
            "fixtures": [MIXED_V1],
            "migrator": "d13-14-test-rename-v1-v2"
        }]
    }));
    repo.write_contract(&candidate);

    let error = validate_against_base(&repo.root, &base)
        .expect_err("a brand-new surface must not mint fake compatibility history")
        .to_string();
    assert!(
        error.contains("cannot claim compatibility shims"),
        "{error}"
    );
}

#[test]
fn d13_14_new_surface_field_history_starts_at_the_candidate_release() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"published"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let base = repo.commit_base();
    repo.write(V2, br#"{"value":"new"}"#);

    let mut candidate = contract(
        2,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    );
    candidate["surfaces"].as_array_mut().unwrap().push(json!({
        "id": "test.new",
        "current_version": 1,
        "version_field": null,
        "fixtures": [fixture(V2, 1)],
        "fields": [{
            "name": "value",
            "introduced_release": 2,
            "deprecated_release": 1
        }],
        "compatibility_shims": []
    }));
    repo.write_contract(&candidate);
    assert!(
        validate_against_base(&repo.root, &base).is_err(),
        "a new surface cannot backdate active field deprecation"
    );

    candidate["surfaces"][1]["fields"][0]["deprecated_release"] = json!(2);
    repo.write_contract(&candidate);
    validate_against_base(&repo.root, &base)
        .expect("a new surface may mark a field deprecated in its actual candidate release");
}

#[test]
fn d13_14_candidate_cannot_mint_a_migrator_in_the_breaking_change() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", Some(1))],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let base = repo.commit_base();
    repo.write(V2, br#"{"version":2,"replacement":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            json!({"name": "replacement", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 1,
            "target_version": 2,
            "target_fields": ["replacement", "version"],
            "fixtures": [V1],
            "migrator": "candidate-only-migrator"
        })],
    ));

    let error = validate_against_base(&repo.root, &base)
        .expect_err("an unregistered candidate-only migrator must be rejected")
        .to_string();
    assert!(error.contains("not registered"), "{error}");
}

#[test]
fn d13_14_unpublished_prs_do_not_satisfy_the_release_runway() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let published_release = repo.commit_base();

    repo.write(V2, br#"{"version":2,"old":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![field("version", None), field("old", Some(2))],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    ));
    let immediate_pr_base = repo.commit_paths("unpublished deprecation", &[CONTRACT_PATH, V2]);

    repo.write(V3, br#"{"version":3,"replacement":"v3"}"#);
    repo.write_contract(&contract(
        3,
        3,
        vec![
            field("version", None),
            json!({"name": "replacement", "introduced_release": 3}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2), fixture(V3, 3)],
        vec![json!({
            "old_field": "old",
            "replacement": "replacement",
            "deprecated_release": 2,
            "target_version": 3,
            "target_fields": ["replacement", "version"],
            "fixtures": [V1, V2],
            "migrator": "d13-14-test-rename-v1-or-v2-v3"
        })],
    ));

    validate_against_base(&repo.root, &immediate_pr_base)
        .expect("the ordinary PR comparison sees the immediately preceding deprecation");
    assert!(
        validate_release_against_base(&repo.root, &published_release).is_err(),
        "an unpublished deprecation must not count as a released compatibility runway"
    );
}

#[test]
fn d13_14_multiple_prs_can_target_one_published_release_ordinal() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let published_release = repo.commit_base();

    repo.write(V2, br#"{"version":2,"old":"v2","first":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            field("old", None),
            json!({"name": "first", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    ));
    let first_pr = repo.commit_paths("first provisional schema change", &[CONTRACT_PATH, V2]);

    repo.write(
        V3,
        br#"{"version":3,"old":"v3","first":"v3","second":"v3"}"#,
    );
    repo.write_contract(&contract(
        2,
        3,
        vec![
            field("version", None),
            field("old", None),
            json!({"name": "first", "introduced_release": 2}),
            json!({"name": "second", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2), fixture(V3, 3)],
        vec![],
    ));

    validate_against_base(&repo.root, &first_pr)
        .expect("a second PR may keep the next unpublished release ordinal");
    validate_release_against_base(&repo.root, &published_release)
        .expect("the combined candidate remains exactly one release after the published anchor");
}

#[test]
fn d13_14_stale_provisional_history_moves_forward_to_the_new_published_ordinal() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let release_one = repo.commit_base();

    repo.write(V2, br#"{"version":2,"old":"v2","provisional":"v2"}"#);
    repo.write_contract(&contract(
        2,
        2,
        vec![
            field("version", None),
            field("old", Some(2)),
            json!({"name": "provisional", "introduced_release": 2}),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    ));
    let stale_next_release =
        repo.commit_paths("stale provisional release two", &[CONTRACT_PATH, V2]);

    repo.git(&["checkout", "--detach", &release_one]);
    repo.write_contract(&contract(
        2,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let published_release_two =
        repo.commit_paths("different published release two", &[CONTRACT_PATH]);

    repo.write(V2, br#"{"version":2,"old":"v2","provisional":"v2"}"#);
    repo.write(V3, br#"{"version":3,"old":"v3","provisional":"v3"}"#);
    let candidate = |release_marker: u32| {
        contract(
            3,
            3,
            vec![
                field("version", None),
                field("old", Some(release_marker)),
                json!({
                    "name": "provisional",
                    "introduced_release": release_marker
                }),
            ],
            vec![fixture(V1, 1), fixture(V2, 2), fixture(V3, 3)],
            vec![],
        )
    };
    repo.write_contract(&candidate(2));
    assert!(
        validate_release_against_base(&repo.root, &published_release_two).is_err(),
        "the published anchor must reject stale provisional release history"
    );

    repo.write_contract(&candidate(3));
    validate_against_base(&repo.root, &stale_next_release)
        .expect("an immediate provisional base may move its unreleased history strictly forward");
    validate_release_against_base(&repo.root, &published_release_two)
        .expect("the corrected history must be grounded in the actual published predecessor");
}

#[test]
fn d13_14_bootstrap_release_cannot_claim_phantom_history() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    validate_bootstrap_release(&repo.root).unwrap();

    repo.write_contract(&contract(
        2,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    assert!(validate_bootstrap_release(&repo.root).is_err());

    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", Some(1))],
        vec![fixture(V1, 1)],
        vec![],
    ));
    assert!(validate_bootstrap_release(&repo.root).is_err());
}

#[test]
fn d13_14_release_requires_one_exact_published_predecessor() {
    let repo = GitRepo::new();
    repo.write("README.md", b"no schema contract yet\n");
    let missing_contract_base = repo.commit_paths("pre-contract base", &["README.md"]);
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    assert!(validate_release_against_base(&repo.root, &missing_contract_base).is_err());

    let published_release = repo.commit_paths("published schema", &[CONTRACT_PATH, V1]);
    repo.write_contract(&contract(
        100,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));
    let error = validate_release_against_base(&repo.root, &published_release)
        .expect_err("a release ordinal cannot skip published chronology")
        .to_string();
    assert!(error.contains("advance exactly once"), "{error}");
}

#[test]
fn d13_14_jsonl_migrators_are_scoped_to_the_selected_record_type() {
    let repo = GitRepo::new();
    repo.write(
        MIXED_V1,
        b"{\"version\":1,\"type\":\"phase\",\"old\":\"v1\"}\n{\"version\":1,\"type\":\"notice\",\"message\":\"v1\"}\n",
    );
    repo.write(
        MIXED_V2,
        b"{\"version\":2,\"type\":\"phase\",\"replacement\":\"v2\"}\n{\"version\":2,\"type\":\"notice\",\"message\":\"v2\"}\n",
    );
    let fixtures = || {
        vec![
            json!({"path": MIXED_V1, "format": "jsonl", "schema_version": 1}),
            json!({"path": MIXED_V2, "format": "jsonl", "schema_version": 2}),
        ]
    };
    let mut contract = json!({
        "schema_version": 1,
        "release_ordinal": 2,
        "minimum_deprecation_releases": 1,
        "surfaces": [
            {
                "id": "test.phase",
                "current_version": 2,
                "version_field": "version",
                "selector": {"field": "type", "value": "phase"},
                "fixtures": fixtures(),
                "fields": [
                    field("version", None),
                    field("type", None),
                    json!({"name": "replacement", "introduced_release": 2})
                ],
                "compatibility_shims": [{
                    "old_field": "old",
                    "replacement": "replacement",
                    "deprecated_release": 1,
                    "target_version": 2,
                    "target_fields": ["replacement", "type", "version"],
                    "fixtures": [MIXED_V1],
                    "migrator": "d13-14-test-rename-v1-v2"
                }]
            },
            {
                "id": "test.notice",
                "current_version": 2,
                "version_field": "version",
                "selector": {"field": "type", "value": "notice"},
                "fixtures": fixtures(),
                "fields": [
                    field("version", None),
                    field("type", None),
                    field("message", None)
                ],
                "compatibility_shims": []
            }
        ]
    });
    repo.write_contract(&contract);

    validate_current(&repo.root)
        .expect("the phase migrator must not be applied to the notice record beside it");

    repo.write(
        MIXED_V2,
        b"{\"version\":2,\"type\":\"phase\",\"replacement\":\"v2\"}\n{\"version\":2,\"type\":\"notice\",\"message\":\"v2\"}\n{\"version\":2,\"type\":\"orphan\"}\n",
    );
    assert!(
        validate_current(&repo.root).is_err(),
        "every selected JSONL record must match exactly one surface"
    );

    repo.write(
        MIXED_V2,
        b"{\"version\":2,\"type\":\"phase\",\"replacement\":\"v2\"}\n{\"version\":2,\"type\":\"notice\",\"message\":\"v2\"}\n",
    );
    contract["surfaces"][0]["compatibility_shims"][0]["migrator"] =
        json!("d13-14-test-changes-selector");
    repo.write_contract(&contract);
    assert!(
        validate_current(&repo.root).is_err(),
        "a migrator cannot move a record into another selector surface"
    );
}

#[test]
fn d13_14_record_selector_is_immutable_across_versions() {
    let repo = GitRepo::new();
    repo.write(
        V1,
        br#"{"version":1,"type":"phase","category":"stable","old":"v1"}"#,
    );
    let mut base_contract = contract(
        1,
        1,
        vec![
            field("version", None),
            field("type", None),
            field("category", None),
            field("old", None),
        ],
        vec![fixture(V1, 1)],
        vec![],
    );
    base_contract["surfaces"][0]["selector"] = json!({"field": "type", "value": "phase"});
    repo.write_contract(&base_contract);
    let base = repo.commit_base();

    repo.write(
        V2,
        br#"{"version":2,"type":"phase","category":"stable","old":"v2"}"#,
    );
    let mut candidate = contract(
        2,
        2,
        vec![
            field("version", None),
            field("type", None),
            field("category", None),
            field("old", None),
        ],
        vec![fixture(V1, 1), fixture(V2, 2)],
        vec![],
    );
    candidate["surfaces"][0]["selector"] = json!({"field": "category", "value": "stable"});
    repo.write_contract(&candidate);
    assert!(validate_against_base(&repo.root, &base).is_err());
}

#[test]
fn d13_14_equal_selectors_are_scoped_to_their_fixture_corpus() {
    let repo = GitRepo::new();
    repo.write(V1, br#"{"type":"thinking","value":"record"}"#);
    repo.write(V2, br#"{"type":"thinking","value":"cli"}"#);
    let contract: Contract = serde_json::from_value(json!({
        "schema_version": 1,
        "release_ordinal": 1,
        "minimum_deprecation_releases": 1,
        "surfaces": [
            {
                "id": "test.record-thinking",
                "current_version": 1,
                "version_field": null,
                "selector": {"field": "type", "value": "thinking"},
                "fixtures": [fixture(V1, 1)],
                "fields": [field("type", None), field("value", None)],
                "compatibility_shims": []
            },
            {
                "id": "test.cli-thinking",
                "current_version": 1,
                "version_field": null,
                "selector": {"field": "type", "value": "thinking"},
                "fixtures": [fixture(V2, 1)],
                "fields": [field("type", None), field("value", None)],
                "compatibility_shims": []
            }
        ]
    }))
    .unwrap();

    manifest::validate_contract(&repo.root, &contract)
        .expect("the same selector value is unambiguous across distinct fixture corpora");
}

#[test]
fn d13_14_unregistered_cli_machine_golden_is_rejected() {
    let repo = GitRepo::new();
    let tracked = "crates/cli/tests/golden/tracked.json";
    let untracked = "crates/cli/tests/golden/untracked.jsonl";
    repo.write(tracked, br#"{"schema_version":1,"type":"result"}"#);
    repo.write(untracked, b"{\"schema_version\":1,\"type\":\"notice\"}\n");
    let contract: Contract = serde_json::from_value(json!({
        "schema_version": 1,
        "release_ordinal": 1,
        "minimum_deprecation_releases": 1,
        "surfaces": [{
            "id": "cli.machine-result",
            "current_version": 1,
            "version_field": "schema_version",
            "selector": {"field": "type", "value": "result"},
            "fixtures": [{"path": tracked, "format": "json", "schema_version": 1}],
            "fields": [
                {"name": "schema_version", "introduced_release": 1},
                {"name": "type", "introduced_release": 1}
            ],
            "compatibility_shims": []
        }]
    }))
    .unwrap();

    assert!(manifest::validate_cli_fixture_inventory(&repo.root, &contract).is_err());
    std::fs::remove_file(repo.root.join(untracked)).unwrap();
    manifest::validate_cli_fixture_inventory(&repo.root, &contract).unwrap();

    let nested = repo.root.join("crates/cli/tests/golden/nested");
    std::fs::create_dir_all(&nested).unwrap();
    assert!(
        manifest::validate_cli_fixture_inventory(&repo.root, &contract).is_err(),
        "the flat CLI golden inventory must fail closed on nested directories"
    );
    std::fs::remove_dir(&nested).unwrap();
    manifest::validate_cli_fixture_inventory(&repo.root, &contract).unwrap();
}

#[cfg(unix)]
#[test]
fn d13_14_contract_and_frozen_fixtures_cannot_be_symlinks() {
    use std::os::unix::fs::symlink;

    let repo = GitRepo::new();
    repo.write(V1, br#"{"version":1,"old":"v1"}"#);
    repo.write_contract(&contract(
        1,
        1,
        vec![field("version", None), field("old", None)],
        vec![fixture(V1, 1)],
        vec![],
    ));

    let contract_path = repo.root.join(CONTRACT_PATH);
    let contract_target = repo.root.join("governance/schema-compatibility-real.json");
    std::fs::rename(&contract_path, &contract_target).unwrap();
    symlink(&contract_target, &contract_path).unwrap();
    let contract_error = manifest::load_candidate(&repo.root)
        .expect_err("an in-repository contract symlink must be rejected")
        .to_string();
    assert!(contract_error.contains("symbolic link"), "{contract_error}");

    std::fs::remove_file(&contract_path).unwrap();
    std::fs::rename(&contract_target, &contract_path).unwrap();
    validate_current(&repo.root).unwrap();

    let fixture_path = repo.root.join(V1);
    let fixture_target = repo
        .root
        .join("governance/schema-compat/fixtures/test/v1-real.json");
    std::fs::rename(&fixture_path, &fixture_target).unwrap();
    symlink(&fixture_target, &fixture_path).unwrap();
    let fixture_error = validate_current(&repo.root)
        .expect_err("an in-repository frozen-fixture symlink must be rejected")
        .to_string();
    assert!(fixture_error.contains("symbolic link"), "{fixture_error}");
}

#[test]
fn d13_14_repository_corpus_contract_is_self_consistent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is directly below the repository root");
    validate_current(root).unwrap();
}

#[test]
fn d1_02_only_a_moved_published_shape_obliges_a_protocol_version_bump() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let bytes = std::fs::read(root.join(super::CONTRACT_PATH)).unwrap();
    let base = super::manifest::parse_contract(&bytes, "base").unwrap();

    // A brand-new top-level tag is a new surface: §4.3(b) rule 2 keeps the line identical.
    let mut added = base.clone();
    let mut fresh = base.surfaces[0].clone();
    fresh.id = "abi.newly-published".to_owned();
    added.surfaces.push(fresh);
    assert!(!super::line_format_moved(&base, &added));

    // An appended Option + skip_serializing_if field: §4.3(b) rule 3, byte-identical when None.
    let mut appended = base.clone();
    appended.surfaces[0].fields.push(super::manifest::Field {
        name: "appended_optional".to_owned(),
        introduced_release: 2,
        deprecated_release: None,
        optional: true,
    });
    assert!(!super::line_format_moved(&base, &appended));

    // Dropping a field from ANY published surface moves bytes. record.event-envelope is `Event`,
    // the whole EqEnvelope payload, and the five abi.* contracts are published from the freeze on;
    // no surface may be silently exempt.
    for index in 0..base.surfaces.len() {
        let mut shrunk = base.clone();
        if shrunk.surfaces[index].fields.is_empty() {
            continue;
        }
        shrunk.surfaces[index].fields.pop();
        assert!(
            super::line_format_moved(&base, &shrunk),
            "surface '{}' escaped the bump trigger",
            base.surfaces[index].id
        );
    }

    let mut dropped = base.clone();
    dropped.surfaces.remove(0);
    assert!(super::line_format_moved(&base, &dropped));
}
