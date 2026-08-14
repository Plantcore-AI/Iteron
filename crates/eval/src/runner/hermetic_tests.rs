use super::hermetic::{
    HERMETIC_RUN_PREVIOUS_SCHEMA_VERSION, HERMETIC_RUN_SCHEMA_VERSION, HermeticRunManifest,
    deterministic_hermetic_manifest, run_hermetic_fixture_cli,
};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

fn fixture_root(label: &str) -> std::path::PathBuf {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "iteron-hermetic-test-{label}-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn two_physical_attempt_ledgers_are_deterministic_and_n_minus_one_migrates() {
    let first = deterministic_hermetic_manifest().unwrap();
    let second = deterministic_hermetic_manifest().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.schema_version, HERMETIC_RUN_SCHEMA_VERSION);
    assert_eq!(first.physical_attempts.len(), 2);
    assert_ne!(
        first.physical_attempts[0].physical_attempt_id,
        first.physical_attempts[1].physical_attempt_id
    );
    assert!(
        first
            .physical_attempts
            .iter()
            .all(|attempt| attempt.physical_attempt_id.starts_with("sha256:"))
    );
    assert!(first.attempt_ledger_sha256.starts_with("sha256:"));
    assert_eq!(first.attempt_ledger_head.len(), 64);

    let mut legacy = serde_json::to_value(&first).unwrap();
    legacy["schema_version"] = HERMETIC_RUN_PREVIOUS_SCHEMA_VERSION.into();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("reference_inputs_sha256");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("container_inputs_sha256");
    let migrated = HermeticRunManifest::from_json(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_eq!(migrated, first);

    legacy["schema_version"] = 0.into();
    assert!(HermeticRunManifest::from_json(&serde_json::to_vec(&legacy).unwrap()).is_err());
}

#[test]
fn fixture_cli_writes_two_create_new_identical_outputs() {
    let root = fixture_root("cli-two-run");
    std::fs::create_dir(&root).unwrap();
    let first = root.join("first.json");
    let second = root.join("second.json");
    let invoke = |path: &std::path::Path| {
        run_hermetic_fixture_cli(&["--output".into(), path.to_string_lossy().into_owned()])
    };
    assert_eq!(invoke(&first), ExitCode::SUCCESS);
    assert_eq!(invoke(&second), ExitCode::SUCCESS);
    assert_eq!(
        std::fs::read(&first).unwrap(),
        std::fs::read(&second).unwrap()
    );
    assert_ne!(invoke(&first), ExitCode::SUCCESS);
    std::fs::remove_dir_all(&root).unwrap();
}
