use super::*;
use std::process::Command;

#[test]
fn trusted_base_rejects_type_serde_and_runtime_dataflow_bypasses() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let temp = std::env::temp_dir().join(format!(
        "core-schema-semantics-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp).unwrap();
    copy_tree(
        &source_root.join("crates/protocol/src"),
        &temp.join("crates/protocol/src"),
    );
    for relative in [
        "crates/record/src/lib.rs",
        "crates/kernel/src/diagnostics.rs",
        "crates/kernel/src/lib.rs",
        "crates/cli/src/output.rs",
        "crates/cli/src/main.rs",
        "crates/eval/src/contract.rs",
        "crates/eval/src/runner.rs",
        "crates/eval/src/strict_json.rs",
        "crates/obs/src/lib.rs",
        "crates/provider/src/lib.rs",
        "crates/ctx/src/compact.rs",
    ] {
        let destination = temp.join(relative);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(source_root.join(relative), destination).unwrap();
    }
    git(&temp, &["init", "-q"]);
    git(&temp, &["add", "."]);
    git(
        &temp,
        &[
            "-c",
            "user.name=Schema Test",
            "-c",
            "user.email=schema@example.invalid",
            "commit",
            "-qm",
            "trusted base",
        ],
    );
    let contract = super::super::super::manifest::load_candidate(source_root).unwrap();

    let event_path = temp.join("crates/protocol/src/event.rs");
    let event = std::fs::read_to_string(&event_path).unwrap();
    let changed_type = event.replacen("pub usage: Usage,", "pub usage: bool,", 1);
    assert_ne!(event, changed_type);
    std::fs::write(&event_path, changed_type).unwrap();
    assert!(compare(&temp, "HEAD", &contract, &contract).is_err());
    std::fs::write(&event_path, &event).unwrap();

    let message_path = temp.join("crates/protocol/src/message.rs");
    let message = std::fs::read_to_string(&message_path).unwrap();
    let changed_serde = message.replacen(
        "serializer.serialize_str(self.as_str())",
        "serializer.serialize_str(\"evil\")",
        1,
    );
    assert_ne!(message, changed_serde);
    std::fs::write(&message_path, changed_serde).unwrap();
    assert!(compare(&temp, "HEAD", &contract, &contract).is_err());
    std::fs::write(&message_path, message).unwrap();

    let eval_path = temp.join("crates/eval/src/contract.rs");
    let eval = std::fs::read_to_string(&eval_path).unwrap();
    let bypass = eval.replacen(
        "if !SUPPORTED_CORE_CLI_SCHEMA_VERSIONS.contains(&actual) {",
        "if false {",
        1,
    );
    assert_ne!(eval, bypass);
    std::fs::write(eval_path, bypass).unwrap();
    assert!(compare(&temp, "HEAD", &contract, &contract).is_err());

    std::fs::remove_dir_all(temp).unwrap();
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn git(root: &Path, arguments: &[&str]) {
    let status = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {arguments:?}");
}
