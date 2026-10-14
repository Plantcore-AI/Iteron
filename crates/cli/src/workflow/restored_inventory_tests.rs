use super::*;
use std::path::PathBuf;
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-host-workflow-inventory-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        // Fixture creation may use macOS's /var alias; production admission never canonicalizes
        // a supplied root. This scratch owner records its actual newly created ordinary path.
        Self(std::fs::canonicalize(path).unwrap())
    }
    fn row(&self, id: &str, name: &str) {
        crate::workflow::persist_inputs(
            &self.0,
            &crate::workflow::RunManifest {
                run_id: id.into(),
                name: name.into(),
                args: serde_json::json!({}),
                provider_id: "fixture".into(),
                model: "m".into(),
                created_at: 1,
            },
            "export default async function(){return null;}",
        )
        .unwrap();
        std::fs::write(
            self.0.join(id).join("journal.jsonl"),
            "{\"type\":\"result\",\"version\":1}\n",
        )
        .unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn actual_finite_rows_preserve_sidecar_status_and_report_omissions() {
    let scratch = Scratch::new("rows");
    for i in 0..20 {
        scratch.row(&format!("wf_{:x}_0", 0x1000 + i), "observed history");
    }
    let observation = restored_inventory(&scratch.0, usize::MAX);
    assert_eq!(observation.rows.len(), 16);
    assert_eq!(observation.omitted, 4);
    assert!(!observation.incomplete);
    assert_eq!(observation.rows[0].run_id, "wf_1013_0");
    assert!(
        observation
            .rows
            .iter()
            .all(|row| row.status == "running" && row.agents == 1)
    );
    // This is a sidecar observation; the frontend source fixtures separately prove no live handle
    // or transcript card is minted from the word "running".
}

#[test]
fn real_manifest_script_and_journal_size_admission_refuses_before_full_reads() {
    let scratch = Scratch::new("size");
    scratch.row("wf_1000_0", "healthy");
    for (id, leaf, maximum) in [
        ("wf_1001_0", "run.json", 64 * 1024),
        ("wf_1002_0", "script.js", 1024 * 1024),
        ("wf_1003_0", "journal.jsonl", 256 * 1024),
        ("wf_1004_0", "result.json", 128 * 1024),
    ] {
        scratch.row(id, "over bound");
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(scratch.0.join(id).join(leaf))
            .unwrap()
            .set_len(maximum + 1)
            .unwrap();
    }
    let observation = restored_inventory(&scratch.0, 16);
    assert_eq!(observation.rows.len(), 1);
    assert_eq!(observation.rows[0].name, "healthy");
    assert!(observation.incomplete);
    assert_eq!(observation.omitted, 4);
}

#[test]
fn directory_work_has_an_actual_entry_limit_even_without_valid_rows() {
    let scratch = Scratch::new("directory");
    for i in 0..4097 {
        std::fs::write(scratch.0.join(format!("entry-{i}")), b"").unwrap();
    }
    let observation = restored_inventory(&scratch.0, 16);
    assert!(observation.incomplete);
    assert!(observation.rows.is_empty());
}

#[cfg(unix)]
#[test]
fn symlink_and_special_sidecars_cannot_redirect_or_block_native_history() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new("links");
    scratch.row("wf_1000_0", "healthy");
    scratch.row("wf_1001_0", "redirected");
    let script = scratch.0.join("wf_1001_0/script.js");
    std::fs::remove_file(&script).unwrap();
    let foreign = scratch.0.join("outside.txt");
    std::fs::write(&foreign, b"foreign data").unwrap();
    symlink(&foreign, &script).unwrap();
    scratch.row("wf_1002_0", "special");
    let script = scratch.0.join("wf_1002_0/script.js");
    std::fs::remove_file(&script).unwrap();
    let name =
        std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(script.as_os_str())).unwrap();
    // SAFETY: a live NUL-terminated fixture path creates one private FIFO, never read as regular.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let observation = restored_inventory(&scratch.0, 16);
    assert_eq!(observation.rows.len(), 1);
    assert_eq!(observation.rows[0].name, "healthy");
    assert!(observation.incomplete);
}

#[cfg(unix)]
#[test]
fn root_or_ancestor_symlink_is_refused_even_when_target_has_valid_sidecars() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new("root-redirect");
    let foreign = Scratch::new("foreign-root");
    foreign.row("wf_2000_0", "foreign retained bytes");
    let redirected = scratch.0.join("redirected");
    symlink(&foreign.0, &redirected).unwrap();
    let observation = restored_inventory(&redirected, 16);
    assert!(observation.incomplete);
    assert!(observation.rows.is_empty());
    let ancestor = scratch.0.join("ancestor");
    symlink(foreign.0.parent().unwrap(), &ancestor).unwrap();
    let observation = restored_inventory(&ancestor.join(foreign.0.file_name().unwrap()), 16);
    assert!(observation.incomplete);
    assert!(observation.rows.is_empty());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn retained_root_enumeration_and_reads_survive_namespace_replacement_without_redirect() {
    let scratch = Scratch::new("retained-root");
    let actual = scratch.0.join("actual");
    std::fs::create_dir(&actual).unwrap();
    let original = Scratch(actual.clone());
    original.row("wf_1000_0", "original namespace");
    // Scratch's destructor would remove the replacement; the outer owner cleans up both names.
    let held = RestartDirectory::open(&actual).unwrap();
    let displaced = scratch.0.join("displaced");
    std::fs::rename(&actual, &displaced).unwrap();
    std::fs::create_dir(&actual).unwrap();
    let replacement = Scratch(actual);
    replacement.row("wf_2000_0", "replacement namespace");
    for _ in 0..2 {
        let names = held
            .entries()
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert!(names.iter().any(|name| name == "wf_1000_0"));
        assert!(!names.iter().any(|name| name == "wf_2000_0"));
    }
    let row = load_held_run_listing(&held, "wf_1000_0".into()).unwrap();
    assert_eq!(row.name, "original namespace");
    assert!(load_held_run_listing(&held, "wf_2000_0".into()).is_none());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn retained_child_cannot_mix_sidecars_with_replacement_child() {
    let scratch = Scratch::new("retained-child");
    scratch.row("wf_1000_0", "original child");
    let held = RestartDirectory::open(&scratch.0).unwrap();
    let child = held.child("wf_1000_0").unwrap();
    std::fs::rename(scratch.0.join("wf_1000_0"), scratch.0.join("displaced")).unwrap();
    scratch.row("wf_1000_0", "replacement child");
    let manifest: crate::workflow::RunManifest =
        serde_json::from_slice(&child.read("run.json", 64 * 1024).unwrap()).unwrap();
    assert_eq!(manifest.name, "original child");
    assert_eq!(
        load_held_run_listing(&held, "wf_1000_0".into())
            .unwrap()
            .name,
        "replacement child"
    );
}

#[cfg(windows)]
#[test]
fn retained_root_and_ancestors_deny_namespace_replacement_until_release() {
    let scratch = Scratch::new("retained-root-windows");
    let actual = scratch.0.join("actual");
    std::fs::create_dir(&actual).unwrap();
    let held = RestartDirectory::open(&actual).unwrap();
    assert!(std::fs::rename(&actual, scratch.0.join("replacement")).is_err());
    assert!(std::fs::rename(&scratch.0, scratch.0.with_extension("replacement")).is_err());
    drop(held);
    std::fs::rename(&actual, scratch.0.join("replacement")).unwrap();
}
