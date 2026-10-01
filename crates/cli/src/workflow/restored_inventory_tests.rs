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
        Self(path)
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
