use super::*;

fn scratch(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "core-tunables-view-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn assert_text_bound(value: &str, max_chars: usize, max_bytes: usize) {
    assert!(value.chars().count() <= max_chars, "char cap: {value:?}");
    assert!(value.len() <= max_bytes, "byte cap: {value:?}");
    assert!(
        !value.chars().any(format::is_unsafe_display_char),
        "control escaped: {value:?}"
    );
}

fn assert_detail_bound(detail: &Detail) {
    assert_text_bound(
        &detail.family_id,
        format::MAX_DETAIL_ID_CHARS,
        format::MAX_DETAIL_ID_BYTES,
    );
    assert_text_bound(
        &detail.label,
        format::MAX_DETAIL_LABEL_CHARS,
        format::MAX_DETAIL_LABEL_BYTES,
    );
    assert_text_bound(
        &detail.hint,
        format::MAX_DETAIL_FIELD_CHARS,
        format::MAX_DETAIL_FIELD_BYTES,
    );
    for (label, value) in &detail.rows {
        assert_text_bound(
            label,
            format::MAX_DETAIL_ROW_LABEL_CHARS,
            format::MAX_DETAIL_ROW_LABEL_BYTES,
        );
        assert_text_bound(
            value,
            format::MAX_DETAIL_FIELD_CHARS,
            format::MAX_DETAIL_FIELD_BYTES,
        );
    }
    for note in &detail.notes {
        assert_text_bound(
            note,
            format::MAX_DETAIL_FIELD_CHARS,
            format::MAX_DETAIL_FIELD_BYTES,
        );
    }
}

fn minimal_request() -> String {
    format!(
        r#"{{"schema_version":1,"registry_id":"core-tunables","registry_revision":{},"registry_digest":"{}","declared_values":[],"default_evidence":[],"activation_evidence":[],"constraint_evidence":[],"runtime":{{}}}}"#,
        core_tunables::REGISTRY_REVISION,
        core_tunables::REGISTRY_DIGEST_SHA256,
    )
}

#[test]
fn catalog_exposes_all_families_and_all_truthful_detail_fields() {
    let catalog = registry_catalog();
    assert_eq!(catalog.entries.len(), core_tunables::EXPECTED_FAMILY_COUNT);
    assert!(catalog.title.contains("simulation only"));
    assert_text_bound(
        &catalog.title,
        format::MAX_DETAIL_TITLE_CHARS,
        format::MAX_DETAIL_TITLE_BYTES,
    );
    for (index, entry) in catalog.entries.iter().enumerate() {
        assert_detail_bound(entry);
        assert_eq!(entry.family_id, core_tunables::families()[index].id);
        let labels: Vec<_> = entry.rows.iter().map(|row| row.0.as_str()).collect();
        for required in [
            "surface",
            "resolution",
            "requested",
            "effective",
            "adjustments",
            "default",
            "declared sources",
            "constraints",
            "benchmarks",
        ] {
            assert!(
                labels.contains(&required),
                "{} omitted {required}",
                entry.family_id
            );
        }
    }
}

#[test]
fn every_detail_string_is_source_bounded_in_chars_bytes_and_controls() {
    let hostile = "😀\n\u{202e}".repeat(2_000);
    let detail = format::bounded_detail(Detail {
        family_id: hostile.clone(),
        label: hostile.clone(),
        hint: hostile.clone(),
        rows: vec![(hostile.clone(), hostile.clone())],
        notes: vec![hostile.clone()],
    });
    assert_detail_bound(&detail);
    assert_text_bound(
        &format::bounded_title(&hostile),
        format::MAX_DETAIL_TITLE_CHARS,
        format::MAX_DETAIL_TITLE_BYTES,
    );
    assert!(detail.family_id.ends_with('…'));
    assert!(detail.label.ends_with('…'));
    assert!(detail.hint.ends_with('…'));
    assert!(detail.rows[0].0.ends_with('…'));
    assert!(detail.rows[0].1.ends_with('…'));
    assert!(detail.notes[0].ends_with('…'));
}

#[test]
fn frozen_request_failure_still_yields_a_redacted_atomic_report() {
    let request = minimal_request();
    let catalog = catalog_from_bytes(request.as_bytes()).expect("valid frozen request");
    assert!(catalog.title.contains("active resolution failed"));
    assert_eq!(catalog.entries.len(), core_tunables::EXPECTED_FAMILY_COUNT);
    assert!(
        catalog
            .entries
            .iter()
            .flat_map(|entry| &entry.rows)
            .any(|row| row.0 == "requested" && row.1.contains("<redacted>"))
    );
    assert!(
        catalog
            .entries
            .iter()
            .flat_map(|entry| &entry.rows)
            .filter(|row| { matches!(row.0.as_str(), "requested" | "effective" | "adjustments") })
            .all(|row| !row.1.contains("glm"))
    );
    let provider = catalog
        .entries
        .iter()
        .find(|entry| entry.family_id == "provider")
        .expect("provider entry");
    assert!(
        provider
            .notes
            .iter()
            .any(|note| note.contains("not the current process state"))
    );
}

#[test]
fn invalid_request_fails_closed_without_a_partial_catalog() {
    let error = catalog_from_bytes(b"{}").expect_err("invalid identity must fail");
    assert_eq!(
        error.to_string(),
        "request validation failed closed; no simulation report was produced"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_loader_is_confined_and_enforces_the_resolver_input_cap() {
    let root = scratch("confined");
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    std::fs::write(root.join("request.json"), minimal_request()).expect("write valid request");

    let catalog = load_workspace_request(&root, "request.json").expect("load confined request");
    assert!(catalog.title.contains("active resolution failed"));
    assert_eq!(
        load_workspace_request(&root, "../request.json")
            .expect_err("parent traversal must fail")
            .to_string(),
        "request path must stay inside the workspace"
    );
    assert_eq!(
        load_workspace_request(&root, &root.join("request.json").display().to_string())
            .expect_err("absolute path must fail")
            .to_string(),
        "request path must stay inside the workspace"
    );

    std::fs::write(
        root.join("oversized.json"),
        vec![b' '; RESOLUTION_INPUT_MAX_BYTES + 1],
    )
    .expect("write oversized request");
    assert_eq!(
        load_workspace_request(&root, "oversized.json")
            .expect_err("oversized request must fail")
            .to_string(),
        "request exceeds the resolver's 1 MiB input cap"
    );
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn workspace_loader_fails_closed_without_linux_capabilities() {
    let root = scratch("unsupported");
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    std::fs::write(root.join("request.json"), minimal_request()).expect("write valid request");
    assert_eq!(
        load_workspace_request(&root, "request.json")
            .expect_err("unsupported platform must refuse")
            .to_string(),
        SAFE_LOAD_REFUSAL
    );
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_leaf_is_refused_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let root = scratch("fifo");
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    let fifo = root.join("request.json");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
    // SAFETY: `fifo_c` remains live and names a test-only path.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let started = std::time::Instant::now();
    let error = load_workspace_request(&root, "request.json").expect_err("FIFO must fail closed");
    assert_eq!(error.to_string(), SAFE_LOAD_REFUSAL);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "nonblocking FIFO refusal exceeded the liveness bound"
    );
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}

#[cfg(target_os = "linux")]
#[test]
fn leaf_swap_after_acquisition_is_refused_before_resolver_delivery() {
    let root = scratch("leaf-swap");
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    std::fs::write(root.join("request.json"), minimal_request()).expect("write held request");
    std::fs::write(root.join("replacement.json"), minimal_request())
        .expect("write replacement request");
    let attack_root = root.clone();
    let error = read_workspace_request_with_hook(&root, "request.json", move || {
        std::fs::rename(
            attack_root.join("request.json"),
            attack_root.join("detached.json"),
        )
        .expect("detach held leaf");
        std::fs::rename(
            attack_root.join("replacement.json"),
            attack_root.join("request.json"),
        )
        .expect("replace visible leaf");
    })
    .expect_err("swapped leaf must fail closed");
    assert_eq!(error.to_string(), SAFE_LOAD_REFUSAL);
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}

#[cfg(target_os = "linux")]
#[test]
fn parent_replacement_after_acquisition_is_refused_before_resolver_delivery() {
    let root = scratch("parent-swap");
    std::fs::create_dir_all(root.join("requests")).expect("create isolated workspace");
    std::fs::write(root.join("requests/request.json"), minimal_request())
        .expect("write held request");
    let attack_root = root.clone();
    let error = read_workspace_request_with_hook(&root, "requests/request.json", move || {
        std::fs::rename(
            attack_root.join("requests"),
            attack_root.join("detached-requests"),
        )
        .expect("detach held parent");
        std::fs::create_dir(attack_root.join("requests")).expect("replace visible parent");
        std::fs::write(attack_root.join("requests/request.json"), minimal_request())
            .expect("write replacement leaf");
    })
    .expect_err("replaced parent must fail closed");
    assert_eq!(error.to_string(), SAFE_LOAD_REFUSAL);
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
}

#[cfg(target_os = "linux")]
#[test]
fn outside_valid_and_invalid_targets_have_indistinguishable_refusals() {
    use std::os::unix::fs::symlink;

    let root = scratch("outside-links");
    let outside = scratch("outside-targets");
    std::fs::create_dir_all(&root).expect("create isolated workspace");
    std::fs::create_dir_all(&outside).expect("create outside fixture");
    std::fs::write(outside.join("valid.json"), minimal_request()).expect("write valid outside");
    std::fs::write(outside.join("invalid.json"), b"{}").expect("write invalid outside");
    symlink(outside.join("valid.json"), root.join("valid.json")).expect("link valid outside");
    symlink(outside.join("invalid.json"), root.join("invalid.json")).expect("link invalid outside");

    let valid = load_workspace_request(&root, "valid.json")
        .expect_err("outside valid document must be refused")
        .to_string();
    let invalid = load_workspace_request(&root, "invalid.json")
        .expect_err("outside invalid document must be refused")
        .to_string();
    assert_eq!(valid, SAFE_LOAD_REFUSAL);
    assert_eq!(invalid, valid);
    std::fs::remove_dir_all(root).expect("remove isolated workspace");
    std::fs::remove_dir_all(outside).expect("remove outside fixture");
}
