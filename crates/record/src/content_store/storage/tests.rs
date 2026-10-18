use super::*;

#[test]
fn reference_pair_admits_exact_membership_and_rolls_back_incomplete_frames() {
    let dir = std::env::temp_dir().join(format!(
        "iteron-reference-pair-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let layout = Layout::new(&dir, &TenantId::default());
    ensure_layout(&layout).unwrap();
    let lease = lock_store(&layout).unwrap();
    let digest = digest_bytes(b"paired content");
    store_locked(
        &layout,
        lease.write_state().unwrap(),
        &digest,
        b"paired content",
    )
    .unwrap();
    let run = RunId("paired-references".into());
    let pair = [
        ContentReferenceSurface::RecordField,
        ContentReferenceSurface::ToolArtifact,
    ];
    let publish = |seq, surfaces: &[ContentReferenceSurface], limit| {
        write_edges_locked(
            &layout,
            &digest,
            &run,
            Seq(seq),
            0,
            "tool_result",
            surfaces,
            PrivateContentRetention::Session,
            limit,
        )
    };
    // Completing an existing root consumes exactly one further member of each direction.
    publish(1, &pair[..1], 2).unwrap();
    publish(1, &pair, 2).unwrap();
    assert_eq!(metadata_count(&layout.run_reference_dir(&run)).unwrap(), 2);
    assert_eq!(
        metadata_count(&layout.object_path(&layout.refs, &digest)).unwrap(),
        2
    );
    let log = layout.scope.join("metadata-v2.log");
    let committed = std::fs::metadata(&log).unwrap().len();
    publish(1, &pair, 2).unwrap();
    assert_eq!(std::fs::metadata(&log).unwrap().len(), committed);
    // One remaining slot cannot admit a new two-reference field; neither direction changes.
    assert!(matches!(
        publish(2, &pair, 3),
        Err(ContentStoreError::ReferenceBound { max: 3 })
    ));
    assert_eq!(std::fs::metadata(&log).unwrap().len(), committed);
    assert_eq!(metadata_count(&layout.run_reference_dir(&run)).unwrap(), 2);
    // A truncated pair has no recoverable first half. A fresh lease repairs the incomplete tail.
    publish(2, &pair, 4).unwrap();
    let complete_pair = std::fs::read(&log).unwrap();
    let frame = &complete_pair[committed as usize..];
    assert_eq!(&frame[..8], b"ITMETA02");
    assert_eq!(
        frame.len(),
        44 + u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize
    );
    drop(lease);
    OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(complete_pair.len() as u64 - 1)
        .unwrap();
    let _lease = lock_store(&layout).unwrap();
    assert_eq!(std::fs::metadata(&log).unwrap().len(), committed);
    assert_eq!(metadata_count(&layout.run_reference_dir(&run)).unwrap(), 2);
    assert_eq!(
        metadata_count(&layout.object_path(&layout.refs, &digest)).unwrap(),
        2
    );
    // Existing malformed semantic metadata refuses the entire pair before adding its root.
    publish(3, &pair[1..], 3).unwrap();
    let semantic =
        reference_edge_path(&layout, &digest, &run, Seq(3), 0, "tool_result", pair[1]).unwrap();
    metadata::replace_batch(&[(semantic, Some(b"malformed edge".to_vec()))]).unwrap();
    let before_refusal = std::fs::metadata(&log).unwrap().len();
    assert!(matches!(
        publish(3, &pair, 4),
        Err(ContentStoreError::Corrupt)
    ));
    assert_eq!(std::fs::metadata(&log).unwrap().len(), before_refusal);
    assert_eq!(metadata_count(&layout.run_reference_dir(&run)).unwrap(), 3);
    drop(_lease);
    std::fs::remove_dir_all(dir).unwrap();
}
