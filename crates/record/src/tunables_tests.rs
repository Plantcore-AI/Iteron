use super::*;
use crate::{
    ChainLine, LegacyTunablesPolicy, RecordError, Rollout, TunablesCompatibility,
    TunablesSnapshotError, ZERO_HASH, hash_line, replay, replay_with_tunables_snapshot,
};
use iteron_protocol::{
    Effort, Event, EventKind, RunGenesisTunablesInheritance, RunGenesisTunablesSnapshot,
    RunGenesisTunablesVersion, RunId, Seq, TenantId, TurnId,
};
use iteron_tunables::{EntryOutcome, ResolutionReport, ResolutionValue, ResolvedEntry, families};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn test_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "core-rec-tunables-{tag}-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn root_start(parent_run: Option<&str>) -> EventKind {
    EventKind::RunStart {
        cwd: "/repo".into(),
        model: "model".into(),
        effort: Effort::Medium,
        created_at: 1,
        environment: None,
        parent_run: parent_run.map(str::to_owned),
        forked_at: parent_run.map(|_| 0),
        parent_hash_at_seq: parent_run.map(|_| "b".repeat(64)),
        config_digest: "c".repeat(64),
        agent_definition_tag: None,
        max_usd: None,
    }
}

fn snapshot_event(
    snapshot: RunGenesisTunablesSnapshot,
    inherited_from: Option<RunGenesisTunablesInheritance>,
) -> EventKind {
    EventKind::TunablesSnapshot {
        version: RunGenesisTunablesVersion::V1,
        snapshot,
        inherited_from,
    }
}

#[test]
fn canonical_snapshot_recomputes_and_tampering_fails_closed() {
    let snapshot = fixture_snapshot();
    validate_tunables_snapshot(&snapshot).unwrap();

    let mut changed = snapshot.clone();
    changed.effective_digest_sha256 = "b".repeat(64);
    assert_eq!(
        validate_tunables_snapshot(&changed),
        Err(TunablesSnapshotError::Invalid {
            reason: "snapshot self-digest mismatch"
        })
    );

    let mut duplicated = snapshot.clone();
    duplicated.entries[1].family_id = duplicated.entries[0].family_id.clone();
    assert_eq!(
        validate_tunables_snapshot(&duplicated),
        Err(TunablesSnapshotError::Invalid {
            reason: "entry identity, order, or uniqueness is invalid"
        })
    );

    let mut missing = snapshot;
    missing.entries.pop();
    assert_eq!(
        validate_tunables_snapshot(&missing),
        Err(TunablesSnapshotError::Invalid {
            reason: "snapshot does not contain exactly the v1 family cardinality"
        })
    );
}

#[test]
fn per_family_state_omits_value_hashes_and_machine_identifiers_stay_bounded() {
    let entry = serde_json::to_value(&fixture_snapshot().entries[0]).unwrap();
    assert_eq!(
        entry
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "family_id".to_owned(),
            "ordinal".to_owned(),
            "semantic_key".to_owned(),
            "state".to_owned(),
        ]),
        "per-family raw hashes would expose dictionary-enumerable low-entropy values"
    );

    let mut credential = fixture_snapshot();
    credential.entries[0].family_id = format!("sk-{}", "x".repeat(80));
    assert_eq!(
        validate_tunables_snapshot(&credential),
        Err(TunablesSnapshotError::Invalid {
            reason: "entry identity, order, or uniqueness is invalid"
        })
    );
}

#[test]
fn genesis_tracker_rejects_late_duplicate_and_unbound_fork_snapshots() {
    let snapshot = fixture_snapshot();
    let mut root = GenesisTunablesState::default();
    root.observe(0, &root_start(None)).unwrap();
    root.observe(1, &snapshot_event(snapshot.clone(), None))
        .unwrap();
    let checkpoint = TunablesCheckpoint::V1(snapshot.clone());
    assert_eq!(root.checkpoint(), Some(&checkpoint));
    assert!(matches!(
        root.observe(2, &snapshot_event(snapshot.clone(), None)),
        Err(TunablesSnapshotError::GenesisOrder { .. })
    ));

    let mut late = GenesisTunablesState::default();
    late.observe(0, &root_start(None)).unwrap();
    assert!(matches!(
        late.observe(2, &snapshot_event(snapshot.clone(), None)),
        Err(TunablesSnapshotError::GenesisOrder { .. })
    ));

    let mut fork = GenesisTunablesState::default();
    fork.observe(0, &root_start(Some("parent"))).unwrap();
    assert!(matches!(
        fork.observe(1, &snapshot_event(snapshot.clone(), None)),
        Err(TunablesSnapshotError::GenesisOrder { .. })
    ));
    let wrong = RunGenesisTunablesInheritance {
        parent_run: "other".into(),
        parent_snapshot_digest_sha256: snapshot.snapshot_digest_sha256.clone(),
    };
    assert!(matches!(
        fork.observe(1, &snapshot_event(snapshot, Some(wrong))),
        Err(TunablesSnapshotError::GenesisOrder { .. })
    ));
}

#[test]
fn legacy_policy_never_reports_an_unpinned_record_as_exact() {
    let expected = fixture_snapshot();
    assert_eq!(
        check_compatibility(None, &expected, LegacyTunablesPolicy::AllowUnpinned),
        Ok(TunablesCompatibility::LegacyUnpinned)
    );
    assert_eq!(
        check_compatibility(None, &expected, LegacyTunablesPolicy::RejectUnpinned),
        Err(TunablesSnapshotError::LegacyUnpinned)
    );
    assert_eq!(
        check_compatibility(
            Some(&expected),
            &expected,
            LegacyTunablesPolicy::RejectUnpinned
        ),
        Ok(TunablesCompatibility::Exact)
    );
}

#[test]
fn accepted_report_projection_covers_every_family_and_aggregate_commitment() {
    let digest = "a".repeat(64);
    let mut entries = families()
        .iter()
        .map(|family| ResolvedEntry {
            ordinal: family.ordinal,
            family_id: family.id,
            semantic_key: family.semantic_key,
            requested: None,
            effective: None,
            provenance: None,
            outcome: EntryOutcome::Unavailable,
            adjustments: Vec::new(),
            shadowed: Vec::new(),
            default: family.default,
            strategy_slots: family.strategy_slots,
            optimization: family.optimization,
            benchmark_relevance: family.benchmark_relevance,
        })
        .collect::<Vec<_>>();
    entries[0].outcome = EntryOutcome::Effective;
    entries[0].effective = Some(ResolutionValue::Boolean { value: true });
    let report = ResolutionReport {
        schema_version: iteron_tunables::RESOLUTION_SCHEMA_VERSION,
        registry_id: iteron_tunables::REGISTRY_ID,
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256,
        input_digest_sha256: digest.clone(),
        effective_digest_sha256: digest.clone(),
        resolution_digest_sha256: digest,
        profile_digest_sha256: None,
        entries,
    };
    let snapshot = snapshot_from_report(&report).unwrap();
    assert_eq!(
        snapshot.entries.len(),
        iteron_tunables::EXPECTED_FAMILY_COUNT
    );
    assert_eq!(snapshot.entries[0].state, RunGenesisTunableState::Effective);
    assert_eq!(snapshot.effective_digest_sha256, "a".repeat(64));
    assert_eq!(
        snapshot.entries[1].state,
        RunGenesisTunableState::Unavailable
    );
    validate_tunables_snapshot(&snapshot).unwrap();
}

fn genesis() -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::RunStart {
            cwd: "/repo".into(),
            model: "model".into(),
            effort: Effort::Medium,
            created_at: 7,
            environment: None,
            parent_run: None,
            forked_at: None,
            parent_hash_at_seq: None,
            config_digest: "a".repeat(64),
            agent_definition_tag: None,
            max_usd: None,
        },
    }
}

#[test]
fn immutable_tunables_genesis_checks_fresh_resume_replay_and_fork() {
    let dir = test_dir("tunables-genesis");
    let parent = RunId("tunables-parent".into());
    let tenant = TenantId::default();
    let snapshot = crate::session::tunables::fixture_snapshot();
    {
        let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
        let seqs = rollout
            .append_genesis_snapshot(&genesis(), snapshot.clone(), None)
            .unwrap();
        assert_eq!(seqs, (Seq::ZERO, Seq(1)));
    }

    let (events, compatibility) = replay_with_tunables_snapshot(
        &dir.join("tunables-parent.jsonl"),
        &snapshot,
        LegacyTunablesPolicy::RejectUnpinned,
    )
    .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(compatibility, TunablesCompatibility::Exact);

    let (resumed, compatibility) = Rollout::open_existing_with_tunables_snapshot(
        &dir,
        &parent,
        tenant.clone(),
        &snapshot,
        LegacyTunablesPolicy::RejectUnpinned,
    )
    .unwrap();
    assert_eq!(compatibility, TunablesCompatibility::Exact);
    drop(resumed);

    let mismatch = crate::session::tunables::fixture_snapshot_variant('b');
    assert!(matches!(
        Rollout::open_existing_with_tunables_snapshot(
            &dir,
            &parent,
            tenant.clone(),
            &mismatch,
            LegacyTunablesPolicy::RejectUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::Mismatch { .. }
        ))
    ));

    let (child, child_compatibility) = crate::fork_with_tunables_snapshot(
        &dir,
        &parent,
        Seq(1),
        &tenant,
        &snapshot,
        LegacyTunablesPolicy::RejectUnpinned,
    )
    .unwrap();
    assert_eq!(child_compatibility, TunablesCompatibility::Exact);
    let child_events = replay(&dir.join(format!("{child}.jsonl"))).unwrap();
    match &child_events[1].kind {
        EventKind::TunablesSnapshot {
            snapshot: inherited,
            inherited_from: Some(binding),
            ..
        } => {
            assert_eq!(inherited, &snapshot);
            assert_eq!(binding.parent_run, parent.0);
            assert_eq!(
                binding.parent_snapshot_digest_sha256,
                snapshot.snapshot_digest_sha256
            );
        }
        other => panic!("fork did not bind the parent tunables snapshot: {other:?}"),
    }
}

#[test]
fn public_resolved_set_wrappers_cover_fresh_resume_replay_and_fork() {
    let dir = test_dir("tunables-public-resolved-wrappers");
    let parent = RunId("resolved-parent".into());
    let tenant = TenantId::default();
    let resolved = super::resolved_fixture::resolved();
    {
        let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
        assert_eq!(
            rollout
                .append_fresh_genesis_with_tunables(&genesis(), &resolved)
                .unwrap(),
            (Seq::ZERO, Seq(1))
        );
    }

    assert_eq!(
        crate::replay_with_resolved_tunables(
            &dir.join("resolved-parent.jsonl"),
            &resolved,
            LegacyTunablesPolicy::RejectUnpinned,
        )
        .unwrap()
        .1,
        TunablesCompatibility::Exact
    );
    let (resumed, compatibility) = Rollout::open_existing_with_resolved_tunables(
        &dir,
        &parent,
        tenant.clone(),
        &resolved,
        LegacyTunablesPolicy::RejectUnpinned,
    )
    .unwrap();
    assert_eq!(compatibility, TunablesCompatibility::Exact);
    drop(resumed);

    let (child, compatibility) = crate::fork_with_resolved_tunables(
        &dir,
        &parent,
        Seq(1),
        &tenant,
        &resolved,
        LegacyTunablesPolicy::RejectUnpinned,
    )
    .unwrap();
    assert_eq!(compatibility, TunablesCompatibility::Exact);
    assert_eq!(
        crate::replay_with_resolved_tunables(
            &dir.join(format!("{child}.jsonl")),
            &resolved,
            LegacyTunablesPolicy::RejectUnpinned,
        )
        .unwrap()
        .1,
        TunablesCompatibility::Exact
    );
}

fn replace_root_snapshot(path: &std::path::Path, replacement: RunGenesisTunablesSnapshot) {
    let mut lines = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<ChainLine>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(lines.len() >= 2);
    let mut event = serde_json::from_value::<Event>(lines[1].payload.clone()).unwrap();
    let EventKind::TunablesSnapshot {
        snapshot,
        inherited_from,
        ..
    } = &mut event.kind
    else {
        panic!("seq 1 stopped being a tunables snapshot")
    };
    assert!(
        inherited_from.is_none(),
        "fixture parent must be a root run"
    );
    *snapshot = replacement;
    lines[1].payload = serde_json::to_value(event).unwrap();
    for index in 1..lines.len() {
        let previous = lines[index - 1].hash.clone();
        lines[index].prev = previous.clone();
        lines[index].hash = hash_line(&previous, lines[index].seq, &lines[index].payload);
    }
    let mut encoded = lines
        .iter()
        .map(|line| serde_json::to_string(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    encoded.push('\n');
    std::fs::write(path, encoded).unwrap();
}

#[test]
fn seq_zero_and_nested_forks_recheck_the_actual_parent_snapshot() {
    let dir = test_dir("tunables-fork-parent-snapshot");
    let tenant = TenantId::default();
    let root = RunId("snapshot-root".into());
    let original = fixture_snapshot();
    {
        let mut rollout = Rollout::open(&dir, &root, tenant.clone()).unwrap();
        rollout
            .append_genesis_snapshot(&genesis(), original.clone(), None)
            .unwrap();
    }

    // A seq-0 fork's ordinary parent hash intentionally covers only RunStart. The separate
    // tunables inheritance edge must therefore bind the parent's actual seq-1 snapshot.
    let direct = crate::fork(&dir, &root, Seq::ZERO, &tenant).unwrap();
    let nested = crate::fork(&dir, &direct, Seq::ZERO, &tenant).unwrap();
    assert!(crate::load_forked(&dir, &direct).is_ok());
    assert!(crate::load_forked(&dir, &nested).is_ok());

    // Replace only the root's snapshot and re-anchor its later hash chain. The seq-0 parent hash
    // remains unchanged, so only the explicit snapshot provenance check can detect this.
    replace_root_snapshot(
        &dir.join(format!("{root}.jsonl")),
        fixture_snapshot_variant('b'),
    );
    for child in [&direct, &nested] {
        assert!(matches!(
            crate::load_forked(&dir, child),
            Err(RecordError::TunablesSnapshot(
                TunablesSnapshotError::GenesisOrder {
                    reason: "fork tunables inheritance does not match the actual parent seq-1 snapshot"
                }
            ))
        ));
    }
}

fn assert_checked_genesis_rejected(
    dir: &std::path::Path,
    run: &RunId,
    expected: &RunGenesisTunablesSnapshot,
) {
    let path = dir.join(format!("{run}.jsonl"));
    for policy in [
        LegacyTunablesPolicy::RejectUnpinned,
        LegacyTunablesPolicy::AllowUnpinned,
    ] {
        assert!(matches!(
            replay_with_tunables_snapshot(&path, expected, policy),
            Err(RecordError::TunablesSnapshot(
                TunablesSnapshotError::GenesisOrder {
                    reason: "physical seq 0 is not a structurally valid run_start"
                }
            ))
        ));
        assert!(matches!(
            Rollout::open_existing_with_tunables_snapshot(
                dir,
                run,
                TenantId::default(),
                expected,
                policy,
            ),
            Err(RecordError::TunablesSnapshot(
                TunablesSnapshotError::GenesisOrder {
                    reason: "physical seq 0 is not a structurally valid run_start"
                }
            ))
        ));
        assert!(matches!(
            crate::fork_with_tunables_snapshot(
                dir,
                run,
                Seq::ZERO,
                &TenantId::default(),
                expected,
                policy,
            ),
            Err(RecordError::TunablesSnapshot(
                TunablesSnapshotError::GenesisOrder {
                    reason: "physical seq 0 is not a structurally valid run_start"
                }
            ))
        ));
    }
}

#[test]
fn legacy_waiver_requires_a_structurally_valid_historical_run() {
    let dir = test_dir("tunables-legacy-structure");
    std::fs::create_dir_all(&dir).unwrap();
    let expected = fixture_snapshot();

    let empty = RunId("empty".into());
    std::fs::File::create(dir.join("empty.jsonl")).unwrap();
    assert_checked_genesis_rejected(&dir, &empty, &expected);

    let wrong_kind = RunId("wrong-kind".into());
    {
        let mut rollout = Rollout::open(&dir, &wrong_kind, TenantId::default()).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
    }
    assert_checked_genesis_rejected(&dir, &wrong_kind, &expected);

    let malformed_fork = RunId("malformed-fork".into());
    {
        let mut rollout = Rollout::open(&dir, &malformed_fork, TenantId::default()).unwrap();
        let mut malformed = genesis();
        let EventKind::RunStart {
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } = &mut malformed.kind
        else {
            unreachable!()
        };
        *parent_run = Some("parent".into());
        *forked_at = None;
        *parent_hash_at_seq = Some("b".repeat(64));
        rollout.append(&malformed).unwrap();
    }
    assert_checked_genesis_rejected(&dir, &malformed_fork, &expected);
}

#[test]
fn fresh_genesis_faults_preserve_only_a_checked_durable_prefix() {
    let expected = fixture_snapshot();
    for barrier in [1, 2] {
        let dir = test_dir(&format!("tunables-genesis-sync-{barrier}"));
        let run = RunId(format!("sync-{barrier}"));
        let mut rollout = Rollout::open(&dir, &run, TenantId::default()).unwrap();
        crate::set_append_sync_fault_at(Some(barrier));
        assert!(matches!(
            rollout.append_genesis_snapshot(&genesis(), expected.clone(), None),
            Err(RecordError::Io(_))
        ));
        crate::set_append_sync_fault_at(None);
        drop(rollout);

        let path = dir.join(format!("{run}.jsonl"));
        let events = replay(&path).unwrap();
        assert_eq!(events.len(), barrier - 1);
        if barrier == 1 {
            // A first-barrier crash leaves no historical run to waive.
            for policy in [
                LegacyTunablesPolicy::RejectUnpinned,
                LegacyTunablesPolicy::AllowUnpinned,
            ] {
                assert!(matches!(
                    replay_with_tunables_snapshot(&path, &expected, policy),
                    Err(RecordError::TunablesSnapshot(
                        TunablesSnapshotError::GenesisOrder { .. }
                    ))
                ));
            }
        } else {
            // A second-barrier crash preserves the confirmed RunStart only: explicit legacy
            // admission may continue, but exact compatibility remains impossible.
            assert!(matches!(
                replay_with_tunables_snapshot(
                    &path,
                    &expected,
                    LegacyTunablesPolicy::RejectUnpinned,
                ),
                Err(RecordError::TunablesSnapshot(
                    TunablesSnapshotError::LegacyUnpinned
                ))
            ));
            assert_eq!(
                replay_with_tunables_snapshot(
                    &path,
                    &expected,
                    LegacyTunablesPolicy::AllowUnpinned,
                )
                .unwrap()
                .1,
                TunablesCompatibility::LegacyUnpinned
            );
        }
    }
}

#[test]
fn checked_legacy_policy_and_snapshot_placement_fail_closed_without_mutation() {
    let dir = test_dir("tunables-legacy-order");
    let tenant = TenantId::default();
    let legacy = RunId("legacy".into());
    {
        let mut rollout = Rollout::open(&dir, &legacy, tenant.clone()).unwrap();
        rollout.append(&genesis()).unwrap();
    }
    let snapshot = crate::session::tunables::fixture_snapshot();
    assert!(matches!(
        Rollout::open_existing_with_tunables_snapshot(
            &dir,
            &legacy,
            tenant.clone(),
            &snapshot,
            LegacyTunablesPolicy::RejectUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::LegacyUnpinned
        ))
    ));
    let (allowed, compatibility) = Rollout::open_existing_with_tunables_snapshot(
        &dir,
        &legacy,
        tenant.clone(),
        &snapshot,
        LegacyTunablesPolicy::AllowUnpinned,
    )
    .unwrap();
    assert_eq!(compatibility, TunablesCompatibility::LegacyUnpinned);
    drop(allowed);
    assert!(matches!(
        replay_with_tunables_snapshot(
            &dir.join("legacy.jsonl"),
            &snapshot,
            LegacyTunablesPolicy::RejectUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::LegacyUnpinned
        ))
    ));
    assert_eq!(
        replay_with_tunables_snapshot(
            &dir.join("legacy.jsonl"),
            &snapshot,
            LegacyTunablesPolicy::AllowUnpinned,
        )
        .unwrap()
        .1,
        TunablesCompatibility::LegacyUnpinned
    );
    let before_rejected_fork = std::fs::read_dir(&dir).unwrap().count();
    assert!(matches!(
        crate::fork_with_tunables_snapshot(
            &dir,
            &legacy,
            Seq::ZERO,
            &tenant,
            &snapshot,
            LegacyTunablesPolicy::RejectUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::LegacyUnpinned
        ))
    ));
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        before_rejected_fork,
        "incompatible fork must fail before child creation"
    );
    let (legacy_child, child_compatibility) = crate::fork_with_tunables_snapshot(
        &dir,
        &legacy,
        Seq::ZERO,
        &tenant,
        &snapshot,
        LegacyTunablesPolicy::AllowUnpinned,
    )
    .unwrap();
    assert_eq!(child_compatibility, TunablesCompatibility::LegacyUnpinned);
    assert!(
        replay(&dir.join(format!("{legacy_child}.jsonl")))
            .unwrap()
            .iter()
            .all(|event| !matches!(event.kind, EventKind::TunablesSnapshot { .. }))
    );

    let invalid = RunId("invalid".into());
    let mut invalid_rollout = Rollout::open(&dir, &invalid, tenant.clone()).unwrap();
    invalid_rollout.append(&genesis()).unwrap();
    let mut tampered = snapshot.clone();
    tampered.effective_digest_sha256 = "b".repeat(64);
    assert!(matches!(
        invalid_rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::TunablesSnapshot {
                version: iteron_protocol::RunGenesisTunablesVersion::V1,
                snapshot: tampered,
                inherited_from: None,
            },
        }),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::Invalid { .. }
        ))
    ));
    assert_eq!(invalid_rollout.next_sequence(), Seq(1));
    invalid_rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::TunablesSnapshot {
                version: iteron_protocol::RunGenesisTunablesVersion::V1,
                snapshot: snapshot.clone(),
                inherited_from: None,
            },
        })
        .unwrap();
    drop(invalid_rollout);

    let late = RunId("late".into());
    let mut rollout = Rollout::open(&dir, &late, tenant).unwrap();
    rollout.append(&genesis()).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::TurnStart,
        })
        .unwrap();
    assert!(matches!(
        rollout.append_genesis_snapshot(&genesis(), snapshot, None),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::GenesisOrder { .. }
        ))
    ));
    drop(rollout);
    assert_eq!(replay(&dir.join("late.jsonl")).unwrap().len(), 2);

    // The generic append ABI accepts a placeholder seq and is schema-frozen. Even if a caller
    // bypasses the companion API, checked readers use the physical chain sequence and refuse to
    // reinterpret a late event as genesis evidence.
    let raw_late = RunId("raw-late".into());
    let raw_snapshot = fixture_snapshot();
    let mut raw = Rollout::open(&dir, &raw_late, TenantId::default()).unwrap();
    raw.append(&genesis()).unwrap();
    raw.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::TurnStart,
    })
    .unwrap();
    raw.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: snapshot_event(raw_snapshot.clone(), None),
    })
    .unwrap();
    drop(raw);
    assert!(matches!(
        replay_with_tunables_snapshot(
            &dir.join("raw-late.jsonl"),
            &raw_snapshot,
            LegacyTunablesPolicy::AllowUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::GenesisOrder { .. }
        ))
    ));
    assert!(matches!(
        Rollout::open_existing_with_tunables_snapshot(
            &dir,
            &raw_late,
            TenantId::default(),
            &raw_snapshot,
            LegacyTunablesPolicy::AllowUnpinned,
        ),
        Err(RecordError::TunablesSnapshot(
            TunablesSnapshotError::GenesisOrder { .. }
        ))
    ));
}

#[test]
fn hash_valid_but_self_inconsistent_snapshot_is_refused_by_every_read_boundary() {
    let dir = test_dir("tunables-forged-self-digest");
    std::fs::create_dir_all(&dir).unwrap();
    let run = RunId("forged".into());
    let path = dir.join("forged.jsonl");

    let start_payload = serde_json::to_value(genesis()).unwrap();
    let start_hash = hash_line(ZERO_HASH, 0, &start_payload);
    let start_line = ChainLine {
        seq: 0,
        tenant: TenantId::default().0,
        prev: ZERO_HASH.into(),
        hash: start_hash.clone(),
        ts_us: None,
        payload: start_payload,
    };
    let mut tampered = crate::session::tunables::fixture_snapshot();
    tampered.effective_digest_sha256 = "b".repeat(64);
    let snapshot_payload = serde_json::to_value(Event {
        seq: Seq(1),
        turn: TurnId(0),
        kind: EventKind::TunablesSnapshot {
            version: iteron_protocol::RunGenesisTunablesVersion::V1,
            snapshot: tampered,
            inherited_from: None,
        },
    })
    .unwrap();
    let snapshot_line = ChainLine {
        seq: 1,
        tenant: TenantId::default().0,
        prev: start_hash.clone(),
        hash: hash_line(&start_hash, 1, &snapshot_payload),
        ts_us: None,
        payload: snapshot_payload,
    };
    std::fs::write(
        &path,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&start_line).unwrap(),
            serde_json::to_string(&snapshot_line).unwrap()
        ),
    )
    .unwrap();

    for error in [
        replay(&path).unwrap_err(),
        Rollout::open(&dir, &run, TenantId::default())
            .err()
            .expect("forged snapshot must make writer open fail"),
        crate::fork(&dir, &run, Seq(1), &TenantId::default()).unwrap_err(),
    ] {
        assert!(matches!(
            error,
            RecordError::TunablesSnapshot(TunablesSnapshotError::Invalid {
                reason: "snapshot self-digest mismatch"
            })
        ));
    }
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "failed fork must not create a child journal"
    );
}
