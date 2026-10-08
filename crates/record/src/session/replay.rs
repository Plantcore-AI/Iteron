//! Verified logical history and fork transactions, with one private cumulative read budget.
#[cfg(test)]
use super::READ_CHAIN_CALLS;
use super::cache_receipts::file_mtime;
use super::model::{MAX_FORK_DEPTH, ScopedEvent, SessionAncestryReceipt};
use super::paths::{MICROUSD_PER_USD, legacy_usd_to_microusd_floor, now_secs, rollout_path};
use super::tunables;
use crate::{RecordError, Rollout, TimedEvent, ensure_tenant, validate_event_bounds};
use iteron_protocol::{
    Event, EventKind, RunId, RuntimePolicyEventVersion, RuntimePolicySource, RuntimePolicyState,
    Seq, TenantId, TurnId,
};
use std::{collections::HashSet, io, path::Path};

/// A run id only has to be collision-resistant: a pre-epoch clock still yields a name, uniqueness
/// then resting on the pid.
const RUN_ID_NANOS_FALLBACK: u128 = 0;

/// A scoped expansion without an `upto` seq is not truncated at all, so every replayed line of the
/// run stays in scope; the bound only ever removes lines a caller explicitly asked to cut.
const UNBOUNDED_SCOPE_ADMITS_LINE: bool = true;

/// A verified rollout line: the chain metadata plus the parsed event. The workhorse behind every
/// projection below; it re-verifies the hash chain exactly as `replay` does (a broken chain is an
/// error, not a warning) and additionally surfaces the per-line `tenant` and `hash` that `replay`
/// discards but the session projection and the fork cross-link need.
pub(super) struct ReadLine {
    pub(super) seq: Seq,
    pub(super) tenant: TenantId,
    pub(super) hash: String,
    pub(super) end_bytes: u64,
    pub(super) event: Event,
}

#[cfg(test)]
pub(super) fn read_chain(path: &Path) -> Result<Vec<ReadLine>, RecordError> {
    let mut total_bytes = 0;
    let mut total_physical_lines = 0;
    read_chain_with_limits(
        path,
        &mut total_bytes,
        &mut total_physical_lines,
        None,
        None,
    )
}

pub(super) fn read_chain_budgeted(
    path: &Path,
    budget: &mut LogicalReplayBudget,
) -> Result<Vec<ReadLine>, RecordError> {
    read_chain_with_limits(
        path,
        &mut budget.bytes,
        &mut budget.physical_lines,
        Some(&mut budget.events),
        budget.projection.as_mut(),
    )
}

fn read_chain_with_limits(
    path: &Path,
    total_bytes: &mut u64,
    total_physical_lines: &mut usize,
    mut total_events: Option<&mut usize>,
    mut projection_budget: Option<&mut crate::bounded_replay::ReplayReadBudget>,
) -> Result<Vec<ReadLine>, RecordError> {
    #[cfg(test)]
    READ_CHAIN_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let mut out = Vec::new();
    let mut prev = crate::ZERO_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut tenant: Option<TenantId> = None;
    let mut physical_bytes = 0u64;
    let mut genesis_tunables = tunables::GenesisTunablesState::default();
    // Tolerate a torn trailing line from a crash mid-append (code review): the resume path routes
    // through here, so a strict read would make a crashed run unresumable — exactly the tolerance
    // scan_tail already gives the append path. A partial FINAL line (no trailing newline) is dropped.
    crate::visit_record_lines_charged(path, total_bytes, total_physical_lines, |line| {
        physical_bytes = physical_bytes.saturating_add(line.len() as u64 + 1);
        if let Some(budget) = projection_budget.as_deref_mut() {
            budget.line(line.len().saturating_add(1), !line.trim().is_empty())?;
        }
        if line.trim().is_empty() {
            return Ok(());
        }
        if let Some(total) = total_events.as_deref_mut() {
            admit_logical_events(total, 1)?;
        }
        let cl: crate::ChainLine = serde_json::from_str(line)?;
        if cl.seq != expected_seq {
            return Err(RecordError::SequenceBroken {
                expected: expected_seq,
                found: cl.seq,
            });
        }
        if let Some(expected) = &tenant {
            ensure_tenant(expected, &cl.tenant, cl.seq)?;
        } else {
            tenant = Some(TenantId(cl.tenant.clone()));
        }
        let computed = crate::hash_line(&cl.prev, cl.seq, &cl.payload);
        if computed != cl.hash || cl.prev != prev {
            return Err(RecordError::ChainBroken {
                seq: cl.seq,
                stored: cl.hash,
                computed,
            });
        }
        // Resolve only after the immutable line hash is verified. A revoked/missing handle is a
        // terminal read failure for projections, resume, and every fork expansion.
        let mut payload = cl.payload;
        let runs_dir = path.parent().ok_or_else(|| {
            RecordError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rollout path has no runs directory",
            ))
        })?;
        crate::content_store::hydrate_event_payload_budgeted(
            runs_dir,
            &TenantId(cl.tenant.clone()),
            &mut payload,
            projection_budget.as_deref_mut(),
        )?;
        // Unknown event kinds deserialize to `EventKind::Unknown` (R5-review Risk 6), so a newer
        // writer's kinds do not fail the scan.
        let event: Event = serde_json::from_value(payload)?;
        validate_event_bounds(&event)?;
        genesis_tunables.observe(cl.seq, &event.kind)?;
        prev = cl.hash.clone();
        expected_seq = expected_seq.saturating_add(1);
        out.push(ReadLine {
            seq: Seq(cl.seq),
            tenant: TenantId(cl.tenant),
            hash: cl.hash,
            end_bytes: physical_bytes,
            event,
        });
        Ok(())
    })?;
    Ok(out)
}

/// Mint a fresh, collision-resistant run id (process id + wall-clock nanos), matching the CLI's
/// scheme. The clock crosses the nondeterminism boundary once, only to name the run.
fn mint_run_id() -> RunId {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(RUN_ID_NANOS_FALLBACK);
    RunId(format!("run-{}-{}", std::process::id(), nanos))
}

/// Fork `parent` at seq `at` into a fresh run (SESS-1, the reference model). Mints a new `RunId`,
/// opens its chain, and writes a genesis [`EventKind::RunStart`] plus the effective
/// [`EventKind::ModelSelected`] snapshot when one exists — no parent-prefix bytes are copied. The
/// genesis pins `parent_hash_at_seq` (the parent chain's hash at `at`) so the reference is
/// tamper-evident on load (ADR-008 §4, R5-review Risk 3). The child inherits the parent's session
/// config (cwd/model/effort/config_digest), exact route at the branch point, and the given `tenant`.
/// If the parent has a valid tunables snapshot this legacy-compatible API preserves and binds it,
/// but does not compare it with a current resolved set. Execution frontends must use
/// [`fork_with_resolved_tunables`] (or the explicitly snapshot-checked form).
pub fn fork(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
) -> Result<RunId, RecordError> {
    Ok(fork_internal(runs_dir, parent, at, tenant, None)?.0)
}

/// Checked fork/rewind. Exact current compatibility is established before a child file is
/// created; a legacy parent requires an explicit policy and produces a legacy child without
/// inventing a migration or a snapshot.
pub fn fork_with_tunables_snapshot(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    expected: &iteron_protocol::RunGenesisTunablesSnapshot,
    legacy: tunables::LegacyTunablesPolicy,
) -> Result<(RunId, tunables::TunablesCompatibility), RecordError> {
    let expected = ForkTunablesExpectation::V1(expected, legacy);
    let (child, compatibility) = fork_internal(runs_dir, parent, at, tenant, Some(expected))?;
    Ok((
        child,
        compatibility.expect("checked fork always computes a compatibility result"),
    ))
}

/// Resolver-typed convenience wrapper for [`fork_with_tunables_snapshot`].
pub fn fork_with_resolved_tunables(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    resolved: &iteron_tunables::ResolvedTunableSet,
    legacy: tunables::LegacyTunablesPolicy,
) -> Result<(RunId, tunables::TunablesCompatibility), RecordError> {
    let expected = ForkTunablesExpectation::Resolved(resolved, legacy);
    let (child, compatibility) = fork_internal(runs_dir, parent, at, tenant, Some(expected))?;
    Ok((
        child,
        compatibility.expect("checked fork always computes a compatibility result"),
    ))
}

/// Version-neutral checked fork against the immutable current host checkpoint. Compatibility
/// is established before creating the child; no resolver or ambient configuration is consulted.
pub fn fork_with_checkpoint(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    checkpoint: &tunables::TunablesCheckpoint,
    legacy: tunables::LegacyTunablesPolicy,
) -> Result<(RunId, tunables::TunablesCompatibility), RecordError> {
    let expected = ForkTunablesExpectation::Checkpoint(checkpoint, legacy);
    let (child, compatibility) = fork_internal(runs_dir, parent, at, tenant, Some(expected))?;
    Ok((
        child,
        compatibility.expect("checked fork computes compatibility"),
    ))
}

#[derive(Clone, Copy)]
enum ForkTunablesExpectation<'a> {
    Checkpoint(
        &'a tunables::TunablesCheckpoint,
        tunables::LegacyTunablesPolicy,
    ),
    V1(
        &'a iteron_protocol::RunGenesisTunablesSnapshot,
        tunables::LegacyTunablesPolicy,
    ),
    Resolved(
        &'a iteron_tunables::ResolvedTunableSet,
        tunables::LegacyTunablesPolicy,
    ),
}

fn fork_internal(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
    expected: Option<ForkTunablesExpectation<'_>>,
) -> Result<(RunId, Option<tunables::TunablesCompatibility>), RecordError> {
    let parent_path = rollout_path(runs_dir, parent)?;
    // Read + verify the parent chain exactly once under the same cumulative budget later used for
    // its ancestors. The verified lines are passed into logical expansion rather than reopened.
    let mut replay_budget = LogicalReplayBudget::default();
    let parent_lines = read_chain_budgeted(&parent_path, &mut replay_budget)?;
    if let Some(first) = parent_lines.first() {
        ensure_tenant(tenant, &first.tenant.0, first.seq.0)?;
    }
    let parent_snapshot = genesis_tunables_event(&parent_lines).map(|(snapshot, _)| snapshot);
    let parent_policy_snapshot =
        genesis_policy_bundle_event(&parent_lines).map(|(snapshot, _)| snapshot);
    let compatibility = if let Some(expected) = expected {
        let recorded = checked_genesis_tunables(&parent_lines)?;
        Some(match expected {
            ForkTunablesExpectation::Checkpoint(checkpoint, legacy) => {
                tunables::check_checkpoint_compatibility(recorded.as_ref(), checkpoint, legacy)?
            }
            ForkTunablesExpectation::V1(expected, legacy) => {
                let expected = tunables::TunablesCheckpoint::V1(expected.clone());
                tunables::check_checkpoint_compatibility(recorded.as_ref(), &expected, legacy)?
            }
            ForkTunablesExpectation::Resolved(resolved, legacy) => {
                tunables::check_resolved_compatibility(recorded.as_ref(), resolved, legacy)?
            }
        })
    } else {
        None
    };
    let pinned = parent_lines
        .iter()
        .find(|l| l.seq == at)
        .map(|l| l.hash.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot fork {parent} at seq {}: beyond the parent tail",
                    at.0
                ),
            )
        })?;

    let (cwd, mut model, config_digest, mut environment, agent_definition_tag) =
        match parent_lines.first().map(|l| &l.event.kind) {
            Some(EventKind::RunStart {
                cwd,
                model,
                config_digest,
                environment,
                agent_definition_tag,
                ..
            }) => (
                cwd.clone(),
                model.clone(),
                config_digest.clone(),
                environment.clone(),
                agent_definition_tag.clone(),
            ),
            _ => (String::new(), String::new(), String::new(), None, None),
        };
    // Resolve the LOGICAL prefix, not only the parent run's physical lines. At seq 0 of a nested
    // fork, the effective route may live in an ancestor prefix; filtering only `parent_lines`
    // silently lost its provider id. `expand(..., Some(at))` preserves that inherited state while
    // still excluding physical selections after the requested branch point.
    let mut ignored_ancestry = Vec::new();
    let logical_prefix = expand_scoped_from(
        runs_dir,
        parent,
        Some(at.0),
        0,
        &mut replay_budget,
        Some(parent_lines),
        &mut ignored_ancestry,
    )?;
    if environment.is_none() {
        environment = logical_prefix.iter().rev().find_map(|scoped| {
            if let EventKind::RunStart { environment, .. } = &scoped.event.kind {
                environment.clone()
            } else {
                None
            }
        });
    }
    let mut legacy_max_microusd: Option<u64> = None;
    for candidate in logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::RunStart {
                max_usd: Some(max_usd),
                ..
            } => Some(*max_usd),
            _ => None,
        })
    {
        if !candidate.is_finite() || candidate < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fork history contains an invalid max_usd ceiling",
            )
            .into());
        }
        let candidate = legacy_usd_to_microusd_floor(candidate);
        legacy_max_microusd =
            Some(legacy_max_microusd.map_or(candidate, |current| current.min(candidate)));
    }
    let mut exact_max_microusd: Option<u64> = None;
    for candidate in logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::UsdCeilingChanged { max_microusd, .. } => Some(*max_microusd),
            _ => None,
        })
    {
        exact_max_microusd =
            Some(exact_max_microusd.map_or(candidate, |current| current.min(candidate)));
    }
    // Once exact policy exists it is authoritative. The legacy f64 field is consulted only for
    // pre-policy journals and is reconstructed by flooring, never ceiling.
    let max_microusd = exact_max_microusd.or(legacy_max_microusd);
    let max_usd = max_microusd.map(|value| {
        value as f64
            / iteron_tunables::param_f64("record.session.microusd_per_usd", MICROUSD_PER_USD)
    });
    let inherited_policy =
        RuntimePolicyState::from_events(logical_prefix.iter().map(|scoped| &scoped.event));
    let inherited_selection = logical_prefix
        .iter()
        .filter_map(|scoped| match &scoped.event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            } => Some((
                provider_id.clone(),
                model_id.clone(),
                catalog_digest.clone(),
                capability_digest.clone(),
            )),
            _ => None,
        })
        .next_back();
    if let Some((_, model_id, _, _)) = &inherited_selection {
        model = model_id.clone();
    }

    let child = mint_run_id();
    let mut rollout = Rollout::open(runs_dir, &child, tenant.clone())?;
    let genesis = Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::RunStart {
            cwd,
            model,
            // A runtime transition after genesis is authoritative at the branch point. The
            // child's genesis snapshots that value so its physical journal is independently
            // projectable without consulting mutable live state.
            effort: inherited_policy.effort,
            created_at: now_secs(),
            environment,
            parent_run: Some(parent.0.clone()),
            forked_at: Some(at.0),
            parent_hash_at_seq: Some(pinned),
            config_digest,
            agent_definition_tag,
            max_usd,
        },
    };
    if let Some(snapshot) = parent_snapshot {
        let inherited = tunables::inherited_from(&parent.0, &snapshot);
        rollout.append_genesis_checkpoint(&genesis, snapshot, Some(inherited))?;
    } else {
        rollout.append(&genesis)?;
    }
    if let Some(snapshot) = parent_policy_snapshot {
        let inherited_from = Some(iteron_protocol::RunGenesisPolicyBundleInheritance {
            parent_run: parent.0.clone(),
            parent_receipt_digest_sha256: snapshot.receipt_digest_sha256.clone(),
        });
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::PolicyBundleSnapshot {
                version: iteron_protocol::RunGenesisPolicyBundleVersion::V1,
                snapshot,
                inherited_from,
            },
        })?;
    }
    if let Some(max_microusd) = max_microusd {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Fork,
                max_microusd,
            },
        })?;
    }
    if let Some(max_turns) = inherited_policy.turn_ceiling {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::TurnCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: RuntimePolicySource::Fork,
                max_turns,
            },
        })?;
    }
    rollout.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::EffortChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Fork,
            effort: inherited_policy.effort,
        },
    })?;
    rollout.append(&Event {
        seq: Seq::ZERO,
        turn: TurnId(0),
        kind: EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::Fork,
            mode: inherited_policy.permission_mode,
            rules: inherited_policy.permission_rules,
        },
    })?;
    if let Some((provider_id, model_id, catalog_digest, capability_digest)) = inherited_selection {
        rollout.append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            },
        })?;
    }
    Ok((child, compatibility))
}

/// Load a run's full logical event stream, following the reference-model fork (SESS-1). If the
/// genesis references a parent, the parent prefix (up to `forked_at`) is replayed first — VERIFYING
/// `parent_hash_at_seq` against the parent chain's actual hash at that seq and erroring with
/// [`RecordError::ForkParentMismatch`] if the parent prefix was altered (ADR-008 §4 tamper-evidence,
/// R5-review Risk 3) — then this chain's events are appended. A plain run returns its own events.
/// The kernel's `messages_from_rollout` will call this; it is exposed here, not wired.
pub fn load_forked(runs_dir: &Path, run: &RunId) -> Result<Vec<Event>, RecordError> {
    Ok(load_forked_scoped(runs_dir, run)?
        .into_iter()
        .map(|scoped| scoped.event)
        .collect())
}

/// Replay ONE run's own chain, keeping each line's segment offset (#102/#104).
///
/// Deliberately not fork-expanding. A parent prefix was written by a different process with a
/// different monotonic origin, so splicing it in would produce segments whose offsets cannot be
/// compared and a "wall time" that is the sum of two unrelated clocks. A timeline reports the run
/// it was asked about; the parent has its own.
pub fn replay_run_timed(runs_dir: &Path, run: &RunId) -> Result<Vec<TimedEvent>, RecordError> {
    crate::replay_timed(&rollout_path(runs_dir, run)?)
}

/// [`load_forked`] with the original tenant/run scope retained for every physical event.
pub fn load_forked_scoped(runs_dir: &Path, run: &RunId) -> Result<Vec<ScopedEvent>, RecordError> {
    crate::require_strict_replay_policy()?;
    let mut budget = LogicalReplayBudget::default();
    expand_scoped(runs_dir, run, None, 0, &mut budget)
}

pub(crate) fn bounded_scoped(
    runs: &Path,
    run: &RunId,
    limits: crate::bounded_replay::ReplayReadLimits,
) -> Result<Vec<ScopedEvent>, RecordError> {
    crate::require_strict_replay_policy()?;
    let mut budget = LogicalReplayBudget {
        projection: Some(limits.budget()?),
        ..Default::default()
    };
    expand_scoped(runs, run, None, 0, &mut budget)
}

pub(crate) fn bounded_physical_events(
    path: &Path,
    limits: crate::bounded_replay::ReplayReadLimits,
) -> Result<Vec<Event>, RecordError> {
    crate::require_strict_replay_policy()?;
    let mut budget = LogicalReplayBudget {
        projection: Some(limits.budget()?),
        ..Default::default()
    };
    let lines = read_chain_budgeted(path, &mut budget)?;
    crate::guard_replay_lineage(path, lines.first().map(|line| &line.tenant))?;
    Ok(lines
        .into_iter()
        .map(|line| {
            let mut event = line.event;
            event.seq = line.seq;
            event
        })
        .collect())
}

#[derive(Default)]
pub(super) struct LogicalReplayBudget {
    projection: Option<crate::bounded_replay::ReplayReadBudget>,
    bytes: u64,
    events: usize,
    physical_lines: usize,
    expanded_runs: HashSet<RunId>,
}

impl LogicalReplayBudget {
    pub(super) fn bounded(
        limits: crate::bounded_replay::ReplayReadLimits,
    ) -> Result<Self, RecordError> {
        Ok(Self {
            projection: Some(limits.budget()?),
            ..Default::default()
        })
    }
    fn ensure_can_expand(&self, run: &RunId) -> Result<(), RecordError> {
        if self.expanded_runs.contains(run) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cyclic fork chain repeats run {run}"),
            )
            .into());
        }
        Ok(())
    }

    fn begin_expand(&mut self, run: &RunId) -> Result<(), RecordError> {
        self.ensure_can_expand(run)?;
        if !self.expanded_runs.insert(run.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cyclic fork chain repeats run {run}"),
            )
            .into());
        }
        Ok(())
    }
}

pub(super) fn admit_logical_events(total: &mut usize, events: usize) -> Result<(), RecordError> {
    *total = total.saturating_add(events);
    if *total > crate::MAX_ROLLOUT_EVENTS {
        return Err(RecordError::TooManyEvents {
            max: crate::MAX_ROLLOUT_EVENTS,
        });
    }
    Ok(())
}

/// Recursively materialize `run`'s event stream, bounded to seq `<= upto` when set. Recurses into a
/// parent so a fork of a fork (a rewound-then-rewound session) resolves; `depth` guards against a
/// pathological/cyclic parent pointer in a hand-crafted record.
fn expand_scoped(
    runs_dir: &Path,
    run: &RunId,
    upto: Option<u64>,
    depth: usize,
    budget: &mut LogicalReplayBudget,
) -> Result<Vec<ScopedEvent>, RecordError> {
    let mut ignored_ancestry = Vec::new();
    expand_scoped_from(
        runs_dir,
        run,
        upto,
        depth,
        budget,
        None,
        &mut ignored_ancestry,
    )
}

pub(super) fn expand_scoped_from(
    runs_dir: &Path,
    run: &RunId,
    upto: Option<u64>,
    depth: usize,
    budget: &mut LogicalReplayBudget,
    preloaded: Option<Vec<ReadLine>>,
    ancestry: &mut Vec<SessionAncestryReceipt>,
) -> Result<Vec<ScopedEvent>, RecordError> {
    if depth > iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fork chain for {run} exceeds max depth {MAX_FORK_DEPTH} (cyclic parent?)"),
        )
        .into());
    }

    let path = rollout_path(runs_dir, run)?;
    budget.begin_expand(run)?;
    let lines = match preloaded {
        Some(lines) => lines,
        None => read_chain_budgeted(&path, budget)?,
    };
    let mut events = Vec::new();

    if let Some(EventKind::RunStart {
        parent_run: Some(pr),
        forked_at: Some(fa),
        parent_hash_at_seq: Some(ph),
        ..
    }) = lines.first().map(|l| &l.event.kind)
    {
        let parent = RunId(pr.clone());
        if depth >= iteron_tunables::param_integer("record.session.max_fork_depth", MAX_FORK_DEPTH)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("fork chain for {run} exceeds max depth {MAX_FORK_DEPTH} (cyclic parent?)"),
            )
            .into());
        }
        budget.ensure_can_expand(&parent)?;
        let parent_path = rollout_path(runs_dir, &parent)?;
        // Verify the cross-link BEFORE trusting the parent prefix: the parent chain's actual hash
        // at the fork seq must equal the pinned value, or the parent prefix was tampered.
        let parent_lines = read_chain_budgeted(&parent_path, budget)?;
        if let (Some(child_first), Some(parent_first)) = (lines.first(), parent_lines.first()) {
            ensure_tenant(
                &child_first.tenant,
                &parent_first.tenant.0,
                parent_first.seq.0,
            )?;
        }
        validate_fork_tunables_inheritance(&lines, &parent, &parent_lines)?;
        validate_fork_policy_bundle_inheritance(&lines, &parent, &parent_lines)?;
        let pinned_line = parent_lines
            .iter()
            .find(|l| l.seq.0 == *fa)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parent {parent} has no seq {fa} for fork of {run}"),
                )
            })?;
        if &pinned_line.hash != ph {
            return Err(RecordError::ForkParentMismatch {
                parent: parent.0.clone(),
                forked_at: *fa,
                pinned: ph.clone(),
                actual: pinned_line.hash.clone(),
            });
        }
        let observed_tail = parent_lines
            .last()
            .expect("a verified pinned parent line implies a non-empty parent chain");
        let observed_mtime = file_mtime(&parent_path).unwrap_or_default();
        let receipt = SessionAncestryReceipt {
            run_id: parent.clone(),
            tenant: pinned_line.tenant.clone(),
            through_seq: *fa,
            prefix_bytes: pinned_line.end_bytes,
            tail_hash: pinned_line.hash.clone(),
            observed_record_bytes: observed_tail.end_bytes,
            observed_tail_seq: observed_tail.seq.0,
            observed_tail_hash: observed_tail.hash.clone(),
            observed_updated_at: observed_mtime.0,
            observed_updated_at_subsec_nanos: observed_mtime.1,
        };
        events.extend(expand_scoped_from(
            runs_dir,
            &parent,
            Some(*fa),
            depth + 1,
            budget,
            Some(parent_lines),
            ancestry,
        )?);
        ancestry.push(receipt);
    }

    for l in &lines {
        if upto
            .map(|u| l.seq.0 <= u)
            .unwrap_or(iteron_tunables::param_bool(
                "record.session.unbounded_scope_admits_line",
                UNBOUNDED_SCOPE_ADMITS_LINE,
            ))
        {
            events.push(ScopedEvent {
                event: l.event.clone(),
                tenant: l.tenant.clone(),
                run_id: run.clone(),
            });
        }
    }
    Ok(events)
}

fn genesis_tunables_event(
    lines: &[ReadLine],
) -> Option<(
    tunables::TunablesCheckpoint,
    Option<&iteron_protocol::RunGenesisTunablesInheritance>,
)> {
    match lines.get(1).map(|line| &line.event.kind) {
        Some(EventKind::TunablesSnapshot {
            snapshot,
            inherited_from,
            ..
        }) => Some((
            tunables::TunablesCheckpoint::V1(snapshot.clone()),
            inherited_from.as_ref(),
        )),
        Some(EventKind::TunablesSnapshotV2 {
            snapshot,
            inherited_from,
            ..
        }) => Some((
            tunables::TunablesCheckpoint::V2(snapshot.clone()),
            inherited_from.as_ref(),
        )),
        _ => None,
    }
}

fn genesis_policy_bundle_event(
    lines: &[ReadLine],
) -> Option<(
    iteron_protocol::RunGenesisPolicyBundleSnapshot,
    Option<&iteron_protocol::RunGenesisPolicyBundleInheritance>,
)> {
    match lines.get(2).map(|line| &line.event.kind) {
        Some(EventKind::PolicyBundleSnapshot {
            snapshot,
            inherited_from,
            ..
        }) => Some((snapshot.clone(), inherited_from.as_ref())),
        _ => None,
    }
}

fn checked_genesis_tunables(
    lines: &[ReadLine],
) -> Result<Option<tunables::TunablesCheckpoint>, RecordError> {
    let mut state = tunables::GenesisTunablesState::default();
    for line in lines {
        state.observe(line.seq.0, &line.event.kind)?;
    }
    Ok(state.finish()?.cloned())
}

/// Cross-check a fork's copied snapshot against the direct parent's actual, unique seq-1
/// snapshot. The ordinary parent hash pins only through `forked_at`; for a seq-0 fork that prefix
/// deliberately excludes seq 1, so this independent binding must be revalidated on every logical
/// load. Recursion applies the same check at every edge in a nested fork chain.
fn validate_fork_tunables_inheritance(
    child_lines: &[ReadLine],
    parent: &RunId,
    parent_lines: &[ReadLine],
) -> Result<(), RecordError> {
    match (
        genesis_tunables_event(child_lines),
        genesis_tunables_event(parent_lines),
    ) {
        (None, None) => Ok(()),
        (Some((child_snapshot, Some(binding))), Some((parent_snapshot, _)))
            if binding.parent_run == parent.0
                && binding.parent_snapshot_digest_sha256
                    == parent_snapshot.snapshot_digest_sha256()
                && child_snapshot == parent_snapshot =>
        {
            Ok(())
        }
        _ => Err(tunables::TunablesSnapshotError::GenesisOrder {
            reason: "fork tunables inheritance does not match the actual parent seq-1 snapshot",
        }
        .into()),
    }
}

fn validate_fork_policy_bundle_inheritance(
    child_lines: &[ReadLine],
    parent: &RunId,
    parent_lines: &[ReadLine],
) -> Result<(), RecordError> {
    match (
        genesis_policy_bundle_event(child_lines),
        genesis_policy_bundle_event(parent_lines),
    ) {
        (None, None) => Ok(()),
        (Some((child_snapshot, Some(binding))), Some((parent_snapshot, _)))
            if binding.parent_run == parent.0
                && binding.parent_receipt_digest_sha256
                    == parent_snapshot.receipt_digest_sha256
                && child_snapshot == parent_snapshot =>
        {
            Ok(())
        }
        _ => Err(
            crate::policy_bundle::PolicyBundleCheckpointError::GenesisOrder(
                "fork policy checkpoint inheritance does not match the parent genesis receipt",
            )
            .into(),
        ),
    }
}
