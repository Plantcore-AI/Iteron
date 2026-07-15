//! Session management as a projection of the rollout (SESS-1/SESS-4, R5 design §2).
//!
//! A session is not a second source of truth: it is a *projection* of its per-run rollout
//! (ADR-006). Every field of [`SessionMeta`] is derivable by replaying the record — `title`
//! from the first user message, `turns`/`cache_hit`/`last_outcome` from recorded events,
//! and `cwd`/initial model/`effort`/`created_at`/`parent` from the seq-0
//! [`EventKind::RunStart`] genesis header. Later [`EventKind::ModelSelected`] events update the
//! provider/model projection. The `.meta.json` per-run file and the `sessions.index` append log are a
//! rebuildable cache in front of that replay (R5 design §2.4): a missing or stale cache is
//! never an error, it degrades to a replay.
//!
//! Fork is a record operation, not an in-place edit. The rollout is append-only and
//! hash-chained (ADR-008), so a single log cannot branch in place. A fork is therefore a new
//! `RunId` whose genesis records the branch point by *reference* (SESS-1/SESS-5): the child
//! stores only its new events and, on load, replays the parent prefix up to the fork seq. To
//! make that reference tamper-evident (ADR-008 §4, R5-review Risk 3), the genesis pins
//! `parent_hash_at_seq` — the parent chain's hash at the fork point — so a child replay
//! detects an altered parent prefix rather than trusting it. Unknown event kinds are tolerated
//! on replay via `EventKind::Unknown` (R5-review Risk 6), so a cross-version scan does not fail.

use crate::{RecordError, Rollout, ensure_tenant, validated_run_path};
use core_obs::{CostState, Ledger};
use core_protocol::{
    Block, Effort, Event, EventKind, Message, Outcome, Role, RunId, RuntimePolicyEventVersion,
    RuntimePolicySource, RuntimePolicyState, Seq, TenantId, TurnId, Usage,
};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The branch point of a fork/rewind child. `parent_hash_at_seq` cross-links the child to the
/// parent chain's hash at `forked_at` so an altered parent prefix is detectable on replay
/// (ADR-008 §4 tamper-evidence, R5-review Risk 3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub parent_run: RunId,
    pub forked_at: Seq,
    pub parent_hash_at_seq: String,
}

/// A session is a PROJECTION of its rollout, never a second source of truth (ADR-006). Populated
/// either from the meta cache (kernel-written, authoritative for cost) or by replaying the record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionMeta {
    /// Projection schema for monetary truth. Legacy caches used a global placeholder price and
    /// are always rebuilt from the rollout rather than trusted.
    #[serde(default)]
    pub pricing_schema_version: u32,
    /// Projection schema independent of pricing. V1 includes additive child-workflow attribution;
    /// legacy caches are replayed so a resume/list cannot silently drop subagent spend.
    #[serde(default)]
    pub projection_schema_version: u32,
    pub run_id: RunId,
    pub tenant: TenantId,
    pub cwd: PathBuf,
    /// Provider instance used by the latest recorded selection. Empty for legacy rollouts.
    #[serde(default)]
    pub provider_id: String,
    pub model: String,
    pub effort: Effort,
    /// Deterministic: the first user message's first line, truncated (SESS-3).
    pub title: String,
    /// Recorded once at run start (from the genesis header), not read at list time (ADR-006 rule 1).
    pub created_at: u64,
    /// Last-touched time. Authoritative when cached (kernel-written); on a replay it degrades to
    /// the rollout file's mtime, since the record carries no per-event wall clock.
    pub updated_at: u64,
    /// Physical rollout length covered by this rebuildable projection cache. Older cache files
    /// deserialize with zero and are replayed. An append-only `ModelSelected` increases the
    /// rollout length, invalidating stale provider/model projections without scanning the log.
    #[serde(default)]
    pub record_bytes: u64,
    pub turns: u32,
    /// Evidence-backed monetary state. Current rollouts have usage but no pinned rate card, so a
    /// completed provider turn is honestly unknown rather than a placeholder dollar amount.
    #[serde(default)]
    pub cost: CostState,
    pub cache_hit: f64,
    /// Serialized via [`outcome_opt`] (as a string), because `Outcome::BudgetExhausted` holds a
    /// `&'static str` and so cannot itself be `Deserialize`d into an owned value.
    #[serde(with = "outcome_opt")]
    pub last_outcome: Option<Outcome>,
    /// `Some(_)` iff this run is a fork/rewind child.
    pub parent: Option<Provenance>,
}

impl SessionMeta {
    pub fn cost_usd(&self) -> Option<f64> {
        self.cost.usd()
    }
}

/// Serde adapter for `Option<Outcome>`: writes the `Debug` label as a string and reads it back
/// through [`parse_outcome`]. This sidesteps deriving `Deserialize` for `Outcome` (its
/// `BudgetExhausted(&'static str)` variant would force a `'de: 'static` bound on `SessionMeta`).
mod outcome_opt {
    use super::{Outcome, parse_outcome};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Outcome>, s: S) -> Result<S::Ok, S::Error> {
        let as_str: Option<String> = v.as_ref().map(|o| format!("{o:?}"));
        as_str.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Outcome>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        Ok(opt.as_deref().and_then(parse_outcome))
    }
}

// ---------------------------------------------------------------------------------------------
// Paths. The rollout, its per-run meta cache, and the append index all live under `runs_dir`
// (in practice `.core/runs`). Co-locating the index there keeps the module dependent on the
// single directory it is handed, and the `.jsonl` listing scan naturally ignores the `.meta.json`
// and `.index` sidecars (different extensions), so they are never mistaken for rollouts.
// ---------------------------------------------------------------------------------------------

fn rollout_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".jsonl")
}

fn per_run_meta_path(runs_dir: &Path, run: &RunId) -> Result<PathBuf, RecordError> {
    validated_run_path(runs_dir, run, ".meta.json")
}

fn index_path(runs_dir: &Path) -> PathBuf {
    runs_dir.join("sessions.index")
}

/// A verified rollout line: the chain metadata plus the parsed event. The workhorse behind every
/// projection below; it re-verifies the hash chain exactly as `replay` does (a broken chain is an
/// error, not a warning) and additionally surfaces the per-line `tenant` and `hash` that `replay`
/// discards but the session projection and the fork cross-link need.
struct ReadLine {
    seq: Seq,
    tenant: TenantId,
    hash: String,
    event: Event,
}

fn read_chain(path: &Path) -> Result<Vec<ReadLine>, RecordError> {
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut prev = crate::ZERO_HASH.to_string();
    let mut tenant: Option<TenantId> = None;
    // Tolerate a torn trailing line from a crash mid-append (code review): the resume path routes
    // through here, so a strict read would make a crashed run unresumable — exactly the tolerance
    // scan_tail already gives the append path. A partial FINAL line (no trailing newline) is dropped.
    let mut lines: Vec<&str> = content.lines().collect();
    if !content.is_empty() && !content.ends_with('\n') {
        lines.pop();
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cl: crate::ChainLine = serde_json::from_str(line)?;
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
        // Unknown event kinds deserialize to `EventKind::Unknown` (R5-review Risk 6), so a newer
        // writer's kinds do not fail the scan.
        let event: Event = serde_json::from_value(cl.payload)?;
        prev = cl.hash.clone();
        out.push(ReadLine {
            seq: Seq(cl.seq),
            tenant: TenantId(cl.tenant),
            hash: cl.hash,
            event,
        });
    }
    Ok(out)
}

/// The run ids of every rollout file in `runs_dir` (the ground truth of which runs exist).
fn rollout_run_ids(runs_dir: &Path) -> Vec<RunId> {
    let mut ids = Vec::new();
    let Ok(rd) = std::fs::read_dir(runs_dir) else {
        return ids;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
            continue;
        }
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            ids.push(RunId(stem.to_string()));
        }
    }
    ids
}

fn file_mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn file_len(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|metadata| metadata.len())
}

fn projection_covers_rollout(runs_dir: &Path, meta: &SessionMeta) -> bool {
    let Ok(path) = rollout_path(runs_dir, &meta.run_id) else {
        return false;
    };
    meta.pricing_schema_version == 1
        && meta.projection_schema_version == 1
        && meta.record_bytes > 0
        && file_len(&path) == Some(meta.record_bytes)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Deterministic title: the first user message's first non-empty line, char-truncated (SESS-3).
fn title_from_message(m: &Message) -> String {
    let text = m
        .content
        .iter()
        .find_map(|b| match b {
            Block::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("");
    let first_line = text.lines().next().unwrap_or("").trim();
    const MAX: usize = 72;
    if first_line.chars().count() <= MAX {
        first_line.to_string()
    } else {
        let mut t: String = first_line.chars().take(MAX).collect();
        t.push('…');
        t
    }
}

/// Map the kernel's recorded `Done{outcome}` (a `format!("{outcome:?}")` Debug string) back to an
/// [`Outcome`]. The `BudgetExhausted` reason is a `&'static str`, so a replay maps to the known
/// reason literal; an unrecognized string yields `None` (a projection convenience, not the record).
fn parse_outcome(s: &str) -> Option<Outcome> {
    let s = s.trim();
    match s {
        "Done" => Some(Outcome::Done),
        "Interrupted" => Some(Outcome::Interrupted),
        "Stuck" => Some(Outcome::Stuck),
        "HarnessError" => Some(Outcome::HarnessError),
        _ if s.starts_with("BudgetExhausted") => {
            let reason = if s.contains("max_turns") {
                "max_turns"
            } else if s.contains("max_usd") {
                "max_usd"
            } else if s.contains("max_wall_secs") {
                "max_wall_secs"
            } else if s.contains("max_consecutive_tool_errors") {
                "max_consecutive_tool_errors"
            } else {
                "budget"
            };
            Some(Outcome::BudgetExhausted(reason))
        }
        _ => None,
    }
}

/// Build a [`SessionMeta`] by replaying the run's record (the degrade path, and the truth `reindex`
/// rebuilds the cache from). Never re-reads disk state that belongs in the record: `created_at`
/// comes from the genesis header, not the clock.
fn meta_from_replay(runs_dir: &Path, run: &RunId) -> Result<SessionMeta, RecordError> {
    let path = rollout_path(runs_dir, run)?;
    let lines = read_chain(&path)?;

    let mut tenant = TenantId::default();
    let mut cwd = PathBuf::new();
    let mut provider_id = String::new();
    let mut model = String::new();
    let mut effort = Effort::default();
    let mut created_at = 0u64;
    let mut parent: Option<Provenance> = None;

    if let Some(g) = lines.first() {
        tenant = g.tenant.clone();
        if let EventKind::RunStart {
            cwd: c,
            model: m,
            effort: ef,
            created_at: ca,
            parent_run,
            forked_at,
            parent_hash_at_seq,
            ..
        } = &g.event.kind
        {
            cwd = PathBuf::from(c);
            model = m.clone();
            effort = *ef;
            created_at = *ca;
            if let (Some(pr), Some(fa), Some(ph)) =
                (parent_run.clone(), forked_at, parent_hash_at_seq.clone())
            {
                parent = Some(Provenance {
                    parent_run: RunId(pr),
                    forked_at: Seq(*fa),
                    parent_hash_at_seq: ph,
                });
            }
        }
    }

    let mut turns = 0u32;
    let mut usage = Usage::default();
    let mut cost_ledger = Ledger::new();
    let mut spawned_subagents = HashSet::new();
    let mut terminal_subagents = HashSet::new();
    let mut title = String::new();
    let mut last_outcome = None;
    for l in &lines {
        match &l.event.kind {
            EventKind::TurnStart => {
                turns += 1;
                cost_ledger.attempt();
            }
            EventKind::TurnEnd { usage: u } => {
                usage.add(u);
                cost_ledger.turn(u, 0);
            }
            EventKind::SubagentSpawned { sub_run, .. } => {
                spawned_subagents.insert(sub_run.clone());
            }
            EventKind::SubagentFinished {
                sub_run, metrics, ..
            } => {
                turns = turns.saturating_add(metrics.provider_attempts);
                usage.add(&metrics.usage);
                cost_ledger.merge_workflow_metrics(metrics);
                terminal_subagents.insert(sub_run.clone());
            }
            EventKind::Workflow {
                event:
                    core_protocol::WorkflowEvent::ChildFinished {
                        sub_run, metrics, ..
                    },
                ..
            } => {
                turns = turns.saturating_add(metrics.provider_attempts);
                usage.add(&metrics.usage);
                cost_ledger.merge_workflow_metrics(metrics);
                if let Some(sub_run) = sub_run {
                    terminal_subagents.insert(sub_run.clone());
                }
            }
            EventKind::ModelSelected {
                provider_id: selected_provider,
                model_id,
                ..
            } => {
                provider_id = selected_provider.clone();
                model = model_id.clone();
            }
            EventKind::EffortChanged { effort: next, .. } => effort = *next,
            EventKind::Message { message } if title.is_empty() && message.role == Role::User => {
                title = title_from_message(message);
            }
            EventKind::Done { outcome } => last_outcome = parse_outcome(outcome),
            _ => {}
        }
    }

    let updated_at = file_mtime_secs(&path).unwrap_or(created_at);
    let record_bytes = file_len(&path).unwrap_or(0);
    let title = if title.is_empty() {
        "(untitled)".to_string()
    } else {
        title
    };

    let cost = if spawned_subagents
        .iter()
        .any(|sub_run| !terminal_subagents.contains(sub_run))
    {
        CostState::Unknown {
            reason: core_obs::CostUnknownReason::LegacyUnattributed,
        }
    } else {
        cost_ledger.cost_state()
    };

    Ok(SessionMeta {
        pricing_schema_version: 1,
        projection_schema_version: 1,
        run_id: run.clone(),
        tenant,
        cwd,
        provider_id,
        model,
        effort,
        title,
        created_at,
        updated_at,
        record_bytes,
        turns,
        cost,
        cache_hit: usage.cache_hit_ratio(),
        last_outcome,
        parent,
    })
}

fn read_index(runs_dir: &Path) -> Vec<SessionMeta> {
    let Ok(txt) = std::fs::read_to_string(index_path(runs_dir)) else {
        return Vec::new();
    };
    txt.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<SessionMeta>(l).ok())
        .collect()
}

/// The metadata for one run: the per-run cache if present and parseable, else a replay of the
/// record (R5 design §2.5). A missing or corrupt cache is never fatal — it degrades to the record.
pub fn meta(runs_dir: &Path, run: &RunId) -> Result<SessionMeta, RecordError> {
    let cache = per_run_meta_path(runs_dir, run)?;
    if let Ok(txt) = std::fs::read_to_string(&cache)
        && let Ok(m) = serde_json::from_str::<SessionMeta>(&txt)
        && m.run_id == *run
        && projection_covers_rollout(runs_dir, &m)
    {
        return Ok(m);
    }
    meta_from_replay(runs_dir, run)
}

/// List the sessions in `runs_dir` for `tenant`, newest first (R5 design §2.5). Listing is
/// O(runs), not O(bytes): the append index provides each run's meta in one file read, and only a
/// rollout not covered by the index degrades to a per-run cache read or a replay. Never errors — a
/// run whose record cannot be projected is skipped, matching the existing degrade-to-scan posture.
pub fn list(runs_dir: &Path, tenant: &TenantId) -> Vec<SessionMeta> {
    let existing: HashSet<String> = rollout_run_ids(runs_dir).into_iter().map(|r| r.0).collect();

    let mut by_run: HashMap<String, SessionMeta> = HashMap::new();
    // Fast path: the append index, last write wins. Entries whose rollout was deleted are dropped.
    for m in read_index(runs_dir) {
        if existing.contains(&m.run_id.0) && projection_covers_rollout(runs_dir, &m) {
            by_run.insert(m.run_id.0.clone(), m);
        }
    }
    // Degrade: any rollout the index does not cover is projected from its per-run cache or record.
    for run in &existing {
        if !by_run.contains_key(run)
            && let Ok(m) = meta(runs_dir, &RunId(run.clone()))
        {
            by_run.insert(run.clone(), m);
        }
    }

    let mut metas: Vec<SessionMeta> = by_run
        .into_values()
        .filter(|m| &m.tenant == tenant)
        .collect();
    // Newest first; ties broken by run id for a stable, reproducible order (ADR-006 rule 4).
    metas.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.run_id.0.cmp(&a.run_id.0))
    });
    metas
}

/// The most recent run in `cwd` for `tenant` — the target of `--continue` (R5 design §2.5). Scoped
/// to `cwd` because the prefix cache is per-repo, so a cross-worktree continue would cache-miss.
pub fn most_recent(runs_dir: &Path, cwd: &Path, tenant: &TenantId) -> Option<RunId> {
    list(runs_dir, tenant)
        .into_iter()
        .find(|m| m.cwd == cwd)
        .map(|m| m.run_id)
}

/// Persist a run's projected metadata (the kernel calls this at each turn boundary). Writes the
/// authoritative per-run `.meta.json` (atomically, via a temp file and rename) and appends a line
/// to the `sessions.index` fast path. The record remains the truth; this cache is rebuildable.
pub fn write_meta(runs_dir: &Path, meta: &SessionMeta) -> Result<(), RecordError> {
    let path = per_run_meta_path(runs_dir, &meta.run_id)?;
    std::fs::create_dir_all(runs_dir)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(meta)?)?;
    std::fs::rename(&tmp, &path)?;

    let mut line = serde_json::to_string(meta)?;
    line.push('\n');
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(index_path(runs_dir))?
        .write_all(line.as_bytes())?;
    Ok(())
}

/// Rebuild the cache from the records (R5 design §2.4): replay every rollout, rewrite each per-run
/// `.meta.json`, and rewrite `sessions.index` from scratch. Truth is the record, so this is always
/// safe to run. A corrupt/broken rollout is skipped rather than aborting the whole rebuild; returns
/// the number of runs indexed.
pub fn reindex(runs_dir: &Path) -> Result<usize, RecordError> {
    let mut metas = Vec::new();
    for run in rollout_run_ids(runs_dir) {
        if let Ok(m) = meta_from_replay(runs_dir, &run) {
            metas.push(m);
        }
    }
    for m in &metas {
        if let Ok(path) = per_run_meta_path(runs_dir, &m.run_id) {
            let _ = std::fs::write(path, serde_json::to_vec_pretty(m)?);
        }
    }
    let mut buf = String::new();
    for m in &metas {
        buf.push_str(&serde_json::to_string(m)?);
        buf.push('\n');
    }
    std::fs::write(index_path(runs_dir), buf)?;
    Ok(metas.len())
}

/// Mint a fresh, collision-resistant run id (process id + wall-clock nanos), matching the CLI's
/// scheme. The clock crosses the nondeterminism boundary once, only to name the run.
fn mint_run_id() -> RunId {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    RunId(format!("run-{}-{}", std::process::id(), nanos))
}

/// Fork `parent` at seq `at` into a fresh run (SESS-1, the reference model). Mints a new `RunId`,
/// opens its chain, and writes a genesis [`EventKind::RunStart`] plus the effective
/// [`EventKind::ModelSelected`] snapshot when one exists — no parent-prefix bytes are copied. The
/// genesis pins `parent_hash_at_seq` (the parent chain's hash at `at`) so the reference is
/// tamper-evident on load (ADR-008 §4, R5-review Risk 3). The child inherits the parent's session
/// config (cwd/model/effort/config_digest), exact route at the branch point, and the given `tenant`.
pub fn fork(
    runs_dir: &Path,
    parent: &RunId,
    at: Seq,
    tenant: &TenantId,
) -> Result<RunId, RecordError> {
    let parent_path = rollout_path(runs_dir, parent)?;
    // Read + verify the parent chain, pin its hash at the fork point, and read its genesis config.
    let parent_lines = read_chain(&parent_path)?;
    if let Some(first) = parent_lines.first() {
        ensure_tenant(tenant, &first.tenant.0, first.seq.0)?;
    }
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

    let (cwd, mut model, config_digest) = match parent_lines.first().map(|l| &l.event.kind) {
        Some(EventKind::RunStart {
            cwd,
            model,
            config_digest,
            ..
        }) => (cwd.clone(), model.clone(), config_digest.clone()),
        _ => (String::new(), String::new(), String::new()),
    };
    // Resolve the LOGICAL prefix, not only the parent run's physical lines. At seq 0 of a nested
    // fork, the effective route may live in an ancestor prefix; filtering only `parent_lines`
    // silently lost its provider id. `expand(..., Some(at))` preserves that inherited state while
    // still excluding physical selections after the requested branch point.
    let logical_prefix = expand(runs_dir, parent, Some(at.0), 0)?;
    let inherited_policy = RuntimePolicyState::from_events(&logical_prefix);
    let inherited_selection = logical_prefix
        .iter()
        .filter_map(|event| match &event.kind {
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
            parent_run: Some(parent.0.clone()),
            forked_at: Some(at.0),
            parent_hash_at_seq: Some(pinned),
            config_digest,
        },
    };
    rollout.append(&genesis)?;
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
    Ok(child)
}

const MAX_FORK_DEPTH: usize = 256;

/// Load a run's full logical event stream, following the reference-model fork (SESS-1). If the
/// genesis references a parent, the parent prefix (up to `forked_at`) is replayed first — VERIFYING
/// `parent_hash_at_seq` against the parent chain's actual hash at that seq and erroring with
/// [`RecordError::ForkParentMismatch`] if the parent prefix was altered (ADR-008 §4 tamper-evidence,
/// R5-review Risk 3) — then this chain's events are appended. A plain run returns its own events.
/// The kernel's `messages_from_rollout` will call this; it is exposed here, not wired.
pub fn load_forked(runs_dir: &Path, run: &RunId) -> Result<Vec<Event>, RecordError> {
    expand(runs_dir, run, None, 0)
}

/// Recursively materialize `run`'s event stream, bounded to seq `<= upto` when set. Recurses into a
/// parent so a fork of a fork (a rewound-then-rewound session) resolves; `depth` guards against a
/// pathological/cyclic parent pointer in a hand-crafted record.
fn expand(
    runs_dir: &Path,
    run: &RunId,
    upto: Option<u64>,
    depth: usize,
) -> Result<Vec<Event>, RecordError> {
    if depth > MAX_FORK_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fork chain for {run} exceeds max depth {MAX_FORK_DEPTH} (cyclic parent?)"),
        )
        .into());
    }

    let lines = read_chain(&rollout_path(runs_dir, run)?)?;
    let mut events = Vec::new();

    if let Some(EventKind::RunStart {
        parent_run: Some(pr),
        forked_at: Some(fa),
        parent_hash_at_seq: Some(ph),
        ..
    }) = lines.first().map(|l| &l.event.kind)
    {
        let parent = RunId(pr.clone());
        // Verify the cross-link BEFORE trusting the parent prefix: the parent chain's actual hash
        // at the fork seq must equal the pinned value, or the parent prefix was tampered.
        let parent_lines = read_chain(&rollout_path(runs_dir, &parent)?)?;
        if let (Some(child_first), Some(parent_first)) = (lines.first(), parent_lines.first()) {
            ensure_tenant(
                &child_first.tenant,
                &parent_first.tenant.0,
                parent_first.seq.0,
            )?;
        }
        let actual = parent_lines
            .iter()
            .find(|l| l.seq.0 == *fa)
            .map(|l| l.hash.clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("parent {parent} has no seq {fa} for fork of {run}"),
                )
            })?;
        if &actual != ph {
            return Err(RecordError::ForkParentMismatch {
                parent: parent.0.clone(),
                forked_at: *fa,
                pinned: ph.clone(),
                actual,
            });
        }
        events.extend(expand(runs_dir, &parent, Some(*fa), depth + 1)?);
    }

    for l in &lines {
        if upto.map(|u| l.seq.0 <= u).unwrap_or(true) {
            events.push(l.event.clone());
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::{Capability, PermissionMode, PermissionRules, Verdict};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "core-sess-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn genesis_event(cwd: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::RunStart {
                cwd: cwd.into(),
                model: "claude".into(),
                effort: Effort::Medium,
                created_at: 1000,
                parent_run: None,
                forked_at: None,
                parent_hash_at_seq: None,
                config_digest: "cfg".into(),
            },
        }
    }

    /// A run with a genesis header, one turn, one user message, usage, and a Done outcome.
    fn mk_run(runs_dir: &Path, run: &RunId, tenant: &TenantId, cwd: &str, task: &str) {
        let mut r = Rollout::open(runs_dir, run, tenant.clone()).unwrap();
        r.append(&genesis_event(cwd)).unwrap();
        r.append(&Event {
            seq: Seq(1),
            turn: TurnId(0),
            kind: EventKind::TurnStart,
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(2),
            turn: TurnId(0),
            kind: EventKind::Message {
                message: Message::user_text(task),
            },
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(3),
            turn: TurnId(0),
            kind: EventKind::TurnEnd {
                usage: Usage {
                    input: 100,
                    output: 10,
                    cache_creation: 0,
                    cache_read: 900,
                    thinking: 0,
                },
            },
        })
        .unwrap();
        r.append(&Event {
            seq: Seq(4),
            turn: TurnId(0),
            kind: EventKind::Done {
                outcome: "Done".into(),
            },
        })
        .unwrap();
    }

    fn user_texts(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::Message { message } if message.role == Role::User => {
                    message.content.iter().find_map(|b| match b {
                        Block::Text { text } => Some(text.clone()),
                        _ => None,
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn selection_event(provider_id: &str, model_id: &str) -> Event {
        Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind: EventKind::ModelSelected {
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                catalog_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                capability_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            },
        }
    }

    fn latest_selection(events: &[Event]) -> Option<(String, String)> {
        events.iter().rev().find_map(|event| match &event.kind {
            EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => Some((provider_id.clone(), model_id.clone())),
            _ => None,
        })
    }

    #[test]
    fn meta_projects_the_record() {
        let dir = tmpdir("meta");
        let t = TenantId::default();
        let run = RunId("s1".into());
        mk_run(&dir, &run, &t, "/repo/a", "Fix the parser bug\nmore detail");
        let m = meta(&dir, &run).unwrap();
        assert_eq!(m.run_id, run);
        assert_eq!(m.cwd, PathBuf::from("/repo/a"));
        assert_eq!(m.model, "claude");
        assert_eq!(m.effort, Effort::Medium);
        assert_eq!(m.title, "Fix the parser bug"); // first line only, deterministic
        assert_eq!(m.created_at, 1000);
        assert_eq!(m.turns, 1);
        assert!((m.cache_hit - 0.9).abs() < 1e-9);
        assert_eq!(m.pricing_schema_version, 1);
        assert_eq!(m.projection_schema_version, 1);
        assert_eq!(
            m.cost,
            CostState::Unknown {
                reason: core_obs::CostUnknownReason::NoVerifiedRateCard
            },
            "replay must not apply one placeholder price across an unattributed route"
        );
        assert_eq!(m.last_outcome, Some(Outcome::Done));
        assert!(m.parent.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn workflow_child_terminal_restores_session_usage_and_attempts() {
        let dir = tmpdir("workflow-attribution");
        let tenant = TenantId::default();
        let run = RunId("workflow-attribution".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit modules");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentSpawned {
                    sub_run: "fan-0".into(),
                    agent: "investigator".into(),
                },
            })
            .unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::Workflow {
                    version: core_protocol::WorkflowEventVersion::V1,
                    workflow_id: "workflow-1".into(),
                    event: core_protocol::WorkflowEvent::ChildFinished {
                        task_id: 0,
                        sub_run: Some("fan-0".into()),
                        outcome: core_protocol::WorkflowChildOutcome::Done,
                        metrics: core_protocol::WorkflowMetrics {
                            provider_attempts: 3,
                            completed_turns: 2,
                            usage: Usage {
                                input: 50,
                                output: 5,
                                cache_creation: 0,
                                cache_read: 50,
                                thinking: 0,
                            },
                            tool_calls: 4,
                            tool_errors: 0,
                            model_ms: 10,
                            tools_ms: 20,
                        },
                        error_code: None,
                        error_detail: None,
                        summary_digest: Some("a".repeat(64)),
                        evidence_bytes: 100,
                    },
                },
            })
            .unwrap();
        drop(rollout);

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.turns, 4, "1 parent + 3 child attempts");
        assert!((projected.cache_hit - (950.0 / 1100.0)).abs() < 1e-9);
        assert_ne!(
            projected.cost,
            CostState::Unknown {
                reason: core_obs::CostUnknownReason::LegacyUnattributed
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spawned_child_without_terminal_is_legacy_unattributed() {
        let dir = tmpdir("workflow-incomplete");
        let tenant = TenantId::default();
        let run = RunId("workflow-incomplete".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "audit modules");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::SubagentSpawned {
                    sub_run: "fan-legacy".into(),
                    agent: "investigator".into(),
                },
            })
            .unwrap();
        drop(rollout);
        assert_eq!(
            meta(&dir, &run).unwrap().cost,
            CostState::Unknown {
                reason: core_obs::CostUnknownReason::LegacyUnattributed
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn model_selection_updates_provider_and_model_projection() {
        let dir = tmpdir("selection-meta");
        let tenant = TenantId::default();
        let run = RunId("selected".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::ModelSelected {
                    provider_id: "openai-work".into(),
                    model_id: "gpt-5-codex".into(),
                    catalog_digest: "catalog-v1".into(),
                    capability_digest: "cap-v1".into(),
                },
            })
            .unwrap();
        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.provider_id, "openai-work");
        assert_eq!(projected.model, "gpt-5-codex");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn meta_projects_the_latest_runtime_effort_snapshot() {
        let dir = tmpdir("runtime-effort-meta");
        let tenant = TenantId::default();
        let run = RunId("runtime-effort".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        let mut rollout = Rollout::open(&dir, &run, tenant).unwrap();
        rollout
            .append(&Event {
                seq: Seq::ZERO,
                turn: TurnId(1),
                kind: EventKind::EffortChanged {
                    version: RuntimePolicyEventVersion::V1,
                    source: RuntimePolicySource::Operator,
                    effort: Effort::Max,
                },
            })
            .unwrap();
        assert_eq!(meta(&dir, &run).unwrap().effort, Effort::Max);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn appended_selection_invalidates_stale_meta_and_index_projections() {
        let dir = tmpdir("selection-cache");
        let tenant = TenantId::default();
        let run = RunId("cached-selection".into());
        mk_run(&dir, &run, &tenant, "/repo/a", "task");
        assert_eq!(reindex(&dir).unwrap(), 1);
        let cached = meta(&dir, &run).unwrap();
        assert!(cached.provider_id.is_empty());
        assert!(cached.record_bytes > 0);

        {
            let mut rollout = Rollout::open(&dir, &run, tenant.clone()).unwrap();
            rollout
                .append(&selection_event("deepseek-work", "deepseek-coder"))
                .unwrap();
        }

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.provider_id, "deepseek-work");
        assert_eq!(projected.model, "deepseek-coder");
        assert!(projected.record_bytes > cached.record_bytes);
        let listed = list(&dir, &tenant)
            .into_iter()
            .find(|meta| meta.run_id == run)
            .unwrap();
        assert_eq!(listed.provider_id, "deepseek-work");
        assert_eq!(listed.model, "deepseek-coder");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_meta_without_provider_or_cursor_remains_readable_and_replays() {
        let dir = tmpdir("legacy-meta");
        let tenant = TenantId::default();
        let run = RunId("legacy".into());
        mk_run(&dir, &run, &tenant, "/repo/legacy", "legacy task");

        let current = meta_from_replay(&dir, &run).unwrap();
        let mut legacy = serde_json::to_value(&current).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.remove("provider_id");
        object.remove("record_bytes");
        let decoded: SessionMeta = serde_json::from_value(legacy.clone()).unwrap();
        assert!(decoded.provider_id.is_empty());
        assert_eq!(decoded.record_bytes, 0);

        // A legacy cache cursor cannot claim freshness. The record is replayed and the cursor is
        // upgraded in-memory without requiring a migration or making the old JSON unreadable.
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let projected = meta(&dir, &run).unwrap();
        assert!(projected.provider_id.is_empty());
        assert_eq!(projected.model, "claude");
        assert!(projected.record_bytes > 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_placeholder_cost_cache_is_replayed_as_unknown() {
        let dir = tmpdir("legacy-placeholder-cost");
        let tenant = TenantId::default();
        let run = RunId("legacy-placeholder-cost".into());
        mk_run(&dir, &run, &tenant, "/repo/legacy", "legacy task");

        // Preserve the exact rollout cursor so the pricing schema is the only reason this cache
        // is rejected. V0 stored a context-free placeholder number under `cost_usd`.
        let current = meta_from_replay(&dir, &run).unwrap();
        let mut legacy = serde_json::to_value(&current).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.remove("pricing_schema_version");
        object.remove("cost");
        object.insert("cost_usd".into(), serde_json::json!(123.45));
        std::fs::write(
            per_run_meta_path(&dir, &run).unwrap(),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let projected = meta(&dir, &run).unwrap();
        assert_eq!(projected.pricing_schema_version, 1);
        assert_eq!(
            projected.cost,
            CostState::Unknown {
                reason: core_obs::CostUnknownReason::NoVerifiedRateCard
            }
        );
        assert_eq!(projected.cost_usd(), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_is_newest_first_and_tenant_scoped() {
        let dir = tmpdir("list");
        let t = TenantId("acme".into());
        let other = TenantId("globex".into());
        mk_run(&dir, &RunId("a".into()), &t, "/repo/a", "task a");
        mk_run(&dir, &RunId("b".into()), &t, "/repo/b", "task b");
        mk_run(&dir, &RunId("c".into()), &other, "/repo/c", "task c");
        let ls = list(&dir, &t);
        assert_eq!(ls.len(), 2, "only this tenant's runs");
        assert!(ls.iter().all(|m| m.tenant == t));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn most_recent_is_cwd_scoped() {
        let dir = tmpdir("recent");
        let t = TenantId::default();
        mk_run(&dir, &RunId("x".into()), &t, "/repo/x", "task x");
        mk_run(&dir, &RunId("y".into()), &t, "/repo/y", "task y");
        assert_eq!(
            most_recent(&dir, Path::new("/repo/x"), &t),
            Some(RunId("x".into()))
        );
        assert_eq!(most_recent(&dir, Path::new("/nope"), &t), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_meta_and_reindex_round_trip() {
        let dir = tmpdir("cache");
        let t = TenantId::default();
        let run = RunId("z".into());
        mk_run(&dir, &run, &t, "/repo/z", "cache me");
        // reindex builds the cache from the record
        assert_eq!(reindex(&dir).unwrap(), 1);
        assert!(per_run_meta_path(&dir, &run).unwrap().exists());
        // write_meta preserves an evidence-bearing cost projection when one eventually exists.
        let mut m = meta_from_replay(&dir, &run).unwrap();
        m.cost = CostState::Known {
            amount_microusd: 1_230_000,
            rate_card_digest: "sha256:test-rate-card".into(),
        };
        write_meta(&dir, &m).unwrap();
        let via_cache = meta(&dir, &run).unwrap();
        assert!(
            (via_cache.cost_usd().unwrap() - 1.23).abs() < 1e-9,
            "cache carries cost"
        );
        assert_eq!(list(&dir, &t).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn session_paths_reject_traversal_in_record_and_cache_run_ids() {
        let root = tmpdir("run-id-traversal");
        let runs = root.join("runs");
        let tenant = TenantId::default();
        let safe = RunId("safe".into());
        mk_run(&runs, &safe, &tenant, "/repo/safe", "safe task");

        let escaped_name = "escaped-session-meta";
        let attack = RunId(format!("../{escaped_name}"));
        let meta_error = meta(&runs, &attack).expect_err("meta lookup must reject a traversal id");
        assert!(matches!(meta_error, RecordError::InvalidRunId { .. }));

        let mut projected = meta(&runs, &safe).unwrap();
        projected.run_id = attack;
        let write_error =
            write_meta(&runs, &projected).expect_err("cache writes must reject a traversal id");
        assert!(matches!(write_error, RecordError::InvalidRunId { .. }));
        assert!(
            !root.join(format!("{escaped_name}.meta.json")).exists(),
            "a hostile run id must not escape runs_dir through a sidecar write"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fork_rejects_a_caller_from_another_tenant_before_creating_a_child() {
        let dir = tmpdir("fork-tenant-boundary");
        let acme = TenantId("acme".into());
        let parent = RunId("acme-parent".into());
        mk_run(&dir, &parent, &acme, "/repo/acme", "tenant task");
        let before = rollout_run_ids(&dir).len();

        let error = fork(&dir, &parent, Seq(4), &TenantId("globex".into()))
            .expect_err("cross-tenant fork must be rejected");
        assert!(matches!(
            error,
            RecordError::TenantMismatch {
                seq: 0,
                ref expected,
                ref found,
            } if expected == "globex" && found == "acme"
        ));
        assert_eq!(
            rollout_run_ids(&dir).len(),
            before,
            "tenant validation must happen before minting/writing the child"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_forked_rejects_a_handcrafted_cross_tenant_parent_edge() {
        let dir = tmpdir("fork-chain-tenant-boundary");
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let parent = RunId("acme-parent".into());
        mk_run(&dir, &parent, &acme, "/repo/acme", "parent task");
        let parent_lines = read_chain(&rollout_path(&dir, &parent).unwrap()).unwrap();
        let pinned = parent_lines
            .iter()
            .find(|line| line.seq == Seq(4))
            .unwrap()
            .hash
            .clone();

        // Public `fork` now prevents this shape. Write a valid child journal directly to model a
        // malicious/legacy record whose genesis crosses the tenant boundary.
        let child = RunId("globex-child".into());
        {
            let mut rollout = Rollout::open(&dir, &child, globex).unwrap();
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::RunStart {
                        cwd: "/repo/globex".into(),
                        model: "claude".into(),
                        effort: Effort::Medium,
                        created_at: 1001,
                        parent_run: Some(parent.0.clone()),
                        forked_at: Some(4),
                        parent_hash_at_seq: Some(pinned),
                        config_digest: "cfg".into(),
                    },
                })
                .unwrap();
        }

        let error = load_forked(&dir, &child)
            .expect_err("a cross-tenant fork edge must not be materialized");
        assert!(matches!(
            error,
            RecordError::TenantMismatch {
                seq: 0,
                ref expected,
                ref found,
            } if expected == "globex" && found == "acme"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_references_the_parent_and_load_concatenates() {
        let dir = tmpdir("fork");
        let t = TenantId::default();
        let parent = RunId("p".into());
        mk_run(&dir, &parent, &t, "/repo/p", "parent-task");
        // fork at the parent tail (seq 4), then add a follow-up to the child
        let child = fork(&dir, &parent, Seq(4), &t).unwrap();
        {
            let mut r = Rollout::open(&dir, &child, t.clone()).unwrap();
            r.append(&Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("child-follow-up"),
                },
            })
            .unwrap();
        }
        // the child's own meta shows the provenance cross-link
        let cm = meta(&dir, &child).unwrap();
        let prov = cm.parent.expect("child records provenance");
        assert_eq!(prov.parent_run, parent);
        assert_eq!(prov.forked_at, Seq(4));
        assert!(!prov.parent_hash_at_seq.is_empty());
        // load_forked replays the parent prefix, then appends the child's events
        let events = load_forked(&dir, &child).unwrap();
        assert_eq!(user_texts(&events), vec!["parent-task", "child-follow-up"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_inherits_the_latest_selection_at_or_before_the_exact_sequence() {
        let dir = tmpdir("fork-selection-seq");
        let tenant = TenantId::default();
        let parent = RunId("route-parent".into());
        {
            let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/routes")).unwrap(); // seq 0
            rollout
                .append(&selection_event("anthropic-a", "claude-a"))
                .unwrap(); // seq 1
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text("between routes"),
                    },
                })
                .unwrap(); // seq 2
            rollout
                .append(&selection_event("openai-b", "gpt-b"))
                .unwrap(); // seq 3
        }

        let before_second = fork(&dir, &parent, Seq(2), &tenant).unwrap();
        let at_second = fork(&dir, &parent, Seq(3), &tenant).unwrap();
        assert_eq!(
            latest_selection(&crate::replay(&rollout_path(&dir, &before_second).unwrap()).unwrap()),
            Some(("anthropic-a".into(), "claude-a".into()))
        );
        assert_eq!(
            latest_selection(&crate::replay(&rollout_path(&dir, &at_second).unwrap()).unwrap()),
            Some(("openai-b".into(), "gpt-b".into()))
        );
        let projected = meta(&dir, &at_second).unwrap();
        assert_eq!(projected.provider_id, "openai-b");
        assert_eq!(projected.model, "gpt-b");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_snapshots_effective_runtime_policy_at_the_exact_branch_point() {
        let dir = tmpdir("fork-runtime-policy");
        let tenant = TenantId::default();
        let parent = RunId("policy-parent".into());
        let mut denied_code = PermissionRules::new();
        denied_code.set_cap(Capability::CodeExecuting, Verdict::Deny);
        {
            let mut rollout = Rollout::open(&dir, &parent, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/policy")).unwrap(); // seq 0
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::EffortChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        effort: Effort::High,
                    },
                })
                .unwrap(); // seq 1
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::PolicyChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        mode: PermissionMode::AcceptEdits,
                        rules: denied_code.clone(),
                    },
                })
                .unwrap(); // seq 2
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::EffortChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        effort: Effort::Max,
                    },
                })
                .unwrap(); // seq 3
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::PolicyChanged {
                        version: RuntimePolicyEventVersion::V1,
                        source: RuntimePolicySource::Operator,
                        mode: PermissionMode::Plan,
                        rules: PermissionRules::new(),
                    },
                })
                .unwrap(); // seq 4
        }

        let early = fork(&dir, &parent, Seq(2), &tenant).unwrap();
        let late = fork(&dir, &parent, Seq(4), &tenant).unwrap();

        let early_physical = crate::replay(&rollout_path(&dir, &early).unwrap()).unwrap();
        let early_state = RuntimePolicyState::from_events(&early_physical);
        assert_eq!(early_state.effort, Effort::High);
        assert_eq!(early_state.permission_mode, PermissionMode::AcceptEdits);
        assert_eq!(early_state.permission_rules, denied_code);
        assert!(early_physical.iter().any(|event| matches!(
            event.kind,
            EventKind::EffortChanged {
                source: RuntimePolicySource::Fork,
                ..
            }
        )));
        assert!(early_physical.iter().any(|event| matches!(
            event.kind,
            EventKind::PolicyChanged {
                source: RuntimePolicySource::Fork,
                ..
            }
        )));

        let late_physical = crate::replay(&rollout_path(&dir, &late).unwrap()).unwrap();
        let late_state = RuntimePolicyState::from_events(&late_physical);
        assert_eq!(late_state.effort, Effort::Max);
        assert_eq!(late_state.permission_mode, PermissionMode::Plan);
        assert!(late_state.permission_rules.is_empty());

        let late_logical = load_forked(&dir, &late).unwrap();
        assert_eq!(RuntimePolicyState::from_events(&late_logical), late_state);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nested_fork_at_child_genesis_inherits_the_ancestor_route() {
        let dir = tmpdir("nested-fork-selection");
        let tenant = TenantId::default();
        let root = RunId("route-root".into());
        {
            let mut rollout = Rollout::open(&dir, &root, tenant.clone()).unwrap();
            rollout.append(&genesis_event("/repo/routes")).unwrap();
            rollout
                .append(&selection_event(
                    "fireworks-work",
                    "accounts/a/models/coder",
                ))
                .unwrap();
        }
        let first = fork(&dir, &root, Seq(1), &tenant).unwrap();
        // seq 0 is the first child's physical genesis. Its effective state already includes the
        // root prefix, so a fork here must retain the ancestor provider as well as the model.
        let second = fork(&dir, &first, Seq(0), &tenant).unwrap();
        let physical = crate::replay(&rollout_path(&dir, &second).unwrap()).unwrap();
        assert_eq!(
            latest_selection(&physical),
            Some(("fireworks-work".into(), "accounts/a/models/coder".into()))
        );
        let logical = load_forked(&dir, &second).unwrap();
        assert_eq!(latest_selection(&logical), latest_selection(&physical));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forking_a_legacy_record_preserves_model_without_inventing_provider() {
        let dir = tmpdir("legacy-fork-route");
        let tenant = TenantId::default();
        let parent = RunId("legacy-parent".into());
        mk_run(&dir, &parent, &tenant, "/repo/legacy", "legacy task");
        let child = fork(&dir, &parent, Seq(4), &tenant).unwrap();
        let physical = crate::replay(&rollout_path(&dir, &child).unwrap()).unwrap();
        assert!(latest_selection(&physical).is_none());
        let projected = meta(&dir, &child).unwrap();
        assert!(projected.provider_id.is_empty());
        assert_eq!(projected.model, "claude");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fork_at_replay_tail_preserves_the_whole_kernel_written_parent() {
        // End-to-end regression for the CRITICAL fork data-loss bug, mirroring the REAL flow: the
        // kernel writes every payload with a placeholder seq (Seq::ZERO), and the CLI computes the
        // fork point as `replay(parent).last().seq`. Before the fix that was 0, so the child forked
        // at genesis and reconstructed ZERO parent messages. The prior fork test missed this by
        // writing distinct payload seqs and forking at a hardcoded Seq(4).
        let dir = tmpdir("fork-kernel");
        let t = TenantId::default();
        let parent = RunId("pk".into());
        {
            let mut r = Rollout::open(&dir, &parent, t.clone()).unwrap();
            // all payloads Seq::ZERO, exactly like kernel `emit`
            r.append(&genesis_event("/repo/pk")).unwrap();
            for text in ["first-turn", "second-turn"] {
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnStart,
                })
                .unwrap();
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::Message {
                        message: Message::user_text(text),
                    },
                })
                .unwrap();
                r.append(&Event {
                    seq: Seq::ZERO,
                    turn: TurnId(0),
                    kind: EventKind::TurnEnd {
                        usage: Usage::default(),
                    },
                })
                .unwrap();
            }
        }
        // Compute the fork point the way the CLI does — from the replayed tail seq.
        let events = crate::replay(&rollout_path(&dir, &parent).unwrap()).unwrap();
        let at = events.last().map(|e| e.seq).unwrap();
        assert_ne!(
            at,
            Seq(0),
            "replay tail must be the real last seq, not the placeholder 0"
        );
        let child = fork(&dir, &parent, at, &t).unwrap();
        // Resuming the child must reconstruct BOTH parent turns, not an empty transcript.
        let loaded = load_forked(&dir, &child).unwrap();
        assert_eq!(user_texts(&loaded), vec!["first-turn", "second-turn"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_the_parent_prefix_is_detected_on_fork_load() {
        // ADR-008 §4 / R5-review Risk 3: an attacker who edits the parent prefix AND re-hashes the
        // parent chain (so it is internally valid again) must still be caught by the pinned
        // parent_hash_at_seq. We simulate that by rebuilding the parent as a valid-but-different
        // chain; load_forked must reject the child with ForkParentMismatch.
        let dir = tmpdir("tamper");
        let t = TenantId::default();
        let parent = RunId("p".into());
        mk_run(&dir, &parent, &t, "/repo/p", "original-parent-task");
        let child = fork(&dir, &parent, Seq(2), &t).unwrap();

        // Rebuild the parent with altered content at seq 2 but a fully valid hash chain.
        std::fs::remove_file(rollout_path(&dir, &parent).unwrap()).unwrap();
        {
            let mut r = Rollout::open(&dir, &parent, t.clone()).unwrap();
            r.append(&genesis_event("/repo/p")).unwrap();
            r.append(&Event {
                seq: Seq(1),
                turn: TurnId(0),
                kind: EventKind::TurnStart,
            })
            .unwrap();
            r.append(&Event {
                seq: Seq(2),
                turn: TurnId(0),
                kind: EventKind::Message {
                    message: Message::user_text("TAMPERED-parent-task"),
                },
            })
            .unwrap();
        }
        // The rebuilt parent is internally valid (a plain replay of it succeeds)...
        assert!(read_chain(&rollout_path(&dir, &parent).unwrap()).is_ok());
        // ...but the child's pinned cross-link no longer matches: tamper detected.
        let err = load_forked(&dir, &child).unwrap_err();
        assert!(
            matches!(err, RecordError::ForkParentMismatch { forked_at: 2, .. }),
            "expected ForkParentMismatch, got {err:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_event_kinds_do_not_fail_the_scan() {
        // R5-review Risk 6: a newer writer's event kind deserializes to EventKind::Unknown, so the
        // projection still works over a rollout that carries one.
        let dir = tmpdir("unknown");
        let t = TenantId::default();
        let run = RunId("u".into());
        mk_run(&dir, &run, &t, "/repo/u", "with an unknown event");
        // Append a hand-written chain line whose payload has an unrecognized kind, keeping the
        // hash chain valid by using the crate's own hashing over the tail.
        let path = rollout_path(&dir, &run).unwrap();
        let tail = read_chain(&path).unwrap();
        let last = tail.last().unwrap();
        let payload =
            serde_json::json!({"seq":0,"turn":0,"kind":{"kind":"from_the_future","extra":1}});
        let seq = last.seq.0 + 1;
        let hash = crate::hash_line(&last.hash, seq, &payload);
        let cl = serde_json::json!({
            "seq": seq, "tenant": t.0, "prev": last.hash, "hash": hash, "payload": payload
        });
        let mut line = serde_json::to_string(&cl).unwrap();
        line.push('\n');
        use std::io::Write as _;
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
        // The scan tolerates the unknown kind rather than failing.
        let m = meta(&dir, &run).unwrap();
        assert_eq!(m.title, "with an unknown event");
        std::fs::remove_dir_all(&dir).ok();
    }
}
