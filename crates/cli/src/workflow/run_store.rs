//! Workflow sidecar filesystem owner and bounded restart inventory readers.

use iteron_workflow::RunReport;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Unix second stamp recorded when the clock reads before the epoch. Zero rather than a guess, so
/// a sidecar carries an obviously-unset time instead of a fabricated one.
const UNIX_SECS_ON_UNUSABLE_CLOCK: u64 = 0;
/// Whether a directory entry whose file type cannot be read is treated as a run directory. False,
/// so an unreadable entry is skipped rather than listed as a run with no sidecars.
const UNREADABLE_ENTRY_IS_RUN_DIR: bool = false;
/// Creation time listed for a run whose manifest is missing or unreadable. Zero sorts it last in
/// the newest-first listing, which is where a run with no recoverable metadata belongs.
const MISSING_MANIFEST_CREATED_AT: u64 = 0;

// ---------------------------------------------------------------------------------------------
// Persistence + enumeration for the background-launch surface (`iteron workflow list/resume/watch`).
//
// The engine persists only the outcome `journal.jsonl` under `<workflows_dir>/<run_id>/`. To make a
// run re-launchable (`resume`/`watch`) and listable by a LATER process, the CLI writes two sidecars
// next to that journal: `run.json` (the manifest — script identity, args, route, name, timestamp)
// and, at completion, `result.json` (the return value + cache metrics + stopped flag). The script
// source itself is copied to `script.js` so a resume needs no `--script` path. None of this is the
// hash-chained rollout; it is lightweight run metadata, mirroring the journal's own posture.
// ---------------------------------------------------------------------------------------------

/// The re-launchable identity of a persisted workflow run (`<workflows_dir>/<run_id>/run.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub name: String,
    pub args: serde_json::Value,
    pub provider_id: String,
    pub model: String,
    pub created_at: u64,
}

/// The terminal outcome of a run (`<workflows_dir>/<run_id>/result.json`), written once it settles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub value: serde_json::Value,
    pub stopped: bool,
    #[serde(default)]
    pub errors: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub finished_at: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "cli.workflow.unix_secs_on_unusable_clock",
            UNIX_SECS_ON_UNUSABLE_CLOCK,
        ))
}

/// `<workflows_dir>/<run_id>/`.
pub fn run_dir(workflows_dir: &Path, run_id: &str) -> PathBuf {
    workflows_dir.join(run_id)
}

/// Whether `run_id` is safe to use as one direct child directory name.
///
/// Generated ids already satisfy this. Operator controls validate persisted ids again because a
/// path-bearing resume request must never turn `Path::join` into traversal outside the workflow
/// store.
pub fn valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 160
        && run_id != "."
        && run_id != ".."
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Persist the re-launchable inputs (script source + manifest) BEFORE the run starts, so a crash
/// mid-run still leaves a resumable record.
pub fn persist_inputs(
    workflows_dir: &Path,
    manifest: &RunManifest,
    script: &str,
) -> anyhow::Result<()> {
    let dir = run_dir(workflows_dir, &manifest.run_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("script.js"), script)?;
    std::fs::write(dir.join("run.json"), serde_json::to_vec_pretty(manifest)?)?;
    Ok(())
}

/// Persist the terminal outcome once the run settles (enables `list` status + shows the value later).
pub fn persist_result(
    workflows_dir: &Path,
    run_id: &str,
    report: &RunReport,
) -> anyhow::Result<()> {
    let dir = run_dir(workflows_dir, run_id);
    std::fs::create_dir_all(&dir)?;
    let result = RunResult {
        value: report.value.clone(),
        stopped: report.stopped,
        errors: report.errors,
        cache_hits: report.cache_hits,
        cache_misses: report.cache_misses,
        finished_at: now_secs(),
    };
    std::fs::write(dir.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}

pub fn load_manifest(workflows_dir: &Path, run_id: &str) -> Option<RunManifest> {
    let bytes = std::fs::read(run_dir(workflows_dir, run_id).join("run.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn load_result(workflows_dir: &Path, run_id: &str) -> Option<RunResult> {
    let bytes = std::fs::read(run_dir(workflows_dir, run_id).join("result.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The persisted script source for a prior run (so `resume`/`watch` need no `--script`).
pub fn load_script(workflows_dir: &Path, run_id: &str) -> Option<String> {
    std::fs::read_to_string(run_dir(workflows_dir, run_id).join("script.js")).ok()
}

/// One row of `iteron workflow list` (also the durable summary the TUI can rehydrate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunListing {
    pub run_id: String,
    pub name: String,
    pub model: String,
    pub status: &'static str,
    pub agents: usize,
    pub created_at: u64,
}

/// Number of completed `agent()` calls recorded in a run's journal (one `"type":"result"` line each).
fn journal_agent_count(workflows_dir: &Path, run_id: &str) -> usize {
    let path = run_dir(workflows_dir, run_id).join("journal.jsonl");
    match std::fs::read_to_string(path) {
        Ok(text) => count_agent_results(&text),
        Err(_) => 0,
    }
}

fn count_agent_results(journal: &str) -> usize {
    journal
        .lines()
        .filter(|line| line.contains("\"type\":\"result\""))
        .count()
}

fn derive_status(result: Option<&RunResult>, has_journal: bool) -> &'static str {
    match result {
        Some(r) if r.stopped => "stopped",
        Some(r) if r.errors > 0 => "failed",
        Some(_) => "done",
        None if has_journal => "running",
        None => "pending",
    }
}

/// Largest journal opened by the first-frame rehydration path. The run remains durable and
/// available to `iteron workflow list|resume`; it is merely omitted from the startup inventory.
const MAX_RECENT_JOURNAL_BYTES: u64 = 256 * 1024;

/// Strict summary used by restart rehydration. Unlike the human-invoked full listing, the first
/// frame must never publish a partial count from a killed writer or spend unbounded time on one
/// historical journal.
fn recent_journal_summary(workflows_dir: &Path, run_id: &str) -> Option<(bool, usize)> {
    let maximum = iteron_tunables::param_integer(
        "cli.workflow.max_recent_journal_bytes",
        MAX_RECENT_JOURNAL_BYTES,
    )
    .min(MAX_RECENT_JOURNAL_BYTES) as usize;
    let bytes = match super::restart_read::read(workflows_dir, run_id, "journal.jsonl", maximum) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some((false, 0)),
        Err(_) => return None,
    };
    let text = String::from_utf8(bytes).ok()?;
    if !text.is_empty() && !text.ends_with('\n') {
        return None;
    }
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line).ok()?;
    }
    Some((true, count_agent_results(&text)))
}

/// Load one restart-safe listing through the same manifest/script/result readers used by
/// `iteron workflow list|resume|watch`. A torn optional sidecar refuses this row, not its neighbours.
pub(crate) fn load_run_listing(workflows_dir: &Path, run_id: String) -> Option<RunListing> {
    let manifest: RunManifest = serde_json::from_slice(
        &super::restart_read::read(workflows_dir, &run_id, "run.json", 64 * 1024).ok()?,
    )
    .ok()?;
    if manifest.run_id != run_id {
        return None;
    }
    // A restart row is resumable only when the actual finite stored script remains readable.
    String::from_utf8(
        super::restart_read::read(workflows_dir, &run_id, "script.js", 1024 * 1024).ok()?,
    )
    .ok()?;
    let result = match super::restart_read::read(workflows_dir, &run_id, "result.json", 128 * 1024)
    {
        Ok(bytes) => Some(serde_json::from_slice::<RunResult>(&bytes).ok()?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return None,
    };
    let (has_journal, agents) = recent_journal_summary(workflows_dir, &run_id)?;
    Some(RunListing {
        run_id,
        name: manifest.name,
        model: manifest.model,
        status: derive_status(result.as_ref(), has_journal),
        agents,
        created_at: manifest.created_at,
    })
}

/// Enumerate every persisted run under `<workflows_dir>`, newest first. A run's status is derived
/// from its sidecars: `done`/`failed`/`stopped` once `result.json` exists, else `running` if a
/// journal is present, else `pending`.
pub fn list_runs(workflows_dir: &Path) -> Vec<RunListing> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(workflows_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry
            .file_type()
            .map(|t| t.is_dir())
            .unwrap_or(UNREADABLE_ENTRY_IS_RUN_DIR)
        {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().into_owned();
        let manifest = load_manifest(workflows_dir, &run_id);
        let result = load_result(workflows_dir, &run_id);
        let has_journal = run_dir(workflows_dir, &run_id)
            .join("journal.jsonl")
            .exists();
        let status = derive_status(result.as_ref(), has_journal);
        let created_at =
            manifest
                .as_ref()
                .map(|m| m.created_at)
                .unwrap_or(iteron_tunables::param_integer(
                    "cli.workflow.missing_manifest_created_at",
                    MISSING_MANIFEST_CREATED_AT,
                ));
        out.push(RunListing {
            run_id: run_id.clone(),
            name: manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| "workflow".into()),
            model: manifest
                .as_ref()
                .map(|m| m.model.clone())
                .unwrap_or_default(),
            status,
            agents: journal_agent_count(workflows_dir, &run_id),
            created_at,
        });
    }
    out.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then(b.run_id.cmp(&a.run_id))
    });
    out
}
