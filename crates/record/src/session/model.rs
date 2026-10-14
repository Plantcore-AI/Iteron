//! Public session projections and provenance contracts; all serialized fields retain their schema.
use iteron_obs::CostState;
use iteron_protocol::{Block, Effort, Event, Message, Outcome, RunId, Seq, TenantId};
use std::path::PathBuf;

/// The branch point of a fork/rewind child. `parent_hash_at_seq` cross-links the child to the
/// parent chain's hash at `forked_at` so an altered parent prefix is detectable on replay
/// (ADR-008 §4 tamper-evidence, R5-review Risk 3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub parent_run: RunId,
    pub forked_at: Seq,
    pub parent_hash_at_seq: String,
}

/// One event in a verified logical fork history together with the physical journal identity that
/// originally authenticated it. Parent-prefix events deliberately retain their parent run id;
/// replay must not reinterpret them as if the child had emitted them.
#[derive(Debug, Clone)]
pub struct ScopedEvent {
    pub event: Event,
    pub tenant: TenantId,
    pub run_id: RunId,
}

/// One verified external prefix consumed by a fork session's logical history. `prefix_bytes`
/// ends exactly after `through_seq`, so later appends to the ancestor do not invalidate a child
/// projection while truncation or replacement of the pinned prefix does.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionAncestryReceipt {
    pub run_id: RunId,
    pub tenant: TenantId,
    pub through_seq: u64,
    pub prefix_bytes: u64,
    pub tail_hash: String,
    /// Complete ancestor extent observed while building this projection. Equality binds the
    /// original mtime; growth is accepted only when the old physical tail still exists at this
    /// exact boundary, distinguishing a valid append from an in-place rewrite.
    #[serde(default)]
    pub observed_record_bytes: u64,
    #[serde(default)]
    pub observed_tail_seq: u64,
    #[serde(default)]
    pub observed_tail_hash: String,
    #[serde(default)]
    pub observed_updated_at: u64,
    #[serde(default)]
    pub observed_updated_at_subsec_nanos: u32,
}

/// A session is a PROJECTION of its rollout, never a second source of truth (ADR-006). Populated
/// either from a record-writer cache or by replaying the record. Mutable cache bytes are never
/// accepted as authority for an exact monetary claim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionMeta {
    /// Projection schema for monetary truth. Legacy caches used a global placeholder price and
    /// are always rebuilt from the rollout rather than trusted.
    #[serde(default)]
    pub pricing_schema_version: u32,
    /// Projection schema independent of pricing. V3 binds fork ancestry prefix receipts;
    /// legacy caches are replayed so a resume/list cannot silently drop logical history.
    #[serde(default)]
    pub projection_schema_version: u32,
    /// Revocation generation against which every content-bearing projection was materialized.
    #[serde(default)]
    pub content_revocation_generation: u64,
    pub run_id: RunId,
    pub tenant: TenantId,
    pub cwd: PathBuf,
    /// Provider instance used by the latest recorded selection. Empty for legacy rollouts.
    #[serde(default)]
    pub provider_id: String,
    pub model: String,
    pub effort: Effort,
    /// Bounded operator-defined grouping metadata from genesis. Legacy sessions are untagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_definition_tag: Option<String>,
    /// Deterministic: the first user message's first line, truncated (SESS-3).
    pub title: String,
    /// Recorded once at run start (from the genesis header), not read at list time (ADR-006 rule 1).
    pub created_at: u64,
    /// Last-touched time. Authoritative when cached (kernel-written); on a replay it degrades to
    /// the rollout file's mtime, since the record carries no per-event wall clock.
    pub updated_at: u64,
    /// Nanosecond fraction of the same rollout mtime. It both breaks same-second continuation
    /// ties and detects accidental in-place record changes that preserve length and tail bytes.
    #[serde(default)]
    pub updated_at_subsec_nanos: u32,
    /// Physical rollout length covered by this rebuildable projection cache. Older cache files
    /// deserialize with zero and are replayed. An append-only `ModelSelected` increases the
    /// rollout length, invalidating stale provider/model projections without scanning the log.
    #[serde(default)]
    pub record_bytes: u64,
    /// Exact physical tail receipt observed by the record writer. Fast-path reads compare this
    /// pair with the bounded final record line before accepting any mutable cache fields.
    #[serde(default)]
    pub record_tail_seq: Option<u64>,
    #[serde(default)]
    pub record_tail_hash: String,
    /// Corruption detector over the complete projection plus its record receipt, with this field
    /// cleared during hashing. It is not a substitute for the hash-chained rollout; a mismatch is
    /// simply a cache miss that forces authoritative replay.
    #[serde(default)]
    pub projection_digest: String,
    /// Root-to-direct-parent receipts for every external prefix included by a fork projection.
    /// Empty for an ordinary root run. Each entry is bounded and rechecked without replaying the
    /// ancestor's full journal.
    #[serde(default)]
    pub ancestry: Vec<SessionAncestryReceipt>,
    pub turns: u32,
    /// Evidence-backed monetary state. Signed route-bound projections produce `Known`; completed
    /// provider turns without matching durable pricing evidence remain honestly `Unknown`.
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

/// Deterministic title: the first user message's first non-empty line, char-truncated (SESS-3).
pub(super) fn title_from_message(m: &Message) -> String {
    let text = m
        .content
        .iter()
        .find_map(|b| match b {
            Block::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("");
    title_from_text(text)
}

/// The stable first-prompt title projection shared by durable session metadata and live clients.
pub fn title_from_text(text: &str) -> String {
    let first_line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    const MAX: usize = 72;
    if first_line.chars().count() <= iteron_tunables::param_integer("record.session.max", MAX) {
        first_line.to_string()
    } else {
        let mut t: String = first_line
            .chars()
            .take(iteron_tunables::param_integer("record.session.max", MAX))
            .collect();
        t.push('…');
        t
    }
}

/// Map the kernel's recorded `Done{outcome}` (a `format!("{outcome:?}")` Debug string) back to an
/// [`Outcome`]. The `BudgetExhausted` reason is a `&'static str`, so a replay maps to the known
/// reason literal; an unrecognized string yields `None` (a projection convenience, not the record).
pub(super) fn parse_outcome(s: &str) -> Option<Outcome> {
    let s = s.trim();
    match s {
        "Done" => Some(Outcome::Done),
        "Drained" => Some(Outcome::Drained),
        "Interrupted" => Some(Outcome::Interrupted),
        "Stuck" => Some(Outcome::Stuck),
        "HarnessError" => Some(Outcome::HarnessError),
        _ if s.starts_with("BudgetExhausted") => {
            let reason = if s.contains("max_turns") {
                "max_turns"
            } else if s.contains("max_usd") {
                "max_usd"
            } else if s.contains("unpriced_usd_ceiling") {
                "unpriced_usd_ceiling"
            } else if s.contains("max_tokens") {
                "max_tokens"
            } else if s.contains("max_wall_secs") {
                "max_wall_secs"
            } else if s.contains("max_consecutive_tool_errors") {
                "max_consecutive_tool_errors"
            } else if s.contains("verify_attempts") {
                "verify_attempts"
            } else {
                "budget"
            };
            Some(Outcome::BudgetExhausted(reason))
        }
        _ => None,
    }
}

pub(super) const MAX_FORK_DEPTH: usize = 256;
