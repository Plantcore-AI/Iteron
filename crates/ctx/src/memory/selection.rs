//! Pure gathered-value policy for memory recall and exact operator-write proposals.
//! No filesystem path/store or journal is available to this owner. Caller admission and
//! byte/trust ceilings remain authoritative; the private cache retains only deterministic scores.
use super::{MAX_FACT_BYTES, MAX_RECALL, MemBudget, suspicious_unicode};
use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::slot::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
use iteron_protocol::trust::Trust;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, OnceLock};

/// The version-skew boundary for a `core/memory` observation and decision.
pub const MEMORY_SLOT_VERSION: u16 = 2;

/// Upper bound on how many already-gathered candidates one decision may consider. Set above
/// `MAX_MEMORY_FILES` so a merge across several stores is not silently truncated.
pub const MAX_MEMORY_CANDIDATES: usize = 4_096;

/// Upper bound on the task query carried into a decision. Deliberately the same 64 KB the
/// `core/context` slot applies to its own task string.
pub const MAX_MEMORY_TASK_BYTES: usize = 64 * 1024;

/// Upper bound on one candidate's scoring text. A body is already head-capped at
/// [`MAX_FACT_BYTES`]; this leaves generous room for title and summary above that.
pub const MAX_MEMORY_CANDIDATE_TEXT_BYTES: usize = 32 * 1024;

/// Upper bound on a candidate slug, mirroring what the index parser will accept.
pub const MAX_MEMORY_SLUG_BYTES: usize = 128;

/// One already-gathered recall candidate: a fact the caller has already read, priced, and
/// provenance-tagged. The slot scores this and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryCandidate {
    /// The fact's slug. The decision names these, so the caller can always map a decision back to
    /// something it actually gathered.
    pub slug: String,
    /// The text to score against the task: title, summary and body, already loaded. Carried in the
    /// observation because the slot may not open the file itself.
    pub text: String,
    /// What one injected copy of this fact costs, priced caller-side by `Fact::framed().len()`.
    /// Pricing lives with the caller because the framing is the caller's, not the policy's.
    pub framed_bytes: usize,
    /// Provenance trust of the store the candidate came from.
    pub trust: Trust,
    /// Caller-observed filesystem modification time. `None` is explicit unknown recency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_unix_secs: Option<u64>,
    #[serde(default = "legacy_confidence")]
    pub confidence_ppm: u32,
}

fn legacy_confidence() -> u32 {
    crate::memory_records::LEGACY_CONFIDENCE_PPM
}

/// Everything the `core/memory` slot is allowed to see, and every ceiling it must respect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySlotObservation {
    pub version: u16,
    /// The task recall is relevant to.
    pub task: String,
    /// Every candidate the caller gathered, in the caller's stable order.
    pub candidates: Vec<MemoryCandidate>,
    /// Caller-owned ceiling on total injected recall bytes.
    pub recall_bytes: usize,
    /// Caller-owned ceiling on how many bodies may be recalled at all.
    pub max_recalled: usize,
    /// The least-trusted provenance the caller will accept. A candidate below this is not
    /// admissible however relevant it scores — relevance never buys authority.
    pub trust_floor: Trust,
    /// One captured decision clock shared by materialization and audit; never read by the slot.
    #[serde(default)]
    pub reference_unix_secs: u64,
    #[serde(default)]
    pub retrieval_policy: crate::MemoryRetrievalPolicy,
    /// Operator-authored bytes offered for persistence. A policy may admit these exact bytes or
    /// refuse them; it may never author, edit, or enlarge the fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
}

impl MemorySlotObservation {
    /// The conservative baseline: the caller's own budget, this crate's recall cap, and no
    /// provenance filtering beyond what the caller already applied when it gathered.
    pub fn baseline(
        task: impl Into<String>,
        candidates: Vec<MemoryCandidate>,
        budget: &MemBudget,
    ) -> Self {
        Self::baseline_with_policy(
            task,
            candidates,
            budget,
            0,
            crate::MemoryRetrievalPolicy::default(),
        )
    }

    pub fn baseline_with_policy(
        task: impl Into<String>,
        candidates: Vec<MemoryCandidate>,
        budget: &MemBudget,
        reference_unix_secs: u64,
        retrieval_policy: crate::MemoryRetrievalPolicy,
    ) -> Self {
        Self {
            version: MEMORY_SLOT_VERSION,
            task: task.into(),
            candidates,
            recall_bytes: budget.recall_bytes,
            max_recalled: usize::try_from(retrieval_policy.recall_limit)
                .unwrap_or(iteron_tunables::param_integer(
                    "ctx.memory.max_recall",
                    MAX_RECALL,
                ))
                .min(iteron_tunables::param_integer(
                    "ctx.memory.max_memory_candidates",
                    MAX_MEMORY_CANDIDATES,
                )),
            trust_floor: Trust::Untrusted,
            reference_unix_secs,
            retrieval_policy,
            write: None,
        }
    }

    /// A bounded project-memory write with no recall authority mixed into the same decision.
    pub fn project_write(text: impl Into<String>) -> Self {
        Self {
            version: MEMORY_SLOT_VERSION,
            task: String::new(),
            candidates: Vec::new(),
            recall_bytes: 0,
            max_recalled: 0,
            trust_floor: Trust::Untrusted,
            reference_unix_secs: 0,
            retrieval_policy: crate::MemoryRetrievalPolicy::default(),
            write: Some(text.into()),
        }
    }

    fn validate(&self) -> Result<(), MemorySlotError> {
        if self.version != MEMORY_SLOT_VERSION {
            return Err(MemorySlotError::UnsupportedVersion);
        }
        if self.task.len()
            > iteron_tunables::param_integer(
                "ctx.memory.max_memory_task_bytes",
                MAX_MEMORY_TASK_BYTES,
            )
        {
            return Err(MemorySlotError::InvalidObservation(
                "memory task exceeds the bounded observation query",
            ));
        }
        self.retrieval_policy
            .validate()
            .map_err(MemorySlotError::InvalidObservation)?;
        if let Some(write) = &self.write {
            if !self.task.is_empty()
                || !self.candidates.is_empty()
                || self.recall_bytes != 0
                || self.max_recalled != 0
            {
                return Err(MemorySlotError::InvalidObservation(
                    "memory write observations cannot also request recall",
                ));
            }
            if write.trim().is_empty() || write.len() > MAX_FACT_BYTES {
                return Err(MemorySlotError::InvalidObservation(
                    "memory write text is empty or exceeds the fact bound",
                ));
            }
            if suspicious_unicode(write) {
                return Err(MemorySlotError::InvalidObservation(
                    "memory write contains suspicious Unicode",
                ));
            }
        }
        if self.candidates.len()
            > iteron_tunables::param_integer(
                "ctx.memory.max_memory_candidates",
                MAX_MEMORY_CANDIDATES,
            )
        {
            return Err(MemorySlotError::InvalidObservation(
                "memory observation carries more candidates than the bound allows",
            ));
        }
        if self.max_recalled
            > iteron_tunables::param_integer(
                "ctx.memory.max_memory_candidates",
                MAX_MEMORY_CANDIDATES,
            )
        {
            return Err(MemorySlotError::InvalidObservation(
                "memory recall count ceiling exceeds the candidate bound",
            ));
        }
        for candidate in &self.candidates {
            if candidate.confidence_ppm > crate::memory_runtime::SCORE_SCALE
                || candidate.slug.is_empty()
                || candidate.slug.len()
                    > iteron_tunables::param_integer(
                        "ctx.memory.max_memory_slug_bytes",
                        MAX_MEMORY_SLUG_BYTES,
                    )
            {
                return Err(MemorySlotError::InvalidObservation(
                    "memory candidate slug must be 1..=128 bytes",
                ));
            }
            if candidate.text.len()
                > iteron_tunables::param_integer(
                    "ctx.memory.max_memory_candidate_text_bytes",
                    MAX_MEMORY_CANDIDATE_TEXT_BYTES,
                )
            {
                return Err(MemorySlotError::InvalidObservation(
                    "memory candidate scoring text exceeds its bound",
                ));
            }
            if candidate.framed_bytes == 0 {
                return Err(MemorySlotError::InvalidObservation(
                    "memory candidate must carry a non-zero injected cost",
                ));
            }
        }
        // Slugs are the decision's vocabulary. Duplicates would make "the fact the decision named"
        // ambiguous, and the budget arithmetic would then depend on which one the caller picked.
        let mut slugs: Vec<&str> = self.candidates.iter().map(|c| c.slug.as_str()).collect();
        slugs.sort_unstable();
        let total = slugs.len();
        slugs.dedup();
        if slugs.len() != total {
            return Err(MemorySlotError::InvalidObservation(
                "memory candidate slugs must be unique",
            ));
        }
        Ok(())
    }
}

/// What the slot decided: which gathered facts to inject, in injection order.
///
/// Slugs rather than bodies, on purpose. A decision that carried content would let a replacement
/// slot inject text the caller never read; a decision that carries slugs can only ever select from
/// what the caller already gathered, which is checkable and is checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecallPlan {
    pub recalled: Vec<String>,
    /// The sum of `framed_bytes` over `recalled`. Stated by the decision and re-derived by the
    /// caller, so a policy cannot under-report what it is about to spend.
    pub recall_bytes_used: usize,
}

/// The version-skew boundary for a memory-slot decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemorySlotDecision {
    Plan {
        plan: MemoryRecallPlan,
    },
    Write {
        /// `None` is an explicit policy refusal. `Some` must remain byte-identical to the offer.
        write: Option<String>,
    },
    #[serde(other)]
    Unknown,
}

/// A plan plus the capabilities that survived intersection with the caller's ceiling. Eligibility
/// is evidence for a later gate, never authority to inject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRecallProposal {
    pub plan: MemoryRecallPlan,
    pub eligible: CapabilitySet,
}

/// Ephemeral, bounded explanation of one lexical recall decision. Candidate text exists only long
/// enough for the caller to hash it into content-free evidence; it is never an exporter payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRecallDisposition {
    /// The pinned slot returned a valid, caller-narrowed recall plan.
    Selected,
    /// The pinned slot refused or returned an invalid plan. No body is recalled.
    Abstained,
    /// An outer isolation rule prevented the slot from being called at all.
    NotInvokedScopeDenied,
}

#[derive(Debug, Clone)]
pub struct MemoryRecallAudit {
    /// Whether this audit describes a real slot decision or an outer pre-decision denial.
    pub disposition: MemoryRecallDisposition,
    pub observation: MemorySlotObservation,
    /// Exact deterministic query used by both materialization and this audit after whitespace
    /// normalization. This is ephemeral; durable evidence stores only its digest and dimensions.
    pub rewritten_query: String,
    pub rewrite_count: u16,
    pub selected: Vec<String>,
    /// Runtime policy's final fused score in deterministic parts-per-million, aligned with
    /// `candidates`.
    pub scores_ppm: Vec<i64>,
    /// Normalized lexical contribution before policy weighting and recency, aligned with
    /// `candidates`.
    pub lexical_scores_ppm: Vec<i64>,
    /// Deterministic query/document token-overlap contribution, aligned with `candidates`.
    pub structural_scores_ppm: Vec<i64>,
    /// Multiplicative recency factor applied to each candidate, aligned with `candidates`.
    pub recency_multipliers_ppm: Vec<u32>,
    /// Candidates rejected by the runtime novelty threshold after a more highly ranked candidate
    /// had already been selected.
    pub novelty_deduplicated: Vec<String>,
    /// One-based relevance rank; zero means the candidate was below the lexical threshold or the
    /// trust floor, aligned with `candidates`.
    pub ranks: Vec<u32>,
    /// Same-slug candidates removed while higher-precedence stores override lower tiers.
    pub deduplicated_candidates: u32,
    /// Candidates actually denied by deterministic precedence, integrity, or attempt isolation.
    pub excluded_candidates: Vec<MemoryRecallExclusion>,
    pub dropped_exclusions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRecallExclusionKind {
    Superseded,
    Contradiction,
    Expired,
    ScopeDenied,
}

#[derive(Debug, Clone)]
pub struct MemoryRecallExclusion {
    pub slug: String,
    pub evidence_text: String,
    pub trust: Trust,
    pub kind: MemoryRecallExclusionKind,
    pub related_slug: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryWriteProposal {
    pub text: String,
    pub eligible: CapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemorySlotError {
    WrongSlot,
    InvalidObservation(&'static str),
    InvalidDecision(&'static str),
    DecisionWidened(&'static str),
    NotAdmittedReadOnly,
    NotAdmittedTrustMutation,
    WriteRefused,
    UnsupportedVersion,
}

impl fmt::Display for MemorySlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSlot => formatter.write_str("strategy does not implement core/memory"),
            Self::InvalidObservation(reason) => formatter.write_str(reason),
            Self::InvalidDecision(reason) => formatter.write_str(reason),
            Self::DecisionWidened(reason) => formatter.write_str(reason),
            Self::NotAdmittedReadOnly => {
                formatter.write_str("memory recall was not admitted read-only")
            }
            Self::NotAdmittedTrustMutation => {
                formatter.write_str("memory write was not admitted trust-mutating")
            }
            Self::WriteRefused => formatter.write_str("memory policy refused the write"),
            Self::UnsupportedVersion => formatter.write_str("unsupported memory slot version"),
        }
    }
}

impl std::error::Error for MemorySlotError {}

impl MemoryRecallPlan {
    /// Re-check a decision against the observation that produced it, whoever produced it.
    ///
    /// Every ceiling in the observation is re-derived here from the caller's own numbers rather
    /// than trusted from the decision, because a replacement slot is exactly the thing that might
    /// lie about them.
    fn validate_against(&self, observation: &MemorySlotObservation) -> Result<(), MemorySlotError> {
        if self.recalled.len() > observation.max_recalled {
            return Err(MemorySlotError::DecisionWidened(
                "memory decision recalled more facts than the caller's cap",
            ));
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.recalled.len());
        let mut spent = 0usize;
        for slug in &self.recalled {
            if seen.contains(&slug.as_str()) {
                return Err(MemorySlotError::InvalidDecision(
                    "memory decision repeats a fact",
                ));
            }
            seen.push(slug.as_str());
            let Some(candidate) = observation
                .candidates
                .iter()
                .find(|candidate| candidate.slug == *slug)
            else {
                return Err(MemorySlotError::InvalidDecision(
                    "memory decision names a fact outside the gathered observation",
                ));
            };
            if candidate.trust < observation.trust_floor {
                return Err(MemorySlotError::DecisionWidened(
                    "memory decision admitted a fact below the caller's trust floor",
                ));
            }
            spent = spent.saturating_add(candidate.framed_bytes);
        }
        if spent != self.recall_bytes_used {
            return Err(MemorySlotError::InvalidDecision(
                "memory decision under-reports what its selection costs",
            ));
        }
        if spent > observation.recall_bytes {
            return Err(MemorySlotError::DecisionWidened(
                "memory decision exceeded the caller's recall byte budget",
            ));
        }
        Ok(())
    }
}

/// The hand-written baseline `core/memory`: BM25-lite relevance, then a greedy fit inside the
/// caller's byte budget and recall cap.
///
/// This is the scoring and selection that `FileMemory::recall` used to perform inline, moved
/// behind the slot seam unchanged: the same tokenizer, the same BM25 constants, the same
/// score-descending / slug-ascending total order, and the same "skip, do not stop" behaviour when
/// a highly ranked fact does not fit — a smaller lower-ranked fact may still fit after it.
#[derive(Debug, Clone)]
pub struct MemoryRecallStrategy {
    slot: SlotId,
}

impl Default for MemoryRecallStrategy {
    fn default() -> Self {
        Self {
            slot: SlotId("core/memory".into()),
        }
    }
}

impl MemoryRecallStrategy {
    /// Typed facade for callers. Capability admission still happens through `decide_narrowed`.
    pub fn select(
        &self,
        input: &MemorySlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<MemoryRecallProposal, MemorySlotError> {
        Self::select_with(self, input, ceiling)
    }

    /// Decode and revalidate any pinned implementation of the frozen slot trait.
    pub fn select_with(
        slot: &dyn StrategySlot,
        input: &MemorySlotObservation,
        ceiling: CapabilitySet,
    ) -> Result<MemoryRecallProposal, MemorySlotError> {
        if slot.slot().as_persisted_str() != "core/memory" {
            return Err(MemorySlotError::WrongSlot);
        }
        input.validate()?;
        let payload = serde_json::to_value(input)
            .map_err(|_| MemorySlotError::InvalidObservation("memory observation is invalid"))?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::ReadOnly) {
            return Err(MemorySlotError::NotAdmittedReadOnly);
        }
        let decision = serde_json::from_value::<MemorySlotDecision>(outcome.decision)
            .map_err(|_| MemorySlotError::InvalidDecision("memory decision is invalid"))?;
        let MemorySlotDecision::Plan { plan } = decision else {
            return Err(MemorySlotError::UnsupportedVersion);
        };
        plan.validate_against(input)?;
        Ok(MemoryRecallProposal {
            plan,
            eligible: outcome.admitted,
        })
    }

    /// Ask the pinned `core/memory` policy to admit exact operator-authored project-memory bytes.
    /// The returned text is rechecked byte-for-byte, so a replacement cannot write instructions
    /// of its own into a later turn.
    pub fn authorize_project_write_with(
        slot: &dyn StrategySlot,
        text: &str,
        ceiling: CapabilitySet,
    ) -> Result<MemoryWriteProposal, MemorySlotError> {
        if slot.slot().as_persisted_str() != "core/memory" {
            return Err(MemorySlotError::WrongSlot);
        }
        let input = MemorySlotObservation::project_write(text);
        input.validate()?;
        let observation = SlotObservation {
            slot: slot.slot().clone(),
            ceiling,
            payload: serde_json::to_value(&input).map_err(|_| {
                MemorySlotError::InvalidObservation("memory write observation is invalid")
            })?,
        };
        let outcome = decide_narrowed(slot, &observation);
        if !outcome.admitted.contains(Capability::TrustMutating) {
            return Err(MemorySlotError::NotAdmittedTrustMutation);
        }
        let decision = serde_json::from_value::<MemorySlotDecision>(outcome.decision)
            .map_err(|_| MemorySlotError::InvalidDecision("memory write decision is invalid"))?;
        let MemorySlotDecision::Write { write } = decision else {
            return Err(MemorySlotError::InvalidDecision(
                "memory write decision used the wrong operation",
            ));
        };
        let Some(write) = write else {
            return Err(MemorySlotError::WriteRefused);
        };
        if write != text {
            return Err(MemorySlotError::DecisionWidened(
                "memory decision altered the operator-authored write",
            ));
        }
        Ok(MemoryWriteProposal {
            text: write,
            eligible: outcome.admitted,
        })
    }

    fn unknown_outcome() -> SlotOutcome {
        SlotOutcome {
            admitted: CapabilitySet::none(),
            decision: serde_json::to_value(MemorySlotDecision::Unknown)
                .expect("unit memory decision serializes"),
        }
    }

    /// The pure ranking: score every admissible candidate, apply novelty, then fit greedily.
    fn plan_for(input: &MemorySlotObservation) -> MemoryRecallPlan {
        let scores = memory_retrieval_scores(input);
        // Rank by score desc, ties by slug asc — a total order, so the sort is reproducible.
        let mut ranked: Vec<(usize, i64)> = scores
            .combined_ppm
            .iter()
            .copied()
            .enumerate()
            .filter(|(index, score)| {
                *score > 0 && input.candidates[*index].trust >= input.trust_floor
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| input.candidates[a.0].slug.cmp(&input.candidates[b.0].slug))
        });

        let mut recalled: Vec<String> = Vec::new();
        let mut selected_indexes: Vec<usize> = Vec::new();
        let mut recall_bytes_used = 0usize;
        for (index, _score) in ranked {
            if recalled.len() >= input.max_recalled {
                break;
            }
            let candidate = &input.candidates[index];
            if selected_indexes.iter().any(|selected| {
                token_jaccard_ppm(&scores.docs[index], &scores.docs[*selected])
                    >= input.retrieval_policy.novelty_dedup_threshold_ppm
            }) {
                continue;
            }
            // Skip rather than stop: a smaller lower-ranked fact may still fit after this one.
            if recall_bytes_used.saturating_add(candidate.framed_bytes) > input.recall_bytes {
                continue;
            }
            recall_bytes_used += candidate.framed_bytes;
            recalled.push(candidate.slug.clone());
            selected_indexes.push(index);
        }
        MemoryRecallPlan {
            recalled,
            recall_bytes_used,
        }
    }
}

#[derive(Clone)]
pub(super) struct MemoryRetrievalScores {
    pub(super) lexical_ppm: Vec<i64>,
    pub(super) structural_ppm: Vec<i64>,
    pub(super) recency_ppm: Vec<u32>,
    pub(super) combined_ppm: Vec<i64>,
    pub(super) docs: Vec<Vec<String>>,
}

pub(super) fn memory_retrieval_scores(input: &MemorySlotObservation) -> MemoryRetrievalScores {
    const CACHE_LIMIT: usize = 128;
    #[derive(Default)]
    struct ScoreCache {
        entries: HashMap<[u8; 32], MemoryRetrievalScores>,
        order: VecDeque<[u8; 32]>,
    }
    static CACHE: OnceLock<Mutex<ScoreCache>> = OnceLock::new();
    let encoded = serde_json::to_vec(input).unwrap_or_default();
    let key: [u8; 32] = Sha256::digest(encoded).into();
    let cache = CACHE.get_or_init(|| Mutex::new(ScoreCache::default()));
    if let Some(scores) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entries
        .get(&key)
        .cloned()
    {
        return scores;
    }
    let scores = compute_memory_retrieval_scores(input);
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let limit = iteron_tunables::param_usize("ctx.memory.cache_limit", CACHE_LIMIT).clamp(1, 1_024);
    while cache.entries.len() >= limit {
        if let Some(oldest) = cache.order.pop_front() {
            cache.entries.remove(&oldest);
        } else {
            break;
        }
    }
    cache.order.push_back(key);
    cache.entries.insert(key, scores.clone());
    scores
}

fn compute_memory_retrieval_scores(input: &MemorySlotObservation) -> MemoryRetrievalScores {
    let query = tokenize(&input.task);
    let docs = input
        .candidates
        .iter()
        .map(|candidate| tokenize(&candidate.text))
        .collect::<Vec<_>>();
    let doc_refs = docs.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let raw_lexical = bm25(
        &query,
        &doc_refs,
        f64::from(input.retrieval_policy.bm25_k1_milli) / 1_000.0,
        f64::from(input.retrieval_policy.bm25_b_ppm)
            / f64::from(crate::memory_runtime::SCORE_SCALE),
    );
    let lexical_max = raw_lexical
        .iter()
        .copied()
        .filter(|score| score.is_finite() && *score > 0.0)
        .fold(0.0_f64, f64::max);
    let lexical_ppm = raw_lexical
        .iter()
        .map(|score| normalized_score_ppm(*score, lexical_max))
        .collect::<Vec<_>>();
    let structural_ppm = docs
        .iter()
        .map(|doc| i64::from(token_jaccard_ppm(&query, doc)))
        .collect::<Vec<_>>();
    let recency_ppm = input
        .candidates
        .iter()
        .map(|candidate| {
            candidate
                .modified_unix_secs
                .map_or(crate::memory_runtime::SCORE_SCALE, |modified| {
                    input
                        .retrieval_policy
                        .recency_multiplier(input.reference_unix_secs.saturating_sub(modified))
                })
        })
        .collect::<Vec<_>>();
    let total_weight = u64::from(input.retrieval_policy.lexical_weight_ppm)
        .saturating_add(u64::from(input.retrieval_policy.structural_weight_ppm));
    let combined_ppm = lexical_ppm
        .iter()
        .zip(&structural_ppm)
        .zip(&recency_ppm)
        .zip(&input.candidates)
        .map(|(((lexical, structural), recency), candidate)| {
            if total_weight == 0 {
                return 0;
            }
            let fused = u64::try_from((*lexical).max(0))
                .unwrap_or(0)
                .saturating_mul(u64::from(input.retrieval_policy.lexical_weight_ppm))
                .saturating_add(
                    u64::try_from((*structural).max(0))
                        .unwrap_or(0)
                        .saturating_mul(u64::from(input.retrieval_policy.structural_weight_ppm)),
                )
                / total_weight;
            i64::try_from(
                fused.saturating_mul(u64::from(*recency))
                    / u64::from(crate::memory_runtime::SCORE_SCALE)
                    * u64::from(
                        candidate
                            .confidence_ppm
                            .min(crate::memory_runtime::SCORE_SCALE),
                    )
                    / u64::from(crate::memory_runtime::SCORE_SCALE),
            )
            .unwrap_or(i64::MAX)
        })
        .collect();
    MemoryRetrievalScores {
        lexical_ppm,
        structural_ppm,
        recency_ppm,
        combined_ppm,
        docs,
    }
}

fn normalized_score_ppm(score: f64, maximum: f64) -> i64 {
    if !score.is_finite() || score <= 0.0 || maximum <= 0.0 {
        return 0;
    }
    let scaled = (score / maximum * f64::from(crate::memory_runtime::SCORE_SCALE)).round();
    scaled.clamp(0.0, f64::from(crate::memory_runtime::SCORE_SCALE)) as i64
}

pub(super) fn token_jaccard_ppm(left: &[String], right: &[String]) -> u32 {
    let mut left = left.iter().collect::<Vec<_>>();
    let mut right = right.iter().collect::<Vec<_>>();
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    let intersection = left
        .iter()
        .filter(|token| right.binary_search(token).is_ok())
        .count();
    let union = left
        .len()
        .saturating_add(right.len())
        .saturating_sub(intersection);
    if union == 0 {
        return 0;
    }
    u32::try_from(
        u64::try_from(intersection)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(crate::memory_runtime::SCORE_SCALE))
            / u64::try_from(union).unwrap_or(u64::MAX),
    )
    .unwrap_or(crate::memory_runtime::SCORE_SCALE)
}

impl StrategySlot for MemoryRecallStrategy {
    fn slot(&self) -> &SlotId {
        &self.slot
    }

    fn decide(&self, observation: &SlotObservation) -> SlotOutcome {
        if observation.slot != self.slot {
            return Self::unknown_outcome();
        }
        let Ok(input) =
            serde_json::from_value::<MemorySlotObservation>(observation.payload.clone())
        else {
            return Self::unknown_outcome();
        };
        if input.validate().is_err() {
            return Self::unknown_outcome();
        }
        if let Some(write) = input.write {
            return SlotOutcome {
                admitted: CapabilitySet::only(Capability::TrustMutating)
                    .intersect(observation.ceiling),
                decision: serde_json::to_value(MemorySlotDecision::Write { write: Some(write) })
                    .expect("memory write decision serializes"),
            };
        }
        SlotOutcome {
            admitted: CapabilitySet::only(Capability::ReadOnly).intersect(observation.ceiling),
            decision: serde_json::to_value(MemorySlotDecision::Plan {
                plan: Self::plan_for(&input),
            })
            .expect("memory recall plan serializes"),
        }
    }
}

/// Lowercase, split on non-alphanumerics, keep tokens of length >= 2 (drops stray single-char
/// noise). Deterministic tokenizer for the lexical score.
pub(super) fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= 2)
        .map(|t| t.to_lowercase())
        .collect()
}

/// BM25-lite score of each doc against `query`. Standard Okapi BM25 with fixed `k1`/`b`, so the
/// score is a pure, reproducible function of the inputs. Returns a score per doc, aligned to `docs`.
pub(super) fn bm25(query: &[String], docs: &[&[String]], k1: f64, b: f64) -> Vec<f64> {
    let n = docs.len();
    if n == 0 {
        return Vec::new();
    }
    let avgdl = docs.iter().map(|d| d.len()).sum::<usize>() as f64 / n as f64;
    if avgdl == 0.0 {
        return vec![0.0; n];
    }
    // Deduplicate query terms; a repeated query term should not double-count.
    let mut terms: Vec<&String> = query.iter().collect();
    terms.sort();
    terms.dedup();

    let mut scores = vec![0.0f64; n];
    for term in terms {
        let df = docs.iter().filter(|d| d.iter().any(|w| w == term)).count();
        if df == 0 {
            continue;
        }
        let idf = (1.0 + (n as f64 - df as f64 + 0.5) / (df as f64 + 0.5)).ln();
        for (i, doc) in docs.iter().enumerate() {
            let tf = doc.iter().filter(|w| *w == term).count() as f64;
            if tf == 0.0 {
                continue;
            }
            let dl = doc.len() as f64;
            let denom = tf + k1 * (1.0 - b + b * dl / avgdl);
            scores[i] += idf * (tf * (k1 + 1.0)) / denom;
        }
    }
    scores
}
